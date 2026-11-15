/**
 * Scheduler and CLI parsing tests.
 *
 * The scheduler's job is to bound load, so the assertions are about limits
 * being respected, not about TLS correctness: targets are grouped per host,
 * global and per-endpoint budgets stop the scan rather than being ignored,
 * and unreachable hosts are not retried.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseTarget, parseTargetFile } from '../src/cli.ts';
import { runScan } from '../src/scheduler.ts';

test('parseTarget: bare host defaults to 443', () => {
  const t = parseTarget('svc.internal');
  assert.equal(t.host, 'svc.internal');
  assert.equal(t.port, 443);
});

test('parseTarget: host:port', () => {
  const t = parseTarget('db.internal:5432');
  assert.equal(t.host, 'db.internal');
  assert.equal(t.port, 5432);
});

test('parseTarget: bracketed IPv6', () => {
  const t = parseTarget('[2001:db8::1]:8443');
  assert.equal(t.host, '2001:db8::1');
  assert.equal(t.port, 8443);
});

test('parseTarget: bracketed IPv6 without port', () => {
  const t = parseTarget('[::1]');
  assert.equal(t.host, '::1');
  assert.equal(t.port, 443);
});

test('parseTarget rejects bad ports and malformed IPv6', () => {
  assert.throws(() => parseTarget('host:notaport'), /invalid port/);
  assert.throws(() => parseTarget('host:0'), /out of range/);
  assert.throws(() => parseTarget('host:70000'), /out of range/);
  assert.throws(() => parseTarget('[::1'), /unterminated IPv6/);
  assert.throws(() => parseTarget(':443'), /missing host/);
});

test('parseTargetFile: comments, blanks, names and http ports', () => {
  const targets = parseTargetFile(`
    # a comment
    api.internal.example
    db.internal.example:5432
    cache.internal:6379 cache-primary
    web.internal:443 http:80

    # trailing comment on a target line
    other.internal:8443 other   # ignored
  `);
  assert.equal(targets.length, 5);
  assert.equal(targets[0]!.host, 'api.internal.example');
  assert.equal(targets[0]!.port, 443);
  assert.equal(targets[1]!.port, 5432);
  assert.equal(targets[2]!.label, 'cache-primary');
  assert.equal(targets[3]!.httpPort, 80);
  assert.equal(targets[4]!.host, 'other.internal');
  assert.equal(targets[4]!.label, 'other');
});

test('parseTargetFile rejects a second unexpected token', () => {
  assert.throws(() => parseTargetFile('h:443 name extra'), /unexpected token/);
});

/** A TCP server that accepts and immediately closes, used to count connections. */
async function countingServer(): Promise<{ port: number; connections: () => number; close: () => Promise<void> }> {
  const net = await import('node:net');
  let count = 0;
  const server = net.createServer((socket) => {
    count++;
    socket.destroy();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as import('node:net').AddressInfo).port;
  return {
    port,
    connections: () => count,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

test('scheduler: does not retry an unreachable port and respects the per-endpoint budget', async () => {
  const srv = await countingServer();
  const outcome = await runScan([{ host: '127.0.0.1', port: srv.port }], {
    timeoutMs: 500,
    maxSuitesPerVersion: 8,
    checkHsts: false,
    checkOcsp: false,
    checkRenegotiation: false,
    rejectUnauthorized: false,
    concurrency: 1,
    maxTotalHandshakes: 100,
    maxHandshakesPerEndpoint: 4,
    interProbeDelayMs: 0,
  });
  // The server closes without a ServerHello, so every version probe fails fast.
  // Four version probes are exactly the per-endpoint budget; no retries beyond
  // it may reach the server.
  assert.ok(srv.connections() <= 4, `server saw ${srv.connections()} connections, budget was 4`);
  assert.equal(outcome.results.length, 1);
  assert.equal(outcome.results[0]!.reachable, false);
  await srv.close();
});

test('scheduler: a zero-ish total budget marks the remaining targets as skipped', async () => {
  const srv = await countingServer();
  const targets = Array.from({ length: 5 }, (_, i) => ({ host: '127.0.0.1', port: srv.port }));
  const outcome = await runScan(targets, {
    timeoutMs: 400,
    maxSuitesPerVersion: 4,
    checkHsts: false,
    checkOcsp: false,
    checkRenegotiation: false,
    rejectUnauthorized: false,
    concurrency: 2,
    maxTotalHandshakes: 4,
    maxHandshakesPerEndpoint: 4,
    interProbeDelayMs: 0,
  });
  // One target consumes the whole budget; the rest must be reported as skipped
  // rather than silently dropped or silently probed anyway.
  assert.equal(outcome.totalHandshakes, 4, 'exactly the budget was spent');
  assert.ok(outcome.skipped.length >= 4, `expected remaining targets in skipped, got ${outcome.skipped.length}`);
  assert.ok(srv.connections() <= 4, `server saw ${srv.connections()} connections for a budget of 4`);
  await srv.close();
});

test('scheduler: targets for the same host are probed sequentially, not in parallel', async () => {
  // Two ports of one host: the scheduler groups them so one worker walks them
  // in order. We assert ordering by recording the ports touched.
  const order: number[] = [];
  const net = await import('node:net');
  const makeServer = async (tag: number) => {
    const s = net.createServer((socket) => {
      order.push(tag);
      socket.destroy();
    });
    await new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve));
    return { server: s, port: (s.address() as import('node:net').AddressInfo).port };
  };
  const a = await makeServer(1);
  const b = await makeServer(2);
  await runScan(
    [
      { host: '127.0.0.1', port: a.port },
      { host: '127.0.0.1', port: b.port },
    ],
    {
      timeoutMs: 300,
      maxSuitesPerVersion: 2,
      checkHsts: false,
      checkOcsp: false,
      checkRenegotiation: false,
      rejectUnauthorized: false,
      concurrency: 4,
      maxTotalHandshakes: 8,
      maxHandshakesPerEndpoint: 4,
      interProbeDelayMs: 0,
    },
  );
  // Port 1's probes must all precede port 2's: the first two entries are port 1.
  assert.deepEqual(order.slice(0, 2), [1, 1], `expected both first connections on port 1, got ${order.join(',')}`);
  await new Promise<void>((r) => a.server.close(() => r()));
  await new Promise<void>((r) => b.server.close(() => r()));
});
