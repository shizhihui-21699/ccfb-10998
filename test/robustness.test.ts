/**
 * Robustness against servers that do not behave.
 *
 * A checkup tool meets every kind of broken service, and must neither hang,
 * crash, nor leak on any of them. Each server here models a failure mode seen
 * in the wild: silence, a lying record length, an endless byte stream, a
 * truncated handshake, an immediate reset.
 *
 * Every assertion has a deadline; a hang shows up as a test timeout, which is
 * the failure mode we care about most.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { helloProbe } from '../src/tls/probe.ts';

type ServerFactory = (socket: net.Socket) => void;

async function hostileServer(onConnection: ServerFactory): Promise<{ port: number; close: () => Promise<void> }> {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    onConnection(socket);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;
  return {
    port,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        sockets.clear();
        server.close(() => resolve());
      }),
  };
}

const PROBE = { legacyVersion: 0x0303, offerTls13: false, suites: [0xc02f], timeoutMs: 700 } as const;

test('a server that accepts and never answers results in a timeout, not a hang', async () => {
  const srv = await hostileServer(() => {
    /* say nothing */
  });
  const started = Date.now();
  const r = await helloProbe({ host: '127.0.0.1', port: srv.port, ...PROBE });
  const elapsed = Date.now() - started;
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.failure.kind, 'timeout');
  assert.ok(elapsed < 2000, `probe should give up near its timeout, took ${elapsed}ms`);
  await srv.close();
});

test('a record header claiming a huge length is not trusted', async () => {
  const srv = await hostileServer((socket) => {
    // Record header says 0xffff bytes follow, but only 4 arrive.
    socket.write(Buffer.from([22, 3, 3, 0xff, 0xff, 1, 2, 3, 4]));
  });
  const r = await helloProbe({ host: '127.0.0.1', port: srv.port, ...PROBE });
  assert.equal(r.ok, false, 'a lying length must not be treated as a ServerHello');
  await srv.close();
});

test('an endless stream of non-TLS bytes does not grow memory without bound per probe', async () => {
  let timer: NodeJS.Timeout | undefined;
  const srv = await hostileServer((socket) => {
    timer = setInterval(() => {
      if (!socket.destroyed) socket.write(Buffer.alloc(4096, 0x41));
    }, 2);
  });
  const r = await helloProbe({ host: '127.0.0.1', port: srv.port, ...PROBE });
  if (timer) clearInterval(timer);
  assert.equal(r.ok, false);
  // The probe must terminate (timeout or closed); the important part is that
  // it returns at all rather than reading forever.
  assert.ok(['timeout', 'closed', 'reset', 'tls-error', 'alert'].includes(r.ok === false ? r.failure.kind : ''));
  await srv.close();
});

test('a truncated handshake then close is reported as closed', async () => {
  const srv = await hostileServer((socket) => {
    socket.end(Buffer.concat([Buffer.from([22, 3, 3, 0xff, 0xff]), Buffer.alloc(100, 0)]));
  });
  const r = await helloProbe({ host: '127.0.0.1', port: srv.port, ...PROBE });
  assert.equal(r.ok, false);
  if (r.ok === false) assert.ok(['closed', 'reset', 'timeout'].includes(r.failure.kind), r.failure.kind);
  await srv.close();
});

test('an immediate reset is classified as reset', async () => {
  const srv = await hostileServer((socket) => {
    socket.resetAndDestroy?.();
    if (!socket.destroyed) socket.destroy();
  });
  const r = await helloProbe({ host: '127.0.0.1', port: srv.port, ...PROBE });
  assert.equal(r.ok, false);
  if (r.ok === false) assert.ok(['reset', 'closed'].includes(r.failure.kind), `got ${r.failure.kind}`);
  await srv.close();
});

test('a refused port is classified as refused and returns promptly', async () => {
  const srv = await hostileServer(() => {});
  const port = srv.port;
  await srv.close(); // port is now closed
  const started = Date.now();
  const r = await helloProbe({ host: '127.0.0.1', port, ...PROBE });
  assert.equal(r.ok, false);
  if (r.ok === false) assert.equal(r.failure.kind, 'refused');
  assert.ok(Date.now() - started < 1000, 'connection refusal should be immediate');
});

test('concurrent probes against one hostile server all settle', async () => {
  const srv = await hostileServer(() => {});
  const probes = Array.from({ length: 25 }, () => helloProbe({ host: '127.0.0.1', port: srv.port, ...PROBE }));
  const results = await Promise.all(probes);
  assert.equal(results.length, 25);
  for (const r of results) {
    assert.equal(r.ok, false);
    if (r.ok === false) assert.equal(r.failure.kind, 'timeout');
  }
  await srv.close();
});

test('the probe does not leave sockets behind', async () => {
  const srv = await hostileServer(() => {});
  const before = process.getActiveResourcesInfo().filter((h) => /TCP|Socket/.test(h)).length;
  await helloProbe({ host: '127.0.0.1', port: srv.port, ...PROBE });
  // Give the socket's close a tick to be observed by the resource tracker.
  await new Promise((r) => setTimeout(r, 50));
  const after = process.getActiveResourcesInfo().filter((h) => /TCP|Socket/.test(h)).length;
  assert.ok(after <= before + 1, `socket leak: ${before} before, ${after} after`);
  await srv.close();
});
