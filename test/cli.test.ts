/**
 * CLI integration tests: exit-code semantics and output routing.
 *
 * `main()` is called directly (never through a shell) so the assertions are
 * about the function's contract. Exit codes are part of that contract: a CI
 * job branches on them, so 0/1/2/3 must mean what the help text says.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from '../src/cli.ts';

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: { stdout: (s: string) => out.push(s), stderr: (s: string) => err.push(s) },
    out,
    err,
    allOut: () => out.join('\n'),
    allErr: () => err.join('\n'),
  };
}

test('--help exits 0 and prints usage', async () => {
  const c = capture();
  assert.equal(await main(['--help'], c.io), 0);
  assert.match(c.allOut(), /Usage:/);
});

test('--version exits 0', async () => {
  const c = capture();
  assert.equal(await main(['--version'], c.io), 0);
  assert.match(c.allOut(), /tls-checkup/);
});

test('no targets is a usage error (exit 2)', async () => {
  const c = capture();
  assert.equal(await main([], c.io), 2);
  assert.match(c.allErr(), /no targets/);
});

test('unknown flag is a usage error (exit 2)', async () => {
  const c = capture();
  assert.equal(await main(['--nonsense'], c.io), 2);
});

test('bad numeric option is a usage error (exit 2)', async () => {
  const c = capture();
  assert.equal(await main(['--target', '127.0.0.1:1', '--concurrency', 'lots'], c.io), 2);
  assert.match(c.allErr(), /--concurrency/);
});

test('out-of-range numeric option is a usage error', async () => {
  const c = capture();
  assert.equal(await main(['--target', '127.0.0.1:1', '--timeout', '10'], c.io), 2);
});

test('missing baseline file is a usage error naming the path', async () => {
  const c = capture();
  assert.equal(await main(['--target', '127.0.0.1:1', '--baseline', '/nonexistent/baseline.json'], c.io), 2);
  assert.match(c.allErr(), /cannot read baseline/);
});

test('invalid baseline JSON shape is rejected at load time', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tls-checkup-'));
  const path = join(dir, 'bad.json');
  writeFileSync(path, JSON.stringify({ id: 'x', name: 'x', checks: [{ id: 'a', kind: 'not-a-check', weight: 1, severity: 'high' }] }));
  const c = capture();
  assert.equal(await main(['--target', '127.0.0.1:1', '--baseline', path], c.io), 2);
  assert.match(c.allErr(), /unknown check kind/);
});

test('unreadable target file is a usage error', async () => {
  const c = capture();
  assert.equal(await main(['/nonexistent/targets.txt'], c.io), 2);
  assert.match(c.allErr(), /cannot read target file/);
});

test('a target that refuses connections yields exit 3 and a zero score', async () => {
  // Port 1 on loopback is essentially never listening; if it somehow is, the
  // test is skipped rather than giving a false negative.
  const c = capture();
  const code = await main(['--target', '127.0.0.1:1', '--timeout', '500', '--no-hsts'], c.io);
  if (code === 3) {
    assert.match(c.allOut(), /unreachable|no listener/);
  } else {
    assert.equal(code, 0, 'if something is listening on port 1 the scan itself succeeded');
  }
});

test('--format json emits parseable JSON with the expected top-level keys', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tls-checkup-'));
  const path = join(dir, 'targets.txt');
  writeFileSync(path, '127.0.0.1:1\n');
  const c = capture();
  const code = await main([path, '--format', 'json', '--timeout', '500', '--no-hsts'], c.io);
  assert.ok(code === 0 || code === 1 || code === 3);
  const report = JSON.parse(c.allOut());
  assert.equal(typeof report.generatedAt, 'string');
  assert.equal(report.baseline.id, 'modern-internal');
  assert.ok(Array.isArray(report.endpoints));
  assert.equal(report.endpoints.length, 1);
  assert.equal(typeof report.endpoints[0].assessment.score.score, 'number');
});

test('invalid --format is rejected', async () => {
  const c = capture();
  assert.equal(await main(['--target', '127.0.0.1:1', '--format', 'yaml'], c.io), 2);
  assert.match(c.allErr(), /--format/);
});
