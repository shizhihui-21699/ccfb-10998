/**
 * Self-test: the lab is the oracle.
 *
 * Every lab profile declares what it is configured to do (`expected`). This
 * test starts the lab, probes each profile with the real checkup code, and
 * asserts that the probe observed exactly those facts. A failure here means
 * either the lab drifted from its declared configuration or the probe is
 * misreading it; both are worth knowing before trusting a scan of real
 * services.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { startLab, type LabServer, type LabStartResult } from '../lab/server.ts';
import { probeEndpoint } from '../src/tls/endpoint.ts';
import { loadBaseline } from '../src/baseline/load.ts';
import { evaluateBaseline } from '../src/baseline/evaluate.ts';
import type { EndpointResult } from '../src/types.ts';

const here = dirname(fileURLToPath(import.meta.url));
const certs = resolve(here, '..', 'lab', 'certs');

const haveCerts =
  existsSync(resolve(certs, 'server.pem')) &&
  existsSync(resolve(certs, 'server.key')) &&
  existsSync(resolve(certs, 'ca.pem')) &&
  existsSync(resolve(certs, 'response.der'));

const OPENSSL = existsSync('/usr/bin/openssl') || existsSync('/opt/homebrew/bin/openssl');

let lab: LabStartResult | undefined;

before(async () => {
  if (!haveCerts) return;
  lab = await startLab({
    certPath: resolve(certs, 'server.pem'),
    keyPath: resolve(certs, 'server.key'),
    chainPath: resolve(certs, 'ca.pem'),
    ocspResponsePath: resolve(certs, 'response.der'),
    // High, explicit base port to keep clear of the ranges a real scan uses.
    basePort: 21000,
  });
});

after(async () => {
  if (lab) await Promise.all(lab.servers.map((s) => s.close()));
});

function server(name: string): LabServer | undefined {
  return lab?.servers.find((s) => s.profile.name === name);
}

async function probe(name: string, extra: { httpPort?: number } = {}): Promise<EndpointResult> {
  const s = server(name);
  assert.ok(s, `lab profile "${name}" did not start (${lab?.failures.find((f) => f.name === name)?.reason ?? 'unknown'})`);
  return probeEndpoint({
    host: '127.0.0.1',
    port: s!.port,
    timeoutMs: 4000,
    maxSuitesPerVersion: 32,
    ...(extra.httpPort !== undefined ? { httpPort: extra.httpPort } : {}),
    checkHsts: true,
    checkOcsp: true,
    checkRenegotiation: true,
    rejectUnauthorized: false,
    interProbeDelayMs: 2,
    maxHandshakes: 200,
  });
}

const skip = !haveCerts;

test('lab: all advertised profiles start', { skip }, async () => {
  assert.ok(lab);
  for (const name of ['modern', 'legacy', 'tls13only', 'weak', 'nohsts', 'http-hsts']) {
    assert.ok(server(name), `profile ${name} failed to start: ${lab!.failures.find((f) => f.name === name)?.reason ?? 'missing'}`);
  }
  if (OPENSSL) {
    assert.ok(server('stapling') || lab!.failures.some((f) => f.name === 'stapling'), 'stapling profile must start or report why not');
  }
});

test('lab modern: TLS 1.2+1.3, no weak suites, server preference, HSTS', { skip }, async () => {
  const r = await probe('modern');
  const versions = r.versions.filter((v) => v.supported).map((v) => v.version);
  assert.deepEqual(versions.sort(), ['TLSv1.2', 'TLSv1.3'], 'modern must offer exactly 1.2 and 1.3');
  assert.equal(r.suites.filter((s) => s.strength === 'weak' || s.strength === 'insecure').length, 0, 'modern must have no weak suites');
  assert.equal(r.preference?.serverPrefers, true, 'modern sets honorCipherOrder');
  assert.equal(r.hsts?.present, true, 'modern sends HSTS');
  assert.equal(r.hsts?.maxAge, 31536000);
  assert.equal(r.hsts?.includeSubDomains, true);
});

test('lab legacy: TLS 1.0/1.1 enabled, weak suites, client preference', { skip }, async () => {
  const r = await probe('legacy');
  const versions = r.versions.filter((v) => v.supported).map((v) => v.version);
  for (const v of ['TLSv1.0', 'TLSv1.1', 'TLSv1.2']) {
    assert.ok(versions.includes(v as (typeof versions)[number]), `legacy must still accept ${v}`);
  }
  assert.ok(
    r.suites.some((s) => s.strength === 'weak'),
    'legacy must expose at least one weak suite (CBC/static RSA)',
  );
  assert.equal(r.preference?.serverPrefers, false, 'legacy does not set honorCipherOrder, so the client order wins');
  assert.equal(r.hsts?.present, false, 'legacy does not send HSTS');
});

test('lab tls13only: only TLS 1.3 is negotiated', { skip }, async () => {
  const r = await probe('tls13only');
  const versions = r.versions.filter((v) => v.supported).map((v) => v.version);
  assert.deepEqual(versions, ['TLSv1.3']);
  // TLS 1.3 removed renegotiation, so the check must report not-applicable
  // rather than claiming either a pass or a failure.
  assert.equal(r.renegotiation?.applicable, false, 'with no TLS <= 1.2 there is nothing to renegotiate');
  assert.equal(r.renegotiation?.clientInitiatedAccepted, false);
  assert.equal(r.renegotiation?.detail, 'no TLS 1.2 connection available for the live renegotiation test');
});

test('lab weak: static-RSA CBC only, server preference', { skip }, async () => {
  const r = await probe('weak');
  assert.deepEqual(r.versions.filter((v) => v.supported).map((v) => v.version), ['TLSv1.2']);
  assert.ok(r.suites.length >= 1);
  for (const s of r.suites) {
    assert.equal(s.forwardSecret, false, `${s.name} should have no forward secrecy on the weak profile`);
  }
  assert.equal(r.preference?.serverPrefers, true, 'weak sets honorCipherOrder');
});

test('lab nohsts: TLS fine, HSTS absent', { skip }, async () => {
  const r = await probe('nohsts');
  assert.equal(r.hsts?.present, false, 'nohsts must not send the header');
  assert.equal(r.hsts?.fetched, true, 'the TLS port still answers HTTP, so the header is definitively absent');
});

test('lab http-hsts: HSTS only on a plain-HTTP redirect with a short max-age', { skip }, async () => {
  const s = server('http-hsts');
  assert.ok(s);
  const r = await probeEndpoint({
    host: '127.0.0.1',
    port: s!.port,
    httpPort: s!.port,
    timeoutMs: 3000,
    maxSuitesPerVersion: 8,
    checkHsts: true,
    checkOcsp: false,
    checkRenegotiation: false,
    rejectUnauthorized: false,
  });
  assert.equal(r.reachable, false, 'there is no TLS listener');
  assert.equal(r.tlsAbsent, true, 'the port answers TCP but not TLS, which must be distinguishable from unreachable');
  assert.equal(r.hsts?.fetched, true, 'HSTS must still be retrieved over HTTP');
  assert.equal(r.hsts?.present, true);
  assert.equal(r.hsts?.maxAge, 3600, 'the redirect sets the short 1-hour max-age by design');
  assert.equal(r.hsts?.source, 'http-fetch');
});

test('lab stapling: a real stapled OCSP response is observed', { skip: skip || !OPENSSL }, async () => {
  const s = server('stapling');
  if (!s) {
    // openssl may be unavailable; in that case the profile reported a failure.
    assert.ok(lab?.failures.some((f) => f.name === 'stapling') || !OPENSSL);
    return;
  }
  const r = await probeEndpoint({
    host: '127.0.0.1',
    port: s.port,
    timeoutMs: 4000,
    maxSuitesPerVersion: 16,
    checkHsts: false,
    checkOcsp: true,
    checkRenegotiation: true,
    rejectUnauthorized: false,
  });
  assert.equal(r.ocsp?.stapled, true, 'the stapling profile must be detected as stapling');
  assert.ok((r.ocsp?.responseBytes ?? 0) > 100, 'a real DER response is far larger than a stub');
  assert.equal(r.ocsp?.certificateStatus, 'good', 'the lab response is generated for a good certificate');
});

test('baseline scoring: legacy scores far below modern on the modern baseline', { skip }, async () => {
  const baseline = await loadBaseline('default');
  const modern = evaluateBaseline(baseline, await probe('modern'));
  const legacy = evaluateBaseline(baseline, await probe('legacy'));
  assert.ok(modern.score.score >= legacy.score.score, `modern (${modern.score.score}) should outscore legacy (${legacy.score.score})`);
  assert.ok(modern.score.score >= 85, 'modern should be compliant on its own baseline');
  assert.ok(legacy.score.score < modern.score.score);
  assert.ok(
    legacy.findings.some((f) => !f.passed && !f.skipped && f.severity === 'critical'),
    'legacy must produce a critical finding (TLS 1.0/1.1 enabled)',
  );
});
