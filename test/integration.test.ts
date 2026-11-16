/**
 * Integration tests against the local fixture fleet.
 *
 * These start the real fixture servers (node:tls, LibreSSL, OpenSSL with OCSP
 * stapling), scan them with the real probe stack, and assert that each host's
 * *known* posture is detected. This is what proves the whole pipeline — wire
 * format, enumeration, certificate parsing, scoring — actually works.
 *
 * The suite is skipped (not failed) when a fixture cannot start, e.g. on a
 * machine without the LibreSSL binary the legacy fixtures need.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { startFixtures, type RunningFixture } from "../fixtures/servers.ts";
import { scanHost, type HostResult } from "../src/probes/host.ts";
import { DEFAULT_BASELINE } from "../src/baseline/default-baseline.ts";
import { mergeBaselines } from "../src/baseline/types.ts";
import type { Target } from "../src/types.ts";

let fixtures: RunningFixture[] = [];
const byId = new Map<string, RunningFixture>();
const cache = new Map<string, HostResult>();

/** Scan options tuned for tests: fast timeouts, no retry delays. */
const TEST_BASELINE = mergeBaselines(DEFAULT_BASELINE, {
  safety: {
    concurrency: 6,
    retries: 0,
    maxAttemptsPerHost: 300,
    maxProbesPerVersion: 48,
    deadlineMs: 60_000,
    jitterMs: [0, 2],
  },
});

before(async () => {
  fixtures = await startFixtures();
  for (const f of fixtures) byId.set(f.id, f);
});

after(async () => {
  await Promise.all(fixtures.map((f) => f.close()));
});

async function scanFixture(id: string): Promise<HostResult | null> {
  const fixture = byId.get(id);
  if (!fixture) return null;
  const cached = cache.get(id);
  if (cached) return cached;
  const target: Target = { host: "127.0.0.1", port: fixture.actualPort };
  const result = await scanHost(target, {
    baseline: TEST_BASELINE,
    timing: { connectTimeoutMs: 3_000, readTimeoutMs: 4_000 },
    skipActiveRenegotiation: false,
  });
  cache.set(id, result);
  return result;
}

function findingStatus(result: HostResult, id: string): string | undefined {
  return result.evaluation.findings.find((f) => f.id === id)?.status;
}

test("modern fixture: TLS 1.2+1.3 only, all strong suites, no renegotiation", async (t) => {
  const result = await scanFixture("modern");
  if (!result) return t.skip("modern fixture unavailable");
  const { report } = result;

  assert.deepEqual(report.protocols.supported, ["TLSv1.2", "TLSv1.3"]);
  assert.ok(report.ciphers.byVersion.every((e) => e.suites.every((s) => !s.weak)));
  assert.equal(report.renegotiation.secureRenegotiation, true);
  assert.equal(report.renegotiation.acceptsClientInitiated, false, "NO_RENEGOTIATION honoured");
  assert.equal(report.hsts.present, true);
  assert.equal(report.hsts.maxAge, 63_072_000);
  assert.equal(findingStatus(result, "proto-tls10"), "pass");
  assert.equal(findingStatus(result, "suite-weak"), "pass");
  assert.equal(findingStatus(result, "reneg-client"), "pass");
  assert.equal(report.certificate.available, true);
  assert.equal(report.certificate.keyBits, 2048);
});

test("tls10-open fixture: TLS 1.0 and 1.1 are detected and fail", async (t) => {
  const result = await scanFixture("tls10-open");
  if (!result) return t.skip("fixture unavailable");
  assert.ok(result.report.protocols.supported.includes("TLSv1.0"));
  assert.ok(result.report.protocols.supported.includes("TLSv1.1"));
  assert.equal(findingStatus(result, "proto-tls10"), "fail");
  assert.equal(findingStatus(result, "proto-tls11"), "fail");
});

test("weak-ciphers fixture: RC4 and 3DES are enumerated and flagged", async (t) => {
  const result = await scanFixture("weak-ciphers");
  if (!result) return t.skip("fixture unavailable");
  const suites = result.report.ciphers.byVersion.flatMap((e) => e.suites);
  assert.ok(suites.some((s) => /RC4/.test(s.name)), "RC4 suite found");
  assert.ok(suites.some((s) => /DES-CBC3|3DES/.test(s.name)), "3DES suite found");
  assert.ok(suites.filter((s) => s.weak).length >= 2);
  assert.equal(findingStatus(result, "suite-weak"), "fail");
  assert.equal(findingStatus(result, "suite-legacy-enc"), "fail");
});

test("client-order fixture: server preference is reported as client-driven", async (t) => {
  const result = await scanFixture("client-order");
  if (!result) return t.skip("fixture unavailable");
  assert.equal(result.report.preference.tested, true);
  assert.equal(result.report.preference.serverPrefersOwnOrder, false);
  assert.equal(findingStatus(result, "pref-server-order"), "warn");
});

test("reneg-open fixture: client-initiated renegotiation is detected", async (t) => {
  const result = await scanFixture("reneg-open");
  if (!result) return t.skip("fixture unavailable");
  assert.equal(result.report.renegotiation.acceptsClientInitiated, true);
  assert.equal(findingStatus(result, "reneg-client"), "fail");
});

test("expired-cert fixture: expiry is detected", async (t) => {
  const result = await scanFixture("expired-cert");
  if (!result) return t.skip("fixture unavailable");
  assert.equal(result.report.certificate.expired, true);
  assert.ok((result.report.certificate.daysRemaining ?? 0) < 0);
  assert.equal(findingStatus(result, "cert-expiry"), "fail");
});

test("wrong-host fixture: hostname mismatch is detected", async (t) => {
  const fixture = byId.get("wrong-host");
  if (!fixture) return t.skip("fixture unavailable");
  // Scan by DNS name so the check has a name to verify against.
  const result = await scanHost(
    { host: "localhost", port: fixture.actualPort },
    { baseline: TEST_BASELINE, timing: { connectTimeoutMs: 3_000, readTimeoutMs: 4_000 } },
  );
  assert.equal(result.report.certificate.hostnameMatch, false);
  assert.equal(
    result.evaluation.findings.find((f) => f.id === "cert-hostname")?.status,
    "fail",
  );
});

test("sha1-small fixture: SHA-1 signature is detected", async (t) => {
  const result = await scanFixture("sha1-small");
  if (!result) return t.skip("fixture unavailable");
  assert.equal(result.report.certificate.sha1Signature, true);
  assert.match(result.report.certificate.signatureAlgorithm ?? "", /sha1/i);
  assert.equal(findingStatus(result, "cert-sha1"), "fail");
});

test("small-key fixture: 1024-bit key fails the strength check", async (t) => {
  const result = await scanFixture("small-key");
  if (!result) return t.skip("fixture unavailable");
  assert.equal(result.report.certificate.keyBits, 1024);
  assert.equal(findingStatus(result, "cert-key-strength"), "fail");
});

test("no-hsts fixture: missing HSTS header fails the check", async (t) => {
  const result = await scanFixture("no-hsts");
  if (!result) return t.skip("fixture unavailable");
  assert.equal(result.report.hsts.httpResponded, true);
  assert.equal(result.report.hsts.present, false);
  assert.equal(findingStatus(result, "hsts"), "fail");
});

test("ocsp-good fixture: stapled response is read and reported good", async (t) => {
  const result = await scanFixture("ocsp-good");
  if (!result) return t.skip("fixture unavailable");
  assert.equal(result.report.ocsp.stapled, true);
  assert.equal(result.report.ocsp.status, "good");
  assert.ok((result.report.ocsp.size ?? 0) > 0);
  assert.equal(findingStatus(result, "ocsp-stapling"), "pass");
});

test("ocsp-revoked fixture: revoked staple fails the check", async (t) => {
  const result = await scanFixture("ocsp-revoked");
  if (!result) return t.skip("fixture unavailable");
  assert.equal(result.report.ocsp.stapled, true);
  assert.equal(result.report.ocsp.status, "revoked");
  assert.equal(findingStatus(result, "ocsp-stapling"), "fail");
});

test("ocsp-expired fixture: expired staple fails the check", async (t) => {
  const result = await scanFixture("ocsp-expired");
  if (!result) return t.skip("fixture unavailable");
  assert.equal(result.report.ocsp.stapled, true);
  assert.equal(result.report.ocsp.expired, true);
  assert.equal(findingStatus(result, "ocsp-stapling"), "fail");
});

test("tls13-only fixture: TLS 1.2 requirement fails, renegotiation is N/A", async (t) => {
  const result = await scanFixture("tls13-only");
  if (!result) return t.skip("fixture unavailable");
  assert.deepEqual(result.report.protocols.supported, ["TLSv1.3"]);
  assert.equal(findingStatus(result, "proto-tls12"), "fail");
  assert.equal(result.report.renegotiation.acceptsClientInitiated, null);
});

test("every fixture scan stays within its connection budget", async (t) => {
  const ids = [...byId.keys()];
  if (ids.length === 0) return t.skip("no fixtures");
  for (const id of ids) {
    const result = await scanFixture(id);
    if (!result) continue;
    assert.ok(
      result.report.stats.connections <= TEST_BASELINE.safety.maxAttemptsPerHost,
      `${id} used ${result.report.stats.connections} connections`,
    );
  }
});
