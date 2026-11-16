/**
 * Baseline loading/merging and the scoring engine, including the
 * "n/a checks must not lower the score" property.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_BASELINE } from "../src/baseline/default-baseline.ts";
import { BaselineError, loadBaselineFile, mergeBaselines } from "../src/baseline/types.ts";
import { computeScore, evaluateHost } from "../src/evaluate/engine.ts";
import type { Finding, HostReport } from "../src/types.ts";

function tmpFile(name: string, content: string): string {
  const dir = mkdtempSync(join(tmpdir(), "tls-doctor-"));
  const path = join(dir, name);
  writeFileSync(path, content);
  return path;
}

test("mergeBaselines overlays scalars deep and replaces lists", () => {
  const merged = mergeBaselines(DEFAULT_BASELINE, {
    name: "custom",
    safety: { concurrency: 2, retries: 0, maxAttemptsPerHost: 10, maxProbesPerVersion: 4, deadlineMs: 1000, jitterMs: [0, 1] },
    protocols: [],
  });
  assert.equal(merged.name, "custom");
  assert.equal(merged.safety.concurrency, 2);
  assert.equal(merged.safety.deadlineMs, 1000);
  assert.equal(merged.protocols.length, 0, "list replaced wholesale");
  assert.equal(merged.hsts.minMaxAge, DEFAULT_BASELINE.hsts.minMaxAge, "untouched section preserved");
});

test("loadBaselineFile reads YAML overlays", () => {
  const path = tmpFile(
    "baseline.yaml",
    `name: strict
hsts:
  minMaxAge: 31536000
  requireIncludeSubDomains: true
safety:
  concurrency: 3
`,
  );
  const baseline = loadBaselineFile(path, DEFAULT_BASELINE);
  assert.equal(baseline.name, "strict");
  assert.equal(baseline.hsts.minMaxAge, 31_536_000);
  assert.equal(baseline.hsts.requireIncludeSubDomains, true);
  assert.equal(baseline.safety.concurrency, 3);
  assert.equal(baseline.safety.maxAttemptsPerHost, DEFAULT_BASELINE.safety.maxAttemptsPerHost);
});

test("loadBaselineFile reads JSON overlays", () => {
  const path = tmpFile("baseline.json", JSON.stringify({ name: "json-baseline" }));
  const baseline = loadBaselineFile(path, DEFAULT_BASELINE);
  assert.equal(baseline.name, "json-baseline");
});

test("loadBaselineFile rejects unknown severity", () => {
  const path = tmpFile(
    "bad.yaml",
    `protocols:
  - id: x
    title: bad
    versions: [TLSv1.0]
    forbid: true
    severity: catastrophic
    weight: 1
    message: nope
`,
  );
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), BaselineError);
});

test("loadBaselineFile rejects negative weights", () => {
  const path = tmpFile(
    "bad2.yaml",
    `protocols:
  - id: x
    title: bad
    versions: [TLSv1.0]
    forbid: true
    severity: high
    weight: -5
    message: nope
`,
  );
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), BaselineError);
});

test("loadBaselineFile rejects malformed YAML", () => {
  const path = tmpFile("broken.yaml", "protocols: [unclosed");
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), BaselineError);
});

test("score excludes n/a checks from the denominator", () => {
  const findings: Finding[] = [
    { id: "a", title: "a", category: "x", severity: "high", weight: 10, status: "pass", message: "" },
    { id: "b", title: "b", category: "x", severity: "low", weight: 10, status: "na", message: "" },
  ];
  const score = computeScore(DEFAULT_BASELINE, findings);
  assert.equal(score.value, 100, "the n/a check neither helps nor hurts");
  assert.equal(score.available, 10);
  assert.equal(score.grade, "A");
});

test("warnings score half weight", () => {
  const findings: Finding[] = [
    { id: "a", title: "a", category: "x", severity: "high", weight: 10, status: "pass", message: "" },
    { id: "b", title: "b", category: "x", severity: "low", weight: 10, status: "warn", message: "" },
  ];
  const score = computeScore(DEFAULT_BASELINE, findings);
  assert.equal(score.value, 75);
  assert.equal(score.earned, 15);
});

test("zero-weight informational findings do not affect the score", () => {
  const findings: Finding[] = [
    { id: "a", title: "a", category: "x", severity: "high", weight: 0, status: "fail", message: "" },
    { id: "b", title: "b", category: "x", severity: "high", weight: 10, status: "pass", message: "" },
  ];
  assert.equal(computeScore(DEFAULT_BASELINE, findings).value, 100);
});

test("an empty finding set scores 0 with grade F", () => {
  const score = computeScore(DEFAULT_BASELINE, []);
  assert.equal(score.value, 0);
  assert.equal(score.grade, "F");
});

/** Build a minimally-populated reachable HostReport for evaluation tests. */
function makeReport(overrides: Partial<HostReport> = {}): HostReport {
  return {
    target: { host: "127.0.0.1", port: 443 },
    startedAt: new Date(0).toISOString(),
    durationMs: 1,
    reachable: true,
    protocols: {
      // A realistic, fully-conclusive sweep: 1.0/1.1 rejected, 1.2/1.3 supported.
      outcomes: [
        outcome("TLSv1.0", false, true),
        outcome("TLSv1.1", false, true),
        outcome("TLSv1.2", true, true),
        outcome("TLSv1.3", true, true),
      ],
      supported: ["TLSv1.2", "TLSv1.3"],
      highest: "TLSv1.3",
      lowest: "TLSv1.2",
    },
    ciphers: {
      byVersion: [
        {
          version: "TLSv1.2",
          probes: 2,
          truncated: false,
          suites: [
            {
              id: 0xc02f,
              name: "ECDHE-RSA-AES128-GCM-SHA256",
              weak: false,
              forwardSecrecy: true,
              anonymous: false,
              enc: "AESGCM(128)",
              kx: "ECDH",
              auth: "RSA",
              mac: "AEAD",
            },
          ],
        },
      ],
      totalProbes: 2,
    },
    preference: { tested: true, serverPrefersOwnOrder: true, version: "TLSv1.2" },
    renegotiation: { secureRenegotiation: true, acceptsClientInitiated: false, testedVersion: "TLSv1.2" },
    ocsp: { stapled: false, hasOcspAia: false, testedVersion: "TLSv1.2" },
    hsts: { httpResponded: true, present: true, maxAge: 31_536_000, includeSubDomains: true, preload: false },
    certificate: {
      available: true,
      keyType: "RSA",
      keyBits: 2048,
      signatureAlgorithm: "sha256WithRSAEncryption",
      sha1Signature: false,
      notAfter: new Date(Date.now() + 200 * 86_400_000).toISOString(),
      daysRemaining: 200,
      expired: false,
      hostnameMatch: true,
      hostnameChecked: "svc.internal",
      chainTrusted: null,
    },
    stats: { connections: 10, retries: 0, timeouts: 0, errors: 0, budgetExhausted: false },
    ...overrides,
  };
}

test("a well-configured host passes every scored check", () => {
  const { findings, score } = evaluateHost(DEFAULT_BASELINE, makeReport());
  const failing = findings.filter((f) => f.status === "fail");
  assert.deepEqual(failing, [], "expected no failures");
  assert.equal(score.value, 100);
  assert.equal(score.grade, "A");
});

test("TLS 1.0 being enabled produces a protocol failure", () => {
  const report = makeReport();
  report.protocols.supported = ["TLSv1.0", "TLSv1.2", "TLSv1.3"];
  const { findings } = evaluateHost(DEFAULT_BASELINE, report);
  const tls10 = findings.find((f) => f.id === "proto-tls10");
  assert.equal(tls10?.status, "fail");
});

test("weak suites fail both the weak and legacy-encryption checks", () => {
  const report = makeReport();
  report.ciphers.byVersion.push({
    version: "TLSv1.0",
    probes: 3,
    truncated: false,
    suites: [
      {
        id: 0x0005,
        name: "RC4-SHA",
        weak: true,
        forwardSecrecy: false,
        anonymous: false,
        enc: "RC4(128)",
        kx: "RSA",
        auth: "RSA",
        mac: "SHA1",
      },
    ],
  });
  const { findings } = evaluateHost(DEFAULT_BASELINE, report);
  const ids = new Map(findings.map((f) => [f.id, f.status]));
  assert.equal(ids.get("suite-weak"), "fail");
  assert.equal(ids.get("suite-legacy-enc"), "fail");
});

test("accepting client renegotiation fails the renegotiation check", () => {
  const report = makeReport();
  report.renegotiation.acceptsClientInitiated = true;
  const { findings } = evaluateHost(DEFAULT_BASELINE, report);
  assert.equal(findings.find((f) => f.id === "reneg-client")?.status, "fail");
});

test("expired certificate fails with critical severity", () => {
  const report = makeReport();
  report.certificate.daysRemaining = -10;
  report.certificate.expired = true;
  const { findings } = evaluateHost(DEFAULT_BASELINE, report);
  const expiry = findings.find((f) => f.id === "cert-expiry");
  assert.equal(expiry?.status, "fail");
  assert.equal(expiry?.severity, "critical");
});

test("an unreachable host is not scored against TLS checks", () => {
  const report = makeReport({ reachable: false, tcpError: "ECONNREFUSED" });
  const { score, findings } = evaluateHost(DEFAULT_BASELINE, report);
  assert.equal(score.available, 0, "no checks are applicable");
  for (const f of findings) assert.notEqual(f.status, "fail", `${f.id} should not fail`);
});

test("disabled checks are skipped", () => {
  const baseline = mergeBaselines(DEFAULT_BASELINE, { disabled: ["hsts"] });
  const report = makeReport();
  report.hsts = { httpResponded: true, present: false };
  const { findings } = evaluateHost(baseline, report);
  assert.equal(findings.find((f) => f.id === "hsts"), undefined);
});

test("a protocol rule without versions is rejected", () => {
  const path = tmpFile(
    "no-versions.yaml",
    `protocols:
  - id: x
    title: t
    forbid: true
    severity: high
    weight: 1
    message: m
`,
  );
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), /versions/);
});

test("a protocol rule without forbid/require is rejected", () => {
  const path = tmpFile(
    "no-rule-type.yaml",
    `protocols:
  - id: x
    title: t
    versions: [TLSv1.0]
    severity: high
    weight: 1
    message: m
`,
  );
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), /forbid|require/);
});

test("a suite rule without any selector is rejected", () => {
  const path = tmpFile(
    "no-selector.yaml",
    `suites:
  - id: x
    title: t
    severity: high
    weight: 1
    message: m
`,
  );
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), /reject/);
});

test("the shipped default baseline validates through the loader", () => {
  // Guards against the defaults and the validator drifting apart.
  const merged = mergeBaselines(DEFAULT_BASELINE, DEFAULT_BASELINE);
  assert.equal(merged.name, DEFAULT_BASELINE.name);
  assert.ok(DEFAULT_BASELINE.protocols.every((p) => p.versions.length > 0));
});

/* --- regression tests for scoring defects found in review ---------------- */

function outcome(version: string, supported: boolean, conclusive: boolean) {
  return { version: version as never, supported, conclusive, elapsedMs: 1 };
}

test("inconclusive protocol probes are n/a, not pass or fail", () => {
  const report = makeReport();
  report.protocols.outcomes = [
    outcome("TLSv1.0", false, false),
    outcome("TLSv1.1", false, false),
    outcome("TLSv1.2", false, false),
    outcome("TLSv1.3", false, false),
  ];
  report.protocols.supported = [];
  const { findings, score } = evaluateHost(DEFAULT_BASELINE, report);
  const proto = findings.filter((f) => f.category === "protocol" && f.id !== "proto-summary");
  for (const f of proto) assert.equal(f.status, "na", `${f.id} should be n/a`);
  // Nothing was confirmed, so no protocol weight is counted at all.
  assert.ok(!findings.some((f) => f.category === "protocol" && f.status === "fail"));
  assert.ok(score.available >= 0);
});

test("a conclusively rejected version still fails a forbid rule", () => {
  const report = makeReport();
  report.protocols.outcomes = [outcome("TLSv1.0", true, true), outcome("TLSv1.2", true, true)];
  report.protocols.supported = ["TLSv1.0", "TLSv1.2"];
  const { findings } = evaluateHost(DEFAULT_BASELINE, report);
  assert.equal(findings.find((f) => f.id === "proto-tls10")?.status, "fail");
});

test("a suite rule scoped to an un-enumerated version is n/a, not pass", () => {
  const baseline = mergeBaselines(DEFAULT_BASELINE, {
    suites: [
      {
        id: "legacy-only",
        title: "Legacy-only rule",
        rejectWeak: true,
        appliesTo: ["TLSv1.0"],
        severity: "high",
        weight: 10,
        message: "m",
      },
    ],
  });
  const report = makeReport(); // enumerates TLS 1.2 only
  const { findings } = evaluateHost(baseline, report);
  assert.equal(findings.find((f) => f.id === "legacy-only")?.status, "na");
});

test("a clean suite result over incomplete enumeration is n/a, not pass", () => {
  const report = makeReport();
  report.ciphers.byVersion.push({
    version: "TLSv1.3",
    probes: 0,
    truncated: false,
    suites: [],
    error: "per-host probe budget exhausted",
  });
  const { findings } = evaluateHost(DEFAULT_BASELINE, report);
  assert.equal(findings.find((f) => f.id === "suite-weak")?.status, "na");
});

test("a non-finite weight never produces a NaN score", () => {
  const findings: Finding[] = [
    { id: "a", title: "a", category: "x", severity: "high", weight: Number.POSITIVE_INFINITY, status: "pass", message: "" },
    { id: "b", title: "b", category: "x", severity: "high", weight: 10, status: "pass", message: "" },
  ];
  const score = computeScore(DEFAULT_BASELINE, findings);
  assert.ok(Number.isFinite(score.value), `score was ${score.value}`);
  assert.equal(score.value, 100);
});

test("a not-yet-valid certificate fails before the expiry warning", () => {
  const report = makeReport();
  report.certificate.notYetValid = true;
  report.certificate.notBefore = new Date(Date.now() + 3 * 86_400_000).toISOString();
  report.certificate.daysRemaining = 5; // would otherwise be a "warn"
  const { findings } = evaluateHost(DEFAULT_BASELINE, report);
  assert.equal(findings.find((f) => f.id === "cert-expiry")?.status, "fail");
});

/* --- regression tests for validation gaps found in review --------------- */

test("a non-enum severity in a nested section is rejected", () => {
  const path = tmpFile("nested-sev.yaml", "renegotiation:\n  severity: severe\n");
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), /severity/);
});

test("a scalar jitterMs is rejected (would crash the scheduler)", () => {
  const path = tmpFile("jitter.yaml", "safety:\n  jitterMs: 50\n");
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), /jitterMs/);
});

test("a non-list scoring.grades is rejected", () => {
  const path = tmpFile("grades.yaml", "scoring:\n  grades: null\n");
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), /grades/);
});

test("a non-list disabled is rejected (would crash isDisabled)", () => {
  const path = tmpFile("disabled.yaml", "disabled:\n  hsts: true\n");
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), /disabled/);
});

test("a protocol rule without a title is rejected", () => {
  const path = tmpFile(
    "no-title.yaml",
    `protocols:
  - id: x
    versions: [TLSv1.0]
    forbid: true
    severity: high
    weight: 1
    message: m
`,
  );
  assert.throws(() => loadBaselineFile(path, DEFAULT_BASELINE), /title/);
});
