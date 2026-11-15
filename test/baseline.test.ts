/**
 * Baseline evaluation tests.
 *
 * These run on synthetic EndpointResults so each check can be exercised
 * without a network. The cases that matter most are the ones where a naive
 * implementation silently does the wrong thing: unreachable endpoints scoring
 * 100, skipped checks inflating a score, informational checks moving the
 * number, and version comparisons being done lexicographically.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateBaseline } from '../src/baseline/evaluate.ts';
import type { Finding, CheckSeverity } from '../src/baseline/evaluate.ts';
import { describeSuite } from '../src/tls/suites.ts';
import type { EndpointResult, VersionResult } from '../src/types.ts';
import type { Baseline } from '../src/baseline/evaluate.ts';

function version(name: VersionResult['version'], suites: number[], supported = true): VersionResult {
  return {
    version: name,
    supported,
    suites: suites.map(describeSuite),
    selectedSuite: suites.length ? describeSuite(suites[0]!) : undefined,
    enumerationTruncated: false,
    ...(supported ? {} : { failure: { kind: 'alert' as const, alert: 70, message: 'protocol_version' } }),
  };
}

function endpoint(over: Partial<EndpointResult> = {}): EndpointResult {
  const versions: VersionResult[] = over.versions ?? [
    version('TLSv1.0', [], false),
    version('TLSv1.1', [], false),
    version('TLSv1.2', [0xc02f, 0xc030]),
    version('TLSv1.3', [0x1301, 0x1302]),
  ];
  return {
    host: 'svc.internal',
    port: 443,
    label: 'svc.internal:443',
    reachable: true,
    highestVersion: 'TLSv1.3',
    versions,
    suites: versions.flatMap((v) => v.suites),
    preference: {
      version: 'TLSv1.2',
      firstChoice: describeSuite(0xc02f),
      secondChoice: describeSuite(0xc02f),
      serverPrefers: true,
      conclusive: true,
    },
    renegotiation: {
      secureRenegotiationSupported: true,
      clientInitiatedAccepted: false,
      conclusive: true,
      applicable: true,
      detail: 'server explicitly refused',
      testedOn: 'TLSv1.2',
    },
    ocsp: {
      stapled: true,
      responseBytes: 1200,
      certificateStatus: 'good',
      statusRequestExtension: true,
      observedOn: ['TLSv1.2'],
      detail: 'stapled',
    },
    hsts: {
      fetched: true,
      header: 'max-age=31536000; includeSubDomains; preload',
      present: true,
      maxAge: 31536000,
      longMaxAge: true,
      includeSubDomains: true,
      preload: true,
      duplicates: false,
      problems: [],
      httpStatus: 200,
      source: 'https-handshake',
    },
    certificate: {
      subject: 'CN=svc',
      issuer: 'CN=Internal CA',
      validFrom: '2026-01-01T00:00:00Z',
      validTo: '2027-01-01T00:00:00Z',
      daysUntilExpiry: 400,
      expired: false,
      keyType: 'rsa',
      keySize: 2048,
      signatureAlgorithm: 'sha256WithRSAEncryption',
      sha1Signature: false,
      selfSigned: false,
      subjectAltNames: ['DNS:svc.internal'],
      chainLength: 2,
    },
    warnings: [],
    durationMs: 0,
    ...over,
  };
}

const baseline: Baseline = {
  id: 'test',
  name: 'test baseline',
  checks: [
    { id: 'min-version', kind: 'version-minimum', params: { minimumVersion: 'TLSv1.2' }, weight: 20, severity: 'critical' },
    { id: 'no-weak', kind: 'no-weak-suites', weight: 20, severity: 'high' },
    { id: 'no-insecure', kind: 'no-insecure-suites', weight: 20, severity: 'critical' },
    { id: 'pref', kind: 'server-cipher-preference', weight: 10, severity: 'medium' },
    { id: 'reneg', kind: 'secure-renegotiation', weight: 10, severity: 'high' },
    { id: 'no-client-reneg', kind: 'no-client-renegotiation', weight: 10, severity: 'medium' },
    { id: 'ocsp', kind: 'ocsp-stapling', params: { required: true }, weight: 10, severity: 'low' },
    { id: 'hsts', kind: 'hsts-present', weight: 10, severity: 'medium' },
    { id: 'info', kind: 'hsts-include-subdomains', weight: 50, severity: 'info', informational: true },
  ],
};

test('a clean endpoint scores 100', () => {
  const r = evaluateBaseline(baseline, endpoint());
  assert.equal(r.score.score, 100, JSON.stringify(r.findings.filter((f) => !f.passed)));
  assert.equal(r.score.grade, 'A');
  assert.equal(r.worstSeverity, undefined);
});

test('an unreachable endpoint scores 0, never 100', () => {
  const r = evaluateBaseline(
    baseline,
    endpoint({ reachable: false, versions: [], suites: [], preference: undefined, ocsp: undefined, hsts: undefined, certificate: undefined }),
  );
  assert.equal(r.score.score, 0);
  assert.equal(r.score.grade, 'F');
  assert.equal(r.worstSeverity, 'critical');
  assert.equal(r.findings[0]!.checkId, 'connectivity');
});

test('a port that answers but does not speak TLS is called out as misconfigured', () => {
  const r = evaluateBaseline(
    baseline,
    endpoint({ reachable: false, tlsAbsent: true, versions: [], suites: [] }),
  );
  assert.match(r.findings[0]!.message, /does not serve TLS/);
  assert.equal(r.score.score, 0);
});

test('informational checks do not move the score', () => {
  const withInfo = evaluateBaseline(baseline, endpoint({ hsts: { ...endpoint().hsts!, includeSubDomains: false } }));
  assert.equal(withInfo.score.score, 100, 'an informational failure must not cost points');
  const failed = withInfo.findings.find((f) => f.checkId === 'info');
  assert.equal(failed?.passed, false);
  assert.equal(failed?.informational, true);
});

test('skipped checks are excluded from both numerator and denominator', () => {
  // No OCSP data at all: the ocsp check is skipped, so it can neither pass nor
  // fail, and the remaining points still total 100.
  const r = evaluateBaseline(baseline, endpoint({ ocsp: undefined }));
  assert.equal(r.score.skipped, 1);
  // Weighted checks total 100; the skipped 10-point OCSP check is excluded.
  assert.equal(r.score.possible, 100, 'the 10-point OCSP check is excluded from the denominator');
  assert.equal(r.score.score, 100);
});

test('TLS 1.0/1.1 enabled is critical and costly', () => {
  const r = evaluateBaseline(
    baseline,
    endpoint({
      versions: [version('TLSv1.0', [0x002f]), version('TLSv1.1', []), version('TLSv1.2', [0xc02f]), version('TLSv1.3', [0x1301])],
      suites: [describeSuite(0x002f), describeSuite(0xc02f), describeSuite(0x1301)],
    }),
  );
  const f = r.findings.find((x) => x.checkId === 'min-version');
  assert.equal(f?.passed, false);
  assert.equal(f?.severity, 'critical');
  assert.ok(f?.evidence?.includes('TLSv1.0'));
  assert.ok(r.score.score < 100);
  assert.equal(r.worstSeverity, 'critical');
});

test('version-minimum treats TLS 1.0 as above nothing and below 1.2 correctly', () => {
  // A baseline that only forbids TLS 1.0 must not complain about TLS 1.1.
  const onlyTls10: Baseline = {
    ...baseline,
    checks: [{ id: 'v', kind: 'version-forbidden', params: { versions: ['TLSv1.0'] }, weight: 10, severity: 'high' }],
  };
  const r = evaluateBaseline(
    onlyTls10,
    endpoint({ versions: [version('TLSv1.0', [], false), version('TLSv1.1', [0xc013]), version('TLSv1.2', [0xc02f])] }),
  );
  assert.equal(r.findings[0]!.passed, true);
});

test('a revoked OCSP staple is a failure even though "stapled" is true', () => {
  const r = evaluateBaseline(baseline, endpoint({ ocsp: { ...endpoint().ocsp!, certificateStatus: 'revoked' } }));
  const f = r.findings.find((x) => x.checkId === 'ocsp');
  assert.equal(f?.passed, false);
  assert.match(f!.message, /REVOKED/);
});

test('client-preference failure is reported with both probe outcomes', () => {
  const r = evaluateBaseline(
    baseline,
    endpoint({
      preference: {
        version: 'TLSv1.2',
        firstChoice: describeSuite(0xc02f),
        secondChoice: describeSuite(0x002f),
        serverPrefers: false,
        conclusive: true,
      },
    }),
  );
  const f = r.findings.find((x) => x.checkId === 'pref');
  assert.equal(f?.passed, false);
  assert.equal(f?.evidence?.length, 2);
});

test('an inconclusive preference experiment is skipped, not failed', () => {
  const r = evaluateBaseline(
    baseline,
    endpoint({ preference: { version: 'TLSv1.2', serverPrefers: false, conclusive: false, failure: { kind: 'timeout', message: 'no reply' } } }),
  );
  const f = r.findings.find((x) => x.checkId === 'pref');
  assert.equal(f?.skipped, true);
  assert.equal(f?.passed, false);
});

test('TLS 1.3-only endpoint: renegotiation checks pass by construction', () => {
  const tls13Only = endpoint({
    versions: [version('TLSv1.0', [], false), version('TLSv1.1', [], false), version('TLSv1.2', [], false), version('TLSv1.3', [0x1301])],
    suites: [describeSuite(0x1301)],
    renegotiation: { secureRenegotiationSupported: false, clientInitiatedAccepted: false, conclusive: false, applicable: false, detail: 'no TLS 1.2' },
  });
  const r = evaluateBaseline(baseline, tls13Only);
  assert.equal(r.findings.find((x) => x.checkId === 'reneg')?.passed, true, 'no legacy version means nothing to secure');
  assert.equal(r.score.score, 100);
});

test('an expired certificate fails the validity check', () => {
  const cert = { ...endpoint().certificate!, expired: true, daysUntilExpiry: -5, validTo: '2026-01-01T00:00:00Z' };
  const b: Baseline = {
    ...baseline,
    checks: [{ id: 'cert', kind: 'certificate-valid', params: { minimumDaysRemaining: 14 }, weight: 10, severity: 'high' }],
  };
  const r = evaluateBaseline(b, endpoint({ certificate: cert }));
  assert.equal(r.findings[0]!.passed, false);
});

test('certificate-signature bans are matched case-insensitively', () => {
  const b: Baseline = {
    ...baseline,
    checks: [{ id: 'sig', kind: 'certificate-signature', params: { forbid: ['sha1'] }, weight: 10, severity: 'critical' }],
  };
  const r = evaluateBaseline(b, endpoint({ certificate: { ...endpoint().certificate!, signatureAlgorithm: 'SHA1withRSAEncryption' } }));
  assert.equal(r.findings[0]!.passed, false);
});

test('certificate-key-strength applies the right minimum per key type', () => {
  const b: Baseline = {
    ...baseline,
    checks: [{ id: 'key', kind: 'certificate-key-strength', params: { minimumRsaBits: 2048, minimumEcBits: 256 }, weight: 10, severity: 'high' }],
  };
  const weakRsa = evaluateBaseline(b, endpoint({ certificate: { ...endpoint().certificate!, keyType: 'rsa', keySize: 1024 } }));
  assert.equal(weakRsa.findings[0]!.passed, false);
  const okEc = evaluateBaseline(b, endpoint({ certificate: { ...endpoint().certificate!, keyType: 'ec', keySize: 256 } }));
  assert.equal(okEc.findings[0]!.passed, true);
});

test('custom-suite-forbidden matches by IANA name, OpenSSL name and hex id', () => {
  const b: Baseline = {
    ...baseline,
    checks: [
      {
        id: 'forbid',
        kind: 'custom-suite-forbidden',
        params: { suites: ['0x002f', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'] },
        weight: 10,
        severity: 'high',
      },
    ],
  };
  const withBoth = endpoint({
    versions: [version('TLSv1.0', [], false), version('TLSv1.1', [], false), version('TLSv1.2', [0xc02f, 0x002f]), version('TLSv1.3', [0x1301])],
  });
  const r = evaluateBaseline(b, withBoth);
  const f = r.findings[0]!;
  assert.equal(f.passed, false);
  assert.equal(f.evidence?.length, 2, 'both the hex-id and the IANA-name form must match');
});

test('severity summary counts only failed, non-informational findings', () => {
  const withFinding = evaluateBaseline(baseline, endpoint({ hsts: { ...endpoint().hsts!, present: false } }));
  const clean = evaluateBaseline(baseline, endpoint());
  const count = (findings: Finding[], sev: CheckSeverity) =>
    findings.filter((f) => !f.skipped && !f.passed && !f.informational && f.severity === sev).length;
  assert.equal(count(withFinding.findings, 'medium'), 1);
  assert.equal(count(clean.findings, 'medium'), 0);
});

test('an inconclusive renegotiation test is skipped, not counted as a pass', () => {
  const r = evaluateBaseline(
    baseline,
    endpoint({
      renegotiation: {
        secureRenegotiationSupported: true,
        clientInitiatedAccepted: false,
        conclusive: false,
        applicable: true,
        detail: 'server neither answered nor refused within 1200ms',
        testedOn: 'TLSv1.2',
      },
    }),
  );
  const f = r.findings.find((x) => x.checkId === 'no-client-reneg');
  assert.equal(f?.skipped, true, 'silence is not proof of refusal');
  assert.ok(r.score.skipped >= 1);
});

test('a conclusive refusal counts as a pass', () => {
  const r = evaluateBaseline(
    baseline,
    endpoint({
      renegotiation: {
        secureRenegotiationSupported: true,
        clientInitiatedAccepted: false,
        conclusive: true,
        applicable: true,
        detail: 'server explicitly refused',
        testedOn: 'TLSv1.2',
      },
    }),
  );
  const f = r.findings.find((x) => x.checkId === 'no-client-reneg');
  assert.equal(f?.passed, true);
  assert.equal(f?.skipped, false);
});
