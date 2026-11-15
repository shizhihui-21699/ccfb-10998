/**
 * Baseline: a configurable list of checks, each with a weight and a severity.
 *
 * The baseline is data, not code: it ships as a JSON file (baseline/default.json)
 * that an operator can copy and edit. This module implements the *evaluator*:
 * it applies check definitions to an EndpointResult and produces findings plus
 * a 0-100 score.
 *
 * Scoring model
 * -------------
 *   score = round(100 * earned / possible), where
 *     possible = sum of weights of checks that were *applicable* to the endpoint
 *     earned   = possible - sum of weights of applicable checks that failed
 *
 * Checks can be `informational`, in which case they produce findings but do
 * not move the score (HSTS preload eligibility, for example, is a nice-to-have).
 * A check whose required data could not be collected is `skipped`, not failed,
 * and is excluded from both numerator and denominator, so an unreachable
 * endpoint does not silently score zero on things that were never measurable.
 */
import type { EndpointResult, SuiteInfo, TlsVersionName } from '../types.ts';

export type CheckSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type CheckKind =
  | 'version-minimum'
  | 'version-forbidden'
  | 'no-weak-suites'
  | 'no-insecure-suites'
  | 'forward-secrecy-required'
  | 'server-cipher-preference'
  | 'secure-renegotiation'
  | 'no-client-renegotiation'
  | 'ocsp-stapling'
  | 'hsts-present'
  | 'hsts-max-age'
  | 'hsts-include-subdomains'
  | 'certificate-valid'
  | 'certificate-key-strength'
  | 'certificate-signature'
  | 'tls13-preferred'
  | 'custom-suite-forbidden';

export interface BaselineCheck {
  /** Stable identifier used in output and for overrides. */
  id: string;
  /** Which built-in evaluation to run. */
  kind: CheckKind;
  /** Points deducted from 100 when the check fails. */
  weight: number;
  severity: CheckSeverity;
  /** Does not affect the score. */
  informational?: boolean;
  /** Overrides for the check's parameters (e.g. minimumVersion, forbidden suites). */
  params?: Record<string, unknown>;
  /** Why the check matters, shown alongside a failure in reports. */
  message?: string;
}

export interface Baseline {
  id: string;
  name: string;
  description?: string;
  checks: BaselineCheck[];
  /** Minimum score for the endpoint to be considered compliant. */
  passScore?: number;
}

export interface Finding {
  checkId: string;
  kind: CheckKind;
  severity: CheckSeverity;
  weight: number;
  passed: boolean;
  skipped: boolean;
  /** Human-readable explanation. */
  message: string;
  /** Concrete evidence (suite names, versions, header values). */
  evidence?: string[];
  /**
   * The baseline author's rationale for this check (the `message` field in the
   * baseline JSON). Shown alongside a failure so the reader gets the "why", not
   * just the "what".
   */
  rationale?: string;
  informational: boolean;
}

export interface ScoreBreakdown {
  score: number;
  possible: number;
  earned: number;
  passed: number;
  failed: number;
  skipped: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface EndpointAssessment {
  label: string;
  host: string;
  port: number;
  findings: Finding[];
  score: ScoreBreakdown;
  /** Worst severity among failed, non-informational checks. */
  worstSeverity?: CheckSeverity;
  compliant: boolean;
}

const SEVERITY_RANK: Record<CheckSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Version ordering used by `version-minimum` / `version-forbidden`.
 * `minimumVersion` means "every version below this must be disabled".
 */
const VERSION_ORDER: TlsVersionName[] = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];

function versionsBelow(min: TlsVersionName): TlsVersionName[] {
  const idx = VERSION_ORDER.indexOf(min);
  return VERSION_ORDER.slice(0, idx);
}

function supportedVersions(r: EndpointResult): TlsVersionName[] {
  return r.versions.filter((v) => v.supported).map((v) => v.version);
}

function weakSuites(r: EndpointResult): SuiteInfo[] {
  return r.suites.filter((s) => s.strength === 'weak');
}
function insecureSuites(r: EndpointResult): SuiteInfo[] {
  return r.suites.filter((s) => s.strength === 'insecure' || s.strength === 'null');
}

function suiteEvidence(suites: SuiteInfo[]): string[] {
  return suites.map((s) => `${s.name}${s.opensslName && s.opensslName !== s.name ? ` (${s.opensslName})` : ''} — ${s.notes.join('; ')}`);
}

export interface EvaluateResult {
  findings: Finding[];
  score: ScoreBreakdown;
  worstSeverity?: CheckSeverity;
}

/** Evaluates a baseline against one endpoint. */
export function evaluateBaseline(baseline: Baseline, r: EndpointResult): EvaluateResult {
  const findings: Finding[] = [];

  for (const check of baseline.checks) {
    findings.push(runCheck(check, r));
  }

  // An endpoint we could not reach has not passed anything. Without this guard
  // every check is skipped, `possible` becomes 0, and the endpoint would score
  // a perfect 100 — the exact inverse of the truth. Report 0 and say why.
  if (!r.reachable) {
    const unreachable: Finding = {
      checkId: 'connectivity',
      kind: 'version-minimum',
      severity: 'critical',
      weight: 100,
      passed: false,
      skipped: false,
      informational: false,
      message: r.tlsAbsent
        ? 'the port is open but does not serve TLS; the endpoint is misconfigured rather than merely unreachable'
        : `endpoint could not be probed: ${r.warnings[0] ?? 'no TLS connection was established'}`,
    };
    const scored = findings.filter((f) => !f.skipped && !f.informational);
    return {
      findings: [unreachable, ...findings],
      score: {
        score: 0,
        possible: 100,
        earned: 0,
        passed: 0,
        failed: scored.filter((f) => !f.passed).length + 1,
        skipped: findings.filter((f) => f.skipped).length,
        grade: 'F',
      },
      worstSeverity: 'critical',
    };
  }

  const scored = findings.filter((f) => !f.skipped && !f.informational);
  const possible = scored.reduce((n, f) => n + f.weight, 0);
  const lost = scored.filter((f) => !f.passed).reduce((n, f) => n + f.weight, 0);
  const earned = possible - lost;
  const score = possible === 0 ? 100 : Math.round((earned / possible) * 100);

  const failed = scored.filter((f) => !f.passed);
  const worstSeverity = failed
    .map((f) => f.severity)
    .sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b])[0];

  return {
    findings,
    score: {
      score,
      possible,
      earned,
      passed: scored.filter((f) => f.passed).length,
      failed: failed.length,
      skipped: findings.filter((f) => f.skipped).length,
      grade: gradeFor(score),
    },
    ...(worstSeverity ? { worstSeverity } : {}),
  };
}

function gradeFor(score: number): ScoreBreakdown['grade'] {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function skip(check: BaselineCheck, reason: string): Finding {
  return {
    checkId: check.id,
    kind: check.kind,
    severity: check.severity,
    weight: check.weight,
    passed: false,
    skipped: true,
    informational: check.informational ?? false,
    message: `not evaluated: ${reason}`,
  };
}

function result(
  check: BaselineCheck,
  passed: boolean,
  message: string,
  evidence?: string[],
): Finding {
  return {
    checkId: check.id,
    kind: check.kind,
    severity: check.severity,
    weight: check.weight,
    passed,
    skipped: false,
    informational: check.informational ?? false,
    message,
    ...(evidence && evidence.length ? { evidence } : {}),
    ...(check.message ? { rationale: check.message } : {}),
  };
}

function runCheck(check: BaselineCheck, r: EndpointResult): Finding {
  const params = check.params ?? {};
  switch (check.kind) {
    // ---------------------------------------------------------------- versions
    case 'version-minimum': {
      if (!r.reachable) return skip(check, 'endpoint is not reachable');
      const min = (params.minimumVersion as TlsVersionName | undefined) ?? 'TLSv1.2';
      const forbidden = versionsBelow(min);
      const enabled = supportedVersions(r).filter((v) => forbidden.includes(v));
      return enabled.length === 0
        ? result(check, true, `no protocol version below ${min} is enabled`)
        : result(check, false, `protocol versions below ${min} should be disabled but are enabled: ${enabled.join(', ')}`, enabled);
    }

    case 'version-forbidden': {
      if (!r.reachable) return skip(check, 'endpoint is not reachable');
      const forbidden = (params.versions as TlsVersionName[] | undefined) ?? [];
      const enabled = supportedVersions(r).filter((v) => forbidden.includes(v));
      return enabled.length === 0
        ? result(check, true, `none of the forbidden versions are enabled`)
        : result(check, false, `forbidden protocol version(s) enabled: ${enabled.join(', ')}`, enabled);
    }

    case 'tls13-preferred': {
      if (!r.reachable) return skip(check, 'endpoint is not reachable');
      const wants = params.required !== false;
      const has = supportedVersions(r).includes('TLSv1.3');
      if (!wants) return result(check, true, 'TLS 1.3 is not required by this baseline');
      return has
        ? result(check, true, 'TLS 1.3 is supported')
        : result(check, false, 'TLS 1.3 is not supported; modern clients will fall back to TLS 1.2');
    }

    // ------------------------------------------------------------------ suites
    case 'no-weak-suites': {
      if (!r.reachable) return skip(check, 'endpoint is not reachable');
      const weak = weakSuites(r);
      return weak.length === 0
        ? result(check, true, 'no weak cipher suites were accepted')
        : result(check, false, `${weak.length} weak cipher suite(s) accepted: ${weak.map((s) => s.name).join(', ')}`, suiteEvidence(weak));
    }

    case 'no-insecure-suites': {
      if (!r.reachable) return skip(check, 'endpoint is not reachable');
      const bad = insecureSuites(r);
      return bad.length === 0
        ? result(check, true, 'no broken cipher suites (RC4, export, NULL, anonymous) were accepted')
        : result(check, false, `${bad.length} broken cipher suite(s) accepted: ${bad.map((s) => s.name).join(', ')}`, suiteEvidence(bad));
    }

    case 'forward-secrecy-required': {
      if (!r.reachable) return skip(check, 'endpoint is not reachable');
      const noFs = r.suites.filter((s) => !s.forwardSecret && s.strength !== 'null' && s.strength !== 'insecure');
      // Only a problem if *every* non-broken suite lacks FS, or if a suite was
      // actually negotiated without it. We cannot see per-version negotiation
      // here, so flag any non-FS non-broken suite as a finding.
      return noFs.length === 0
        ? result(check, true, 'every offered suite provides forward secrecy')
        : result(
            check,
            false,
            `${noFs.length} suite(s) without forward secrecy are accepted: ${noFs.map((s) => s.name).join(', ')}`,
            suiteEvidence(noFs),
          );
    }

    case 'custom-suite-forbidden': {
      if (!r.reachable) return skip(check, 'endpoint is not reachable');
      const ids = new Set<number>();
      for (const raw of (params.suites as Array<string | number> | undefined) ?? []) {
        if (typeof raw === 'number') ids.add(raw);
        else if (/^0x[0-9a-f]+$/i.test(raw)) ids.add(parseInt(raw.slice(2), 16));
        else {
          const found = r.suites.find((s) => s.name === raw || s.opensslName === raw);
          if (found) ids.add(found.id);
        }
      }
      const hit = r.suites.filter((s) => ids.has(s.id));
      return hit.length === 0
        ? result(check, true, 'none of the explicitly forbidden suites are accepted')
        : result(check, false, `explicitly forbidden suite(s) accepted: ${hit.map((s) => s.name).join(', ')}`, suiteEvidence(hit));
    }

    // -------------------------------------------------------------- preference
    case 'server-cipher-preference': {
      const pref = r.preference;
      if (!pref) return skip(check, 'no version with at least two suites was available for the preference test');
      if (!pref.conclusive) return skip(check, `the preference experiment was inconclusive${pref.failure ? `: ${pref.failure.message}` : ''}`);
      if (pref.serverPrefers) {
        return result(check, true, `server enforces its own suite order on ${pref.version}`);
      }
      // TLS 1.3 servers must prefer their own order per RFC 8446; a TLS 1.2
      // server following client order is a real weakness but a milder one.
      return result(
        check,
        false,
        `server follows the client's suite order on ${pref.version}; a client can steer it to a weaker suite`,
        [
          `offered ${pref.firstChoice?.name} first -> server chose ${pref.firstChoice?.name}`,
          `offered ${pref.secondChoice?.name} first -> server chose ${pref.secondChoice?.name}`,
        ],
      );
    }

    // ---------------------------------------------------------- renegotiation
    case 'secure-renegotiation': {
      if (!r.renegotiation) return skip(check, 'renegotiation was not probed');
      // A TLS 1.3-only server has no renegotiation to secure; the extension is
      // not applicable and the check passes by construction.
      const legacyEnabled = supportedVersions(r).some((v) => v !== 'TLSv1.3');
      if (!legacyEnabled) {
        return result(check, true, 'only TLS 1.3 is enabled, which does not support renegotiation at all');
      }
      return r.renegotiation.secureRenegotiationSupported
        ? result(check, true, 'server implements secure renegotiation (RFC 5746)')
        : result(check, false, 'server did not signal secure renegotiation (RFC 5746) in its ServerHello');
    }

    case 'no-client-renegotiation': {
      if (!r.renegotiation) return skip(check, 'renegotiation was not probed');
      if (!r.renegotiation.applicable) {
        return skip(check, 'no TLS 1.2 or older connection was available for the live renegotiation test');
      }
      // Silence is not a pass: a non-HTTP service that ignores the renegotiation
      // ClientHello leaves the question open. Skip rather than award the points.
      if (!r.renegotiation.conclusive && !r.renegotiation.clientInitiatedAccepted) {
        return skip(check, `the live renegotiation test was inconclusive: ${r.renegotiation.detail}`);
      }
      if (r.renegotiation.clientInitiatedAccepted) {
        return result(
          check,
          false,
          `server accepted a client-initiated renegotiation on ${r.renegotiation.testedOn ?? 'TLS 1.2'} (DoS amplification risk)`,
          [r.renegotiation.detail],
        );
      }
      return result(check, true, `client-initiated renegotiation was not accepted${r.renegotiation.testedOn ? ` on ${r.renegotiation.testedOn}` : ''}`);
    }

    // -------------------------------------------------------------------- OCSP
    case 'ocsp-stapling': {
      if (!r.ocsp) return skip(check, 'OCSP stapling was not probed');
      if (r.ocsp.certificateStatus === 'revoked') {
        return result(check, false, 'the stapled OCSP response says the certificate is REVOKED', [r.ocsp.detail]);
      }
      if (r.ocsp.stapled) {
        return result(check, true, `OCSP stapling is working (${r.ocsp.responseBytes ?? 0} bytes on ${r.ocsp.observedOn.join(', ')})`, [r.ocsp.detail]);
      }
      const required = params.required !== false;
      if (!required) return result(check, true, 'OCSP stapling is not required by this baseline', [r.ocsp.detail]);
      return result(check, false, 'server does not staple OCSP responses; clients must query the responder themselves', [r.ocsp.detail]);
    }

    // -------------------------------------------------------------------- HSTS
    case 'hsts-present': {
      if (!r.hsts) return skip(check, 'HSTS was not checked');
      if (!r.hsts.fetched) return skip(check, `HSTS could not be retrieved: ${r.hsts.failure?.message ?? 'no HTTP response'}`);
      return r.hsts.present
        ? result(check, true, `Strict-Transport-Security is set (${r.hsts.header})`, [r.hsts.header ?? ''])
        : result(check, false, 'no Strict-Transport-Security header was returned');
    }

    case 'hsts-max-age': {
      if (!r.hsts) return skip(check, 'HSTS was not checked');
      if (!r.hsts.fetched || !r.hsts.present) return skip(check, 'no HSTS header to evaluate');
      const min = (params.minimumSeconds as number | undefined) ?? 15768000; // 6 months
      const maxAge = r.hsts.maxAge ?? 0;
      if (r.hsts.problems.length && r.hsts.maxAge === undefined) {
        return result(check, false, `HSTS max-age is missing or malformed: ${r.hsts.problems.join('; ')}`);
      }
      return maxAge >= min
        ? result(check, true, `HSTS max-age ${maxAge} >= ${min}`)
        : result(check, false, `HSTS max-age ${maxAge} is below the required ${min} seconds`);
    }

    case 'hsts-include-subdomains': {
      if (!r.hsts) return skip(check, 'HSTS was not checked');
      if (!r.hsts.fetched || !r.hsts.present) return skip(check, 'no HSTS header to evaluate');
      return r.hsts.includeSubDomains
        ? result(check, true, 'HSTS covers subdomains')
        : result(check, false, 'HSTS does not include includeSubDomains');
    }

    // ------------------------------------------------------------- certificate
    case 'certificate-valid': {
      if (!r.certificate) return skip(check, 'no certificate could be retrieved');
      const cert = r.certificate;
      const minDays = (params.minimumDaysRemaining as number | undefined) ?? 0;
      if (cert.expired) return result(check, false, `certificate expired on ${cert.validTo}`);
      if (cert.daysUntilExpiry < minDays) {
        return result(check, false, `certificate expires in ${cert.daysUntilExpiry} days (minimum ${minDays})`);
      }
      return result(check, true, `certificate is valid until ${cert.validTo} (${cert.daysUntilExpiry} days)`);
    }

    case 'certificate-key-strength': {
      if (!r.certificate) return skip(check, 'no certificate could be retrieved');
      const cert = r.certificate;
      const minRsa = (params.minimumRsaBits as number | undefined) ?? 2048;
      const minEc = (params.minimumEcBits as number | undefined) ?? 256;
      const needed = cert.keyType.startsWith('rsa') ? minRsa : cert.keyType === 'ec' ? minEc : 0;
      if (needed === 0) return result(check, true, `key type ${cert.keyType} is not subject to a size minimum in this baseline`);
      return cert.keySize >= needed
        ? result(check, true, `${cert.keyType.toUpperCase()} key is ${cert.keySize} bits`)
        : result(check, false, `${cert.keyType.toUpperCase()} key is only ${cert.keySize} bits (minimum ${needed})`);
    }

    case 'certificate-signature': {
      if (!r.certificate) return skip(check, 'no certificate could be retrieved');
      const banned = (params.forbid as string[] | undefined) ?? ['sha1'];
      const sig = r.certificate.signatureAlgorithm.toLowerCase();
      const hit = banned.find((b) => sig.includes(b.toLowerCase()));
      return hit
        ? result(check, false, `certificate is signed with ${r.certificate.signatureAlgorithm}, which is banned by this baseline`)
        : result(check, true, `certificate signature algorithm ${r.certificate.signatureAlgorithm} is acceptable`);
    }

    default: {
      const never: never = check.kind;
      return skip(check, `unknown check kind ${String(never)}`);
    }
  }
}

/** Summarises a set of assessments. */
export function summarizeAssessments(assessments: EndpointAssessment[]): {
  endpoints: number;
  compliant: number;
  averageScore: number;
  bySeverity: Record<CheckSeverity, number>;
} {
  const bySeverity: Record<CheckSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const a of assessments) {
    for (const f of a.findings) {
      if (!f.skipped && !f.passed && !f.informational) bySeverity[f.severity]++;
    }
  }
  const averageScore =
    assessments.length === 0 ? 100 : Math.round(assessments.reduce((n, a) => n + a.score.score, 0) / assessments.length);
  return {
    endpoints: assessments.length,
    compliant: assessments.filter((a) => a.compliant).length,
    averageScore,
    bySeverity,
  };
}
