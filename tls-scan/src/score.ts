import { Baseline } from './baseline';
import { Finding, ScanResult, ScoreReport, Severity } from './types';

const VERSION_ORDER = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];

function gradeOf(score: number): ScoreReport['grade'] {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 45) return 'D';
  return 'F';
}

export function scoreScan(result: ScanResult, baseline: Baseline): ScoreReport {
  const findings: Finding[] = [];
  const w = baseline.weights;
  const add = (severity: Severity, check: string, message: string, deduction: number) =>
    findings.push({ severity, check, message, deduction });

  if (result.error) {
    add('critical', 'connectivity', `scan failed: ${result.error}`, 100);
    return { score: 0, grade: 'F', findings };
  }

  // ---- protocol versions ----
  const supported = new Set(result.versions.filter((v) => v.supported).map((v) => v.version));
  for (const v of baseline.forbiddenProtocols) {
    if (supported.has(v)) {
      add('critical', 'protocol', `forbidden protocol ${v} is enabled`, w.forbiddenProtocol);
    }
  }
  const minIdx = VERSION_ORDER.indexOf(baseline.minProtocol);
  for (let i = 0; i < minIdx; i++) {
    const v = VERSION_ORDER[i];
    if (supported.has(v as never) && !baseline.forbiddenProtocols.includes(v as never)) {
      add('high', 'protocol', `${v} is below the baseline minimum ${baseline.minProtocol}`, w.forbiddenProtocol);
    }
  }
  if (baseline.recommendTls13 && !supported.has('TLSv1.3')) {
    add('low', 'protocol', 'TLS 1.3 is not enabled', w.missingTls13);
  }

  // ---- ciphers ----
  const weakRe = baseline.weakCipherPatterns.map((p) => new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));
  const weak = new Set<string>();
  const nonPfs = new Set<string>();
  for (const ce of result.ciphers) {
    for (const c of ce.ciphers) {
      const name = c.opensslName;
      if (weakRe.some((re) => re.test(name))) weak.add(name);
      if (ce.version !== 'TLSv1.3' && !/^(EC)?DHE[-_]/i.test(name)) nonPfs.add(name);
    }
  }
  if (weak.size > 0) {
    const deduction = Math.min(weak.size * w.weakCipher, w.weakCipherCap);
    add('high', 'cipher', `weak ciphers enabled: ${[...weak].join(', ')}`, deduction);
  }
  if (baseline.penalizeNonPfs && nonPfs.size > 0) {
    const deduction = Math.min(nonPfs.size * w.nonPfsCipher, w.nonPfsCap);
    add('medium', 'cipher', `ciphers without forward secrecy: ${[...nonPfs].join(', ')}`, deduction);
  }

  // ---- cipher order ----
  if (baseline.requireServerCipherOrder && result.cipherOrder.tested && result.cipherOrder.enforcesServerOrder === false) {
    add('medium', 'cipher-order', 'server does not enforce its own cipher order (client picks)', w.cipherOrder);
  }

  // ---- renegotiation ----
  if (result.renegotiation.secureRenegotiationExt === false) {
    add('medium', 'renegotiation', 'server does not advertise secure renegotiation (renegotiation_info absent)', w.renegotiationInfoMissing);
  }
  if (result.renegotiation.clientInitiatedAllowed === true) {
    add('low', 'renegotiation', 'server permits client-initiated renegotiation (DoS vector)', w.clientRenegotiationAllowed);
  }

  // ---- OCSP stapling ----
  if (baseline.ocspStapling !== 'ignore' && result.ocspStapling === false) {
    const sev: Severity = baseline.ocspStapling === 'required' ? 'medium' : 'low';
    add(sev, 'ocsp', 'OCSP stapling is not enabled', w.ocspMissing);
  }

  // ---- HSTS ----
  if (result.hsts && !result.hsts.nonHttp) {
    if (!result.hsts.present) {
      if (baseline.hsts.required) add('medium', 'hsts', 'Strict-Transport-Security header missing', w.hstsMissing);
      else add('low', 'hsts', 'Strict-Transport-Security header missing', w.hstsMissing);
    } else {
      if (result.hsts.maxAge !== undefined && result.hsts.maxAge < baseline.hsts.minMaxAge) {
        add('low', 'hsts', `HSTS max-age ${result.hsts.maxAge}s is below baseline ${baseline.hsts.minMaxAge}s`, w.hstsShortMaxAge);
      }
      if (baseline.hsts.requireIncludeSubDomains && !result.hsts.includeSubDomains) {
        add('low', 'hsts', 'HSTS lacks includeSubDomains', w.hstsNoIncludeSubDomains);
      }
    }
  }

  // ---- certificate ----
  if (result.cert) {
    if (result.cert.daysRemaining < 0) {
      add('critical', 'cert', `certificate expired ${-result.cert.daysRemaining} days ago`, w.certExpired);
    } else if (result.cert.daysRemaining < baseline.cert.expiringSoonDays) {
      add('low', 'cert', `certificate expires in ${result.cert.daysRemaining} days`, w.certExpiringSoon);
    }
    if (baseline.cert.penalizeSelfSigned && result.cert.selfSigned) {
      add('low', 'cert', 'certificate is self-signed', w.certSelfSigned);
    }
  }

  const total = findings.reduce((s, f) => s + f.deduction, 0);
  const score = Math.max(0, 100 - total);
  return { score, grade: gradeOf(score), findings };
}
