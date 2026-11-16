/**
 * Turn raw probe results into baseline findings and a weighted score.
 *
 * Scoring model:
 *   - Each check contributes `weight` points when it passes, 0 when it fails,
 *     and half when it is a warning.
 *   - Checks that cannot apply (e.g. stapling when the certificate has no OCSP
 *     URL) are `na` and excluded from both numerator and denominator, so they
 *     never silently drag a score down.
 *   - The score is earned/available×100 over the applicable checks, then mapped
 *     to a letter grade by the baseline's thresholds.
 */
import type { Baseline, SuiteRule } from "../baseline/types.ts";
import type {
  CheckStatus,
  CipherProbe,
  Finding,
  HostEvaluation,
  HostReport,
  Score,
  Severity,
  SuiteEntry,
} from "../types.ts";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function isDisabled(baseline: Baseline, id: string): boolean {
  return (baseline.disabled ?? []).includes(id);
}

function finding(
  partial: Omit<Finding, "status"> & { status: CheckStatus },
): Finding {
  return { ...partial };
}

/* ------------------------------------------------------------- protocols */

function evaluateProtocols(baseline: Baseline, report: HostReport): Finding[] {
  const out: Finding[] = [];
  const supported = new Set(report.protocols.supported);
  // A version only counts as *absent* if the probe reached a definitive
  // verdict. Timeouts, connection errors and budget stops leave it unknown,
  // and an unknown version must never be scored as "not enabled".
  const conclusivelyAbsent = new Set(
    report.protocols.outcomes
      .filter((o) => o.conclusive && !o.supported)
      .map((o) => o.version),
  );

  for (const rule of baseline.protocols) {
    if (isDisabled(baseline, rule.id)) continue;
    const present = rule.versions.filter((v) => supported.has(v as never));
    const absent = rule.versions.filter((v) => conclusivelyAbsent.has(v as never));
    const unknown = rule.versions.filter(
      (v) => !supported.has(v as never) && !conclusivelyAbsent.has(v as never),
    );

    let status: CheckStatus;
    let detail: string;
    if (rule.forbid) {
      if (present.length > 0) {
        status = "fail";
        detail = `enabled: ${present.join(", ")}`;
      } else if (absent.length > 0) {
        // Confirmed off for at least one governed version and not observed on
        // any: a pass. Any unknown versions are noted but do not fail it.
        status = "pass";
        detail =
          `${absent.join(", ")} not enabled` +
          (unknown.length > 0 ? ` (unconfirmed: ${unknown.join(", ")})` : "");
      } else {
        status = "na";
        detail = `could not confirm ${rule.versions.join(", ")}`;
      }
    } else if (rule.require) {
      if (present.length === rule.versions.length) {
        status = "pass";
        detail = `available: ${present.join(", ")}`;
      } else if (absent.length > 0) {
        status = "fail";
        detail = `missing: ${absent.join(", ")}` +
          (unknown.length > 0 ? ` (unconfirmed: ${unknown.join(", ")})` : "");
      } else {
        status = "na";
        detail = `could not confirm ${rule.versions.join(", ")}`;
      }
    } else {
      status = "na";
      detail = "rule has neither forbid nor require";
    }

    out.push(
      finding({
        id: rule.id,
        title: rule.title,
        category: "protocol",
        severity: rule.severity,
        weight: rule.weight,
        status,
        message: `${rule.message} (${detail})`,
        evidence: { present, absent, unknown },
      }),
    );
  }

  // Informational: what the server actually supports.
  const anyConclusive = report.protocols.outcomes.some((o) => o.conclusive);
  out.push(
    finding({
      id: "proto-summary",
      title: "Supported protocol versions",
      category: "protocol",
      severity: "info",
      weight: 0,
      status: supported.size > 0 ? "pass" : anyConclusive ? "fail" : "na",
      message:
        supported.size > 0
          ? `supports ${[...supported].sort().join(", ")}`
          : anyConclusive
            ? "no supported TLS version detected"
            : "no conclusive protocol result (probes failed or were skipped)",
      evidence: { supported: [...supported] },
    }),
  );

  return out;
}

/* --------------------------------------------------------------- suites */

function allSuites(ciphers: CipherProbe): Array<SuiteEntry & { version: string }> {
  const out: Array<SuiteEntry & { version: string }> = [];
  for (const enumeration of ciphers.byVersion) {
    for (const suite of enumeration.suites) out.push({ ...suite, version: enumeration.version });
  }
  return out;
}
function ruleMatches(rule: SuiteRule, suite: SuiteEntry): boolean {
  if (rule.rejectWeak && suite.weak) return true;
  if (rule.rejectNoForwardSecrecy && !suite.forwardSecrecy) return true;
  if (rule.rejectAnonymous && suite.anonymous) return true;
  if (rule.rejectRsaKeyExchange && isStaticRsa(suite)) return true;
  if (rule.rejectLegacyEncryption && /RC4|3DES|DES|RC2|EXPORT|NULL/i.test(suite.enc)) return true;
  return false;
}

function isStaticRsa(suite: SuiteEntry): boolean {
  // Key exchange is plain RSA (not ECDHE/DHE/PSK): no forward secrecy.
  const kx = suite.kx.toUpperCase();
  return (kx === "RSA" || kx === "RSA(512)" || kx === "RSA(1024)") && !suite.anonymous;
}

function evaluateSuites(baseline: Baseline, report: HostReport): Finding[] {
  const out: Finding[] = [];
  const suites = allSuites(report.ciphers);
  const versionsTested = report.ciphers.byVersion.filter((e) => !e.error).map((e) => e.version);
  // Versions whose enumeration was incomplete (network error, budget stop, or
  // truncation) — a rule cannot claim a clean pass across a gap in coverage.
  const incomplete = new Set(
    report.ciphers.byVersion
      .filter((e) => e.error !== undefined || e.truncated || e.anomaly !== undefined)
      .map((e) => e.version),
  );

  for (const rule of baseline.suites) {
    if (isDisabled(baseline, rule.id)) continue;
    if (versionsTested.length === 0) {
      out.push(
        finding({
          id: rule.id,
          title: rule.title,
          category: "cipher",
          severity: rule.severity,
          weight: rule.weight,
          status: "na",
          message: "cipher enumeration unavailable",
        }),
      );
      continue;
    }

    const inScope = rule.appliesTo
      ? suites.filter((s) => rule.appliesTo!.includes(s.version))
      : suites;

    // A rule scoped to versions that were never enumerated has nothing to say.
    if (rule.appliesTo && rule.appliesTo.every((v) => !versionsTested.includes(v as never))) {
      out.push(
        finding({
          id: rule.id,
          title: rule.title,
          category: "cipher",
          severity: rule.severity,
          weight: rule.weight,
          status: "na",
          message: `no enumerated version matches ${rule.appliesTo.join(", ")}`,
        }),
      );
      continue;
    }

    const offenders = inScope.filter((s) => ruleMatches(rule, s));
    const unique = dedupeByName(offenders);
    // If enumeration was incomplete for any in-scope version and no offender
    // was found, the clean result cannot be trusted.
    const scopeIncomplete = [...incomplete].some(
      (v) => !rule.appliesTo || rule.appliesTo.includes(v),
    );
    const status: CheckStatus =
      offenders.length > 0 ? "fail" : scopeIncomplete ? "na" : "pass";

    out.push(
      finding({
        id: rule.id,
        title: rule.title,
        category: "cipher",
        severity: rule.severity,
        weight: rule.weight,
        status,
        message:
          offenders.length > 0
            ? `${rule.message} Found ${unique.length}: ${unique.slice(0, 6).map((s) => s.name).join(", ")}${
                unique.length > 6 ? ", …" : ""
              }`
            : rule.message,
        evidence: {
          // One entry per offending suite (deduped), naming the versions it was
          // accepted on, so the count in the message and this list agree.
          offenders: unique.map((s) => ({
            name: s.name,
            versions: offenders.filter((o) => o.name === s.name).map((o) => o.version),
          })),
        },
      }),
    );
  }

  // Informational: suite summary per version.
  out.push(
    finding({
      id: "suite-summary",
      title: "Negotiable cipher suites",
      category: "cipher",
      severity: "info",
      weight: 0,
      // Informational only. With no suites enumerated there is nothing to
      // report; that is n/a, not a failure.
      status: suites.length > 0 ? "pass" : "na",
      message: report.ciphers.byVersion
        .map((e) => `${e.version}: ${e.suites.length}${e.error ? ` (${e.error})` : ""}`)
        .join("; "),
      evidence: {
        byVersion: report.ciphers.byVersion.map((e) => ({
          version: e.version,
          suites: e.suites.map((s) => s.name),
          truncated: e.truncated,
        })),
      },
    }),
  );

  const truncated = report.ciphers.byVersion.filter((e) => e.truncated);
  if (truncated.length > 0) {
    out.push(
      finding({
        id: "suite-coverage",
        title: "Cipher enumeration incomplete",
        category: "cipher",
        severity: "info",
        weight: 0,
        status: "warn",
        message: `probe budget exhausted for ${truncated.map((e) => e.version).join(", ")}; results may be partial`,
      }),
    );
  }

  return out;
}

function dedupeByName(suites: Array<SuiteEntry & { version?: string }>): SuiteEntry[] {
  const seen = new Map<string, SuiteEntry>();
  for (const s of suites) if (!seen.has(s.name)) seen.set(s.name, s);
  return [...seen.values()];
}

/* -------------------------------------------------------- renegotiation */

function evaluateRenegotiation(baseline: Baseline, report: HostReport): Finding[] {
  const out: Finding[] = [];
  const rule = baseline.renegotiation;
  const reneg = report.renegotiation;

  if (rule.requireSecureRenegotiation) {
    if (isDisabled(baseline, "reneg-secure")) {
      // skipped
    } else if (reneg.secureRenegotiation === null) {
      out.push(
        finding({
          id: "reneg-secure",
          title: "Secure renegotiation (RFC 5746)",
          category: "renegotiation",
          severity: rule.severity,
          weight: rule.weight,
          status: "na",
          message: reneg.reason ?? "secure renegotiation could not be determined",
        }),
      );
    } else {
      out.push(
        finding({
          id: "reneg-secure",
          title: "Secure renegotiation (RFC 5746)",
          category: "renegotiation",
          severity: rule.severity,
          weight: rule.weight,
          status: reneg.secureRenegotiation ? "pass" : "fail",
          message: reneg.secureRenegotiation
            ? "server signals RFC 5746 secure renegotiation"
            : "server does not signal RFC 5746 secure renegotiation (CVE-2009-3555)",
        }),
      );
    }
  }

  if (rule.forbidClientInitiated) {
    if (isDisabled(baseline, "reneg-client")) {
      // skipped
    } else if (reneg.acceptsClientInitiated === null) {
      out.push(
        finding({
          id: "reneg-client",
          title: "Client-initiated renegotiation disabled",
          category: "renegotiation",
          severity: rule.severity,
          weight: rule.weight,
          status: "na",
          message: reneg.error ?? reneg.reason ?? "could not test client-initiated renegotiation",
        }),
      );
    } else {
      out.push(
        finding({
          id: "reneg-client",
          title: "Client-initiated renegotiation disabled",
          category: "renegotiation",
          severity: rule.severity,
          weight: rule.weight,
          status: reneg.acceptsClientInitiated ? "fail" : "pass",
          message: reneg.acceptsClientInitiated
            ? "server accepts client-initiated renegotiation (CPU amplification / DoS risk)"
            : "server refuses client-initiated renegotiation",
        }),
      );
    }
  }

  return out;
}

/* ----------------------------------------------------------- preference */

function evaluatePreference(baseline: Baseline, report: HostReport): Finding[] {
  const rule = baseline.preference;
  if (isDisabled(baseline, "pref-server-order")) return [];
  const pref = report.preference;

  if (!pref.tested || pref.serverPrefersOwnOrder === null) {
    return [
      finding({
        id: "pref-server-order",
        title: "Server enforces its cipher order",
        category: "preference",
        severity: rule.severity,
        weight: rule.weight,
        status: "na",
        message: pref.reason ?? "not testable",
      }),
    ];
  }

  const wanted = rule.requireServerOrder ? pref.serverPrefersOwnOrder : true;
  return [
    finding({
      id: "pref-server-order",
      title: "Server enforces its cipher order",
      category: "preference",
      severity: rule.severity,
      weight: rule.weight,
      status: wanted ? "pass" : "warn",
      message: pref.serverPrefersOwnOrder
        ? `${pref.version}: server prefers its own order (strong suites stay strong)`
        : `${pref.version}: server follows client cipher order — a client can steer it to a weaker suite`,
      evidence: pref.orderA ? { orderA: pref.orderA, orderB: pref.orderB } : undefined,
    }),
  ];
}

/* ----------------------------------------------------------------- ocsp */

function evaluateOcsp(baseline: Baseline, report: HostReport): Finding[] {
  const rule = baseline.ocsp;
  if (isDisabled(baseline, "ocsp-stapling")) return [];
  const ocsp = report.ocsp;

  if (ocsp.stapled === null) {
    return [
      finding({
        id: "ocsp-stapling",
        title: "OCSP stapling",
        category: "ocsp",
        severity: rule.severity,
        weight: rule.weight,
        status: "na",
        message: ocsp.reason ?? "stapling could not be tested",
      }),
    ];
  }

  if (!ocsp.stapled) {
    // Not a finding when the certificate has no OCSP URL to staple.
    if (ocsp.hasOcspAia === false) {
      return [
        finding({
          id: "ocsp-stapling",
          title: "OCSP stapling",
          category: "ocsp",
          severity: rule.severity,
          weight: rule.weight,
          status: "na",
          message: "certificate has no OCSP AIA URL — nothing to staple",
        }),
      ];
    }
    return [
      finding({
        id: "ocsp-stapling",
        title: "OCSP stapling",
        category: "ocsp",
        severity: rule.severity,
        weight: rule.weight,
        status: rule.expectStapling ? "warn" : "pass",
        message: "certificate advertises an OCSP responder but the server did not staple a response",
      }),
    ];
  }

  if (ocsp.expired && rule.rejectExpired) {
    return [
      finding({
        id: "ocsp-stapling",
        title: "OCSP stapling",
        category: "ocsp",
        severity: "medium",
        weight: rule.weight,
        status: "fail",
        message: `served an expired OCSP staple (nextUpdate ${ocsp.nextUpdate})`,
        evidence: ocsp,
      }),
    ];
  }

  const status = ocsp.status ?? "unknown";
  const bad = status === "revoked" || status === "malformed";
  return [
    finding({
      id: "ocsp-stapling",
      title: "OCSP stapling",
      category: "ocsp",
      severity: rule.severity,
      weight: rule.weight,
      status: bad ? "fail" : "pass",
      message: `staple present (status: ${status}${
        ocsp.nextUpdate ? `, nextUpdate ${ocsp.nextUpdate}` : ""
      })`,
      evidence: { status, size: ocsp.size, nextUpdate: ocsp.nextUpdate },
    }),
  ];
}

/* ----------------------------------------------------------------- hsts */

function evaluateHsts(baseline: Baseline, report: HostReport): Finding[] {
  const rule = baseline.hsts;
  if (isDisabled(baseline, "hsts")) return [];
  const hsts = report.hsts;

  if (!hsts.httpResponded) {
    return [
      finding({
        id: "hsts",
        title: "HSTS header",
        category: "hsts",
        severity: rule.severity,
        weight: rule.weight,
        status: "na",
        message: hsts.error ?? "no HTTP response to inspect",
      }),
    ];
  }

  if (!hsts.present) {
    return [
      finding({
        id: "hsts",
        title: "HSTS header",
        category: "hsts",
        severity: rule.severity,
        weight: rule.weight,
        status: rule.require ? "fail" : "na",
        message: "no Strict-Transport-Security header in the HTTP response",
      }),
    ];
  }

  const maxAge = hsts.maxAge ?? 0;
  const problems: string[] = [];
  if (maxAge < rule.minMaxAge) {
    problems.push(`max-age ${maxAge}s is below the ${rule.minMaxAge}s baseline`);
  }
  if (rule.requireIncludeSubDomains && !hsts.includeSubDomains) {
    problems.push("includeSubDomains missing");
  }

  return [
    finding({
      id: "hsts",
      title: "HSTS header",
      category: "hsts",
      severity: rule.severity,
      weight: rule.weight,
      status: problems.length === 0 ? "pass" : "warn",
      message:
        problems.length === 0
          ? `HSTS max-age=${maxAge}${hsts.includeSubDomains ? " includeSubDomains" : ""}${
              hsts.preload ? " preload" : ""
            }`
          : `HSTS present but weak: ${problems.join("; ")}`,
      evidence: { raw: hsts.raw, maxAge, includeSubDomains: hsts.includeSubDomains },
    }),
  ];
}

/* ---------------------------------------------------------- certificate */

function evaluateCertificate(baseline: Baseline, report: HostReport): Finding[] {
  const rule = baseline.certificate;
  const cert = report.certificate;
  const out: Finding[] = [];

  if (!cert.available) {
    out.push(
      finding({
        id: "cert-available",
        title: "Certificate available",
        category: "certificate",
        severity: "high",
        weight: rule.weight,
        status: "na",
        message: cert.error ?? "no certificate obtained",
      }),
    );
    return out;
  }

  // Key strength
  if (!isDisabled(baseline, "cert-key-strength")) {
    const rsaOk = cert.keyType?.startsWith("RSA") ? (cert.keyBits ?? 0) >= rule.minRsaBits : true;
    const ecOk = cert.keyType === "EC" ? (cert.keyBits ?? 0) >= rule.minEcBits : true;
    const ok = rsaOk && ecOk;
    out.push(
      finding({
        id: "cert-key-strength",
        title: "Certificate key strength",
        category: "certificate",
        severity: rule.severity,
        weight: 5,
        status: ok ? "pass" : "fail",
        message: ok
          ? `${cert.keyType} ${cert.keyBits ?? "?"} bits`
          : `${cert.keyType} ${cert.keyBits ?? "?"} bits is below the baseline (RSA≥${rule.minRsaBits}, EC≥${rule.minEcBits})`,
      }),
    );
  }

  // Signature algorithm
  if (rule.rejectSha1 && !isDisabled(baseline, "cert-sha1")) {
    const sha1 = cert.sha1Signature === true;
    out.push(
      finding({
        id: "cert-sha1",
        title: "Certificate signature algorithm",
        category: "certificate",
        severity: rule.severity,
        weight: 4,
        status: sha1 ? "fail" : "pass",
        message: sha1
          ? `signed with ${cert.signatureAlgorithm} (SHA-1 is broken)`
          : `signed with ${cert.signatureAlgorithm ?? "unknown"}`,
      }),
    );
  }

  // Expiry
  if (!isDisabled(baseline, "cert-expiry")) {
    const days = cert.daysRemaining;
    let status: CheckStatus = "pass";
    let message = `valid until ${cert.notAfter}`;
    if (cert.expired) {
      status = "fail";
      message = `expired ${Math.abs(days ?? 0)} days ago (${cert.notAfter})`;
    } else if (cert.notYetValid) {
      // Checked before the "expires soon" warning: a certificate that is not
      // valid *yet* fails regardless of how long it will later be valid.
      status = "fail";
      message = `not valid until ${cert.notBefore}`;
    } else if (days !== undefined && days <= rule.maxDaysToExpiryWarn) {
      status = "warn";
      message = `expires in ${days} days (${cert.notAfter})`;
    }
    out.push(
      finding({
        id: "cert-expiry",
        title: "Certificate validity window",
        category: "certificate",
        severity: status === "fail" ? "critical" : rule.severity,
        weight: 6,
        status,
        message,
      }),
    );
  }

  // Hostname match
  if (cert.hostnameMatch !== null && cert.hostnameChecked) {
    out.push(
      finding({
        id: "cert-hostname",
        title: "Hostname coverage",
        category: "certificate",
        severity: "high",
        weight: 5,
        status: cert.hostnameMatch ? "pass" : "fail",
        message: cert.hostnameMatch
          ? `certificate covers ${cert.hostnameChecked}`
          : `certificate does NOT cover ${cert.hostnameChecked} (SAN: ${(cert.san ?? []).join(", ") || "none"})`,
      }),
    );
  }

  return out;
}

/* ------------------------------------------------------------- scoring */

export function evaluateHost(baseline: Baseline, report: HostReport): HostEvaluation {
  const findings: Finding[] = [
    ...evaluateProtocols(baseline, report),
    ...evaluateSuites(baseline, report),
    ...evaluateRenegotiation(baseline, report),
    ...evaluatePreference(baseline, report),
    ...evaluateOcsp(baseline, report),
    ...evaluateHsts(baseline, report),
    ...evaluateCertificate(baseline, report),
  ];

  // A host that answered no TCP connection at all cannot be scored on TLS.
  if (!report.reachable) {
    for (const f of findings) {
      if (f.status !== "na") {
        // Keep the finding but mark unscored by zeroing its weight.
        f.weight = 0;
        f.status = "na";
      }
    }
  }

  findings.sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return a.id.localeCompare(b.id);
  });

  return { findings, score: computeScore(baseline, findings) };
}

export function computeScore(baseline: Baseline, findings: readonly Finding[]): Score {
  const counts: Record<CheckStatus, number> = { pass: 0, fail: 0, warn: 0, na: 0 };
  let earned = 0;
  let available = 0;

  for (const f of findings) {
    counts[f.status] += 1;
    // Ignore non-finite or non-positive weights so a bad baseline can never
    // poison the score with NaN/Infinity.
    if (!Number.isFinite(f.weight) || f.weight <= 0 || f.status === "na") continue;
    available += f.weight;
    if (f.status === "pass") earned += f.weight;
    else if (f.status === "warn") earned += f.weight * 0.5;
  }

  const value = available > 0 ? Math.round((earned / available) * 1000) / 10 : 0;
  const grade = gradeFor(baseline, value);

  return { value, grade, earned: round1(earned), available: round1(available), counts };
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

function gradeFor(baseline: Baseline, value: number): string {
  const sorted = [...baseline.scoring.grades].sort((a, b) => b.minScore - a.minScore);
  for (const g of sorted) if (value >= g.minScore) return g.grade;
  return sorted.at(-1)?.grade ?? "F";
}
