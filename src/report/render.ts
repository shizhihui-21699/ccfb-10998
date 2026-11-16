/**
 * Human-readable report rendering for a single host and for a fleet summary.
 */
import type { Finding, HostEvaluation, HostReport, Severity } from "../types.ts";
import { targetLabel } from "../types.ts";
import {
  colour,
  formatDuration,
  gradeColour,
  padEnd,
  rule,
  severityColour,
  statusColour,
  table,
} from "./term.ts";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED",
  low: "LOW",
  info: "INFO",
};

function findingLine(f: Finding): string {
  const label = SEVERITY_LABEL[f.severity] ?? String(f.severity).toUpperCase().slice(0, 4);
  const tag = severityColour(f.severity)(padEnd(label, 4));
  const status = statusColour(f.status)(padEnd(String(f.status).toUpperCase(), 4));
  return `  ${tag} ${status} ${colour.bold(f.title)} — ${f.message}`;
}

function protocolTable(report: HostReport): string {
  const rows = report.protocols.outcomes.map((o) => [
    o.version,
    o.supported ? colour.green("yes") : colour.grey("no"),
    o.negotiatedSuite ?? (o.alert ? `alert: ${o.alert}` : (o.reason ?? "")),
  ]);
  if (rows.length === 0) return colour.grey("  (not probed)");
  return table(rows, [
    { header: "version", width: 9 },
    { header: "ok", width: 4 },
    { header: "detail" },
  ]);
}

function cipherSection(report: HostReport): string {
  const lines: string[] = [];
  for (const enumeration of report.ciphers.byVersion) {
    const header = `${colour.bold(enumeration.version)} — ${enumeration.suites.length} suites (${enumeration.probes} probes)`;
    lines.push(`  ${header}${enumeration.truncated ? colour.yellow(" [truncated]") : ""}`);
    if (enumeration.error) {
      lines.push(colour.grey(`    ${enumeration.error}`));
      continue;
    }
    for (const suite of enumeration.suites) {
      const flags: string[] = [];
      if (suite.weak) flags.push(colour.red("weak"));
      if (!suite.forwardSecrecy) flags.push(colour.yellow("no-FS"));
      if (suite.anonymous) flags.push(colour.red("anon"));
      lines.push(
        `    ${padEnd(suite.name, 40)} ${colour.grey(`${suite.kx}/${suite.enc}/${suite.mac}`)} ${flags.join(" ")}`,
      );
    }
  }
  if (lines.length === 0) return colour.grey("  (not enumerated)");
  return lines.join("\n");
}

function renegotiationSection(report: HostReport): string {
  const r = report.renegotiation;
  const lines: string[] = [];
  lines.push(
    `  secure renegotiation (RFC 5746): ${renderBool(r.secureRenegotiation)}`,
  );
  lines.push(`  client-initiated renegotiation: ${renderBool(r.acceptsClientInitiated, true)}`);
  if (r.testedVersion) lines.push(colour.grey(`  tested over ${r.testedVersion}`));
  if (r.error) lines.push(colour.grey(`  ${r.error}`));
  if (r.reason) lines.push(colour.grey(`  ${r.reason}`));
  return lines.join("\n");
}

function renderBool(value: boolean | null, invertShown = false): string {
  if (value === null) return colour.grey("unknown");
  if (invertShown) {
    // For "accepts client renegotiation": true is bad.
    return value ? colour.red("accepted (bad)") : colour.green("refused (good)");
  }
  return value ? colour.green("yes") : colour.red("no");
}

function preferenceSection(report: HostReport): string {
  const p = report.preference;
  if (!p.tested || p.serverPrefersOwnOrder === null) {
    return colour.grey(`  ${p.reason ?? "not tested"}`);
  }
  const verdict = p.serverPrefersOwnOrder
    ? colour.green("server enforces its own cipher order")
    : colour.yellow("server follows client cipher order");
  const lines = [`  ${verdict} (${p.version})`];
  if (p.orderA && p.orderB) {
    lines.push(colour.grey(`  offered ${p.orderA.offered.join(",")} -> ${p.orderA.chosen}`));
    lines.push(colour.grey(`  offered ${p.orderB.offered.join(",")} -> ${p.orderB.chosen}`));
  }
  return lines.join("\n");
}

function ocspSection(report: HostReport): string {
  const o = report.ocsp;
  const lines: string[] = [];
  if (o.stapled === null) return colour.grey(`  ${o.reason ?? "not tested"}`);
  if (!o.stapled) {
    lines.push(
      `  stapled: ${colour.yellow("no")}${o.hasOcspAia === false ? colour.grey(" (no OCSP AIA URL)") : ""}`,
    );
    if (o.reason) lines.push(colour.grey(`  ${o.reason}`));
    return lines.join("\n");
  }
  const statusColourFn =
    o.status === "good" ? colour.green : o.status === "revoked" ? colour.red : colour.yellow;
  lines.push(`  stapled: ${colour.green("yes")} — status ${statusColourFn(o.status ?? "unknown")}`);
  if (o.nextUpdate) {
    const expiry = o.expired ? colour.red(" (EXPIRED)") : "";
    lines.push(colour.grey(`  nextUpdate ${o.nextUpdate}${expiry}`));
  }
  if (o.size) lines.push(colour.grey(`  staple size ${o.size} bytes, tested over ${o.testedVersion}`));
  if (o.error) lines.push(colour.grey(`  ${o.error}`));
  return lines.join("\n");
}

function hstsSection(report: HostReport): string {
  const h = report.hsts;
  if (!h.httpResponded) return colour.grey(`  ${h.reason ?? h.error ?? "no HTTP response"}`);
  if (!h.present) return `  HSTS: ${colour.yellow("absent")} (HTTP ${h.statusCode ?? "?"})`;
  return (
    `  HSTS: ${colour.green("present")} max-age=${h.maxAge ?? "?"}` +
    `${h.includeSubDomains ? " includeSubDomains" : ""}${h.preload ? " preload" : ""}` +
    colour.grey(`\n  ${h.raw ?? ""}`)
  );
}

function certificateSection(report: HostReport): string {
  const c = report.certificate;
  if (!c.available) return colour.grey(`  ${c.error ?? "unavailable"}`);
  const rows: string[][] = [];
  if (c.subject) rows.push(["subject", c.subject.replace(/\n/g, ", ")]);
  if (c.issuer) rows.push(["issuer", c.issuer.replace(/\n/g, ", ")]);
  if (c.san && c.san.length > 0) rows.push(["SAN", c.san.join(", ")]);
  if (c.notAfter) rows.push(["valid until", `${c.notAfter} (${c.daysRemaining ?? "?"} days)`]);
  if (c.keyType) rows.push(["key", `${c.keyType} ${c.keyBits ?? ""}${c.curve ? ` (${c.curve})` : ""}`]);
  if (c.signatureAlgorithm) rows.push(["signature", c.signatureAlgorithm]);
  if (c.hostnameChecked) {
    rows.push(["hostname", c.hostnameMatch ? colour.green("matches") : colour.red("MISMATCH")]);
  }
  if (c.ocspUrl) rows.push(["OCSP AIA", c.ocspUrl]);
  if (c.chainTrusted !== null && c.chainTrusted !== undefined) {
    rows.push(["chain", c.chainTrusted ? colour.green("trusted") : colour.yellow("not trusted")]);
  }
  return table(rows, [{ header: "", width: 12 }, { header: "" }]);
}

function scoreBadge(score: number, grade: string, reachable: boolean, scorable = true): string {
  // A host we could not assess earns neither a score nor a misleading 0/100.
  if (!reachable) return colour.grey("unreachable — not scored");
  if (!scorable) return colour.grey("not scored (no conclusive checks)");
  const paint = gradeColour(score);
  return paint(colour.bold(`${grade} ${score.toFixed(1)}/100`));
}

export interface HostRenderOptions {
  /** Show the full cipher lists (default false: summarise). */
  verbose?: boolean;
  /** Show passing checks too. */
  showPassing?: boolean;
}

/** Render one host's card. */
export function renderHost(
  report: HostReport,
  evaluation: HostEvaluation,
  options: HostRenderOptions = {},
): string {
  const lines: string[] = [];
  const title = `${colour.bold(targetLabel(report.target))}  ${scoreBadge(
    evaluation.score.value,
    evaluation.score.grade,
    report.reachable,
    evaluation.score.available > 0,
  )}`;
  lines.push(rule());
  lines.push(title);
  lines.push(
    colour.grey(
      `reachable=${report.reachable} duration=${formatDuration(report.durationMs)} ` +
        `connections=${report.stats.connections} retries=${report.stats.retries}` +
        (report.stats.budgetExhausted ? " (budget exhausted)" : ""),
    ),
  );
  if (!report.reachable) {
    lines.push(colour.red(`unreachable: ${report.tcpError ?? "no TCP connection"}`));
    lines.push(colour.grey("No TLS assessment was possible for this host."));
    return lines.join("\n");
  }

  lines.push("");
  lines.push(colour.bold("Protocols"));
  lines.push(protocolTable(report));

  lines.push("");
  lines.push(colour.bold("Cipher suites"));
  lines.push(describeCipherSummary(report));
  if (options.verbose) lines.push(cipherSection(report));

  lines.push("");
  lines.push(colour.bold("Cipher order preference"));
  lines.push(preferenceSection(report));

  lines.push("");
  lines.push(colour.bold("Renegotiation"));
  lines.push(renegotiationSection(report));

  lines.push("");
  lines.push(colour.bold("OCSP stapling"));
  lines.push(ocspSection(report));

  lines.push("");
  lines.push(colour.bold("HSTS"));
  lines.push(hstsSection(report));

  lines.push("");
  lines.push(colour.bold("Certificate"));
  lines.push(certificateSection(report));

  lines.push("");
  lines.push(colour.bold(`Findings (${evaluation.findings.filter((f) => f.status !== "na").length})`));
  lines.push(renderFindings(evaluation.findings, options.showPassing ?? false));

  lines.push("");
  lines.push(scoreLine(evaluation, report.reachable));
  return lines.join("\n");
}

function describeCipherSummary(report: HostReport): string {
  return report.ciphers.byVersion
    .map((e) => {
      const weak = e.suites.filter((s) => s.weak).length;
      const noFs = e.suites.filter((s) => !s.forwardSecrecy).length;
      const badge =
        weak > 0
          ? colour.red(`${weak} weak`)
          : noFs > 0
            ? colour.yellow(`${noFs} no-FS`)
            : colour.green("all strong");
      return `  ${padEnd(e.version, 9)} ${e.suites.length} suites — ${badge}`;
    })
    .join("\n");
}

export function renderFindings(findings: readonly Finding[], showPassing: boolean): string {
  const shown = findings.filter(
    (f) => showPassing || f.status === "fail" || f.status === "warn",
  );
  // Always show at least the failing/warning set; if empty say so plainly.
  if (shown.length === 0) {
    return colour.green("  ✓ all scored checks passed");
  }
  return shown.map(findingLine).join("\n");
}

function scoreLine(evaluation: HostEvaluation, reachable: boolean): string {
  const { score } = evaluation;
  return (
    colour.grey("score: ") +
    `${score.earned}/${score.available} weighted points — ` +
    `pass ${score.counts.pass}, fail ${score.counts.fail}, warn ${score.counts.warn}, n/a ${score.counts.na} — ` +
    scoreBadge(score.value, score.grade, reachable, score.available > 0)
  );
}

/* --------------------------------------------------------------- summary */

export interface FleetRow {
  report: HostReport;
  evaluation: HostEvaluation;
}

/** Render a compact table across hosts. */
export function renderFleet(rows: readonly FleetRow[]): string {
  const body = rows.map(({ report, evaluation }) => {
    const versions = report.protocols.supported.length
      ? report.protocols.supported.join(",")
      : colour.grey(report.reachable ? "none" : "unreachable");
    const fails = evaluation.findings.filter((f) => f.status === "fail").length;
    const warns = evaluation.findings.filter((f) => f.status === "warn").length;
    // A score only means something when at least one check was applicable.
    const scorable = evaluation.score.available > 0;
    const grade = !report.reachable
      ? colour.grey("n/a")
      : !scorable
        ? colour.grey("not scored")
        : gradeColour(evaluation.score.value)(
            `${evaluation.score.grade} ${evaluation.score.value.toFixed(0)}`,
          );
    return [
      targetLabel(report.target),
      versions,
      fails > 0 ? colour.red(String(fails)) : colour.grey("0"),
      warns > 0 ? colour.yellow(String(warns)) : colour.grey("0"),
      grade,
    ];
  });

  const tableText = table(body, [
    { header: "target", width: Math.max(12, ...rows.map((r) => targetLabel(r.report.target).length)) },
    { header: "versions" },
    { header: "fail", width: 4, align: "right" },
    { header: "warn", width: 4, align: "right" },
    { header: "score", width: 6, align: "right" },
  ]);

  const critical = rows.reduce(
    (n, r) => n + r.evaluation.findings.filter((f) => f.severity === "critical" && f.status === "fail").length,
    0,
  );
  const failing = rows.filter((r) => r.evaluation.findings.some((f) => f.status === "fail")).length;
  const unreachable = rows.filter((r) => !r.report.reachable).length;
  const footerParts = [`${failing} with failing checks`];
  if (critical > 0) footerParts.push(colour.magenta(`${critical} critical`));
  if (unreachable > 0) footerParts.push(colour.red(`${unreachable} unreachable`));
  const footer = ["", `${rows.length} host(s) scanned — ${footerParts.join(", ")}`].join("\n");

  return [tableText, footer].join("\n");
}
