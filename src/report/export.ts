/**
 * Machine- and human-consumable exports: JSON, Markdown and a self-contained
 * HTML report. All three render the same in-memory fleet result.
 */
import type { HostEvaluation, HostReport, Severity } from "../types.ts";
import { targetLabel } from "../types.ts";

export interface FleetResult {
  generatedAt: string;
  baseline: string;
  hosts: Array<{ report: HostReport; evaluation: HostEvaluation }>;
}

export function exportJson(result: FleetResult): string {
  // Average only over hosts that were actually scorable: an unreachable host
  // is "not assessed", not a zero.
  const scored = result.hosts.filter((h) => h.report.reachable);
  const payload = {
    generatedAt: result.generatedAt,
    baseline: result.baseline,
    summary: {
      hosts: result.hosts.length,
      reachable: result.hosts.filter((h) => h.report.reachable).length,
      failing: result.hosts.filter((h) =>
        h.evaluation.findings.some((f) => f.status === "fail"),
      ).length,
      averageScore:
        scored.length === 0
          ? null
          : Math.round(
              (scored.reduce((sum, h) => sum + h.evaluation.score.value, 0) / scored.length) * 10,
            ) / 10,
    },
    hosts: result.hosts.map(({ report, evaluation }) => ({
      target: { host: report.target.host, port: report.target.port, label: targetLabel(report.target) },
      reachable: report.reachable,
      durationMs: report.durationMs,
      startedAt: report.startedAt,
      score: evaluation.score,
      protocols: report.protocols,
      ciphers: report.ciphers,
      preference: report.preference,
      renegotiation: report.renegotiation,
      ocsp: report.ocsp,
      hsts: report.hsts,
      certificate: report.certificate,
      stats: report.stats,
      findings: evaluation.findings,
    })),
  };
  return JSON.stringify(payload, null, 2);
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function escapeMd(text: string): string {
  // Escape table-breaking pipes, collapse newlines, and neutralise HTML so a
  // hostname like `<img onerror=…>` cannot execute when the Markdown is
  // rendered by a Markdown-to-HTML pipeline.
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\|/g, "\\|")
    .replace(/\n/g, " ");
}

export function exportMarkdown(result: FleetResult): string {
  const lines: string[] = [];
  lines.push("# TLS configuration report");
  lines.push("");
  lines.push(`- Generated: ${result.generatedAt}`);
  lines.push(`- Baseline: ${result.baseline}`);
  lines.push(`- Hosts: ${result.hosts.length}`);
  lines.push("");

  // Fleet table
  lines.push("## Summary");
  lines.push("");
  lines.push("| Target | Score | Grade | Versions | Failing | Warnings |");
  lines.push("| --- | ---: | :---: | --- | ---: | ---: |");
  for (const { report, evaluation } of result.hosts) {
    const fails = evaluation.findings.filter((f) => f.status === "fail").length;
    const warns = evaluation.findings.filter((f) => f.status === "warn").length;
    const scorable = report.reachable && evaluation.score.available > 0;
    const score = scorable ? evaluation.score.value.toFixed(1) : "n/a";
    const grade = scorable ? evaluation.score.grade : "—";
    lines.push(
      `| ${escapeMd(targetLabel(report.target))} | ${score} | ${grade} | ${
        report.protocols.supported.join(", ") || (report.reachable ? "none" : "unreachable")
      } | ${fails} | ${warns} |`,
    );
  }
  lines.push("");

  for (const { report, evaluation } of result.hosts) {
    lines.push(`## ${targetLabel(report.target)}`);
    lines.push("");
    lines.push(
      (!report.reachable
        ? "**Score:** not assessed (host unreachable)"
        : evaluation.score.available === 0
          ? "**Score:** not scored (no conclusive checks)"
          : `**Score:** ${evaluation.score.value.toFixed(1)}/100 (grade ${evaluation.score.grade})`) + ` · ` +
        `pass ${evaluation.score.counts.pass} / fail ${evaluation.score.counts.fail} / ` +
        `warn ${evaluation.score.counts.warn} / n/a ${evaluation.score.counts.na} · ` +
        `${report.durationMs}ms · ${report.stats.connections} connections`,
    );
    lines.push("");

    if (!report.reachable) {
      lines.push(`> Unreachable: ${report.tcpError ?? "no TCP connection"}`);
      lines.push("");
      continue;
    }

    lines.push("### Protocol versions");
    lines.push("");
    lines.push("| Version | Supported | Negotiated suite / reason |");
    lines.push("| --- | :---: | --- |");
    for (const o of report.protocols.outcomes) {
      lines.push(
        `| ${o.version} | ${o.supported ? "yes" : "no"} | ${escapeMd(o.negotiatedSuite ?? o.alert ?? o.reason ?? "")} |`,
      );
    }
    lines.push("");

    lines.push("### Cipher suites");
    lines.push("");
    for (const e of report.ciphers.byVersion) {
      lines.push(`**${e.version}** — ${e.suites.length} suites (${e.probes} probes)`);
      lines.push("");
      if (e.suites.length > 0) {
        lines.push(
          e.suites.map((s) => `\`${s.name}\`${s.weak ? " ⚠️ weak" : ""}${s.forwardSecrecy ? "" : " (no FS)"}`).join(", "),
        );
        lines.push("");
      }
    }

    lines.push("### Renegotiation");
    lines.push("");
    lines.push(
      `- Secure renegotiation (RFC 5746): ${describeTri(report.renegotiation.secureRenegotiation)}\n` +
        `- Client-initiated renegotiation: ${
          report.renegotiation.acceptsClientInitiated === null
            ? "unknown"
            : report.renegotiation.acceptsClientInitiated
              ? "accepted by server"
              : "refused"
        }${report.renegotiation.testedVersion ? ` (${report.renegotiation.testedVersion})` : ""}`,
    );
    lines.push("");

    lines.push("### Preference, OCSP, HSTS, certificate");
    lines.push("");
    lines.push(`- Cipher order: ${describePreferenceMd(report)}`);
    lines.push(
      `- OCSP stapling: ${
        report.ocsp.stapled === null
          ? (report.ocsp.reason ?? "unknown")
          : report.ocsp.stapled
            ? `stapled, status ${report.ocsp.status ?? "unknown"}${report.ocsp.nextUpdate ? `, nextUpdate ${report.ocsp.nextUpdate}` : ""}`
            : "not stapled"
      }`,
    );
    lines.push(
      `- HSTS: ${
        report.hsts.present
          ? `\`${escapeMd(report.hsts.raw ?? "")}\``
          : report.hsts.httpResponded
            ? "absent"
            : (report.hsts.reason ?? "no HTTP response")
      }`,
    );
    if (report.certificate.available) {
      const c = report.certificate;
      lines.push(
        `- Certificate: ${c.keyType ?? "?"} ${c.keyBits ?? ""}, ${c.signatureAlgorithm ?? "?"}, ` +
          `expires ${c.notAfter ?? "?"} (${c.daysRemaining ?? "?"} days)` +
          `${c.hostnameMatch === false ? ", **hostname mismatch**" : ""}`,
      );
    } else {
      lines.push(`- Certificate: ${report.certificate.error ?? "unavailable"}`);
    }
    lines.push("");

    const problems = evaluation.findings
      .filter((f) => f.status === "fail" || f.status === "warn")
      .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
    lines.push("### Findings");
    lines.push("");
    if (problems.length === 0) {
      lines.push("All scored checks passed.");
    } else {
      lines.push("| Severity | Check | Status | Detail |");
      lines.push("| --- | --- | :---: | --- |");
      for (const f of problems) {
        lines.push(
          `| ${f.severity} | ${escapeMd(f.title)} | ${f.status} | ${escapeMd(f.message)} |`,
        );
      }
    }
    lines.push("");
  }

  return lines.join("\n");
}

function describeTri(value: boolean | null): string {
  return value === null ? "unknown" : value ? "yes" : "no";
}

function describePreferenceMd(report: HostReport): string {
  const p = report.preference;
  if (!p.tested || p.serverPrefersOwnOrder === null) return p.reason ?? "not tested";
  return p.serverPrefersOwnOrder
    ? `server enforces its own order (${p.version})`
    : `server follows client order (${p.version})`;
}

/* ------------------------------------------------------------------ HTML */

function esc(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};

export function exportHtml(result: FleetResult): string {
  const cards = result.hosts.map(({ report, evaluation }) => renderHostCard(report, evaluation)).join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TLS configuration report</title>
<style>
  :root { color-scheme: light dark; --bg:#fdfdfc; --fg:#1a1a19; --muted:#6b6b68; --card:#fff; --line:#e4e4e0;
    --pass:#1f7a3d; --fail:#b3261e; --warn:#8a6100; --sev-critical:#7a1fa2; --sev-high:#b3261e; --sev-medium:#8a6100; --sev-low:#1a5fb4; --sev-info:#6b6b68; }
  @media (prefers-color-scheme: dark) { :root { --bg:#121212; --fg:#ececea; --muted:#9a9a97; --card:#1c1c1b; --line:#2e2e2c;
    --pass:#57c97a; --fail:#f2706a; --warn:#e0b143; --sev-critical:#c98df0; --sev-high:#f2706a; --sev-medium:#e0b143; --sev-low:#79aef0; --sev-info:#9a9a97; } }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px 16px 64px; background: var(--bg); color: var(--fg);
    font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  .wrap { max-width: 1080px; margin: 0 auto; }
  h1 { font-size: 24px; margin: 0 0 4px; }
  .sub { color: var(--muted); margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 18px 20px; margin-bottom: 20px; }
  .card-head { display: flex; flex-wrap: wrap; gap: 12px; align-items: baseline; justify-content: space-between; }
  .host { font-size: 18px; font-weight: 650; }
  .badge { font-weight: 700; padding: 2px 10px; border-radius: 999px; border: 1px solid currentColor; font-variant-numeric: tabular-nums; }
  .badge.good { color: var(--pass); } .badge.mid { color: var(--warn); } .badge.bad { color: var(--fail); }
  h3 { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 20px 0 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; }
  td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
  code { font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; }
  ul.plain { list-style: none; padding: 0; margin: 0; }
  ul.plain li { padding: 3px 0; }
  .sev { font-weight: 700; font-size: 11px; }
  .sev-critical { color: var(--sev-critical); } .sev-high { color: var(--sev-high); }
  .sev-medium { color: var(--sev-medium); } .sev-low { color: var(--sev-low); } .sev-info { color: var(--sev-info); }
  .st-pass { color: var(--pass); } .st-fail { color: var(--fail); } .st-warn { color: var(--warn); } .st-na { color: var(--muted); }
  .pill { display:inline-block; padding:0 6px; border-radius:4px; border:1px solid var(--line); font-size:11px; color:var(--muted); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px; }
  .kv { font-size: 13px; }
  .kv b { display: block; color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
  @media (max-width: 560px) { body { padding: 16px 10px 48px; } .card { padding: 14px; } }
</style>
</head>
<body>
<div class="wrap">
  <h1>TLS configuration report</h1>
  <p class="sub">Generated ${esc(result.generatedAt)} · baseline <code>${esc(result.baseline)}</code> · ${result.hosts.length} host(s)</p>
  ${cards}
</div>
</body>
</html>`;
}

function badgeClass(score: number): string {
  return score >= 80 ? "good" : score >= 60 ? "mid" : "bad";
}

function renderHostCard(report: HostReport, evaluation: HostEvaluation): string {
  const score = evaluation.score;
  const problems = evaluation.findings.filter((f) => f.status !== "na" && f.status !== "pass");
  const findingsHtml =
    problems.length === 0
      ? `<p class="st-pass">All scored checks passed.</p>`
      : `<table><thead><tr><th>Severity</th><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>${problems
          .map(
            (f) =>
              `<tr><td class="sev ${SEVERITY_CLASS[f.severity] ?? "sev-info"}">${esc(String(f.severity).toUpperCase())}</td>` +
              `<td>${esc(f.title)}</td><td class="st-${f.status}">${f.status}</td><td>${esc(f.message)}</td></tr>`,
          )
          .join("")}</tbody></table>`;

  const protocolRows = report.protocols.outcomes
    .map(
      (o) =>
        `<tr><td><code>${o.version}</code></td><td class="st-${o.supported ? "pass" : "na"}">${
          o.supported ? "yes" : "no"
        }</td><td><code>${esc(o.negotiatedSuite ?? o.alert ?? o.reason ?? "")}</code></td></tr>`,
    )
    .join("");

  const cipherBlocks = report.ciphers.byVersion
    .map((e) => {
      const suites = e.suites
        .map(
          (s) =>
            `<li><code>${esc(s.name)}</code>` +
            (s.weak ? ` <span class="pill">weak</span>` : "") +
            (!s.forwardSecrecy ? ` <span class="pill">no-FS</span>` : "") +
            `</li>`,
        )
        .join("");
      return `<div class="kv"><b>${e.version} · ${e.suites.length} suites</b><ul class="plain">${suites || '<li class="st-na">none</li>'}</ul></div>`;
    })
    .join("");

  const reneg = report.renegotiation;
  const ocsp = report.ocsp;
  const hsts = report.hsts;
  const cert = report.certificate;

  const facts = [
    ["Cipher order", report.preference.tested ? (report.preference.serverPrefersOwnOrder ? "server order" : "client order") : "n/a"],
    ["Secure reneg.", reneg.secureRenegotiation === null ? "unknown" : reneg.secureRenegotiation ? "yes" : "no"],
    ["Client reneg.", reneg.acceptsClientInitiated === null ? "unknown" : reneg.acceptsClientInitiated ? "accepted" : "refused"],
    ["OCSP staple", ocsp.stapled === null ? "unknown" : ocsp.stapled ? `yes (${ocsp.status ?? "?"})` : "no"],
    ["HSTS", hsts.present ? `max-age=${hsts.maxAge ?? "?"}` : hsts.httpResponded ? "absent" : "n/a"],
    ["Certificate", cert.available ? `${cert.keyType ?? "?"} ${cert.keyBits ?? ""} · ${cert.daysRemaining ?? "?"} days left` : (cert.error ?? "unavailable")],
  ]
    .map(([k, v]) => `<div class="kv"><b>${esc(k ?? "")}</b>${esc(v ?? "")}</div>`)
    .join("");

  return `<section class="card">
  <div class="card-head">
    <div>
      <div class="host">${esc(targetLabel(report.target))}</div>
      <div class="sub" style="margin:4px 0 0">${report.durationMs} ms · ${report.stats.connections} connections · ${
        report.protocols.supported.join(", ") || (report.reachable ? "no TLS" : "unreachable")
      }</div>
    </div>
    <span class="badge ${badgeClass(score.value)}">${
      !report.reachable
        ? "unreachable"
        : score.available === 0
          ? "not scored"
          : `${score.grade} ${score.value.toFixed(1)}`
    }</span>
  </div>
  ${report.reachable ? "" : `<p class="st-fail">Unreachable: ${esc(report.tcpError ?? "no TCP connection")}</p>`}
  <h3>Protocols</h3>
  <table><thead><tr><th>Version</th><th>Supported</th><th>Negotiated</th></tr></thead><tbody>${protocolRows}</tbody></table>
  <h3>Key properties</h3>
  <div class="grid">${facts}</div>
  <h3>Findings</h3>
  ${findingsHtml}
  <h3>Cipher suites</h3>
  <div class="grid">${cipherBlocks || '<p class="st-na">not enumerated</p>'}</div>
</section>`;
}
