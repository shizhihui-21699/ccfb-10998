/**
 * Report renderers: terminal, JSON, Markdown, HTML.
 *
 * All renderers consume the same report object so the four outputs can never
 * disagree about a finding. The terminal renderer is the primary one; the
 * others exist for CI artifacts and for handing to a service owner.
 */
import type { EndpointAssessment, Finding, ScoreBreakdown } from '../baseline/evaluate.ts';
import type { EndpointResult, SuiteInfo, TlsVersionName } from '../types.ts';

export interface Report {
  generatedAt: string;
  baseline: { id: string; name: string };
  scan: {
    targets: number;
    probed: number;
    skipped: number;
    handshakes: number;
    elapsedMs: number;
  };
  endpoints: Array<{ result: EndpointResult; assessment: EndpointAssessment }>;
  summary: {
    compliant: number;
    averageScore: number;
    bySeverity: Record<string, number>;
  };
}

const COLOR = {
  reset: '\u001b[0m',
  dim: '\u001b[2m',
  bold: '\u001b[1m',
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  green: '\u001b[32m',
  cyan: '\u001b[36m',
  magenta: '\u001b[35m',
  gray: '\u001b[90m',
};

export interface RenderOptions {
  color: boolean;
  verbose: boolean;
}

function paint(s: string, code: string, enabled: boolean): string {
  return enabled ? `${code}${s}${COLOR.reset}` : s;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: COLOR.red,
  high: COLOR.magenta,
  medium: COLOR.yellow,
  low: COLOR.cyan,
  info: COLOR.gray,
};

const GRADE_COLOR: Record<string, string> = {
  A: COLOR.green,
  B: COLOR.green,
  C: COLOR.yellow,
  D: COLOR.yellow,
  F: COLOR.red,
};

function grade(score: ScoreBreakdown): string {
  return `${score.grade} ${score.score}/100`;
}

/** Terminal report. Designed to be readable at a glance and greppable. */
export function renderTerminal(report: Report, opts: RenderOptions): string {
  const c = opts.color;
  const lines: string[] = [];
  const rule = (label = '') => {
    const width = 78;
    if (!label) return paint('─'.repeat(width), COLOR.gray, c);
    const text = ` ${label} `;
    const left = Math.floor((width - text.length) / 2);
    return paint('─'.repeat(Math.max(0, left)) + text + '─'.repeat(Math.max(0, width - left - text.length)), COLOR.gray, c);
  };

  lines.push(rule());
  lines.push(`${paint('TLS checkup', COLOR.bold, c)}  ${paint(report.baseline.name, COLOR.dim, c)}`);
  lines.push(
    paint(
      `${report.scan.targets} target(s), ${report.scan.probed} probed, ${report.scan.handshakes} handshakes in ${(report.scan.elapsedMs / 1000).toFixed(1)}s`,
      COLOR.dim,
      c,
    ),
  );
  lines.push(rule());

  for (const ep of report.endpoints) {
    lines.push('');
    const r = ep.result;
    const a = ep.assessment;
    const gradeText = paint(grade(a.score), GRADE_COLOR[a.score.grade] ?? COLOR.reset, c);
    const status = a.compliant ? paint('PASS', COLOR.green, c) : paint('FAIL', COLOR.red, c);
    lines.push(`${paint(r.label, COLOR.bold, c)}  ${gradeText}  ${status}`);

    if (!r.reachable) {
      const why = r.tlsAbsent ? 'no TLS on this port' : 'unreachable';
      lines.push(`  ${paint(why, COLOR.red, c)} ${r.warnings[0] ?? ''}`);
      if (r.hsts?.fetched) {
        lines.push(`  ${paint(`HSTS (via HTTP): ${r.hsts.present ? r.hsts.header : 'not set'}`, r.hsts.present ? COLOR.yellow : COLOR.gray, c)}`);
      }
      continue;
    }

    // Versions
    const versionBits = r.versions.map((v) => {
      if (!v.supported) return paint(`${v.version} off`, COLOR.gray, c);
      const weak = v.suites.some((s) => s.strength === 'weak' || s.strength === 'insecure' || s.strength === 'null');
      const text = `${v.version} (${v.suites.length})`;
      return paint(text, weak ? COLOR.yellow : COLOR.green, c);
    });
    lines.push(`  versions: ${versionBits.join('  ')}`);

    // Suites, grouped by strength
    const weak = r.suites.filter((s) => s.strength === 'weak' || s.strength === 'insecure' || s.strength === 'null');
    const strong = r.suites.filter((s) => s.strength === 'strong' || s.strength === 'acceptable');
    if (strong.length) {
      lines.push(`  strong:   ${strong.map((s) => s.name).join(', ')}`);
    }
    if (weak.length) {
      lines.push(`  ${paint('weak:     ' + weak.map((s) => s.name).join(', '), COLOR.yellow, c)}`);
    }

    // Facts line
    const facts: string[] = [];
    if (r.preference?.conclusive) {
      facts.push(
        r.preference.serverPrefers
          ? paint('server cipher order: yes', COLOR.green, c)
          : paint('server cipher order: NO (client order wins)', COLOR.yellow, c),
      );
    }
    if (r.renegotiation) {
      const legacyEnabled = r.versions.some((v) => v.supported && v.version !== 'TLSv1.3');
      if (!legacyEnabled) {
        facts.push(paint('renegotiation: n/a (TLS 1.3 only)', COLOR.gray, c));
      } else {
        if (!r.renegotiation.secureRenegotiationSupported) {
          facts.push(paint('secure renegotiation: NO', COLOR.red, c));
        } else {
          facts.push(paint('secure renegotiation: yes', COLOR.green, c));
        }
        if (r.renegotiation.clientInitiatedAccepted) {
          facts.push(paint('client renegotiation: ACCEPTED', COLOR.red, c));
        } else if (r.renegotiation.conclusive) {
          facts.push(paint('client renegotiation: refused', COLOR.green, c));
        } else {
          facts.push(paint('client renegotiation: no answer (unproven)', COLOR.gray, c));
        }
      }
    }
    if (r.ocsp) {
      if (r.ocsp.stapled) {
        const st = r.ocsp.certificateStatus ? ` (${r.ocsp.certificateStatus})` : '';
        facts.push(paint(`OCSP stapling: yes${st}`, r.ocsp.certificateStatus === 'revoked' ? COLOR.red : COLOR.green, c));
      } else {
        facts.push(paint('OCSP stapling: no', COLOR.yellow, c));
      }
    }
    if (r.hsts) {
      if (r.hsts.present) {
        facts.push(paint(`HSTS: ${r.hsts.header}`, COLOR.green, c));
      } else if (r.hsts.fetched) {
        facts.push(paint('HSTS: not set', COLOR.yellow, c));
      } else {
        facts.push(paint('HSTS: unknown', COLOR.gray, c));
      }
    }
    for (const f of facts) lines.push(`  ${f}`);

    if (r.certificate) {
      const cert = r.certificate;
      const expiryColor = cert.expired ? COLOR.red : cert.daysUntilExpiry <= 30 ? COLOR.yellow : COLOR.green;
      lines.push(
        `  cert: ${cert.keyType.toUpperCase()} ${cert.keySize} · ${cert.signatureAlgorithm} · ` +
          paint(`${cert.expired ? 'EXPIRED' : `${cert.daysUntilExpiry} days left`}`, expiryColor, c) +
          (cert.selfSigned ? paint(' · self-signed', COLOR.yellow, c) : ''),
      );
    }

    // Findings
    const failed = a.findings.filter((f) => !f.skipped && !f.passed);
    const skipped = a.findings.filter((f) => f.skipped);
    if (failed.length) {
      lines.push(`  ${paint('findings:', COLOR.bold, c)}`);
      for (const f of failed) {
        const sev = paint(`[${f.severity}]`, SEVERITY_COLOR[f.severity] ?? COLOR.reset, c);
        const info = f.informational ? paint(' (info)', COLOR.gray, c) : '';
        lines.push(`    ${sev}${info} ${f.message}`);
        if (f.rationale) lines.push(paint(`        ${f.rationale}`, COLOR.gray, c));
        if (opts.verbose && f.evidence?.length) {
          for (const e of f.evidence) lines.push(paint(`        - ${e}`, COLOR.dim, c));
        }
      }
    }
    if (opts.verbose && skipped.length) {
      for (const f of skipped) lines.push(paint(`    (skipped) ${f.checkId}: ${f.message}`, COLOR.dim, c));
    }
    if (!failed.length) {
      lines.push(`  ${paint('no findings', COLOR.green, c)}`);
    }
    if (r.warnings.length && opts.verbose) {
      for (const w of r.warnings) lines.push(paint(`  warning: ${w}`, COLOR.gray, c));
    }
  }

  lines.push('');
  lines.push(rule());
  const s = report.summary;
  lines.push(
    `${paint('Summary', COLOR.bold, c)}: ${s.compliant}/${report.scan.probed} compliant · average score ${s.averageScore}/100 · ` +
      `critical ${s.bySeverity.critical ?? 0}, high ${s.bySeverity.high ?? 0}, medium ${s.bySeverity.medium ?? 0}, low ${s.bySeverity.low ?? 0}`,
  );
  lines.push(rule());
  return lines.join('\n');
}

/** Machine-readable report. The full probe data is included, not just findings. */
export function renderJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

/** Markdown report for pasting into a wiki or ticket. */
export function renderMarkdown(report: Report): string {
  const out: string[] = [];
  out.push(`# TLS checkup: ${report.baseline.name}`, '');
  out.push(
    `Generated ${report.generatedAt} · ${report.scan.probed} endpoint(s) · ` +
      `${report.scan.handshakes} handshakes · ${report.summary.compliant} compliant · average ${report.summary.averageScore}/100`,
    '',
  );
  out.push('| Endpoint | Score | Grade | Versions | Worst finding |', '|---|---|---|---|---|');
  for (const { result: r, assessment: a } of report.endpoints) {
    const worst = [...a.findings]
      .filter((f) => !f.skipped && !f.passed && !f.informational)
      .sort((x, y) => severityRank(x.severity) - severityRank(y.severity))[0];
    out.push(
      `| ${r.label} | ${a.score.score} | ${a.score.grade} | ${r.versions.filter((v) => v.supported).map((v) => v.version).join(', ') || '—'} | ${worst?.message ?? 'none'} |`,
    );
  }
  out.push('');
  for (const { result: r, assessment: a } of report.endpoints) {
    out.push(`## ${r.label}`, '');
    out.push(`Score **${a.score.score}/100** (${a.score.grade}) — ${a.compliant ? 'compliant' : 'not compliant'}`, '');
    if (!r.reachable) {
      out.push('**Unreachable.** ' + (r.warnings[0] ?? ''), '');
      continue;
    }
    out.push('### Protocol versions', '');
    out.push('| Version | Supported | Suites |', '|---|---|---|');
    for (const v of r.versions) {
      out.push(`| ${v.version} | ${v.supported ? 'yes' : 'no'} | ${v.suites.map((s) => s.name).join('<br>') || '—'} |`);
    }
    out.push('');
    out.push('### Findings', '');
    const failed = a.findings.filter((f) => !f.skipped && !f.passed);
    if (!failed.length) out.push('None.', '');
    for (const f of failed) {
      out.push(`- **[${f.severity}]** ${f.message}${f.informational ? ' _(informational)_' : ''}`);
      if (f.rationale) out.push(`  - _${f.rationale}_`);
      for (const e of f.evidence ?? []) out.push(`  - \`${e}\``);
    }
    out.push('');
  }
  return out.join('\n');
}

function severityRank(s: string): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 9;
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** Self-contained HTML report (no external assets, safe to attach to a ticket). */
export function renderHtml(report: Report): string {
  const rows = report.endpoints
    .map(({ result: r, assessment: a }) => {
      const failed = a.findings.filter((f) => !f.skipped && !f.passed);
      const findings = failed
        .map(
          (f) =>
            `<li class="sev-${f.severity}"><strong>${f.severity}</strong> ${esc(f.message)}` +
            (f.rationale ? `<br><small>${esc(f.rationale)}</small>` : '') +
            `</li>`,
        )
        .join('');
      const versions = r.versions
        .map((v) => `<span class="v ${v.supported ? 'on' : 'off'}">${v.version}</span>`)
        .join(' ');
      return `<tr>
  <td><code>${esc(r.label)}</code></td>
  <td class="score g${a.score.grade}">${a.score.score}<small>${a.score.grade}</small></td>
  <td>${versions}</td>
  <td><ul>${findings || '<li class="none">no findings</li>'}</ul></td>
</tr>`;
    })
    .join('\n');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>TLS checkup — ${esc(report.baseline.name)}</title>
<style>
  :root { color-scheme: light dark; --fg:#1b1f23; --bg:#fff; --muted:#57606a; --line:#d0d7de; }
  @media (prefers-color-scheme: dark) { :root { --fg:#e6edf3; --bg:#0d1117; --muted:#8d96a0; --line:#30363d; } }
  body { font: 14px/1.5 system-ui, sans-serif; color: var(--fg); background: var(--bg); margin: 2rem auto; max-width: 1100px; padding: 0 1rem; }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  .meta { color: var(--muted); margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; vertical-align: top; padding: .6rem .5rem; border-bottom: 1px solid var(--line); }
  code { font-size: .95em; }
  .score { font-weight: 600; font-size: 1.2rem; white-space: nowrap; }
  .score small { display: block; font-size: .7rem; color: var(--muted); font-weight: 400; }
  ul { margin: 0; padding-left: 1.1rem; }
  li { margin: .15rem 0; }
  .sev-critical strong { color: #cf222e; }
  .sev-high strong { color: #bc4c00; }
  .sev-medium strong { color: #9a6700; }
  .sev-low strong { color: #0969da; }
  .v { display: inline-block; padding: .05rem .35rem; border-radius: 4px; font-size: .8rem; margin-right: .2rem; }
  .v.on { background: #dafbe1; color: #116329; }
  .v.off { background: #eff1f3; color: #6e7781; }
  @media (prefers-color-scheme: dark) {
    .v.on { background:#12261e; color:#57ab5a; } .v.off { background:#21262d; color:#7d8590; }
  }
  .none { color: var(--muted); }
</style></head><body>
<h1>TLS checkup — ${esc(report.baseline.name)}</h1>
<div class="meta">Generated ${esc(report.generatedAt)} · ${report.scan.probed} endpoint(s) ·
${report.summary.compliant} compliant · average ${report.summary.averageScore}/100 ·
${report.scan.handshakes} handshakes in ${(report.scan.elapsedMs / 1000).toFixed(1)}s</div>
<table><thead><tr><th>Endpoint</th><th>Score</th><th>Versions</th><th>Findings</th></tr></thead>
<tbody>
${rows}
</tbody></table>
</body></html>
`;
}
