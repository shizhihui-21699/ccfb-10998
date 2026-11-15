"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatReport = formatReport;
exports.formatSummary = formatSummary;
exports.toJsonReport = toJsonReport;
const C = {
    reset: '[0m',
    bold: '[1m',
    dim: '[2m',
    red: '[31m',
    green: '[32m',
    yellow: '[33m',
    blue: '[34m',
    cyan: '[36m',
};
const NO_COLOR = Object.fromEntries(Object.keys(C).map((k) => [k, '']));
const SEV_COLOR = {
    critical: 'red',
    high: 'red',
    medium: 'yellow',
    low: 'cyan',
    info: 'dim',
};
function gradeColor(c, grade) {
    return grade === 'A' ? c.green : grade === 'B' ? c.cyan : grade === 'C' ? c.yellow : c.red;
}
function formatReport(result, score, opts) {
    const c = opts.color ? C : NO_COLOR;
    const lines = [];
    const t = result.target;
    lines.push('');
    lines.push(`${c.bold}═══ ${t.host}:${t.port} ═══${c.reset}  ` +
        `score ${gradeColor(c, score.grade)}${c.bold}${score.score}/100 (${score.grade})${c.reset}  ` +
        `${c.dim}${result.durationMs}ms${c.reset}`);
    if (result.error) {
        lines.push(`  ${c.red}error: ${result.error}${c.reset}`);
    }
    // versions
    const vParts = result.versions.map((v) => v.supported ? `${c.green}${v.version} ✓${c.reset}` : `${c.dim}${v.version} ✗${c.reset}`);
    lines.push(`  protocols: ${vParts.join('  ')}`);
    // ciphers
    for (const ce of result.ciphers) {
        lines.push(`  ${ce.version} ciphers (${ce.ciphers.length})${ce.note ? ` ${c.dim}[${ce.note}]${c.reset}` : ''}:`);
        for (const ci of ce.ciphers) {
            lines.push(`    - ${ci.standardName ?? ci.opensslName}`);
        }
    }
    // cipher order
    const co = result.cipherOrder;
    const coStr = co.tested
        ? co.enforcesServerOrder
            ? `${c.green}server-enforced ✓${c.reset}`
            : `${c.yellow}client-order (server does not enforce)${c.reset}`
        : `${c.dim}untested${c.reset}`;
    lines.push(`  cipher order: ${coStr} ${c.dim}${co.detail}${c.reset}`);
    // renegotiation
    const rn = result.renegotiation;
    const extStr = rn.secureRenegotiationExt === null
        ? 'unknown'
        : rn.secureRenegotiationExt
            ? `${c.green}secure renegotiation supported ✓${c.reset}`
            : `${c.yellow}renegotiation_info absent${c.reset}`;
    const activeStr = rn.clientInitiatedAllowed === null
        ? 'n/a'
        : rn.clientInitiatedAllowed
            ? `${c.yellow}allowed${c.reset}`
            : `${c.green}rejected${c.reset}`;
    lines.push(`  renegotiation: ${extStr}${c.reset}, client-initiated: ${activeStr}${c.reset}`);
    // ocsp
    const ocspStr = result.ocspStapling === null
        ? 'unknown'
        : result.ocspStapling
            ? `${c.green}enabled ✓${c.reset}`
            : `${c.yellow}not enabled${c.reset}`;
    lines.push(`  OCSP stapling: ${ocspStr}${c.reset}`);
    // hsts
    if (result.hsts) {
        const h = result.hsts;
        const hStr = h.nonHttp
            ? `${c.dim}n/a (not an HTTP service)${c.reset}`
            : h.present
                ? `${c.green}${h.raw}${c.reset}`
                : `${c.yellow}missing${c.reset}`;
        lines.push(`  HSTS: ${hStr}`);
    }
    // cert
    if (result.cert) {
        const cert = result.cert;
        const expColor = cert.daysRemaining < 0 ? c.red : cert.daysRemaining < 30 ? c.yellow : c.green;
        lines.push(`  certificate: ${cert.subject} ${c.dim}(issuer: ${cert.issuer})${c.reset}\n` +
            `    valid to ${cert.validTo} — ${expColor}${cert.daysRemaining}d remaining${c.reset}` +
            (cert.selfSigned ? ` ${c.yellow}[self-signed]${c.reset}` : ''));
    }
    // findings
    if (score.findings.length > 0) {
        lines.push(`  findings:`);
        for (const f of score.findings) {
            const col = c[SEV_COLOR[f.severity]];
            lines.push(`    ${col}[${f.severity}]${c.reset} ${f.message} ${c.dim}(-${f.deduction})${c.reset}`);
        }
    }
    else {
        lines.push(`  ${c.green}no findings — clean against baseline${c.reset}`);
    }
    return lines.join('\n');
}
function formatSummary(rows, opts) {
    const c = opts.color ? C : NO_COLOR;
    const lines = ['', `${c.bold}═══ summary ═══${c.reset}`];
    const byGrade = {};
    for (const { result, score } of rows) {
        byGrade[score.grade] = (byGrade[score.grade] ?? 0) + 1;
        lines.push(`  ${result.target.host}:${result.target.port}  ` +
            `${gradeColor(c, score.grade)}${score.grade} (${score.score})${c.reset}  ` +
            `${c.dim}${score.findings.length} finding(s)${c.reset}`);
    }
    lines.push(`  ${c.bold}grades:${c.reset} ` +
        ['A', 'B', 'C', 'D', 'F'].map((g) => `${g}:${byGrade[g] ?? 0}`).join('  '));
    return lines.join('\n');
}
function toJsonReport(rows, baseline) {
    return {
        tool: 'tls-scan',
        generatedAt: new Date().toISOString(),
        baseline,
        hosts: rows.map(({ result, score }) => ({ ...result, score })),
    };
}
