/**
 * CLI.
 *
 * Targets come from a file (one `host[:port]` or `host:port name` per line,
 * `#` comments allowed) or from repeated --target flags, so the tool drops
 * into a shell pipeline as easily as into a config-management job.
 *
 * Exit codes:
 *   0  every probed endpoint met the baseline's passScore
 *   1  at least one endpoint fell below passScore
 *   2  usage / configuration error (bad baseline, unreadable target file)
 *   3  every target was unreachable (likely a network or targeting mistake,
 *      which is different from "the services are insecure")
 */
import { parseArgs } from 'node:util';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { writeFile } from 'node:fs/promises';
import { loadBaseline, BaselineError } from './baseline/load.ts';
import { evaluateBaseline, summarizeAssessments, type Baseline, type EndpointAssessment } from './baseline/evaluate.ts';
import { runScan, type ScheduledTarget, type SchedulerOptions } from './scheduler.ts';
import { renderTerminal, renderJson, renderMarkdown, renderHtml, type Report } from './report/render.ts';
import type { EndpointResult } from './types.ts';

const USAGE = `tls-checkup — active TLS configuration checkup

Usage:
  tls-checkup [options] <target-file>
  tls-checkup [options] --target host[:port] [--target ...]

Target file format:
  # comments and blank lines are ignored
  api.internal.example                # port 443
  db.internal.example:5432            # port
  cache.internal:6379 cache-primary   # port and a display name
  api.internal.example:443 http:80    # also fetch plain HTTP on port 80 for HSTS

Options:
  --target <host[:port]>       add a target (repeatable)
  --baseline <name|path>       baseline to score against (default: default)
                               built-ins: default (alias modern-internal), legacy-tolerant
  --concurrency <n>            endpoints probed in parallel (default: 4)
  --timeout <ms>               per-connection timeout (default: 5000)
  --max-suites <n>             cap suites enumerated per version (default: 32)
  --max-handshakes <n>         global handshake ceiling for the whole run (default: 4000)
  --delay <ms>                 gap between two handshakes to the same endpoint (default: 20)
  --no-ocsp                    skip OCSP stapling detection
  --no-hsts                    skip HSTS retrieval
  --no-renegotiation           skip the live renegotiation test (passive check still runs)
  --verify-certs               verify server certificates against system CAs
  --ca <path>                  CA bundle to verify against (implies --verify-certs)
  --format <terminal|json|md|html>   output format (default: terminal)
  --out <path>                 write the report to a file instead of stdout
  --verbose                    include evidence and skipped checks
  --no-color                   disable ANSI colour
  --fail-under <score>         exit 1 if any endpoint scores below this (default: baseline passScore)
  --version                    print the version
  --help                       print this help

Exit codes: 0 all compliant, 1 some below threshold, 2 usage error, 3 all unreachable.
`;

export interface CliIo {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

const DEFAULT_IO: CliIo = {
  stdout: (s) => process.stdout.write(s + '\n'),
  stderr: (s) => process.stderr.write(s + '\n'),
};

interface ParsedTarget {
  target: ScheduledTarget;
}

/** Parses one target token: host[:port] plus optional name and http:port. */
export function parseTarget(token: string, extra?: { name?: string; httpPort?: number }): ScheduledTarget {
  const trimmed = token.trim();
  if (!trimmed) throw new Error('empty target');

  // Bracketed IPv6 literal: [::1]:443
  let host: string;
  let port = 443;
  if (trimmed.startsWith('[')) {
    const close = trimmed.indexOf(']');
    if (close === -1) throw new Error(`unterminated IPv6 literal in target "${trimmed}"`);
    host = trimmed.slice(1, close);
    const rest = trimmed.slice(close + 1);
    if (rest.startsWith(':')) port = parsePort(rest.slice(1), trimmed);
    else if (rest !== '') throw new Error(`unexpected text after IPv6 literal in target "${trimmed}"`);
  } else {
    const colon = trimmed.lastIndexOf(':');
    if (colon === -1) {
      host = trimmed;
    } else {
      host = trimmed.slice(0, colon);
      port = parsePort(trimmed.slice(colon + 1), trimmed);
    }
  }
  if (!host) throw new Error(`missing host in target "${trimmed}"`);

  return {
    host,
    port,
    ...(extra?.name ? { serverName: extra.name, label: extra.name, } : {}),
    ...(extra?.httpPort !== undefined ? { httpPort: extra.httpPort } : {}),
  };
}

function parsePort(raw: string, context: string): number {
  if (!/^\d+$/.test(raw)) throw new Error(`invalid port "${raw}" in target "${context}"`);
  const n = parseInt(raw, 10);
  if (n < 1 || n > 65535) throw new Error(`port ${n} out of range in target "${context}"`);
  return n;
}

/** Parses a target file. */
export function parseTargetFile(text: string): ScheduledTarget[] {
  const targets: ScheduledTarget[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    const addr = parts[0]!;
    let name: string | undefined;
    let httpPort: number | undefined;
    for (const extra of parts.slice(1)) {
      const m = extra.match(/^http:(\d+)$/);
      if (m) {
        httpPort = parsePort(m[1]!, `${addr} http:${m[1]}`);
      } else if (!name) {
        name = extra;
      } else {
        throw new Error(`target file line ${i + 1}: unexpected token "${extra}"`);
      }
    }
    targets.push(parseTarget(addr, { ...(name ? { name } : {}), ...(httpPort !== undefined ? { httpPort } : {}) }));
  }
  return targets;
}

export async function main(argv: string[], io: CliIo = DEFAULT_IO): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        target: { type: 'string', multiple: true },
        baseline: { type: 'string' },
        concurrency: { type: 'string' },
        timeout: { type: 'string' },
        'max-suites': { type: 'string' },
        'max-handshakes': { type: 'string' },
        delay: { type: 'string' },
        'no-ocsp': { type: 'boolean' },
        'no-hsts': { type: 'boolean' },
        'no-renegotiation': { type: 'boolean' },
        'verify-certs': { type: 'boolean' },
        ca: { type: 'string' },
        format: { type: 'string' },
        out: { type: 'string' },
        verbose: { type: 'boolean' },
        'no-color': { type: 'boolean' },
        'fail-under': { type: 'string' },
        version: { type: 'boolean' },
        help: { type: 'boolean' },
      },
    });
  } catch (err) {
    io.stderr(`error: ${(err as Error).message}`);
    io.stderr(USAGE);
    return 2;
  }

  const { values, positionals } = parsed;

  if (values.help) {
    io.stdout(USAGE);
    return 0;
  }
  if (values.version) {
    io.stdout('tls-checkup 1.0.0');
    return 0;
  }

  // --- collect targets ----------------------------------------------------
  const targets: ScheduledTarget[] = [];
  try {
    for (const t of values.target ?? []) {
      targets.push(parseTarget(t));
    }
    if (positionals.length > 1) {
      io.stderr(`error: expected one target file, got ${positionals.length} positional arguments`);
      return 2;
    }
    const file = positionals[0];
    if (file) {
      let text: string;
      try {
        text = await readFile(file, 'utf8');
      } catch (err) {
        io.stderr(`error: cannot read target file "${file}": ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`);
        return 2;
      }
      targets.push(...parseTargetFile(text));
    }
  } catch (err) {
    io.stderr(`error: ${(err as Error).message}`);
    return 2;
  }

  if (targets.length === 0) {
    io.stderr('error: no targets given (pass a target file or --target host[:port])');
    io.stderr(USAGE);
    return 2;
  }

  // --- numbers with validation -------------------------------------------
  const num = (name: string, raw: string | undefined, def: number, min: number, max: number): number => {
    if (raw === undefined) return def;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < min || n > max) {
      throw new Error(`--${name} must be an integer between ${min} and ${max}`);
    }
    return n;
  };

  let baseline: Baseline;
  let concurrency: number;
  let timeoutMs: number;
  let maxSuites: number;
  let maxHandshakes: number;
  let delay: number;
  let failUnder: number;
  try {
    baseline = await loadBaseline(values.baseline ?? 'default');
    concurrency = num('concurrency', values.concurrency, 4, 1, 64);
    timeoutMs = num('timeout', values.timeout, 5000, 250, 120000);
    maxSuites = num('max-suites', values['max-suites'], 32, 1, 256);
    maxHandshakes = num('max-handshakes', values['max-handshakes'], 4000, 10, 1_000_000);
    delay = num('delay', values.delay, 20, 0, 5000);
    failUnder = num('fail-under', values['fail-under'], baseline.passScore ?? 85, 0, 100);
  } catch (err) {
    if (err instanceof BaselineError) {
      io.stderr(`error: ${err.message}`);
    } else {
      io.stderr(`error: ${(err as Error).message}`);
    }
    return 2;
  }

  const format = values.format ?? 'terminal';
  if (!['terminal', 'json', 'md', 'html'].includes(format)) {
    io.stderr(`error: --format must be one of terminal, json, md, html`);
    return 2;
  }

  const schedulerOpts: SchedulerOptions = {
    timeoutMs,
    maxSuitesPerVersion: maxSuites,
    checkHsts: !values['no-hsts'],
    checkOcsp: !values['no-ocsp'],
    checkRenegotiation: !values['no-renegotiation'],
    rejectUnauthorized: Boolean(values['verify-certs'] || values.ca),
    ...(values.ca ? { caFile: values.ca } : {}),
    concurrency,
    maxTotalHandshakes: maxHandshakes,
    maxHandshakesPerEndpoint: maxSuites * 4 + 40,
    interProbeDelayMs: delay,
  };

  const startedAt = new Date();
  const outcome = await runScan(targets, schedulerOpts);

  // --- assess -------------------------------------------------------------
  const endpoints: Array<{ result: EndpointResult; assessment: EndpointAssessment }> = outcome.results.map((result) => {
    const evaluated = evaluateBaseline(baseline, result);
    const worst = evaluated.worstSeverity;
    const assessment: EndpointAssessment = {
      label: result.label,
      host: result.host,
      port: result.port,
      findings: evaluated.findings,
      score: evaluated.score,
      ...(worst ? { worstSeverity: worst } : {}),
      compliant: evaluated.score.score >= failUnder,
    };
    return { result, assessment };
  });

  const summary = summarizeAssessments(endpoints.map((e) => e.assessment));
  const report: Report = {
    generatedAt: startedAt.toISOString(),
    baseline: { id: baseline.id, name: baseline.name },
    scan: {
      targets: targets.length,
      probed: outcome.results.length,
      skipped: outcome.skipped.length,
      handshakes: outcome.totalHandshakes,
      elapsedMs: outcome.elapsedMs,
    },
    endpoints,
    summary: {
      compliant: summary.compliant,
      averageScore: summary.averageScore,
      bySeverity: summary.bySeverity,
    },
  };

  // --- render -------------------------------------------------------------
  const useColor = !values['no-color'] && format === 'terminal' && process.stdout.isTTY !== false;
  const rendered =
    format === 'json'
      ? renderJson(report)
      : format === 'md'
        ? renderMarkdown(report)
        : format === 'html'
          ? renderHtml(report)
          : renderTerminal(report, { color: useColor, verbose: Boolean(values.verbose) });

  if (values.out) {
    await writeFile(values.out, rendered + (rendered.endsWith('\n') ? '' : '\n'), 'utf8');
    if (format === 'terminal') io.stdout(`report written to ${values.out}`);
  } else {
    io.stdout(rendered);
  }

  // --- exit code ----------------------------------------------------------
  // Exit 3 is reserved for "nothing answered at all", which usually means the
  // target list or network is wrong. A port that answers TCP but not TLS is a
  // real (bad) finding and is scored, not excused.
  const allUnreachable = outcome.results.every((r) => !r.reachable && !r.tlsAbsent);
  if (allUnreachable) return 3;
  return endpoints.every((e) => e.assessment.compliant) ? 0 : 1;
}

// Only run when invoked directly, so tests can import main().
// Comparing paths is unreliable (macOS resolves /tmp to /private/tmp), so we
// resolve both through the filesystem before falling back to the argument
// shape. The .ts check keeps `node src/cli.ts` working under every spelling.
function invokedDirectly(): boolean {
  const arg = process.argv[1];
  if (!arg) return false;
  try {
    if (realpathSync(arg) === realpathSync(fileURLToPath(import.meta.url))) return true;
  } catch {
    /* fall through */
  }
  return arg.endsWith('cli.ts') || arg.endsWith('cli.js');
}
if (invokedDirectly()) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      process.stderr.write(`fatal: ${(err as Error).stack ?? (err as Error).message}\n`);
      process.exitCode = 2;
    });
}
