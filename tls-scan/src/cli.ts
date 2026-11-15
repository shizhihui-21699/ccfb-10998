import fs from 'node:fs';
import { Baseline, mergeBaseline } from './baseline';
import { scanTarget } from './scanner';
import { formatReport, formatSummary, toJsonReport } from './report';
import { scoreScan } from './score';
import { ScanResult, ScoreReport, Target } from './types';
import { mapPool, Semaphore } from './util';

const USAGE = `tls-scan — TLS configuration health check

usage:
  node dist/cli.js --host example.com:443 [--host ...] [options]

targets:
  --host <host:port>       target (repeatable); :port defaults to 443
  --targets <file>         file with one target per line ("host:port" or "host port")

options:
  --baseline <file>        baseline JSON (merged over built-in defaults)
  --concurrency <n>        max simultaneous connections, global (default 8)
  --hosts-concurrency <n>  max hosts scanned in parallel (default 3)
  --timeout <ms>           per-connection timeout (default 5000)
  --no-tls13-enum          skip TLS 1.3 suite enumeration via openssl CLI
  --no-hsts                skip the HTTP/HSTS probe
  --json <file>            write full JSON report
  --no-color               disable ANSI colors
  --verbose                show per-host progress
  --fail-below <grade>     exit 1 if any host grades below A/B/C/D (e.g. --fail-below B)
  -h, --help               this help
`;

interface Cli {
  targets: Target[];
  baselineFile?: string;
  concurrency: number;
  hostsConcurrency: number;
  timeoutMs: number;
  enumTls13: boolean;
  checkHsts: boolean;
  jsonOut?: string;
  color: boolean;
  verbose: boolean;
  failBelow?: string;
}

function parseHostPort(s: string): Target {
  s = s.trim();
  if (!s || s.startsWith('#')) throw new Error('skip');
  const m = /^(\[[0-9a-f:]+\]|[^\s:]+)(?::(\d+))?$/i.exec(s.replace(/\s+/, ':'));
  if (!m) throw new Error(`bad target: ${s}`);
  return { host: m[1].replace(/^\[|\]$/g, ''), port: m[2] ? Number(m[2]) : 443 };
}

function parseArgs(argv: string[]): Cli {
  const cli: Cli = {
    targets: [],
    concurrency: 8,
    hostsConcurrency: 3,
    timeoutMs: 5000,
    enumTls13: true,
    checkHsts: true,
    color: process.stdout.isTTY,
    verbose: false,
  };
  const next = (i: number, flag: string): string => {
    const v = argv[i + 1];
    if (v === undefined) throw new Error(`${flag} needs a value`);
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--host': {
        cli.targets.push(parseHostPort(next(i, a)));
        i++;
        break;
      }
      case '--targets': {
        const lines = fs.readFileSync(next(i, a), 'utf8').split(/\r?\n/);
        for (const line of lines) {
          try {
            cli.targets.push(parseHostPort(line));
          } catch {
            /* skip blanks/comments */
          }
        }
        i++;
        break;
      }
      case '--baseline':
        cli.baselineFile = next(i, a);
        i++;
        break;
      case '--concurrency':
        cli.concurrency = Math.max(1, Number(next(i, a)) || 8);
        i++;
        break;
      case '--hosts-concurrency':
        cli.hostsConcurrency = Math.max(1, Number(next(i, a)) || 3);
        i++;
        break;
      case '--timeout':
        cli.timeoutMs = Math.max(500, Number(next(i, a)) || 5000);
        i++;
        break;
      case '--no-tls13-enum':
        cli.enumTls13 = false;
        break;
      case '--no-hsts':
        cli.checkHsts = false;
        break;
      case '--json':
        cli.jsonOut = next(i, a);
        i++;
        break;
      case '--no-color':
        cli.color = false;
        break;
      case '--verbose':
        cli.verbose = true;
        break;
      case '--fail-below':
        cli.failBelow = next(i, a).toUpperCase();
        i++;
        break;
      case '-h':
      case '--help':
        process.stdout.write(USAGE);
        process.exit(0);
      default:
        throw new Error(`unknown option: ${a}`);
    }
  }
  return cli;
}

const GRADE_ORDER = ['A', 'B', 'C', 'D', 'F'];

async function main(): Promise<void> {
  let cli: Cli;
  try {
    cli = parseArgs(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n\n${USAGE}`);
    process.exit(2);
  }
  if (cli!.targets.length === 0) {
    process.stderr.write(`no targets given.\n\n${USAGE}`);
    process.exit(2);
  }

  let baseline: Baseline;
  try {
    const user = cli!.baselineFile
      ? (JSON.parse(fs.readFileSync(cli!.baselineFile, 'utf8')) as Partial<Baseline>)
      : undefined;
    baseline = mergeBaseline(user);
  } catch (e) {
    process.stderr.write(`cannot load baseline: ${(e as Error).message}\n`);
    process.exit(2);
  }

  // one global semaphore caps simultaneous sockets across all hosts —
  // this is what keeps the scan from hammering any service
  const limiter = new Semaphore(cli!.concurrency);
  const rows: Array<{ result: ScanResult; score: ScoreReport }> = [];

  await mapPool(cli!.targets, cli!.hostsConcurrency, async (target) => {
    const result = await scanTarget(
      target,
      {
        timeoutMs: cli!.timeoutMs,
        enumTls13: cli!.enumTls13,
        checkHsts: cli!.checkHsts,
        onProgress: cli!.verbose ? (m) => process.stderr.write(`${m}\n`) : undefined,
      },
      limiter,
    );
    const score = scoreScan(result, baseline!);
    rows.push({ result, score });
    process.stdout.write(formatReport(result, score, { color: cli!.color }) + '\n');
  });

  // restore target order for summary/json
  const key = (t: Target) => `${t.host}:${t.port}`;
  const order = new Map(cli!.targets.map((t, i) => [key(t), i]));
  rows.sort((a, b) => order.get(key(a.result.target))! - order.get(key(b.result.target))!);

  process.stdout.write(formatSummary(rows, { color: cli!.color }) + '\n');

  if (cli!.jsonOut) {
    fs.writeFileSync(cli!.jsonOut, JSON.stringify(toJsonReport(rows, baseline!), null, 2));
    process.stderr.write(`JSON report written to ${cli!.jsonOut}\n`);
  }

  if (cli!.failBelow) {
    const threshold = GRADE_ORDER.indexOf(cli!.failBelow);
    if (threshold === -1) {
      process.stderr.write(`bad grade for --fail-below: ${cli!.failBelow}\n`);
      process.exit(2);
    }
    const worst = rows.some((r) => GRADE_ORDER.indexOf(r.score.grade) > threshold);
    if (worst) process.exit(1);
  }
}

main().catch((e) => {
  process.stderr.write(`fatal: ${e instanceof Error ? e.stack ?? e.message : String(e)}\n`);
  process.exit(2);
});
