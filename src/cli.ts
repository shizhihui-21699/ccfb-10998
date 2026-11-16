#!/usr/bin/env node
/**
 * tls-doctor CLI.
 *
 *   scan     scan one or more host:port targets against a baseline
 *   probe    probe a single protocol version (ad-hoc debugging)
 *   baseline print the effective baseline (defaults + any overlay)
 *
 * Exit codes: 0 = all scored checks passed; 1 = at least one failing check;
 * 2 = usage/runtime error. Designed to be usable in CI.
 */
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { DEFAULT_BASELINE } from "./baseline/default-baseline.ts";
import { BaselineError, loadBaselineFile, type Baseline } from "./baseline/types.ts";
import { parseTarget, parseTargets, readTargetFile, TargetError } from "./config/targets.ts";
import { scanFleet } from "./scan/fleet.ts";
import { probeProtocols, specForVersion } from "./probes/protocols.ts";
import { ProbeScheduler } from "./net/scheduler.ts";
import { renderFleet, renderHost } from "./report/render.ts";
import { table } from "./report/term.ts";
import { exportHtml, exportJson, exportMarkdown, type FleetResult } from "./report/export.ts";
import { colour, formatDuration, rule } from "./report/term.ts";
import type { VersionString } from "./types.ts";
import { targetLabel } from "./types.ts";

const VERSION_NAMES: readonly VersionString[] = [
  "SSLv3",
  "TLSv1.0",
  "TLSv1.1",
  "TLSv1.2",
  "TLSv1.3",
];

function usage(): string {
  return `tls-doctor — active TLS configuration health check

Usage:
  tls-doctor scan <target...> [options]
  tls-doctor probe <target> [--version <v>] [options]
  tls-doctor baseline [--baseline <file>]

Targets:
  host:port            e.g. api.internal:443
  https://host[:port]  scheme and path are ignored
  [::1]:443            IPv6 literals in brackets
  @file                read one target per line from a file

Scan options:
  --baseline <file>     YAML/JSON overlay on the default baseline
  --hosts <n>           hosts scanned in parallel (default 4)
  --concurrency <n>     max in-flight connections per host (default from baseline)
  --json <file>         write machine-readable JSON
  --markdown <file>     write a Markdown report
  --html <file>         write a self-contained HTML report
  --verbose             list every negotiable cipher suite
  --show-passing        include passing checks in terminal output
  --no-renegotiate-test skip the active client-renegotiation handshake
  --timeout <ms>        per-step connect/read timeout
  --quiet               only print the fleet summary table

Probe options:
  --version <v>         one of: ${VERSION_NAMES.join(", ")} (default: all)

Common options:
  --help                show this help

Exit status: 0 all checks pass, 1 failing checks found, 2 usage error.
`;
}

interface CommonFlags {
  baseline: Baseline;
  baselineName: string;
  timeoutMs?: number;
}

function buildBaseline(values: Record<string, unknown>): CommonFlags {
  const path = values.baseline as string | undefined;
  if (path) {
    const merged = loadBaselineFile(path, DEFAULT_BASELINE);
    return { baseline: merged, baselineName: merged.name };
  }
  return { baseline: DEFAULT_BASELINE, baselineName: DEFAULT_BASELINE.name };
}

async function cmdScan(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      baseline: { type: "string" },
      hosts: { type: "string" },
      concurrency: { type: "string" },
      json: { type: "string" },
      markdown: { type: "string" },
      html: { type: "string" },
      verbose: { type: "boolean", default: false },
      "show-passing": { type: "boolean", default: false },
      "no-renegotiate-test": { type: "boolean", default: false },
      timeout: { type: "string" },
      quiet: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });

  if (values.help) {
    process.stdout.write(usage());
    return 0;
  }

  const specs: string[] = [];
  for (const positional of positionals) {
    if (positional.startsWith("@")) specs.push(...readTargetFile(positional.slice(1)));
    else specs.push(positional);
  }
  if (specs.length === 0) {
    process.stderr.write("error: no targets given\n\n" + usage());
    return 2;
  }

  const { targets, errors } = parseTargets(specs);
  for (const e of errors) process.stderr.write(`warning: ${e.spec}: ${e.error}\n`);
  if (targets.length === 0) {
    process.stderr.write("error: no valid targets\n");
    return 2;
  }

  const common = buildBaseline(values);
  const hostConcurrency = values.hosts ? Number(values.hosts) : Math.min(4, targets.length);
  if (!Number.isFinite(hostConcurrency) || hostConcurrency < 1) {
    process.stderr.write("error: --hosts must be a positive integer\n");
    return 2;
  }

  const perHostConcurrency = values.concurrency
    ? Number(values.concurrency)
    : common.baseline.safety.concurrency;
  const timeoutMs = values.timeout ? Number(values.timeout) : undefined;
  if (timeoutMs !== undefined && (!Number.isFinite(timeoutMs) || timeoutMs <= 0)) {
    process.stderr.write("error: --timeout must be a positive number of milliseconds\n");
    return 2;
  }

  const baseline: Baseline = {
    ...common.baseline,
    safety: { ...common.baseline.safety, concurrency: perHostConcurrency },
  };

  const quiet = values.quiet as boolean;
  const startedAt = new Date().toISOString();
  process.stderr.write(
    colour.grey(
      `scanning ${targets.length} host(s) with baseline ${common.baselineName} ` +
        `(${hostConcurrency} hosts in parallel, ${perHostConcurrency} connections/host)\n`,
    ),
  );

  const started = Date.now();
  const summary = await scanFleet(targets, {
    baseline,
    hostConcurrency,
    ...(timeoutMs !== undefined
      ? { timing: { connectTimeoutMs: timeoutMs, readTimeoutMs: timeoutMs } }
      : {}),
    skipActiveRenegotiation: values["no-renegotiate-test"] as boolean,
    onHostProgress: (_target, message) => {
      if (!quiet) process.stderr.write(colour.grey(`  ${message}\n`));
    },
    onResult: (result) => {
      if (!quiet) {
        process.stdout.write("\n" + renderHost(result.report, result.evaluation, {
          verbose: values.verbose as boolean,
          showPassing: values["show-passing"] as boolean,
        }) + "\n");
      }
    },
  });

  const result: FleetResult = {
    generatedAt: startedAt,
    baseline: common.baselineName,
    hosts: summary.results.map((r) => ({ report: r.report, evaluation: r.evaluation })),
  };

  // Summary table always, even in quiet mode.
  process.stdout.write("\n" + rule() + "\n");
  process.stdout.write(renderFleet(result.hosts) + "\n");
  process.stdout.write(
    colour.grey(`total scan time ${formatDuration(Date.now() - started)}\n`),
  );

  writeOutputs(values, result);

  return exitCodeFor(result);
}

function writeOutputs(values: Record<string, unknown>, result: FleetResult): void {
  const json = values.json as string | undefined;
  if (json) {
    writeFileSync(json, exportJson(result) + "\n");
    process.stderr.write(colour.grey(`wrote JSON report to ${json}\n`));
  }
  const md = values.markdown as string | undefined;
  if (md) {
    writeFileSync(md, exportMarkdown(result) + "\n");
    process.stderr.write(colour.grey(`wrote Markdown report to ${md}\n`));
  }
  const html = values.html as string | undefined;
  if (html) {
    writeFileSync(html, exportHtml(result) + "\n");
    process.stderr.write(colour.grey(`wrote HTML report to ${html}\n`));
  }
}

function exitCodeFor(result: FleetResult): number {
  for (const host of result.hosts) {
    if (!host.report.reachable) return 1;
    if (host.evaluation.findings.some((f) => f.status === "fail")) return 1;
  }
  return 0;
}

async function cmdProbe(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      version: { type: "string" },
      baseline: { type: "string" },
      timeout: { type: "string" },
      help: { type: "boolean", default: false },
    },
  });

  if (values.help || positionals.length === 0) {
    process.stdout.write(usage());
    return positionals.length === 0 ? 2 : 0;
  }

  const target = parseTarget(positionals[0]!);
  const common = buildBaseline(values);
  const timeoutMs = values.timeout ? Number(values.timeout) : 6_000;
  const timing = { connectTimeoutMs: timeoutMs, readTimeoutMs: timeoutMs };

  if (values.version) {
    const version = values.version as VersionString;
    if (!VERSION_NAMES.includes(version)) {
      process.stderr.write(`error: unknown version ${version}\n`);
      return 2;
    }
    const scheduler = new ProbeScheduler({ concurrency: 1, retries: 0, maxAttempts: 4, deadlineMs: 15_000 });
    const { probeVersion } = await import("./probes/protocols.ts");
    const outcome = await probeVersion(target, specForVersion(version), scheduler, { timing });
    const status = outcome.supported
      ? colour.green(`supported (${outcome.negotiatedSuite})`)
      : colour.red(`not supported (${outcome.alert ?? outcome.reason ?? "unknown"})`);
    process.stdout.write(`${targetLabel(target)} ${version}: ${status}\n`);
    return outcome.supported ? 0 : 1;
  }

  const scheduler = new ProbeScheduler({ concurrency: 4, retries: 0, maxAttempts: 20, deadlineMs: 30_000 });
  const protocols = await probeProtocols(target, scheduler, { timing, includeSsl3: true });
  const reachable = protocols.outcomes.some((o) => o.supported || o.alert !== undefined);

  if (!reachable) {
    const reasons = protocols.outcomes.map((o) => `${o.version}: ${o.reason ?? "no reply"}`);
    process.stderr.write(`error: ${targetLabel(target)} did not answer any TLS probe\n`);
    for (const line of reasons) process.stderr.write(`  ${line}\n`);
    return 1;
  }

  // `probe` is a diagnostic subcommand: print the version outcomes directly
  // rather than dressing them in a scored report with empty sections.
  const rows = protocols.outcomes.map((o) => [
    o.version,
    o.supported ? colour.green("yes") : colour.grey("no"),
    o.negotiatedSuite ?? o.alert ?? o.reason ?? "",
  ]);
  process.stdout.write(`${colour.bold(targetLabel(target))}\n`);
  process.stdout.write(
    table(rows, [
      { header: "version", width: 9 },
      { header: "ok", width: 4 },
      { header: "detail" },
    ]) + "\n",
  );
  process.stdout.write(
    colour.grey(
      `supported: ${protocols.supported.join(", ") || "none"} · highest: ${protocols.highest ?? "-"} · ` +
        `${scheduler.counters.connections} connections\n`,
    ),
  );
  void common;
  return protocols.supported.length > 0 ? 0 : 1;
}

function cmdBaseline(argv: string[]): number {
  const { values } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { baseline: { type: "string" }, help: { type: "boolean", default: false } },
  });
  if (values.help) {
    process.stdout.write(usage());
    return 0;
  }
  const common = buildBaseline(values);
  process.stdout.write(JSON.stringify(common.baseline, null, 2) + "\n");
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  switch (command) {
    case "scan":
      return cmdScan(rest);
    case "probe":
      return cmdProbe(rest);
    case "baseline":
      return cmdBaseline(rest);
    case "help":
    case "--help":
    case "-h":
    case undefined:
      process.stdout.write(usage());
      return command === undefined ? 2 : 0;
    default:
      process.stderr.write(`error: unknown command '${command}'\n\n` + usage());
      return 2;
  }
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    if (err instanceof BaselineError || err instanceof TargetError) {
      process.stderr.write(`error: ${err.message}\n`);
    } else {
      process.stderr.write(`error: ${(err as Error)?.stack ?? String(err)}\n`);
    }
    process.exitCode = 2;
  });
