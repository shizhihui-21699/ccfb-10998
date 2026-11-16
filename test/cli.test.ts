/**
 * CLI smoke tests: run the real entry point as a subprocess against the
 * fixtures and assert exit codes, output formats and usage errors.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { startFixtures, type RunningFixture } from "../fixtures/servers.ts";

const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, "..", "src", "cli.ts");

let fixtures: RunningFixture[] = [];
const byId = new Map<string, RunningFixture>();

before(async () => {
  // Offset the port range so this file never collides with the integration
  // suite when node --test runs files in parallel.
  fixtures = await startFixtures({ basePort: 15501 });
  for (const f of fixtures) byId.set(f.id, f);
});

after(async () => {
  await Promise.all(fixtures.map((f) => f.close()));
});

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

/**
 * Run the CLI, capturing exit status even on non-zero.
 *
 * Must be async: the fixture servers live in this same process, so a
 * synchronous child-process wait would block the event loop and starve them.
 */
function run(args: string[]): Promise<RunResult> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ["--no-warnings", cli, ...args],
      { encoding: "utf8", timeout: 60_000 },
      (err, stdout, stderr) => {
        const status = err ? ((err as { code?: number }).code ?? 1) : 0;
        resolve({ status: typeof status === "number" ? status : 1, stdout, stderr });
      },
    );
  });
}

test("no arguments prints usage and exits 2", async () => {
  const result = await run([]);
  assert.equal(result.status, 2);
  assert.match(result.stdout, /Usage:/);
});

test("--help exits 0", async () => {
  const result = await run(["--help"]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /tls-doctor/);
});

test("invalid targets exit 2", async () => {
  const result = await run(["scan", "not a host:port"]);
  assert.equal(result.status, 2);
});

test("scanning an unreachable host exits 1", async () => {
  const result = await run(["scan", "127.0.0.1:1", "--timeout", "800", "--quiet"]);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /unreachable/i);
});

test("a modern host passes with exit 0 and writes every export format", async (t) => {
  const fixture = byId.get("modern");
  if (!fixture) return t.skip("modern fixture unavailable");
  const dir = mkdtempSync(join(tmpdir(), "tls-doctor-cli-"));
  const json = join(dir, "report.json");
  const md = join(dir, "report.md");
  const html = join(dir, "report.html");
  const result = await run([
    "scan",
    `127.0.0.1:${fixture.actualPort}`,
    "--timeout",
    "3000",
    "--quiet",
    "--json",
    json,
    "--markdown",
    md,
    "--html",
    html,
  ]);
  assert.equal(result.status, 0, `expected pass, got ${result.status}: ${result.stdout}`);

  const parsed = JSON.parse(readFileSync(json, "utf8"));
  assert.equal(parsed.hosts.length, 1);
  assert.equal(parsed.hosts[0].score.grade, "A");
  assert.ok(parsed.hosts[0].protocols.supported.includes("TLSv1.3"));

  const markdown = readFileSync(md, "utf8");
  assert.match(markdown, /^# TLS configuration report/);

  const htmlText = readFileSync(html, "utf8");
  assert.match(htmlText, /<!doctype html>/);
  assert.match(htmlText, /TLS configuration report/);
});

test("a host with failing checks exits 1", async (t) => {
  const fixture = byId.get("weak-ciphers");
  if (!fixture) return t.skip("weak-ciphers fixture unavailable");
  const result = await run(["scan", `127.0.0.1:${fixture.actualPort}`, "--timeout", "3000", "--quiet"]);
  assert.equal(result.status, 1);
});

test("probe with an explicit version reports support", async (t) => {
  const fixture = byId.get("modern");
  if (!fixture) return t.skip("modern fixture unavailable");
  const ok = await run(["probe", `127.0.0.1:${fixture.actualPort}`, "--version", "TLSv1.3"]);
  assert.equal(ok.status, 0);
  assert.match(ok.stdout, /supported/);

  const unsupported = await run(["probe", `127.0.0.1:${fixture.actualPort}`, "--version", "TLSv1.0"]);
  assert.equal(unsupported.status, 1);
  assert.match(unsupported.stdout, /not supported/);
});

test("baseline subcommand prints the effective baseline", async () => {
  const result = await run(["baseline"]);
  assert.equal(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.name, "internal-default");
  assert.ok(Array.isArray(parsed.protocols));
});
