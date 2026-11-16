#!/usr/bin/env node
/**
 * Start the fixture servers and keep them running until Ctrl-C.
 *
 *   node fixtures/serve.ts            # all fixtures
 *   node fixtures/serve.ts --only modern,weak-ciphers
 *   node fixtures/serve.ts --json     # print a machine-readable manifest
 */
import { startFixtures } from "./servers.ts";
import { ensurePki } from "./pki.ts";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const onlyIndex = args.indexOf("--only");
  const only =
    onlyIndex !== -1 && args[onlyIndex + 1]
      ? new Set(args[onlyIndex + 1]!.split(",").map((s) => s.trim()))
      : undefined;

  ensurePki();
  const running = (await startFixtures()).filter((f) => !only || only.has(f.id));

  if (json) {
    process.stdout.write(
      JSON.stringify(
        running.map((f) => ({ id: f.id, port: f.actualPort, runtime: f.runtime, description: f.description })),
        null,
        2,
      ) + "\n",
    );
  } else {
    process.stdout.write(`fixture servers (127.0.0.1 only):\n\n`);
    for (const f of running) {
      process.stdout.write(
        `  ${f.id.padEnd(14)} 127.0.0.1:${f.actualPort}  [${f.runtime}]\n` +
          `  ${" ".repeat(14)} ${f.description}\n` +
          `  ${" ".repeat(14)} expect: ${f.expect.join("; ")}\n\n`,
      );
    }
    process.stdout.write(`Press Ctrl-C to stop.\n`);
  }

  const shutdown = async (): Promise<void> => {
    await Promise.all(running.map((f) => f.close()));
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err: unknown) => {
  process.stderr.write(`fixture runner failed: ${(err as Error).message}\n`);
  process.exit(1);
});
