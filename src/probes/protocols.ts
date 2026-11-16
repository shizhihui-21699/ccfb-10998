/**
 * Protocol version discovery.
 *
 * Offers one version at a time (never a range) so the reply is unambiguous:
 * either the server negotiates that exact version, or it rejects with a
 * version/alert. We also send one broad "what is your favourite version"
 * hello to learn the server's preferred version quickly.
 */
import {
  DEFAULT_TIMING,
  probeClientHello,
  probeOrThrow,
  type ProbeTiming,
} from "../net/client-hello.ts";
import { VERSION, versionName } from "../tls/wire.ts";
import { offerListFor } from "../tls/suites.ts";
import { suiteById } from "../tls/suites.ts";
import { RateLimitError } from "../net/scheduler.ts";
import type { ProbeScheduler } from "../net/scheduler.ts";
import type {
  ProtocolOutcome,
  ProtocolProbe,
  Target,
  VersionString,
} from "../types.ts";

interface VersionSpec {
  name: VersionString;
  code: number;
}

const VERSION_SPECS: readonly VersionSpec[] = [
  { name: "TLSv1.3", code: VERSION.TLS13 },
  { name: "TLSv1.2", code: VERSION.TLS12 },
  { name: "TLSv1.1", code: VERSION.TLS11 },
  { name: "TLSv1.0", code: VERSION.TLS10 },
  { name: "SSLv3", code: VERSION.SSL3 },
];

/** Look up the wire spec for a named version. */
export function specForVersion(name: VersionString): { name: VersionString; code: number } {
  const spec = VERSION_SPECS.find((s) => s.name === name);
  if (!spec) throw new Error(`unknown TLS version: ${name}`);
  return spec;
}

/** Broad modern+legacy suite list used when only discovering versions. */
function discoverySuites(): number[] {
  const ids = new Set<number>();
  for (const name of ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"] as const) {
    for (const id of offerListFor(name)) ids.add(id);
  }
  return [...ids];
}

function serverNameFor(target: Target): string | undefined {
  if (target.serverName) return target.serverName;
  // IP literals are not valid SNI; omit it unless explicitly configured.
  return isIpLiteral(target.host) ? undefined : target.host;
}

export function isIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

export interface VersionProbeOptions {
  timing?: ProbeTiming;
  /** Include SSLv3 in the sweep (off by default: almost always rejected). */
  includeSsl3?: boolean;
}

/**
 * Probe a single protocol version in isolation.
 * Returns the ServerHello's negotiated suite, or the rejection reason.
 */
export async function probeVersion(
  target: Target,
  spec: VersionSpec,
  scheduler: ProbeScheduler,
  options: VersionProbeOptions = {},
): Promise<ProtocolOutcome> {
  const timing = options.timing ?? DEFAULT_TIMING;
  const suites = spec.name === "SSLv3" ? [] : offerListFor(spec.name);
  const helloSuites = suites.length > 0 ? suites : discoverySuites();
  const started = performance.now();

  let outcome: Awaited<ReturnType<typeof probeClientHello>> | null = null;
  let failure: string | undefined;
  try {
    outcome = await scheduler.run(async () => {
      const result = await probeClientHello(
        { host: target.host, port: target.port },
        {
          supportedVersions: [spec.code],
          legacyVersion: spec.code === VERSION.TLS13 ? VERSION.TLS12 : spec.code,
          suites: helloSuites,
          serverName: serverNameFor(target),
          renegotiationInfo: true,
          keyShare: spec.code === VERSION.TLS13,
        },
        timing,
      );
      return probeOrThrow(result);
    });
  } catch (err) {
    // Keep the real reason: a refused connection reads very differently from a
    // timeout, and both differ from a scheduler budget stop.
    failure =
      err instanceof RateLimitError
        ? "probe budget/deadline exhausted"
        : `${(err as NodeJS.ErrnoException).code ?? "error"}: ${(err as Error).message}`;
  }

  const elapsedMs = Math.round(performance.now() - started);

  if (outcome === null) {
    return {
      version: spec.name,
      supported: false,
      conclusive: false,
      reason: failure ?? "probe failed",
      elapsedMs,
    };
  }

  switch (outcome.kind) {
    case "server_hello":
      return {
        version: spec.name,
        supported: outcome.version === spec.code,
        conclusive: true,
        negotiatedSuite: suiteById(outcome.cipherSuite).name,
        reason:
          outcome.version === spec.code
            ? undefined
            : `server answered with ${versionName(outcome.version)}`,
        elapsedMs,
      };
    case "alert":
      return {
        version: spec.name,
        supported: false,
        conclusive: true,
        alert: outcome.alert,
        reason: `server sent ${outcome.alert}`,
        elapsedMs,
      };
    case "closed":
      // A server that accepts TCP but closes without a TLS byte is a
      // definitive "not speaking TLS here"; treat it as conclusive.
      return {
        version: spec.name,
        supported: false,
        conclusive: true,
        reason: `connection closed with no reply (${outcome.bytes} bytes)`,
        elapsedMs,
      };
    case "timeout":
      return {
        version: spec.name,
        supported: false,
        conclusive: false,
        reason: `timeout during ${outcome.phase}`,
        elapsedMs,
      };
    case "error":
      return {
        version: spec.name,
        supported: false,
        conclusive: false,
        reason: `${outcome.code}: ${outcome.message}`,
        elapsedMs,
      };
  }
}

/**
 * Probe every version concurrently (bounded by the scheduler) and summarise.
 */
export async function probeProtocols(
  target: Target,
  scheduler: ProbeScheduler,
  options: VersionProbeOptions = {},
): Promise<ProtocolProbe> {
  const specs = options.includeSsl3
    ? VERSION_SPECS
    : VERSION_SPECS.filter((s) => s.name !== "SSLv3");

  const outcomes = await Promise.all(
    specs.map((spec) => probeVersion(target, spec, scheduler, options)),
  );

  // Present oldest → newest regardless of probe order.
  const ordered = [...outcomes].sort(
    (a, b) => versionOrder(a.version) - versionOrder(b.version),
  );
  const supported = ordered.filter((o) => o.supported).map((o) => o.version);

  return {
    outcomes: ordered,
    supported,
    highest: supported.at(-1) ?? null,
    lowest: supported[0] ?? null,
  };
}

export function versionOrder(v: VersionString): number {
  switch (v) {
    case "SSLv3":
      return 0;
    case "TLSv1.0":
      return 1;
    case "TLSv1.1":
      return 2;
    case "TLSv1.2":
      return 3;
    case "TLSv1.3":
      return 4;
  }
}
