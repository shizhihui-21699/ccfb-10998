/**
 * Per-host orchestration: run every probe in dependency order under shared
 * safety budgets, then evaluate the result against a baseline.
 *
 * Order matters — later probes reuse earlier findings:
 *   TCP reachability -> protocols -> ciphers -> certificate -> {preference,
 *   renegotiation, OCSP} -> HSTS -> evaluate
 *
 * Concurrency is per-target: a scan of many hosts runs several hosts at once,
 * but each individual host's probes are sequential and paced, so no single
 * service sees a burst.
 */
import net from "node:net";
import { ProbeScheduler } from "../net/scheduler.ts";
import { probeProtocols } from "./protocols.ts";
import { probeCiphers } from "./ciphers.ts";
import { probePreference } from "./preference.ts";
import { probeCertificate } from "./certificate.ts";
import { probeRenegotiation } from "./renegotiation.ts";
import { probeOcspStapling } from "./ocsp-stapling.ts";
import { probeHsts } from "./hsts.ts";
import { DEFAULT_TIMING, type ProbeTiming } from "../net/client-hello.ts";
import type { Baseline } from "../baseline/types.ts";
import type {
  CertificateProbe,
  CipherProbe,
  HostEvaluation,
  HostReport,
  PreferenceProbe,
  ProbeStats,
  ProtocolProbe,
  RenegotiationProbe,
  OcspProbe,
  HstsProbe,
  Target,
} from "../types.ts";
import { targetLabel } from "../types.ts";
import { evaluateHost } from "../evaluate/engine.ts";

export interface HostScanOptions {
  baseline: Baseline;
  timing?: ProbeTiming;
  /** Disable the active renegotiation handshake test. */
  skipActiveRenegotiation?: boolean;
  /** Which probes to run; all by default. */
  enable?: Partial<Record<ProbeName, boolean>>;
  /** Progress callback for CLI feedback. */
  onProgress?: (message: string) => void;
}

export type ProbeName =
  | "protocols"
  | "ciphers"
  | "certificate"
  | "preference"
  | "renegotiation"
  | "ocsp"
  | "hsts";

/** Cheap TCP connect used to distinguish "unreachable" from "TLS rejected". */
function checkReachable(
  target: Target,
  timeoutMs: number,
): Promise<{ reachable: boolean; error?: string }> {
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.connect({ host: target.host, port: target.port });
    const done = (result: { reachable: boolean; error?: string }): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };
    const timer = setTimeout(() => done({ reachable: false, error: "TCP connect timeout" }), timeoutMs);
    socket.once("connect", () => done({ reachable: true }));
    socket.once("error", (err: NodeJS.ErrnoException) =>
      done({ reachable: false, error: `${err.code ?? "EUNKNOWN"}: ${err.message}` }),
    );
  });
}

const emptyProtocols = (): ProtocolProbe => ({
  outcomes: [],
  supported: [],
  highest: null,
  lowest: null,
});
const emptyCiphers = (): CipherProbe => ({ byVersion: [], totalProbes: 0 });
const emptyCertificate = (): CertificateProbe => ({ available: false });

export interface HostResult {
  report: HostReport;
  evaluation: HostEvaluation;
}

/**
 * Scan one host. Never throws for network/protocol problems: unreachable or
 * hostile endpoints are recorded in the report and scored accordingly.
 */
export async function scanHost(
  target: Target,
  options: HostScanOptions,
): Promise<HostResult> {
  const baseline = options.baseline;
  const timing = options.timing ?? DEFAULT_TIMING;
  const started = Date.now();
  const progress = options.onProgress ?? (() => {});
  const enable = options.enable ?? {};
  const enabled = (name: ProbeName): boolean => enable[name] !== false;

  const scheduler = new ProbeScheduler({
    concurrency: baseline.safety.concurrency,
    retries: baseline.safety.retries,
    maxAttempts: baseline.safety.maxAttemptsPerHost,
    deadlineMs: baseline.safety.deadlineMs,
    jitterMs: baseline.safety.jitterMs,
  });
  const stats: ProbeStats = {
    connections: 0,
    retries: 0,
    timeouts: 0,
    errors: 0,
    budgetExhausted: false,
  };

  progress(`[${targetLabel(target)}] checking reachability`);
  const reach = await checkReachable(target, timing.connectTimeoutMs);
  stats.connections += 1;

  if (!reach.reachable) {
    const report: HostReport = {
      target,
      startedAt: new Date(started).toISOString(),
      durationMs: Date.now() - started,
      reachable: false,
      ...(reach.error ? { tcpError: reach.error } : {}),
      protocols: emptyProtocols(),
      ciphers: emptyCiphers(),
      preference: { tested: false, serverPrefersOwnOrder: null, reason: "host unreachable" },
      renegotiation: {
        secureRenegotiation: null,
        acceptsClientInitiated: null,
        reason: "host unreachable",
      },
      ocsp: { stapled: null, reason: "host unreachable" },
      hsts: { httpResponded: null, present: null, reason: "host unreachable" },
      certificate: emptyCertificate(),
      stats,
    };
    return { report, evaluation: evaluateHost(baseline, report) };
  }

  // --- protocols ---------------------------------------------------------
  let protocols = emptyProtocols();
  if (enabled("protocols")) {
    progress(`[${targetLabel(target)}] probing protocol versions`);
    protocols = await probeProtocols(target, scheduler, {
      timing,
      includeSsl3: true,
    });
  }

  // --- ciphers -----------------------------------------------------------
  let ciphers = emptyCiphers();
  if (enabled("ciphers") && protocols.supported.length > 0) {
    progress(`[${targetLabel(target)}] enumerating cipher suites`);
    ciphers = await probeCiphers(target, scheduler, {
      timing,
      supportedVersions: protocols.supported,
      maxProbesPerVersion: baseline.safety.maxProbesPerVersion,
      maxProbesPerHost: baseline.safety.maxAttemptsPerHost - scheduler.counters.connections,
    });
  }

  // --- certificate -------------------------------------------------------
  let certificate = emptyCertificate();
  if (enabled("certificate") && protocols.supported.length > 0) {
    progress(`[${targetLabel(target)}] reading certificate`);
    certificate = await probeCertificate(target, protocols, scheduler, stats, { timing });
  }

  // The remaining probes are independent of each other; run them together but
  // under the same scheduler so the concurrency cap and pacing still apply.
  const [preference, renegotiation, ocsp, hsts] = await Promise.all([
    enabled("preference") && protocols.supported.length > 0
      ? probePreference(target, ciphers, scheduler, { timing })
      : Promise.resolve<PreferenceProbe>({
          tested: false,
          serverPrefersOwnOrder: null,
          reason: "skipped",
        }),
    enabled("renegotiation") && protocols.supported.length > 0
      ? probeRenegotiation(target, protocols, ciphers, scheduler, stats, {
          timing,
          ...(options.skipActiveRenegotiation ? { skipActiveTest: true } : {}),
        })
      : Promise.resolve<RenegotiationProbe>({
          secureRenegotiation: null,
          acceptsClientInitiated: null,
          reason: "skipped",
        }),
    enabled("ocsp") && protocols.supported.length > 0
      ? probeOcspStapling(target, protocols, certificate, scheduler, stats, { timing })
      : Promise.resolve<OcspProbe>({ stapled: null, reason: "skipped" }),
    enabled("hsts") && protocols.supported.length > 0
      ? probeHsts(target, protocols, stats, { timeoutMs: timing.readTimeoutMs })
      : Promise.resolve<HstsProbe>({ httpResponded: null, present: null, reason: "skipped" }),
  ]);

  // `stats.connections` has so far counted only connections opened directly by
  // probes (reachability, renegotiation handshake, OCSP-over-1.3, HSTS). Probes
  // that go through the scheduler are counted by the scheduler itself, so add
  // those now for a single accurate total.
  stats.connections += scheduler.counters.connections;
  stats.retries = scheduler.counters.retries;
  stats.errors = scheduler.counters.errors;
  stats.budgetExhausted = scheduler.counters.budgetExhausted;

  const report: HostReport = {
    target,
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    reachable: true,
    protocols,
    ciphers,
    preference,
    renegotiation,
    ocsp,
    hsts,
    certificate,
    stats,
  };

  progress(
    `[${targetLabel(target)}] done: ${protocols.supported.join("/") || "no TLS"} in ${report.durationMs}ms`,
  );

  return { report, evaluation: evaluateHost(baseline, report) };
}

