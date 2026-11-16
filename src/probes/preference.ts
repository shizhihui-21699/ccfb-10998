/**
 * Server cipher-preference detection (RFC 5246 §7.4.1.2).
 *
 * A server that "honours its own cipher order" ignores the client's preference
 * list and picks by its configured priority. We detect this by offering the
 * same two suites twice, in opposite orders:
 *
 *   offer A,B -> chose X
 *   offer B,A -> chose Y
 *
 *   X === Y      -> server prefers its own order
 *   X !== Y      -> server follows client order (weaker hardening)
 *
 * TLS 1.3 is deliberately not tested: the server picks the cipher (there is no
 * client-selectable encryption order), so the concept does not apply. We need
 * at least two suites that the server accepts for a pre-1.3 version; those come
 * from the enumeration results.
 */
import {
  DEFAULT_TIMING,
  probeClientHello,
  probeOrThrow,
  type ProbeTiming,
} from "../net/client-hello.ts";
import { VERSION } from "../tls/wire.ts";
import { suiteById } from "../tls/suites.ts";
import type { ProbeScheduler } from "../net/scheduler.ts";
import type {
  CipherProbe,
  PreferenceProbe,
  Target,
  VersionString,
} from "../types.ts";
import { isIpLiteral } from "./protocols.ts";

const WIRE_VERSION: Record<VersionString, number> = {
  "SSLv3": VERSION.SSL3,
  "TLSv1.0": VERSION.TLS10,
  "TLSv1.1": VERSION.TLS11,
  "TLSv1.2": VERSION.TLS12,
  "TLSv1.3": VERSION.TLS13,
};

export interface PreferenceOptions {
  timing?: ProbeTiming;
}

async function negotiate(
  target: Target,
  version: VersionString,
  suites: readonly number[],
  scheduler: ProbeScheduler,
  timing: ProbeTiming,
): Promise<{ suite: number | null; outcome: string }> {
  const serverName = target.serverName ?? (isIpLiteral(target.host) ? undefined : target.host);
  const wireVersion = WIRE_VERSION[version];
  const result = await scheduler.runSoft(async () => {
    const r = await probeClientHello(
      { host: target.host, port: target.port },
      {
        supportedVersions: [wireVersion],
        legacyVersion: wireVersion,
        suites,
        serverName,
        renegotiationInfo: true,
        keyShare: false,
      },
      timing,
    );
    return probeOrThrow(r);
  });
  if (result === null) return { suite: null, outcome: "probe failed (network)" };
  if (result.kind === "server_hello") {
    return { suite: result.cipherSuite, outcome: "server_hello" };
  }
  if (result.kind === "alert") return { suite: null, outcome: result.alert };
  if (result.kind === "timeout") return { suite: null, outcome: "timeout" };
  if (result.kind === "closed") return { suite: null, outcome: "closed" };
  return { suite: null, outcome: `${result.code}: ${result.message}` };
}

/**
 * Determine whether the server enforces its own cipher order.
 * Uses two accepted pre-1.3 suites from `ciphers`.
 */
export async function probePreference(
  target: Target,
  ciphers: CipherProbe,
  scheduler: ProbeScheduler,
  options: PreferenceOptions = {},
): Promise<PreferenceProbe> {
  const timing = options.timing ?? DEFAULT_TIMING;

  // Prefer TLS 1.2, then 1.1, then 1.0 — anywhere ≥2 suites were enumerated.
  const candidates = ciphers.byVersion.filter(
    (e) => e.version !== "TLSv1.3" && !e.error && e.suites.length >= 2,
  );
  const chosen = candidates[0];
  if (!chosen) {
    return {
      tested: false,
      serverPrefersOwnOrder: null,
      reason:
        "no pre-TLS1.3 version exposed two negotiable suites (TLS 1.3 has no client-ordered suites)",
    };
  }

  const [a, b] = chosen.suites;
  if (!a || !b) {
    return { tested: false, serverPrefersOwnOrder: null, reason: "fewer than two suites" };
  }

  const first = await negotiate(target, chosen.version, [a.id, b.id], scheduler, timing);
  const second = await negotiate(target, chosen.version, [b.id, a.id], scheduler, timing);

  if (first.suite === null || second.suite === null) {
    return {
      tested: true,
      version: chosen.version,
      serverPrefersOwnOrder: null,
      reason: `could not gather both negotiations (${first.outcome} / ${second.outcome})`,
    };
  }

  const orderA = { offered: [a.name, b.name], chosen: suiteById(first.suite).name };
  const orderB = { offered: [b.name, a.name], chosen: suiteById(second.suite).name };

  return {
    tested: true,
    version: chosen.version,
    serverPrefersOwnOrder: first.suite === second.suite,
    orderA,
    orderB,
  };
}
