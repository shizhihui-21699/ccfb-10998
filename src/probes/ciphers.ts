/**
 * Cipher-suite enumeration by iterative elimination.
 *
 * For a version, we send one ClientHello offering every remaining candidate.
 * The server picks its favourite; we record it and remove it from the list.
 * Repeating until the server stops negotiating yields exactly the suites it
 * accepts, without testing each suite individually:
 *
 *   N suites supported  ->  N + 1 ClientHellos (the last one is rejected)
 *
 * Every probe is a single TCP connection that we abort right after the
 * ServerHello, so enumerating a host is a bounded, small number of short-lived
 * connections. A per-host probe budget caps the worst case.
 */
import {
  DEFAULT_TIMING,
  probeClientHello,
  probeOrThrow,
  type ProbeTiming,
} from "../net/client-hello.ts";
import { VERSION } from "../tls/wire.ts";
import { offerListFor, suiteById } from "../tls/suites.ts";
import type { ProbeScheduler } from "../net/scheduler.ts";
import type {
  CipherEnumeration,
  CipherProbe,
  SuiteEntry,
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

function serverNameFor(target: Target): string | undefined {
  if (target.serverName) return target.serverName;
  return isIpLiteral(target.host) ? undefined : target.host;
}

function toEntry(id: number): SuiteEntry {
  const meta = suiteById(id);
  return {
    id: meta.id,
    name: meta.name,
    weak: meta.weak,
    forwardSecrecy: meta.forwardSecrecy,
    anonymous: meta.anonymous,
    enc: meta.enc,
    kx: meta.kx,
    auth: meta.auth,
    mac: meta.mac,
  };
}

export interface CipherProbeOptions {
  timing?: ProbeTiming;
  /** Max ClientHello probes spent per version (safety budget). */
  maxProbesPerVersion?: number;
  /** Max probes per host across all versions. */
  maxProbesPerHost?: number;
}

/**
 * Enumerate the suites a server accepts for one protocol version.
 * Returns an empty set with `error` if the version is not supported.
 */
export async function enumerateCiphers(
  target: Target,
  version: VersionString,
  scheduler: ProbeScheduler,
  options: CipherProbeOptions = {},
  versionSupported = true,
): Promise<CipherEnumeration> {
  const timing = options.timing ?? DEFAULT_TIMING;
  const budget = options.maxProbesPerVersion ?? 64;

  if (!versionSupported) {
    return { version, suites: [], probes: 0, truncated: false, error: "version not supported" };
  }

  const wireVersion = WIRE_VERSION[version];
  let candidates = offerListFor(
    version === "SSLv3" ? "TLSv1.0" : (version as "TLSv1.3" | "TLSv1.2" | "TLSv1.1" | "TLSv1.0"),
  );
  if (candidates.length === 0) {
    return { version, suites: [], probes: 0, truncated: false, error: "no offer list for version" };
  }

  const accepted: number[] = [];
  let probes = 0;
  let truncated = false;
  const serverName = serverNameFor(target);
  const is13 = version === "TLSv1.3";

  while (candidates.length > 0) {
    if (probes >= budget) {
      truncated = true;
      break;
    }
    const offer = candidates;
    // `runSoft` still propagates RateLimitError (budget/deadline), which is the
    // scheduler telling us to stop. Treat it as truncation for *this host*
    // rather than letting it abort the whole fleet scan.
    let outcome: Awaited<ReturnType<typeof probeClientHello>> | null;
    try {
      outcome = await scheduler.runSoft(async () => {
        const result = await probeClientHello(
          { host: target.host, port: target.port },
          {
            supportedVersions: [wireVersion],
            legacyVersion: is13 ? VERSION.TLS12 : wireVersion,
            suites: offer,
            serverName,
            renegotiationInfo: true,
            keyShare: is13,
          },
          timing,
        );
        return probeOrThrow(result);
      });
    } catch {
      // Scheduler budget/deadline exceeded: stop enumerating this version.
      return {
        version,
        suites: accepted.map(toEntry),
        probes,
        truncated: true,
        error: "probe budget/deadline exhausted during enumeration",
      };
    }

    if (outcome === null) {
      probes += 1;
      return {
        version,
        suites: accepted.map(toEntry),
        probes,
        truncated,
        error: "probe failed (network)",
      };
    }

    if (outcome.kind !== "server_hello") {
      // Server rejected the remaining offer set: enumeration is complete.
      probes += 1;
      break;
    }

    if (outcome.version !== wireVersion) {
      // Server answered with a different version than requested; stop rather
      // than record a suite that belongs to another version's list.
      probes += 1;
      break;
    }

    probes += 1;
    const picked = outcome.cipherSuite;
    if (!candidates.includes(picked)) {
      // The server selected a suite we never offered: a middlebox or a buggy
      // endpoint. Do not present it as a normal negotiable suite — that would
      // be a false positive — but surface the fact and stop, since continuing
      // could loop forever. The suites already confirmed stay in the result.
      return {
        version,
        suites: accepted.map(toEntry),
        probes,
        truncated,
        anomaly: `server chose an unoffered suite 0x${picked.toString(16).padStart(4, "0")} (${suiteById(picked).name})`,
      };
    }

    accepted.push(picked);
    candidates = candidates.filter((id) => id !== picked);
  }

  return { version, suites: accepted.map(toEntry), probes, truncated };
}

export interface FullCipherOptions extends CipherProbeOptions {
  /** Versions known to be supported, newest first; enumeration runs only here. */
  supportedVersions: readonly VersionString[];
}

/**
 * Enumerate suites for every supported version. TLS 1.3 is enumerated before
 * 1.2 etc.; the per-host budget is shared across them.
 */
export async function probeCiphers(
  target: Target,
  scheduler: ProbeScheduler,
  options: FullCipherOptions,
): Promise<CipherProbe> {
  const perHostBudget = options.maxProbesPerHost ?? 200;
  const byVersion: CipherEnumeration[] = [];
  let totalProbes = 0;

  for (const version of options.supportedVersions) {
    if (totalProbes >= perHostBudget) {
      byVersion.push({
        version,
        suites: [],
        probes: 0,
        truncated: true,
        error: "per-host probe budget exhausted",
      });
      continue;
    }
    const remaining = perHostBudget - totalProbes;
    const enumeration = await enumerateCiphers(
      target,
      version,
      scheduler,
      {
        ...options,
        maxProbesPerVersion: Math.min(options.maxProbesPerVersion ?? 64, remaining),
      },
      true,
    );
    totalProbes += enumeration.probes;
    byVersion.push(enumeration);
  }

  // Newest version first in the report.
  byVersion.sort((a, b) => versionRank(b.version) - versionRank(a.version));

  return { byVersion, totalProbes };
}

function versionRank(v: VersionString): number {
  switch (v) {
    case "TLSv1.3":
      return 3;
    case "TLSv1.2":
      return 2;
    case "TLSv1.1":
      return 1;
    case "TLSv1.0":
      return 0;
    case "SSLv3":
      return -1;
  }
}
