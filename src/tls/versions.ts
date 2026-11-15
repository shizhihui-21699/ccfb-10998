/**
 * Protocol version and cipher suite enumeration for one endpoint.
 *
 * Enumeration strategy
 * --------------------
 * Naively testing 60 candidate suites per version means 60 handshakes per
 * version and shades into a load test. Instead we use adaptive removal:
 *
 *   1. Offer all candidates for the version. The server picks its most
 *      preferred one that it supports. Record it.
 *   2. Remove that suite from the offer and repeat with the remainder.
 *   3. Stop when the server rejects (no mutually supported suite) or when we
 *      hit `maxSuitesPerVersion`.
 *
 * That costs one handshake per *supported* suite plus one final rejection,
 * so a typical internal server with 8–15 suites takes 9–16 hellos for TLS 1.2
 * and 2–4 for TLS 1.3. It also naturally reveals the server's preference
 * order, which we reuse for the preference check.
 *
 * Version detection uses one hello per version. A server that supports a
 * version answers with a ServerHello; otherwise it sends a protocol_version /
 * handshake_failure alert, which we record rather than retry.
 */
import { helloProbe } from './probe.ts';
import { candidateSuitesFor } from './suites.ts';
import { describeSuite } from './suites.ts';
import type { SuiteInfo, TlsVersionName, VersionResult } from '../types.ts';
import { TLS_VERSIONS } from '../types.ts';

export interface EnumerateOptions {
  host: string;
  port: number;
  serverName?: string;
  timeoutMs: number;
  maxSuitesPerVersion: number;
  /** Delay between two handshakes to the same endpoint, in ms. Gentle by default. */
  interProbeDelayMs: number;
  /** Hard cap on total handshakes for this endpoint across all versions. */
  maxHandshakes: number;
  /** Called before each handshake so the caller can enforce a global budget. */
  onHandshake?: () => void;
}

interface VersionSpec {
  version: TlsVersionName;
  legacyVersion: number;
  offerTls13: boolean;
}

const VERSION_SPECS: VersionSpec[] = [
  { version: 'TLSv1.0', legacyVersion: 0x0301, offerTls13: false },
  { version: 'TLSv1.1', legacyVersion: 0x0302, offerTls13: false },
  { version: 'TLSv1.2', legacyVersion: 0x0303, offerTls13: false },
  { version: 'TLSv1.3', legacyVersion: 0x0303, offerTls13: true },
];

// Note: intentionally *not* unref'd. During the gap between two hellos there
// may be no socket outstanding, and an unref'd timer would let Node exit the
// process mid-scan.
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Enumerates versions and suites. Versions are probed in order from oldest to
 * newest so that the report has a natural reading order; total handshakes are
 * capped by `maxHandshakes`.
 */
export async function enumerateEndpoint(opts: EnumerateOptions): Promise<{
  versions: VersionResult[];
  handshakes: number;
}> {
  const versions: VersionResult[] = [];
  let handshakes = 0;

  const budgetLeft = () => handshakes < opts.maxHandshakes;

  const runProbe = async (spec: VersionSpec, suites: readonly number[]) => {
    if (!budgetLeft()) {
      return { skipped: true as const };
    }
    opts.onHandshake?.();
    handshakes++;
    const res = await helloProbe({
      host: opts.host,
      port: opts.port,
      legacyVersion: spec.legacyVersion,
      offerTls13: spec.offerTls13,
      suites,
      serverName: opts.serverName,
      timeoutMs: opts.timeoutMs,
      requestStatus: true,
    });
    if (opts.interProbeDelayMs > 0) await sleep(opts.interProbeDelayMs);
    return res;
  };

  for (const spec of VERSION_SPECS) {
    const candidates = candidateSuitesFor(spec.offerTls13 ? 0x0304 : spec.legacyVersion);
    const first = await runProbe(spec, candidates);

    if ('skipped' in first) {
      versions.push({
        version: spec.version,
        supported: false,
        suites: [],
        enumerationTruncated: true,
        failure: { kind: 'internal', message: 'handshake budget exhausted before this version could be probed' },
      });
      continue;
    }

    if (!first.ok) {
      versions.push({
        version: spec.version,
        supported: false,
        suites: [],
        enumerationTruncated: false,
        failure: first.failure,
      });
      continue;
    }

    // Confirm the server really selected this version. A TLS 1.3-capable server
    // answering a legacy hello will pick 1.2, which would otherwise look like
    // support for a version we did not offer.
    const selected = first.serverHello.selectedVersion;
    const expected = spec.offerTls13 ? 0x0304 : spec.legacyVersion;
    if (selected !== expected) {
      // Server answered, but negotiated something else: this version is not
      // actually supported (e.g. it downgraded to 1.2). Report accordingly.
      versions.push({
        version: spec.version,
        supported: false,
        suites: [],
        enumerationTruncated: false,
        failure: {
          kind: 'tls-error',
          message: `server answered with ${versionNameSafe(selected)} when ${spec.version} was offered`,
        },
      });
      continue;
    }

    const selectedSuiteId = first.serverHello.cipherSuite;
    const collected: number[] = [selectedSuiteId];
    let remaining = candidates.filter((id) => id !== selectedSuiteId);
    let truncated = false;

    // Adaptive enumeration: keep removing the negotiated suite until rejection.
    while (remaining.length > 0) {
      if (collected.length >= opts.maxSuitesPerVersion) {
        truncated = true;
        break;
      }
      if (!budgetLeft()) {
        truncated = true;
        break;
      }
      const res = await runProbe(spec, remaining);
      if ('skipped' in res || !res.ok) break;
      const picked = res.serverHello.cipherSuite;
      if (!remaining.includes(picked)) {
        // Server picked a suite we did not offer (protocol bug) or repeated a
        // choice: stop rather than loop.
        break;
      }
      if (collected.includes(picked)) break;
      collected.push(picked);
      remaining = remaining.filter((id) => id !== picked);
    }

    // Present suites in a stable order: strongest first for readability.
    const suiteInfos = collected.map(describeSuite).sort(compareSuites);
    versions.push({
      version: spec.version,
      supported: true,
      selectedSuite: describeSuite(selectedSuiteId),
      suites: suiteInfos,
      enumerationTruncated: truncated,
      serverHelloExtensions: first.serverHello.extensions.types,
    });
  }

  return { versions, handshakes };
}

function versionNameSafe(id: number): string {
  switch (id) {
    case 0x0301:
      return 'TLSv1.0';
    case 0x0302:
      return 'TLSv1.1';
    case 0x0303:
      return 'TLSv1.2';
    case 0x0304:
      return 'TLSv1.3';
    default:
      return `0x${id.toString(16)}`;
  }
}

const STRENGTH_ORDER: Record<SuiteInfo['strength'], number> = {
  strong: 0,
  acceptable: 1,
  unknown: 2,
  weak: 3,
  insecure: 4,
  null: 5,
};

export function compareSuites(a: SuiteInfo, b: SuiteInfo): number {
  const s = STRENGTH_ORDER[a.strength] - STRENGTH_ORDER[b.strength];
  if (s !== 0) return s;
  return a.id - b.id;
}

/** Highest supported version, if any. */
export function highestVersion(versions: VersionResult[]): TlsVersionName | undefined {
  for (const v of [...TLS_VERSIONS].reverse()) {
    const r = versions.find((x) => x.version === v);
    if (r?.supported) return v;
  }
  return undefined;
}

/** Flatten all suites observed across versions into one deduplicated list. */
export function mergeSuites(versions: VersionResult[]): SuiteInfo[] {
  const seen = new Map<number, SuiteInfo>();
  for (const v of versions) {
    for (const s of v.suites) if (!seen.has(s.id)) seen.set(s.id, s);
  }
  return [...seen.values()].sort(compareSuites);
}
