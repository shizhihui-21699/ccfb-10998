/**
 * Detects whether the server enforces its own cipher suite preference.
 *
 * Method: offer the same two suites to the same version in both orders.
 *   - Server picks the same suite both times  => server preference (good).
 *   - Server picks the client's first suite   => client preference.
 *
 * TLS 1.3 has a wrinkle: RFC 8446 §4.1.3 says the server MUST use its own
 * preference and the client SHOULD ignore its own, so a TLS 1.3 server that
 * honours client order is protocol-nonconforming. We therefore only report
 * client preference as a finding for TLS 1.2 and below.
 */
import { helloProbe } from './probe.ts';
import { describeSuite } from './suites.ts';
import type { PreferenceResult, SuiteInfo, TlsVersionName } from '../types.ts';

export interface PreferenceProbeOptions {
  host: string;
  port: number;
  serverName?: string;
  timeoutMs: number;
  version: TlsVersionName;
  legacyVersion: number;
  offerTls13: boolean;
  /** The server's first two preferred suites, from enumeration. */
  first: SuiteInfo;
  second: SuiteInfo;
}

export async function probePreference(opts: PreferenceProbeOptions): Promise<PreferenceResult> {
  const orderA = [opts.first.id, opts.second.id];
  const orderB = [opts.second.id, opts.first.id];

  const a = await helloProbe({
    host: opts.host,
    port: opts.port,
    legacyVersion: opts.legacyVersion,
    offerTls13: opts.offerTls13,
    suites: orderA,
    serverName: opts.serverName,
    timeoutMs: opts.timeoutMs,
  });
  const b = await helloProbe({
    host: opts.host,
    port: opts.port,
    legacyVersion: opts.legacyVersion,
    offerTls13: opts.offerTls13,
    suites: orderB,
    serverName: opts.serverName,
    timeoutMs: opts.timeoutMs,
  });

  if (!a.ok || !b.ok) {
    return {
      version: opts.version,
      serverPrefers: false,
      conclusive: false,
      failure: (!a.ok ? a.failure : !b.ok ? b.failure : undefined)!,
    };
  }

  const pickA = a.serverHello.cipherSuite;
  const pickB = b.serverHello.cipherSuite;

  // Each probe must select one of the two offered suites, and the two orders
  // must be internally consistent, otherwise the experiment is inconclusive.
  const valid = orderA.includes(pickA) && orderB.includes(pickB);
  if (!valid) {
    return {
      version: opts.version,
      serverPrefers: false,
      conclusive: false,
      failure: { kind: 'tls-error', message: 'server selected a suite that was not offered' },
    };
  }

  return {
    version: opts.version,
    firstChoice: describeSuite(pickA),
    secondChoice: describeSuite(pickB),
    serverPrefers: pickA === pickB,
    conclusive: true,
  };
}
