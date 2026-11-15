/**
 * Endpoint orchestration: runs every probe for one host:port and assembles an
 * EndpointResult.
 *
 * Ordering is deliberate and keeps the number of connections small:
 *
 *   1. Version + suite enumeration. One hello per supported suite. This also
 *      yields the ServerHello extension set that the passive renegotiation and
 *      status_request checks need, for free.
 *   2. Cipher preference. Two hellos.
 *   3. Certificate + staple. Two node:tls sessions (TLS 1.2 and 1.3), which
 *      also supply the leaf certificate.
 *   4. Renegotiation. One node:tls session + one renegotiation attempt.
 *   5. HSTS. One HTTP request on the existing TLS path (plus an optional
 *      plain-HTTP fetch).
 *
 * A typical endpoint therefore costs roughly (supported suites + 8) TCP
 * connections, all sequential within the endpoint. Concurrency happens across
 * endpoints, not within one, which is what keeps a single service from being
 * hammered.
 */
import { enumerateEndpoint, highestVersion, mergeSuites } from './versions.ts';
import { probePreference } from './preference.ts';
import { probeRenegotiation } from './renegotiation.ts';
import { probeOcsp } from './ocsp.ts';
import { probeHsts } from './hsts.ts';
import { summarizeCertificate, certificateWarnings } from './certificate.ts';
import { tlsSession } from './probe.ts';
import type { EndpointResult, ProbeOptions, TlsVersionName } from '../types.ts';

export interface EndpointProbeOptions extends ProbeOptions {
  /** Global handshake budget shared across all endpoints (checked before each hello). */
  onHandshake?: () => void;
  /** Delay between consecutive probes to this endpoint. */
  interProbeDelayMs?: number;
  /** Maximum total hellos for this endpoint. */
  maxHandshakes?: number;
}

export async function probeEndpoint(opts: EndpointProbeOptions): Promise<EndpointResult> {
  const start = performance.now();
  const warnings: string[] = [];
  const label = `${opts.host}:${opts.port}`;

  const enumeration = await enumerateEndpoint({
    host: opts.host,
    port: opts.port,
    serverName: opts.serverName,
    timeoutMs: opts.timeoutMs,
    maxSuitesPerVersion: opts.maxSuitesPerVersion,
    interProbeDelayMs: opts.interProbeDelayMs ?? 20,
    maxHandshakes: opts.maxHandshakes ?? 200,
    ...(opts.onHandshake ? { onHandshake: opts.onHandshake } : {}),
  });

  const { versions } = enumeration;
  const supported = versions.filter((v) => v.supported);
  const reachable = supported.length > 0;
  const highest = highestVersion(versions);
  const suites = mergeSuites(versions);

  // Any version probe that failed for a non-restrictive reason is worth a warning.
  for (const v of versions) {
    if (!v.supported && v.failure) {
      if (v.failure.kind === 'timeout') warnings.push(`${v.version}: probe timed out`);
      else if (v.failure.kind === 'reset') warnings.push(`${v.version}: connection reset mid-probe`);
      else if (v.failure.kind === 'tls-error') warnings.push(`${v.version}: ${v.failure.message}`);
    }
  }

  const result: EndpointResult = {
    host: opts.host,
    port: opts.port,
    ...(opts.serverName ? { serverName: opts.serverName } : {}),
    label,
    reachable,
    ...(reachable
      ? {}
      : {
          tlsAbsent:
            versions.every((v) => v.failure !== undefined && (v.failure.kind === 'closed' || v.failure.kind === 'alert')) &&
            versions.some((v) => v.failure?.kind === 'closed'),
        }),
    ...(highest ? { highestVersion: highest } : {}),
    versions,
    suites,
    warnings,
    durationMs: 0,
  };

  if (!reachable) {
    // No version answered. Report why, and still attempt an HTTP fetch when a
    // plain-HTTP port was configured: a target with no TLS listener at all is
    // a finding in itself ("this port is not speaking TLS"), not a transport
    // error, and its HSTS story is still worth reporting.
    const firstFailure = versions[0]?.failure;
    if (firstFailure && (firstFailure.kind === 'refused' || firstFailure.kind === 'dns')) {
      warnings.push(`no listener answered on this port: ${firstFailure.message}`);
    } else if (firstFailure) {
      warnings.push(
        `the port accepted TCP but does not appear to speak TLS (${firstFailure.message}); ` +
          `this is a configuration finding, not a transport error`,
      );
    }
    if (opts.checkHsts && opts.httpPort !== undefined) {
      result.hsts = await probeHsts({
        host: opts.host,
        port: opts.port,
        serverName: opts.serverName,
        timeoutMs: opts.timeoutMs,
        httpPort: opts.httpPort,
        rejectUnauthorized: opts.rejectUnauthorized,
        ...(opts.caFile ? { caFile: opts.caFile } : {}),
      });
    }
    result.durationMs = Math.round(performance.now() - start);
    return result;
  }

  // --- cipher preference --------------------------------------------------
  // Use the version with the most enumerated suites; that is where a server
  // preference is most visible and where the two-order test is meaningful.
  const richest = [...supported].sort((a, b) => b.suites.length - a.suites.length)[0];
  if (richest && richest.suites.length >= 2) {
    const legacyVersion = richest.version === 'TLSv1.0' ? 0x0301 : richest.version === 'TLSv1.1' ? 0x0302 : 0x0303;
    result.preference = await probePreference({
      host: opts.host,
      port: opts.port,
      serverName: opts.serverName,
      timeoutMs: opts.timeoutMs,
      version: richest.version,
      legacyVersion,
      offerTls13: richest.version === 'TLSv1.3',
      first: richest.suites[0]!,
      second: richest.suites[1]!,
    });
  }

  // --- certificate + OCSP staple -----------------------------------------
  // We ask on TLS 1.2 preferentially (staple events are reliable there) and on
  // TLS 1.3 as well so the report can state whether stapling works on both.
  const ocspVersions: TlsVersionName[] = [];
  if (supported.some((v) => v.version === 'TLSv1.2')) ocspVersions.push('TLSv1.2');
  if (supported.some((v) => v.version === 'TLSv1.3')) ocspVersions.push('TLSv1.3');
  if (ocspVersions.length === 0 && highest) ocspVersions.push(highest);

  const certSession = await tlsSession({
    host: opts.host,
    port: opts.port,
    serverName: opts.serverName,
    minVersion: 'TLSv1.2',
    timeoutMs: opts.timeoutMs,
    requestOCSP: opts.checkOcsp,
    alpn: ['h2', 'http/1.1'],
    rejectUnauthorized: opts.rejectUnauthorized,
    caFile: opts.caFile,
  });

  if (certSession.ok && certSession.chain && certSession.chain.length > 0) {
    const cert = summarizeCertificate(certSession.chain);
    if (cert) {
      result.certificate = cert;
      warnings.push(...certificateWarnings(cert));
    }
  } else if (!certSession.ok && certSession.failure) {
    warnings.push(`certificate fetch failed: ${certSession.failure.message}`);
  }

  if (opts.checkOcsp) {
    // The enumeration hellos already asked for status_request; a ServerHello
    // that echoed extension 5 is a passive "we support stapling" signal.
    const statusRequestSeen: Partial<Record<TlsVersionName, boolean>> = {};
    for (const v of supported) {
      statusRequestSeen[v.version] = (v.serverHelloExtensions ?? []).includes(5);
    }
    const ocsp = await probeOcsp(
      {
        host: opts.host,
        port: opts.port,
        serverName: opts.serverName,
        timeoutMs: opts.timeoutMs,
        versions: ocspVersions,
        rejectUnauthorized: opts.rejectUnauthorized,
        caFile: opts.caFile,
      },
      statusRequestSeen,
    );
    // Fold in the staple we may already have seen on the certificate session.
    if (!ocsp.stapled && certSession.ocspResponse && certSession.ocspResponse.length > 0) {
      ocsp.stapled = true;
      ocsp.responseBytes = certSession.ocspResponse.length;
      ocsp.observedOn = certSession.protocol ? [certSession.protocol as TlsVersionName] : [];
      ocsp.detail += '; staple also seen on the certificate session';
    }
    result.ocsp = ocsp;
  }

  // --- renegotiation ------------------------------------------------------
  // The passive fact comes from any TLS <= 1.2 ServerHello; a TLS 1.3-only
  // server has no renegotiation by design and is not penalised.
  const legacySupported = supported.filter((v) => v.version !== 'TLSv1.3');
  const liveTestVersion: TlsVersionName | undefined = legacySupported.some((v) => v.version === 'TLSv1.2')
    ? 'TLSv1.2'
    : legacySupported[0]?.version;
  // Passive fact: did any TLS <= 1.2 ServerHello echo renegotiation_info
  // (extension 0xff01, type 65281)? A TLS 1.3-only server has none by design.
  const passiveSupported = legacySupported.some((v) => (v.serverHelloExtensions ?? []).includes(0xff01));
  const reneg = await probeRenegotiation(
    {
      host: opts.host,
      port: opts.port,
      serverName: opts.serverName,
      timeoutMs: opts.timeoutMs,
      rejectUnauthorized: opts.rejectUnauthorized,
      caFile: opts.caFile,
      ...(liveTestVersion ? { liveTestVersion } : {}),
      passiveOnly: !opts.checkRenegotiation,
    },
    passiveSupported,
  );
  result.renegotiation = reneg;

  // --- HSTS ---------------------------------------------------------------
  if (opts.checkHsts) {
    result.hsts = await probeHsts({
      host: opts.host,
      port: opts.port,
      serverName: opts.serverName,
      timeoutMs: opts.timeoutMs,
      ...(opts.httpPort !== undefined ? { httpPort: opts.httpPort } : {}),
      rejectUnauthorized: opts.rejectUnauthorized,
      ...(opts.caFile ? { caFile: opts.caFile } : {}),
    });
  }

  result.durationMs = Math.round(performance.now() - start);
  return result;
}
