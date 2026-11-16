/**
 * OCSP stapling probe.
 *
 * TLS 1.2: send status_request in the ClientHello and look for a
 * CertificateStatus handshake message in the server's first flight — that is
 * the staple. We capture it over the same plaintext transport used elsewhere.
 *
 * TLS 1.3: CertificateStatus is encrypted, so it cannot be seen without
 * completing the handshake. We fall back to node:tls with `requestOCSP`, which
 * surfaces the staple through its OCSPResponse event.
 *
 * "Stapling disabled" is only reported when a certificate actually carries an
 * OCSP AIA URL — without one there is nothing to staple, and calling that a
 * finding would be noise.
 */
import tls from "node:tls";
import {
  DEFAULT_TIMING,
  probeClientHello,
  probeOrThrow,
  type ProbeTiming,
} from "../net/client-hello.ts";
import { VERSION } from "../tls/wire.ts";
import { parseOcspResponse, type StapleSummary } from "../tls/ocsp.ts";
import type { ProbeScheduler } from "../net/scheduler.ts";
import type {
  CertificateProbe,
  OcspProbe,
  ProbeStats,
  ProtocolProbe,
  Target,
  VersionString,
} from "../types.ts";
import { isIpLiteral } from "./protocols.ts";

export interface OcspStaplingOptions {
  timing?: ProbeTiming;
  /** How long to wait after ServerHello for Certificate/CertificateStatus. */
  collectWindowMs?: number;
}

function hasOcspAia(cert: CertificateProbe): boolean {
  return typeof cert.ocspUrl === "string" && cert.ocspUrl.length > 0;
}

/** Build the staple summary into an OcspProbe. */
function summarize(der: Buffer, testedVersion: VersionString): OcspProbe {
  const parsed: StapleSummary = parseOcspResponse(der);
  const now = Date.now();
  const expired =
    parsed.nextUpdate !== undefined && Date.parse(parsed.nextUpdate) < now;
  return {
    stapled: true,
    status: parsed.error ? "malformed" : parsed.leafStatus,
    ...(parsed.producedAt ? { producedAt: parsed.producedAt } : {}),
    ...(parsed.thisUpdate ? { thisUpdate: parsed.thisUpdate } : {}),
    ...(parsed.nextUpdate ? { nextUpdate: parsed.nextUpdate } : {}),
    ...(parsed.producerName ? { responder: parsed.producerName } : {}),
    size: der.length,
    expired,
    testedVersion,
    ...(parsed.error ? { error: parsed.error } : {}),
  };
}

/**
 * TLS 1.2 staple capture over a plaintext ClientHello.
 * Returns the raw staple, or null when the server sent none.
 */
async function stapleViaTls12(
  target: Target,
  scheduler: ProbeScheduler,
  timing: ProbeTiming,
  collectWindowMs: number,
): Promise<{ staple: Buffer | null; sawCertificate: boolean }> {
  const serverName = target.serverName ?? (isIpLiteral(target.host) ? undefined : target.host);
  const outcome = await scheduler.runSoft(async () => {
    const r = await probeClientHello(
      { host: target.host, port: target.port },
      {
        supportedVersions: [VERSION.TLS12],
        legacyVersion: VERSION.TLS12,
        // A broad modern list: the specific suite does not matter for stapling.
        suites: [0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009c, 0x009d, 0x002f, 0x0035],
        serverName,
        statusRequest: true,
        renegotiationInfo: true,
        keyShare: false,
      },
      timing,
      { keepReadingMs: collectWindowMs, idleMs: 150 },
    );
    return probeOrThrow(r);
  });

  if (!outcome || outcome.kind !== "server_hello") {
    return { staple: null, sawCertificate: false };
  }
  let sawCertificate = false;
  for (const message of outcome.messages) {
    if (message.kind === "certificate") sawCertificate = true;
    if (message.kind === "certificate_status") {
      return { staple: message.response, sawCertificate };
    }
  }
  return { staple: null, sawCertificate };
}

/**
 * TLS 1.3 staple capture via node:tls (CertificateStatus is encrypted there).
 */
function stapleViaTls13(target: Target, timeoutMs: number): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const servername =
      target.serverName ?? (isIpLiteral(target.host) ? undefined : target.host);
    let settled = false;
    let staple: Buffer | null = null;
    const socket = tls.connect({
      host: target.host,
      port: target.port,
      ...(servername ? { servername } : {}),
      rejectUnauthorized: false,
      requestOCSP: true,
      minVersion: "TLSv1.3",
      maxVersion: "TLSv1.3",
    });

    const finish = (value: Buffer | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      resolve(value);
    };
    const timer = setTimeout(() => finish(staple), timeoutMs);

    socket.on("OCSPResponse", (response: Buffer | null) => {
      // Node emits this once during the handshake, with the staple or null.
      if (response && response.length > 0) staple = response;
      // The staple (or its absence) is known now; no need to wait further.
      finish(staple);
    });
    socket.once("secureConnect", () => {
      // No OCSPResponse event by the time the handshake completes means the
      // server sent no staple.
      finish(staple);
    });
    socket.once("error", () => finish(staple));
  });
}

/**
 * Probe OCSP stapling. `protocols` tells us which TLS version to try, and
 * `certificate` decides whether "not stapled" is worth reporting.
 */
export async function probeOcspStapling(
  target: Target,
  protocols: ProtocolProbe,
  certificate: CertificateProbe,
  scheduler: ProbeScheduler,
  stats: ProbeStats,
  options: OcspStaplingOptions = {},
): Promise<OcspProbe> {
  const timing = options.timing ?? DEFAULT_TIMING;
  const collectWindowMs = options.collectWindowMs ?? 800;
  const hasOcsp = hasOcspAia(certificate);

  const supports12 = protocols.supported.includes("TLSv1.2");
  const supports13 = protocols.supported.includes("TLSv1.3");

  if (!supports12 && !supports13) {
    return {
      stapled: null,
      reason: "no TLS 1.2 or 1.3 to test stapling over",
      hasOcspAia: hasOcsp,
    };
  }

  if (supports12) {
    const { staple } = await stapleViaTls12(target, scheduler, timing, collectWindowMs);
    if (staple !== null) {
      return { ...summarize(staple, "TLSv1.2"), hasOcspAia: hasOcsp };
    }
    // TLS 1.2 gave no staple; if 1.3 is available the server may still staple
    // there, so fall through before concluding.
    if (!supports13) {
      return {
        stapled: false,
        testedVersion: "TLSv1.2",
        hasOcspAia: hasOcsp,
        reason: hasOcsp
          ? "certificate has an OCSP AIA URL but the server sent no CertificateStatus"
          : "certificate has no OCSP AIA URL, so there is nothing to staple",
      };
    }
  }

  const staple = await stapleViaTls13(target, Math.max(timing.readTimeoutMs, 4_000));
  stats.connections += 1;
  if (staple !== null) {
    return { ...summarize(staple, "TLSv1.3"), hasOcspAia: hasOcsp };
  }
  return {
    stapled: false,
    testedVersion: supports13 ? "TLSv1.3" : "TLSv1.2",
    hasOcspAia: hasOcsp,
    reason: hasOcsp
      ? "certificate has an OCSP AIA URL but the server did not staple a response"
      : "certificate has no OCSP AIA URL, so there is nothing to staple",
  };
}
