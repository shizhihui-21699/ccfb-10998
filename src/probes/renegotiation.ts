/**
 * Renegotiation checks.
 *
 * Two independent questions:
 *
 *  1. Does the server support RFC 5746 "secure renegotiation"? If it does not
 *     echo the renegotiation_info extension (or accept the SCSV) in its
 *     ServerHello, a network attacker can splice data into the handshake
 *     (the original 2009 prefix-injection flaw, CVE-2009-3555).
 *
 *  2. Does the server accept a *client-initiated* renegotiation? That lets any
 *     client force repeated key exchanges on one connection — a CPU
 *     amplification / DoS vector, which is why nginx and others disable it.
 *
 * (1) is answered from the plaintext ServerHello we already read. (2) requires
 * a completed handshake, so it uses node:tls, pinned to a pre-TLS-1.3 version
 * (TLS 1.3 removed renegotiation entirely).
 */
import tls from "node:tls";
import type { ConnectionOptions } from "node:tls";
import { constants as cryptoConstants } from "node:crypto";
import {
  DEFAULT_TIMING,
  probeClientHello,
  probeOrThrow,
  type ProbeTiming,
} from "../net/client-hello.ts";
import { VERSION } from "../tls/wire.ts";
import type { ProbeScheduler } from "../net/scheduler.ts";
import type {
  CipherProbe,
  ProbeStats,
  ProtocolProbe,
  RenegotiationProbe,
  Target,
  VersionString,
} from "../types.ts";
import { isIpLiteral } from "./protocols.ts";

const NODE_VERSIONS: Partial<Record<VersionString, tls.SecureVersion>> = {
  "TLSv1.2": "TLSv1.2",
  "TLSv1.1": "TLSv1.1",
  "TLSv1.0": "TLSv1",
};

/** Names Node/OpenSSL can actually negotiate on this host. */
const NODE_CIPHERS = new Set(tls.getCiphers().map((c) => c.toUpperCase()));

function cipherStringFor(version: VersionString, ciphers: CipherProbe): string {
  const enumeration = ciphers.byVersion.find((e) => e.version === version);
  const usable = (enumeration?.suites ?? [])
    .map((s) => s.name)
    .filter((name) => NODE_CIPHERS.has(name.toUpperCase()));
  // Include legacy strength settings so TLS 1.0/1.1 CBC suites remain usable.
  const base = usable.length > 0 ? usable.join(":") : "ALL";
  return `${base}:@SECLEVEL=0`;
}

function tlsConnectOptions(
  target: Target,
  version: VersionString,
  ciphers: CipherProbe,
): ConnectionOptions {
  const servername =
    target.serverName ?? (isIpLiteral(target.host) ? undefined : target.host);
  return {
    host: target.host,
    port: target.port,
    ...(servername ? { servername } : {}),
    rejectUnauthorized: false,
    minVersion: NODE_VERSIONS[version],
    maxVersion: NODE_VERSIONS[version],
    ciphers: cipherStringFor(version, ciphers),
    // Accept servers that lack RFC 5746; otherwise OpenSSL 3 refuses to connect
    // and we could not tell "rejects renegotiation" from "legacy handshake".
    secureOptions: cryptoConstants.SSL_OP_LEGACY_SERVER_CONNECT,
  };
}

interface ConnectAttempt {
  ok: boolean;
  socket?: tls.TLSSocket;
  error?: string;
  negotiatedVersion?: string;
  negotiatedCipher?: string;
  elapsedMs: number;
}

function openHandshake(
  options: ConnectionOptions,
  timeoutMs: number,
): Promise<ConnectAttempt> {
  const started = performance.now();
  return new Promise<ConnectAttempt>((resolve) => {
    let settled = false;
    let socket: tls.TLSSocket;
    // tls.connect throws synchronously for an unusable option (e.g. a cipher
    // string the local OpenSSL rejects); surface that as a failed attempt
    // rather than rejecting and aborting the whole scan.
    try {
      socket = tls.connect(options);
    } catch (err) {
      resolve({
        ok: false,
        error: `tls.connect failed: ${(err as Error).message}`,
        elapsedMs: Math.round(performance.now() - started),
      });
      return;
    }
    const done = (attempt: ConnectAttempt): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners("error");
      if (!attempt.ok) socket.destroy();
      resolve(attempt);
    };
    const timer = setTimeout(() => {
      done({ ok: false, error: "handshake timeout", elapsedMs: Math.round(performance.now() - started) });
    }, timeoutMs);

    socket.once("secureConnect", () => {
      done({
        ok: true,
        socket,
        negotiatedVersion: socket.getProtocol() ?? undefined,
        negotiatedCipher: socket.getCipher()?.name,
        elapsedMs: Math.round(performance.now() - started),
      });
    });
    socket.once("error", (err: NodeJS.ErrnoException) => {
      done({ ok: false, error: `${err.code ?? "EUNKNOWN"}: ${err.message}`, elapsedMs: Math.round(performance.now() - started) });
    });
  });
}

interface RenegotiationAttempt {
  /** true = accepted, false = refused, null = inconclusive/timeout */
  accepted: boolean | null;
  error?: string;
  /** True when the server answered with a no_renegotiation alert. */
  refusedByAlert?: boolean;
}

function attemptRenegotiation(
  socket: tls.TLSSocket,
  timeoutMs: number,
): Promise<RenegotiationAttempt> {
  return new Promise<RenegotiationAttempt>((resolve) => {
    let settled = false;
    const onError = (err: Error): void => {
      // A TLS alert (no_renegotiation / handshake_failure) means the server
      // actively refused. A bare transport reset or timeout tells us nothing
      // about policy, so leave the verdict unknown rather than asserting a
      // refusal the server never made.
      const message = err.message ?? String(err);
      const code = (err as NodeJS.ErrnoException).code;
      const refused =
        /no renegotiation|no_renegotiation|handshake failure|alert|tlsv1 alert/i.test(message);
      finish(
        refused
          ? { accepted: false, error: message, refusedByAlert: true }
          : { accepted: null, error: `${code ?? "error"}: ${message}` },
      );
    };
    const finish = (r: RenegotiationAttempt): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeListener("error", onError);
      resolve(r);
    };
    const timer = setTimeout(() => finish({ accepted: null, error: "renegotiation timed out" }), timeoutMs);

    socket.once("error", onError);

    try {
      socket.renegotiate({}, (err) => {
        if (!err) {
          finish({ accepted: true });
          return;
        }
        const message = err.message ?? String(err);
        const refused = /no renegotiation|no_renegotiation|handshake failure|alert/i.test(message);
        finish({ accepted: refused ? false : null, error: message, refusedByAlert: refused });
      });
    } catch (err) {
      finish({ accepted: null, error: (err as Error).message });
    }
  });
}

export interface RenegotiationOptions {
  timing?: ProbeTiming;
  /** Skip the socket-level client-initiated test (ServerHello check only). */
  skipActiveTest?: boolean;
}

/**
 * Choose the newest supported version that still permits renegotiation.
 */
function renegotiableVersion(protocols: ProtocolProbe): VersionString | undefined {
  const supported = new Set(protocols.supported);
  for (const v of ["TLSv1.2", "TLSv1.1", "TLSv1.0"] as const) {
    if (supported.has(v)) return v;
  }
  return undefined;
}

export async function probeRenegotiation(
  target: Target,
  protocols: ProtocolProbe,
  ciphers: CipherProbe,
  scheduler: ProbeScheduler,
  stats: ProbeStats,
  options: RenegotiationOptions = {},
): Promise<RenegotiationProbe> {
  const timing = options.timing ?? DEFAULT_TIMING;
  const version = renegotiableVersion(protocols);

  if (!version) {
    return {
      secureRenegotiation: null,
      acceptsClientInitiated: null,
      reason: "TLS 1.3 only — renegotiation is not part of TLS 1.3",
    };
  }

  // --- (1) RFC 5746 support from the plaintext ServerHello -----------------
  const wireVersion =
    version === "TLSv1.2" ? VERSION.TLS12 : version === "TLSv1.1" ? VERSION.TLS11 : VERSION.TLS10;
  const serverName = target.serverName ?? (isIpLiteral(target.host) ? undefined : target.host);
  const enumeration = ciphers.byVersion.find((e) => e.version === version);
  const offerSuites = (enumeration?.suites ?? []).map((s) => s.id);

  let secureRenegotiation: boolean | null = null;
  if (offerSuites.length > 0) {
    const hello = await scheduler.runSoft(async () => {
      const r = await probeClientHello(
        { host: target.host, port: target.port },
        {
          supportedVersions: [wireVersion],
          legacyVersion: wireVersion,
          suites: offerSuites,
          serverName,
          renegotiationInfo: true,
          keyShare: false,
        },
        timing,
      );
      return probeOrThrow(r);
    });
    if (hello && hello.kind === "server_hello") {
      secureRenegotiation = hello.secureRenegotiation;
    }
  }

  // --- (2) client-initiated renegotiation over a real handshake ------------
  if (options.skipActiveTest) {
    return {
      secureRenegotiation,
      acceptsClientInitiated: null,
      testedVersion: version,
      reason: "active renegotiation test skipped",
    };
  }

  const connect = await openHandshake(
    tlsConnectOptions(target, version, ciphers),
    timing.readTimeoutMs,
  );
  stats.connections += 1;

  if (!connect.ok || !connect.socket) {
    return {
      secureRenegotiation,
      acceptsClientInitiated: null,
      testedVersion: version,
      reason: `could not complete a ${version} handshake to test renegotiation`,
      error: connect.error,
    };
  }

  const socket = connect.socket;
  try {
    const result = await attemptRenegotiation(socket, timing.readTimeoutMs);
    return {
      secureRenegotiation,
      acceptsClientInitiated: result.accepted,
      testedVersion: version,
      ...(result.accepted === null && result.error ? { error: result.error } : {}),
    };
  } finally {
    socket.destroy();
  }
}

/** Human-readable renegotiation summary for CLI tables. */
export function describeRenegotiation(r: RenegotiationProbe): string {
  const parts: string[] = [];
  if (r.secureRenegotiation === true) parts.push("RFC5746 secure renegotiation");
  else if (r.secureRenegotiation === false) parts.push("NO secure renegotiation (RFC5746)");
  else parts.push("secure renegotiation unknown");

  if (r.acceptsClientInitiated === true) parts.push("accepts client renegotiation");
  else if (r.acceptsClientInitiated === false) parts.push("refuses client renegotiation");
  else if (r.reason) parts.push(r.reason);

  return parts.join(" | ");
}
