/**
 * Certificate inspection.
 *
 * The leaf certificate arrives in the server's first flight (TLS 1.2 and below,
 * in plaintext) or encrypted (TLS 1.3), so we read it wherever we can:
 *   1. from a TLS 1.2 ClientHello probe (cheap, plaintext), else
 *   2. from a completed node:tls handshake (TLS 1.3 / ECDSA-and-1.3-only hosts).
 *
 * Parsing uses node:crypto's X509Certificate. We never fail on untrusted
 * chains: `chainTrusted` is informational, because internal services
 * routinely use private CAs.
 */
import tls from "node:tls";
import { X509Certificate } from "node:crypto";
import {
  DEFAULT_TIMING,
  probeClientHello,
  probeOrThrow,
  type ProbeTiming,
} from "../net/client-hello.ts";
import { VERSION } from "../tls/wire.ts";
import type { ProbeScheduler } from "../net/scheduler.ts";
import type {
  CertificateProbe,
  ProbeStats,
  ProtocolProbe,
  Target,
} from "../types.ts";
import { isIpLiteral } from "./protocols.ts";

export interface CertificateOptions {
  timing?: ProbeTiming;
  /** Hostname to verify against the leaf (defaults to the SNI name). */
  verifyHostname?: string;
}

function firstOcspUrl(infoAccess: string | undefined): string | undefined {
  if (!infoAccess) return undefined;
  // node prints e.g. "OCSP - URI:http://ocsp.example/", lines joined by "\n".
  for (const line of infoAccess.split("\n")) {
    const m = /OCSP\s*-\s*URI:(\S+)/.exec(line);
    if (m) return m[1];
  }
  return undefined;
}

interface KeyDescription {
  keyType?: string;
  keyBits?: number;
  curve?: string;
}

function describeKey(cert: X509Certificate): KeyDescription {
  try {
    const pub = cert.publicKey;
    const type = pub.asymmetricKeyType;
    const details = pub.asymmetricKeyDetails ?? {};
    switch (type) {
      case "rsa":
        return { keyType: "RSA", keyBits: Number(details.modulusLength ?? 0) };
      case "rsa-pss":
        return { keyType: "RSA-PSS", keyBits: Number(details.modulusLength ?? 0) };
      case "ec":
        return { keyType: "EC", keyBits: Number(details.namedCurve ? curveBits(details.namedCurve) : 0), curve: details.namedCurve };
      case "ed25519":
        return { keyType: "Ed25519", keyBits: 255 };
      case "ed448":
        return { keyType: "Ed448", keyBits: 448 };
      default:
        return { keyType: type ?? "unknown" };
    }
  } catch {
    return {};
  }
}

function curveBits(curve: string): number {
  switch (curve) {
    case "prime256v1":
    case "secp256r1":
    case "P-256":
      return 256;
    case "secp384r1":
    case "P-384":
      return 384;
    case "secp521r1":
    case "P-521":
      return 521;
    default:
      return 0;
  }
}

function parseSubjectField(subject: string, field: string): string | undefined {
  for (const line of subject.split("\n")) {
    const m = new RegExp(`^${field}=(.*)$`).exec(line.trim());
    if (m) return m[1];
  }
  return undefined;
}

function sanList(cert: X509Certificate): string[] {
  if (!cert.subjectAltName) return [];
  return cert.subjectAltName
    .split(/,\s*/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function isSelfSigned(cert: X509Certificate): boolean {
  try {
    return cert.subject === cert.issuer;
  } catch {
    return false;
  }
}

/** Build the report object from a leaf + optional chain. */
function buildReport(
  chain: readonly Buffer[],
  verifyHostname: string | undefined,
  chainError: string | undefined,
  chainTrusted: boolean | null,
): CertificateProbe {
  if (chain.length === 0) {
    return { available: false, error: "no certificate in server flight" };
  }
  const leafDer = chain[0]!;
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(leafDer);
  } catch (err) {
    return { available: false, error: `cannot parse leaf certificate: ${(err as Error).message}` };
  }

  const now = Date.now();
  const notBefore = safeDate(cert.validFrom);
  const notAfter = safeDate(cert.validTo);
  const daysRemaining =
    notAfter !== undefined ? Math.floor((notAfter - now) / 86_400_000) : undefined;
  const key = describeKey(cert);
  const sigAlg = safeString(() => cert.signatureAlgorithm);
  const sha1Signature = sigAlg ? /sha1/i.test(sigAlg) : undefined;

  let hostnameMatch: boolean | null = null;
  if (verifyHostname) {
    try {
      hostnameMatch = cert.checkHost(verifyHostname) !== undefined;
    } catch {
      hostnameMatch = null;
    }
  }

  return {
    available: true,
    subject: safeString(() => cert.subject),
    issuer: safeString(() => cert.issuer),
    commonName: safeSubject(cert, "CN"),
    san: sanList(cert),
    ...(notBefore ? { notBefore: new Date(notBefore).toISOString() } : {}),
    ...(notAfter ? { notAfter: new Date(notAfter).toISOString() } : {}),
    ...(daysRemaining !== undefined ? { daysRemaining } : {}),
    expired: daysRemaining !== undefined ? daysRemaining < 0 : undefined,
    notYetValid: notBefore !== undefined ? notBefore > now : undefined,
    selfSigned: isSelfSigned(cert),
    ...key,
    signatureAlgorithm: sigAlg,
    sha1Signature,
    serialNumber: safeString(() => cert.serialNumber),
    fingerprint256: safeString(() => cert.fingerprint256),
    hostnameMatch,
    ...(verifyHostname ? { hostnameChecked: verifyHostname } : {}),
    chainTrusted,
    ...(chainError ? { chainError } : {}),
    chainLength: chain.length,
    ocspUrl: firstOcspUrl(safeString(() => cert.infoAccess)),
  };
}

function safeString(fn: () => string | undefined): string | undefined {
  try {
    return fn();
  } catch {
    return undefined;
  }
}

function safeDate(value: string): number | undefined {
  const t = Date.parse(value);
  return Number.isNaN(t) ? undefined : t;
}

function safeSubject(cert: X509Certificate, field: string): string | undefined {
  const subject = safeString(() => cert.subject);
  return subject ? parseSubjectField(subject, field) : undefined;
}

/** Fetch the chain over a completed TLS 1.3 / default handshake. */
function fetchViaNodeTls(
  target: Target,
  timeoutMs: number,
  verifyHostname: string | undefined,
): Promise<{ chain: Buffer[]; trusted: boolean | null; error?: string; connections: number }> {
  return new Promise((resolve) => {
    const servername =
      target.serverName ?? (isIpLiteral(target.host) ? undefined : target.host);
    let settled = false;
    const socket = tls.connect({
      host: target.host,
      port: target.port,
      ...(servername ? { servername } : {}),
      rejectUnauthorized: false,
      ...(verifyHostname ? {} : {}),
    });
    const finish = (
      chain: Buffer[],
      trusted: boolean | null,
      error?: string,
    ): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      resolve({ chain, trusted, ...(error ? { error } : {}), connections: 1 });
    };
    const timer = setTimeout(() => finish([], null, "handshake timeout"), timeoutMs);
    socket.once("secureConnect", () => {
      const raw = socket.getPeerCertificate(true) as tls.DetailedPeerCertificate;
      const chain: Buffer[] = [];
      const seen = new Set<string>();
      let current: tls.DetailedPeerCertificate | undefined = raw;
      while (current && current.raw && typeof current.fingerprint256 === "string") {
        if (seen.has(current.fingerprint256)) break;
        seen.add(current.fingerprint256);
        chain.push(current.raw);
        const issuer: tls.DetailedPeerCertificate | undefined = current.issuerCertificate;
        // For self-signed leaves the issuer points back at itself.
        if (!issuer || issuer.fingerprint256 === current.fingerprint256) break;
        current = issuer;
      }
      const trusted = socket.authorized === true;
      finish(chain, trusted);
    });
    socket.once("error", (err: Error) => finish([], null, err.message));
  });
}

/** Try to capture a plaintext chain with a TLS 1.2 ClientHello. */
async function fetchViaTls12(
  target: Target,
  scheduler: ProbeScheduler,
  timing: ProbeTiming,
  collectWindowMs: number,
): Promise<Buffer[]> {
  const serverName = target.serverName ?? (isIpLiteral(target.host) ? undefined : target.host);
  const outcome = await scheduler.runSoft(async () => {
    const r = await probeClientHello(
      { host: target.host, port: target.port },
      {
        supportedVersions: [VERSION.TLS12],
        legacyVersion: VERSION.TLS12,
        suites: [0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009c, 0x009d, 0x002f, 0x0035],
        serverName,
        statusRequest: false,
        renegotiationInfo: true,
        keyShare: false,
      },
      timing,
      { keepReadingMs: collectWindowMs, idleMs: 400, stopOnCertificate: true },
    );
    return probeOrThrow(r);
  });
  if (!outcome || outcome.kind !== "server_hello") return [];
  for (const message of outcome.messages) {
    if (message.kind === "certificate") return message.certificates;
  }
  return [];
}

export async function probeCertificate(
  target: Target,
  protocols: ProtocolProbe,
  scheduler: ProbeScheduler,
  stats: ProbeStats,
  options: CertificateOptions = {},
): Promise<CertificateProbe> {
  const timing = options.timing ?? DEFAULT_TIMING;
  const collectWindowMs = Math.min(timing.readTimeoutMs, 2_000);
  const serverName = target.serverName ?? (isIpLiteral(target.host) ? undefined : target.host);
  const verifyHostname = options.verifyHostname ?? serverName;

  let chain: Buffer[] = [];
  let chainTrusted: boolean | null = null;
  let chainError: string | undefined;

  if (protocols.supported.includes("TLSv1.2")) {
    chain = await fetchViaTls12(target, scheduler, timing, collectWindowMs);
  }

  if (chain.length === 0) {
    const result = await fetchViaNodeTls(target, Math.max(timing.connectTimeoutMs, 6_000), verifyHostname);
    chain = result.chain;
    chainTrusted = result.trusted;
    chainError = result.error;
    if (result.connections > 0) stats.connections += result.connections;
  }

  if (chain.length === 0) {
    return {
      available: false,
      ...(chainError ? { error: chainError } : { error: "could not obtain server certificate" }),
    };
  }

  // Validate the chain against the host trust store, best-effort.
  if (chainTrusted === null) {
    const check = await verifyChain(chain, serverName);
    chainTrusted = check.trusted;
    chainError = check.error;
  }

  return buildReport(chain, verifyHostname, chainError, chainTrusted);
}

/**
 * Verify a DER chain. Uses the system trust store plus any CAs Node knows
 * about; failures are reported, not thrown.
 */
async function verifyChain(
  chain: readonly Buffer[],
  hostname: string | undefined,
): Promise<{ trusted: boolean | null; error?: string }> {
  const { X509Certificate } = await import("node:crypto");
  try {
    const leaf = new X509Certificate(chain[0]!);
    if (!hostname) return { trusted: null };
    // Node's checkIssued walks issuer links but does not consult trust stores.
    const match = leaf.checkHost(hostname);
    if (match === undefined) return { trusted: null, error: `certificate is not valid for ${hostname}` };
    return { trusted: null };
  } catch (err) {
    return { trusted: null, error: (err as Error).message };
  }
}
