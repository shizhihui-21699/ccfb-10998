/** Shared result/domain types for tls-doctor. */

export type VersionString = "SSLv3" | "TLSv1.0" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

export const ALL_VERSIONS: readonly VersionString[] = [
  "SSLv3",
  "TLSv1.0",
  "TLSv1.1",
  "TLSv1.2",
  "TLSv1.3",
];

export interface Target {
  /** Hostname or IP literal to connect to. */
  host: string;
  port: number;
  /** SNI value; defaults to host when it is a DNS name. */
  serverName?: string;
  /** Optional display label (defaults to host:port). */
  label?: string;
}

export function targetLabel(t: Target): string {
  if (t.label) return t.label;
  // Bracket IPv6 literals so `::1:443` is not ambiguous.
  const host = t.host.includes(":") ? `[${t.host}]` : t.host;
  return `${host}:${t.port}`;
}

/* ------------------------------------------------------------- protocols */

export interface ProtocolOutcome {
  version: VersionString;
  supported: boolean;
  /** Suite the server picked when only this version was offered. */
  negotiatedSuite?: string;
  /** Why the probe concluded "not supported". */
  reason?: string;
  /** TLS alert name if the server rejected the offer. */
  alert?: string;
  /**
   * True when the probe reached a definitive verdict: the server either
   * negotiated the version, rejected it with a TLS alert, or answered with a
   * different version. False for timeouts, connection errors, and scheduler
   * budget/deadline stops — those leave the version's support *unknown*, which
   * must not be scored as "not supported".
   */
  conclusive: boolean;
  elapsedMs: number;
}

export interface ProtocolProbe {
  /** Ordered from oldest to newest. */
  outcomes: ProtocolOutcome[];
  supported: VersionString[];
  highest: VersionString | null;
  lowest: VersionString | null;
}

/* --------------------------------------------------------------- ciphers */

export interface SuiteEntry {
  id: number;
  name: string;
  weak: boolean;
  forwardSecrecy: boolean;
  anonymous: boolean;
  enc: string;
  kx: string;
  auth: string;
  mac: string;
}

export interface CipherEnumeration {
  version: VersionString;
  suites: SuiteEntry[];
  /** Number of ClientHello probes spent discovering these suites. */
  probes: number;
  /** True when the per-host probe budget ran out before the set was complete. */
  truncated: boolean;
  /** Set when enumeration could not run for this version. */
  error?: string;
  /**
   * Set when the server behaved unexpectedly (e.g. chose a suite we never
   * offered). The confirmed suites are still reported, but the version's
   * coverage is suspect and suite rules treat it as incomplete.
   */
  anomaly?: string;
}

export interface CipherProbe {
  byVersion: CipherEnumeration[];
  totalProbes: number;
}

/* ------------------------------------------------------------ preference */

export interface PreferenceProbe {
  /** False when no pre-1.3 version supported 2+ suites, or TLS 1.3 only. */
  tested: boolean;
  version?: VersionString;
  /** True = server picks by its own order; false = it follows client order. */
  serverPrefersOwnOrder: boolean | null;
  orderA?: { offered: string[]; chosen: string };
  orderB?: { offered: string[]; chosen: string };
  reason?: string;
}

/* ---------------------------------------------------------- renegotiation */

export interface RenegotiationProbe {
  /** RFC 5746 secure renegotiation extension echoed by the server. */
  secureRenegotiation: boolean | null;
  /**
   * Whether the server accepted a client-initiated renegotiation.
   * null = not testable (e.g. TLS 1.3 only, handshake failed).
   */
  acceptsClientInitiated: boolean | null;
  testedVersion?: VersionString;
  reason?: string;
  error?: string;
}

/* ------------------------------------------------------------------ ocsp */

export type OcspStatus = "good" | "revoked" | "unknown" | "malformed";

export interface OcspProbe {
  /** Did the server staple an OCSP response at all? */
  stapled: boolean | null;
  /** Parsed certificate status from the staple, if any. */
  status?: OcspStatus;
  producedAt?: string;
  thisUpdate?: string;
  nextUpdate?: string;
  responder?: string;
  /** Raw staple size in bytes. */
  size?: number;
  /** True when nextUpdate is in the past. */
  expired?: boolean;
  testedVersion?: VersionString;
  /** True if the certificate carries an OCSP AIA URL at all. */
  hasOcspAia?: boolean;
  reason?: string;
  error?: string;
}

/* ------------------------------------------------------------------ hsts */

export interface HstsProbe {
  /** Did an HTTP(S) response arrive at all? */
  httpResponded: boolean | null;
  statusCode?: number;
  present: boolean | null;
  maxAge?: number;
  includeSubDomains?: boolean;
  preload?: boolean;
  raw?: string;
  reason?: string;
  error?: string;
}

/* ----------------------------------------------------------- certificate */

export interface CertificateProbe {
  available: boolean;
  subject?: string;
  issuer?: string;
  commonName?: string;
  san?: string[];
  notBefore?: string;
  notAfter?: string;
  daysRemaining?: number;
  expired?: boolean;
  notYetValid?: boolean;
  selfSigned?: boolean;
  keyType?: string;
  keyBits?: number;
  curve?: string;
  signatureAlgorithm?: string;
  sha1Signature?: boolean;
  serialNumber?: string;
  fingerprint256?: string;
  hostnameMatch?: boolean | null;
  hostnameChecked?: string;
  /** Chain validation against the host's trust store, when attempted. */
  chainTrusted?: boolean | null;
  chainError?: string;
  chainLength?: number;
  /** AIA OCSP responder URL from the leaf, if present. */
  ocspUrl?: string;
  error?: string;
}

/* -------------------------------------------------------------- overall */

export interface ProbeStats {
  connections: number;
  retries: number;
  timeouts: number;
  errors: number;
  budgetExhausted: boolean;
}

export interface HostReport {
  target: Target;
  startedAt: string;
  durationMs: number;
  reachable: boolean;
  tcpError?: string;
  protocols: ProtocolProbe;
  ciphers: CipherProbe;
  preference: PreferenceProbe;
  renegotiation: RenegotiationProbe;
  ocsp: OcspProbe;
  hsts: HstsProbe;
  certificate: CertificateProbe;
  stats: ProbeStats;
}

/* -------------------------------------------------------------- findings */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type CheckStatus = "pass" | "fail" | "warn" | "na";

export interface Finding {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  weight: number;
  status: CheckStatus;
  message: string;
  evidence?: unknown;
}

export interface Score {
  /** 0-100, rounded to one decimal. */
  value: number;
  grade: string;
  /** Weighted points earned / available. */
  earned: number;
  available: number;
  counts: Record<CheckStatus, number>;
}

export interface HostEvaluation {
  findings: Finding[];
  score: Score;
}
