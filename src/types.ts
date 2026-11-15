/**
 * Shared types for the TLS checkup tool.
 *
 * Everything here is plain data so that probe results can be serialized to
 * JSON, compared across runs, and scored by the baseline evaluator without
 * importing any of the probing machinery.
 */

/** TLS protocol versions we know how to probe, keyed by the wire version id. */
export const TLS_VERSIONS = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as const;
export type TlsVersionName = (typeof TLS_VERSIONS)[number];

/** 16-bit wire ids for the protocol versions. TLS 1.3 uses 0x0304 in supported_versions. */
export const VERSION_ID: Record<TlsVersionName, number> = {
  'TLSv1.0': 0x0301,
  'TLSv1.1': 0x0302,
  'TLSv1.2': 0x0303,
  'TLSv1.3': 0x0304,
};

/** Which major family a cipher suite belongs to. */
export type SuiteFamily = 'TLS1.3' | 'ECDHE' | 'DHE' | 'static-RSA' | 'static-DH' | 'anonymous' | 'other';

/** How a suite is judged by the built-in heuristics. */
export type SuiteStrength = 'strong' | 'acceptable' | 'weak' | 'insecure' | 'null' | 'unknown';

export interface SuiteInfo {
  id: number;
  /** 4-char hex, e.g. "c02f". */
  hex: string;
  /** IANA name when known, otherwise "UNKNOWN-0x....". */
  name: string;
  /** OpenSSL-style short name when known, e.g. ECDHE-RSA-AES128-GCM-SHA256. */
  opensslName?: string;
  family: SuiteFamily;
  strength: SuiteStrength;
  /** Human-readable reasons for the strength verdict. */
  notes: string[];
  /** Forward-secret: the session key does not depend on the server's long-term key. */
  forwardSecret: boolean;
  /** Authenticated: the server proves possession of a certificate key (not anonymous). */
  authenticated: boolean;
  /** IANA recommendation column, when the suite is in the registry. */
  ianaRecommended?: 'Y' | 'D' | 'N' | '';
  /** True when the suite is TLS 1.3 (its name has no Kx/Au component). */
  isTls13: boolean;
}

export interface VersionResult {
  version: TlsVersionName;
  supported: boolean;
  /** Suite chosen by the server for this version, when the probe succeeded. */
  selectedSuite?: SuiteInfo;
  /** Suites confirmed available on this version (may be a subset if enumeration was capped). */
  suites: SuiteInfo[];
  /** True when suite enumeration stopped early because of a configured cap. */
  enumerationTruncated: boolean;
  /**
   * Extension type ids from the ServerHello of the first successful handshake
   * on this version. Lets the caller read the passive renegotiation_info and
   * status_request signals without extra connections.
   */
  serverHelloExtensions?: number[];
  /** Failure category when the version was not supported. */
  failure?: ProbeFailure;
}

export type ProbeFailureKind =
  | 'refused'
  | 'timeout'
  | 'reset'
  | 'dns'
  | 'alert'
  | 'closed'
  | 'tls-error'
  | 'internal';

export interface ProbeFailure {
  kind: ProbeFailureKind;
  /** Alert description number when the server sent a fatal alert. */
  alert?: number;
  alertName?: string;
  /** Short human-readable explanation. */
  message: string;
}

/** Result of the "does the server enforce its own suite order" experiment. */
export interface PreferenceResult {
  version: TlsVersionName;
  /** The suite the server picks regardless of client order. */
  firstChoice?: SuiteInfo;
  /** The suite the server picks when that first choice is withheld. */
  secondChoice?: SuiteInfo;
  /** True when reordering the same two suites does not change the pick. */
  serverPrefers: boolean;
  /** Both probes agreed with a stable choice per order. */
  conclusive: boolean;
  /** Set when the experiment could not run. */
  failure?: ProbeFailure;
}

export interface RenegotiationResult {
  /** The server advertised the secure renegotiation extension (RFC 5746). */
  secureRenegotiationSupported: boolean;
  /**
   * False when no TLS <= 1.2 version is enabled, so renegotiation does not
   * exist at all (TLS 1.3 removed it). In that case the checks are satisfied
   * by construction rather than by evidence.
   */
  applicable: boolean;
  /** A client-initiated renegotiation was actually accepted on a live connection. */
  clientInitiatedAccepted: boolean;
  /**
   * Whether the live test produced a definite answer. A timeout or a dropped
   * connection leaves "accepted" false without proof of refusal, and the
   * report must not present an unproven pass as a pass.
   */
  conclusive: boolean;
  /** Details about how the conclusion was reached, for the report. */
  detail: string;
  /** Version used for the live test, when one ran. */
  testedOn?: TlsVersionName;
}

export interface OcspResult {
  /** The server returned a stapled OCSP response during the handshake. */
  stapled: boolean;
  /** Response size in bytes, when stapled. */
  responseBytes?: number;
  /** Certificate status when it could be parsed: good / revoked / unknown. */
  certificateStatus?: 'good' | 'revoked' | 'unknown';
  /** True when the handshake advertised status_request in ServerHello extensions. */
  statusRequestExtension: boolean;
  /** Version(s) on which stapling was observed. */
  observedOn: TlsVersionName[];
  detail: string;
}

export interface HstsResult {
  /** A plain-HTTP fetch was attempted (baseline asks for it). */
  fetched: boolean;
  /** Header value as received, if present. */
  header?: string;
  present: boolean;
  maxAge?: number;
  /** max-age >= 1 year (the common preload threshold). */
  longMaxAge: boolean;
  includeSubDomains: boolean;
  preload: boolean;
  /** Multiple header values were sent (which browsers ignore). */
  duplicates: boolean;
  /** Malformed directives, e.g. max-age not a number. */
  problems: string[];
  /** HTTP status of the response that carried the header. */
  httpStatus?: number;
  /** Where the header came from: the https probe or a separate http fetch. */
  source?: 'https-handshake' | 'http-fetch';
  failure?: ProbeFailure;
}

export interface CertificateSummary {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  expired: boolean;
  keyType: string;
  keySize: number;
  signatureAlgorithm: string;
  sha1Signature: boolean;
  selfSigned: boolean;
  subjectAltNames: string[];
  chainLength: number;
}

export interface EndpointResult {
  host: string;
  port: number;
  /** Server name sent in SNI. */
  serverName?: string;
  /** Target label used in reports (defaults to host:port). */
  label: string;
  reachable: boolean;
  /**
   * TCP connected but no TLS version was negotiated. Distinct from `reachable`
   * so the report can say "this port is open but not serving TLS" instead of
   * treating it as an unreachable host.
   */
  tlsAbsent?: boolean;
  /** Highest version that completed a handshake. */
  highestVersion?: TlsVersionName;
  versions: VersionResult[];
  /** All suites observed across versions, deduplicated. */
  suites: SuiteInfo[];
  preference?: PreferenceResult;
  renegotiation?: RenegotiationResult;
  ocsp?: OcspResult;
  hsts?: HstsResult;
  certificate?: CertificateSummary;
  /** Non-fatal problems encountered while probing (timeouts, odd alerts). */
  warnings: string[];
  /** Wall-clock duration of the endpoint scan in ms. */
  durationMs: number;
}

export interface ProbeOptions {
  host: string;
  port: number;
  serverName?: string;
  /** Per-connection timeout. */
  timeoutMs: number;
  /** Maximum suites to enumerate per version (protects slow/old servers). */
  maxSuitesPerVersion: number;
  /** Attempt HSTS retrieval over the TLS connection (and plain HTTP fallback). */
  checkHsts: boolean;
  /** Attempt OCSP stapling detection. */
  checkOcsp: boolean;
  /** Attempt live client-initiated renegotiation. */
  checkRenegotiation: boolean;
  /** Skip certificate verification (internal services often use private CAs). */
  rejectUnauthorized: boolean;
  /** CA bundle path when verification is on. */
  caFile?: string;
  /** Plain-HTTP port used to fetch HSTS when the TLS handshake has no HTTP. */
  httpPort?: number;
}
