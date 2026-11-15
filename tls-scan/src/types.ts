export type TlsVersion = 'TLSv1' | 'TLSv1.1' | 'TLSv1.2' | 'TLSv1.3';

export const ALL_VERSIONS: TlsVersion[] = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];

export interface Target {
  host: string;
  port: number;
  servername?: string;
}

export interface VersionProbe {
  version: TlsVersion;
  supported: boolean;
  error?: string;
  negotiatedCipher?: string;
}

export interface CipherInfo {
  opensslName: string;   // e.g. ECDHE-RSA-AES128-GCM-SHA256
  standardName?: string; // e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
}

export interface CipherEnumResult {
  version: TlsVersion;
  ciphers: CipherInfo[];
  source: 'elimination' | 'openssl-cli' | 'negotiated-only';
  note?: string;
}

export interface CipherOrderResult {
  tested: boolean;
  enforcesServerOrder?: boolean;
  detail: string;
}

export interface RenegotiationResult {
  /** server sent renegotiation_info extension => secure renegotiation (RFC 5746) */
  secureRenegotiationExt: boolean | null;
  /** server accepted a client-initiated renegotiation attempt */
  clientInitiatedAllowed: boolean | null;
  note: string;
}

export interface HstsResult {
  present: boolean;
  maxAge?: number;
  includeSubDomains?: boolean;
  preload?: boolean;
  raw?: string;
  nonHttp?: boolean;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  selfSigned: boolean;
}

export interface ScanResult {
  target: Target;
  startedAt: string;
  durationMs: number;
  versions: VersionProbe[];
  ciphers: CipherEnumResult[];
  cipherOrder: CipherOrderResult;
  renegotiation: RenegotiationResult;
  ocspStapling: boolean | null;
  hsts: HstsResult | null;
  cert: CertInfo | null;
  error?: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  severity: Severity;
  check: string;
  message: string;
  deduction: number;
}

export interface ScoreReport {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  findings: Finding[];
}
