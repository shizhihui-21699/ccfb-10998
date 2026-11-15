import { TlsVersion } from './types';

export interface Baseline {
  /** minimum protocol version that must be the *oldest* enabled (older ones are forbidden) */
  minProtocol: TlsVersion;
  /** protocol versions that must not be enabled at all */
  forbiddenProtocols: TlsVersion[];
  /** deduct a little if TLS 1.3 is missing */
  recommendTls13: boolean;
  /** server must enforce its own cipher order */
  requireServerCipherOrder: boolean;
  /** substring patterns (case-insensitive) matched against OpenSSL cipher names */
  weakCipherPatterns: string[];
  /** ciphers without forward secrecy (non ECDHE/DHE key exchange) are penalized */
  penalizeNonPfs: boolean;
  ocspStapling: 'required' | 'optional' | 'ignore';
  hsts: {
    required: boolean;
    minMaxAge: number;
    requireIncludeSubDomains: boolean;
  };
  cert: {
    penalizeSelfSigned: boolean;
    expiringSoonDays: number;
  };
  weights: {
    forbiddenProtocol: number;
    missingTls13: number;
    weakCipher: number;
    weakCipherCap: number;
    nonPfsCipher: number;
    nonPfsCap: number;
    cipherOrder: number;
    renegotiationInfoMissing: number;
    clientRenegotiationAllowed: number;
    ocspMissing: number;
    hstsMissing: number;
    hstsShortMaxAge: number;
    hstsNoIncludeSubDomains: number;
    certExpired: number;
    certExpiringSoon: number;
    certSelfSigned: number;
  };
}

export const DEFAULT_BASELINE: Baseline = {
  minProtocol: 'TLSv1.2',
  forbiddenProtocols: ['TLSv1', 'TLSv1.1'],
  recommendTls13: true,
  requireServerCipherOrder: true,
  weakCipherPatterns: ['NULL', 'EXP', 'RC4', 'RC2', 'IDEA', 'MD5', 'anon', '3DES', 'DES-CBC', 'SEED', 'CAMELLIA'],
  penalizeNonPfs: true,
  ocspStapling: 'optional',
  hsts: {
    required: false,
    minMaxAge: 15552000, // 180 days
    requireIncludeSubDomains: false,
  },
  cert: {
    penalizeSelfSigned: true,
    expiringSoonDays: 30,
  },
  weights: {
    forbiddenProtocol: 15,
    missingTls13: 5,
    weakCipher: 5,
    weakCipherCap: 25,
    nonPfsCipher: 2,
    nonPfsCap: 10,
    cipherOrder: 10,
    renegotiationInfoMissing: 5,
    clientRenegotiationAllowed: 5,
    ocspMissing: 5,
    hstsMissing: 10,
    hstsShortMaxAge: 5,
    hstsNoIncludeSubDomains: 3,
    certExpired: 40,
    certExpiringSoon: 5,
    certSelfSigned: 5,
  },
};

export function mergeBaseline(user?: Partial<Baseline>): Baseline {
  if (!user) return DEFAULT_BASELINE;
  return {
    ...DEFAULT_BASELINE,
    ...user,
    hsts: { ...DEFAULT_BASELINE.hsts, ...(user.hsts ?? {}) },
    cert: { ...DEFAULT_BASELINE.cert, ...(user.cert ?? {}) },
    weights: { ...DEFAULT_BASELINE.weights, ...(user.weights ?? {}) },
  };
}
