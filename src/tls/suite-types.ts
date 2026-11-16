/** Cipher-suite metadata shape, shared by the generated table and lookup code. */

export type MinTlsVersion = "SSLv3" | "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

export interface SuiteMeta {
  /** IANA numeric suite id, e.g. 0xc02f. */
  readonly id: number;
  /** OpenSSL-style short name, e.g. "ECDHE-RSA-AES128-GCM-SHA256". */
  readonly name: string;
  /** Lowest protocol version in which this suite is defined. */
  readonly minVersion: MinTlsVersion;
  readonly kx: string;
  readonly auth: string;
  readonly enc: string;
  readonly mac: string;
  /** True when the key exchange gives forward secrecy (and the suite is not anonymous). */
  readonly forwardSecrecy: boolean;
  /** True when the suite is considered weak: RC4/3DES/DES/RC2/EXPORT/NULL/GOST/MD5 or no auth. */
  readonly weak: boolean;
  /** True for suites with Au=None (no certificate authentication). */
  readonly anonymous: boolean;
}
