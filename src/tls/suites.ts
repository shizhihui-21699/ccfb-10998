/**
 * Cipher-suite knowledge base: lookup by IANA id or short name, plus the
 * curated offer lists the probe walks when enumerating what a server accepts.
 */
import type { MinTlsVersion, SuiteMeta } from "./suite-types.ts";
import { SUITE_TABLE } from "./suite-data.generated.ts";

export type { MinTlsVersion, SuiteMeta };

const BY_ID = new Map<number, SuiteMeta>();
const BY_NAME = new Map<string, SuiteMeta>();
for (const s of SUITE_TABLE) {
  BY_ID.set(s.id, s);
  BY_NAME.set(s.name.toUpperCase(), s);
}

/** Look up by IANA id; unknown suites get a synthetic, weakly-known entry. */
export function suiteById(id: number): SuiteMeta {
  return (
    BY_ID.get(id) ?? {
      id,
      name: `UNKNOWN-0x${id.toString(16).padStart(4, "0")}`,
      minVersion: "TLSv1.2",
      kx: "unknown",
      auth: "unknown",
      enc: "unknown",
      mac: "unknown",
      forwardSecrecy: false,
      weak: false,
      anonymous: false,
    }
  );
}

/** Look up by OpenSSL short name (case-insensitive). */
export function suiteByName(name: string): SuiteMeta | undefined {
  return BY_NAME.get(name.toUpperCase());
}

export function allSuites(): readonly SuiteMeta[] {
  return SUITE_TABLE;
}

/**
 * Suites offered when enumerating a given protocol version, in the order we
 * prefer to learn them (modern/AEAD and ECDHE first). Order here has no effect
 * on *which* suites a server supports — the enumeration discovers each one by
 * removing what it already negotiated — only on how quickly we land on the
 * common ones.
 */
type OfferVersion = "TLSv1.3" | "TLSv1.2" | "TLSv1.1" | "TLSv1.0";

const CURATED_OFFERS: Record<OfferVersion, string[]> = {
  "TLSv1.3": [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
  ],
  "TLSv1.2": [
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES128-SHA",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-SHA256",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-CCM",
    "ECDHE-ECDSA-AES256-CCM",
    "ECDHE-RSA-AES128-CCM",
    "ECDHE-ECDSA-AES128-CCM",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    "ECDHE-RSA-RC4-SHA",
    "ECDHE-ECDSA-RC4-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "ECDHE-RSA-DES-CBC3-SHA",
    "ECDHE-ECDSA-DES-CBC3-SHA",
    "EDH-RSA-DES-CBC3-SHA",
    "DHE-RSA-DES-CBC3-SHA",
    "DES-CBC3-SHA",
    "ECDHE-RSA-CAMELLIA256-SHA384",
    "ECDHE-RSA-CAMELLIA128-SHA256",
    "DHE-RSA-CAMELLIA256-SHA256",
    "DHE-RSA-CAMELLIA128-SHA256",
    "CAMELLIA256-SHA256",
    "CAMELLIA128-SHA256",
    "CAMELLIA256-SHA",
    "CAMELLIA128-SHA",
  ],
  "TLSv1.1": [
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES128-SHA",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA",
    "ECDHE-RSA-DES-CBC3-SHA",
    "EDH-RSA-DES-CBC3-SHA",
    "DES-CBC3-SHA",
    "AES256-SHA",
    "AES128-SHA",
    "ECDHE-RSA-RC4-SHA",
    "RC4-SHA",
    "RC4-MD5",
  ],
  "TLSv1.0": [
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES128-SHA",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA",
    "ECDHE-RSA-DES-CBC3-SHA",
    "EDH-RSA-DES-CBC3-SHA",
    "DES-CBC3-SHA",
    "DES-CBC-SHA",
    "AES256-SHA",
    "AES128-SHA",
    "ECDHE-RSA-RC4-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "EXP-RC4-MD5",
    "EXP-DES-CBC-SHA",
  ],
};

/** The offer list (numeric ids) for a version. Unknown names are dropped. */
export function offerListFor(version: OfferVersion): number[] {
  const ids: number[] = [];
  for (const name of CURATED_OFFERS[version]) {
    const meta = suiteByName(name);
    if (meta) ids.push(meta.id);
  }
  return ids;
}

export const OFFER_VERSIONS: readonly OfferVersion[] = [
  "TLSv1.3",
  "TLSv1.2",
  "TLSv1.1",
  "TLSv1.0",
];
