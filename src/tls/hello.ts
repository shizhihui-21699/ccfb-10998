/**
 * Minimal TLS handshake codec: build a ClientHello, read a ServerHello.
 *
 * Why hand-roll this instead of using node:tls?
 *
 *   node:tls validates its own cipher list against the OpenSSL build it ships
 *   with. That build (OpenSSL 3.x) has no RC4, no 3DES and no export ciphers,
 *   and refuses to even construct a context that offers them. For a checkup
 *   tool the *weak* suites are exactly what we must be able to offer, or the
 *   answer "this server still accepts RC4" is unobtainable. Speaking the
 *   hello ourselves also keeps each probe to a single round trip: no
 *   certificate exchange, no Finished, no session state.
 *
 * Scope: client side, full handshake start only. No sessions, no key
 * material derivation, no record encryption. We never send a Finished and
 * never read ApplicationData; the connection is torn down after ServerHello.
 */

export const CONTENT_TYPE = {
  changeCipherSpec: 20,
  alert: 21,
  handshake: 22,
  applicationData: 23,
} as const;

export const HANDSHAKE_TYPE = {
  clientHello: 1,
  serverHello: 2,
  helloRequest: 0,
} as const;

export const EXT = {
  serverName: 0,
  supportedGroups: 10,
  ecPointFormats: 11,
  signatureAlgorithms: 13,
  alpn: 16,
  statusRequest: 5,
  extendedMasterSecret: 23,
  renegotiationInfo: 0xff01,
  supportedVersions: 43,
  keyShare: 51,
  sessionTicket: 35,
} as const;

export const ALERT_NAMES: Record<number, string> = {
  0: 'close_notify',
  10: 'unexpected_message',
  20: 'bad_record_mac',
  21: 'decryption_failed',
  22: 'record_overflow',
  30: 'decompression_failure',
  40: 'handshake_failure',
  41: 'no_certificate',
  42: 'bad_certificate',
  43: 'unsupported_certificate',
  44: 'certificate_revoked',
  45: 'certificate_expired',
  46: 'certificate_unknown',
  47: 'illegal_parameter',
  48: 'unknown_ca',
  49: 'access_denied',
  50: 'decode_error',
  51: 'decrypt_error',
  70: 'protocol_version',
  71: 'insufficient_security',
  80: 'user_canceled',
  86: 'inappropriate_fallback',
  90: 'user_canceled',
  100: 'no_renegotiation',
  109: 'missing_extension',
  110: 'unsupported_extension',
  112: 'unrecognized_name',
  113: 'bad_certificate_status_response',
  115: 'unknown_psk_identity',
  116: 'certificate_required',
  120: 'no_application_protocol',
};

// --- small builders -------------------------------------------------------

function u8(n: number): Buffer {
  return Buffer.from([n & 0xff]);
}
function u16(n: number): Buffer {
  return Buffer.from([(n >> 8) & 0xff, n & 0xff]);
}
function u24(n: number): Buffer {
  return Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}
function vec8(b: Buffer): Buffer {
  return Buffer.concat([u8(b.length), b]);
}
function vec16(b: Buffer): Buffer {
  return Buffer.concat([u16(b.length), b]);
}
function ext(type: number, data: Buffer): Buffer {
  return Buffer.concat([u16(type), vec16(data)]);
}

// --- key share ------------------------------------------------------------

export interface KeyShare {
  /** Named group id (IANA "TLS Supported Groups"), e.g. 29 for x25519. */
  group: number;
  /** Raw public key bytes in the group's own encoding. */
  publicKey: Buffer;
}

/** Give hex for a named curve. */
export const NAMED_GROUP = {
  x25519: 29,
  secp256r1: 23,
  secp384r1: 24,
  secp521r1: 25,
} as const;

/**
 * Generates one key share. We only need a syntactically valid public key so
 * the server will accept the hello and reply; we never derive a shared secret.
 */
export function generateKeyShare(group: number, crypto: typeof import('node:crypto')): KeyShare {
  switch (group) {
    case NAMED_GROUP.x25519: {
      const { publicKey } = crypto.generateKeyPairSync('x25519');
      const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
      return { group, publicKey: Buffer.from(jwk.x, 'base64url') };
    }
    case NAMED_GROUP.secp256r1:
    case NAMED_GROUP.secp384r1:
    case NAMED_GROUP.secp521r1: {
      const curve = group === NAMED_GROUP.secp256r1 ? 'prime256v1' : group === NAMED_GROUP.secp384r1 ? 'secp384r1' : 'secp521r1';
      const ecdh = crypto.createECDH(curve);
      ecdh.generateKeys();
      return { group, publicKey: ecdh.getPublicKey() };
    }
    default:
      throw new Error(`unsupported key share group ${group}`);
  }
}

// --- ClientHello ----------------------------------------------------------

export interface ClientHelloOptions {
  /** Wire version in the legacy version field: 0x0301..0x0303. */
  legacyVersion: number;
  suites: readonly number[];
  /** true => include supported_versions (TLS 1.3) and a key_share. */
  offerTls13: boolean;
  /** Version list for supported_versions when offerTls13 is set. */
  supportedVersions?: readonly number[];
  serverName?: string;
  /** Include the RFC 5746 renegotiation_info extension (empty, as a fresh client). */
  offerRenegotiationInfo?: boolean;
  /** Request OCSP stapling. */
  requestStatus?: boolean;
  /** ALPN protocols; the first is preferred. */
  alpn?: readonly string[];
  /** Override the random for deterministic tests. */
  random?: Buffer;
  /** Override the session id; by default a random 32-byte value. */
  sessionId?: Buffer;
  /** Provide pre-generated key shares for TLS 1.3 (tests inject deterministic ones). */
  keyShares?: KeyShare[];
  /** Include the session_ticket extension (harmless, some servers need it). */
  sessionTicket?: boolean;
  /**
   * When set, omit this extension id. Used by the lab to emulate servers whose
   * ClientHello handling is wrong in specific ways (e.g. rejecting key_share).
   */
  omitExtension?: number;
}

/** Builds a complete TLS record containing one ClientHello. */
export function buildClientHello(opts: ClientHelloOptions, crypto: typeof import('node:crypto')): Buffer {
  const legacyVersion = opts.legacyVersion;
  const random = opts.random ?? crypto.randomBytes(32);
  const sessionId = opts.sessionId ?? crypto.randomBytes(32);
  const suiteIds = opts.suites.length ? opts.suites : [0x002f];

  const exts: Buffer[] = [];
  const skip = (id: number) => opts.omitExtension === id;

  if (opts.serverName && !skip(EXT.serverName)) {
    // list of server_name entries; only host_name (type 0) is defined.
    const sni = Buffer.concat([u8(0), vec16(Buffer.from(opts.serverName, 'utf8'))]);
    exts.push(ext(EXT.serverName, vec16(sni)));
  }

  if (!skip(EXT.supportedGroups)) {
    const groups = [NAMED_GROUP.x25519, NAMED_GROUP.secp256r1, NAMED_GROUP.secp384r1, NAMED_GROUP.secp521r1];
    exts.push(ext(EXT.supportedGroups, vec16(Buffer.concat(groups.map(u16)))));
  }

  if (!skip(EXT.ecPointFormats)) {
    exts.push(ext(EXT.ecPointFormats, Buffer.from([1, 0]))); // 1 format: uncompressed
  }

  if (!skip(EXT.signatureAlgorithms)) {
    // A broad modern list, including SHA-1 RSA for very old stacks.
    const sigalgs = [
      0x0403, // ecdsa_secp256r1_sha256
      0x0503, // ecdsa_secp384r1_sha384
      0x0603, // ecdsa_secp521r1_sha512
      0x0804, // rsa_pss_rsae_sha256
      0x0805, // rsa_pss_rsae_sha384
      0x0806, // rsa_pss_rsae_sha512
      0x0401, // rsa_pkcs1_sha256
      0x0501, // rsa_pkcs1_sha384
      0x0601, // rsa_pkcs1_sha512
      0x0201, // rsa_pkcs1_sha1 (legacy stacks)
      0x0203, // ecdsa_sha1
    ];
    exts.push(ext(EXT.signatureAlgorithms, vec16(Buffer.concat(sigalgs.map(u16)))));
  }

  if (opts.offerTls13 && !skip(EXT.supportedVersions)) {
    const versions = (opts.supportedVersions ?? [0x0304, 0x0303, 0x0302, 0x0301]).map(u16);
    // ClientHello's supported_versions carries a 1-byte-length vector
    // (RFC 8446 §4.2.1); ServerHello's carries a bare ProtocolVersion (2 bytes).
    exts.push(ext(EXT.supportedVersions, vec8(Buffer.concat(versions))));
  }

  if (opts.offerTls13 && !skip(EXT.keyShare)) {
    const shares = opts.keyShares ?? [generateKeyShare(NAMED_GROUP.x25519, crypto)];
    const entries = shares.map((s) => Buffer.concat([u16(s.group), vec16(s.publicKey)]));
    exts.push(ext(EXT.keyShare, vec16(Buffer.concat(entries))));
  }

  if (opts.offerRenegotiationInfo && !skip(EXT.renegotiationInfo)) {
    // A fresh client sends the extension with an empty renegotiated_connection.
    exts.push(ext(EXT.renegotiationInfo, Buffer.from([0])));
  }

  if (opts.requestStatus && !skip(EXT.statusRequest)) {
    // status_type ocsp = 1, then an empty responder_id list: we accept any responder.
    exts.push(ext(EXT.statusRequest, Buffer.from([1, 0, 0, 0, 0])));
  }

  if (opts.sessionTicket && !skip(EXT.sessionTicket)) {
    exts.push(ext(EXT.sessionTicket, Buffer.alloc(0)));
  }

  if (opts.alpn && !skip(EXT.alpn)) {
    const protos = opts.alpn.map((p) => vec8(Buffer.from(p, 'utf8')));
    exts.push(ext(EXT.alpn, vec16(Buffer.concat(protos))));
  }

  const extensions = exts.length ? vec16(Buffer.concat(exts)) : Buffer.alloc(0);
  const compression = Buffer.from([1, 0]); // null compression only

  const body = Buffer.concat([
    u16(legacyVersion),
    random,
    vec8(sessionId),
    vec16(Buffer.concat(suiteIds.map(u16))),
    compression,
    extensions,
  ]);
  const handshake = Buffer.concat([u8(HANDSHAKE_TYPE.clientHello), u24(body.length), body]);

  // TLS 1.3 Clients send record version 0x0301 for the first flight (RFC 8446
  // Appendix D.4); older stacks expect 0x0301..0x0303. Using the legacy
  // version in the record header is correct for all of them.
  const recordVersion = legacyVersion;
  return Buffer.concat([u8(CONTENT_TYPE.handshake), u16(recordVersion), u16(handshake.length), handshake]);
}

// --- ServerHello ----------------------------------------------------------

export interface ServerHelloExtensions {
  /** Extension type ids present, for presence checks. */
  types: number[];
  /** negotiated protocol version from supported_versions (TLS 1.3), if any. */
  selectedVersion?: number;
  /** Renegotiation info extension was present (RFC 5746). */
  renegotiationInfo: boolean;
  /** status_request extension present (staple announced in Certificate). */
  statusRequest: boolean;
  /** type 51 key_share extension present. */
  keyShare: boolean;
}

export interface ServerHello {
  /** Legacy version field from the ServerHello body. */
  legacyVersion: number;
  /** The actually selected version (supported_versions wins on TLS 1.3). */
  selectedVersion: number;
  random: Buffer;
  /** True when this is a HelloRetryRequest (the random has the RFC 8446 marker). */
  helloRetryRequest: boolean;
  /** Cipher suite the server selected. */
  cipherSuite: number;
  sessionId: Buffer;
  extensions: ServerHelloExtensions;
}

const HRR_RANDOM = Buffer.from(
  'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c',
  'hex',
);

export interface ParsedRecord {
  contentType: number;
  version: number;
  data: Buffer;
}

/** Splits a byte stream into complete TLS records. Returns leftovers in `rest`. */
export function splitRecords(buf: Buffer, startOffset = 0): { records: ParsedRecord[]; rest: Buffer; consumed: number } {
  const records: ParsedRecord[] = [];
  let off = startOffset;
  while (off + 5 <= buf.length) {
    const contentType = buf.readUInt8(off);
    const version = buf.readUInt16BE(off + 1);
    const length = buf.readUInt16BE(off + 3);
    if (off + 5 + length > buf.length) break;
    records.push({ contentType, version, data: buf.subarray(off + 5, off + 5 + length) });
    off += 5 + length;
  }
  return { records, rest: buf.subarray(off), consumed: off - startOffset };
}

/** Parses a Handshake message payload beginning with its own type/length header. */
export function parseServerHello(payload: Buffer): ServerHello | null {
  if (payload.length < 4) return null;
  if (payload[0] !== HANDSHAKE_TYPE.serverHello) return null;
  const bodyLen = payload.readUIntBE(1, 3);
  const body = payload.subarray(4, 4 + bodyLen);
  if (body.length < 34) return null;

  const legacyVersion = body.readUInt16BE(0);
  const random = body.subarray(2, 34);
  const sessionIdLen = body.readUInt8(34);
  if (35 + sessionIdLen + 2 > body.length) return null;

  let off = 35;
  const sessionId = body.subarray(off, off + sessionIdLen);
  off += sessionIdLen;
  const cipherSuite = body.readUInt16BE(off);
  off += 2;
  const compressionMethod = body[off];
  off += 1;
  void compressionMethod;

  const exts: ServerHelloExtensions = {
    types: [],
    renegotiationInfo: false,
    statusRequest: false,
    keyShare: false,
  };

  if (off + 2 <= body.length) {
    const extsLen = body.readUInt16BE(off);
    off += 2;
    const end = Math.min(off + extsLen, body.length);
    while (off + 4 <= end) {
      const type = body.readUInt16BE(off);
      const len = body.readUInt16BE(off + 2);
      if (off + 4 + len > end) break;
      const extData = body.subarray(off + 4, off + 4 + len);
      exts.types.push(type);
      if (type === EXT.supportedVersions && extData.length >= 2) {
        exts.selectedVersion = extData.readUInt16BE(0);
      } else if (type === EXT.renegotiationInfo) {
        exts.renegotiationInfo = true;
      } else if (type === EXT.statusRequest) {
        exts.statusRequest = true;
      } else if (type === EXT.keyShare) {
        exts.keyShare = true;
      }
      off += 4 + len;
    }
  }

  const selectedVersion = exts.selectedVersion ?? legacyVersion;
  return {
    legacyVersion,
    selectedVersion,
    random,
    helloRetryRequest: random.length === 32 && random.equals(HRR_RANDOM),
    cipherSuite,
    sessionId,
    extensions: exts,
  };
}

/** Maps a 0x0301..0x0304 wire id to our display name. */
/** Human name for a TLS alert description, falling back to the number. */
export function alertDescriptionName(n: number): string {
  return ALERT_NAMES[n] ?? `alert_${n}`;
}

export function versionName(id: number): string {
  switch (id) {
    case 0x0301:
      return 'TLSv1.0';
    case 0x0302:
      return 'TLSv1.1';
    case 0x0303:
      return 'TLSv1.2';
    case 0x0304:
      return 'TLSv1.3';
    default:
      return `0x${id.toString(16).padStart(4, '0')}`;
  }
}

