/**
 * Minimal, dependency-free TLS wire format helpers.
 *
 * We craft ClientHello messages by hand (rather than using node:tls) so the
 * prober can offer protocol versions and cipher suites that the local OpenSSL
 * build may refuse to negotiate — TLS 1.0/1.1, RC4, 3DES, EXPORT suites. We
 * never complete a handshake: we read the server's first flight (ServerHello,
 * and optionally Certificate/CertificateStatus) and disconnect. That keeps the
 * load we place on a production service close to a single TCP connection.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import type { KeyObject } from "node:crypto";

export const VERSION = {
  SSL3: 0x0300,
  TLS10: 0x0301,
  TLS11: 0x0302,
  TLS12: 0x0303,
  TLS13: 0x0304,
} as const;

export type WireVersion = (typeof VERSION)[keyof typeof VERSION];

export function versionName(code: number): string {
  switch (code) {
    case VERSION.SSL3:
      return "SSLv3";
    case VERSION.TLS10:
      return "TLSv1.0";
    case VERSION.TLS11:
      return "TLSv1.1";
    case VERSION.TLS12:
      return "TLSv1.2";
    case VERSION.TLS13:
      return "TLSv1.3";
    default:
      return `0x${code.toString(16).padStart(4, "0")}`;
  }
}

/* ------------------------------------------------------------------ bytes */

const u8 = (n: number): Buffer => Buffer.from([n & 0xff]);

function u16(n: number): Buffer {
  const b = Buffer.allocUnsafe(2);
  b.writeUInt16BE(n & 0xffff);
  return b;
}

function u24(n: number): Buffer {
  const b = Buffer.allocUnsafe(3);
  b.writeUIntBE(n & 0xffffff, 0, 3);
  return b;
}

/** Length-prefixed vector with a one-byte length. */
function vec8(body: Buffer): Buffer {
  if (body.length > 0xff) throw new RangeError(`vector8 too long: ${body.length}`);
  return Buffer.concat([u8(body.length), body]);
}

/** Length-prefixed vector with a two-byte length. */
function vec16(body: Buffer): Buffer {
  if (body.length > 0xffff) throw new RangeError(`vector16 too long: ${body.length}`);
  return Buffer.concat([u16(body.length), body]);
}

const extension = (type: number, body: Buffer): Buffer =>
  Buffer.concat([u16(type), vec16(body)]);

/** Reads big-endian integers out of a buffer with strict bounds checking. */
export class Cursor {
  private offset = 0;
  private readonly buf: Buffer;

  constructor(buf: Buffer) {
    this.buf = buf;
  }

  get position(): number {
    return this.offset;
  }
  get remaining(): number {
    return this.buf.length - this.offset;
  }
  get done(): boolean {
    return this.offset >= this.buf.length;
  }

  readU8(): number {
    this.need(1);
    return this.buf[this.offset++]!;
  }
  readU16(): number {
    this.need(2);
    const v = this.buf.readUInt16BE(this.offset);
    this.offset += 2;
    return v;
  }

  readU24(): number {
    this.need(3);
    const v = this.buf.readUIntBE(this.offset, 3);
    this.offset += 3;
    return v;
  }

  readBytes(n: number): Buffer {
    this.need(n);
    const out = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  readVec8(): Buffer {
    return this.readBytes(this.readU8());
  }

  readVec16(): Buffer {
    return this.readBytes(this.readU16());
  }

  readVec24(): Buffer {
    return this.readBytes(this.readU24());
  }

  skip(n: number): void {
    this.need(n);
    this.offset += n;
  }

  private need(n: number): void {
    if (this.offset + n > this.buf.length) {
      throw new RangeError(
        `truncated: wanted ${n} bytes at ${this.offset}, have ${this.buf.length}`,
      );
    }
  }
}

/* ------------------------------------------------------ ClientHello build */

const GROUPS = {
  x25519: 0x001d,
  secp256r1: 0x0017,
  secp384r1: 0x0018,
  secp521r1: 0x0019,
  ffdhe2048: 0x0100,
  ffdhe3072: 0x0101,
} as const;

/** Signature algorithms spanning TLS 1.3 PSS through TLS 1.0 PKCS#1/SHA-1. */
const SIGNATURE_ALGORITHMS: readonly number[] = [
  0x0403, // ecdsa_secp256r1_sha256
  0x0503, // ecdsa_secp384r1_sha384
  0x0603, // ecdsa_secp521r1_sha512
  0x0804, // rsa_pss_rsae_sha256
  0x0805, // rsa_pss_rsae_sha384
  0x0806, // rsa_pss_rsae_sha512
  0x0807, // ed25519
  0x0808, // ed448
  0x0809, // rsa_pss_pss_sha256
  0x080a, // rsa_pss_pss_sha384
  0x080b, // rsa_pss_pss_sha512
  0x0401, // rsa_pkcs1_sha256
  0x0501, // rsa_pkcs1_sha384
  0x0601, // rsa_pkcs1_sha512
  0x0203, // ecdsa_sha1
  0x0201, // rsa_pkcs1_sha1
];

interface KeyShare {
  group: number;
  publicKey: Buffer;
}

let cachedKeyShares: KeyShare[] | undefined;
let cachedPrivateKey: { publicKey: KeyObject; privateKey: KeyObject } | undefined;

/**
 * A real X25519 keypair is generated once and cached. The private half is only
 * used by the renegotiation probe (which must complete a handshake); for the
 * plain ClientHello probes we abort after ServerHello and only a well-formed
 * public point matters, so TLS 1.3 servers answer without a
 * HelloRetryRequest.
 */
export function ephemeralX25519Key(): { publicKey: Buffer; privateKey: Buffer } {
  if (!cachedPrivateKey) {
    const pair = generateKeyPairSync("x25519");    const pubDer = pair.publicKey.export({ type: "spki", format: "der" });
    const privDer = pair.privateKey.export({ type: "pkcs8", format: "der" });
    // X25519 SPKI: 12-byte prefix then 32 raw bytes; PKCS8: 16-byte prefix then 32.
    cachedKeyShares = [
      { group: GROUPS.x25519, publicKey: Buffer.from(pubDer.subarray(pubDer.length - 32)) },
    ];
    cachedPrivateKey = pair;
    return {
      publicKey: cachedKeyShares[0]!.publicKey,
      privateKey: Buffer.from(privDer.subarray(privDer.length - 32)),
    };
  }
  const pubDer = cachedPrivateKey.publicKey.export({ type: "spki", format: "der" });
  const privDer = cachedPrivateKey.privateKey.export({ type: "pkcs8", format: "der" });
  return {
    publicKey: Buffer.from(pubDer.subarray(pubDer.length - 32)),
    privateKey: Buffer.from(privDer.subarray(privDer.length - 32)),
  };
}

function keyShares(): KeyShare[] {
  if (cachedKeyShares) return cachedKeyShares;
  const shares: KeyShare[] = [];

  const x = ephemeralX25519Key();
  shares.push({ group: GROUPS.x25519, publicKey: x.publicKey });

  const p = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const pDer = p.publicKey.export({ type: "spki", format: "der" });
  shares.push({ group: GROUPS.secp256r1, publicKey: Buffer.from(pDer.subarray(pDer.length - 65)) });

  cachedKeyShares = shares;
  return shares;
}

export interface ClientHelloOptions {
  /** Protocol versions to advertise through supported_versions (TLS 1.3 path). */
  supportedVersions?: readonly number[];
  /** Legacy version field. Defaults to 0x0303. */
  legacyVersion?: number;
  /** Cipher suite ids, in preference order. */
  suites: readonly number[];
  /** SNI host name; omit for IP-literal targets unless overridden. */
  serverName?: string;
  /** ALPN protocol list. */
  alpn?: readonly string[];
  /** Advertise RFC 5746 renegotiation_info. Default true. */
  renegotiationInfo?: boolean;
  /** Advertise status_request so a TLS 1.2 server may staple an OCSP response. */
  statusRequest?: boolean;
  /** Include a TLS 1.3 key_share extension. Defaults to auto (when 1.3 offered). */
  keyShare?: boolean;
  /** Include extended_master_secret. Default true. */
  extendedMasterSecret?: boolean;
  /** Session id bytes; defaults to 32 random bytes. */
  sessionId?: Buffer;
}

function sniExtension(host: string): Buffer {
  const name = Buffer.from(host, "utf8");
  // ServerNameList: one host_name entry (type 0)
  const entry = Buffer.concat([u8(0), u16(name.length), name]);
  return vec16(entry);
}

function supportedGroupsExtension(): Buffer {
  const groups = [
    GROUPS.x25519,
    GROUPS.secp256r1,
    GROUPS.secp384r1,
    GROUPS.secp521r1,
    GROUPS.ffdhe2048,
    GROUPS.ffdhe3072,
  ];
  return vec16(Buffer.concat(groups.map(u16)));
}

function signatureAlgorithmsExtension(): Buffer {
  return vec16(Buffer.concat(SIGNATURE_ALGORITHMS.map(u16)));
}

function keyShareExtension(): Buffer {
  const entries = keyShares().map((s) => Buffer.concat([u16(s.group), vec16(s.publicKey)]));
  return vec16(Buffer.concat(entries));
}

function alpnExtension(protocols: readonly string[]): Buffer {
  const list = Buffer.concat(protocols.map((p) => vec8(Buffer.from(p, "ascii"))));
  return vec16(list);
}

function supportedVersionsExtension(versions: readonly number[]): Buffer {
  return vec8(Buffer.concat(versions.map(u16)));
}

/**
 * Build a complete TLS record containing one ClientHello.
 * Unknown extensions are ignored by compliant servers, so the message is safe
 * to send to old and new endpoints alike.
 */
export function buildClientHello(options: ClientHelloOptions): Buffer {
  const supported = options.supportedVersions ?? [];
  const offers13 = supported.includes(VERSION.TLS13);
  const legacyVersion = options.legacyVersion ?? VERSION.TLS12;
  const sessionId = options.sessionId ?? Buffer.alloc(32);
  const includeKeyShare = options.keyShare ?? offers13;

  const exts: Buffer[] = [];
  if (options.serverName) exts.push(extension(0x0000, sniExtension(options.serverName)));

  exts.push(extension(0x000a, supportedGroupsExtension()));
  exts.push(extension(0x000b, vec8(u8(0)))); // ec_point_formats: uncompressed
  exts.push(extension(0x000d, signatureAlgorithmsExtension()));

  if (options.extendedMasterSecret !== false) {
    exts.push(extension(0x0017, Buffer.alloc(0)));
  }
  if (options.statusRequest) {
    // status_request: type=ocsp(1), responder_id_list empty, request_extensions empty
    exts.push(extension(0x0005, Buffer.concat([u8(1), u16(0), u16(0)])));
  }
  if (options.renegotiationInfo !== false) {
    exts.push(extension(0xff01, vec8(Buffer.alloc(0))));
  }
  if (options.alpn && options.alpn.length > 0) {
    exts.push(extension(0x0010, alpnExtension(options.alpn)));
  }
  if (supported.length > 0) {
    exts.push(extension(0x002b, supportedVersionsExtension(supported)));
  }
  if (includeKeyShare) {
    exts.push(extension(0x0033, keyShareExtension()));
  }

  const body = Buffer.concat([
    u16(legacyVersion),
    randomBytes(32),
    vec8(sessionId),
    vec16(Buffer.concat(options.suites.map(u16))),
    vec8(u8(0)), // compression methods: null
    vec16(Buffer.concat(exts)),
  ]);

  const handshake = Buffer.concat([u8(0x01), u24(body.length), body]);
  return Buffer.concat([u8(0x16), u16(VERSION.TLS10), vec16(handshake)]);
}

/* ------------------------------------------------------- server messages */

export interface ServerHelloInfo {
  /** Negotiated version after resolving supported_versions. */
  version: number;
  legacyVersion: number;
  cipherSuite: number;
  compression: number;
  sessionId: Buffer;
  extensions: Map<number, Buffer>;
  /** True when the server echoed RFC 5746 renegotiation_info. */
  secureRenegotiation: boolean;
}

export type ParsedMessage =
  | { kind: "server_hello"; info: ServerHelloInfo }
  | { kind: "certificate"; certificates: Buffer[] }
  | { kind: "certificate_status"; response: Buffer }
  | { kind: "hello_request" }
  | { kind: "other"; type: number; body: Buffer };

/** Parse one handshake message body (excluding the 4-byte handshake header). */
export function parseHandshake(type: number, body: Buffer): ParsedMessage {
  switch (type) {
    case 0x02:
      return { kind: "server_hello", info: parseServerHello(body) };
    case 0x0b:
      return { kind: "certificate", certificates: parseCertificate(body) };
    case 0x16:
      return { kind: "certificate_status", response: parseCertificateStatus(body) };
    case 0x00:
      return { kind: "hello_request" };
    default:
      return { kind: "other", type, body };
  }
}

export function parseServerHello(body: Buffer): ServerHelloInfo {
  const c = new Cursor(body);
  const legacyVersion = c.readU16();
  c.skip(32); // random
  const sessionId = Buffer.from(c.readVec8());
  const cipherSuite = c.readU16();
  const compression = c.readU8();

  const extensions = new Map<number, Buffer>();
  if (c.remaining >= 2) {
    const extBlock = c.readVec16();
    const ec = new Cursor(extBlock);
    while (!ec.done) {
      const type = ec.readU16();
      extensions.set(type, Buffer.from(ec.readVec16()));
    }
  }

  let version = legacyVersion;
  const sv = extensions.get(0x002b);
  if (sv && sv.length >= 2) version = sv.readUInt16BE(0);

  return {
    version,
    legacyVersion,
    cipherSuite,
    compression,
    sessionId,
    extensions,
    secureRenegotiation: extensions.has(0xff01),
  };
}

function parseCertificate(body: Buffer): Buffer[] {
  const c = new Cursor(body);
  // TLS 1.2: certificate_list<0..2^24-1>. (TLS 1.3 certificates arrive inside
  // encrypted records, which this plaintext reader never sees.)
  const list = c.readVec24();
  const lc = new Cursor(list);
  const out: Buffer[] = [];
  while (!lc.done) out.push(Buffer.from(lc.readVec24()));
  return out;
}

function parseCertificateStatus(body: Buffer): Buffer {
  // CertificateStatus: status_type(1) + response<1..2^24-1>
  const c = new Cursor(body);
  c.readU8();
  return Buffer.from(c.readVec24());
}

/* ---------------------------------------------------------- record layer */

export interface TlsRecord {
  type: number;
  version: number;
  payload: Buffer;
}

/** Split a byte stream into complete TLS records. Returns leftover bytes. */
export function splitRecords(buffer: Buffer): { records: TlsRecord[]; rest: Buffer } {
  const records: TlsRecord[] = [];
  let offset = 0;
  while (offset + 5 <= buffer.length) {
    const type = buffer[offset]!;
    const version = buffer.readUInt16BE(offset + 1);
    const length = buffer.readUInt16BE(offset + 3);
    if (offset + 5 + length > buffer.length) break;
    records.push({ type, version, payload: buffer.subarray(offset + 5, offset + 5 + length) });
    offset += 5 + length;
  }
  return { records, rest: buffer.subarray(offset) };
}

/** Accumulates handshake fragments across records and yields whole messages. */
export class HandshakeReader {
  private buffer: Buffer = Buffer.alloc(0);

  /** Feed handshake record payloads; returns any complete handshake messages. */
  push(payload: Buffer): ParsedMessage[] {
    this.buffer = Buffer.concat([this.buffer, payload]);
    const messages: ParsedMessage[] = [];
    let offset = 0;
    while (this.buffer.length - offset >= 4) {
      const type = this.buffer[offset]!;
      const length = this.buffer.readUIntBE(offset + 1, 3);
      if (this.buffer.length - offset - 4 < length) break;
      const body = this.buffer.subarray(offset + 4, offset + 4 + length);
      messages.push(parseHandshake(type, body));
      offset += 4 + length;
    }
    this.buffer = this.buffer.subarray(offset);
    return messages;
  }

  /** Bytes buffered but not yet forming a whole handshake message. */
  get pending(): number {
    return this.buffer.length;
  }
}

/** Decode a TLS alert record payload into its numeric description. */
export function parseAlert(payload: Buffer): { level: number; description: number } {
  return { level: payload[0] ?? 0, description: payload[1] ?? 0 };
}

export const ALERT_DESCRIPTION: Record<number, string> = {
  0: "close_notify",
  10: "unexpected_message",
  20: "bad_record_mac",
  21: "decryption_failed",
  22: "record_overflow",
  40: "handshake_failure",
  42: "bad_certificate",
  43: "unsupported_certificate",
  44: "certificate_revoked",
  45: "certificate_expired",
  46: "certificate_unknown",
  47: "illegal_parameter",
  48: "unknown_ca",
  49: "access_denied",
  50: "decode_error",
  51: "decrypt_error",
  70: "protocol_version",
  71: "insufficient_security",
  80: "internal_error",
  86: "inappropriate_fallback",
  90: "user_canceled",
  100: "no_renegotiation",
  109: "missing_extension",
  110: "unsupported_extension",
  112: "unrecognized_name",
  113: "bad_certificate_status_response",
  115: "unknown_psk_identity",
  116: "certificate_required",
  120: "no_application_protocol",
};
