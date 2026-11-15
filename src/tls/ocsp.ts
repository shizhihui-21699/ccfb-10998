/**
 * OCSP stapling detection.
 *
 * "Is the server stapling?" has two distinct observable signals, and a
 * truthful answer needs both:
 *
 *   1. The ServerHello carries a status_request extension. This is the server
 *      acknowledging the request; it means the server *supports* stapling.
 *      Cheap and version-independent, but says nothing about whether a staple
 *      is actually present.
 *
 *   2. The Certificate message contains a certificate_status structure with
 *      real OCSP bytes. This is the staple itself. node:tls surfaces it as an
 *      'OCSPResponse' event when requestOCSP is set. Note this is reliable on
 *      TLS 1.2 but NOT on TLS 1.3: OpenSSL does not emit the event for
 *      TLS 1.3 responses in the same way, which is why we test the staple on
 *      TLS 1.2 preferentially.
 *
 * We also parse the DER to say whether the stapled response is "good",
 * "revoked", or "unknown", because a server can staple a response that says
 * revoked and that is worth flagging loudly. Parsing is best-effort: a valid
 * staple with unusual extensions still counts as stapled even if we cannot
 * decode the status.
 */
import { tlsSession } from './probe.ts';
import type { OcspResult, ProbeFailure, TlsVersionName } from '../types.ts';

export interface OcspOptions {
  host: string;
  port: number;
  serverName?: string;
  timeoutMs: number;
  /** Versions to try; TLS 1.2 first because the staple event is reliable there. */
  versions: TlsVersionName[];
  rejectUnauthorized: boolean;
  caFile?: string;
}

/**
 * Minimal DER reader: just enough to walk an OCSPResponse down to
 * ResponseData / SingleResponse / certStatus.
 */
interface DerNode {
  tag: number;
  value: Buffer;
  /** Offset of the node's first byte in the original buffer. */
  start: number;
  /** Offset just past the node. */
  end: number;
}

function readDer(buf: Buffer, off: number): DerNode | null {
  if (off >= buf.length) return null;
  const tag = buf[off]!;
  let lenByte = buf[off + 1];
  if (lenByte === undefined) return null;
  let headerLen = 2;
  let len: number;
  if (lenByte & 0x80) {
    const n = lenByte & 0x7f;
    if (n === 0 || n > 4 || off + 2 + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[off + 2 + i]!;
    headerLen = 2 + n;
  } else {
    len = lenByte;
  }
  const valueStart = off + headerLen;
  if (valueStart + len > buf.length) return null;
  return { tag, value: buf.subarray(valueStart, valueStart + len), start: off, end: valueStart + len };
}

function children(node: DerNode): DerNode[] {
  const out: DerNode[] = [];
  let off = 0;
  const v = node.value;
  while (off < v.length) {
    const child = readDer(v, off);
    if (!child) break;
    out.push(child);
    off = child.end;
  }
  return out;
}

/**
 * Extracts the certificate status from an OCSP BasicResponse.
 *
 *   OCSPResponse     ::= SEQUENCE { responseStatus ENUMERATED,
 *                                   responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL }
 *   ResponseBytes    ::= SEQUENCE { responseType OID, response OCTET STRING }
 *   BasicOCSPResponse::= SEQUENCE { tbsResponseData, ... }
 *   ResponseData     ::= SEQUENCE { version, responderID, producedAt,
 *                                   responses SEQUENCE OF SingleResponse, ... }
 *   SingleResponse   ::= SEQUENCE { certID, certStatus, thisUpdate, ... }
 *   certStatus       ::= CHOICE { good [0], revoked [1], unknown [2] }
 *
 * The OCTET STRING layer is easy to miss: the DER inside it is a fresh
 * structure, so it must be re-parsed with the reader rather than treated as a
 * child of ResponseBytes.
 */
export function parseOcspStatus(der: Buffer): 'good' | 'revoked' | 'unknown' | undefined {
  const root = readDer(der, 0);
  if (!root || root.tag !== 0x30) return undefined;
  const top = children(root);
  if (top.length < 2) return undefined;

  const statusEnum = top[0]!;
  if (statusEnum.tag !== 0x0a) return undefined;
  // responseStatus 0 == successful.
  if (statusEnum.value.length < 1 || statusEnum.value[0] !== 0) return undefined;

  const responseBytes = top[1]!;
  // [0] EXPLICIT (constructed)
  if ((responseBytes.tag & 0x1f) !== 0) return undefined;

  const rb = children(responseBytes)[0];
  if (!rb || rb.tag !== 0x30) return undefined;
  const rbChildren = children(rb);
  // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
  const octets = rbChildren.find((n) => n.tag === 0x04);
  if (!octets) return undefined;

  const basic = readDer(octets.value, 0);
  if (!basic || basic.tag !== 0x30) return undefined;
  const basicChildren = children(basic);
  const tbs = basicChildren[0];
  if (!tbs || tbs.tag !== 0x30) return undefined;
  const tbsChildren = children(tbs);

  // ResponseData ::= SEQUENCE {
  //     version           [0] EXPLICIT Version DEFAULT v1,   -- usually OMITTED
  //     responderID       ResponderID,                        -- [1] or [2]
  //     producedAt        GeneralizedTime,                    -- 0x18
  //     responses         SEQUENCE OF SingleResponse,
  //     responseExtensions [1] EXPLICIT Extensions OPTIONAL }
  //
  // The version field is DEFAULT v1 and therefore commonly absent, so counting
  // fields from zero gets the wrong index. Anchor on producedAt instead: the
  // next element after it is always the responses sequence.
  const producedAtIdx = tbsChildren.findIndex((n) => n.tag === 0x18);
  if (producedAtIdx === -1) return undefined;
  const responses = tbsChildren[producedAtIdx + 1];
  if (!responses || responses.tag !== 0x30) return undefined;
  const single = children(responses)[0];
  if (!single || single.tag !== 0x30) return undefined;
  const singleChildren = children(single);
  const certStatus = singleChildren[1];
  if (!certStatus) return undefined;
  switch (certStatus.tag) {
    case 0x80: // [0] IMPLICIT NULL => good
      return 'good';
    case 0xa1: // [1] => revoked
      return 'revoked';
    case 0x82: // [2] IMPLICIT NULL => unknown
      return 'unknown';
    default:
      return undefined;
  }
}

export interface StapledProbe {
  version: TlsVersionName;
  ok: boolean;
  protocol?: string;
  stapleBytes?: number;
  status?: 'good' | 'revoked' | 'unknown';
  statusRequestExtension?: boolean;
  failure?: ProbeFailure;
}

/** Runs one TLS session on one version, asking for a staple. */
async function stapleOnVersion(opts: OcspOptions, version: TlsVersionName): Promise<StapledProbe> {
  const res = await tlsSession({
    host: opts.host,
    port: opts.port,
    serverName: opts.serverName,
    minVersion: version,
    maxVersion: version,
    requestOCSP: true,
    alpn: ['h2', 'http/1.1'],
    timeoutMs: opts.timeoutMs,
    rejectUnauthorized: false,
    caFile: opts.caFile,
    // No write: we only need the handshake (the Certificate message carries the staple).
  });

  if (!res.ok) {
    return { version, ok: false, failure: res.failure };
  }

  const staple = res.ocspResponse;
  return {
    version,
    ok: true,
    protocol: res.protocol,
    stapleBytes: staple?.length,
    status: staple ? parseOcspStatus(staple) : undefined,
  };
}

/**
 * Combines the passive ServerHello signal (status_request in extensions) with
 * live staple observation on one or more versions.
 */
export async function probeOcsp(opts: OcspOptions, statusRequestSeen: Partial<Record<TlsVersionName, boolean>>): Promise<OcspResult> {
  const observedOn: TlsVersionName[] = [];
  let responseBytes: number | undefined;
  let certificateStatus: 'good' | 'revoked' | 'unknown' | undefined;
  const notes: string[] = [];
  let anyStapleAttemptOk = false;

  for (const v of opts.versions) {
    const r = await stapleOnVersion(opts, v);
    if (!r.ok) {
      notes.push(`${v}: handshake failed (${r.failure?.kind ?? 'error'})`);
      continue;
    }
    anyStapleAttemptOk = true;
    if (r.stapleBytes) {
      observedOn.push(v);
      responseBytes = r.stapleBytes;
      if (r.status) certificateStatus = r.status;
      notes.push(`${v}: stapled ${r.stapleBytes} bytes${r.status ? ` (${r.status})` : ''}`);
    } else {
      notes.push(`${v}: handshake ok, no staple`);
    }
  }

  const statusRequestExtension = Object.values(statusRequestSeen).some(Boolean);
  const stapled = observedOn.length > 0;

  let detail: string;
  if (stapled) {
    detail = `server stapled an OCSP response on ${observedOn.join(', ')}`;
    if (certificateStatus === 'revoked') detail += ' — WARNING: the stapled response says the certificate is REVOKED';
  } else if (statusRequestExtension && anyStapleAttemptOk) {
    detail = 'server acknowledges status_request but sent no staple (stapling configured but responder unavailable or misconfigured)';
  } else if (statusRequestExtension) {
    detail = 'server advertises status_request support in ServerHello, but no staple was observed';
  } else if (anyStapleAttemptOk) {
    detail = 'server completed a handshake without requesting-status support and sent no staple';
  } else {
    detail = 'could not complete a TLS handshake for the OCSP probe';
  }

  return {
    stapled,
    ...(responseBytes !== undefined ? { responseBytes } : {}),
    ...(certificateStatus !== undefined ? { certificateStatus } : {}),
    statusRequestExtension,
    observedOn,
    detail: `${detail} (${notes.join('; ')})`,
  };
}
