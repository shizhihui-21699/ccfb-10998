/**
 * Minimal DER reader for the OCSP response a server staples (RFC 6960).
 *
 * We only need the outer shape: responseStatus, then the BasicOCSPResponse
 * inside responseBytes — its producedAt / thisUpdate / nextUpdate times and the
 * per-certificate status (good / revoked / unknown). Full signature
 * verification is out of scope: the point of this check is whether stapling is
 * enabled and the staple is fresh, not to be a revocation client.
 */

export interface DerNode {
  tag: number;
  /** Content octets (excluding tag and length). */
  value: Buffer;
}

const TAG_CLASS_HIGH = 0x1f;

/** Read one DER TLV starting at `offset`. Throws on truncation/overflow. */
export function readDer(buf: Buffer, offset = 0): { node: DerNode; next: number } {
  if (offset >= buf.length) throw new RangeError("DER: unexpected end of input");
  const tag = buf[offset]!;
  if ((tag & TAG_CLASS_HIGH) === TAG_CLASS_HIGH) {
    throw new RangeError("DER: high-tag-number form not supported");
  }
  let p = offset + 1;
  if (p >= buf.length) throw new RangeError("DER: missing length");
  const first = buf[p++]!;
  let length: number;
  if ((first & 0x80) === 0) {
    length = first;
  } else {
    const numBytes = first & 0x7f;
    if (numBytes === 0 || numBytes > 4) throw new RangeError("DER: bad length encoding");
    if (p + numBytes > buf.length) throw new RangeError("DER: truncated length");
    length = 0;
    for (let i = 0; i < numBytes; i += 1) length = length * 256 + buf[p++]!;
  }
  if (p + length > buf.length) throw new RangeError("DER: value overruns buffer");
  return { node: { tag, value: buf.subarray(p, p + length) }, next: p + length };
}

/** Parse a DER SEQUENCE into child nodes. */
export function readSequence(node: DerNode): DerNode[] {
  if (node.tag !== 0x30) throw new RangeError(`DER: expected SEQUENCE, got 0x${node.tag.toString(16)}`);
  const children: DerNode[] = [];
  let offset = 0;
  while (offset < node.value.length) {
    const { node: child, next } = readDer(node.value, offset);
    children.push(child);
    offset = next;
  }
  return children;
}

export function decodeOid(value: Buffer): string {
  if (value.length === 0) return "";
  const parts: number[] = [];
  const first = value[0]!;
  parts.push(Math.floor(first / 40), first % 40);
  let acc = 0;
  for (let i = 1; i < value.length; i += 1) {
    const byte = value[i]!;
    acc = acc * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(acc);
      acc = 0;
    }
  }
  return parts.join(".");
}

/** Parse an ASN.1 UTCTime / GeneralizedTime into an ISO string. */
export function decodeTime(node: DerNode): string | undefined {
  const raw = node.value.toString("ascii");
  try {
    if (node.tag === 0x17) {
      // UTCTime: YYMMDDHHMMSSZ
      const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(raw);
      if (!m) return undefined;
      const yy = Number(m[1]);
      const year = yy >= 50 ? 1900 + yy : 2000 + yy;
      return iso(year, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
    }
    if (node.tag === 0x18) {
      // GeneralizedTime: YYYYMMDDHHMMSSZ
      const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(raw);
      if (!m) return undefined;
      return iso(Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function iso(y: number, mo: number, d: number, h: number, mi: number, s: number): string {
  return new Date(Date.UTC(y, mo - 1, d, h, mi, s)).toISOString();
}

export type SingleCertStatus = "good" | "revoked" | "unknown";

export interface StapleSummary {
  /** ResponseStatus: 0 = successful. */
  responseStatus: number;
  producerName?: string;
  producedAt?: string;
  thisUpdate?: string;
  nextUpdate?: string;
  /** Status of the leaf certificate (first SingleResponse), when present. */
  leafStatus?: SingleCertStatus;
  revokedAt?: string;
  revocationReason?: number;
  error?: string;
}

/** OIDs for cert status CHOICE tags: [0] good, [1] revoked, [2] unknown. */
function statusFromTag(tag: number): SingleCertStatus | undefined {
  // IMPLICIT tags: context-specific primitive 0x80/0x81/0x82, and constructed
  // 0xa0/0xa1/0xa2 for encodings that wrap their content.
  switch (tag & 0x1f) {
    case 0:
      return "good";
    case 1:
      return "revoked";
    case 2:
      return "unknown";
    default:
      return undefined;
  }
}

/**
 * Parse an OCSPResponse structure. Never throws: malformed input is reported
 * through `error`, because a staple that cannot be parsed is itself a finding.
 */
export function parseOcspResponse(der: Buffer): StapleSummary {
  const summary: StapleSummary = { responseStatus: -1 };
  try {
    const { node: response } = readDer(der, 0);
    const top = readSequence(response);
    if (top.length === 0) throw new RangeError("empty OCSPResponse");
    const statusNode = top[0]!;
    if (statusNode.tag !== 0x0a) throw new RangeError("missing responseStatus ENUMERATED");
    summary.responseStatus = statusNode.value[0] ?? 0;
    if (summary.responseStatus !== 0) return summary;

    const responseBytes = top[1];
    if (!responseBytes) throw new RangeError("successful OCSPResponse without responseBytes");
    // responseBytes is a [0] EXPLICIT wrapper around:
    //   SEQUENCE { responseType OID, response OCTET STRING }
    if (responseBytes.tag !== 0xa0) throw new RangeError("responseBytes is not [0] EXPLICIT");
    const inner = readDer(responseBytes.value, 0).node;
    const seq = readSequence(inner);
    const oidNode = seq[0];
    if (!oidNode) throw new RangeError("missing responseType");
    const oid = decodeOid(oidNode.value);
    if (oid !== "1.3.6.1.5.5.7.48.1.1") {
      summary.error = `unexpected responseType OID ${oid}`;
      return summary;
    }
    const octets = seq[1];
    if (!octets) throw new RangeError("missing response OCTET STRING");
    parseBasicOcsp(octets.value, summary);
    return summary;
  } catch (err) {
    summary.error = (err as Error).message;
    return summary;
  }
}

function parseBasicOcsp(der: Buffer, summary: StapleSummary): void {
  const basicSeq = readDer(der, 0).node;
  const fields = readSequence(basicSeq);
  // BasicOCSPResponse ::= SEQUENCE {
  //   tbsResponseData ResponseData, signatureAlgorithm, signature, certs [0] }
  const tbs = fields[0];
  if (!tbs) throw new RangeError("missing tbsResponseData");
  const tbsFields = readSequence(tbs);

  let idx = 0;
  if (tbsFields[0] && tbsFields[0].tag === 0xa0) {
    // version [0] EXPLICIT
    idx = 1;
  }
  const responderId = tbsFields[idx++];
  if (responderId) summary.producerName = responderIdName(responderId);
  const producedAt = tbsFields[idx++];
  if (producedAt) summary.producedAt = decodeTime(producedAt);

  const responses = tbsFields[idx];
  if (!responses) throw new RangeError("missing responses sequence");
  const singleResponses = readSequence(responses);
  const first = singleResponses[0];
  if (first) {
    const sr = readSequence(first);
    const certStatus = sr[1];
    if (certStatus) {
      summary.leafStatus = statusFromTag(certStatus.tag);
      if (certStatus.tag === 0xa1) {
        const revoked = readSequence({ tag: 0x30, value: certStatus.value });
        const when = revoked[0];
        if (when) summary.revokedAt = decodeTime(when);
        // RevokedInfo ::= SEQUENCE { revocationTime, revocationReason
        //   [0] EXPLICIT CRLReason OPTIONAL } — so the reason is wrapped in an
        // 0xa0 node whose content is the ENUMERATED (0x0a).
        const reasonWrapper = revoked[1];
        if (reasonWrapper?.tag === 0xa0) {
          const enumerated = readDer(reasonWrapper.value, 0).node;
          if (enumerated.tag === 0x0a) summary.revocationReason = enumerated.value[0] ?? 0;
        } else if (reasonWrapper?.tag === 0x0a) {
          // Tolerate an IMPLICIT encoding some responders emit.
          summary.revocationReason = reasonWrapper.value[0] ?? 0;
        }
      }
    }
    const thisUpdate = sr[2];
    if (thisUpdate) summary.thisUpdate = decodeTime(thisUpdate);
    // nextUpdate [0] EXPLICIT GeneralizedTime
    const nextUpdate = sr[3];
    if (nextUpdate?.tag === 0xa0) {
      const inner = readDer(nextUpdate.value, 0).node;
      summary.nextUpdate = decodeTime(inner);
    }
  }
}

function responderIdName(node: DerNode): string | undefined {
  try {
    if (node.tag === 0xa1) {
      // byName [1] Name. A Name is a SEQUENCE of RelativeDistinguishedName,
      // each of which is a SET (0x31) of AttributeTypeAndValue SEQUENCEs.
      const name = readSequence(readDer(node.value, 0).node);
      for (const rdn of name) {
        const attrs = rdn.tag === 0x31 ? readSet(rdn) : readSequence(rdn);
        for (const attr of attrs) {
          const [oidNode, valueNode] = readSequence(attr);
          if (!oidNode || !valueNode) continue;
          const oid = decodeOid(oidNode.value);
          if (oid === "2.5.4.3") return `CN=${valueNode.value.toString("utf8")}`;
        }
      }
      return undefined;
    }
    if (node.tag === 0xa2) {
      // byKey [2] KeyHash — render a short fingerprint
      return `keyHash=${node.value.subarray(0, 8).toString("hex")}`;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/** Parse a DER SET (tag 0x31) into its child nodes. */
function readSet(node: DerNode): DerNode[] {
  if (node.tag !== 0x31) throw new RangeError(`DER: expected SET, got 0x${node.tag.toString(16)}`);
  const children: DerNode[] = [];
  let offset = 0;
  while (offset < node.value.length) {
    const { node: child, next } = readDer(node.value, offset);
    children.push(child);
    offset = next;
  }
  return children;
}
