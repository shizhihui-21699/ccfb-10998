"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.probeRenegotiation = probeRenegotiation;
const node_net_1 = __importDefault(require("node:net"));
const node_tls_1 = __importDefault(require("node:tls"));
const node_crypto_1 = __importDefault(require("node:crypto"));
const EXT_RENEGOTIATION_INFO = 0xff01;
function ext(type, data) {
    const b = Buffer.alloc(4 + data.length);
    b.writeUInt16BE(type, 0);
    b.writeUInt16BE(data.length, 2);
    data.copy(b, 4);
    return b;
}
/** Build a TLS 1.2 ClientHello carrying SNI + an (empty) renegotiation_info extension. */
function buildClientHello(servername) {
    const random = node_crypto_1.default.randomBytes(32);
    // a spread of common suites so most servers can answer
    const cipherSuites = [
        0xc02f, 0xc030, 0xc02b, 0xc02c, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
    ];
    const csBuf = Buffer.alloc(cipherSuites.length * 2);
    cipherSuites.forEach((c, i) => csBuf.writeUInt16BE(c, i * 2));
    const exts = [];
    if (servername && !node_net_1.default.isIP(servername)) {
        const name = Buffer.from(servername, 'ascii');
        const entry = Buffer.alloc(3 + name.length);
        entry.writeUInt8(0, 0); // host_name
        entry.writeUInt16BE(name.length, 1);
        name.copy(entry, 3);
        const list = Buffer.alloc(2 + entry.length);
        list.writeUInt16BE(entry.length, 0);
        entry.copy(list, 2);
        exts.push(ext(0x0000, list)); // server_name
    }
    // supported_groups: x25519, secp256r1, secp384r1, secp521r1, ffdhe2048, ffdhe3072
    const groups = Buffer.alloc(2 + 6 * 2);
    groups.writeUInt16BE(12, 0);
    [0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101].forEach((g, i) => groups.writeUInt16BE(g, 2 + i * 2));
    exts.push(ext(0x000a, groups));
    // ec_point_formats: uncompressed
    exts.push(ext(0x000b, Buffer.from([0x01, 0x00])));
    // signature_algorithms (required by OpenSSL 3.x servers for TLS 1.2)
    const sigAlgs = [0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0201];
    const sa = Buffer.alloc(2 + sigAlgs.length * 2);
    sa.writeUInt16BE(sigAlgs.length * 2, 0);
    sigAlgs.forEach((a, i) => sa.writeUInt16BE(a, 2 + i * 2));
    exts.push(ext(0x000d, sa));
    // renegotiation_info with empty renegotiated_connection (initial handshake)
    exts.push(Buffer.from([0xff, 0x01, 0x00, 0x01, 0x00]));
    const extBuf = Buffer.concat(exts);
    const parts = [
        Buffer.from([0x03, 0x03]), // client_version: TLS 1.2
        random,
        Buffer.from([0x00]), // session id length
    ];
    const csLen = Buffer.alloc(2);
    csLen.writeUInt16BE(csBuf.length, 0);
    parts.push(csLen, csBuf);
    parts.push(Buffer.from([0x01, 0x00])); // compression: null only
    const extLen = Buffer.alloc(2);
    extLen.writeUInt16BE(extBuf.length, 0);
    parts.push(extLen, extBuf);
    const body = Buffer.concat(parts);
    const hsHead = Buffer.alloc(4);
    hsHead.writeUInt8(0x01, 0); // client_hello
    hsHead.writeUIntBE(body.length, 1, 3);
    const hs = Buffer.concat([hsHead, body]);
    const recHead = Buffer.alloc(5);
    recHead.writeUInt8(0x16, 0); // handshake record
    recHead.writeUInt16BE(0x0301, 1);
    recHead.writeUInt16BE(hs.length, 3);
    return Buffer.concat([recHead, hs]);
}
const ALERT_NAMES = {
    0: 'close_notify',
    10: 'unexpected_message',
    20: 'bad_record_mac',
    40: 'handshake_failure',
    42: 'bad_certificate',
    47: 'illegal_parameter',
    70: 'protocol_version',
    71: 'insufficient_security',
    80: 'internal_error',
    90: 'user_canceled',
    109: 'missing_extension',
    112: 'unrecognized_name',
};
function parseServerHelloBody(body) {
    // server_version(2) random(32) session_id_len(1) session_id cipher(2) compression(1) extensions
    let p = 2 + 32;
    if (body.length < p + 1)
        return { hasRenegInfo: false, alert: 'truncated ServerHello' };
    const sidLen = body.readUInt8(p);
    p += 1 + sidLen;
    if (body.length < p + 3)
        return { hasRenegInfo: false, alert: 'truncated ServerHello' };
    p += 2; // cipher suite
    p += 1; // compression
    let hasRenegInfo = false;
    if (p + 2 <= body.length) {
        const extLen = body.readUInt16BE(p);
        p += 2;
        const end = Math.min(body.length, p + extLen);
        while (p + 4 <= end) {
            const et = body.readUInt16BE(p);
            const el = body.readUInt16BE(p + 2);
            p += 4;
            if (et === EXT_RENEGOTIATION_INFO)
                hasRenegInfo = true;
            p += el;
        }
    }
    return { hasRenegInfo };
}
/** Walk TLS records in buf; returns null while the ServerHello is incomplete. */
function tryParseRecords(buf) {
    let offset = 0;
    let hs = Buffer.alloc(0);
    while (offset + 5 <= buf.length) {
        const type = buf.readUInt8(offset);
        const len = buf.readUInt16BE(offset + 3);
        if (offset + 5 + len > buf.length)
            return null; // need more bytes
        const frag = buf.subarray(offset + 5, offset + 5 + len);
        offset += 5 + len;
        if (type === 21) {
            // alert
            const desc = frag.length >= 2 ? frag.readUInt8(1) : -1;
            return { hasRenegInfo: false, alert: ALERT_NAMES[desc] ?? `alert ${desc}` };
        }
        if (type !== 22)
            continue; // ignore CCS etc.
        hs = Buffer.concat([hs, frag]);
        if (hs.length >= 4) {
            const htype = hs.readUInt8(0);
            const hlen = hs.readUIntBE(1, 3);
            if (htype !== 0x02)
                return { hasRenegInfo: false, alert: `unexpected handshake message ${htype}` };
            if (hs.length >= 4 + hlen)
                return parseServerHelloBody(hs.subarray(4, 4 + hlen));
        }
    }
    return null;
}
/** Send a raw ClientHello and check the ServerHello for renegotiation_info. */
function probeRenegotiationExt(target, timeoutMs) {
    return new Promise((resolve) => {
        let settled = false;
        const done = (v) => {
            if (settled)
                return;
            settled = true;
            try {
                sock.destroy();
            }
            catch {
                /* ignore */
            }
            resolve(v);
        };
        const sock = node_net_1.default.connect({ host: target.host, port: target.port });
        sock.setTimeout(timeoutMs, () => done(null));
        sock.once('error', () => done(null));
        let buf = Buffer.alloc(0);
        sock.on('data', (d) => {
            buf = Buffer.concat([buf, d]);
            const parsed = tryParseRecords(buf);
            if (parsed)
                done(parsed.alert ? null : parsed.hasRenegInfo);
        });
        sock.on('close', () => done(null));
        sock.once('connect', () => {
            sock.write(buildClientHello(target.servername ?? (node_net_1.default.isIP(target.host) ? undefined : target.host)));
        });
    });
}
/** Attempt a client-initiated renegotiation over a real (TLS <= 1.2) connection. */
function tryActiveRenegotiation(target, timeoutMs) {
    return new Promise((resolve) => {
        let settled = false;
        let attempted = false;
        const done = (v) => {
            if (settled)
                return;
            settled = true;
            try {
                sock.destroy();
            }
            catch {
                /* ignore */
            }
            resolve(v);
        };
        const sock = node_tls_1.default.connect({
            host: target.host,
            port: target.port,
            servername: target.servername ?? (node_net_1.default.isIP(target.host) ? undefined : target.host),
            rejectUnauthorized: false,
            minVersion: 'TLSv1',
            maxVersion: 'TLSv1.2', // TLS 1.3 removed renegotiation entirely
            ciphers: 'ALL:@SECLEVEL=0',
        });
        sock.setTimeout(timeoutMs, () => done(null));
        sock.once('error', () => done(attempted ? false : null));
        sock.once('secureConnect', () => {
            attempted = true;
            try {
                sock.renegotiate({ rejectUnauthorized: false }, (err) => done(!err));
            }
            catch {
                done(null);
            }
        });
    });
}
async function probeRenegotiation(target, hasPre13, timeoutMs) {
    const ext = await probeRenegotiationExt(target, timeoutMs);
    let active = null;
    let note;
    if (hasPre13) {
        active = await tryActiveRenegotiation(target, timeoutMs);
        note =
            'insecure (legacy) renegotiation cannot be triggered from a modern OpenSSL client; ' +
                'reported value is RFC 5746 secure-renegotiation support';
    }
    else {
        note = 'TLS 1.3-only service: renegotiation does not exist in TLS 1.3';
    }
    return { secureRenegotiationExt: ext, clientInitiatedAllowed: active, note };
}
