"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.handshake = handshake;
const node_net_1 = __importDefault(require("node:net"));
const node_tls_1 = __importDefault(require("node:tls"));
function normalizeErr(e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/sslv3 alert handshake failure|tlsv1 alert protocol version|handshake failure/i.test(msg))
        return 'handshake failure (no common protocol/cipher)';
    if (/no ciphers available/i.test(msg))
        return 'no ciphers available';
    if (/unsupported protocol/i.test(msg))
        return 'unsupported protocol';
    if (/wrong version number/i.test(msg))
        return 'wrong version number (not a TLS service?)';
    if (/ECONNREFUSED/.test(msg))
        return 'connection refused';
    if (/ECONNRESET/.test(msg))
        return 'connection reset';
    if (/ETIMEDOUT|timeout/i.test(msg))
        return 'timeout';
    if (/certificate/i.test(msg))
        return `certificate error: ${msg}`;
    return msg.split('\n')[0];
}
/** One TLS handshake. Socket is always destroyed before the promise settles. */
async function handshake(target, opts, limiter) {
    if (limiter)
        await limiter.acquire();
    try {
        return await doHandshake(target, opts);
    }
    finally {
        if (limiter)
            limiter.release();
    }
}
function doHandshake(target, opts) {
    return new Promise((resolve) => {
        let settled = false;
        let sock;
        const done = (r) => {
            if (settled)
                return;
            settled = true;
            try {
                sock?.destroy();
            }
            catch {
                /* ignore */
            }
            resolve(r);
        };
        try {
            const connOpts = {
                host: target.host,
                port: target.port,
                servername: target.servername ?? (node_net_1.default.isIP(target.host) ? undefined : target.host),
                rejectUnauthorized: false, // we are probing configuration, not validating trust
                minVersion: opts.minVersion,
                maxVersion: opts.maxVersion,
                ciphers: opts.ciphers,
                requestOCSP: opts.requestOCSP,
            };
            sock = node_tls_1.default.connect(connOpts);
        }
        catch (e) {
            resolve({ ok: false, error: normalizeErr(e) });
            return;
        }
        sock.setTimeout(opts.timeoutMs, () => done({ ok: false, error: 'timeout' }));
        sock.once('error', (e) => done({ ok: false, error: normalizeErr(e) }));
        // the stapled OCSP response arrives as an event before secureConnect
        let ocsp;
        sock.once('OCSPResponse', (r) => {
            ocsp = r ?? undefined;
        });
        sock.once('secureConnect', () => {
            const c = sock.getCipher();
            let cert;
            try {
                cert = sock.getPeerCertificate();
            }
            catch {
                /* ignore */
            }
            done({
                ok: true,
                cipherName: c?.name ?? '',
                standardName: c?.standardName,
                protocol: sock.getProtocol(),
                ocsp,
                cert,
            });
        });
    });
}
