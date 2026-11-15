"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.enumerateCiphers = enumerateCiphers;
exports.enumerateTls13 = enumerateTls13;
const node_tls_1 = __importDefault(require("node:tls"));
const node_child_process_1 = require("node:child_process");
const connect_1 = require("./connect");
/**
 * Enumerate ciphers for TLS <= 1.2 with the classic elimination method:
 * offer all remaining candidates, record the one the server picks, remove
 * it, repeat until the handshake fails. Costs (supported + 1) connections
 * per version instead of one connection per candidate cipher.
 */
async function enumerateCiphers(target, version, limiter, timeoutMs) {
    const candidates = [
        ...new Set(node_tls_1.default
            .getCiphers()
            .map((c) => c.toUpperCase())
            // TLS 1.3 suites (TLS_AES_...) cannot be set via the `ciphers` option.
            .filter((c) => !c.startsWith('TLS_'))),
    ];
    const remaining = [...candidates];
    const supported = [];
    for (let i = 0; i < candidates.length + 2 && remaining.length > 0; i++) {
        const r = await (0, connect_1.handshake)(target, {
            minVersion: version,
            maxVersion: version,
            ciphers: remaining.join(':') + ':@SECLEVEL=0',
            timeoutMs,
        }, limiter);
        if (!r.ok)
            break;
        supported.push({ opensslName: r.cipherName, standardName: r.standardName });
        const idx = remaining.findIndex((c) => c === r.cipherName.toUpperCase());
        if (idx === -1)
            break; // negotiated something we did not offer (shouldn't happen)
        remaining.splice(idx, 1);
    }
    return { version, ciphers: supported, source: 'elimination' };
}
const TLS13_SUITES = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_128_CCM_SHA256',
    'TLS_AES_128_CCM_8_SHA256',
];
let opensslOk = null;
function opensslVersion() {
    return new Promise((resolve) => {
        const p = (0, node_child_process_1.spawn)('openssl', ['version'], { stdio: ['ignore', 'pipe', 'ignore'] });
        let out = '';
        p.stdout.on('data', (d) => (out += d));
        p.on('error', () => resolve(null));
        p.on('close', () => resolve(out.trim() || null));
    });
}
async function hasOpensslCli() {
    if (opensslOk !== null)
        return opensslOk;
    const v = await opensslVersion();
    // need OpenSSL >= 1.1.1 for -ciphersuites / TLS 1.3
    opensslOk = !!v && /OpenSSL (1\.1\.1|[2-9]\.)/i.test(v);
    return opensslOk;
}
function sClientNegotiatedSuite(target, suites, timeoutMs) {
    return new Promise((resolve) => {
        const args = [
            's_client',
            '-connect',
            `${target.host}:${target.port}`,
            '-tls1_3',
            '-ciphersuites',
            suites.join(':'),
            '-brief',
        ];
        const sni = target.servername ?? target.host;
        if (sni)
            args.push('-servername', sni);
        const p = (0, node_child_process_1.spawn)('openssl', args, { stdio: ['pipe', 'pipe', 'pipe'] });
        let out = '';
        let settled = false;
        const done = (v) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            try {
                p.kill();
            }
            catch {
                /* ignore */
            }
            resolve(v);
        };
        const timer = setTimeout(() => done(null), timeoutMs + 2000);
        p.stdout.on('data', (d) => {
            out += d;
            const m = out.match(/Ciphersuite:\s*(\S+)/) ?? out.match(/Cipher is\s*(\S+)/);
            if (m)
                done(m[1]);
        });
        p.stderr.on('data', (d) => {
            out += d;
        });
        p.on('error', () => done(null));
        p.on('close', () => {
            const m = out.match(/Ciphersuite:\s*(\S+)/) ?? out.match(/Cipher is\s*(\S+)/);
            done(m ? m[1] : null);
        });
        // 'Q' makes s_client quit right after the handshake instead of hanging on stdin
        p.stdin.write('Q\n');
        p.stdin.end();
    });
}
/**
 * TLS 1.3 cipher enumeration. Node's tls API cannot restrict TLS 1.3
 * ciphersuites per connection, so we shell out to `openssl s_client` with
 * the same elimination method when a suitable CLI is available. Otherwise
 * we report only the suite negotiated during version probing.
 */
async function enumerateTls13(target, negotiatedCipher, timeoutMs) {
    if (await hasOpensslCli()) {
        const remaining = [...TLS13_SUITES];
        const supported = [];
        while (remaining.length > 0) {
            const picked = await sClientNegotiatedSuite(target, remaining, timeoutMs);
            if (!picked)
                break;
            const idx = remaining.findIndex((s) => s === picked);
            if (idx === -1)
                break;
            supported.push({ opensslName: picked, standardName: picked });
            remaining.splice(idx, 1);
        }
        if (supported.length > 0)
            return { version: 'TLSv1.3', ciphers: supported, source: 'openssl-cli' };
    }
    return {
        version: 'TLSv1.3',
        ciphers: negotiatedCipher ? [{ opensslName: negotiatedCipher, standardName: negotiatedCipher }] : [],
        source: 'negotiated-only',
        note: 'TLS 1.3 suite enumeration needs the openssl CLI (>=1.1.1); only the negotiated suite is shown',
    };
}
