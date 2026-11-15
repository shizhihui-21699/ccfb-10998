"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanTarget = scanTarget;
const connect_1 = require("./connect");
const probeVersions_1 = require("./probeVersions");
const probeCiphers_1 = require("./probeCiphers");
const probeCipherOrder_1 = require("./probeCipherOrder");
const probeRenegotiation_1 = require("./probeRenegotiation");
const probeHsts_1 = require("./probeHsts");
function certInfo(cert) {
    if (!cert || !cert.subject)
        return null;
    const fmt = (o) => Object.entries(o)
        .map(([k, v]) => `${k}=${String(v)}`)
        .join(', ');
    const validTo = Date.parse(cert.valid_to);
    return {
        subject: fmt(cert.subject),
        issuer: fmt(cert.issuer),
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysRemaining: Math.floor((validTo - Date.now()) / 86400000),
        selfSigned: JSON.stringify(cert.subject) === JSON.stringify(cert.issuer),
    };
}
async function scanTarget(target, opts, limiter) {
    const startedAt = new Date();
    const t0 = Date.now();
    const log = (m) => opts.onProgress?.(`[${target.host}:${target.port}] ${m}`);
    const t = opts.timeoutMs;
    const base = {
        target,
        startedAt: startedAt.toISOString(),
        durationMs: 0,
        versions: [],
        ciphers: [],
        cipherOrder: { tested: false, detail: 'not run' },
        renegotiation: { secureRenegotiationExt: null, clientInitiatedAllowed: null, note: 'not run' },
        ocspStapling: null,
        hsts: null,
        cert: null,
    };
    // 1. protocol versions
    log('probing protocol versions…');
    base.versions = await (0, probeVersions_1.probeVersions)(target, limiter, t);
    const supported = base.versions.filter((v) => v.supported).map((v) => v.version);
    if (supported.length === 0) {
        base.error = `no TLS version could be negotiated (${base.versions
            .map((v) => `${v.version}: ${v.error}`)
            .join('; ')})`;
        base.durationMs = Date.now() - t0;
        return base;
    }
    log(`supported: ${supported.join(', ')}`);
    // 2. cipher enumeration per version
    const pre13 = supported.filter((v) => v !== 'TLSv1.3');
    for (const v of pre13) {
        log(`enumerating ${v} ciphers…`);
        const r = await (0, probeCiphers_1.enumerateCiphers)(target, v, limiter, t);
        log(`${v}: ${r.ciphers.length} cipher(s)`);
        base.ciphers.push(r);
    }
    if (supported.includes('TLSv1.3')) {
        const negotiated = base.versions.find((v) => v.version === 'TLSv1.3')?.negotiatedCipher;
        const r = opts.enumTls13
            ? await (0, probeCiphers_1.enumerateTls13)(target, negotiated, t)
            : {
                version: 'TLSv1.3',
                ciphers: negotiated ? [{ opensslName: negotiated, standardName: negotiated }] : [],
                source: 'negotiated-only',
            };
        log(`TLSv1.3: ${r.ciphers.length} suite(s) (${r.source})`);
        base.ciphers.push(r);
    }
    // 3. cipher order, using the newest pre-1.3 version
    const orderVersion = [...pre13].sort().pop();
    if (orderVersion) {
        const list = base.ciphers.find((c) => c.version === orderVersion)?.ciphers ?? [];
        base.cipherOrder = await (0, probeCipherOrder_1.probeCipherOrder)(target, orderVersion, list.map((c) => c.opensslName), limiter, t);
        log(`cipher order: ${base.cipherOrder.detail}`);
    }
    // 4. renegotiation
    log('checking renegotiation…');
    base.renegotiation = await (0, probeRenegotiation_1.probeRenegotiation)(target, pre13.length > 0, t);
    // 5. OCSP stapling (also captures the certificate)
    log('checking OCSP stapling…');
    const best = supported.includes('TLSv1.3') ? 'TLSv1.3' : orderVersion ?? 'TLSv1.2';
    const ocspProbe = await (0, connect_1.handshake)(target, {
        minVersion: 'TLSv1',
        maxVersion: best,
        ciphers: best === 'TLSv1.3' ? undefined : 'ALL:@SECLEVEL=0',
        requestOCSP: true,
        timeoutMs: t,
    }, limiter);
    if (ocspProbe.ok) {
        base.ocspStapling = !!ocspProbe.ocsp && ocspProbe.ocsp.length > 0;
        base.cert = certInfo(ocspProbe.cert);
    }
    else {
        base.ocspStapling = null;
    }
    // 6. HSTS
    if (opts.checkHsts) {
        log('fetching HSTS header…');
        base.hsts = await (0, probeHsts_1.probeHsts)(target, t);
    }
    base.durationMs = Date.now() - t0;
    log(`done in ${base.durationMs}ms`);
    return base;
}
