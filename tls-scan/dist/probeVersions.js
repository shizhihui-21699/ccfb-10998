"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.probeVersions = probeVersions;
const types_1 = require("./types");
const connect_1 = require("./connect");
const util_1 = require("./util");
/** Probe each protocol version by pinning minVersion=maxVersion. */
async function probeVersions(target, limiter, timeoutMs) {
    return (0, util_1.mapPool)(types_1.ALL_VERSIONS, 2, async (v) => {
        const r = await (0, connect_1.handshake)(target, {
            minVersion: v,
            maxVersion: v,
            // SECLEVEL=0 lets our client offer legacy ciphers so an old server
            // has the best chance to complete the handshake.
            ciphers: v === 'TLSv1.3' ? undefined : 'ALL:COMPLEMENTOFALL:@SECLEVEL=0',
            timeoutMs,
        }, limiter);
        return {
            version: v,
            supported: r.ok,
            error: r.ok ? undefined : r.error,
            negotiatedCipher: r.ok ? r.standardName ?? r.cipherName : undefined,
        };
    });
}
