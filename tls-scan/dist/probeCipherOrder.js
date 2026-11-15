"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.probeCipherOrder = probeCipherOrder;
const connect_1 = require("./connect");
/**
 * Offer the same two ciphers in both orders. If the server picks the same
 * cipher both times it enforces its own preference; if the pick follows the
 * client's order, the client controls cipher selection.
 */
async function probeCipherOrder(target, version, supportedOpensslNames, limiter, timeoutMs) {
    if (supportedOpensslNames.length < 2) {
        return { tested: false, detail: 'fewer than 2 supported ciphers, cannot test ordering' };
    }
    const [a, b] = supportedOpensslNames;
    const opts = { minVersion: version, maxVersion: version, timeoutMs };
    const r1 = await (0, connect_1.handshake)(target, { ...opts, ciphers: `${a}:${b}:@SECLEVEL=0` }, limiter);
    const r2 = await (0, connect_1.handshake)(target, { ...opts, ciphers: `${b}:${a}:@SECLEVEL=0` }, limiter);
    if (!r1.ok || !r2.ok) {
        const err = !r1.ok ? r1.error : !r2.ok ? r2.error : 'unknown';
        return { tested: false, detail: `probe connections failed (${err})` };
    }
    const enforced = r1.cipherName === r2.cipherName;
    return {
        tested: true,
        enforcesServerOrder: enforced,
        detail: enforced
            ? `server picked ${r1.cipherName} regardless of client order`
            : `server followed client order (${r1.cipherName} vs ${r2.cipherName})`,
    };
}
