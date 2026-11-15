"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_BASELINE = void 0;
exports.mergeBaseline = mergeBaseline;
exports.DEFAULT_BASELINE = {
    minProtocol: 'TLSv1.2',
    forbiddenProtocols: ['TLSv1', 'TLSv1.1'],
    recommendTls13: true,
    requireServerCipherOrder: true,
    weakCipherPatterns: ['NULL', 'EXP', 'RC4', 'RC2', 'IDEA', 'MD5', 'anon', '3DES', 'DES-CBC', 'SEED', 'CAMELLIA'],
    penalizeNonPfs: true,
    ocspStapling: 'optional',
    hsts: {
        required: false,
        minMaxAge: 15552000, // 180 days
        requireIncludeSubDomains: false,
    },
    cert: {
        penalizeSelfSigned: true,
        expiringSoonDays: 30,
    },
    weights: {
        forbiddenProtocol: 15,
        missingTls13: 5,
        weakCipher: 5,
        weakCipherCap: 25,
        nonPfsCipher: 2,
        nonPfsCap: 10,
        cipherOrder: 10,
        renegotiationInfoMissing: 5,
        clientRenegotiationAllowed: 5,
        ocspMissing: 5,
        hstsMissing: 10,
        hstsShortMaxAge: 5,
        hstsNoIncludeSubDomains: 3,
        certExpired: 40,
        certExpiringSoon: 5,
        certSelfSigned: 5,
    },
};
function mergeBaseline(user) {
    if (!user)
        return exports.DEFAULT_BASELINE;
    return {
        ...exports.DEFAULT_BASELINE,
        ...user,
        hsts: { ...exports.DEFAULT_BASELINE.hsts, ...(user.hsts ?? {}) },
        cert: { ...exports.DEFAULT_BASELINE.cert, ...(user.cert ?? {}) },
        weights: { ...exports.DEFAULT_BASELINE.weights, ...(user.weights ?? {}) },
    };
}
