/**
 * The default baseline.
 *
 * Tuned for an internal service fleet, not the public web: it still flags
 * TLS 1.0/1.1 and weak suites as findings, but the required floor is TLS 1.2
 * because many internal appliances cannot yet do 1.3. Raise `protocols` rules
 * to `require` TLS 1.3 for a stricter posture.
 */
import type { Baseline } from "./types.ts";

export const DEFAULT_BASELINE: Baseline = {
  version: "1.0",
  name: "internal-default",
  description:
    "Default posture for an internal service fleet: TLS 1.2+ required, TLS 1.0/1.1 and weak suites flagged, client-initiated renegotiation and SHA-1 certificates forbidden, HSTS encouraged.",

  safety: {
    concurrency: 6,
    retries: 1,
    maxAttemptsPerHost: 260,
    maxProbesPerVersion: 48,
    deadlineMs: 120_000,
    jitterMs: [20, 120],
  },

  protocols: [
    {
      id: "proto-sslv3",
      title: "SSLv3 disabled",
      versions: ["SSLv3"],
      forbid: true,
      severity: "critical",
      weight: 10,
      message: "SSLv3 must not be enabled (POODLE).",
    },
    {
      id: "proto-tls10",
      title: "TLS 1.0 disabled",
      versions: ["TLSv1.0"],
      forbid: true,
      severity: "high",
      weight: 8,
      message: "TLS 1.0 is deprecated (RFC 8996) and must be disabled.",
    },
    {
      id: "proto-tls11",
      title: "TLS 1.1 disabled",
      versions: ["TLSv1.1"],
      forbid: true,
      severity: "high",
      weight: 8,
      message: "TLS 1.1 is deprecated (RFC 8996) and must be disabled.",
    },
    {
      id: "proto-tls12",
      title: "TLS 1.2 enabled",
      versions: ["TLSv1.2"],
      require: true,
      severity: "medium",
      weight: 6,
      message: "TLS 1.2 should remain available for older clients.",
    },
    {
      id: "proto-tls13",
      title: "TLS 1.3 enabled",
      versions: ["TLSv1.3"],
      require: true,
      severity: "medium",
      weight: 6,
      message: "TLS 1.3 should be enabled for modern clients.",
    },
  ],

  suites: [
    {
      id: "suite-weak",
      title: "No weak cipher suites",
      rejectWeak: true,
      severity: "high",
      weight: 10,
      message: "Weak suites (RC4, 3DES, DES, RC2, EXPORT, NULL, GOST, MD5) must not be offered.",
    },
    {
      id: "suite-legacy-enc",
      title: "No legacy bulk ciphers",
      rejectLegacyEncryption: true,
      severity: "high",
      weight: 8,
      message: "Legacy bulk ciphers (RC4/3DES/DES) must not be negotiable.",
    },
    {
      id: "suite-no-fs",
      title: "All suites provide forward secrecy",
      rejectNoForwardSecrecy: true,
      severity: "medium",
      weight: 7,
      message: "Every negotiable suite should use ephemeral key exchange (ECDHE/DHE).",
    },
    {
      id: "suite-rsa-kx",
      title: "No static RSA key exchange",
      rejectRsaKeyExchange: true,
      severity: "medium",
      weight: 6,
      message: "Static RSA key exchange lacks forward secrecy and should be disabled.",
    },
    {
      id: "suite-anonymous",
      title: "No anonymous suites",
      rejectAnonymous: true,
      severity: "critical",
      weight: 10,
      message: "Anonymous (ADH/AECDH) suites provide no authentication and must be disabled.",
    },
  ],

  renegotiation: {
    requireSecureRenegotiation: true,
    forbidClientInitiated: true,
    severity: "high",
    weight: 8,
  },

  preference: {
    requireServerOrder: true,
    severity: "low",
    weight: 4,
  },

  ocsp: {
    expectStapling: true,
    rejectExpired: true,
    severity: "low",
    weight: 4,
  },

  hsts: {
    require: true,
    minMaxAge: 15_552_000, // 180 days
    requireIncludeSubDomains: false,
    severity: "low",
    weight: 3,
  },

  certificate: {
    minRsaBits: 2048,
    minEcBits: 224,
    rejectSha1: true,
    maxDaysToExpiryWarn: 30,
    severity: "high",
    weight: 9,
  },

  scoring: {
    grades: [
      { minScore: 90, grade: "A" },
      { minScore: 80, grade: "B" },
      { minScore: 70, grade: "C" },
      { minScore: 60, grade: "D" },
      { minScore: 0, grade: "F" },
    ],
  },
};
