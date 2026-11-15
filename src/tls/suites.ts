/**
 * Cipher suite classification.
 *
 * The registry (suite-registry.generated.ts) gives us authoritative IANA names
 * and their "Recommended" column. This module turns a raw 16-bit id into an
 * SuiteInfo with the properties the baseline cares about: key exchange family,
 * forward secrecy, authentication, and a strength verdict with reasons.
 *
 * Names in the registry are the canonical TLS_* form. We also keep a small map
 * of OpenSSL-style short names for the suites operators most often configure,
 * because that is what they will search for in their own configs.
 */
import { IANA_SUITES } from './suite-registry.generated.ts';
import type { SuiteFamily, SuiteInfo, SuiteStrength } from '../types.ts';

const byId = new Map<number, (typeof IANA_SUITES)[number]>();
for (const s of IANA_SUITES) byId.set(s.id, s);

/** OpenSSL short names for common suites. Extended when a lookup misses. */
const OPENSSL_NAMES: Record<number, string> = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02b: 'ECDHE-ECDSA-AES128-GCM-SHA256',
  0xc02c: 'ECDHE-ECDSA-AES256-GCM-SHA384',
  0xc02f: 'ECDHE-RSA-AES128-GCM-SHA256',
  0xc030: 'ECDHE-RSA-AES256-GCM-SHA384',
  0xcca8: 'ECDHE-RSA-CHACHA20-POLY1305',
  0xcca9: 'ECDHE-ECDSA-CHACHA20-POLY1305',
  0xc009: 'ECDHE-ECDSA-AES128-SHA',
  0xc00a: 'ECDHE-ECDSA-AES256-SHA',
  0xc013: 'ECDHE-RSA-AES128-SHA',
  0xc014: 'ECDHE-RSA-AES256-SHA',
  0x009c: 'AES128-GCM-SHA256',
  0x009d: 'AES256-GCM-SHA384',
  0x002f: 'AES128-SHA',
  0x0035: 'AES256-SHA',
  0x000a: 'DES-CBC3-SHA',
  0x0005: 'RC4-SHA',
  0x0004: 'RC4-MD5',
  0x009e: 'DHE-RSA-AES128-GCM-SHA256',
  0x009f: 'DHE-RSA-AES256-GCM-SHA384',
  0x0033: 'DHE-RSA-AES128-SHA',
  0x0039: 'DHE-RSA-AES256-SHA',
  0xc0a8: 'PSK-AES128-GCM-SHA256',
  0xc0a9: 'PSK-AES256-GCM-SHA384',
  0x00a8: 'PSK-AES128-GCM-SHA256',
  0x00a9: 'PSK-AES256-GCM-SHA384',
};

/** Suites we recognise as having no encryption at all (downgraded, never acceptable). */
function isNullEncryption(name: string): boolean {
  return /_WITH_NULL_/.test(name) || /_NULL_/.test(name) || name === 'TLS_NULL_WITH_NULL_NULL';
}

function isExport(name: string): boolean {
  return /_EXPORT_/.test(name);
}

function isAnonymous(name: string): boolean {
  return /_(anon|ANON)_/.test(name) || /_WITH_ADH_/.test(name) || /_WITH_AECDH_/.test(name);
}

function isPskOnly(name: string): boolean {
  // PSK suites with no certificate authentication. Still encrypted, but trust is
  // pre-shared rather than PKI; treat as acceptable-but-flagged rather than weak.
  return /^(TLS_)?(DHE_)?PSK_/.test(name) || /_WITH_PSK_/.test(name) || /^TLS_SRP/.test(name);
}

function isStaticRsa(name: string): boolean {
  return /^TLS_RSA_WITH_/.test(name);
}

function isStaticDh(name: string): boolean {
  return /^TLS_DH_(DSS|RSA)_WITH_/.test(name);
}

function isDhe(name: string): boolean {
  return /^TLS_DHE_(DSS|RSA|PSK)_WITH_/.test(name) || /^TLS_DHE_PSK_WITH_/.test(name);
}

function isEcdhe(name: string): boolean {
  return /^TLS_ECDHE_/.test(name) || /^TLS_ECDH_ANON_/.test(name);
}

function isTls13Suite(id: number): boolean {
  return id >= 0x1301 && id <= 0x1305;
}

function familyOf(name: string, id: number): SuiteFamily {
  if (isTls13Suite(id)) return 'TLS1.3';
  if (isAnonymous(name)) return 'anonymous';
  if (isEcdhe(name)) return 'ECDHE';
  if (isDhe(name)) return 'DHE';
  if (isStaticRsa(name)) return 'static-RSA';
  if (isStaticDh(name)) return 'static-DH';
  return 'other';
}

function strengthOf(name: string, id: number, ianaRecommended: string | undefined): {
  strength: SuiteStrength;
  notes: string[];
} {
  const notes: string[] = [];
  const tls13 = isTls13Suite(id);

  if (name === 'TLS_NULL_WITH_NULL_NULL' || isNullEncryption(name)) {
    notes.push('no encryption');
    return { strength: 'null', notes };
  }
  if (isExport(name)) {
    notes.push('EXPORT-grade key exchange (broken by design)');
    return { strength: 'insecure', notes };
  }
  if (/RC4/.test(name)) {
    notes.push('RC4 is cryptographically broken');
    return { strength: 'insecure', notes };
  }
  if (isAnonymous(name)) {
    notes.push('anonymous key exchange: server is not authenticated');
    return { strength: 'insecure', notes };
  }
  if (/_DES_|_3DES_|DES_EDE/.test(name) && !/AES|CHACHA/.test(name)) {
    notes.push('DES/3DES is deprecated');
    return { strength: 'weak', notes };
  }
  if (/CAMELLIA/.test(name) && /_(CBC|SHA)$|_SHA(256|384)?$/.test(name)) {
    notes.push('Camellia-CBC is uncommon and not preferred');
    return { strength: 'weak', notes };
  }
  if (tls13) {
    // TLS 1.3 suites are all AEAD with an ephemeral key exchange by design.
    if (id === 0x1301 || id === 0x1302 || id === 0x1303) {
      return { strength: 'strong', notes: ['TLS 1.3 AEAD suite with ephemeral key exchange'] };
    }
    return { strength: 'unknown', notes: ['unrecognised TLS 1.3 suite'] };
  }

  // TLS <= 1.2 from here on.
  //
  // Mode and key exchange are independent axes:
  //   AEAD  = _GCM_ or CHACHA20 (TLS 1.2 form); everything else with a MAC
  //           in the name is CBC (the only other mode TLS 1.2 defines).
  //   FS    = ECDHE/DHE; static RSA and static DH are the no-forward-secrecy
  //           cases.
  // Judging "CBC" by a name suffix is wrong: TLS_RSA_WITH_AES_128_GCM_SHA256
  // ends in SHA256 but is GCM.
  const isGcm = /_GCM_/.test(name) || /_CCM_/.test(name);
  const isChaCha = /CHACHA20/.test(name);
  const isAead = isGcm || isChaCha;
  const isCbc = !isAead && /_CBC_|_SHA$|_SHA256$|_SHA384$|_SHA_/.test(name);
  const sha1Mac = /_SHA$/.test(name) && !isAead;

  if (isAead) {
    if (isStaticRsa(name) || isStaticDh(name)) {
      notes.push('AEAD but with static key exchange: no forward secrecy');
      return { strength: 'weak', notes };
    }
    notes.push('AEAD with forward-secret key exchange');
    return { strength: 'strong', notes };
  }

  if (isCbc) {
    if (isStaticRsa(name) || isStaticDh(name)) {
      notes.push('CBC mode with static RSA/DH key exchange (no forward secrecy)');
      return { strength: 'weak', notes };
    }
    if (sha1Mac) {
      notes.push('CBC mode with SHA-1 MAC');
      return { strength: 'weak', notes };
    }
    notes.push('CBC mode');
    return { strength: 'acceptable', notes };
  }

  if (isStaticRsa(name) || isStaticDh(name)) {
    notes.push('static RSA/DH key exchange: no forward secrecy');
    return { strength: 'weak', notes };
  }
  if (isPskOnly(name)) {
    notes.push('pre-shared-key suite: encrypted but not PKI-authenticated');
    return { strength: 'acceptable', notes };
  }
  if (ianaRecommended === 'D') {
    notes.push('IANA marks this suite discouraged');
    return { strength: 'weak', notes };
  }
  return { strength: 'unknown', notes: ['unrecognised suite; no strength heuristic'] };
}

/** Turn a raw suite id into a fully described SuiteInfo. */
export function describeSuite(id: number): SuiteInfo {
  const meta = byId.get(id);
  const name = meta?.name ?? `UNKNOWN_0x${id.toString(16).padStart(4, '0').toUpperCase()}`;
  const ianaRecommended = meta?.recommended;
  const { strength, notes } = strengthOf(name, id, ianaRecommended);
  const family = familyOf(name, id);
  const tls13 = isTls13Suite(id);

  const forwardSecret = tls13 || family === 'ECDHE' || family === 'DHE' || /^TLS_ECDHE_/.test(name);
  const authenticated = family !== 'anonymous' && !isPskOnly(name);

  return {
    id,
    hex: id.toString(16).padStart(4, '0'),
    name,
    opensslName: OPENSSL_NAMES[id],
    family,
    strength,
    notes,
    forwardSecret,
    authenticated,
    ianaRecommended,
    isTls13: tls13,
  };
}

/**
 * Candidate suites offered to a server during enumeration, in the order we
 * prefer them. This is the union of every suite TLS 1.0-1.3 servers plausibly
 * implement in 2026, including weak ones we want to catch. Offering a superset
 * is safe: servers ignore suites they do not know.
 */
export const CANDIDATE_SUITES: readonly number[] = [
  // TLS 1.3
  0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
  // ECDHE + AEAD (preferred TLS 1.2)
  0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0xccaa,
  // ECDHE + CBC
  0xc013, 0xc014, 0xc009, 0xc00a, 0xc023, 0xc024, 0xc027, 0xc028,
  // DHE + AEAD
  0x009e, 0x009f, 0x00a2, 0x00a3, 0x00aa, 0x00ab,
  // DHE + CBC
  0x0033, 0x0039, 0x0067, 0x006b, 0x00b2, 0x00b3,
  // static RSA + AEAD
  0x009c, 0x009d, 0x00a0, 0x00a1,
  // static RSA + CBC (legacy)
  0x002f, 0x0035, 0x003c, 0x003d, 0x000a, 0x0005, 0x0004,
  // anonymous DH (insecure, but we want to detect it)
  0x0034, 0x003a, 0x006c, 0x006d, 0x00b8, 0x00b9, 0xc018, 0xc019,
  // export / null (ancient, detect-and-report)
  0x0003, 0x0008, 0x0009, 0x0002, 0x0001,
];

/**
 * TLS 1.3 suites are identified by five specific ids (0x1301-0x1305), not by a
 * numeric threshold: valid TLS 1.2 suites such as 0xc02f sort *above* 0x1305.
 */
const TLS13_SUITE_IDS = new Set([0x1301, 0x1302, 0x1303, 0x1304, 0x1305]);

/** Suites offered when probing a specific version, filtered to what that version can use. */
export function candidateSuitesFor(versionId: number): number[] {
  if (versionId === 0x0304) return CANDIDATE_SUITES.filter((id) => TLS13_SUITE_IDS.has(id));
  if (versionId <= 0x0302) {
    // TLS 1.0/1.1: no AEAD GCM in practice, and no TLS 1.3 suites. Keep CBC and
    // the handful of suites those stacks actually ship.
    return CANDIDATE_SUITES.filter(
      (id) => !TLS13_SUITE_IDS.has(id) && id !== 0xcca8 && id !== 0xcca9 && id !== 0xccaa,
    );
  }
  return CANDIDATE_SUITES.filter((id) => !TLS13_SUITE_IDS.has(id));
}

/** Convenience predicate used by the baseline: is this suite acceptable at all? */
export function isUnsafeSuite(s: SuiteInfo): boolean {
  return s.strength === 'insecure' || s.strength === 'null' || s.strength === 'weak';
}
