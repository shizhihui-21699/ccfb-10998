/**
 * Leaf certificate summary.
 *
 * The interesting facts for a checkup are expiry, key strength, signature
 * algorithm (SHA-1 signed certs still turn up on appliances), and whether the
 * certificate is self-signed. Parsing uses node:crypto's X509Certificate, so
 * we get correct ASN.1 handling without a dependency.
 */
import { X509Certificate } from 'node:crypto';
import type { CertificateSummary } from '../types.ts';

const WEAK_KEY_BITS = { rsa: 2048, ec: 256, ed25519: 256 } as const;

export function summarizeCertificate(chain: string[]): CertificateSummary | undefined {
  const leafPem = chain[0];
  if (!leafPem) return undefined;

  let leaf: X509Certificate;
  try {
    leaf = new X509Certificate(leafPem);
  } catch {
    return undefined;
  }

  const validFrom = new Date(leaf.validFrom);
  const validTo = new Date(leaf.validTo);
  const now = Date.now();
  const daysUntilExpiry = Math.floor((validTo.getTime() - now) / 86_400_000);

  const keyType = leaf.publicKey.asymmetricKeyType ?? 'unknown';
  let keySize = 0;
  try {
    const details = leaf.publicKey.asymmetricKeyDetails;
    if (keyType === 'rsa' || keyType === 'rsa-pss') keySize = details?.modulusLength ?? 0;
    else if (keyType === 'ec') keySize = details?.namedCurve ? curveBits(details.namedCurve) : 0;
    else if (keyType === 'ed25519' || keyType === 'ed448') keySize = 256;
  } catch {
    keySize = 0;
  }

  const raw = leaf.raw;
  const sha1Signature = /sha1/i.test(leaf.signatureAlgorithm ?? '') || /sha1/i.test(algorithmNameFromDer(raw));

  const issuer = leaf.issuer.replace(/\n/g, ', ');
  const subject = leaf.subject.replace(/\n/g, ', ');

  return {
    subject,
    issuer,
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    daysUntilExpiry,
    expired: validTo.getTime() < now,
    keyType,
    keySize,
    signatureAlgorithm: leaf.signatureAlgorithm ?? algorithmNameFromDer(raw),
    sha1Signature,
    selfSigned: leaf.subject === leaf.issuer && leaf.checkIssued(leaf) && verifySelfSigned(leaf),
    subjectAltNames: parseSubjectAltNames(leaf.subjectAltName),
    chainLength: chain.length,
  };
}

function curveBits(curve: string): number {
  switch (curve) {
    case 'prime256v1':
    case 'secp256r1':
      return 256;
    case 'secp384r1':
      return 384;
    case 'secp521r1':
      return 521;
    case 'secp256k1':
      return 256;
    default:
      return 0;
  }
}

/** Best-effort lookup of the signature algorithm OID name from the DER. */
function algorithmNameFromDer(der: Buffer): string {
  // sha1WithRSAEncryption OID: 1.2.840.113549.1.1.5
  const sha1Rsa = Buffer.from('06092a864886f70d010105', 'hex');
  // ecdsa-with-SHA1: 1.2.840.10045.4.1
  const ecdsaSha1 = Buffer.from('06072a8648ce3d0401', 'hex');
  if (der.includes(sha1Rsa)) return 'sha1WithRSAEncryption';
  if (der.includes(ecdsaSha1)) return 'ecdsa-with-SHA1';
  return 'unknown';
}

function verifySelfSigned(leaf: X509Certificate): boolean {
  try {
    return leaf.verify(leaf.publicKey);
  } catch {
    return false;
  }
}

function parseSubjectAltNames(san: string | undefined): string[] {
  if (!san) return [];
  // node formats as "DNS:localhost, IP Address:127.0.0.1"
  return san
    .split(/,\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Adds human-readable warnings for certificate weaknesses. */
export function certificateWarnings(cert: CertificateSummary): string[] {
  const warnings: string[] = [];
  if (cert.expired) warnings.push(`certificate expired on ${cert.validTo}`);
  else if (cert.daysUntilExpiry <= 30) warnings.push(`certificate expires in ${cert.daysUntilExpiry} days`);
  if (cert.sha1Signature) warnings.push('certificate is signed with SHA-1');
  if (cert.keyType === 'rsa' && cert.keySize > 0 && cert.keySize < WEAK_KEY_BITS.rsa) {
    warnings.push(`RSA key is only ${cert.keySize} bits`);
  }
  if (cert.keyType === 'ec' && cert.keySize > 0 && cert.keySize < WEAK_KEY_BITS.ec) {
    warnings.push(`EC key is only ${cert.keySize} bits`);
  }
  if (cert.selfSigned) {
    warnings.push('certificate is self-signed');
  } else if (cert.chainLength === 1) {
    // A self-signed certificate is legitimately alone; a non-self-signed leaf
    // with no intermediates is usually a misconfigured chain.
    warnings.push('server sent no intermediate certificates');
  }
  return warnings;
}
