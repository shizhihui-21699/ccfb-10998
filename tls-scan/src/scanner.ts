import tls from 'node:tls';
import { handshake } from './connect';
import { probeVersions } from './probeVersions';
import { enumerateCiphers, enumerateTls13 } from './probeCiphers';
import { probeCipherOrder } from './probeCipherOrder';
import { probeRenegotiation } from './probeRenegotiation';
import { probeHsts } from './probeHsts';
import {
  CertInfo,
  CipherEnumResult,
  ScanResult,
  Target,
  TlsVersion,
} from './types';
import { Semaphore } from './util';

export interface ScanOptions {
  timeoutMs: number;
  /** try TLS 1.3 suite enumeration via openssl CLI */
  enumTls13: boolean;
  /** run the HTTP/HSTS probe */
  checkHsts: boolean;
  onProgress?: (msg: string) => void;
}

function certInfo(cert: tls.PeerCertificate | undefined): CertInfo | null {
  if (!cert || !cert.subject) return null;
  const fmt = (o: Record<string, unknown>) =>
    Object.entries(o)
      .map(([k, v]) => `${k}=${String(v)}`)
      .join(', ');
  const validTo = Date.parse(cert.valid_to);
  return {
    subject: fmt(cert.subject as unknown as Record<string, unknown>),
    issuer: fmt(cert.issuer as unknown as Record<string, unknown>),
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    daysRemaining: Math.floor((validTo - Date.now()) / 86400000),
    selfSigned:
      JSON.stringify(cert.subject) === JSON.stringify(cert.issuer),
  };
}

export async function scanTarget(
  target: Target,
  opts: ScanOptions,
  limiter: Semaphore,
): Promise<ScanResult> {
  const startedAt = new Date();
  const t0 = Date.now();
  const log = (m: string) => opts.onProgress?.(`[${target.host}:${target.port}] ${m}`);
  const t = opts.timeoutMs;

  const base: ScanResult = {
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
  base.versions = await probeVersions(target, limiter, t);
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
  const pre13 = supported.filter((v): v is Exclude<TlsVersion, 'TLSv1.3'> => v !== 'TLSv1.3');
  for (const v of pre13) {
    log(`enumerating ${v} ciphers…`);
    const r = await enumerateCiphers(target, v, limiter, t);
    log(`${v}: ${r.ciphers.length} cipher(s)`);
    base.ciphers.push(r);
  }
  if (supported.includes('TLSv1.3')) {
    const negotiated = base.versions.find((v) => v.version === 'TLSv1.3')?.negotiatedCipher;
    const r = opts.enumTls13
      ? await enumerateTls13(target, negotiated, t)
      : {
          version: 'TLSv1.3',
          ciphers: negotiated ? [{ opensslName: negotiated, standardName: negotiated }] : [],
          source: 'negotiated-only',
        } as CipherEnumResult;
    log(`TLSv1.3: ${r.ciphers.length} suite(s) (${r.source})`);
    base.ciphers.push(r);
  }

  // 3. cipher order, using the newest pre-1.3 version
  const orderVersion = [...pre13].sort().pop();
  if (orderVersion) {
    const list = base.ciphers.find((c) => c.version === orderVersion)?.ciphers ?? [];
    base.cipherOrder = await probeCipherOrder(
      target,
      orderVersion,
      list.map((c) => c.opensslName),
      limiter,
      t,
    );
    log(`cipher order: ${base.cipherOrder.detail}`);
  }

  // 4. renegotiation
  log('checking renegotiation…');
  base.renegotiation = await probeRenegotiation(target, pre13.length > 0, t);

  // 5. OCSP stapling (also captures the certificate)
  log('checking OCSP stapling…');
  const best = supported.includes('TLSv1.3') ? 'TLSv1.3' : orderVersion ?? 'TLSv1.2';
  const ocspProbe = await handshake(
    target,
    {
      minVersion: 'TLSv1',
      maxVersion: best as tls.SecureVersion,
      ciphers: best === 'TLSv1.3' ? undefined : 'ALL:@SECLEVEL=0',
      requestOCSP: true,
      timeoutMs: t,
    },
    limiter,
  );
  if (ocspProbe.ok) {
    base.ocspStapling = !!ocspProbe.ocsp && ocspProbe.ocsp.length > 0;
    base.cert = certInfo(ocspProbe.cert);
  } else {
    base.ocspStapling = null;
  }

  // 6. HSTS
  if (opts.checkHsts) {
    log('fetching HSTS header…');
    base.hsts = await probeHsts(target, t);
  }

  base.durationMs = Date.now() - t0;
  log(`done in ${base.durationMs}ms`);
  return base;
}
