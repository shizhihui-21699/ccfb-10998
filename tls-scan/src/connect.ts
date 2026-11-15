import net from 'node:net';
import tls from 'node:tls';
import { Target } from './types';
import { Semaphore } from './util';

export interface HandshakeOk {
  ok: true;
  cipherName: string;      // OpenSSL name, e.g. ECDHE-RSA-AES128-GCM-SHA256
  standardName?: string;   // IANA name, e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  protocol: string | null; // negotiated protocol, e.g. TLSv1.2
  ocsp?: Buffer;
  cert?: tls.PeerCertificate;
}

export interface HandshakeFail {
  ok: false;
  error: string;
}

export type HandshakeResult = HandshakeOk | HandshakeFail;

export interface ProbeOptions {
  minVersion?: tls.SecureVersion;
  maxVersion?: tls.SecureVersion;
  ciphers?: string;
  requestOCSP?: boolean;
  timeoutMs: number;
}

function normalizeErr(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (/sslv3 alert handshake failure|tlsv1 alert protocol version|handshake failure/i.test(msg))
    return 'handshake failure (no common protocol/cipher)';
  if (/no ciphers available/i.test(msg)) return 'no ciphers available';
  if (/unsupported protocol/i.test(msg)) return 'unsupported protocol';
  if (/wrong version number/i.test(msg)) return 'wrong version number (not a TLS service?)';
  if (/ECONNREFUSED/.test(msg)) return 'connection refused';
  if (/ECONNRESET/.test(msg)) return 'connection reset';
  if (/ETIMEDOUT|timeout/i.test(msg)) return 'timeout';
  if (/certificate/i.test(msg)) return `certificate error: ${msg}`;
  return msg.split('\n')[0];
}

/** One TLS handshake. Socket is always destroyed before the promise settles. */
export async function handshake(
  target: Target,
  opts: ProbeOptions,
  limiter?: Semaphore,
): Promise<HandshakeResult> {
  if (limiter) await limiter.acquire();
  try {
    return await doHandshake(target, opts);
  } finally {
    if (limiter) limiter.release();
  }
}

function doHandshake(target: Target, opts: ProbeOptions): Promise<HandshakeResult> {
  return new Promise((resolve) => {
    let settled = false;
    let sock: tls.TLSSocket | undefined;
    const done = (r: HandshakeResult) => {
      if (settled) return;
      settled = true;
      try {
        sock?.destroy();
      } catch {
        /* ignore */
      }
      resolve(r);
    };

    try {
      const connOpts: tls.ConnectionOptions & { requestOCSP?: boolean } = {
        host: target.host,
        port: target.port,
        servername: target.servername ?? (net.isIP(target.host) ? undefined : target.host),
        rejectUnauthorized: false, // we are probing configuration, not validating trust
        minVersion: opts.minVersion,
        maxVersion: opts.maxVersion,
        ciphers: opts.ciphers,
        requestOCSP: opts.requestOCSP,
      };
      sock = tls.connect(connOpts);
    } catch (e) {
      resolve({ ok: false, error: normalizeErr(e) });
      return;
    }

    sock.setTimeout(opts.timeoutMs, () => done({ ok: false, error: 'timeout' }));
    sock.once('error', (e) => done({ ok: false, error: normalizeErr(e) }));
    // the stapled OCSP response arrives as an event before secureConnect
    let ocsp: Buffer | undefined;
    sock.once('OCSPResponse' as never, (r: Buffer) => {
      ocsp = r ?? undefined;
    });
    sock.once('secureConnect', () => {
      const c = sock!.getCipher();
      let cert: tls.PeerCertificate | undefined;
      try {
        cert = sock!.getPeerCertificate();
      } catch {
        /* ignore */
      }
      done({
        ok: true,
        cipherName: c?.name ?? '',
        standardName: (c as { standardName?: string } | null)?.standardName,
        protocol: sock!.getProtocol(),
        ocsp,
        cert,
      });
    });
  });
}
