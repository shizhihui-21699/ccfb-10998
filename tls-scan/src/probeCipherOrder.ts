import { CipherOrderResult, Target, TlsVersion } from './types';
import { handshake } from './connect';
import { Semaphore } from './util';

/**
 * Offer the same two ciphers in both orders. If the server picks the same
 * cipher both times it enforces its own preference; if the pick follows the
 * client's order, the client controls cipher selection.
 */
export async function probeCipherOrder(
  target: Target,
  version: TlsVersion,
  supportedOpensslNames: string[],
  limiter: Semaphore,
  timeoutMs: number,
): Promise<CipherOrderResult> {
  if (supportedOpensslNames.length < 2) {
    return { tested: false, detail: 'fewer than 2 supported ciphers, cannot test ordering' };
  }
  const [a, b] = supportedOpensslNames;
  const opts = { minVersion: version, maxVersion: version, timeoutMs } as const;
  const r1 = await handshake(target, { ...opts, ciphers: `${a}:${b}:@SECLEVEL=0` }, limiter);
  const r2 = await handshake(target, { ...opts, ciphers: `${b}:${a}:@SECLEVEL=0` }, limiter);
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
