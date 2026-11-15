import { ALL_VERSIONS, Target, VersionProbe } from './types';
import { handshake } from './connect';
import { mapPool, Semaphore } from './util';

/** Probe each protocol version by pinning minVersion=maxVersion. */
export async function probeVersions(
  target: Target,
  limiter: Semaphore,
  timeoutMs: number,
): Promise<VersionProbe[]> {
  return mapPool(ALL_VERSIONS, 2, async (v) => {
    const r = await handshake(
      target,
      {
        minVersion: v,
        maxVersion: v,
        // SECLEVEL=0 lets our client offer legacy ciphers so an old server
        // has the best chance to complete the handshake.
        ciphers: v === 'TLSv1.3' ? undefined : 'ALL:COMPLEMENTOFALL:@SECLEVEL=0',
        timeoutMs,
      },
      limiter,
    );
    return {
      version: v,
      supported: r.ok,
      error: r.ok ? undefined : r.error,
      negotiatedCipher: r.ok ? r.standardName ?? r.cipherName : undefined,
    };
  });
}
