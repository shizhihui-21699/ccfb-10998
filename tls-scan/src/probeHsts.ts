import net from 'node:net';
import tls from 'node:tls';
import { HstsResult, Target } from './types';

function parseHstsHeader(raw: string): HstsResult {
  const head = raw.split('\r\n\r\n', 1)[0];
  if (!/^HTTP\/\d/.test(head)) return { present: false, nonHttp: true };
  const lines = head.split('\r\n');
  const h = lines.find((l) => /^strict-transport-security\s*:/i.test(l));
  if (!h) return { present: false };
  const value = h.slice(h.indexOf(':') + 1).trim();
  const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(value)?.[1];
  return {
    present: true,
    maxAge: maxAge !== undefined ? Number(maxAge) : undefined,
    includeSubDomains: /includesubdomains/i.test(value),
    preload: /preload/i.test(value),
    raw: value,
  };
}

/** Best-effort HTTP/1.1 GET over TLS to inspect the Strict-Transport-Security header. */
export function probeHsts(target: Target, timeoutMs: number): Promise<HstsResult> {
  return new Promise((resolve) => {
    let raw = '';
    let settled = false;
    const done = (r: HstsResult) => {
      if (settled) return;
      settled = true;
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
      resolve(r);
    };
    const sock = tls.connect({
      host: target.host,
      port: target.port,
      servername: target.servername ?? (net.isIP(target.host) ? undefined : target.host),
      rejectUnauthorized: false,
    });
    sock.setTimeout(timeoutMs, () =>
      done(raw.length > 0 ? parseHstsHeader(raw) : { present: false, nonHttp: true }),
    );
    sock.once('error', () =>
      done(raw.length > 0 ? parseHstsHeader(raw) : { present: false, nonHttp: true }),
    );
    sock.once('secureConnect', () => {
      const host = target.servername ?? target.host;
      sock.write(
        `GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: tls-scan/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
      );
    });
    sock.on('data', (d) => {
      raw += d.toString('latin1');
      if (raw.includes('\r\n\r\n') || raw.length > 16384) done(parseHstsHeader(raw));
    });
    sock.on('close', () =>
      done(raw.length > 0 ? parseHstsHeader(raw) : { present: false, nonHttp: true }),
    );
  });
}
