import tls from 'node:tls';
import { spawn } from 'node:child_process';
import { CipherEnumResult, CipherInfo, Target, TlsVersion } from './types';
import { handshake } from './connect';
import { Semaphore } from './util';

/**
 * Enumerate ciphers for TLS <= 1.2 with the classic elimination method:
 * offer all remaining candidates, record the one the server picks, remove
 * it, repeat until the handshake fails. Costs (supported + 1) connections
 * per version instead of one connection per candidate cipher.
 */
export async function enumerateCiphers(
  target: Target,
  version: Exclude<TlsVersion, 'TLSv1.3'>,
  limiter: Semaphore,
  timeoutMs: number,
): Promise<CipherEnumResult> {
  const candidates = [
    ...new Set(
      tls
        .getCiphers()
        .map((c) => c.toUpperCase())
        // TLS 1.3 suites (TLS_AES_...) cannot be set via the `ciphers` option.
        .filter((c) => !c.startsWith('TLS_')),
    ),
  ];
  const remaining = [...candidates];
  const supported: CipherInfo[] = [];

  for (let i = 0; i < candidates.length + 2 && remaining.length > 0; i++) {
    const r = await handshake(
      target,
      {
        minVersion: version,
        maxVersion: version,
        ciphers: remaining.join(':') + ':@SECLEVEL=0',
        timeoutMs,
      },
      limiter,
    );
    if (!r.ok) break;
    supported.push({ opensslName: r.cipherName, standardName: r.standardName });
    const idx = remaining.findIndex((c) => c === r.cipherName.toUpperCase());
    if (idx === -1) break; // negotiated something we did not offer (shouldn't happen)
    remaining.splice(idx, 1);
  }
  return { version, ciphers: supported, source: 'elimination' };
}

const TLS13_SUITES = [
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',
  'TLS_AES_128_GCM_SHA256',
  'TLS_AES_128_CCM_SHA256',
  'TLS_AES_128_CCM_8_SHA256',
];

let opensslOk: boolean | null = null;

function opensslVersion(): Promise<string | null> {
  return new Promise((resolve) => {
    const p = spawn('openssl', ['version'], { stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '';
    p.stdout.on('data', (d) => (out += d));
    p.on('error', () => resolve(null));
    p.on('close', () => resolve(out.trim() || null));
  });
}

async function hasOpensslCli(): Promise<boolean> {
  if (opensslOk !== null) return opensslOk;
  const v = await opensslVersion();
  // need OpenSSL >= 1.1.1 for -ciphersuites / TLS 1.3
  opensslOk = !!v && /OpenSSL (1\.1\.1|[2-9]\.)/i.test(v);
  return opensslOk;
}

function sClientNegotiatedSuite(target: Target, suites: string[], timeoutMs: number): Promise<string | null> {
  return new Promise((resolve) => {
    const args = [
      's_client',
      '-connect',
      `${target.host}:${target.port}`,
      '-tls1_3',
      '-ciphersuites',
      suites.join(':'),
      '-brief',
    ];
    const sni = target.servername ?? target.host;
    if (sni) args.push('-servername', sni);
    const p = spawn('openssl', args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let settled = false;
    const done = (v: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        p.kill();
      } catch {
        /* ignore */
      }
      resolve(v);
    };
    const timer = setTimeout(() => done(null), timeoutMs + 2000);
    p.stdout.on('data', (d) => {
      out += d;
      const m = out.match(/Ciphersuite:\s*(\S+)/) ?? out.match(/Cipher is\s*(\S+)/);
      if (m) done(m[1]);
    });
    p.stderr.on('data', (d) => {
      out += d;
    });
    p.on('error', () => done(null));
    p.on('close', () => {
      const m = out.match(/Ciphersuite:\s*(\S+)/) ?? out.match(/Cipher is\s*(\S+)/);
      done(m ? m[1] : null);
    });
    // 'Q' makes s_client quit right after the handshake instead of hanging on stdin
    p.stdin.write('Q\n');
    p.stdin.end();
  });
}

/**
 * TLS 1.3 cipher enumeration. Node's tls API cannot restrict TLS 1.3
 * ciphersuites per connection, so we shell out to `openssl s_client` with
 * the same elimination method when a suitable CLI is available. Otherwise
 * we report only the suite negotiated during version probing.
 */
export async function enumerateTls13(
  target: Target,
  negotiatedCipher: string | undefined,
  timeoutMs: number,
): Promise<CipherEnumResult> {
  if (await hasOpensslCli()) {
    const remaining = [...TLS13_SUITES];
    const supported: CipherInfo[] = [];
    while (remaining.length > 0) {
      const picked = await sClientNegotiatedSuite(target, remaining, timeoutMs);
      if (!picked) break;
      const idx = remaining.findIndex((s) => s === picked);
      if (idx === -1) break;
      supported.push({ opensslName: picked, standardName: picked });
      remaining.splice(idx, 1);
    }
    if (supported.length > 0) return { version: 'TLSv1.3', ciphers: supported, source: 'openssl-cli' };
  }
  return {
    version: 'TLSv1.3',
    ciphers: negotiatedCipher ? [{ opensslName: negotiatedCipher, standardName: negotiatedCipher }] : [],
    source: 'negotiated-only',
    note: 'TLS 1.3 suite enumeration needs the openssl CLI (>=1.1.1); only the negotiated suite is shown',
  };
}
