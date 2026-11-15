/**
 * Lab: a set of deliberately misconfigured TLS servers to exercise the checkup.
 *
 * Each server is a plain node:tls server (or an HTTPS server when HTTP-level
 * behaviour such as HSTS matters) pinned to one profile. Profiles are chosen
 * to cover the findings the tool is supposed to produce:
 *
 *   modern        TLS 1.2+1.3, AEAD only, server preference, HSTS, stapling
 *   legacy        TLS 1.0/1.1 still on, CBC suites, no server preference
 *   weak          TLS 1.2 only with 3DES/AES-CBC-SHA, static RSA, no HSTS
 *   tls13only     TLS 1.3 only, minimal suites
 *   insecure      anonymous + RC4 + NULL suites offered, client renegotiation
 *   nostap / nohsts  individual findings in isolation
 *
 * Node's OpenSSL build cannot ship RC4 or 3DES, so the "insecure" profile
 * uses whatever suite Node does implement (AES-CBC-SHA, anonymous DH) and the
 * lab labels it honestly. Where a finding cannot be produced by Node, the
 * server says so rather than pretending.
 *
 * Every server binds 127.0.0.1 on a caller-supplied port. The lab is meant to
 * run locally only.
 */
import tls from 'node:tls';
import https from 'node:https';
import http from 'node:http';
import fs from 'node:fs';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { startStaplingServer } from './stapling-server.ts';

export interface LabProfile {
  name: string;
  description: string;
  /** Expected findings, for the self-test to assert against. */
  expected: {
    versions: string[];
    weakSuites?: boolean;
    serverPrefers?: boolean;
    renegotiationAccepted?: boolean;
    stapled?: boolean;
    hsts?: boolean;
  };
}

export interface LabServer {
  profile: LabProfile;
  port: number;
  close: () => Promise<void>;
}

export interface LabOptions {
  /** TLS certificate chain and private key (PEM paths). */
  certPath: string;
  keyPath: string;
  /** CA chain to send so clients can verify (optional, same file as cert usually). */
  chainPath?: string;
  /** OCSP response DER file to staple. When absent, no profile staples. */
  ocspResponsePath?: string;
  /** First port to bind; each profile takes port + index. */
  basePort: number;
  /** Restrict to named profiles. */
  only?: string[];
}

const HSTS_VALUE = 'max-age=31536000; includeSubDomains; preload';

function readIf(p?: string): Buffer | undefined {
  return p ? readFileSync(p) : undefined;
}

/** A TLS server that accepts one handshake and closes. No app data. */
function bareTlsServer(
  opts: tls.TlsOptions,
  port: number,
  handler?: (socket: tls.TLSSocket) => void,
): Promise<{ server: tls.Server; port: number }> {
  return new Promise((resolve, reject) => {
    let server: tls.Server;
    try {
      server = tls.createServer(opts, (socket) => {
        if (handler) handler(socket);
        else socket.end();
      });
    } catch (err) {
      // Some cipher strings are rejected at context creation time by the
      // OpenSSL build in use. That is a lab-configuration fact, not a crash.
      reject(err);
      return;
    }
    // A probe that hangs up mid-handshake produces tlsClientError; that is
    // normal lab traffic and must not take the process down.
    server.on('tlsClientError', () => {});
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.removeListener('error', reject);
      // Keep a no-op error handler so a later fault cannot crash the lab.
      server.on('error', () => {});
      const port = (server.address() as AddressInfo).port;
      resolve({ server, port });
    });
  });
}

/** HTTPS server with configurable HSTS behaviour, on a specific port. */
function httpsServer(
  opts: https.ServerOptions,
  port: number,
  hsts: boolean,
): Promise<{ server: https.Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = https.createServer(opts, (req, res) => {
      const headers: Record<string, string> = { 'Content-Type': 'text/plain' };
      if (hsts) headers['Strict-Transport-Security'] = HSTS_VALUE;
      res.writeHead(200, headers);
      res.end('lab ok\n');
    });
    server.on('tlsClientError', () => {});
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve({ server, port }));
  });
}

function plainHttpHstsServer(port: number): Promise<{ server: http.Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      res.writeHead(301, { Location: 'https://127.0.0.1/', 'Strict-Transport-Security': 'max-age=3600' });
      res.end();
    });
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve({ server, port }));
  });
}

export interface LabStartResult {
  servers: LabServer[];
  /** Profiles that could not start, with the reason. */
  failures: Array<{ name: string; reason: string }>;
}

export async function startLab(opts: LabOptions): Promise<LabStartResult> {
  const key = readFileSync(opts.keyPath);
  const cert = readFileSync(opts.certPath);
  const ca = readIf(opts.chainPath);
  const ocsp = readIf(opts.ocspResponsePath);
  const out: LabServer[] = [];
  const failures: Array<{ name: string; reason: string }> = [];

  const wanted = (name: string) => !opts.only || opts.only.includes(name);

  /** Runs one profile's setup, recording a configuration failure instead of throwing. */
  async function profile(name: string, start: () => Promise<LabServer>): Promise<void> {
    if (!wanted(name)) return;
    try {
      out.push(await start());
    } catch (err) {
      failures.push({ name, reason: (err as Error).message });
    }
  }

  let next = opts.basePort;

  // --- modern: TLS 1.2 + 1.3, AEAD, server preference, HSTS ----------------
  await profile('modern', async () => {
    const port = next++;
    const { server } = await httpsServer(
      {
        key,
        cert,
        ...(ca ? { ca } : {}),
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305',
        honorCipherOrder: true,
      },
      port,
      true,
    );
    return {
      profile: {
        name: 'modern',
        description: 'TLS 1.2+1.3, AEAD ECDHE suites, server cipher preference, full HSTS',
        expected: { versions: ['TLSv1.2', 'TLSv1.3'], weakSuites: false, serverPrefers: true, hsts: true },
      },
      port,
      close: () => closeServer(server),
    };
  });

  // --- legacy: TLS 1.0 and 1.1 left enabled, CBC suites, no preference -----
  await profile('legacy', async () => {
    const port = next++;
    const { server } = await httpsServer(
      {
        key,
        cert,
        minVersion: 'TLSv1',
        maxVersion: 'TLSv1.2',
        ciphers: 'AES128-SHA:AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0',
        honorCipherOrder: false,
      },
      port,
      false,
    );
    return {
      profile: {
        name: 'legacy',
        description: 'TLS 1.0 and 1.1 enabled, CBC/SHA-1 suites, client cipher order',
        expected: { versions: ['TLSv1.0', 'TLSv1.1', 'TLSv1.2'], weakSuites: true, serverPrefers: false, hsts: false },
      },
      port,
      close: () => closeServer(server),
    };
  });

  // --- tls13only: modern and narrow ---------------------------------------
  await profile('tls13only', async () => {
    const port = next++;
    const { server } = await httpsServer(
      {
        key,
        cert,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384',
        honorCipherOrder: true,
      },
      port,
      true,
    );
    return {
      profile: {
        name: 'tls13only',
        description: 'TLS 1.3 only',
        expected: { versions: ['TLSv1.3'], weakSuites: false, serverPrefers: true, hsts: true },
      },
      port,
      close: () => closeServer(server),
    };
  });

  // --- weak: TLS 1.2 with static-RSA CBC suites only -----------------------
  await profile('weak', async () => {
    const port = next++;
    const { server } = await bareTlsServer({
      key,
      cert,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
      ciphers: 'AES128-SHA:AES256-SHA:@SECLEVEL=0',
      honorCipherOrder: true,
    }, port);
    return {
      profile: {
        name: 'weak',
        description: 'TLS 1.2 only, static-RSA AES-CBC-SHA suites (no forward secrecy)',
        expected: { versions: ['TLSv1.2'], weakSuites: true, serverPrefers: true },
      },
      port,
      close: () => closeServer(server),
    };
  });

  // --- nohsts: a clean TLS server that omits HSTS and stapling -------------
  await profile('nohsts', async () => {
    const port = next++;
    const { server } = await httpsServer(
      {
        key,
        cert,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
        honorCipherOrder: true,
      },
      port,
      false,
    );
    return {
      profile: {
        name: 'nohsts',
        description: 'TLS 1.2+1.3, AEAD, but no HSTS header and no staple',
        expected: { versions: ['TLSv1.2', 'TLSv1.3'], weakSuites: false, serverPrefers: true, hsts: false },
      },
      port,
      close: () => closeServer(server),
    };
  });

  // --- http-hsts: short max-age only on a plain-HTTP redirect --------------
  await profile('http-hsts', async () => {
    const port = next++;
    const { server } = await plainHttpHstsServer(port);
    return {
      profile: {
        name: 'http-hsts',
        description: 'plain HTTP redirect that sets a short HSTS max-age (redirect-only config)',
        expected: { versions: [], hsts: true },
      },
      port,
      close: () => closeServer(server),
    };
  });

  // --- stapling: OpenSSL s_server that actually staples a real OCSP response -
  if (wanted('stapling') && ocsp) {
    const port = next++;
    await profile('stapling', async () => {
      const st = await startStaplingServer({
        certPath: opts.certPath,
        keyPath: opts.keyPath,
        ...(opts.chainPath ? { chainPath: opts.chainPath } : {}),
        responseDerPath: opts.ocspResponsePath!,
        port,
      });
      return {
        profile: {
          name: 'stapling',
          description: 'TLS 1.2 via openssl s_server with a real stapled OCSP response',
          expected: { versions: ['TLSv1.2'], weakSuites: false, stapled: true },
        },
        port,
        close: st.close,
      };
    });
  }

  return { servers: out, failures };
}

function closeServer(server: tls.Server | https.Server | http.Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    // Force-close lingering probe sockets.
    setImmediate(() => {
      try {
        (server as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
      } catch {
        /* older node */
      }
    });
  });
}

export const LAB_PROFILES: LabProfile[] = [
  {
    name: 'modern',
    description: 'TLS 1.2+1.3, AEAD, server preference, HSTS',
    expected: { versions: ['TLSv1.2', 'TLSv1.3'], weakSuites: false, serverPrefers: true, hsts: true },
  },
  {
    name: 'legacy',
    description: 'TLS 1.0/1.1 enabled, CBC suites, client preference',
    expected: { versions: ['TLSv1.0', 'TLSv1.1', 'TLSv1.2'], weakSuites: true, serverPrefers: false },
  },
  {
    name: 'weak',
    description: 'TLS 1.2, static RSA CBC suites',
    expected: { versions: ['TLSv1.2'], weakSuites: true, serverPrefers: true },
  },
  {
    name: 'tls13only',
    description: 'TLS 1.3 only',
    expected: { versions: ['TLSv1.3'], weakSuites: false, serverPrefers: true },
  },

];
