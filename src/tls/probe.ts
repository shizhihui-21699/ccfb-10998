/**
 * Connection-level probe: one TCP connection, one ClientHello, one ServerHello.
 *
 * Design constraints that matter for not knocking services over:
 *
 *   - Every probe is a *single* handshake that stops at ServerHello. We never
 *     complete the handshake, never send Finished, never send application data
 *     beyond the optional HSTS GET. Servers handle abandoned handshakes
 *     normally; this is the same traffic pattern as any client that hangs up.
 *   - Every connection has a hard deadline (socket timeout + destroy).
 *   - Calls to a single endpoint are serialized by the caller; the global
 *     concurrency limit lives in the scheduler, not here.
 *   - We never enable TLS-level renegotiation retries or retry storms; a
 *     failed probe is reported, not repeated.
 */
import net from 'node:net';
import crypto from 'node:crypto';
import {
  buildClientHello,
  parseServerHello,
  splitRecords,
  versionName,
  alertDescriptionName,
  CONTENT_TYPE,
  type ServerHello,
} from './hello.ts';
import type { ProbeFailure, ProbeFailureKind } from '../types.ts';

export interface HelloProbeOptions {
  host: string;
  port: number;
  legacyVersion: number;
  offerTls13: boolean;
  supportedVersions?: readonly number[];
  suites: readonly number[];
  serverName?: string;
  timeoutMs: number;
  requestStatus?: boolean;
  /** Offer ALPN protocols; the server's answer is on ServerHello but we only need it for HSTS. */
  alpn?: readonly string[];
  /** Send abort slightly more politely with a close_notify on early exit. */
  politeClose?: boolean;
  /** Extra bytes to read after ServerHello (only used by the HSTS probe). */
  keepOpen?: boolean;
}

export type HelloProbeResult =
  | { ok: true; serverHello: ServerHello; protocol: string }
  | { ok: false; failure: ProbeFailure };

/** Classifies a socket error into a failure kind. */
function classifySocketError(err: NodeJS.ErrnoException): ProbeFailure {
  const code = err.code ?? '';
  let kind: ProbeFailureKind = 'tls-error';
  switch (code) {
    case 'ECONNREFUSED':
      kind = 'refused';
      break;
    case 'ETIMEDOUT':
      kind = 'timeout';
      break;
    case 'ECONNRESET':
    case 'EPIPE':
      kind = 'reset';
      break;
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      kind = 'dns';
      break;
    default:
      if (/timeout/i.test(err.message)) kind = 'timeout';
  }
  return { kind, message: `${code || 'socket error'}: ${err.message}` };
}

/**
 * Opens a TCP connection to host:port, sends a ClientHello, and resolves with
 * the parsed ServerHello (or the failure). The socket is always destroyed.
 */
export function helloProbe(opts: HelloProbeOptions): Promise<HelloProbeResult> {
  return new Promise((resolve) => {
    let settled = false;
    let received: Buffer = Buffer.alloc(0);
    let sawAnyBytes = false;

    const sock = net.connect({ host: opts.host, port: opts.port });
    sock.setNoDelay(true);

    const cleanup = () => {
      clearTimeout(timer);
      sock.removeAllListeners();
      sock.destroy();
    };

    const finish = (result: HelloProbeResult) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    };

    const timer = setTimeout(() => {
      finish({ ok: false, failure: { kind: 'timeout', message: `no ServerHello within ${opts.timeoutMs}ms` } });
    }, opts.timeoutMs);
    // Deliberately not unref'd: this timer is what keeps a stalled probe from
    // letting the process exit.

    sock.on('connect', () => {
      sock.write(
        buildClientHello(
          {
            legacyVersion: opts.legacyVersion,
            suites: opts.suites,
            offerTls13: opts.offerTls13,
            supportedVersions: opts.supportedVersions,
            serverName: opts.serverName,
            offerRenegotiationInfo: true,
            requestStatus: opts.requestStatus,
            alpn: opts.alpn ?? ['h2', 'http/1.1'],
            sessionTicket: true,
          },
          crypto,
        ),
      );
    });

    sock.on('data', (chunk: Buffer) => {
      sawAnyBytes = true;
      received = Buffer.concat([received, chunk]);

      const { records, rest } = splitRecords(received);
      received = rest;

      for (const record of records) {
        if (record.contentType === CONTENT_TYPE.alert) {
          // Alert record: uint8 level, uint8 description.
          const description = record.data.length >= 2 ? record.data.readUInt8(1) : -1;
          finish({
            ok: false,
            failure: {
              kind: 'alert',
              alert: description,
              alertName: description >= 0 ? alertName(description) : undefined,
              message: description >= 0 ? `fatal alert ${alertName(description)} (${description})` : 'alert record without description',
            },
          });
          return;
        }
        if (record.contentType === CONTENT_TYPE.handshake) {
          const sh = parseServerHello(record.data);
          if (sh) {
            finish({ ok: true, serverHello: sh, protocol: versionName(sh.selectedVersion) });
            return;
          }
          // Handshake record that is not a ServerHello (e.g. HelloRequest):
          // keep reading. Our timeout covers the rest.
        }
      }
    });

    sock.on('error', (err: NodeJS.ErrnoException) => {
      finish({ ok: false, failure: classifySocketError(err) });
    });

    sock.on('end', () => {
      finish({
        ok: false,
        failure: {
          kind: sawAnyBytes ? 'closed' : 'closed',
          message: sawAnyBytes
            ? 'server closed the connection before sending a ServerHello'
            : 'server closed the connection without sending any bytes',
        },
      });
    });

    sock.on('close', () => {
      if (!settled) {
        finish({ ok: false, failure: { kind: 'closed', message: 'connection closed before ServerHello was received' } });
      }
    });
  });
}

/** Single source of truth for alert names lives in hello.ts. */
function alertName(n: number): string {
  return alertDescriptionName(n);
}

/**
 * Runs a full TLS session with node:tls long enough to read one HTTP response.
 * Used for HSTS, where we need the actual header bytes, and for OCSP stapling,
 * where node:tls emits the staple it received.
 *
 * node:tls is safe to use here despite its cipher restrictions: we only need
 * *a* successful handshake on a version the server supports, and HSTS/OCSP are
 * protocol-level facts that do not depend on which suite was chosen.
 */
export interface TlsSessionOptions {
  host: string;
  port: number;
  serverName?: string;
  minVersion?: string;
  maxVersion?: string;
  requestOCSP?: boolean;
  alpn?: string[];
  timeoutMs: number;
  rejectUnauthorized: boolean;
  caFile?: string;
  /** Bytes to write once connected (an HTTP request). */
  write?: string | Buffer;
  /** How long to collect a response after writing. */
  readMs?: number;
}

export interface TlsSessionResult {
  ok: boolean;
  protocol?: string;
  cipher?: string;
  /** Certificate chain as PEM list, leaf first. */
  chain?: string[];
  /** Stapled OCSP response, when the server sent one. */
  ocspResponse?: Buffer;
  /** ServerHello extension list, when exposed by the TLS stack. */
  serverHelloExtensions?: number[];
  /** Collected bytes from the peer. */
  data: Buffer;
  failure?: ProbeFailure;
}

export function tlsSession(opts: TlsSessionOptions): Promise<TlsSessionResult> {
  // Imported lazily so tests that only exercise the raw codec need not have
  // a working TLS stack.
  return import('node:tls').then(
    (tls) =>
      new Promise<TlsSessionResult>((resolve) => {
        const dataChunks: Buffer[] = [];
        let settled = false;
        let socket: import('node:tls').TLSSocket | undefined;
        let ocspResponse: Buffer | undefined;

        const finish = (r: Omit<TlsSessionResult, 'data'>) => {
          if (settled) return;
          settled = true;
          clearTimeout(deadline);
          socket?.destroy();
          const data = Buffer.concat(dataChunks);
          resolve({ ...r, data });
        };

        const deadline = setTimeout(() => {
          finish({ ok: false, data: Buffer.alloc(0), failure: { kind: 'timeout', message: `TLS session not established within ${opts.timeoutMs}ms` } } as Omit<TlsSessionResult, 'data'>);
        }, opts.timeoutMs);
        // Deliberately not unref'd: holds the event loop for a stalled session.

        try {
          socket = tls.connect(
            {
              host: opts.host,
              port: opts.port,
              servername: opts.serverName,
              minVersion: opts.minVersion as import('node:tls').SecureVersion | undefined,
              maxVersion: opts.maxVersion as import('node:tls').SecureVersion | undefined,
              requestOCSP: opts.requestOCSP ?? false,
              ALPNProtocols: opts.alpn,
              rejectUnauthorized: opts.rejectUnauthorized,
              ca: opts.caFile,
              // Probe-only: we want the handshake regardless of certificate
              // problems (the report records them separately).
              checkServerIdentity: () => undefined,
            },
            () => {
              const peer = socket!.getPeerCertificate(true);
              const chain: string[] = [];
              for (let c: typeof peer | undefined = peer; c && c.raw; c = c.issuerCertificate === c ? undefined : c.issuerCertificate) {
                chain.push(pemFromDer(c.raw));
                if (chain.length > 10) break;
              }
              const r: Omit<TlsSessionResult, 'data'> = {
                ok: true,
                protocol: socket!.getProtocol() ?? undefined,
                cipher: socket!.getCipher()?.name,
                chain,
                ocspResponse,
              };
              if (opts.write) {
                socket!.write(opts.write);
                setTimeout(() => finish(r), opts.readMs ?? 400);
              } else {
                finish(r);
              }
            },
          );

          socket.on('OCSPResponse', (resp: Buffer | null) => {
            // An empty buffer or null means the server did not staple.
            if (resp && resp.length > 0) ocspResponse = Buffer.from(resp);
          });

          socket.on('data', (d: Buffer) => dataChunks.push(d));
          socket.on('error', (err: NodeJS.ErrnoException) => {
            finish({ ok: false, failure: classifySocketError(err) });
          });
          socket.on('end', () => {
            finish({ ok: false, failure: { kind: 'closed', message: 'connection closed' } });
          });
          socket.on('close', () => {
            if (!settled) finish({ ok: false, failure: { kind: 'closed', message: 'connection closed before handshake completed' } });
          });
        } catch (err) {
          finish({ ok: false, failure: { kind: 'tls-error', message: (err as Error).message } });
        }
      }),
  );
}

function pemFromDer(der: Buffer): string {
  const b64 = der.toString('base64');
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}
