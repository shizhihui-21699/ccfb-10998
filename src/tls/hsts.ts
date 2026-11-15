/**
 * HSTS header retrieval and parsing.
 *
 * HSTS is an HTTP-layer header, so we need an HTTP response from the same
 * origin. Two paths, tried in order:
 *
 *   1. Over the TLS connection we already know how to make: send a minimal
 *      `GET /` and read the first response head. This is the truthful check
 *      for "what does this service send on its TLS port".
 *   2. If that yields nothing and the caller configured a plain-HTTP port,
 *      fetch over HTTP. Plain HTTP still matters: a server that only sets
 *      HSTS on its HTTP redirect is doing it wrong, and we want to say so.
 *
 * Parsing follows RFC 6797 §6.1: max-age is required and must parse as a
 * non-negative integer; unknown directives are ignored; a repeated
 * Strict-Transport-Security header is invalid (browsers ignore the whole
 * header when duplicated).
 */
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import type { HstsResult, ProbeFailure } from '../types.ts';

export interface HstsOptions {
  host: string;
  port: number;
  serverName?: string;
  timeoutMs: number;
  /** Plain HTTP port to try when the TLS port yields no header. */
  httpPort?: number;
  rejectUnauthorized: boolean;
  caFile?: string;
}

const MAX_HEAD_BYTES = 32 * 1024;

/** Sends a minimal HTTP/1.1 GET over an existing TLS socket and returns the response head. */
function httpsHead(opts: HstsOptions): Promise<string | undefined> {
  return new Promise((resolve) => {
    let done = false;
    let socket: tls.TLSSocket | undefined;
    let buf = Buffer.alloc(0);

    // Two deadlines, because they answer different questions:
    //   - `timer`: how long to allow for the handshake itself.
    //   - `requestTimer`: once the handshake is up, how long to wait for an
    //     HTTP response. A TLS service that is not HTTP (Postgres, Redis, an
    //     LDAP listener) will happily hold the connection open and never
    //     answer, so waiting the full connection timeout per endpoint is
    //     wasted scan time multiplied by every non-HTTP target.
    let requestTimer: NodeJS.Timeout | undefined;

    const finish = (head: string | undefined) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (requestTimer) clearTimeout(requestTimer);
      socket?.destroy();
      resolve(head);
    };

    const HTTP_REPLY_TIMEOUT_MS = 1000;
    const timer = setTimeout(() => finish(undefined), opts.timeoutMs);

    try {
      socket = tls.connect(
        {
          host: opts.host,
          port: opts.port,
          servername: opts.serverName,
          rejectUnauthorized: false,
          checkServerIdentity: () => undefined,
          ALPNProtocols: ['http/1.1'],
          minVersion: 'TLSv1.2',
        },
        () => {
          const hostHeader = opts.serverName ?? opts.host;
          const req =
            `GET / HTTP/1.1\r\n` +
            `Host: ${hostHeader}\r\n` +
            `User-Agent: tls-checkup/1.0\r\n` +
            `Accept: */*\r\n` +
            `Connection: close\r\n\r\n`;
          socket!.write(req);
          // If no HTTP response arrives shortly, this is not an HTTP service.
          requestTimer = setTimeout(() => finish(undefined), HTTP_REPLY_TIMEOUT_MS);
        },
      );

      socket.on('data', (d: Buffer) => {
        buf = Buffer.concat([buf, d]);
        const headEnd = buf.indexOf('\r\n\r\n');
        if (headEnd !== -1) {
          finish(buf.subarray(0, headEnd).toString('latin1'));
        } else if (buf.length > MAX_HEAD_BYTES) {
          finish(undefined);
        }
      });
      socket.on('error', () => finish(undefined));
      socket.on('close', () => finish(buf.length ? buf.toString('latin1') : undefined));
    } catch {
      finish(undefined);
    }
  });
}

/** Fetches the response head over plain HTTP. */
function httpHead(opts: HstsOptions, port: number): Promise<{ head?: string; status?: number; failure?: ProbeFailure }> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (r: { head?: string; status?: number; failure?: ProbeFailure }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(r);
    };
    const timer = setTimeout(
      () => finish({ failure: { kind: 'timeout', message: `plain HTTP fetch timed out after ${opts.timeoutMs}ms` } }),
      opts.timeoutMs,
    );

    const req = http.request(
      {
        host: opts.host,
        port,
        path: '/',
        method: 'GET',
        headers: { Host: opts.serverName ?? opts.host, 'User-Agent': 'tls-checkup/1.0', Connection: 'close' },
        timeout: opts.timeoutMs,
      },
      (res) => {
        // We only need the headers; drop the body immediately.
        const parts: string[] = [`HTTP/${res.httpVersion} ${res.statusCode ?? 0} ${res.statusMessage ?? ''}`];
        for (const [k, v] of Object.entries(res.headers)) {
          if (Array.isArray(v)) for (const item of v) parts.push(`${k}: ${item}`);
          else if (v !== undefined) parts.push(`${k}: ${v}`);
        }
        res.destroy();
        finish({ head: parts.join('\r\n'), status: res.statusCode });
      },
    );
    req.on('error', (err: NodeJS.ErrnoException) =>
      finish({
        failure: {
          kind: err.code === 'ECONNREFUSED' ? 'refused' : err.code === 'ETIMEDOUT' ? 'timeout' : 'closed',
          message: `${err.code ?? 'error'}: ${err.message}`,
        },
      }),
    );
    req.on('timeout', () => {
      req.destroy();
      finish({ failure: { kind: 'timeout', message: 'plain HTTP request timed out' } });
    });
    req.end();
  });
}

interface ParsedHeaders {
  status: number;
  /** All Strict-Transport-Security values, in order. */
  sts: string[];
}

/** Parses an HTTP response head into status + HSTS header values. */
export function parseHttpHead(head: string): ParsedHeaders | undefined {
  const lines = head.split('\r\n');
  const statusLine = lines[0];
  if (!statusLine) return undefined;
  const m = statusLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/);
  if (!m) return undefined;
  const status = parseInt(m[1]!, 10);
  const sts: string[] = [];
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const name = line.slice(0, idx).trim().toLowerCase();
    if (name === 'strict-transport-security') {
      sts.push(line.slice(idx + 1).trim());
    }
  }
  return { status, sts };
}

export interface ParsedHsts {
  maxAge?: number;
  includeSubDomains: boolean;
  preload: boolean;
  problems: string[];
}

/** Parses one Strict-Transport-Security value per RFC 6797. */
export function parseHsts(value: string): ParsedHsts {
  const problems: string[] = [];
  let maxAge: number | undefined;
  let includeSubDomains = false;
  let preload = false;
  let sawMaxAge = false;

  for (const raw of value.split(';')) {
    const directive = raw.trim();
    if (!directive) continue;
    const eq = directive.indexOf('=');
    const name = (eq === -1 ? directive : directive.slice(0, eq)).trim().toLowerCase();
    const arg = eq === -1 ? '' : directive.slice(eq + 1).trim().replace(/^"(.*)"$/, '$1');

    if (name === 'max-age') {
      if (sawMaxAge) {
        problems.push('max-age appears more than once');
        continue;
      }
      sawMaxAge = true;
      if (!/^\d+$/.test(arg)) {
        problems.push(`max-age is not a non-negative integer: "${arg}"`);
      } else {
        maxAge = parseInt(arg, 10);
      }
    } else if (name === 'includesubdomains') {
      includeSubDomains = true;
    } else if (name === 'preload') {
      preload = true;
    }
    // Unknown directives are ignored per the RFC.
  }

  if (!sawMaxAge) problems.push('max-age directive is missing');
  return { maxAge, includeSubDomains, preload, problems };
}

/** Builds the HstsResult from one or more header values. */
function summarize(
  values: string[],
  status: number | undefined,
  source: HstsResult['source'],
): Omit<HstsResult, 'fetched'> {
  if (values.length === 0) {
    return {
      present: false,
      longMaxAge: false,
      includeSubDomains: false,
      preload: false,
      duplicates: false,
      problems: [],
      httpStatus: status,
      source,
    };
  }
  const parsed = parseHsts(values[0]!);
  const duplicates = values.length > 1;
  const problems = [...parsed.problems];
  if (duplicates) problems.push('the header appears more than once; browsers ignore duplicated HSTS headers');
  return {
    header: values.join(' | '),
    present: true,
    maxAge: parsed.maxAge,
    longMaxAge: (parsed.maxAge ?? 0) >= 31536000,
    includeSubDomains: parsed.includeSubDomains,
    preload: parsed.preload,
    duplicates,
    problems,
    httpStatus: status,
    source,
  };
}

/**
 * Retrieves and grades HSTS. Never throws: every failure becomes a
 * `fetched: false` result with a reason, so a dead HTTP port does not abort a
 * whole endpoint report.
 */
export async function probeHsts(opts: HstsOptions): Promise<HstsResult> {
  // 1. Try the TLS port first: that is what a browser actually talks to.
  const tlsHead = await httpsHead(opts);
  if (tlsHead) {
    const parsed = parseHttpHead(tlsHead);
    if (parsed) {
      const summary = summarize(parsed.sts, parsed.status, 'https-handshake');
      if (summary.present) return { fetched: true, ...summary };
      // A TLS response with no HSTS header is a definitive "not set" for this
      // origin, but we still try plain HTTP to catch redirect-only config.
    }
  }

  // 2. Fall back to plain HTTP when configured, to describe the full picture.
  if (opts.httpPort !== undefined) {
    const plain = await httpHead(opts, opts.httpPort);
    if (plain.head) {
      const parsed = parseHttpHead(plain.head);
      if (parsed) {
        const summary = summarize(parsed.sts, parsed.status, 'http-fetch');
        if (summary.present) return { fetched: true, ...summary };
        // Neither port set the header.
        return {
          fetched: true,
          present: false,
          longMaxAge: false,
          includeSubDomains: false,
          preload: false,
          duplicates: false,
          problems: [],
          httpStatus: parsed.status,
          source: 'http-fetch',
        };
      }
    }
    if (!tlsHead) {
      return {
        fetched: false,
        present: false,
        longMaxAge: false,
        includeSubDomains: false,
        preload: false,
        duplicates: false,
        problems: [],
        ...(plain.failure ? { failure: plain.failure } : {}),
      };
    }
  }

  if (tlsHead) {
    // TLS response arrived but had no parseable HSTS; report "not set".
    return {
      fetched: true,
      present: false,
      longMaxAge: false,
      includeSubDomains: false,
      preload: false,
      duplicates: false,
      problems: [],
      source: 'https-handshake',
    };
  }

  return {
    fetched: false,
    present: false,
    longMaxAge: false,
    includeSubDomains: false,
    preload: false,
    duplicates: false,
    problems: [],
    failure: { kind: 'timeout', message: 'no HTTP response over TLS and no plain-HTTP fallback configured' },
  };
}
