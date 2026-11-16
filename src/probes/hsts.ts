/**
 * HSTS header inspection.
 *
 * HSTS is delivered in the HTTP response, not in TLS itself, so this makes one
 * HTTPS request (GET /, HTTP/1.1) over a verified-or-not TLS connection and
 * reads the Strict-Transport-Security header. We parse max-age,
 * includeSubDomains and preload per RFC 6797.
 *
 * A response served over HTTP (not HTTPS) is flagged: HSTS only takes effect
 * when delivered over a secure transport, and browsers ignore it otherwise.
 */
import tls from "node:tls";
import { isIpLiteral } from "./protocols.ts";
import type {
  HstsProbe,
  ProbeStats,
  ProtocolProbe,
  Target,
} from "../types.ts";

export interface HstsOptions {
  /** Request path. */
  path?: string;
  /** Overall request timeout. */
  timeoutMs?: number;
}

export const HSTS_HEADER = "strict-transport-security";

export interface ParsedHsts {
  maxAge?: number;
  includeSubDomains: boolean;
  preload: boolean;
  /** Problem found while parsing, if any. */
  error?: string;
}

/**
 * Parse an HSTS header value. Follows RFC 6797 §6.1: directives are
 * case-insensitive, `max-age` is required, and unknown directives are ignored.
 */
export function parseHstsHeader(raw: string | undefined): ParsedHsts {
  const out: ParsedHsts = { includeSubDomains: false, preload: false };
  if (raw === undefined) return out;
  const directives = raw.split(";").map((d) => d.trim()).filter((d) => d.length > 0);
  let sawMaxAge = false;
  for (const directive of directives) {
    const eq = directive.indexOf("=");
    const name = (eq === -1 ? directive : directive.slice(0, eq)).trim().toLowerCase();
    const value = eq === -1 ? undefined : directive.slice(eq + 1).trim();
    if (name === "max-age") {
      if (value === undefined || !/^\d+$/.test(value)) {
        out.error = `invalid max-age value: ${value ?? "(missing)"}`;
        continue;
      }
      sawMaxAge = true;
      out.maxAge = Number(value);
    } else if (name === "includesubdomains") {
      out.includeSubDomains = true;
    } else if (name === "preload") {
      out.preload = true;
    }
  }
  if (!sawMaxAge && out.error === undefined) out.error = "missing max-age directive";
  return out;
}

interface HttpResult {
  responded: boolean;
  statusCode?: number;
  headers?: Record<string, string>;
  error?: string;
}

/** Issue one HTTP/1.1 GET over TLS and collect the response head. */
function httpsHead(
  endpoints: { host: string; port: number },
  servername: string | undefined,
  path: string,
  timeoutMs: number,
): Promise<HttpResult> {
  return new Promise((resolve) => {
    let settled = false;
    let buffer = Buffer.alloc(0);
    const socket = tls.connect({
      host: endpoints.host,
      port: endpoints.port,
      ...(servername ? { servername } : {}),
      rejectUnauthorized: false,
      // A permissive ALPN so we speak HTTP/1.1 regardless of server support.
      ALPNProtocols: ["http/1.1"],
    });
    const finish = (r: HttpResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      resolve(r);
    };
    const timer = setTimeout(() => finish({ responded: false, error: "HTTP timeout" }), timeoutMs);

    socket.once("secureConnect", () => {
      const host = servername ?? endpoints.host;
      socket.write(
        `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: tls-doctor\r\nAccept: */*\r\nConnection: close\r\n\r\n`,
      );
    });
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      const headEnd = buffer.indexOf("\r\n\r\n");
      if (headEnd === -1) return;
      const text = buffer.subarray(0, headEnd).toString("latin1");
      const lines = text.split("\r\n");
      const statusLine = lines.shift() ?? "";
      const m = /^HTTP\/\d\.\d\s+(\d{3})/.exec(statusLine);
      const headers: Record<string, string> = {};
      for (const line of lines) {
        const idx = line.indexOf(":");
        if (idx === -1) continue;
        const name = line.slice(0, idx).trim().toLowerCase();
        const value = line.slice(idx + 1).trim();
        // Keep the first occurrence, which is what browsers act on.
        if (!(name in headers)) headers[name] = value;
      }
      finish({ responded: true, statusCode: m ? Number(m[1]) : undefined, headers });
    });
    socket.once("error", (err: Error) => finish({ responded: false, error: err.message }));
  });
}

export async function probeHsts(
  target: Target,
  protocols: ProtocolProbe,
  stats: ProbeStats,
  options: HstsOptions = {},
): Promise<HstsProbe> {
  const timeoutMs = options.timeoutMs ?? 8_000;
  const path = options.path ?? "/";

  if (protocols.supported.length === 0) {
    return { httpResponded: null, present: null, reason: "no TLS — cannot deliver HSTS" };
  }

  const servername = target.serverName ?? (isIpLiteral(target.host) ? undefined : target.host);
  const result = await httpsHead({ host: target.host, port: target.port }, servername, path, timeoutMs);
  stats.connections += 1;

  if (!result.responded) {
    return {
      httpResponded: false,
      present: null,
      ...(result.error ? { error: result.error } : {}),
      reason: "no HTTP response to inspect",
    };
  }

  const raw = result.headers?.[HSTS_HEADER];
  const parsed = parseHstsHeader(raw);
  return {
    httpResponded: true,
    ...(result.statusCode !== undefined ? { statusCode: result.statusCode } : {}),
    present: raw !== undefined,
    ...(parsed.maxAge !== undefined ? { maxAge: parsed.maxAge } : {}),
    ...(raw !== undefined ? { includeSubDomains: parsed.includeSubDomains } : {}),
    ...(raw !== undefined ? { preload: parsed.preload } : {}),
    ...(raw !== undefined ? { raw } : {}),
    ...(parsed.error ? { reason: parsed.error } : {}),
  };
}
