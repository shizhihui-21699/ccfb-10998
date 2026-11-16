/**
 * Target parsing: `host:port`, `https://host:port/path`, IPv6 literals,
 * and comma/whitespace-separated lists (or a target file with one per line).
 */
import { readFileSync } from "node:fs";
import type { Target } from "../types.ts";

export const DEFAULT_PORT = 443;

export class TargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetError";
  }
}

/**
 * Parse a single target spec.
 * Accepted forms: host, host:port, [v6]:port, scheme://host:port[/path].
 */
export function parseTarget(input: string, defaultPort = DEFAULT_PORT): Target {
  const raw = input.trim();
  if (raw.length === 0) throw new TargetError("empty target");

  // Reject things that clearly are not a single host:port (e.g. a stray URL
  // path is fine, but a whole list should be split first).
  let spec = raw;
  let port = defaultPort;

  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\/(.*)$/i.exec(spec);
  if (schemeMatch) {
    spec = schemeMatch[2]!;
    // Drop path/query/fragment; the probe only needs the authority.
    spec = spec.split(/[/?#]/)[0] ?? spec;
  }

  let host: string;
  if (spec.startsWith("[")) {
    // IPv6 literal: [::1]:443
    const end = spec.indexOf("]");
    if (end === -1) throw new TargetError(`unterminated IPv6 literal: ${raw}`);
    host = spec.slice(1, end);
    const rest = spec.slice(end + 1);
    if (rest.startsWith(":")) port = parsePort(rest.slice(1), raw);
    else if (rest.length > 0) throw new TargetError(`unexpected text after IPv6 literal: ${raw}`);
  } else {
    const lastColon = spec.lastIndexOf(":");
    const colonCount = (spec.match(/:/g) ?? []).length;
    if (lastColon !== -1 && colonCount === 1) {
      host = spec.slice(0, lastColon);
      port = parsePort(spec.slice(lastColon + 1), raw);
    } else {
      // No port, or a bare IPv6 address without brackets.
      host = spec;
    }
  }

  if (host.length === 0) throw new TargetError(`missing host in target: ${raw}`);
  if (/\s/.test(host)) throw new TargetError(`host contains whitespace: ${raw}`);

  return { host, port };
}

function parsePort(text: string, original: string): number {
  if (!/^\d+$/.test(text)) throw new TargetError(`invalid port in target: ${original}`);
  const port = Number(text);
  if (port < 1 || port > 65535) throw new TargetError(`port out of range in target: ${original}`);
  return port;
}

/** Split a comma/whitespace separated list into individual specs. */
export function splitTargetList(input: string): string[] {
  return input
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Read a targets file: one spec per line, `#` comments ignored. */
export function readTargetFile(path: string): string[] {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new TargetError(`cannot read targets file ${path}: ${(err as Error).message}`);
  }
  return text
    .split("\n")
    .map((line) => line.replace(/#.*$/, "").trim())
    .filter((line) => line.length > 0);
}

/** Parse many specs, returning parsed targets and per-line errors. */
export function parseTargets(
  specs: readonly string[],
  defaultPort = DEFAULT_PORT,
): { targets: Target[]; errors: Array<{ spec: string; error: string }> } {
  const targets: Target[] = [];
  const errors: Array<{ spec: string; error: string }> = [];
  const seen = new Set<string>();
  for (const spec of specs) {
    try {
      const target = parseTarget(spec, defaultPort);
      const key = `${target.host}:${target.port}`;
      if (seen.has(key)) continue; // de-duplicate silently
      seen.add(key);
      targets.push(target);
    } catch (err) {
      errors.push({ spec, error: (err as Error).message });
    }
  }
  return { targets, errors };
}
