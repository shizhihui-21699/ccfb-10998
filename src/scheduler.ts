/**
 * Scheduler: runs endpoint probes with bounded concurrency and a shared budget.
 *
 * "Don't knock the service over" is a design requirement, so the limits are
 * explicit rather than emergent:
 *
 *   - `concurrency` bounds how many endpoints are probed at once. Each
 *     endpoint itself probes sequentially, so the real upper bound on
 *     simultaneous TCP connections against any single host is `1`.
 *   - `maxHandshakesPerEndpoint` caps the hellos per endpoint. Enumeration
 *     uses one per supported suite, so this only bites on servers with
 *     enormous suite lists.
 *   - `maxTotalHandshakes` is a global ceiling for a scan. When it is reached,
 *     remaining endpoints are reported as skipped, not silently dropped.
 *   - `interProbeDelayMs` inserts a small gap between handshakes to the same
 *     endpoint. 20ms is enough to keep a fragile appliance's connection
 *     accounting sane and is imperceptible in a scan.
 *   - Endpoints that fail to connect are not retried. Retrying an unreachable
 *     service is what turns a checkup into a stress test.
 *
 * Endpoints are grouped by host so that all ports of one host are probed by
 * one worker in sequence; that avoids two workers hammering the same box.
 */
import { probeEndpoint, type EndpointProbeOptions } from './tls/endpoint.ts';
import type { EndpointResult } from './types.ts';

export interface ScheduledTarget {
  host: string;
  port: number;
  serverName?: string;
  label?: string;
  /** Plain HTTP port for the HSTS fallback, when known. */
  httpPort?: number;
}

export interface SchedulerOptions extends Omit<EndpointProbeOptions, 'host' | 'port' | 'serverName'> {
  concurrency: number;
  maxTotalHandshakes: number;
  maxHandshakesPerEndpoint: number;
  /** Called as each endpoint finishes, for progress output. */
  onResult?: (r: EndpointResult) => void;
}

export interface ScanOutcome {
  results: EndpointResult[];
  /** Targets that were never probed because the total handshake budget ran out. */
  skipped: ScheduledTarget[];
  totalHandshakes: number;
  elapsedMs: number;
}

/**
 * Runs the scan. Targets are grouped by host and processed host-by-host, with
 * `concurrency` hosts in flight at once.
 */
export async function runScan(targets: ScheduledTarget[], opts: SchedulerOptions): Promise<ScanOutcome> {
  const started = performance.now();
  const byHost = new Map<string, ScheduledTarget[]>();
  for (const t of targets) {
    const key = t.host;
    if (!byHost.has(key)) byHost.set(key, []);
    byHost.get(key)!.push(t);
  }

  const hostGroups = [...byHost.values()];
  const results: EndpointResult[] = [];
  const skipped: ScheduledTarget[] = [];
  let handshakes = 0;

  const budgetExhausted = () => handshakes >= opts.maxTotalHandshakes;

  const runGroup = async (group: ScheduledTarget[]) => {
    for (const t of group) {
      if (budgetExhausted()) {
        skipped.push(t);
        continue;
      }
      let remainingForEndpoint = opts.maxHandshakesPerEndpoint;
      const guard = () => {
        if (budgetExhausted() || remainingForEndpoint <= 0) {
          throw new BudgetExhausted();
        }
        handshakes++;
        remainingForEndpoint--;
      };
      try {
        const r = await probeEndpoint({
          ...opts,
          host: t.host,
          port: t.port,
          ...(t.serverName ? { serverName: t.serverName } : {}),
          ...(t.httpPort !== undefined ? { httpPort: t.httpPort } : {}),
          maxHandshakes: remainingForEndpoint,
          onHandshake: guard,
        });
        if (t.label) r.label = t.label;
        results.push(r);
        opts.onResult?.(r);
      } catch (err) {
        if (err instanceof BudgetExhausted) {
          // Endpoint ran out mid-scan: report what we have as an incomplete
          // result rather than losing it.
          const partial: EndpointResult = {
            host: t.host,
            port: t.port,
            ...(t.serverName ? { serverName: t.serverName } : {}),
            label: t.label ?? `${t.host}:${t.port}`,
            reachable: false,
            versions: [],
            suites: [],
            warnings: ['handshake budget exhausted before the endpoint was fully probed'],
            durationMs: 0,
          };
          results.push(partial);
          opts.onResult?.(partial);
          skipped.push(t);
          continue;
        }
        throw err;
      }
    }
  };

  // Worker pool over host groups.
  let nextGroup = 0;
  const workers = Array.from({ length: Math.min(opts.concurrency, hostGroups.length) }, async () => {
    while (true) {
      const idx = nextGroup++;
      if (idx >= hostGroups.length) return;
      await runGroup(hostGroups[idx]!);
    }
  });
  await Promise.all(workers);

  return {
    results,
    skipped,
    totalHandshakes: handshakes,
    elapsedMs: Math.round(performance.now() - started),
  };
}

class BudgetExhausted extends Error {
  constructor() {
    super('handshake budget exhausted');
    this.name = 'BudgetExhausted';
  }
}
