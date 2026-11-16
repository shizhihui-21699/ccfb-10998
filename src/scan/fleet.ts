/**
 * Fleet-level scanning: many hosts, bounded parallelism.
 *
 * Each host is scanned by its own `scanHost` (whose probes are sequential and
 * paced). Here we cap how many *hosts* are in flight at once, so a scan of 200
 * services never means 200 simultaneous connections to any one of them, nor a
 * thundering herd across the fleet.
 */
import { scanHost, type HostScanOptions, type HostResult } from "../probes/host.ts";
import type { Target } from "../types.ts";
import { targetLabel } from "../types.ts";

export interface FleetScanOptions extends Omit<HostScanOptions, "onProgress"> {
  /** Max hosts scanned simultaneously. */
  hostConcurrency: number;
  /** Per-host progress callback. */
  onHostProgress?: (target: Target, message: string) => void;
  /** Called as each host finishes (for streaming output). */
  onResult?: (result: HostResult) => void;
}

export interface FleetScanSummary {
  results: HostResult[];
  startedAt: string;
  finishedAt: string;
  durationMs: number;
}

export async function scanFleet(
  targets: readonly Target[],
  options: FleetScanOptions,
): Promise<FleetScanSummary> {
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  const results = new Array<HostResult>(targets.length);
  let next = 0;

  const worker = async (): Promise<void> => {
    for (;;) {
      const index = next++;
      if (index >= targets.length) return;
      const target = targets[index]!;
      const label = targetLabel(target);
      const result = await scanHost(target, {
        ...options,
        onProgress: (message) => options.onHostProgress?.(target, message),
      });
      results[index] = result;
      options.onResult?.(result);
      void label;
    }
  };

  const lanes = Math.min(Math.max(1, options.hostConcurrency), targets.length);
  await Promise.all(Array.from({ length: lanes }, () => worker()));

  const finished = Date.now();
  return {
    results: results.filter(Boolean),
    startedAt,
    finishedAt: new Date(finished).toISOString(),
    durationMs: finished - started,
  };
}
