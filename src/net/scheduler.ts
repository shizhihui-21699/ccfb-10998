/**
 * Bounded concurrency, retry/backoff and pacing helpers.
 *
 * The tool must not harm production services, so every network action goes
 * through `ProbeScheduler`, which enforces:
 *   - a global cap on in-flight connections,
 *   - a small random jitter before each connect (avoids lock-step bursts),
 *   - exponential backoff with jitter on transient failures,
 *   - a per-target connection budget and wall-clock deadline.
 */

export interface SchedulerOptions {
  /** Max simultaneous in-flight connections across all targets. */
  concurrency: number;
  /** Delay added before each attempt, `[minMs, maxMs]`. */
  jitterMs?: readonly [number, number];
  /** Retries for transient failures (timeouts, ECONNRESET, refusals). */
  retries?: number;
  /** Base backoff delay in ms (doubled per retry, with full jitter). */
  backoffBaseMs?: number;
  /** Hard cap on total connection attempts. */
  maxAttempts?: number;
  /** Wall-clock deadline in ms; pending work fails once exceeded. */
  deadlineMs?: number;
  /** Injectable randomness/sleep for deterministic tests. */
  random?: () => number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export class RateLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RateLimitError";
  }
}

class Semaphore {
  private available: number;
  private readonly waiters: Array<() => void> = [];

  constructor(permits: number) {
    this.available = permits;
  }

  async acquire(): Promise<void> {
    if (this.available > 0) {
      this.available -= 1;
      return;
    }
    await new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  release(): void {
    const next = this.waiters.shift();
    if (next) next();
    else this.available += 1;
  }
}

export interface SchedulerCounters {
  connections: number;
  retries: number;
  timeouts: number;
  errors: number;
  budgetExhausted: boolean;
}

// Pacing timers must keep the process alive: awaiting one is real work, not
// incidental bookkeeping, so they are deliberately *not* unref'd.
const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

export class ProbeScheduler {
  private readonly sem: Semaphore;
  private readonly opts: Required<Omit<SchedulerOptions, "random" | "sleep" | "now">> & {
    random: () => number;
    sleep: (ms: number) => Promise<void>;
    now: () => number;
  };
  private readonly started: number;
  private attempts = 0;
  readonly counters: SchedulerCounters = {
    connections: 0,
    retries: 0,
    timeouts: 0,
    errors: 0,
    budgetExhausted: false,
  };

  constructor(options: SchedulerOptions) {
    const concurrency = Math.max(1, Math.floor(options.concurrency));
    this.sem = new Semaphore(concurrency);
    this.opts = {
      concurrency,
      jitterMs: options.jitterMs ?? [15, 90],
      retries: Math.max(0, options.retries ?? 1),
      backoffBaseMs: options.backoffBaseMs ?? 250,
      maxAttempts: Math.max(1, options.maxAttempts ?? 400),
      deadlineMs: options.deadlineMs ?? 120_000,
      random: options.random ?? Math.random,
      sleep: options.sleep ?? defaultSleep,
      now: options.now ?? Date.now,
    };
    this.started = this.opts.now();
  }

  /** True once the wall-clock deadline has passed. */
  deadlineExceeded(): boolean {
    return this.opts.now() - this.started >= this.opts.deadlineMs;
  }

  remainingMs(): number {
    return Math.max(0, this.opts.deadlineMs - (this.opts.now() - this.started));
  }

  /** Reserve one connection attempt from the global budget. */
  private takeAttempt(): void {
    if (this.attempts >= this.opts.maxAttempts) {
      this.counters.budgetExhausted = true;
      throw new RateLimitError(
        `global attempt budget of ${this.opts.maxAttempts} exhausted`,
      );
    }
    this.attempts += 1;
  }

  /** True when the global attempt budget is used up (non-throwing check). */
  budgetExhausted(): boolean {
    return this.attempts >= this.opts.maxAttempts;
  }

  private async jitter(): Promise<void> {
    const [lo, hi] = this.opts.jitterMs;
    if (hi <= 0) return;
    const span = Math.max(0, hi - lo);
    const ms = lo + this.opts.random() * span;
    if (ms > 0) await this.opts.sleep(ms);
  }

  /**
   * Run `fn` under the concurrency cap and pacing rules, retrying transient
   * failures with exponential backoff. `fn` should throw on a retryable error.
   */
  async run<T>(
    fn: () => Promise<T>,
    isRetryable: (err: unknown) => boolean = defaultIsRetryable,
  ): Promise<T> {
    const maxTries = this.opts.retries + 1;
    let lastErr: unknown;
    for (let attempt = 0; attempt < maxTries; attempt += 1) {
      if (this.deadlineExceeded()) {
        throw new RateLimitError("scheduler deadline exceeded");
      }
      this.takeAttempt();
      await this.sem.acquire();
      try {
        await this.jitter();
        this.counters.connections += 1;
        return await fn();
      } catch (err) {
        lastErr = err;
        if (err instanceof RateLimitError) throw err;
        this.counters.errors += 1;
        if (!isRetryable(err) || attempt >= maxTries - 1) throw err;
        this.counters.retries += 1;
        await this.backoff(attempt);
      } finally {
        this.sem.release();
      }
    }
    throw lastErr;
  }

  /**
   * Like `run`, but returns `null` instead of throwing once retries/backoff are
   * exhausted. Budget exhaustion still propagates so callers can stop early.
   */
  async runSoft<T>(
    fn: () => Promise<T>,
    isRetryable: (err: unknown) => boolean = defaultIsRetryable,
  ): Promise<T | null> {
    try {
      return await this.run(fn, isRetryable);
    } catch (err) {
      if (err instanceof RateLimitError) throw err;
      return null;
    }
  }

  private async backoff(attempt: number): Promise<void> {
    const base = this.opts.backoffBaseMs * 2 ** attempt;
    // Full jitter: sleep uniformly in [0, base] scaled to 50-100%.
    const ms = base * (0.5 + this.opts.random() * 0.5);
    const capped = Math.min(ms, this.remainingMs(), 5_000);
    if (capped > 0) await this.opts.sleep(capped);
  }

  /**
   * Run `items` through `worker` with bounded concurrency. Result order matches
   * input order. A RateLimitError aborts remaining work and rejects.
   */
  async map<T, R>(items: readonly T[], worker: (item: T, index: number) => Promise<R>): Promise<R[]> {
    const results = new Array<R>(items.length);
    let next = 0;
    let failure: unknown;
    let failed = false;

    const pump = async (): Promise<void> => {
      for (;;) {
        if (failed) return;
        const i = next++;
        if (i >= items.length) return;
        try {
          results[i] = await worker(items[i]!, i);
        } catch (err) {
          failed = true;
          failure = err;
          return;
        }
      }
    };

    const lanes = Math.min(this.opts.concurrency, items.length);
    await Promise.all(Array.from({ length: lanes }, () => pump()));
    if (failed) throw failure;
    return results;
  }
}

/** Errors worth retrying: transient network conditions, not protocol replies. */
export function defaultIsRetryable(err: unknown): boolean {
  if (err instanceof RateLimitError) return false;
  const code = (err as { code?: string } | null)?.code;
  switch (code) {
    case "ECONNRESET":
    case "ECONNREFUSED":
    case "ETIMEDOUT":
    case "EPIPE":
    case "EAI_AGAIN":
    case "EHOSTUNREACH":
    case "ENETUNREACH":
      return true;
    default:
      return (err as { transient?: boolean } | null)?.transient === true;
  }
}
