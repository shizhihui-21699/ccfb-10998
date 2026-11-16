/**
 * Scheduler tests: concurrency cap, retries/backoff, budget and deadline.
 * All timing is injected so the tests are fast and deterministic.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { ProbeScheduler, RateLimitError, defaultIsRetryable } from "../src/net/scheduler.ts";
import type { SchedulerOptions } from "../src/net/scheduler.ts";

/** A scheduler whose sleeps are recorded instead of awaited. */
function instrumented(options: SchedulerOptions) {
  const sleeps: number[] = [];
  const scheduler = new ProbeScheduler({
    ...options,
    sleep: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  return { scheduler, sleeps };
}

test("never exceeds the concurrency cap", async () => {
  let inFlight = 0;
  let peak = 0;
  const { scheduler } = instrumented({
    concurrency: 3,
    jitterMs: [0, 0],
    retries: 0,
    maxAttempts: 100,
    deadlineMs: 60_000,
  });
  const work = Array.from({ length: 20 }, (_, i) =>
    scheduler.run(async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 2));
      inFlight -= 1;
      return i;
    }),
  );
  const results = await Promise.all(work);
  assert.equal(results.length, 20);
  assert.ok(peak <= 3, `peak concurrency ${peak} exceeded cap 3`);
  assert.equal(scheduler.counters.connections, 20);
});

test("retries transient failures and succeeds", async () => {
  let attempts = 0;
  const { scheduler, sleeps } = instrumented({
    concurrency: 1,
    jitterMs: [0, 0],
    retries: 2,
    backoffBaseMs: 10,
    maxAttempts: 10,
    deadlineMs: 60_000,
    random: () => 0.5,
  });
  const result = await scheduler.run(async () => {
    attempts += 1;
    if (attempts < 3) {
      throw Object.assign(new Error("reset"), { code: "ECONNRESET" });
    }
    return "ok";
  });
  assert.equal(result, "ok");
  assert.equal(attempts, 3);
  assert.equal(scheduler.counters.retries, 2);
  assert.equal(sleeps.length, 2, "backoff slept between attempts");
});

test("does not retry non-transient errors", async () => {
  let attempts = 0;
  const scheduler = new ProbeScheduler({
    concurrency: 1,
    jitterMs: [0, 0],
    retries: 3,
    maxAttempts: 10,
    deadlineMs: 60_000,
    sleep: async () => {},
  });
  await assert.rejects(
    scheduler.run(async () => {
      attempts += 1;
      throw Object.assign(new Error("bad certificate"), { code: "CERT_REVOKED" });
    }),
  );
  assert.equal(attempts, 1, "fatal errors are not retried");
});

test("runSoft returns null after exhausting retries", async () => {
  const scheduler = new ProbeScheduler({
    concurrency: 1,
    jitterMs: [0, 0],
    retries: 1,
    maxAttempts: 10,
    deadlineMs: 60_000,
    sleep: async () => {},
  });
  const result = await scheduler.runSoft(async () => {
    throw Object.assign(new Error("timeout"), { code: "ETIMEDOUT" });
  });
  assert.equal(result, null);
});

test("exhausting the attempt budget raises RateLimitError", async () => {
  const scheduler = new ProbeScheduler({
    concurrency: 1,
    jitterMs: [0, 0],
    retries: 0,
    maxAttempts: 2,
    deadlineMs: 60_000,
    sleep: async () => {},
  });
  await scheduler.run(async () => 1);
  await scheduler.run(async () => 2);
  await assert.rejects(
    scheduler.run(async () => 3),
    (err: unknown) => err instanceof RateLimitError,
  );
  assert.equal(scheduler.counters.budgetExhausted, true);
});

test("deadline aborts further work", async () => {
  let now = 0;
  const scheduler = new ProbeScheduler({
    concurrency: 1,
    jitterMs: [0, 0],
    retries: 0,
    maxAttempts: 100,
    deadlineMs: 1000,
    now: () => now,
    sleep: async () => {},
  });
  await scheduler.run(async () => "first");
  now = 5000;
  assert.equal(scheduler.deadlineExceeded(), true);
  await assert.rejects(
    scheduler.run(async () => "second"),
    (err: unknown) => err instanceof RateLimitError,
  );
});

test("map preserves input order under concurrency", async () => {
  const scheduler = new ProbeScheduler({
    concurrency: 4,
    jitterMs: [0, 0],
    retries: 0,
    maxAttempts: 100,
    deadlineMs: 60_000,
  });
  const results = await scheduler.map([5, 1, 3, 2, 4], async (n) => {
    await new Promise((r) => setTimeout(r, n));
    return n * 10;
  });
  assert.deepEqual(results, [50, 10, 30, 20, 40]);
});

test("defaultIsRetryable classifies network errors, not protocol errors", () => {
  assert.equal(defaultIsRetryable({ code: "ECONNRESET" }), true);
  assert.equal(defaultIsRetryable({ code: "ETIMEDOUT" }), true);
  assert.equal(defaultIsRetryable({ code: "ERR_SSL_BAD_CERT" }), false);
  assert.equal(defaultIsRetryable(new Error("nope")), false);
  assert.equal(defaultIsRetryable(new RateLimitError("budget")), false);
});

test("jitter is applied before connecting", async () => {
  const sleeps: number[] = [];
  const scheduler = new ProbeScheduler({
    concurrency: 1,
    jitterMs: [20, 60],
    retries: 0,
    maxAttempts: 10,
    deadlineMs: 60_000,
    random: () => 0.5,
    sleep: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await scheduler.run(async () => "ok");
  assert.equal(sleeps.length, 1);
  assert.ok(sleeps[0]! >= 20 && sleeps[0]! <= 60, `jitter ${sleeps[0]} in range`);
});
