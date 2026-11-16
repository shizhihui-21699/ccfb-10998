/**
 * Robustness tests: hostile or broken peers must produce a probe outcome,
 * never an uncaught exception or an aborted scan.
 */
import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { probeClientHello } from "../src/net/client-hello.ts";
import { enumerateCiphers } from "../src/probes/ciphers.ts";
import { ProbeScheduler } from "../src/net/scheduler.ts";

/** Start a raw TCP server that replies to the first bytes with `reply`. */
function misbehavingServer(
  reply: (socket: net.Socket) => void,
): Promise<{ port: number; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const sockets = new Set<net.Socket>();
    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.on("error", () => {});
      socket.on("close", () => sockets.delete(socket));
      socket.on("data", () => reply(socket));
    });
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({
        port,
        close: () =>
          new Promise<void>((done) => {
            for (const s of sockets) s.destroy();
            server.close(() => done());
          }),
      });
    });
  });
}

const timing = { connectTimeoutMs: 1_500, readTimeoutMs: 2_000 };

test("a truncated ServerHello yields an error outcome, not a crash", async () => {
  // Record: handshake, body claims a 2-byte ServerHello that is too short to parse.
  const server = await misbehavingServer((socket) => {
    socket.write(Buffer.from([0x16, 0x03, 0x03, 0x00, 0x06, 0x02, 0x00, 0x00, 0x02, 0x03, 0x03]));
  });
  try {
    const outcome = await probeClientHello(
      { host: "127.0.0.1", port: server.port },
      { suites: [0xc02f], renegotiationInfo: true },
      timing,
    );
    assert.equal(outcome.kind, "error");
    if (outcome.kind === "error") {
      assert.equal(outcome.code, "EMALFORMEDTLS");
    }
  } finally {
    await server.close();
  }
});

test("a ServerHello with an overrunning extension block does not crash", async () => {
  // Valid-length record whose ServerHello declares a huge extensions length.
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 0),
    Buffer.from([0]),
    Buffer.from([0xc0, 0x2f]),
    Buffer.from([0]),
    Buffer.from([0xff, 0xff]), // extensions length 65535, but none follow
  ]);
  const record = Buffer.concat([
    Buffer.from([0x16, 0x03, 0x03]),
    Buffer.from([0x00, body.length + 4]),
    Buffer.from([0x02, 0x00, 0x00, body.length]),
    body,
  ]);
  const server = await misbehavingServer((socket) => socket.write(record));
  try {
    const outcome = await probeClientHello(
      { host: "127.0.0.1", port: server.port },
      { suites: [0xc02f], renegotiationInfo: true },
      timing,
    );
    assert.equal(outcome.kind, "error");
  } finally {
    await server.close();
  }
});

test("cipher enumeration stops cleanly when the scheduler budget is exhausted", async () => {
  const server = await misbehavingServer((socket) => socket.destroy());
  // A scheduler with a single permitted attempt: the second probe must throw
  // RateLimitError internally, which enumerateCiphers converts to truncation
  // rather than propagating and aborting the scan.
  const scheduler = new ProbeScheduler({
    concurrency: 1,
    jitterMs: [0, 0],
    retries: 0,
    maxAttempts: 1,
    deadlineMs: 30_000,
    sleep: async () => {},
  });
  try {
    const result = await enumerateCiphers(
      { host: "127.0.0.1", port: server.port },
      "TLSv1.2",
      scheduler,
      { timing },
    );
    // The essential property: it returns a result instead of throwing
    // RateLimitError up into the fleet scan.
    assert.equal(result.version, "TLSv1.2");
    assert.ok(Array.isArray(result.suites));
  } finally {
    await server.close();
  }
});
