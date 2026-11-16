/**
 * One-shot TLS ClientHello probe over a single TCP connection.
 *
 * Reads only the server's first flight and disconnects. No handshake is
 * completed, nothing is written after the ClientHello, and no session state is
 * retained — the lightest possible active probe short of a bare TCP connect.
 */
import net from "node:net";
import {
  ALERT_DESCRIPTION,
  HandshakeReader,
  buildClientHello,
  parseAlert,
  splitRecords,
  type ParsedMessage,
} from "../tls/wire.ts";
import type { ClientHelloOptions } from "../tls/wire.ts";

export interface ProbeEndpoints {
  host: string;
  port: number;
}

export interface ProbeTiming {
  connectTimeoutMs: number;
  /** Time to wait for the server's first flight after the hello is written. */
  readTimeoutMs: number;
}

export const DEFAULT_TIMING: ProbeTiming = {
  connectTimeoutMs: 5_000,
  readTimeoutMs: 6_000,
};

export type ProbeOutcome =
  | {
      kind: "server_hello";
      version: number;
      cipherSuite: number;
      extensions: ReadonlyMap<number, Buffer>;
      secureRenegotiation: boolean;
      serverHello: Extract<ParsedMessage, { kind: "server_hello" }>["info"];
      /** Any further plaintext messages captured (Certificate, CertStatus). */
      messages: ParsedMessage[];
      /** Raw bytes received, for callers that need to look at records. */
      bytes: number;
      elapsedMs: number;
    }
  | {
      kind: "alert";
      level: number;
      description: number;
      alert: string;
      bytes: number;
      elapsedMs: number;
    }
  | { kind: "timeout"; phase: "connect" | "read"; elapsedMs: number }
  | { kind: "error"; code: string; message: string; elapsedMs: number; transient: boolean }
  | { kind: "closed"; bytes: number; elapsedMs: number };

/** Node error codes that represent a transient network hiccup worth retrying. */
const TRANSIENT_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EPIPE",
  "EAI_AGAIN",
  "EHOSTUNREACH",
  "ENETUNREACH",
]);

function isTransientCode(code: string | undefined): boolean {
  return code !== undefined && TRANSIENT_CODES.has(code);
}

/**
 * Send one ClientHello and classify the server's response.
 *
 * `keepReadingMs` extends the read window after ServerHello so a TLS 1.2
 * server's Certificate / CertificateStatus records can be captured (OCSP
 * stapling and certificate inspection need them).
 */
export function probeClientHello(
  endpoints: ProbeEndpoints,
  hello: ClientHelloOptions,
  timing: ProbeTiming = DEFAULT_TIMING,
  options: {
    /**
     * Keep reading this long after ServerHello so Certificate /
     * CertificateStatus can be captured. The window ends early once the
     * connection goes idle (see `idleMs`).
     */
    keepReadingMs?: number;
    /** Quiet period that ends the keep-reading window early. */
    idleMs?: number;
    /**
     * Finish as soon as a Certificate message arrives (the caller only needs
     * the chain). CertificateStatus always finishes early regardless.
     */
    stopOnCertificate?: boolean;
  } = {},
): Promise<ProbeOutcome> {
  const started = performance.now();
  const elapsed = (): number => Math.round(performance.now() - started);

  return new Promise<ProbeOutcome>((resolve) => {
    let settled = false;
    let bytes = 0;
    let phase: "connect" | "read" = "connect";
    let buffer: Buffer = Buffer.alloc(0);
    const reader = new HandshakeReader();
    const messages: ParsedMessage[] = [];
    let serverHello: Extract<ParsedMessage, { kind: "server_hello" }>["info"] | null =
      null;

    const socket = net.connect({ host: endpoints.host, port: endpoints.port });
    socket.setNoDelay(true);

    let connectTimer: NodeJS.Timeout | undefined = setTimeout(
      () => finish({ kind: "timeout", phase: "connect", elapsedMs: elapsed() }),
      timing.connectTimeoutMs,
    );
    /** Overall deadline for the server's first flight. */
    let readTimer: NodeJS.Timeout | undefined;
    /** Separate short "server went quiet" timer used only after ServerHello. */
    let idleTimer: NodeJS.Timeout | undefined;

    function cleanup(): void {
      if (connectTimer) clearTimeout(connectTimer);
      if (readTimer) clearTimeout(readTimer);
      if (idleTimer) clearTimeout(idleTimer);
      connectTimer = undefined;
      readTimer = undefined;
      idleTimer = undefined;
      socket.removeAllListeners();
      // Destroy without sending anything: we never want to complete a handshake.
      socket.destroy();
    }

    function finish(outcome: ProbeOutcome): void {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(outcome);
    }

    const keepReadingMs = options.keepReadingMs ?? 0;
    const idleMs = options.idleMs ?? Math.min(200, keepReadingMs || 200);

    /** Restart the post-hello idle timer; only meaningful once we have a hello. */
    function bumpIdleWindow(): void {
      if (keepReadingMs <= 0 || settled || !serverHello) return;
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => finishHelloNow(), idleMs);
    }

    function completeWithHello(): void {
      if (!serverHello) return;
      const sh = serverHello;
      if (keepReadingMs <= 0) {
        finish({
          kind: "server_hello",
          version: sh.version,
          cipherSuite: sh.cipherSuite,
          extensions: sh.extensions,
          secureRenegotiation: sh.secureRenegotiation,
          serverHello: sh,
          messages,
          bytes,
          elapsedMs: elapsed(),
        });
        return;
      }
      // The overall read timer stays armed as a backstop; the idle timer lets
      // us stop as soon as the server falls quiet instead of always waiting
      // the full window.
      bumpIdleWindow();
    }

    function finishHelloNow(): void {
      if (!serverHello) return;
      const sh = serverHello;
      finish({
        kind: "server_hello",
        version: sh.version,
        cipherSuite: sh.cipherSuite,
        extensions: sh.extensions,
        secureRenegotiation: sh.secureRenegotiation,
        serverHello: sh,
        messages,
        bytes,
        elapsedMs: elapsed(),
      });
    }

    function armReadTimer(): void {
      phase = "read";
      if (connectTimer) {
        clearTimeout(connectTimer);
        connectTimer = undefined;
      }
      if (readTimer) clearTimeout(readTimer);
      readTimer = setTimeout(
        () => finish({ kind: "timeout", phase: "read", elapsedMs: elapsed() }),
        timing.readTimeoutMs,
      );
    }

    socket.on("connect", () => {
      try {
        socket.write(buildClientHello(hello));
      } catch (err) {
        finish({
          kind: "error",
          code: "EHANDSHAKEBUILD",
          message: (err as Error).message,
          elapsedMs: elapsed(),
          transient: false,
        });
        return;
      }
      armReadTimer();
    });

    socket.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      buffer = Buffer.concat([buffer, chunk]);
      const { records, rest } = splitRecords(buffer);
      buffer = rest;
      // Any new bytes mean the server is still talking: extend the idle window.
      bumpIdleWindow();

      try {
        for (const record of records) {
          if (record.type === 0x15) {
            // Alert: either a rejection or close_notify. Either way we are done.
            const alert = parseAlert(record.payload);
            if (alert.description === 0 && serverHello) return; // close_notify after hello
            finish({
              kind: "alert",
              level: alert.level,
              description: alert.description,
              alert: ALERT_DESCRIPTION[alert.description] ?? `alert(${alert.description})`,
              bytes,
              elapsedMs: elapsed(),
            });
            return;
          }
          if (record.type !== 0x16) continue; // ignore change_cipher_spec / app data

          for (const message of reader.push(record.payload)) {
            if (message.kind === "server_hello") {
              serverHello = message.info;
              messages.push(message);
              completeWithHello();
              continue;
            }
            if (serverHello) {
              messages.push(message);
              if (message.kind === "certificate_status") {
                // The staple is what we came for; stop early.
                finishHelloNow();
                return;
              }
              if (message.kind === "certificate" && options.stopOnCertificate) {
                // The chain is what we came for; no need to wait for the rest
                // of the flight.
                finishHelloNow();
                return;
              }
            }
          }
        }
      } catch (err) {
        // Handshake parsers throw RangeError on truncated/overrunning input,
        // which a non-TLS service, a buggy server or a fuzzer can produce. That
        // must become a probe outcome, never an uncaught exception that takes
        // down the whole scan.
        finish({
          kind: "error",
          code: "EMALFORMEDTLS",
          message: `malformed TLS message: ${(err as Error).message}`,
          elapsedMs: elapsed(),
          transient: false,
        });
      }
    });

    // A half-closed peer has sent everything it is going to send.
    socket.on("end", () => {
      if (serverHello) finishHelloNow();
    });

    socket.on("error", (err: NodeJS.ErrnoException) => {
      finish({
        kind: "error",
        code: err.code ?? "EUNKNOWN",
        message: err.message,
        elapsedMs: elapsed(),
        transient: isTransientCode(err.code),
      });
    });

    socket.on("close", () => {
      if (serverHello) {
        finishHelloNow();
        return;
      }
      finish({ kind: "closed", bytes, elapsedMs: elapsed() });
    });

    // If the hello is written but the peer never answers we rely on readTimer.
    void phase;
  });
}

/** Throw a retryable error for transient probe outcomes, else return the outcome. */
export function probeOrThrow<T extends { kind: "error"; transient: boolean; code: string; message: string }>(
  outcome: T | ProbeOutcome,
): ProbeOutcome {
  if (outcome.kind === "error" && outcome.transient) {
    const err = new Error(`${outcome.code}: ${outcome.message}`) as NodeJS.ErrnoException & {
      transient: boolean;
    };
    err.code = outcome.code;
    err.transient = true;
    throw err;
  }
  return outcome as ProbeOutcome;
}
