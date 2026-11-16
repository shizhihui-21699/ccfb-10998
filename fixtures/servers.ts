/**
 * Local TLS fixture servers with deliberately different configurations.
 *
 * They exist so the scanner can be tested end-to-end against servers whose
 * posture is known in advance — including servers that are intentionally
 * broken (TLS 1.0 on, RC4/3DES, client renegotiation enabled, weak certs).
 *
 * Three runtimes are used because no single one covers every case:
 *   - node:tls       : precise control; cannot staple OCSP server-side, and its
 *                      bundled OpenSSL refuses RC4/3DES and TLS <1.2.
 *   - openssl (3.x)  : only spawned for OCSP stapling (`-status_file`).
 *   - openssl (libressl, /usr/bin/openssl): legacy cases (RC4/3DES, TLS 1.0/1.1),
 *                      which LibreSSL still negotiates out of the box.
 *
 * Every fixture binds to 127.0.0.1 only. Nothing listens on a public interface.
 */
import tls from "node:tls";
import https from "node:https";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { ensurePki, type PkiPaths } from "./pki.ts";

export type FixtureRuntime = "node" | "openssl" | "libressl";

export interface FixtureSpec {
  id: string;
  description: string;
  runtime: FixtureRuntime;
  /** Fixed port keeps reports and docs stable. */
  port: number;
  /** Expected findings this fixture is designed to trigger. */
  expect: string[];
}

export interface RunningFixture extends FixtureSpec {
  close: () => Promise<void>;
  actualPort: number;
}

interface NodeFixtureConfig {
  cert: string;
  key: string;
  minVersion: string;
  maxVersion: string;
  ciphers?: string;
  honorCipherOrder?: boolean;
  secureOptions?: number;
  hsts?: string | false;
  responseBody?: string;
}

interface OpensslFixtureConfig {
  cert: string;
  key: string;
  /** s_server protocol flag: -tls1 / -tls1_2 / ... */
  protocolFlag: string;
  cipherList?: string;
  /** Extra s_server flags. */
  extraFlags?: string[];
  /** DER file to staple as an OCSP response. */
  statusFile?: string;
}

export interface FixtureDefinition {
  spec: FixtureSpec;
  node?: NodeFixtureConfig;
  openssl?: OpensslFixtureConfig;
}

const LIBRESSL = "/usr/bin/openssl";
const MODERN_OPENSSL = "openssl";

/**
 * Whether the system `openssl` is LibreSSL, whose cipher table still
 * negotiates RC4/3DES. On Linux that path is usually OpenSSL 3, which cannot
 * start those fixtures at all — they are skipped rather than failed.
 */
function libresslAvailable(): boolean {
  try {
    const out = execFileSync(LIBRESSL, ["version"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    return /LibreSSL/i.test(out);
  } catch {
    return false;
  }
}

/** OpenSSL option that makes a TLS server refuse renegotiation. */
const SSL_OP_NO_RENEGOTIATION = 0x40000000;

export function fixtureDefinitions(
  pki: PkiPaths,
  basePort = 0,
): FixtureDefinition[] {
  const valid = pki.leaves["leaf-valid"]!;
  const expired = pki.leaves["leaf-expired"]!;
  const wrongHost = pki.leaves["leaf-wronghost"]!;
  const sha1 = pki.leaves["leaf-sha1"]!;
  const small = pki.leaves["leaf-small"]!;

  return [
    {
      spec: {
        id: "modern",
        description: "TLS 1.2+1.3, ECDHE/AEAD only, HSTS, no renegotiation",
        runtime: "node",
        port: basePort + 0,
        expect: ["passes protocol, suite, renegotiation and HSTS checks"],
      },
      node: {
        cert: valid.cert,
        key: valid.key,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.3",
        ciphers:
          "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256",
        honorCipherOrder: true,
        secureOptions: SSL_OP_NO_RENEGOTIATION,
        hsts: "max-age=63072000; includeSubDomains; preload",
      },
    },
    {
      spec: {
        id: "tls10-open",
        description: "TLS 1.0 through 1.2 enabled (deprecated protocols), modern suites",
        runtime: "node",
        port: basePort + 1,
        expect: ["proto-tls10", "proto-tls11"],
      },
      node: {
        cert: valid.cert,
        key: valid.key,
        minVersion: "TLSv1",
        maxVersion: "TLSv1.2",
        ciphers:
          "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:@SECLEVEL=0",
        honorCipherOrder: true,
        secureOptions: SSL_OP_NO_RENEGOTIATION,
        hsts: "max-age=31536000",
      },
    },
    {
      spec: {
        id: "weak-ciphers",
        description: "RC4 and 3DES negotiable, TLS 1.0 still enabled (LibreSSL)",
        runtime: "libressl",
        port: basePort + 2,
        expect: ["suite-weak", "suite-legacy-enc", "suite-no-fs", "proto-tls10"],
      },
      openssl: {
        cert: valid.cert,
        key: valid.key,
        protocolFlag: "-tls1",
        cipherList: "ALL",
      },
    },
    {
      spec: {
        id: "client-order",
        description: "TLS 1.2 follows the client's cipher order (no server preference)",
        runtime: "node",
        port: basePort + 3,
        expect: ["pref-server-order (warn: client order honoured)"],
      },
      node: {
        cert: valid.cert,
        key: valid.key,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.2",
        ciphers:
          "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
        honorCipherOrder: false,
        secureOptions: SSL_OP_NO_RENEGOTIATION,
        hsts: false,
      },
    },
    {
      spec: {
        id: "reneg-open",
        description: "Accepts client-initiated renegotiation (CPU amplification)",
        runtime: "node",
        port: basePort + 4,
        expect: ["reneg-client"],
      },
      node: {
        cert: valid.cert,
        key: valid.key,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.2",
        ciphers: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
        honorCipherOrder: true,
        // No NO_RENEGOTIATION: Node's default accepts client renegotiation.
        hsts: false,
      },
    },
    {
      spec: {
        id: "expired-cert",
        description: "Expired leaf certificate, otherwise modern",
        runtime: "node",
        port: basePort + 5,
        expect: ["cert-expiry"],
      },
      node: {
        cert: expired.cert,
        key: expired.key,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.3",
        ciphers: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
        honorCipherOrder: true,
        secureOptions: SSL_OP_NO_RENEGOTIATION,
        hsts: "max-age=31536000",
      },
    },
    {
      spec: {
        id: "wrong-host",
        description: "Certificate does not cover the scanned hostname",
        runtime: "node",
        port: basePort + 6,
        expect: ["cert-hostname"],
      },
      node: {
        cert: wrongHost.cert,
        key: wrongHost.key,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.3",
        ciphers: "ECDHE-RSA-AES128-GCM-SHA256",
        honorCipherOrder: true,
        secureOptions: SSL_OP_NO_RENEGOTIATION,
        hsts: false,
      },
    },
    {
      spec: {
        id: "sha1-small",
        description: "SHA-1 signed certificate with a 1024-bit RSA key",
        runtime: "node",
        port: basePort + 7,
        expect: ["cert-sha1", "cert-key-strength"],
      },
      node: {
        cert: sha1.cert,
        key: sha1.key,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.2",
        ciphers: "AES128-SHA:@SECLEVEL=0",
        honorCipherOrder: true,
        secureOptions: SSL_OP_NO_RENEGOTIATION,
        hsts: false,
      },
    },
    {
      spec: {
        id: "no-hsts",
        description: "Modern TLS but no HSTS header",
        runtime: "node",
        port: basePort + 8,
        expect: ["hsts"],
      },
      node: {
        cert: valid.cert,
        key: valid.key,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.3",
        ciphers: "ECDHE-RSA-AES128-GCM-SHA256",
        honorCipherOrder: true,
        secureOptions: SSL_OP_NO_RENEGOTIATION,
        hsts: false,
      },
    },
    {
      spec: {
        id: "ocsp-good",
        description: "OCSP stapling enabled, staple says the certificate is good",
        runtime: "openssl",
        port: basePort + 9,
        expect: ["ocsp-stapling pass"],
      },
      openssl: {
        cert: valid.cert,
        key: valid.key,
        protocolFlag: "-tls1_2",
        cipherList: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
        statusFile: pki.ocspGood,
      },
    },
    {
      spec: {
        id: "ocsp-revoked",
        description: "OCSP stapling enabled, staple says the certificate is revoked",
        runtime: "openssl",
        port: basePort + 10,
        expect: ["ocsp-stapling fail (revoked)"],
      },
      openssl: {
        cert: valid.cert,
        key: valid.key,
        protocolFlag: "-tls1_2",
        cipherList: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
        statusFile: pki.ocspRevoked,
      },
    },
    {
      spec: {
        id: "ocsp-expired",
        description: "OCSP stapling enabled, staple's nextUpdate is in the past",
        runtime: "openssl",
        port: basePort + 13,
        expect: ["ocsp-stapling fail (expired staple)"],
      },
      openssl: {
        cert: valid.cert,
        key: valid.key,
        protocolFlag: "-tls1_2",
        cipherList: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
        statusFile: pki.ocspExpired,
      },
    },
    {
      spec: {
        id: "tls13-only",
        description: "TLS 1.3 only (renegotiation N/A; stapling not visible in plaintext)",
        runtime: "node",
        port: basePort + 11,
        expect: ["proto-tls12 (require) fail", "renegotiation N/A"],
      },
      node: {
        cert: valid.cert,
        key: valid.key,
        minVersion: "TLSv1.3",
        maxVersion: "TLSv1.3",
        honorCipherOrder: true,
        secureOptions: SSL_OP_NO_RENEGOTIATION,
        hsts: "max-age=31536000",
      },
    },
    {
      spec: {
        id: "small-key",
        description: "1024-bit RSA key, otherwise modern",
        runtime: "node",
        port: basePort + 12,
        expect: ["cert-key-strength"],
      },
      node: {
        cert: small.cert,
        key: small.key,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.2",
        ciphers: "AES128-SHA:@SECLEVEL=0",
        honorCipherOrder: true,
        secureOptions: SSL_OP_NO_RENEGOTIATION,
        hsts: false,
      },
    },
  ];
}

/* ---------------------------------------------------------------- runner */

function nodeTlsOptions(config: NodeFixtureConfig): tls.TlsOptions {
  return {
    cert: readFileSync(config.cert),
    key: readFileSync(config.key),
    minVersion: config.minVersion as tls.SecureVersion,
    maxVersion: config.maxVersion as tls.SecureVersion,
    honorCipherOrder: config.honorCipherOrder ?? true,
    ...(config.ciphers ? { ciphers: config.ciphers } : {}),
    ...(config.secureOptions !== undefined ? { secureOptions: config.secureOptions } : {}),
  };
}

async function startNodeFixture(definition: FixtureDefinition): Promise<RunningFixture> {
  const config = definition.node!;
  const body = config.responseBody ?? "tls-doctor fixture\n";
  const server = https.createServer(nodeTlsOptions(config), (_req, res) => {
    if (config.hsts) res.setHeader("Strict-Transport-Security", config.hsts);
    res.setHeader("Content-Type", "text/plain");
    res.end(body);
  });
  server.on("tlsClientError", () => {
    /* probes abort after ServerHello, which is expected */
  });

  const actualPort = await listen(server, definition.spec.port);
  return {
    ...definition.spec,
    actualPort,
    close: () => closeServer(server),
  };
}

function listen(server: https.Server, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      resolve(typeof address === "object" && address ? address.port : port);
    });
  });
}

function closeServer(server: https.Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections?.();
  });
}

async function startOpensslFixture(
  definition: FixtureDefinition,
  binary: string,
  legacyProvider: boolean,
): Promise<RunningFixture> {
  const config = definition.openssl!;
  const args = ["s_server", "-accept", String(definition.spec.port)];
  if (legacyProvider) args.push("-provider", "legacy", "-provider", "default");
  args.push("-cert", config.cert, "-key", config.key, config.protocolFlag);
  if (config.cipherList) args.push("-cipher", config.cipherList);
  if (config.statusFile) args.push("-status_file", config.statusFile);
  if (config.extraFlags) args.push(...config.extraFlags);
  args.push("-www", "-quiet");

  const child = spawn(binary, args, { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });

  const started = await waitForPort("127.0.0.1", definition.spec.port, 4_000);
  if (!started) {
    child.kill("SIGKILL");
    throw new Error(
      `openssl s_server for fixture ${definition.spec.id} did not start: ${stderr.trim().split("\n")[0] ?? "unknown error"}`,
    );
  }
  return {
    ...definition.spec,
    actualPort: definition.spec.port,
    close: () => stopChild(child),
  };
}

function stopChild(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      if (child.exitCode === null) child.kill("SIGKILL");
    }, 2_000);
    timer.unref();
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

async function waitForPort(host: string, port: number, timeoutMs: number): Promise<boolean> {
  const net = await import("node:net");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await new Promise<boolean>((resolve) => {
      const socket = net.connect({ host, port });
      const timer = setTimeout(() => {
        socket.destroy();
        resolve(false);
      }, 250);
      socket.once("connect", () => {
        clearTimeout(timer);
        socket.destroy();
        resolve(true);
      });
      socket.once("error", () => {
        clearTimeout(timer);
        socket.destroy();
        resolve(false);
      });
    });
    if (ok) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

/** Start every fixture, skipping (with a warning) any that cannot start. */
export async function startFixtures(options: { basePort?: number } = {}): Promise<RunningFixture[]> {
  const pki = ensurePki();
  const definitions = fixtureDefinitions(pki, options.basePort ?? 15401);
  const running: RunningFixture[] = [];
  const haveLibressl = libresslAvailable();
  for (const definition of definitions) {
    if (definition.spec.runtime === "libressl" && !haveLibressl) {
      process.stderr.write(
        `fixture ${definition.spec.id} skipped: needs LibreSSL at ${LIBRESSL} for RC4/3DES/TLS1.0\n`,
      );
      continue;
    }
    try {
      const fixture =
        definition.spec.runtime === "node"
          ? await startNodeFixture(definition)
          : await startOpensslFixture(
              definition,
              definition.spec.runtime === "libressl" ? LIBRESSL : MODERN_OPENSSL,
              false,
            );
      running.push(fixture);
    } catch (err) {
      process.stderr.write(
        `fixture ${definition.spec.id} failed to start: ${(err as Error).message}\n`,
      );
    }
  }
  return running;
}
