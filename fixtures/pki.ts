/**
 * Test PKI generator.
 *
 * Produces a throwaway CA and a set of leaf certificates covering the cases
 * the fixtures need: a valid RSA leaf, an SHA-1-signed leaf, a tiny key, an
 * expired leaf, and a hostname-mismatched leaf. Everything lands in
 * `fixtures/.pki/`, which is gitignored.
 *
 * Certs are re-generated only when missing or older than `maxAgeMs`, so the
 * suite starts fast on repeat runs.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const PKI_DIR = join(here, ".pki");

export interface LeafSpec {
  name: string;
  commonName: string;
  san: string;
  keyBits: number;
  /** SHA-1 signature (rejected by modern OpenSSL at default security level). */
  sha1?: boolean;
  /** Expired at generation time. */
  expired?: boolean;
  /** RSA key size below the 2048-bit baseline. */
  smallKey?: boolean;
}

const LEAVES: readonly LeafSpec[] = [
  { name: "leaf-valid", commonName: "localhost", san: "DNS:localhost,IP:127.0.0.1", keyBits: 2048 },
  { name: "leaf-sha1", commonName: "localhost", san: "DNS:localhost,IP:127.0.0.1", keyBits: 2048, sha1: true },
  { name: "leaf-small", commonName: "localhost", san: "DNS:localhost,IP:127.0.0.1", keyBits: 1024 },
  { name: "leaf-expired", commonName: "localhost", san: "DNS:localhost,IP:127.0.0.1", keyBits: 2048, expired: true },
  { name: "leaf-wronghost", commonName: "wrong.example.test", san: "DNS:wrong.example.test", keyBits: 2048 },
];

export interface PkiPaths {
  caCert: string;
  caKey: string;
  leaves: Record<string, { cert: string; key: string }>;
  ocspGood: string;
  ocspRevoked: string;
  ocspExpired: string;
}

let cached: PkiPaths | undefined;

function openssl(args: string[]): void {
  execFileSync("openssl", args, { stdio: ["ignore", "ignore", "pipe"] });
}

function fresh(path: string, maxAgeMs: number): boolean {
  if (!existsSync(path)) return false;
  try {
    return Date.now() - statSync(path).mtimeMs < maxAgeMs;
  } catch {
    return false;
  }
}

export function ensurePki(maxAgeMs = 24 * 60 * 60 * 1000): PkiPaths {
  if (cached) return cached;
  mkdirSync(PKI_DIR, { recursive: true });

  const caCert = join(PKI_DIR, "ca.pem");
  const caKey = join(PKI_DIR, "ca.key");
  const marker = join(PKI_DIR, ".complete");

  if (!fresh(marker, maxAgeMs)) {
    regenerate(caCert, caKey);
    writeFileSync(marker, "ok\n");
  }

  const leaves: Record<string, { cert: string; key: string }> = {};
  for (const spec of LEAVES) {
    leaves[spec.name] = {
      cert: join(PKI_DIR, `${spec.name}.pem`),
      key: join(PKI_DIR, `${spec.name}.key`),
    };
  }

  cached = {
    caCert,
    caKey,
    leaves,
    ocspGood: join(PKI_DIR, "ocsp-good.der"),
    ocspRevoked: join(PKI_DIR, "ocsp-revoked.der"),
    ocspExpired: join(PKI_DIR, "ocsp-expired.der"),
  };
  return cached;
}

function regenerate(caCert: string, caKey: string): void {
  // --- CA -----------------------------------------------------------------
  openssl([
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-keyout",
    caKey,
    "-out",
    caCert,
    "-days",
    "3650",
    "-nodes",
    "-subj",
    "/CN=tls-doctor fixture CA",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
  ]);

  for (const spec of LEAVES) {
    const keyPath = join(PKI_DIR, `${spec.name}.key`);
    const csrPath = join(PKI_DIR, `${spec.name}.csr`);
    const certPath = join(PKI_DIR, `${spec.name}.pem`);
    const extPath = join(PKI_DIR, `${spec.name}.ext`);

    const keyBits = spec.smallKey ? 1024 : spec.keyBits;
    openssl([
      "req",
      "-newkey",
      `rsa:${keyBits}`,
      "-keyout",
      keyPath,
      "-out",
      csrPath,
      "-nodes",
      "-subj",
      `/CN=${spec.commonName}`,
    ]);

    const ext = [
      "basicConstraints=CA:FALSE",
      "keyUsage=digitalSignature,keyEncipherment",
      "extendedKeyUsage=serverAuth",
      `subjectAltName=${spec.san}`,
      "authorityInfoAccess=OCSP;URI:http://ocsp.fixture.test/",
    ].join("\n");
    writeFileSync(extPath, `${ext}\n`);

    const baseArgs = [
      "x509",
      "-req",
      "-in",
      csrPath,
      "-CA",
      caCert,
      "-CAkey",
      caKey,
      "-CAcreateserial",
      "-out",
      certPath,
      "-extfile",
      extPath,
    ];
    if (spec.expired) {
      // Backdate so the leaf is already expired at scan time.
      openssl([
        ...baseArgs,
        "-not_before",
        "20200101000000Z",
        "-not_after",
        "20210101000000Z",
      ]);
    } else if (spec.sha1) {
      openssl([...baseArgs, "-sha1", "-days", "365"]);
    } else {
      openssl([...baseArgs, "-days", "365"]);
    }
  }

  // OCSP staples signed by the fixture CA: one "good" and one "revoked".
  writeOcspFixtures(caCert, caKey);
}

/** Produce DER OCSP responses for the valid leaf, good and revoked. */
function writeOcspFixtures(caCert: string, caKey: string): void {
  const leafCert = join(PKI_DIR, "leaf-valid.pem");
  const reqPath = join(PKI_DIR, "ocsp.req.der");
  const goodPath = join(PKI_DIR, "ocsp-good.der");
  const revokedPath = join(PKI_DIR, "ocsp-revoked.der");
  try {
    openssl(["ocsp", "-issuer", caCert, "-cert", leafCert, "-reqout", reqPath, "-no_nonce"]);
    const serial = execFileSync("openssl", ["x509", "-in", leafCert, "-noout", "-serial"], {
      encoding: "utf8",
    })
      .trim()
      .replace(/^serial=/, "");

    const makeIndex = (status: "V" | "R"): string => {
      const path = join(PKI_DIR, `index-${status}.txt`);
      const fields =
        status === "V"
          ? `V\t300101000000Z\t\t${serial}\tunknown\t/CN=localhost`
          : `R\t300101000000Z\t260101000000Z\t${serial}\tunknown\t/CN=localhost`;
      writeFileSync(path, `${fields}\n`);
      return path;
    };

    for (const [status, out] of [
      ["V", goodPath],
      ["R", revokedPath],
    ] as const) {
      const index = makeIndex(status);
      openssl([
        "ocsp",
        "-index",
        index,
        "-rsigner",
        caCert,
        "-rkey",
        caKey,
        "-CA",
        caCert,
        "-reqin",
        reqPath,
        "-respout",
        out,
        "-ndays",
        "1",
      ]);
    }

    // An "expired staple" is a good response whose nextUpdate is in the past.
    // OpenSSL will not mint one with a past date, so backdate the nextUpdate
    // GeneralizedTime in a copy of the good response.
    writeExpiredStaple(goodPath, join(PKI_DIR, "ocsp-expired.der"));
  } catch {
    // OCSP fixtures are optional: if the local OpenSSL cannot build them the
    // OCSP probe still runs, it just finds no staple on the OCSP fixtures.
  }
}

/**
 * Copy an OCSP response and rewrite its nextUpdate to 2020. The last
 * GeneralizedTime in the DER is nextUpdate (after producedAt and thisUpdate).
 */
function writeExpiredStaple(sourcePath: string, outPath: string): void {
  const der = readFileSync(sourcePath);
  const times: number[] = [];
  for (let i = 0; i < der.length - 1; i += 1) {
    if (der[i] === 0x18 && der[i + 1] === 0x0f) {
      const value = der.subarray(i + 2, i + 17).toString("ascii");
      if (/^\d{14}Z$/.test(value)) times.push(i);
    }
  }
  if (times.length === 0) return;
  const nextUpdateOffset = times[times.length - 1]!;
  const patched = Buffer.from(der);
  Buffer.from("20200101000000Z", "ascii").copy(patched, nextUpdateOffset + 2);
  writeFileSync(outPath, patched);
}

/** Read a PEM bundle's DER bytes. */
export function readPem(path: string): Buffer {
  return readFileSync(path);
}
