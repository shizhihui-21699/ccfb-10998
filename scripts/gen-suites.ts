/**
 * Generates `src/tls/suite-data.generated.ts` from the OpenSSL cipher tables
 * available on the build machine.
 *
 * We merge two sources when possible:
 *   - a modern OpenSSL 3.x `openssl` binary (rich metadata, no RC4/3DES)
 *   - a LibreSSL `/usr/bin/openssl` binary (has RC4/3DES/GOST legacy suites)
 *
 * The tool does not need OpenSSL at runtime: the emitted table is committed.
 * Extra legacy suites that neither build may list (EXPORT/NULL) are added by
 * hand in LEGACY_EXTRAS.
 */
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

type MinVersion = "SSLv3" | "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

interface RawRow {
  id: number;
  name: string;
  minLabel: string;
  kx: string;
  au: string;
  enc: string;
  mac: string;
}

const ROW_RE =
  /^\s*0x([0-9A-Fa-f]{2}),0x([0-9A-Fa-f]{2})\s+-\s+(\S+)(?:\s+-\s+\S+)?\s+(SSLv3|TLSv1(?:\.1|\.2|\.3)?)\s+Kx=(\S+)\s+Au=(\S+)\s+Enc=(\S+)\s+Mac=(\S+)/;

function parseOpenSsl(bin: string, lib: "openssl" | "libressl"): RawRow[] {
  // OpenSSL 3.x supports the @SECLEVEL knob; LibreSSL rejects it, so fall back.
  const attempts = [["ciphers", "-V", "ALL:@SECLEVEL=0"], ["ciphers", "-V", "ALL"]];
  let out = "";
  for (const args of attempts) {
    try {
      out = execFileSync(bin, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
      break;
    } catch {
      out = "";
    }
  }
  if (!out) return [];
  const rows: RawRow[] = [];
  for (const line of out.split("\n")) {
    const m = ROW_RE.exec(line);
    if (!m) continue;
    rows.push({
      id: (parseInt(m[1]!, 16) << 8) | parseInt(m[2]!, 16),
      name: m[3]!,
      minLabel: m[4]!,
      kx: m[5]!,
      au: m[6]!,
      enc: m[7]!,
      mac: m[8]!,
    });
  }
  // LibreSSL reports GOST suites as SSLv3; tag them by name so they classify.
  if (lib === "libressl") {
    for (const r of rows) if (/^GOST/i.test(r.name)) r.enc = "GOST";
  }
  return rows;
}

/** Suites neither local build tends to enumerate but real servers still run. */
const LEGACY_EXTRAS: RawRow[] = [
  // TLS 1.3 AEAD suites that OpenSSL 3 omits from `ciphers -V` output.
  // (RFC 8446 defines five; the three GCM/ChaCha ones are listed already.)
  { id: 0x1304, name: "TLS_AES_128_CCM_SHA256", minLabel: "TLSv1.3", kx: "any", au: "any", enc: "AESCCM(128)", mac: "AEAD" },
  { id: 0x1305, name: "TLS_AES_128_CCM_8_SHA256", minLabel: "TLSv1.3", kx: "any", au: "any", enc: "AESCCM8(128)", mac: "AEAD" },
  { id: 0x0000, name: "NULL-NULL", minLabel: "SSLv3", kx: "RSA", au: "RSA", enc: "NULL", mac: "NULL" },
  { id: 0x0001, name: "RSA-NULL-MD5", minLabel: "SSLv3", kx: "RSA", au: "RSA", enc: "NULL", mac: "MD5" },
  { id: 0x0002, name: "RSA-NULL-SHA", minLabel: "SSLv3", kx: "RSA", au: "RSA", enc: "NULL", mac: "SHA1" },
  { id: 0x0003, name: "EXP-RC4-MD5", minLabel: "SSLv3", kx: "RSA(512)", au: "RSA", enc: "RC4(40)", mac: "MD5" },
  { id: 0x0006, name: "EXP-RC2-CBC-MD5", minLabel: "SSLv3", kx: "RSA(512)", au: "RSA", enc: "RC2(40)", mac: "MD5" },
  { id: 0x0008, name: "EXP-DES-CBC-SHA", minLabel: "SSLv3", kx: "RSA(512)", au: "RSA", enc: "DES(40)", mac: "SHA1" },
  { id: 0x0009, name: "DES-CBC-SHA", minLabel: "SSLv3", kx: "RSA", au: "RSA", enc: "DES(56)", mac: "SHA1" },
  { id: 0x0011, name: "EXP-EDH-DSS-DES-CBC-SHA", minLabel: "SSLv3", kx: "DH(512)", au: "DSS", enc: "DES(40)", mac: "SHA1" },
  { id: 0x0014, name: "EXP-EDH-RSA-DES-CBC-SHA", minLabel: "SSLv3", kx: "DH(512)", au: "RSA", enc: "DES(40)", mac: "SHA1" },
  { id: 0x0017, name: "EXP-EDH-RSA-DES-CBC-SHA", minLabel: "SSLv3", kx: "DH(512)", au: "RSA", enc: "DES(40)", mac: "SHA1" },
  { id: 0x0019, name: "EXP-ADH-DES-CBC-SHA", minLabel: "SSLv3", kx: "DH(512)", au: "None", enc: "DES(40)", mac: "SHA1" },
  { id: 0x0060, name: "EXP1024-RC4-SHA", minLabel: "SSLv3", kx: "RSA(1024)", au: "RSA", enc: "RC4(56)", mac: "SHA1" },
  { id: 0x0062, name: "EXP1024-DES-CBC-SHA", minLabel: "SSLv3", kx: "RSA(1024)", au: "RSA", enc: "DES(56)", mac: "SHA1" },
  { id: 0x0063, name: "EXP1024-EDH-DSS-DES-CBC-SHA", minLabel: "SSLv3", kx: "DH(1024)", au: "DSS", enc: "DES(56)", mac: "SHA1" },
  { id: 0x0065, name: "EXP1024-EDH-RSA-DES-CBC-SHA", minLabel: "SSLv3", kx: "DH(1024)", au: "RSA", enc: "DES(56)", mac: "SHA1" },
  { id: 0x0066, name: "EXP1024-ADH-DES-CBC-SHA", minLabel: "SSLv3", kx: "DH(1024)", au: "None", enc: "DES(56)", mac: "SHA1" },
];

function normalizeMin(label: string): MinVersion {
  const l = label.toLowerCase();
  if (l === "sslv3") return "SSLv3";
  if (l === "tlsv1.3") return "TLSv1.3";
  if (l === "tlsv1.2") return "TLSv1.2";
  if (l === "tlsv1.1") return "TLSv1.1";
  return "TLSv1";
}

function hasEphemeralKx(kx: string): boolean {
  const k = kx.toUpperCase();
  return k.includes("ECDH") || k.includes("DH") || k.includes("DHEPSK") || k.includes("ECDHEPSK");
}

function isWeak(row: RawRow): boolean {
  const enc = row.enc.toUpperCase();
  return (
    /RC4|3DES|(^|[^A-Z])DES|RC2|NULL|GOST/.test(enc) ||
    /EXPORT|^EXP/.test(row.kx.toUpperCase()) ||
    /EXP/i.test(row.name) ||
    row.mac.toUpperCase() === "MD5" ||
    row.au === "None"
  );
}

function main(): void {
  const openSslRows = parseOpenSsl("openssl", "openssl");
  const libresslRows = parseOpenSsl("/usr/bin/openssl", "libressl");
  const byId = new Map<number, RawRow>();
  // Modern OpenSSL wins on naming/metadata; LibreSSL fills in legacy suites.
  for (const r of libresslRows) byId.set(r.id, r);
  for (const r of openSslRows) byId.set(r.id, r);
  for (const r of LEGACY_EXTRAS) if (!byId.has(r.id)) byId.set(r.id, r);

  const rows = [...byId.values()].sort((a, b) => a.id - b.id);
  const records = rows.map((r) => {
    const minVersion = normalizeMin(r.minLabel);
    const forwardSecrecy =
      minVersion === "TLSv1.3" || (hasEphemeralKx(r.kx) && r.au !== "None");
    return {
      id: r.id,
      name: r.name,
      minVersion,
      kx: r.kx,
      auth: r.au,
      enc: r.enc,
      mac: r.mac,
      forwardSecrecy,
      weak: isWeak(r),
      anonymous: r.au === "None",
    };
  });

  const lines: string[] = [];
  lines.push("/**");
  lines.push(" * AUTO-GENERATED by scripts/gen-suites.ts — do not edit by hand.");
  lines.push(` * ${records.length} cipher suites (OpenSSL ${openSslRows.length} + LibreSSL legacy ${libresslRows.length} merged).`);
  lines.push(" */");
  lines.push('import type { SuiteMeta } from "./suite-types.ts";');
  lines.push("");
  lines.push("export const SUITE_TABLE: readonly SuiteMeta[] = [");
  for (const r of records) {
    lines.push(
      `  { id: 0x${r.id.toString(16).padStart(4, "0")}, name: ${JSON.stringify(r.name)}, minVersion: ${JSON.stringify(r.minVersion)}, kx: ${JSON.stringify(r.kx)}, auth: ${JSON.stringify(r.auth)}, enc: ${JSON.stringify(r.enc)}, mac: ${JSON.stringify(r.mac)}, forwardSecrecy: ${r.forwardSecrecy}, weak: ${r.weak}, anonymous: ${r.anonymous} },`,
    );
  }
  lines.push("];");
  lines.push("");

  const here = dirname(fileURLToPath(import.meta.url));
  const outPath = join(here, "..", "src", "tls", "suite-data.generated.ts");
  writeFileSync(outPath, lines.join("\n"), "utf8");
  const weak = records.filter((r) => r.weak).length;
  console.log(
    `wrote ${records.length} suites (${weak} weak, ${records.filter((r) => r.minVersion === "TLSv1.3").length} TLS1.3) to ${outPath}`,
  );
}

main();
