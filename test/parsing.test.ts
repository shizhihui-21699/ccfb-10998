/** HSTS header parsing (RFC 6797) and cipher-list bookkeeping. */
import test from "node:test";
import assert from "node:assert/strict";
import { parseHstsHeader } from "../src/probes/hsts.ts";
import { offerListFor, suiteById, suiteByName } from "../src/tls/suites.ts";

test("parses a full HSTS header", () => {
  const parsed = parseHstsHeader("max-age=31536000; includeSubDomains; preload");
  assert.equal(parsed.maxAge, 31_536_000);
  assert.equal(parsed.includeSubDomains, true);
  assert.equal(parsed.preload, true);
  assert.equal(parsed.error, undefined);
});

test("HSTS directives are case-insensitive", () => {
  const parsed = parseHstsHeader("MAX-AGE=600; IncludeSubDomains");
  assert.equal(parsed.maxAge, 600);
  assert.equal(parsed.includeSubDomains, true);
});

test("missing max-age is reported", () => {
  const parsed = parseHstsHeader("includeSubDomains");
  assert.equal(parsed.maxAge, undefined);
  assert.match(parsed.error ?? "", /missing max-age/);
});

test("non-numeric max-age is reported", () => {
  const parsed = parseHstsHeader("max-age=abc");
  assert.equal(parsed.maxAge, undefined);
  assert.match(parsed.error ?? "", /invalid max-age/);
});

test("max-age=0 parses to zero, not undefined", () => {
  assert.equal(parseHstsHeader("max-age=0").maxAge, 0);
});

test("unknown directives are ignored", () => {
  const parsed = parseHstsHeader("max-age=100; fooBar; baz=1");
  assert.equal(parsed.maxAge, 100);
  assert.equal(parsed.error, undefined);
});

test("undefined header yields no directives and no error", () => {
  const parsed = parseHstsHeader(undefined);
  assert.equal(parsed.maxAge, undefined);
  assert.equal(parsed.error, undefined);
});

test("suiteById resolves known suites and synthesises unknown ones", () => {
  assert.equal(suiteById(0xc02f).name, "ECDHE-RSA-AES128-GCM-SHA256");
  assert.equal(suiteById(0xc02f).forwardSecrecy, true);
  const unknown = suiteById(0xdead);
  assert.match(unknown.name, /UNKNOWN-0xdead/);
});

test("weak suites are flagged in the table", () => {
  assert.equal(suiteById(0x0005).weak, true, "RC4-SHA");
  assert.equal(suiteById(0x000a).weak, true, "3DES");
  assert.equal(suiteById(0x1301).weak, false, "TLS_AES_128_GCM_SHA256");
});

test("offer lists contain only suites the table knows", () => {
  for (const version of ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"] as const) {
    const ids = offerListFor(version);
    assert.ok(ids.length > 0, `${version} offer list is non-empty`);
    for (const id of ids) {
      assert.equal(suiteById(id).id, id);
    }
  }
});

test("TLS 1.3 offer list is exactly the five TLS 1.3 suites", () => {
  const names = offerListFor("TLSv1.3").map((id) => suiteById(id).minVersion);
  assert.ok(names.every((v) => v === "TLSv1.3"));
});

test("suiteByName is case-insensitive", () => {
  assert.equal(suiteByName("ecdhe-rsa-aes128-gcm-sha256")?.id, 0xc02f);
});
