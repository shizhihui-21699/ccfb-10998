/** Target parsing: host:port forms, IPv6, URLs, lists, files. */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TargetError,
  parseTarget,
  parseTargets,
  readTargetFile,
  splitTargetList,
} from "../src/config/targets.ts";

test("parses host:port", () => {
  assert.deepEqual(parseTarget("api.internal:8443"), { host: "api.internal", port: 8443 });
});

test("defaults the port", () => {
  assert.deepEqual(parseTarget("api.internal"), { host: "api.internal", port: 443 });
});

test("parses bracketed IPv6 with a port", () => {
  assert.deepEqual(parseTarget("[::1]:8443"), { host: "::1", port: 8443 });
});

test("parses bare IPv6 without a port", () => {
  assert.deepEqual(parseTarget("::1"), { host: "::1", port: 443 });
});

test("strips scheme, path and query from URLs", () => {
  assert.deepEqual(parseTarget("https://api.internal:8443/health?x=1"), {
    host: "api.internal",
    port: 8443,
  });
});

test("handles an IPv6 URL", () => {
  assert.deepEqual(parseTarget("https://[2001:db8::1]:9443/x"), {
    host: "2001:db8::1",
    port: 9443,
  });
});

test("rejects out-of-range and non-numeric ports", () => {
  assert.throws(() => parseTarget("host:99999"), TargetError);
  assert.throws(() => parseTarget("host:abc"), TargetError);
  assert.throws(() => parseTarget("host:0"), TargetError);
});

test("rejects empty input", () => {
  assert.throws(() => parseTarget("   "), TargetError);
});

test("splits comma and whitespace separated lists", () => {
  assert.deepEqual(splitTargetList("a:1, b:2  c:3\nd:4"), ["a:1", "b:2", "c:3", "d:4"]);
});

test("parseTargets de-duplicates and reports per-spec errors", () => {
  const { targets, errors } = parseTargets(["a:1", "a:1", "https://a:1/", "bad:abc"]);
  assert.equal(targets.length, 1);
  assert.equal(errors.length, 1);
  assert.equal(errors[0]!.spec, "bad:abc");
});

test("readTargetFile ignores comments and blank lines", () => {
  const dir = mkdtempSync(join(tmpdir(), "tls-doctor-targets-"));
  const path = join(dir, "targets.txt");
  writeFileSync(path, "# production\napi.internal:443\n\n  db.internal:5432  # db\n");
  assert.deepEqual(readTargetFile(path), ["api.internal:443", "db.internal:5432"]);
});
