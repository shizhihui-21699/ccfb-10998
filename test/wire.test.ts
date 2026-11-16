/**
 * Wire-format unit tests: ClientHello construction, ServerHello/alert parsing,
 * record framing, and the OCSP DER reader. These run without any network.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  Cursor,
  HandshakeReader,
  VERSION,
  buildClientHello,
  parseAlert,
  parseServerHello,
  splitRecords,
  versionName,
} from "../src/tls/wire.ts";
import { parseOcspResponse, readDer } from "../src/tls/ocsp.ts";

test("versionName maps wire versions to names", () => {
  assert.equal(versionName(VERSION.TLS12), "TLSv1.2");
  assert.equal(versionName(VERSION.TLS13), "TLSv1.3");
  assert.equal(versionName(0x1234), "0x1234");
});

test("buildClientHello produces one well-framed handshake record", () => {
  const hello = buildClientHello({
    supportedVersions: [VERSION.TLS13, VERSION.TLS12],
    suites: [0x1301, 0xc02f],
    serverName: "example.test",
  });
  // Record header
  assert.equal(hello[0], 0x16, "handshake record type");
  assert.equal(hello.readUInt16BE(3), hello.length - 5, "record length matches");
  // Handshake header
  assert.equal(hello[5], 0x01, "ClientHello type");
  assert.equal(hello.readUIntBE(6, 3), hello.length - 9, "handshake length matches");
});

test("built ClientHello advertises SNI, supported_versions and key_share", () => {
  const hello = buildClientHello({
    supportedVersions: [VERSION.TLS13, VERSION.TLS12],
    suites: [0x1301],
    serverName: "svc.internal",
  });
  const body = hello.subarray(9);
  const c = new Cursor(body);
  c.readU16(); // legacy version
  c.skip(32); // random
  c.readVec8(); // session id
  c.readVec16(); // suites
  c.readVec8(); // compression
  const extBlock = c.readVec16();
  const names = new Set<string>();
  const ec = new Cursor(extBlock);
  while (!ec.done) {
    const type = ec.readU16();
    ec.readVec16();
    names.add(type.toString(16));
  }
  assert.ok(names.has("0"), "SNI extension present");
  assert.ok(names.has("2b"), "supported_versions present");
  assert.ok(names.has("33"), "key_share present");
});

test("parseServerHello resolves TLS 1.3 version from supported_versions", () => {
  // Hand-built ServerHello: version field 0x0303, supported_versions 0x0304.
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]), // legacy version
    Buffer.alloc(32, 7), // random
    Buffer.from([0]), // session id length
    Buffer.from([0x13, 0x01]), // TLS_AES_128_GCM_SHA256
    Buffer.from([0]), // compression
    // extensions: supported_versions = 0x0304
    Buffer.from([0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]),
  ]);
  const info = parseServerHello(body);
  assert.equal(info.version, VERSION.TLS13);
  assert.equal(info.cipherSuite, 0x1301);
  assert.equal(info.secureRenegotiation, false);
});

test("parseServerHello flags RFC 5746 secure renegotiation", () => {
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 1),
    Buffer.from([0]),
    Buffer.from([0xc0, 0x2f]),
    Buffer.from([0]),
    // renegotiation_info (0xff01) with a zero-length renegotiated_connection
    Buffer.from([0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00]),
  ]);
  const info = parseServerHello(body);
  assert.equal(info.version, VERSION.TLS12);
  assert.equal(info.secureRenegotiation, true);
});

test("splitRecords reassembles fragmented and partial records", () => {
  const record1 = Buffer.concat([Buffer.from([0x16, 0x03, 0x03, 0x00, 0x02]), Buffer.from([0xaa, 0xbb])]);
  const record2 = Buffer.concat([Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02]), Buffer.from([0x02, 0x28])]);
  const { records, rest } = splitRecords(Buffer.concat([record1, record2, Buffer.from([0x16, 0x03])]));
  assert.equal(records.length, 2);
  assert.equal(records[0]!.type, 0x16);
  assert.equal(records[1]!.type, 0x15);
  assert.equal(rest.length, 2, "incomplete record kept as leftover");
});

test("HandshakeReader assembles a message split across records", () => {
  // A HelloRequest (type 0x00, empty body) split mid-header across two pushes.
  const message = Buffer.from([0x00, 0x00, 0x00, 0x00]);
  const reader = new HandshakeReader();
  assert.equal(reader.push(message.subarray(0, 2)).length, 0, "no message yet");
  const messages = reader.push(message.subarray(2));
  assert.equal(messages.length, 1);
  assert.equal(messages[0]!.kind, "hello_request");
});

test("parseAlert decodes level and description", () => {
  assert.deepEqual(parseAlert(Buffer.from([0x02, 0x46])), { level: 2, description: 70 });
});

test("Cursor throws on truncated reads", () => {
  const c = new Cursor(Buffer.from([0x00]));
  assert.throws(() => c.readU16(), /truncated/);
});

test("readDer rejects overrunning lengths", () => {
  // SEQUENCE claiming 5 bytes but only 1 provided
  assert.throws(() => readDer(Buffer.from([0x30, 0x05, 0x00])), /overruns|truncated/i);
});

/** Build a minimal but structurally valid OCSPResponse with a given status. */
function buildOcsp(status: "good" | "revoked"): Buffer {
  // Minimal DER helpers local to the test.
  const len = (n: number): Buffer =>
    n < 0x80 ? Buffer.from([n]) : Buffer.from([0x81, n]);
  const tlv = (tag: number, value: Buffer): Buffer =>
    Buffer.concat([Buffer.from([tag]), len(value.length), value]);
  const seq = (...children: Buffer[]): Buffer => tlv(0x30, Buffer.concat(children));

  // GeneralizedTime "20260101000000Z" (what real OCSP responders emit)
  const time = tlv(0x18, Buffer.from("20260101000000Z", "ascii"));
  const nextTime = tlv(0x18, Buffer.from("20270101000000Z", "ascii"));

  // CertID: SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serial }
  const certId = seq(
    seq(tlv(0x06, Buffer.from([0x2b, 0x0e, 0x03, 0x02, 0x1a])), tlv(0x05, Buffer.alloc(0))),
    tlv(0x04, Buffer.alloc(20, 1)),
    tlv(0x04, Buffer.alloc(20, 2)),
    tlv(0x02, Buffer.from([0x01])),
  );

  // ResponseData ::= SEQUENCE { responderID, producedAt, responses, [1] extensions }
  // responderID byName [1] { Name }
  const responderName = seq(seq(seq(tlv(0x06, Buffer.from([0x55, 0x04, 0x03])), tlv(0x0c, Buffer.from("test")))),
  );
  const responderId = tlv(0xa1, responderName);
  const single = seq(
    certId,
    status === "good" ? tlv(0x80, Buffer.alloc(0)) : tlv(0xa1, time),
    time,
    tlv(0xa0, nextTime),
  );
  const tbs = seq(responderId, time, seq(single));
  const basic = seq(tbs, seq(tlv(0x06, Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])), tlv(0x05, Buffer.alloc(0))), tlv(0x03, Buffer.from([0x00])));
  const responseBytes = tlv(0xa0, seq(
    tlv(0x06, Buffer.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01])),
    tlv(0x04, basic),
  ));
  return seq(tlv(0x0a, Buffer.from([0x00])), responseBytes);
}

test("parseOcspResponse reads a good staple", () => {
  const summary = parseOcspResponse(buildOcsp("good"));
  assert.equal(summary.responseStatus, 0);
  assert.equal(summary.leafStatus, "good");
  assert.equal(summary.thisUpdate, "2026-01-01T00:00:00.000Z");
});

test("parseOcspResponse reads a revoked staple", () => {
  const summary = parseOcspResponse(buildOcsp("revoked"));
  assert.equal(summary.leafStatus, "revoked");
});

test("parseOcspResponse reports malformed input instead of throwing", () => {
  const summary = parseOcspResponse(Buffer.from([0x30, 0x02, 0xff, 0xff]));
  assert.ok(summary.error !== undefined);
});

test("parseOcspResponse decodes a byName responderId", () => {
  const der = buildOcsp("good");
  const summary = parseOcspResponse(der);
  // buildOcsp uses a byName [1] Name with CN=test.
  assert.equal(summary.producerName, "CN=test");
});

test("parseOcspResponse decodes a revocation reason [0] EXPLICIT", () => {
  const len = (n: number): Buffer => (n < 0x80 ? Buffer.from([n]) : Buffer.from([0x81, n]));
  const tlv = (t: number, v: Buffer): Buffer => Buffer.concat([Buffer.from([t]), len(v.length), v]);
  const seq = (...c: Buffer[]): Buffer => tlv(0x30, Buffer.concat(c));
  const time = tlv(0x18, Buffer.from("20260101000000Z", "ascii"));
  const certId = seq(
    seq(tlv(0x06, Buffer.from([0x2b, 0x0e, 0x03, 0x02, 0x1a])), tlv(0x05, Buffer.alloc(0))),
    tlv(0x04, Buffer.alloc(20, 1)),
    tlv(0x04, Buffer.alloc(20, 2)),
    tlv(0x02, Buffer.from([1])),
  );
  const revoked = tlv(0xa1, Buffer.concat([time, tlv(0xa0, tlv(0x0a, Buffer.from([1])))]));
  const single = seq(certId, revoked, time, tlv(0xa0, time));
  const tbs = seq(tlv(0x82, Buffer.alloc(20, 9)), time, seq(single));
  const basic = seq(
    tbs,
    seq(tlv(0x06, Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])), tlv(0x05, Buffer.alloc(0))),
    tlv(0x03, Buffer.from([0])),
  );
  const rb = tlv(0xa0, seq(
    tlv(0x06, Buffer.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01])),
    tlv(0x04, basic),
  ));
  const full = seq(tlv(0x0a, Buffer.from([0])), rb);
  const summary = parseOcspResponse(full);
  assert.equal(summary.leafStatus, "revoked");
  assert.equal(summary.revocationReason, 1);
});
