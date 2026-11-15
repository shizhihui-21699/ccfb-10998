/**
 * Wire-format tests for the ClientHello builder and ServerHello parser.
 *
 * These run without any network access: they assert on byte layout and on
 * parsing of hand-built records, including the edge cases a real server can
 * produce (HelloRetryRequest, TLS 1.3 supported_versions, alerts).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  buildClientHello,
  parseServerHello,
  splitRecords,
  versionName,
  NAMED_GROUP,
  generateKeyShare,
  CONTENT_TYPE,
} from '../src/tls/hello.ts';
import { serverHelloRecord, alertRecord, clientHelloRecord, HRR_RANDOM } from './fixtures.ts';

/** Walks the ClientHello we build and returns its parts for assertions. */
function dissect(record: Buffer) {
  assert.equal(record[0], CONTENT_TYPE.handshake, 'record is a handshake');
  const recLen = record.readUInt16BE(3);
  assert.equal(record.length, 5 + recLen, 'record length field matches');
  const hs = record.subarray(5);
  assert.equal(hs[0], 1, 'handshake type is ClientHello');
  const hsLen = hs.readUIntBE(1, 3);
  const body = hs.subarray(4, 4 + hsLen);
  const legacyVersion = body.readUInt16BE(0);
  const random = body.subarray(2, 34);
  const sidLen = body.readUInt8(34);
  const sessionId = body.subarray(35, 35 + sidLen);
  const suiteLen = body.readUInt16BE(35 + sidLen);
  const suites = body.subarray(37 + sidLen, 37 + sidLen + suiteLen);
  const compLen = body.readUInt8(37 + sidLen + suiteLen);
  const extsOff = 38 + sidLen + suiteLen + compLen;
  const extsLen = body.readUInt16BE(extsOff);
  const extBlock = body.subarray(extsOff + 2, extsOff + 2 + extsLen);
  const extensions: Array<{ type: number; data: Buffer }> = [];
  let off = 0;
  while (off + 4 <= extBlock.length) {
    const type = extBlock.readUInt16BE(off);
    const len = extBlock.readUInt16BE(off + 2);
    extensions.push({ type, data: extBlock.subarray(off + 4, off + 4 + len) });
    off += 4 + len;
  }
  const suiteIds: number[] = [];
  for (let i = 0; i + 1 < suites.length; i += 2) suiteIds.push(suites.readUInt16BE(i));
  return { legacyVersion, random, sessionId, suiteIds, extensions, extBlockCovered: off === extBlock.length };
}

test('ClientHello TLS 1.2: suites, SNI, renegotiation_info', () => {
  const suites = [0xc02f, 0xc030, 0x002f];
  const rec = buildClientHello(
    {
      legacyVersion: 0x0303,
      suites,
      offerTls13: false,
      serverName: 'svc.internal.example',
      offerRenegotiationInfo: true,
    },
    crypto,
  );
  const d = dissect(rec);
  assert.equal(d.legacyVersion, 0x0303);
  assert.equal(d.random.length, 32);
  assert.deepEqual(d.suiteIds, suites);
  assert.equal(d.extBlockCovered, true, 'extension block is exactly consumed');

  const sni = d.extensions.find((e) => e.type === 0);
  assert.ok(sni, 'SNI present');
  // host_name_list: 2-byte length, one entry: type 0 + 2-byte name length + name
  assert.equal(sni!.data.readUInt16BE(0), sni!.data.length - 2);
  assert.equal(sni!.data[2], 0);
  const nameLen = sni!.data.readUInt16BE(3);
  assert.equal(sni!.data.subarray(5, 5 + nameLen).toString('utf8'), 'svc.internal.example');

  const ri = d.extensions.find((e) => e.type === 0xff01);
  assert.ok(ri, 'renegotiation_info present');
  assert.deepEqual([...ri!.data], [0], 'empty renegotiated_connection for a fresh client');

  assert.ok(!d.extensions.some((e) => e.type === 43), 'no supported_versions without TLS 1.3');
  assert.ok(!d.extensions.some((e) => e.type === 51), 'no key_share without TLS 1.3');
});

test('ClientHello TLS 1.3: supported_versions and key_share round trip', () => {
  const shares = [generateKeyShare(NAMED_GROUP.x25519, crypto)];
  const rec = buildClientHello(
    {
      legacyVersion: 0x0303,
      suites: [0x1301, 0x1302],
      offerTls13: true,
      supportedVersions: [0x0304, 0x0303],
      keyShares: shares,
      serverName: 'tls13.example',
    },
    crypto,
  );
  const d = dissect(rec);
  const sv = d.extensions.find((e) => e.type === 43);
  assert.ok(sv, 'supported_versions present');
  // ClientHello form: 1-byte vector length, then 2-byte ProtocolVersions.
  assert.equal(sv!.data.readUInt8(0), 4, 'version list length is a single byte');
  assert.equal(sv!.data.readUInt16BE(1), 0x0304);
  assert.equal(sv!.data.readUInt16BE(3), 0x0303);

  const ks = d.extensions.find((e) => e.type === 51);
  assert.ok(ks, 'key_share present');
  const listLen = ks!.data.readUInt16BE(0);
  assert.equal(listLen, ks!.data.length - 2);
  assert.equal(ks!.data.readUInt16BE(2), NAMED_GROUP.x25519);
  const keyLen = ks!.data.readUInt16BE(4);
  assert.equal(keyLen, 32, 'x25519 public key is 32 bytes');
});

test('ClientHello is deterministic when random and session id are injected', () => {
  const opts = {
    legacyVersion: 0x0303,
    suites: [0xc02f],
    offerTls13: false,
    random: Buffer.alloc(32, 0x01),
    sessionId: Buffer.alloc(16, 0x02),
  } as const;
  const a = buildClientHello(opts, crypto);
  const b = buildClientHello(opts, crypto);
  assert.equal(a.toString('hex'), b.toString('hex'));
});

test('minimum suite list is never empty', () => {
  // Offering an empty list is a protocol error; the builder substitutes one.
  const rec = buildClientHello({ legacyVersion: 0x0303, suites: [], offerTls13: false }, crypto);
  const d = dissect(rec);
  assert.equal(d.suiteIds.length, 1);
});

test('parseServerHello: TLS 1.2 record', () => {
  const rec = serverHelloRecord({ legacyVersion: 0x0303, cipherSuite: 0xc02f });
  const sh = parseServerHello(rec.subarray(5));
  assert.ok(sh);
  assert.equal(sh!.selectedVersion, 0x0303);
  assert.equal(sh!.cipherSuite, 0xc02f);
  assert.equal(sh!.helloRetryRequest, false);
  assert.deepEqual(sh!.extensions.types, []);
});

test('parseServerHello: TLS 1.3 uses supported_versions, not the legacy field', () => {
  const rec = serverHelloRecord({ legacyVersion: 0x0303, cipherSuite: 0x1301, selectedVersion: 0x0304 });
  const sh = parseServerHello(rec.subarray(5));
  assert.ok(sh);
  assert.equal(sh!.legacyVersion, 0x0303, 'legacy field stays 1.2');
  assert.equal(sh!.selectedVersion, 0x0304, 'supported_versions wins');
  assert.equal(sh!.extensions.selectedVersion, 0x0304);
  assert.equal(sh!.helloRetryRequest, false);
});

test('parseServerHello: HelloRetryRequest is recognised by its random', () => {
  const rec = serverHelloRecord({
    legacyVersion: 0x0303,
    cipherSuite: 0x1301,
    selectedVersion: 0x0304,
    random: HRR_RANDOM,
    extensions: [{ type: 51, data: Buffer.concat([crypto_u16(24), Buffer.alloc(0)]) }],
  });
  const sh = parseServerHello(rec.subarray(5));
  assert.ok(sh);
  assert.equal(sh!.helloRetryRequest, true);
  assert.deepEqual(sh!.extensions.types, [43, 51]);
  assert.equal(sh!.extensions.keyShare, true);
});

test('parseServerHello: extension presence flags', () => {
  const rec = serverHelloRecord({
    legacyVersion: 0x0303,
    cipherSuite: 0xc02f,
    extensions: [
      { type: 0xff01, data: Buffer.from([0]) },
      { type: 5, data: Buffer.alloc(0) },
      { type: 23, data: Buffer.from([1, 2, 3]) },
    ],
  });
  const sh = parseServerHello(rec.subarray(5));
  assert.ok(sh);
  assert.equal(sh!.extensions.renegotiationInfo, true);
  assert.equal(sh!.extensions.statusRequest, true);
  assert.equal(sh!.extensions.keyShare, false);
});

test('parseServerHello rejects non-ServerHello handshake messages', () => {
  const ch = clientHelloRecord();
  assert.equal(parseServerHello(ch.subarray(5)), null);
  assert.equal(parseServerHello(Buffer.from([2])), null, 'truncated');
  assert.equal(parseServerHello(Buffer.alloc(0)), null);
});

test('parseServerHello tolerates a ServerHello with no extension block', () => {
  // Pre-RFC 5746 server: extensions field is entirely absent.
  const body = Buffer.concat([
    Buffer.from([0x03, 0x01]),
    Buffer.alloc(32, 0x33),
    Buffer.from([0]),
    Buffer.from([0x00, 0x0a]),
    Buffer.from([0]),
  ]);
  const hs = Buffer.concat([Buffer.from([2]), Buffer.from([0, 0, body.length]), body]);
  const sh = parseServerHello(hs);
  assert.ok(sh);
  assert.equal(sh!.cipherSuite, 0x000a);
  assert.equal(sh!.selectedVersion, 0x0301);
});

test('splitRecords handles partial records and multiple records', () => {
  const two = Buffer.concat([alertRecord(2, 40), alertRecord(2, 70)]);
  const { records, rest } = splitRecords(two);
  assert.equal(records.length, 2);
  assert.equal(rest.length, 0);
  assert.deepEqual([...records[0]!.data], [2, 40]);
  assert.deepEqual([...records[1]!.data], [2, 70]);

  const torn = Buffer.concat([alertRecord(2, 40), Buffer.from([21, 3, 3, 0, 2, 2])]);
  const split = splitRecords(torn);
  assert.equal(split.records.length, 1, 'incomplete record is left as rest');
  assert.equal(split.rest.length, 6);
});

test('splitRecords rejects nonsense lengths without throwing', () => {
  const garbage = Buffer.from([22, 3, 3, 0xff, 0xff, 0, 0]);
  const { records } = splitRecords(garbage);
  assert.equal(records.length, 0);
});

test('versionName covers the four versions and unknown ids', () => {
  assert.equal(versionName(0x0301), 'TLSv1.0');
  assert.equal(versionName(0x0302), 'TLSv1.1');
  assert.equal(versionName(0x0303), 'TLSv1.2');
  assert.equal(versionName(0x0304), 'TLSv1.3');
  assert.equal(versionName(0x0300), '0x0300');
});

function crypto_u16(n: number): Buffer {
  return Buffer.from([(n >> 8) & 0xff, n & 0xff]);
}
