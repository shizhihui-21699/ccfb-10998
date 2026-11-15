/**
 * Suite classification tests.
 *
 * These encode the judgments the baseline depends on. A regression here is
 * silent and consequential (a weak suite scored strong, or vice versa), so every
 * category of suite the tool expects to meet is pinned by an example.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeSuite, candidateSuitesFor, CANDIDATE_SUITES, isUnsafeSuite } from '../src/tls/suites.ts';

test('TLS 1.3 suites are all strong and marked isTls13', () => {
  for (const id of [0x1301, 0x1302, 0x1303]) {
    const s = describeSuite(id);
    assert.equal(s.strength, 'strong', s.name);
    assert.equal(s.isTls13, true);
    assert.equal(s.family, 'TLS1.3');
    assert.equal(s.forwardSecret, true);
  }
});

test('ECDHE + AEAD is strong and forward secret', () => {
  for (const id of [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0x009e, 0x009f]) {
    const s = describeSuite(id);
    assert.equal(s.strength, 'strong', `${s.name} should be strong`);
    assert.equal(s.forwardSecret, true, `${s.name} should be forward secret`);
    assert.equal(s.authenticated, true);
  }
});

test('static RSA AEAD is weak despite the AEAD mode, because there is no forward secrecy', () => {
  for (const id of [0x009c, 0x009d]) {
    const s = describeSuite(id);
    assert.equal(s.strength, 'weak', `${s.name}: ${s.notes.join('; ')}`);
    assert.equal(s.forwardSecret, false);
    assert.ok(s.notes.some((n) => /forward secrecy/.test(n)), 'reason must mention forward secrecy');
    assert.ok(!s.notes.some((n) => /CBC/.test(n)), `${s.name} is GCM, not CBC`);
  }
});

test('static RSA CBC is weak for both reasons', () => {
  const s = describeSuite(0x002f);
  assert.equal(s.name, 'TLS_RSA_WITH_AES_128_CBC_SHA');
  assert.equal(s.strength, 'weak');
  assert.equal(s.forwardSecret, false);
  assert.match(s.notes.join(' '), /CBC/);
});

test('ECDHE CBC with SHA-1 MAC is weak', () => {
  for (const id of [0xc013, 0xc009, 0x0033]) {
    const s = describeSuite(id);
    assert.equal(s.strength, 'weak', s.name);
    assert.match(s.notes.join(' '), /SHA-1/);
  }
});

test('ECDHE CBC with SHA-256 MAC is acceptable, not weak', () => {
  const s = describeSuite(0xc023); // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
  assert.equal(s.strength, 'acceptable', s.notes.join('; '));
  assert.equal(s.forwardSecret, true);
});

test('RC4, 3DES, NULL and anonymous suites are flagged', () => {
  assert.equal(describeSuite(0x0005).strength, 'insecure', 'RC4-SHA');
  assert.equal(describeSuite(0x0004).strength, 'insecure', 'RC4-MD5');
  assert.equal(describeSuite(0x000a).strength, 'weak', '3DES');
  assert.equal(describeSuite(0x0002).strength, 'null', 'NULL cipher');
  assert.equal(describeSuite(0x0003).strength, 'insecure', 'export');

  const anon = describeSuite(0x0034); // TLS_DH_anon_WITH_AES_128_CBC_SHA
  assert.equal(anon.strength, 'insecure');
  assert.equal(anon.authenticated, false, 'anonymous suites must not count as authenticated');
  assert.equal(anon.family, 'anonymous');
});

test('isUnsafeSuite covers weak, insecure and null but not acceptable', () => {
  assert.equal(isUnsafeSuite(describeSuite(0x002f)), true); // weak
  assert.equal(isUnsafeSuite(describeSuite(0x0005)), true); // insecure
  assert.equal(isUnsafeSuite(describeSuite(0x0002)), true); // null
  assert.equal(isUnsafeSuite(describeSuite(0xc02f)), false); // strong
  assert.equal(isUnsafeSuite(describeSuite(0xc023)), false); // acceptable
});

test('unknown suite ids degrade gracefully', () => {
  const s = describeSuite(0xfe00);
  assert.match(s.name, /UNKNOWN_0xFE00/);
  assert.equal(s.strength, 'unknown');
  assert.equal(s.hex, 'fe00');
});

test('candidateSuitesFor: TLS 1.3 offers only the five 1.3 ids', () => {
  const suites = candidateSuitesFor(0x0304);
  assert.deepEqual(suites.sort((a, b) => a - b), [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]);
});

test('candidateSuitesFor: TLS 1.2 offers ECDHE suites and excludes TLS 1.3 ids', () => {
  const suites = candidateSuitesFor(0x0303);
  assert.ok(suites.includes(0xc02f), 'ECDHE-RSA-AES128-GCM must be offered; ids above 0x1305 are not TLS 1.3');
  assert.ok(suites.includes(0xcca8), 'ChaCha20 must be offered on TLS 1.2');
  for (const id13 of [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]) {
    assert.ok(!suites.includes(id13), `TLS 1.3 id 0x${id13.toString(16)} must not appear in a 1.2 offer`);
  }
});

test('candidateSuitesFor: TLS 1.0/1.1 exclude AEAD/1.3-only suites', () => {
  for (const version of [0x0301, 0x0302]) {
    const suites = candidateSuitesFor(version);
    assert.ok(!suites.includes(0x1301));
    assert.ok(!suites.includes(0xcca8), 'ChaCha20 is a TLS 1.2 construction');
    assert.ok(suites.includes(0xc013), 'ECDHE-RSA-AES128-SHA is valid in TLS 1.0');
    assert.ok(suites.includes(0x002f), 'AES128-SHA is valid in TLS 1.0');
  }
});

test('every candidate suite describes without throwing', () => {
  for (const id of CANDIDATE_SUITES) {
    const s = describeSuite(id);
    assert.equal(typeof s.name, 'string');
    assert.ok(s.name.length > 0);
  }
});

test('candidate list covers the weak suites a legacy fleet actually runs', () => {
  const required = [
    0x000a, // 3DES
    0x0005, // RC4
    0x002f, // static RSA AES-CBC
    0xc013, // ECDHE-RSA-AES128-SHA
  ];
  for (const id of required) {
    assert.ok(CANDIDATE_SUITES.includes(id), `0x${id.toString(16)} must be offered so it can be detected`);
  }
});
