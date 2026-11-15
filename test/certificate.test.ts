/**
 * Certificate summarisation tests, using the lab's real generated certificates.
 *
 * The cases that matter are the ones a checkup exists to catch: expiry,
 * SHA-1 signatures, undersized keys, and a chain that is missing its
 * intermediates. They are exercised against genuine X.509 rather than stubs,
 * because the ASN.1 parsing is the part most likely to be wrong.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { summarizeCertificate, certificateWarnings } from '../src/tls/certificate.ts';

const here = dirname(fileURLToPath(import.meta.url));
const certs = resolve(here, '..', 'lab', 'certs');
const skip = !existsSync(resolve(certs, 'server.pem')) || !existsSync(resolve(certs, 'weak.pem'));

test('a healthy leaf is summarised accurately', { skip }, () => {
  const c = summarizeCertificate([readFileSync(resolve(certs, 'server.pem'), 'utf8')]);
  assert.ok(c);
  assert.equal(c!.keyType, 'rsa');
  assert.equal(c!.keySize, 2048);
  assert.match(c!.signatureAlgorithm, /sha256/i);
  assert.equal(c!.sha1Signature, false);
  assert.equal(c!.expired, false);
  assert.ok(c!.daysUntilExpiry > 0);
  assert.equal(c!.subject, 'CN=localhost');
  assert.equal(c!.issuer, 'CN=TLS Checkup Lab CA');
  assert.ok(c!.subjectAltNames.some((n) => n.includes('localhost')));
});

test('a SHA-1 certificate with a 1024-bit key is flagged on three counts', { skip }, () => {
  const c = summarizeCertificate([readFileSync(resolve(certs, 'weak.pem'), 'utf8')])!;
  assert.equal(c.keySize, 1024);
  assert.equal(c.sha1Signature, true);
  assert.equal(c.selfSigned, true);
  const w = certificateWarnings(c);
  assert.ok(w.some((x) => /SHA-1/.test(x)), w.join('; '));
  assert.ok(w.some((x) => /1024 bits/.test(x)), w.join('; '));
  assert.ok(w.some((x) => /self-signed/.test(x)), w.join('; '));
});

test('a self-signed certificate is not also reported as missing intermediates', { skip }, () => {
  const c = summarizeCertificate([readFileSync(resolve(certs, 'weak.pem'), 'utf8')])!;
  const w = certificateWarnings(c);
  assert.ok(!w.some((x) => /no intermediate/.test(x)), `self-signed cert must not get the chain warning: ${w.join('; ')}`);
});

test('a non-self-signed single-certificate chain warns about intermediates', { skip }, () => {
  const c = summarizeCertificate([readFileSync(resolve(certs, 'server.pem'), 'utf8')])!;
  const w = certificateWarnings(c);
  assert.ok(w.some((x) => /no intermediate/.test(x)));
});

test('garbage and empty chains return undefined rather than throwing', () => {
  assert.equal(summarizeCertificate([]), undefined);
  assert.equal(summarizeCertificate(['not a certificate']), undefined);
  assert.equal(summarizeCertificate(['-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----']), undefined);
});
