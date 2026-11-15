/**
 * Hand-built TLS byte fixtures. Building these by concatenation (rather than
 * by capturing live traffic) makes the tests independent of any particular
 * OpenSSL build and documents the exact wire layout under test.
 */
import { Buffer } from 'node:buffer';

export function u8(n: number): Buffer {
  return Buffer.from([n & 0xff]);
}
export function u16(n: number): Buffer {
  return Buffer.from([(n >> 8) & 0xff, n & 0xff]);
}
export function u24(n: number): Buffer {
  return Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}

export const HRR_RANDOM = Buffer.from(
  'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c',
  'hex',
);

export interface ShFixture {
  legacyVersion: number;
  selectedVersion?: number;
  cipherSuite: number;
  random?: Buffer;
  sessionId?: Buffer;
  extensions?: Array<{ type: number; data: Buffer }>;
}

export function serverHelloRecord(f: ShFixture): Buffer {
  const random = f.random ?? Buffer.alloc(32, 0x11);
  const sessionId = f.sessionId ?? Buffer.alloc(0);
  const exts: Buffer[] = [];
  if (f.selectedVersion !== undefined) {
    exts.push(Buffer.concat([u16(43), u16(2), u16(f.selectedVersion)]));
  }
  for (const e of f.extensions ?? []) {
    exts.push(Buffer.concat([u16(e.type), u16(e.data.length), e.data]));
  }
  const extsBlock = exts.length ? Buffer.concat([u16(Buffer.concat(exts).length), Buffer.concat(exts)]) : Buffer.alloc(0);
  const body = Buffer.concat([
    u16(f.legacyVersion),
    random,
    u8(sessionId.length),
    sessionId,
    u16(f.cipherSuite),
    u8(0),
    extsBlock,
  ]);
  const hs = Buffer.concat([u8(2), u24(body.length), body]);
  return Buffer.concat([u8(22), u16(f.legacyVersion), u16(hs.length), hs]);
}

export function alertRecord(level: number, description: number): Buffer {
  return Buffer.concat([u8(21), u16(0x0303), u16(2), u8(level), u8(description)]);
}

export function clientHelloRecord(): Buffer {
  // A minimal but well-formed client hello, used to prove our parser can
  // re-read what our builder writes.
  const body = Buffer.concat([
    u16(0x0303),
    Buffer.alloc(32, 0x22),
    u8(0),
    Buffer.concat([u16(2), u16(0x002f)]),
    u8(1),
    u8(0),
    u16(0),
  ]);
  const hs = Buffer.concat([u8(1), u24(body.length), body]);
  return Buffer.concat([u8(22), u16(0x0303), u16(hs.length), hs]);
}
