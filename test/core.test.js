import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeChecksum } from '../src/index.js';

/**
 * Tiny reference implementation, written independently of the production
 * `addBytes`/`fold` helpers, used as an oracle in the "known answer" tests.
 * Folding here uses Math.floor so the arithmetic is patently integer-only.
 */
function refChecksum(bytes) {
  let sum = 0;
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    sum += (bytes[i] << 8) | bytes[i + 1];
  }
  if (bytes.length % 2 === 1) {
    sum += bytes[bytes.length - 1] << 8;
  }
  while (sum > 0xffff) {
    sum = (sum & 0xffff) + Math.floor(sum / 0x10000);
  }
  return (~sum) & 0xffff;
}

function v4Header(src, dst, proto, len) {
  return { version: 4, srcAddr: Uint8Array.from(src), dstAddr: Uint8Array.from(dst), protocol: proto, transportLength: len };
}
function v6Header(src, dst, proto, len) {
  return { version: 6, srcAddr: Uint8Array.from(src), dstAddr: Uint8Array.from(dst), protocol: proto, transportLength: len };
}

test('IPv4 zero-length segment yields pseudo-header-only checksum', () => {
  const pseudo = v4Header([192, 168, 1, 1], [192, 168, 1, 2], 6, 0);
  const seg = new Uint8Array(0);
  const got = computeChecksum(pseudo, seg);
  // Pseudo header is exactly 12 bytes; build it and compare to oracle.
  const hdr = new Uint8Array(12);
  hdr.set([192, 168, 1, 1, 192, 168, 1, 2, 0, 6, 0, 0]);
  assert.equal(got, refChecksum(hdr));
});

test('IPv4 odd-length segment pads trailing byte with zero', () => {
  const seg = Uint8Array.from([0x01, 0x02, 0x03]);
  const pseudo = v4Header([10, 0, 0, 1], [10, 0, 0, 2], 6, seg.length);
  const got = computeChecksum(pseudo, seg);
  const hdr = new Uint8Array(12);
  hdr.set([10, 0, 0, 1, 10, 0, 0, 2, 0, 6, 0, 3]);
  const full = new Uint8Array(hdr.length + seg.length + 1); // +1 for pad
  full.set(hdr, 0);
  full.set(seg, hdr.length);
  assert.equal(got, refChecksum(full));
});

test('IPv4 even-length segment matches oracle over full buffer', () => {
  const seg = Uint8Array.from([0x45, 0x00, 0x00, 0x14, 0xab, 0xcd, 0xef, 0x01]);
  const pseudo = v4Header([172, 16, 254, 1], [172, 16, 254, 2], 17, seg.length);
  const got = computeChecksum(pseudo, seg);
  const hdr = new Uint8Array(12);
  hdr.set([172, 16, 254, 1, 172, 16, 254, 2, 0, 17, 0, 8]);
  const full = new Uint8Array(hdr.length + seg.length);
  full.set(hdr, 0);
  full.set(seg, hdr.length);
  assert.equal(got, refChecksum(full));
});

test('IPv6 pseudo header uses 32-bit length and next-header field', () => {
  const src = new Uint8Array(16); src[0] = 0xfe; src[1] = 0x80;
  const dst = new Uint8Array(16); dst[0] = 0xfe; dst[1] = 0x80; dst[15] = 0x01;
  const seg = Uint8Array.from([0x00, 0x50, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00]);
  const pseudo = v6Header(Array.from(src), Array.from(dst), 6, seg.length);
  const got = computeChecksum(pseudo, seg);
  const hdr = new Uint8Array(40);
  hdr.set(src, 0);
  hdr.set(dst, 16);
  hdr[32] = 0; hdr[33] = 0; hdr[34] = 0; hdr[35] = seg.length;
  hdr[39] = 6;
  const full = new Uint8Array(hdr.length + seg.length);
  full.set(hdr, 0);
  full.set(seg, hdr.length);
  assert.equal(got, refChecksum(full));
});

test('checksum is independent of bytes beyond transportLength in the segment view', () => {
  const real = Uint8Array.from([0xaa, 0xbb, 0xcc, 0xdd]);
  const padded = new Uint8Array(8); // extra bytes should be ignored
  padded.set(real, 0);
  const pseudo = v4Header([1, 2, 3, 4], [5, 6, 7, 8], 6, real.length);
  assert.equal(computeChecksum(pseudo, padded), computeChecksum(pseudo, real));
});

test('transportLength exceeding segment throws synchronously', () => {
  const seg = new Uint8Array(2);
  const pseudo = v4Header([1, 1, 1, 1], [2, 2, 2, 2], 6, 3);
  assert.throws(() => computeChecksum(pseudo, seg), /exceeds segment length/);
});

test('IPv4 with wrong srcAddr width throws', () => {
  const pseudo = { version: 4, srcAddr: new Uint8Array(16), dstAddr: new Uint8Array(4), protocol: 6, transportLength: 0 };
  assert.throws(() => computeChecksum(pseudo, new Uint8Array(0)), /srcAddr length 16 != 4/);
});

test('IPv6 with wrong dstAddr width throws', () => {
  const pseudo = { version: 6, srcAddr: new Uint8Array(16), dstAddr: new Uint8Array(4), protocol: 6, transportLength: 0 };
  assert.throws(() => computeChecksum(pseudo, new Uint8Array(0)), /dstAddr length 4 != 16/);
});

test('unsupported IP version throws', () => {
  const pseudo = { version: 5, srcAddr: new Uint8Array(4), dstAddr: new Uint8Array(4), protocol: 6, transportLength: 0 };
  assert.throws(() => computeChecksum(pseudo, new Uint8Array(0)), /unsupported IP version: 5/);
});

test('protocol out of byte range throws', () => {
  const pseudo = v4Header([1, 1, 1, 1], [2, 2, 2, 2], 256, 0);
  assert.throws(() => computeChecksum(pseudo, new Uint8Array(0)), /protocol out of byte range/);
});

test('return type is a 16-bit unsigned integer (Number, not BigInt)', () => {
  const pseudo = v4Header([1, 1, 1, 1], [2, 2, 2, 2], 6, 0);
  const v = computeChecksum(pseudo, new Uint8Array(0));
  assert.equal(typeof v, 'number');
  assert.ok(Number.isInteger(v));
  assert.ok(v >= 0 && v <= 0xffff);
});

test('checksum is stable across repeated calls (purity)', () => {
  const pseudo = v4Header([8, 8, 8, 8], [1, 1, 1, 1], 17, 4);
  const seg = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);
  const a = computeChecksum(pseudo, seg);
  const b = computeChecksum(pseudo, seg);
  assert.equal(a, b);
});
