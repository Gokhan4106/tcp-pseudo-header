# TCP Pseudo Header

Computes the TCP or UDP checksum over an IPv4 or IPv6 pseudo header plus a transport segment. Returns a 16-bit unsigned integer in host byte order; no byte swapping is performed.

## Usage

```js
import { computeChecksum } from 'tcp-pseudo-header';

const segment = Uint8Array.of(0x00, 0x50, 0x1f, 0x90);

const pseudo = {
  version: 4,
  srcAddr: Uint8Array.of(192, 168, 1, 1),
  dstAddr: Uint8Array.of(192, 168, 1, 2),
  protocol: 6,        // TCP
  transportLength: segment.length,
};

const checksum = computeChecksum(pseudo, segment);
// checksum is a Number in [0, 0xffff]; caller writes it to the wire in network order.
```

Exports: `computeChecksum(pseudo, segment) -> number`, and the `PseudoHeader` shape (a plain object; see `src/core.js` for the JSDoc typedef).

## Why this exists

Offloading checksum computation to a small, dependency-free function keeps packet-processing code free of the fiddly bits: building the pseudo header in the correct byte order, padding an odd-length trailing byte per RFC 1071, and folding the 32-bit accumulator down to 16 bits. The trade-off is that this library computes the *mathematical* checksum only — it does not touch your segment buffer, and it does not encode the result for the wire. Callers serialize the 16-bit result themselves.

## The awkward edge

UDP transmits a computed checksum of `0x0000` as `0xFFFF` on the wire (RFC 768). This library deliberately does **not** perform that mapping. It returns the mathematical one's-complement sum; a UDP sender must convert a zero result to `0xFFFF` before transmission. TCP has no such special case (RFC 793 forbids a zero TCP checksum).

The `transportLength` field is authoritative and must fit within the provided `segment` view. If it exceeds `segment.length`, the function throws rather than silently truncating. Bytes beyond `transportLength` inside the view are ignored, so you may pass a slice of a larger buffer.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

