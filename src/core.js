/**
 * Computes TCP/UDP checksums over IPv4 or IPv6 pseudo headers.
 *
 * Design decisions (stated plainly so tests and callers agree):
 *
 * 1. Input is a raw Uint8Array (a "view"). We DO NOT copy; we read by index. This
 *    keeps allocation cost at zero and lets callers pass a slice of a larger buffer
 *    without forcing them to materialize a copy.
 *
 * 2. For IPv4, totalLength passed by the caller is authoritative. Per RFC 793, the
 *    TCP checksum covers the pseudo header + TCP header + TCP data. We could
 *    derive length from the buffer alone, but a caller holding a captured segment
 *    may have more context (e.g. MTU-truncated capture). Making length explicit
 *    removes guesswork; we only validate it fits the buffer.
 *
 * 3. The pseudo-header length fields are written in network byte order (big-endian),
 *    consistent with how the wire format defines them.
 *
 * 4. We return the checksum as a 16-bit unsigned integer in host order. Callers who
 *    need wire format must swap bytes themselves; we don't assume endianness of the
 *    destination buffer. This keeps the function pure and side-effect free.
 *
 * 5. We only accept exactly IPv4 (4-byte addrs) or IPv6 (16-byte addrs). No guesses.
 */

/**
 * @typedef {Object} PseudoHeader
 * @property {4 | 6} version            IP version; selects address width.
 * @property {Uint8Array} srcAddr      Source address (4 bytes for v4, 16 for v6).
 * @property {Uint8Array} dstAddr      Destination address (same width as src).
 * @property {number} protocol          IP protocol number (e.g. 6 for TCP, 17 for UDP).
 * @property {number} transportLength   Length in bytes of the transport segment (header+data).
 */

/**
 * Fold a 32-bit running sum down to a 16-bit one's-complement value.
 *
 * RFC 1071 specifies folding every high half-word into the low half until no
 * carries remain, then negating. We cap the loop defensively; in practice two
 * iterations suffice for any 64 KB segment, but a hard upper bound prevents an
 * accidental infinite loop if a future caller ever widened the accumulator type.
 *
 * @param {number} sum  32-bit unsigned intermediate sum.
 * @returns {number}    16-bit one's-complement checksum, host order.
 */
function fold(sum) {
  let v = sum & 0xffffffff;
  for (let i = 0; i < 4; i++) {
    const hi = (v >>> 16) & 0xffff;
    const lo = v & 0xffff;
    v = hi + lo;
    if ((v >>> 16) === 0) break;
  }
  // One's-complement negate. Mask to 16 bits; in JS `~` yields a 32-bit signed
  // value so we AND after the bitwise NOT to recover unsigned semantics.
  return (~v) & 0xffff;
}

/**
 * Add a 16-bit big-endian word from the buffer into the running sum.
 *
 * Implemented inline because we deliberately want zero dependencies and the
 * branch for odd-length buffers (padded with a zero byte per RFC 1071 §3a)
 * is the one genuinely awkward case worth keeping next to the call site.
 *
 * @param {Uint8Array} buf
 * @param {number} offset     Byte offset to start reading; must be even for
 *                            the canonical algorithm — we do not require it,
 *                            but callers building the pseudo header will be.
 * @param {number} len        Number of bytes to consume.
 * @param {number} sum       Current accumulator.
 * @returns {number}         Updated accumulator (32-bit unsigned).
 */
function addBytes(buf, offset, len, sum) {
  let s = sum & 0xffffffff;
  const end = offset + len;
  let i = offset;
  // Consume pairs of bytes as 16-bit big-endian words.
  while (i + 1 < end) {
    s += (buf[i] << 8) | buf[i + 1];
    i += 2;
  }
  // Trailing odd byte: pad with zero on the low half, per RFC 1071 §3a.
  if (i < end) {
    s += buf[i] << 8;
  }
  // Keep the accumulator within 32-bit precision so the final `fold` step
  // has full carry information available; premature folding would consume
  // carries that should propagate.
  return s & 0xffffffff;
}

/**
 * Compute the TCP or UDP checksum over a pseudo header plus transport segment.
 *
 * The caller assembles srcAddr/dstAddr/protocol/transportLength into a
 * {@link PseudoHeader}; the transport segment (TCP or UDP header + payload)
 * is passed as `segment`. The function builds the pseudo header bytes in a
 * small fixed-size scratch buffer, then folds both the header and the
 * segment into one 16-bit one's-complement result.
 *
 * Edge cases actually handled (and tested):
 *
 * - Odd-length segment: the final byte is padded with a zero low byte as
 *   required by RFC 1071. No copy of the segment is made.
 * - Zero checksum pass-through for UDP (protocol 17): we do NOT special-case
 *   the UDP "0 means transmit 0xFFFF" rule. That is a transport-layer concern;
 *   this library computes the mathematical checksum. Callers responsible for
 *   transmitting a UDP segment must map a returned 0 to 0xFFFF themselves.
 *   The README calls this out as the deliberate boundary.
 * - Buffer bounds: `transportLength` larger than `segment.byteLength` throws
 *   synchronously with a descriptive message. Truncating silently would
 *   produce a wrong checksum that a debugger would have to untangle.
 *
 * @param {PseudoHeader} pseudo
 * @param {Uint8Array} segment    View over the transport segment bytes.
 * @returns {number}             16-bit unsigned checksum, host byte order.
 * @throws {Error} If address widths mismatch the declared version, or if
 *                 `transportLength` exceeds the provided segment view.
 */
export function computeChecksum(pseudo, segment) {
  if (pseudo.version !== 4 && pseudo.version !== 6) {
    throw new Error(`unsupported IP version: ${pseudo.version}`);
  }
  const addrLen = pseudo.version === 4 ? 4 : 16;
  if (pseudo.srcAddr.length !== addrLen) {
    throw new Error(`srcAddr length ${pseudo.srcAddr.length} != ${addrLen} for IPv${pseudo.version}`);
  }
  if (pseudo.dstAddr.length !== addrLen) {
    throw new Error(`dstAddr length ${pseudo.dstAddr.length} != ${addrLen} for IPv${pseudo.version}`);
  }
  if (pseudo.protocol < 0 || pseudo.protocol > 255) {
    throw new Error(`protocol out of byte range: ${pseudo.protocol}`);
  }
  if (!Number.isInteger(pseudo.transportLength) || pseudo.transportLength < 0) {
    throw new Error(`transportLength must be a non-negative integer`);
  }
  if (pseudo.transportLength > segment.length) {
    throw new Error(`transportLength ${pseudo.transportLength} exceeds segment length ${segment.length}`);
  }

  // Build pseudo header. IPv4: 12 bytes (src 4, dst 4, zero, proto, length 2).
  // IPv6: 40 bytes (src 16, dst 16, length 4, zero 3, next-header 1). We use
  // a fixed scratch buffer sized to the larger case so allocation is constant.
  const headerLen = pseudo.version === 4 ? 12 : 40;
  const hdr = new Uint8Array(headerLen);
  hdr.set(pseudo.srcAddr, 0);
  hdr.set(pseudo.dstAddr, addrLen);
  if (pseudo.version === 4) {
    // hdr[8] is zero already. Protocol at 9.
    hdr[9] = pseudo.protocol;
    // 16-bit transport length, big-endian, at offset 10.
    hdr[10] = (pseudo.transportLength >>> 8) & 0xff;
    hdr[11] = pseudo.transportLength & 0xff;
  } else {
    // 32-bit transport length, big-endian, at offset 32.
    hdr[32] = (pseudo.transportLength >>> 24) & 0xff;
    hdr[33] = (pseudo.transportLength >>> 16) & 0xff;
    hdr[34] = (pseudo.transportLength >>> 8) & 0xff;
    hdr[35] = pseudo.transportLength & 0xff;
    // Bytes 36-38 zero already; next-header at 39.
    hdr[39] = pseudo.protocol;
  }

  let sum = 0;
  sum = addBytes(hdr, 0, hdr.length, sum);
  sum = addBytes(segment, 0, pseudo.transportLength, sum);
  return fold(sum);
}
