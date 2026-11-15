/**
 * HMAC-SHA-256 (RFC 2104), with the key schedule cached.
 *
 * PBKDF2 calls HMAC once per iteration under the SAME key, and a brute-force
 * exhibit calls PBKDF2 once per (password, salt) pair with a small set of
 * passwords and a fresh salt each time. So the ipad/opad blocks — which depend
 * only on the key — are compressed ONCE when the key object is built and
 * reused for every message thereafter. That turns the per-iteration cost into
 * two compressions, which is what makes the twenty-thousand-trial measurement
 * finish.
 *
 * Caching a midstate is an optimisation, not a shortcut: the value produced is
 * bit-identical to the definition, and hmac.test.ts checks it against
 * WebCrypto over random keys and messages, including keys longer than the
 * block size.
 */

import {
  BLOCK_BYTES,
  DIGEST_BYTES,
  SHA256_IV,
  compress,
  loadBlock,
  loadWords,
  sha256,
  writeState,
} from './sha256';

const IPAD = 0x36;
const OPAD = 0x5c;

/** Scratch shared by every HmacSha256Key; single-threaded by construction. */
const scratch = new Uint8Array(BLOCK_BYTES * 2);
const words = new Int32Array(16);
const innerState = new Int32Array(8);
const outerState = new Int32Array(8);

export class HmacSha256Key {
  /** The state after absorbing the ipad block. */
  private readonly ip = new Int32Array(8);
  /** The state after absorbing the opad block. */
  private readonly op = new Int32Array(8);

  constructor(key: Uint8Array) {
    // RFC 2104: a key longer than the block size is replaced by its own hash.
    const k = key.length > BLOCK_BYTES ? sha256(key) : key;
    for (const [pad, dst] of [
      [IPAD, this.ip],
      [OPAD, this.op],
    ] as const) {
      dst.set(SHA256_IV);
      for (let i = 0; i < 16; i++) {
        let w = 0;
        for (let j = 0; j < 4; j++) {
          const idx = i * 4 + j;
          const kb = idx < k.length ? k[idx]! : 0;
          w = (w << 8) | (kb ^ pad);
        }
        words[i] = w | 0;
      }
      loadWords(words);
      compress(dst);
    }
  }

  /**
   * HMAC of `msg`, written into `out` (32 bytes).
   *
   * `msg` must be at most 55 bytes, which is what fits beside the nine
   * trailing bytes in the single block following the pad block. Both callers
   * in this lab are inside that: PBKDF2's first message is
   * salt (16 bytes) + a 4-byte counter, and every later one is a 32-byte
   * digest. The bound is asserted rather than handled, so a future caller
   * with a longer message gets an error instead of a wrong MAC.
   */
  mac(msg: Uint8Array, out: Uint8Array): void {
    if (msg.length > BLOCK_BYTES - 9) {
      throw new Error(`hmac: message of ${msg.length} bytes exceeds this fast path`);
    }
    if (out.length < DIGEST_BYTES) {
      throw new Error(`hmac: output needs ${DIGEST_BYTES} bytes`);
    }
    // Inner: H((K^ipad) || msg). The pad block is already absorbed.
    innerState.set(this.ip);
    scratch.fill(0, 0, BLOCK_BYTES);
    scratch.set(msg, 0);
    scratch[msg.length] = 0x80;
    writeLengthBits(scratch, 0, (BLOCK_BYTES + msg.length) * 8);
    loadBlock(scratch, 0);
    compress(innerState);

    // Outer: H((K^opad) || innerDigest).
    outerState.set(this.op);
    scratch.fill(0, 0, BLOCK_BYTES);
    writeState(innerState, scratch, 0);
    scratch[DIGEST_BYTES] = 0x80;
    writeLengthBits(scratch, 0, (BLOCK_BYTES + DIGEST_BYTES) * 8);
    loadBlock(scratch, 0);
    compress(outerState);

    writeState(outerState, out, 0);
  }
}

/** Write a 64-bit big-endian bit length into the last eight bytes of a block. */
function writeLengthBits(buf: Uint8Array, blockOff: number, bits: number): void {
  const end = blockOff + BLOCK_BYTES;
  // Bit lengths here are far below 2^32, so the high word is always zero.
  buf[end - 8] = 0;
  buf[end - 7] = 0;
  buf[end - 6] = 0;
  buf[end - 5] = 0;
  buf[end - 4] = (bits >>> 24) & 0xff;
  buf[end - 3] = (bits >>> 16) & 0xff;
  buf[end - 2] = (bits >>> 8) & 0xff;
  buf[end - 1] = bits & 0xff;
}

/** One-shot HMAC-SHA-256, for tests and one-off use. */
export function hmacSha256(key: Uint8Array, msg: Uint8Array): Uint8Array {
  const out = new Uint8Array(DIGEST_BYTES);
  new HmacSha256Key(key).mac(msg, out);
  return out;
}
