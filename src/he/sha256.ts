/**
 * SHA-256 (FIPS 180-4), hand-rolled.
 *
 * Why not WebCrypto: H is the cipher of the honey-encryption construction, so
 * it is the inspectable teaching subject — and the brute-force exhibits need
 * MILLIONS of evaluations. WebCrypto's `deriveBits` is asynchronous, and the
 * per-call promise overhead measured here is roughly seven times the cost of
 * the hashing itself, which puts a twenty-thousand-trial measurement out of
 * reach in a browser.
 *
 * This is real SHA-256, not an approximation of one. It is checked against the
 * FIPS 180-4 digests, against the RFC 7914 PBKDF2 vectors through hmac.ts and
 * pbkdf2.ts, and against WebCrypto's own SHA-256 over random inputs — see
 * sha256.test.ts. If any of those disagree the suite fails; there is no path
 * where the page shows a number this file produced without those checks having
 * passed.
 *
 * The state is carried as eight 32-bit words in an Int32Array and the message
 * schedule in a module-level Int32Array reused by every call, so the hot loop
 * allocates nothing.
 */

/** The first 32 bits of the fractional parts of the cube roots of the first 64 primes. */
const K = new Int32Array([
  0x428a2f98 | 0, 0x71374491 | 0, 0xb5c0fbcf | 0, 0xe9b5dba5 | 0,
  0x3956c25b | 0, 0x59f111f1 | 0, 0x923f82a4 | 0, 0xab1c5ed5 | 0,
  0xd807aa98 | 0, 0x12835b01 | 0, 0x243185be | 0, 0x550c7dc3 | 0,
  0x72be5d74 | 0, 0x80deb1fe | 0, 0x9bdc06a7 | 0, 0xc19bf174 | 0,
  0xe49b69c1 | 0, 0xefbe4786 | 0, 0x0fc19dc6 | 0, 0x240ca1cc | 0,
  0x2de92c6f | 0, 0x4a7484aa | 0, 0x5cb0a9dc | 0, 0x76f988da | 0,
  0x983e5152 | 0, 0xa831c66d | 0, 0xb00327c8 | 0, 0xbf597fc7 | 0,
  0xc6e00bf3 | 0, 0xd5a79147 | 0, 0x06ca6351 | 0, 0x14292967 | 0,
  0x27b70a85 | 0, 0x2e1b2138 | 0, 0x4d2c6dfc | 0, 0x53380d13 | 0,
  0x650a7354 | 0, 0x766a0abb | 0, 0x81c2c92e | 0, 0x92722c85 | 0,
  0xa2bfe8a1 | 0, 0xa81a664b | 0, 0xc24b8b70 | 0, 0xc76c51a3 | 0,
  0xd192e819 | 0, 0xd6990624 | 0, 0xf40e3585 | 0, 0x106aa070 | 0,
  0x19a4c116 | 0, 0x1e376c08 | 0, 0x2748774c | 0, 0x34b0bcb5 | 0,
  0x391c0cb3 | 0, 0x4ed8aa4a | 0, 0x5b9cca4f | 0, 0x682e6ff3 | 0,
  0x748f82ee | 0, 0x78a5636f | 0, 0x84c87814 | 0, 0x8cc70208 | 0,
  0x90befffa | 0, 0xa4506ceb | 0, 0xbef9a3f7 | 0, 0xc67178f2 | 0,
]);

/** The first 32 bits of the fractional parts of the square roots of the first 8 primes. */
export const SHA256_IV = new Int32Array([
  0x6a09e667 | 0, 0xbb67ae85 | 0, 0x3c6ef372 | 0, 0xa54ff53a | 0,
  0x510e527f | 0, 0x9b05688c | 0, 0x1f83d9ab | 0, 0x5be0cd19 | 0,
]);

export const BLOCK_BYTES = 64;
export const DIGEST_BYTES = 32;

/** The message schedule, reused across calls. Never read before being written. */
const W = new Int32Array(64);

/**
 * The compression function, over the sixteen words already placed in `W[0..15]`.
 *
 * Updates `state` in place. Everything is kept in `|0` integer form; `>>>` is
 * used for the right-rotations so the shifted-in bits are zeros rather than
 * sign copies.
 */
export function compress(state: Int32Array): void {
  for (let i = 16; i < 64; i++) {
    const a = W[i - 15]!;
    const b = W[i - 2]!;
    const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
    const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
    W[i] = (W[i - 16]! + s0 + W[i - 7]! + s1) | 0;
  }
  let a = state[0]!, b = state[1]!, c = state[2]!, d = state[3]!;
  let e = state[4]!, f = state[5]!, g = state[6]!, h = state[7]!;
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i]! + W[i]!) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0;
    d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  state[0] = (state[0]! + a) | 0;
  state[1] = (state[1]! + b) | 0;
  state[2] = (state[2]! + c) | 0;
  state[3] = (state[3]! + d) | 0;
  state[4] = (state[4]! + e) | 0;
  state[5] = (state[5]! + f) | 0;
  state[6] = (state[6]! + g) | 0;
  state[7] = (state[7]! + h) | 0;
}

/** Load `block[off .. off+63]` big-endian into the message schedule. */
export function loadBlock(block: Uint8Array, off: number): void {
  for (let i = 0; i < 16; i++) {
    const j = off + i * 4;
    W[i] = ((block[j]! << 24) | (block[j + 1]! << 16) | (block[j + 2]! << 8) | block[j + 3]!) | 0;
  }
}

/** Place sixteen words directly into the message schedule. */
export function loadWords(words: Int32Array): void {
  for (let i = 0; i < 16; i++) W[i] = words[i]!;
}

/** Write the eight state words big-endian into `out` at `off`. */
export function writeState(state: Int32Array, out: Uint8Array, off = 0): void {
  for (let i = 0; i < 8; i++) {
    const v = state[i]!;
    out[off + i * 4] = (v >>> 24) & 0xff;
    out[off + i * 4 + 1] = (v >>> 16) & 0xff;
    out[off + i * 4 + 2] = (v >>> 8) & 0xff;
    out[off + i * 4 + 3] = v & 0xff;
  }
}

/**
 * SHA-256 of a byte string.
 *
 * Straightforward and allocating — the bulk paths go through hmac.ts, which
 * keeps its own buffers. This exists for tests and for one-off use.
 */
export function sha256(msg: Uint8Array): Uint8Array {
  const state = SHA256_IV.slice();
  const full = Math.floor(msg.length / BLOCK_BYTES);
  for (let i = 0; i < full; i++) {
    loadBlock(msg, i * BLOCK_BYTES);
    compress(state);
  }
  const rest = msg.length - full * BLOCK_BYTES;
  // The tail: remaining bytes, 0x80, zeros, then the 64-bit bit length. Two
  // blocks when the remainder leaves no room for the nine trailing bytes.
  const tailBlocks = rest + 9 > BLOCK_BYTES ? 2 : 1;
  const tail = new Uint8Array(tailBlocks * BLOCK_BYTES);
  tail.set(msg.subarray(full * BLOCK_BYTES), 0);
  tail[rest] = 0x80;
  const bits = BigInt(msg.length) * 8n;
  const end = tail.length;
  for (let i = 0; i < 8; i++) {
    tail[end - 1 - i] = Number((bits >> BigInt(8 * i)) & 0xffn);
  }
  for (let i = 0; i < tailBlocks; i++) {
    loadBlock(tail, i * BLOCK_BYTES);
    compress(state);
  }
  const out = new Uint8Array(DIGEST_BYTES);
  writeState(state, out);
  return out;
}
