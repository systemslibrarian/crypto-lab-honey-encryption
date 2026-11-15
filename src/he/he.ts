/**
 * Honey encryption — the DTE-then-encrypt construction of Figure 4 in
 * Juels and Ristenpart, IACR ePrint 2014/155 (section 5):
 *
 *   HEnc(K, M):  S <- encode(M);  R <- random n bits;  C2 <- H(R, K) XOR S
 *                return (R, C2)
 *   HDec(K, (R, C2)):  S <- C2 XOR H(R, K);  return decode(S)
 *
 * The cipher is a one-time pad from a hash of (R, K), so decryption cannot
 * fail: every key yields some seed, and every seed decodes to a message. There
 * is no tag to check and nothing to reject.
 *
 * The paper notes that one should apply a password-based key-derivation
 * function to K first and omits it for simplicity. This lab does not omit it —
 * H is built on PBKDF2-HMAC-SHA-256 — but it uses a DELIBERATELY LOW iteration
 * count so the brute-force exhibits finish in a browser. Honey encryption is
 * about what happens when the key-derivation cost is not enough; a lab that
 * made the KDF expensive would be demonstrating the other defence.
 */

import { decode, encode, SEED_SPACE, type RandomSource, cryptoRandom } from './dte';
import { keyForPassword, pbkdf2WithKey } from './pbkdf2';
import type { HmacSha256Key } from './hmac';

/**
 * PBKDF2 iterations for H.
 *
 * 100 is far below any production figure (RFC 8018 wants orders of magnitude
 * more, and OWASP's current advice for PBKDF2-HMAC-SHA-256 is in the hundreds
 * of thousands). It is low ON PURPOSE: exhibit 5 runs twenty thousand trials
 * of a hundred decryptions each, and at a realistic iteration count that is
 * hours of browser time. The page says so where the number appears.
 */
export const PBKDF2_ITERATIONS = 100;

/** The length of R in bytes. R is the salt handed to PBKDF2. */
export const R_BYTES = 16;

/** A honey-encryption ciphertext: the nonce R and the masked seed C2. */
export interface HeCiphertext {
  /** n random bits, n = 128. Also the PBKDF2 salt. */
  R: Uint8Array;
  /** The seed XORed with the pad, as a 64-bit integer. */
  C2: bigint;
}

function assertCiphertext(c: HeCiphertext): void {
  if (c.R.length !== R_BYTES) {
    throw new Error(`he: R must be ${R_BYTES} bytes, got ${c.R.length}`);
  }
  if (c.C2 < 0n || c.C2 >= SEED_SPACE) {
    throw new Error(`he: C2 outside [0, 2^64): ${c.C2}`);
  }
}

/**
 * H(R, K): the first 8 bytes, big-endian, of
 * PBKDF2-HMAC-SHA-256(password = K as UTF-8, salt = R, 100 iterations).
 *
 * Big-endian matters. Reading the same 8 bytes little-endian is a different
 * pad, and a page that did so would still produce valid cards for every
 * password — the exhibits would look right and the published vectors would be
 * wrong. That is mutation (5) in scripts/mutate.mjs.
 *
 * Synchronous, because a brute-force exhibit evaluates it millions of times.
 * See sha256.ts for why this does not go through WebCrypto, and pbkdf2.test.ts
 * for the vectors that hold it to RFC 8018.
 */
export function H(R: Uint8Array, K: string): bigint {
  return hWithKey(R, keyForPassword(K));
}

/**
 * H with the password's HMAC key already built.
 *
 * A trial loop sweeps thousands of salts under a fixed handful of passwords,
 * so it builds each key once and calls this. Identical output to `H`.
 */
export function hWithKey(R: Uint8Array, key: HmacSha256Key): bigint {
  const bytes = pbkdf2WithKey(key, R, PBKDF2_ITERATIONS, 8);
  let v = 0n;
  for (const byte of bytes) v = (v << 8n) | BigInt(byte);
  return v;
}

/** The HMAC key for a password, to be reused across many evaluations of H. */
export { keyForPassword };

/** HEnc. `b` is the size of the message space; `m` the message, in [0, b). */
export function henc(
  K: string,
  m: bigint,
  b: bigint,
  rng: RandomSource = cryptoRandom,
): HeCiphertext {
  const S = encode(m, b, rng);
  const R = rng(R_BYTES);
  return { R, C2: H(R, K) ^ S };
}

/**
 * HEnc with the seed supplied, for the published test vector.
 *
 * Not reachable from the UI: the page always draws its seed. It exists so a
 * test can pin the one encryption whose ciphertext is written down.
 */
export function hencWithSeed(K: string, S: bigint, R: Uint8Array): HeCiphertext {
  if (S < 0n || S >= SEED_SPACE) throw new Error(`he: seed outside [0, 2^64): ${S}`);
  if (R.length !== R_BYTES) throw new Error(`he: R must be ${R_BYTES} bytes, got ${R.length}`);
  return { R, C2: H(R, K) ^ S };
}

/** The seed a key recovers from a ciphertext, before decoding. */
export function hdecSeed(K: string, c: HeCiphertext): bigint {
  assertCiphertext(c);
  return c.C2 ^ H(c.R, K);
}

/**
 * HDec. Returns a message for EVERY key. There is no failure path, and adding
 * one would destroy the property the page exists to show.
 */
export function hdec(K: string, c: HeCiphertext, b: bigint): bigint {
  return decode(hdecSeed(K, c), b);
}

/** HDec with the password's HMAC key already built, for trial loops. */
export function hdecWithKey(key: HmacSha256Key, c: HeCiphertext, b: bigint): bigint {
  assertCiphertext(c);
  return decode(c.C2 ^ hWithKey(c.R, key), b);
}

/**
 * Maul a ciphertext by flipping the top bit of C2.
 *
 * C2 is a one-time pad, so a flipped bit in the ciphertext is a flipped bit in
 * the seed: the top bit moves the seed by 2^63, which is exactly half the seed
 * space, which is exactly b/2 messages. For b = 10^9 that is 500,000,000 —
 * up if the seed's top bit was 0, down if it was 1. The attacker does not
 * learn the card, but the recipient's decryption is moved by an amount the
 * attacker chose, under a password the attacker never had.
 */
export function maulTopBit(c: HeCiphertext): HeCiphertext {
  assertCiphertext(c);
  return { R: Uint8Array.from(c.R), C2: c.C2 ^ (1n << 63n) };
}

/** Hex for a 64-bit value, zero-padded, as the page displays seeds. */
export function hex64(v: bigint): string {
  if (v < 0n || v >= SEED_SPACE) throw new Error(`he: not a 64-bit value: ${v}`);
  return '0x' + v.toString(16).padStart(16, '0');
}

/** Hex for a byte string, as the page displays R. */
export function hexBytes(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/** Parse a hex byte string back to bytes, strictly. */
export function parseHexBytes(s: string, expectBytes: number): Uint8Array {
  const t = s.trim().replace(/^0x/i, '');
  if (t.length !== expectBytes * 2 || !/^[0-9a-fA-F]*$/.test(t)) {
    throw new Error(`he: expected ${expectBytes} hex bytes, got ${JSON.stringify(s)}`);
  }
  const out = new Uint8Array(expectBytes);
  for (let i = 0; i < expectBytes; i++) out[i] = parseInt(t.slice(i * 2, i * 2 + 2), 16);
  return out;
}
