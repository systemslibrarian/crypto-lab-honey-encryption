/**
 * PBKDF2-HMAC-SHA-256 (RFC 8018 section 5.2).
 *
 *   DK = T_1 || T_2 || ... ,  T_i = U_1 XOR U_2 XOR ... XOR U_c
 *   U_1 = PRF(P, S || INT_32_BE(i)),  U_j = PRF(P, U_{j-1})
 *
 * Checked against the two PBKDF2-HMAC-SHA-256 vectors in RFC 7914 section 11
 * and against WebCrypto over random inputs — see pbkdf2.test.ts.
 */

import { DIGEST_BYTES } from './sha256';
import { HmacSha256Key } from './hmac';

const u = new Uint8Array(DIGEST_BYTES);
const t = new Uint8Array(DIGEST_BYTES);

/**
 * Derive `dkLen` bytes using an already-built HMAC key.
 *
 * The key object carries the password's cached ipad/opad states, so a caller
 * sweeping many salts under one password builds it once. `salt` must be at
 * most 51 bytes so that salt || counter fits hmac.ts's single-block path.
 */
export function pbkdf2WithKey(
  key: HmacSha256Key,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Uint8Array {
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error(`pbkdf2: iterations must be a positive integer, got ${iterations}`);
  }
  if (!Number.isInteger(dkLen) || dkLen < 1) {
    throw new Error(`pbkdf2: dkLen must be a positive integer, got ${dkLen}`);
  }
  if (salt.length > 51) {
    throw new Error(`pbkdf2: salt of ${salt.length} bytes exceeds this implementation`);
  }
  const out = new Uint8Array(dkLen);
  const msg = new Uint8Array(salt.length + 4);
  msg.set(salt, 0);
  const blocks = Math.ceil(dkLen / DIGEST_BYTES);
  for (let bi = 1; bi <= blocks; bi++) {
    // INT_32_BE(bi)
    msg[salt.length] = (bi >>> 24) & 0xff;
    msg[salt.length + 1] = (bi >>> 16) & 0xff;
    msg[salt.length + 2] = (bi >>> 8) & 0xff;
    msg[salt.length + 3] = bi & 0xff;
    key.mac(msg, u);
    t.set(u);
    for (let i = 1; i < iterations; i++) {
      key.mac(u, u);
      for (let j = 0; j < DIGEST_BYTES; j++) t[j]! ^= u[j]!;
    }
    const off = (bi - 1) * DIGEST_BYTES;
    out.set(t.subarray(0, Math.min(DIGEST_BYTES, dkLen - off)), off);
  }
  return out;
}

/** PBKDF2-HMAC-SHA-256 over a password given as bytes. */
export function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Uint8Array {
  return pbkdf2WithKey(new HmacSha256Key(password), salt, iterations, dkLen);
}

/** The HMAC key for a password given as a string, encoded UTF-8. */
export function keyForPassword(password: string): HmacSha256Key {
  return new HmacSha256Key(new TextEncoder().encode(password));
}
