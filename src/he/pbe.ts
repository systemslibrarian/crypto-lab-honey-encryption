/**
 * Ordinary password-based encryption, for the comparison that makes honey
 * encryption legible.
 *
 * The card is stored the obvious way — sixteen ASCII digits — and encrypted
 * under a PBKDF2-derived key with AES-CTR or AES-GCM. Both give a brute-force
 * search exactly what honey encryption takes away: a way to RECOGNISE the
 * right password.
 *
 *   AES-CTR — no tag, so a wrong password yields sixteen arbitrary bytes.
 *             They are ASCII digits with probability (10/256)^16, about
 *             2.9e-23, so in practice the first all-digit result is the
 *             plaintext and the search is over.
 *   AES-GCM — authenticated, so a wrong password is REJECTED outright. The
 *             attacker does not even have to look at the plaintext.
 *
 * Same KDF and same iteration count as honey encryption's H, so the comparison
 * isolates the one thing that differs: whether a wrong key produces something
 * that could be a card.
 */

import { PBKDF2_ITERATIONS } from './he';
import { buf } from './bufsrc';

export const SALT_BYTES = 16;
export const CTR_IV_BYTES = 16;
export const GCM_IV_BYTES = 12;

export type PbeMode = 'aes-ctr' | 'aes-gcm';

export interface PbeCiphertext {
  mode: PbeMode;
  salt: Uint8Array;
  iv: Uint8Array;
  ct: Uint8Array;
}

/**
 * The outcome of one ordinary decryption attempt.
 *
 * `rejected` is a distinct state from "produced bytes that are not a card".
 * Collapsing them would erase the difference between CTR and GCM, which is
 * half of what exhibit 1 teaches — and is mutation (9).
 */
export type PbeAttempt =
  | { kind: 'rejected' }
  | { kind: 'plaintext'; bytes: Uint8Array; text: string; allDigits: boolean };

async function deriveKey(
  password: string,
  salt: Uint8Array,
  mode: PbeMode,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: buf(Uint8Array.from(salt)),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    material,
    { name: mode === 'aes-ctr' ? 'AES-CTR' : 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function params(mode: PbeMode, iv: Uint8Array): AesCtrParams | AesGcmParams {
  return mode === 'aes-ctr'
    ? { name: 'AES-CTR', counter: buf(Uint8Array.from(iv)), length: 64 }
    : { name: 'AES-GCM', iv: buf(Uint8Array.from(iv)), tagLength: 128 };
}

/** Encrypt a card number as ASCII under `password`. */
export async function pbeEncrypt(
  password: string,
  card: string,
  mode: PbeMode,
  rng: (n: number) => Uint8Array = (n) => crypto.getRandomValues(new Uint8Array(n)),
): Promise<PbeCiphertext> {
  const salt = rng(SALT_BYTES);
  const iv = rng(mode === 'aes-ctr' ? CTR_IV_BYTES : GCM_IV_BYTES);
  const key = await deriveKey(password, salt, mode);
  const pt = new TextEncoder().encode(card);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(params(mode, iv), key, buf(pt)),
  );
  return { mode, salt, iv, ct };
}

/**
 * Attempt a decryption under `password`.
 *
 * Fails closed: an AES-GCM tag mismatch returns `{kind: 'rejected'}`. It is
 * never caught and dressed up as a garbage plaintext — GCM's refusal is a
 * RESULT, and the exhibit's whole point is that the attacker gets it for free.
 */
export async function pbeDecrypt(
  password: string,
  c: PbeCiphertext,
): Promise<PbeAttempt> {
  const key = await deriveKey(password, c.salt, c.mode);
  let raw: ArrayBuffer;
  try {
    raw = await crypto.subtle.decrypt(
      params(c.mode, c.iv),
      key,
      buf(Uint8Array.from(c.ct)),
    );
  } catch {
    return { kind: 'rejected' };
  }
  const bytes = new Uint8Array(raw);
  const allDigits = bytes.length > 0 && bytes.every((b) => b >= 0x30 && b <= 0x39);
  return {
    kind: 'plaintext',
    bytes,
    text: new TextDecoder('utf-8', { fatal: false }).decode(bytes),
    allDigits,
  };
}

/**
 * The probability that a wrong AES-CTR decryption of a 16-digit card happens
 * to be sixteen ASCII digits: (10/256)^16.
 *
 * Computed, not quoted, so the figure on the page cannot drift from the
 * exponent beside it.
 */
export function allDigitsProbability(digits = 16): number {
  return Math.pow(10 / 256, digits);
}

/** The same probability as a base-2 exponent, for "below 2^-74" on the page. */
export function allDigitsLog2(digits = 16): number {
  return digits * Math.log2(10 / 256);
}

/** Render bytes as the page shows a failed CTR decryption. */
export function describeBytes(bytes: Uint8Array): string {
  return Array.from(bytes, (b) =>
    b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.',
  ).join('');
}
