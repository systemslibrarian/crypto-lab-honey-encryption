import { describe, expect, it } from 'vitest';
import { interval, decode, SEED_SPACE } from './dte';
import {
  H,
  PBKDF2_ITERATIONS,
  R_BYTES,
  hdec,
  hdecSeed,
  hencWithSeed,
  henc,
  hex64,
  hexBytes,
  maulTopBit,
  parseHexBytes,
} from './he';
import { ACCOUNT_SPACE, cardFromAccount, luhnValid } from './luhn';

const B = BigInt(ACCOUNT_SPACE);
/** The published vector's R: 000102030405060708090a0b0c0d0e0f. */
const R = new Uint8Array(Array.from({ length: 16 }, (_, i) => i));
const TRUE_PASSWORD = 'correct horse';
const ACCOUNT = 123456789n;
/** lower bound + 0x1234567, as the brief's vector fixes it. */
const SEED = interval(ACCOUNT, B).lo + 0x1234567n;

describe('honey encryption — the construction of Figure 4 (ePrint 2014/155, section 5)', () => {
  it('uses the iteration count and nonce width the page states', () => {
    expect(PBKDF2_ITERATIONS).toBe(100);
    expect(R_BYTES).toBe(16);
  });

  // ACCEPTANCE C. Every value here was computed in Python before this source
  // existed, from the construction's definition rather than from this code.
  it('reproduces the published fixed vector', () => {
    expect(hexBytes(R)).toBe('000102030405060708090a0b0c0d0e0f');
    expect(hex64(SEED)).toBe('0x1f9add373a86a499');
    expect(hex64(H(R, TRUE_PASSWORD))).toBe('0xe79380776b5f9544');
    const c = hencWithSeed(TRUE_PASSWORD, SEED, R);
    expect(hex64(c.C2)).toBe('0xf8095d4051d931dd');
    expect(cardFromAccount(123456789)).toBe('4000001234567899');
  });

  // The table the page and the README both print.
  const VECTOR_TABLE: Array<[string, string]> = [
    ['correct horse', '4000001234567899'],
    ['123456', '4000002152029847'],
    ['password', '4000004893076335'],
    ['letmein', '4000005600717434'],
    ['qwerty', '4000007943404878'],
    ['correct horsf', '4000005684553184'],
  ];

  it.each(VECTOR_TABLE)('decrypts the vector under %s to %s', (password, card) => {
    const c = hencWithSeed(TRUE_PASSWORD, SEED, R);
    const account = Number(hdec(password, c, B));
    expect(cardFromAccount(account)).toBe(card);
  });

  it('gets a Luhn-valid card from every password in the table', () => {
    const c = hencWithSeed(TRUE_PASSWORD, SEED, R);
    for (const [password] of VECTOR_TABLE) {
      const card = cardFromAccount(Number(hdec(password, c, B)));
      expect(luhnValid(card), `${password} -> ${card}`).toBe(true);
    }
  });

  it('round-trips: the true password recovers the card that was encrypted', () => {
    for (let i = 0; i < 200; i++) {
      const account = BigInt(Math.floor(Math.random() * ACCOUNT_SPACE));
      const c = henc('a password', account, B);
      expect(hdec('a password', c, B)).toBe(account);
    }
  });

  // INVARIANT: every key yields a message. No rejection path exists, and this
  // is what the whole lab is about.
  it('never rejects: 2,000 arbitrary passwords all yield a valid card', () => {
    const c = henc(TRUE_PASSWORD, ACCOUNT, B);
    for (let i = 0; i < 2000; i++) {
      const account = Number(hdec(`candidate-${i}`, c, B));
      expect(account).toBeGreaterThanOrEqual(0);
      expect(account).toBeLessThan(ACCOUNT_SPACE);
      expect(luhnValid(cardFromAccount(account))).toBe(true);
    }
  });

  it('is randomized: two encryptions of the same card differ', () => {
    const a = henc(TRUE_PASSWORD, ACCOUNT, B);
    const b = henc(TRUE_PASSWORD, ACCOUNT, B);
    expect(hexBytes(a.R) === hexBytes(b.R) && a.C2 === b.C2).toBe(false);
    expect(hdec(TRUE_PASSWORD, a, B)).toBe(ACCOUNT);
    expect(hdec(TRUE_PASSWORD, b, B)).toBe(ACCOUNT);
  });

  it('decrypts an empty password — a bad password is still a password', () => {
    const c = henc('', ACCOUNT, B);
    expect(hdec('', c, B)).toBe(ACCOUNT);
    expect(luhnValid(cardFromAccount(Number(hdec('x', c, B))))).toBe(true);
  });

  describe('mauling — ACCEPTANCE F', () => {
    it('moves the vector’s account by exactly +500,000,000', () => {
      const c = hencWithSeed(TRUE_PASSWORD, SEED, R);
      expect(SEED >> 63n).toBe(0n); // the seed's top bit is 0, so the move is up
      const mauled = maulTopBit(c);
      const account = Number(hdec(TRUE_PASSWORD, mauled, B));
      expect(account).toBe(623456789);
      expect(cardFromAccount(account)).toBe('4000006234567898');
      expect(luhnValid(cardFromAccount(account))).toBe(true);
    });

    it('moves a random encryption’s account by exactly ±500,000,000', () => {
      for (let i = 0; i < 300; i++) {
        const account = BigInt(Math.floor(Math.random() * ACCOUNT_SPACE));
        const c = henc('pw', account, B);
        const seed = hdecSeed('pw', c);
        const moved = hdec('pw', maulTopBit(c), B);
        const delta = moved - account;
        expect(delta, `seed top bit ${seed >> 63n}`).toBe(
          seed >> 63n === 0n ? 500_000_000n : -500_000_000n,
        );
      }
    });

    it('leaves R untouched and does not alias the original ciphertext', () => {
      const c = hencWithSeed(TRUE_PASSWORD, SEED, R);
      const m = maulTopBit(c);
      expect(hexBytes(m.R)).toBe(hexBytes(c.R));
      expect(m.R).not.toBe(c.R);
      expect(maulTopBit(m).C2).toBe(c.C2);
    });
  });

  describe('fail-closed parsing — EDGE CASES', () => {
    it('refuses a ciphertext whose R is not 16 bytes', () => {
      expect(() => hdec('pw', { R: new Uint8Array(15), C2: 1n }, B)).toThrow(/R must be 16 bytes/);
      expect(() => hdec('pw', { R: new Uint8Array(17), C2: 1n }, B)).toThrow(/R must be 16 bytes/);
    });

    it('refuses a C2 outside 64 bits', () => {
      expect(() => hdec('pw', { R, C2: -1n }, B)).toThrow(/C2 outside/);
      expect(() => hdec('pw', { R, C2: SEED_SPACE }, B)).toThrow(/C2 outside/);
    });

    it('refuses a seed outside 64 bits at encryption', () => {
      expect(() => hencWithSeed('pw', SEED_SPACE, R)).toThrow(/seed outside/);
      expect(() => hencWithSeed('pw', 0n, new Uint8Array(4))).toThrow(/R must be 16 bytes/);
    });

    it('parses R strictly', () => {
      expect(hexBytes(parseHexBytes('000102030405060708090a0b0c0d0e0f', 16))).toBe(
        '000102030405060708090a0b0c0d0e0f',
      );
      expect(() => parseHexBytes('00', 16)).toThrow(/expected 16 hex bytes/);
      expect(() => parseHexBytes('zz0102030405060708090a0b0c0d0e0f', 16)).toThrow(/expected 16/);
    });

    it('refuses to render a non-64-bit value as a seed', () => {
      expect(() => hex64(SEED_SPACE)).toThrow(/not a 64-bit value/);
      expect(hex64(0n)).toBe('0x0000000000000000');
      expect(hex64(SEED_SPACE - 1n)).toBe('0xffffffffffffffff');
    });
  });

  it('decodes seed 0 and seed 2^64 - 1 to the extreme accounts', () => {
    expect(decode(0n, B)).toBe(0n);
    expect(cardFromAccount(Number(decode(0n, B)))).toBe('4000000000000002');
    expect(decode(SEED_SPACE - 1n, B)).toBe(999999999n);
    expect(cardFromAccount(Number(decode(SEED_SPACE - 1n, B)))).toBe('4000009999999991');
  });
});
