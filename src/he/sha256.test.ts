import { describe, expect, it } from 'vitest';
import { sha256 } from './sha256';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const ascii = (s: string) => new TextEncoder().encode(s);

describe('SHA-256 (FIPS 180-4)', () => {
  it('matches the FIPS 180-4 one-block digest for "abc"', () => {
    expect(hex(sha256(ascii('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('matches the FIPS 180-4 multi-block digest', () => {
    expect(
      hex(sha256(ascii('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    ).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });

  it('matches the digest of the empty string', () => {
    expect(hex(sha256(new Uint8Array(0)))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('matches the million-a digest', () => {
    expect(hex(sha256(new Uint8Array(1_000_000).fill(0x61)))).toBe(
      'cd c7 6e 5c 99 14 fb 92 81 a1 c7 e2 84 d7 3e 67 f1 80 9a 48 a4 97 20 0e 04 6d 39 cc c7 11 2c d0'.replace(
        / /g,
        '',
      ),
    );
  });

  // Every length from 0 to 200 crosses both the one-block and two-block tail
  // cases and both sides of each padding boundary (55/56, 119/120).
  it('agrees with WebCrypto on every input length from 0 to 200 bytes', async () => {
    for (let n = 0; n <= 200; n++) {
      const msg = new Uint8Array(n);
      for (let i = 0; i < n; i++) msg[i] = (i * 31 + n) & 0xff;
      const ref = new Uint8Array(await crypto.subtle.digest('SHA-256', msg));
      expect(hex(sha256(msg)), `length ${n}`).toBe(hex(ref));
    }
  });

  it('agrees with WebCrypto on 300 random inputs', async () => {
    for (let i = 0; i < 300; i++) {
      const n = crypto.getRandomValues(new Uint8Array(1))[0]! * 3;
      const msg = crypto.getRandomValues(new Uint8Array(n));
      const ref = new Uint8Array(await crypto.subtle.digest('SHA-256', msg));
      expect(hex(sha256(msg))).toBe(hex(ref));
    }
  });
});
