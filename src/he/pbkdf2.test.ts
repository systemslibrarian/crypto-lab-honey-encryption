import { describe, expect, it } from 'vitest';
import { buf } from './bufsrc';
import { pbkdf2Sha256 } from './pbkdf2';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const ascii = (s: string) => new TextEncoder().encode(s);

async function webcryptoPbkdf2(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Promise<string> {
  const material = await crypto.subtle.importKey('raw', buf(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: buf(salt), iterations, hash: 'SHA-256' },
    material,
    dkLen * 8,
  );
  return hex(new Uint8Array(bits));
}

describe('PBKDF2-HMAC-SHA-256 (RFC 8018, vectors from RFC 7914 section 11)', () => {
  // ACCEPTANCE A. The full value, not a prefix: the brief quotes only the
  // first and last bytes, and a prefix check passes an implementation that
  // corrupts the middle.
  it('matches RFC 7914 vector 1 — "passwd" / "salt" / 1 iteration / 64 bytes', () => {
    const dk = pbkdf2Sha256(ascii('passwd'), ascii('salt'), 1, 64);
    expect(hex(dk)).toBe(
      '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc' +
        '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783',
    );
    // The two anchors the brief quotes, asserted separately so a failure says
    // which end moved.
    expect(hex(dk).startsWith('55ac046e56e3089f')).toBe(true);
    expect(hex(dk).endsWith('41d3a19783')).toBe(true);
  });

  it('matches RFC 7914 vector 2 — "Password" / "NaCl" / 80000 iterations / 64 bytes', () => {
    expect(hex(pbkdf2Sha256(ascii('Password'), ascii('NaCl'), 80000, 64))).toBe(
      '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56' +
        'a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d',
    );
  });

  it('derives output longer than one hash block correctly (T_1 || T_2 || T_3)', async () => {
    // dkLen 64 spans two blocks and 65 spans three, so an implementation that
    // reuses the block counter or mis-slices the tail fails here.
    for (const dkLen of [1, 31, 32, 33, 63, 64, 65, 96]) {
      expect(hex(pbkdf2Sha256(ascii('pw'), ascii('sodium'), 7, dkLen)), `dkLen ${dkLen}`).toBe(
        await webcryptoPbkdf2(ascii('pw'), ascii('sodium'), 7, dkLen),
      );
    }
  });

  it('agrees with WebCrypto over random passwords and salts at this lab’s parameters', async () => {
    for (let i = 0; i < 40; i++) {
      const password = crypto.getRandomValues(new Uint8Array(1 + (i % 40)));
      const salt = crypto.getRandomValues(new Uint8Array(16));
      expect(hex(pbkdf2Sha256(password, salt, 100, 8))).toBe(
        await webcryptoPbkdf2(password, salt, 100, 8),
      );
    }
  });

  it('refuses a zero or fractional iteration count', () => {
    expect(() => pbkdf2Sha256(ascii('p'), ascii('s'), 0, 8)).toThrow(/positive integer/);
    expect(() => pbkdf2Sha256(ascii('p'), ascii('s'), 1.5, 8)).toThrow(/positive integer/);
  });
});
