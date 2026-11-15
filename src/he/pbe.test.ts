import { describe, expect, it } from 'vitest';
import {
  allDigitsLog2,
  allDigitsProbability,
  describeBytes,
  pbeDecrypt,
  pbeEncrypt,
} from './pbe';
import { cardFromAccount } from './luhn';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) =>
  new Uint8Array((s.match(/../g) ?? []).map((p) => parseInt(p, 16)));

const CARD = cardFromAccount(123456789); // 4000001234567899
const TRUE_PASSWORD = 'correct horse';

describe('AES known-answer tests', () => {
  // ACCEPTANCE A — NIST SP 800-38A F.5.1, CTR-AES128.Encrypt. All four blocks,
  // so a counter that fails to increment is caught.
  it('matches NIST SP 800-38A F.5.1 (CTR-AES128)', async () => {
    const key = await crypto.subtle.importKey(
      'raw',
      unhex('2b7e151628aed2a6abf7158809cf4f3c'),
      'AES-CTR',
      false,
      ['encrypt'],
    );
    const plaintext = unhex(
      '6bc1bee22e409f96e93d7e117393172a' +
        'ae2d8a571e03ac9c9eb76fac45af8e51' +
        '30c81c46a35ce411e5fbc1191a0a52ef' +
        'f69f2445df4f9b17ad2b417be66c3710',
    );
    const out = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-CTR', counter: unhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'), length: 32 },
        key,
        plaintext,
      ),
    );
    expect(hex(out)).toBe(
      '874d6191b620e3261bef6864990db6ce' +
        '9806f66b7970fdff8617187bb9fffdff' +
        '5ae4df3edbd5d35e5b4f09020db03eab' +
        '1e031dda2fbe03d1792170a0f3009cee',
    );
  });

  // ACCEPTANCE A — McGrew & Viega GCM test case 3: a 60-byte plaintext, well
  // over one block, with the tag checked separately from the ciphertext.
  it('matches GCM test case 3 (McGrew–Viega), ciphertext and tag', async () => {
    const key = await crypto.subtle.importKey(
      'raw',
      unhex('feffe9928665731c6d6a8f9467308308'),
      'AES-GCM',
      false,
      ['encrypt', 'decrypt'],
    );
    const plaintext = unhex(
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
        '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
    );
    const iv = unhex('cafebabefacedbaddecaf888');
    const out = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintext),
    );
    const ct = out.subarray(0, plaintext.length);
    const tag = out.subarray(plaintext.length);
    expect(hex(ct)).toBe(
      '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e' +
        '21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
    );
    expect(hex(tag)).toBe('4d5c2af327cd64a62cf35abd2ba6fab4');
  });

  it('matches GCM test case 4 (with associated data)', async () => {
    const key = await crypto.subtle.importKey(
      'raw',
      unhex('feffe9928665731c6d6a8f9467308308'),
      'AES-GCM',
      false,
      ['encrypt'],
    );
    const plaintext = unhex(
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
        '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    );
    const out = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: unhex('cafebabefacedbaddecaf888'),
          additionalData: unhex('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
          tagLength: 128,
        },
        key,
        plaintext,
      ),
    );
    expect(hex(out.subarray(plaintext.length))).toBe('5bc94fbc3221a5db94fae95ae7121a47');
  });
});

describe('ordinary password-based encryption', () => {
  it('round-trips a card under both modes', async () => {
    for (const mode of ['aes-ctr', 'aes-gcm'] as const) {
      const c = await pbeEncrypt(TRUE_PASSWORD, CARD, mode);
      const got = await pbeDecrypt(TRUE_PASSWORD, c);
      expect(got.kind).toBe('plaintext');
      if (got.kind !== 'plaintext') throw new Error('unreachable');
      expect(got.text).toBe(CARD);
      expect(got.allDigits).toBe(true);
    }
  });

  // ACCEPTANCE D. The expected number of all-digit results among 2,000 wrong
  // CTR decryptions is 2,000 x (10/256)^16, about 5.9e-20 — so observing even
  // one would be extraordinary, and that is exactly the recognition test the
  // attacker uses.
  it('AES-CTR: 2,000 wrong passwords give no all-digit result', async () => {
    const c = await pbeEncrypt(TRUE_PASSWORD, CARD, 'aes-ctr');
    let allDigit = 0;
    for (let i = 0; i < 2000; i++) {
      const got = await pbeDecrypt(`wrong-${i}`, c);
      expect(got.kind).toBe('plaintext'); // CTR never rejects
      if (got.kind === 'plaintext' && got.allDigits) allDigit++;
    }
    expect(allDigit).toBe(0);
    expect(2000 * allDigitsProbability()).toBeLessThan(1e-18);
  });

  // ACCEPTANCE D / EDGE CASE: GCM rejects. It is reported as a rejection, and
  // never as a decryption. Mutation (9) breaks exactly this.
  it('AES-GCM: every wrong password is rejected, not decrypted', async () => {
    const c = await pbeEncrypt(TRUE_PASSWORD, CARD, 'aes-gcm');
    for (let i = 0; i < 200; i++) {
      expect(await pbeDecrypt(`wrong-${i}`, c)).toEqual({ kind: 'rejected' });
    }
  });

  it('states the all-digit probability the page prints', () => {
    // (10/256)^16, which the brief gives as about 2.9e-23 and below 2^-74.
    expect(allDigitsProbability()).toBeGreaterThan(2.8e-23);
    expect(allDigitsProbability()).toBeLessThan(3.0e-23);
    expect(allDigitsLog2()).toBeLessThan(-74);
    expect(allDigitsLog2()).toBeGreaterThan(-75);
    expect(Math.pow(2, allDigitsLog2())).toBeCloseTo(allDigitsProbability(), 30);
  });

  it('renders non-printable bytes without pretending they are text', () => {
    expect(describeBytes(new Uint8Array([0x34, 0x00, 0x7f, 0x39]))).toBe('4..9');
  });

  it('uses a fresh salt and IV per encryption', async () => {
    const a = await pbeEncrypt(TRUE_PASSWORD, CARD, 'aes-gcm');
    const b = await pbeEncrypt(TRUE_PASSWORD, CARD, 'aes-gcm');
    expect(hex(a.salt)).not.toBe(hex(b.salt));
    expect(hex(a.iv)).not.toBe(hex(b.iv));
  });
});
