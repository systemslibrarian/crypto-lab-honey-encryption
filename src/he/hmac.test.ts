import { describe, expect, it } from 'vitest';
import { buf } from './bufsrc';
import { hmacSha256 } from './hmac';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const ascii = (s: string) => new TextEncoder().encode(s);

async function webcryptoHmac(key: Uint8Array, msg: Uint8Array): Promise<string> {
  const k = await crypto.subtle.importKey(
    'raw',
    buf(key.length === 0 ? new Uint8Array(1).subarray(0, 0) : key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return hex(new Uint8Array(await crypto.subtle.sign('HMAC', k, buf(msg))));
}

describe('HMAC-SHA-256 (RFC 4231)', () => {
  it('matches RFC 4231 test case 1', () => {
    expect(hex(hmacSha256(new Uint8Array(20).fill(0x0b), ascii('Hi There')))).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    );
  });

  it('matches RFC 4231 test case 2', () => {
    expect(hex(hmacSha256(ascii('Jefe'), ascii('what do ya want for nothing?')))).toBe(
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    );
  });

  it('matches RFC 4231 test case 4 (keyed with 25 bytes)', () => {
    const key = new Uint8Array(25);
    for (let i = 0; i < 25; i++) key[i] = i + 1;
    const msg = new Uint8Array(50).fill(0xcd);
    // This message is 50 bytes, inside the single-block fast path.
    expect(hex(hmacSha256(key, msg))).toBe(
      '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
    );
  });

  it('hashes an over-long key, as RFC 2104 requires', async () => {
    // 131 bytes, longer than the 64-byte block: the key is replaced by its own
    // digest. RFC 4231 case 6 uses this key; its message is too long for the
    // fast path, so the value is checked against WebCrypto on a short message.
    const key = new Uint8Array(131).fill(0xaa);
    const msg = ascii('Test Using Larger Than Block-Size Key');
    expect(hex(hmacSha256(key, msg))).toBe(await webcryptoHmac(key, msg));
  });

  it('agrees with WebCrypto across key and message lengths', async () => {
    for (const keyLen of [1, 16, 32, 63, 64, 65, 100, 200]) {
      for (const msgLen of [0, 1, 20, 32, 54, 55]) {
        const key = crypto.getRandomValues(new Uint8Array(keyLen));
        const msg = crypto.getRandomValues(new Uint8Array(msgLen));
        expect(hex(hmacSha256(key, msg)), `key ${keyLen} msg ${msgLen}`).toBe(
          await webcryptoHmac(key, msg),
        );
      }
    }
  });

  it('refuses a message too long for the single-block path rather than MACing it wrongly', () => {
    expect(() => hmacSha256(ascii('k'), new Uint8Array(56))).toThrow(/exceeds this fast path/);
  });
});
