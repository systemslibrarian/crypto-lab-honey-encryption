import { describe, expect, it } from 'vitest';
import {
  ACCOUNT_SPACE,
  CARD_PREFIX,
  cardFromAccount,
  groupCard,
  luhnCheckDigit,
  luhnValid,
} from './luhn';

describe('Luhn checksum (ISO/IEC 7812-1)', () => {
  // ACCEPTANCE A.
  it('accepts the classic example 79927398713', () => {
    expect(luhnValid('79927398713')).toBe(true);
  });

  it('rejects 79927398710', () => {
    expect(luhnValid('79927398710')).toBe(false);
  });

  it('accepts exactly one check digit for 7992739871x', () => {
    const accepted = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].filter((d) => luhnValid(`7992739871${d}`));
    expect(accepted).toEqual([3]);
    expect(luhnCheckDigit('7992739871')).toBe(3);
  });

  // Independent re-derivation: the doubling runs right-to-left from the check
  // digit, computed here by reversing the string rather than by the index
  // parity the source uses. Mutation (4) changes which positions double; this
  // test does not share that expression.
  it('agrees with a right-to-left re-derivation on 2,000 random numbers', () => {
    const luhnByReversal = (s: string): boolean => {
      const d = Array.from(s).reverse().map(Number);
      let total = 0;
      for (let i = 0; i < d.length; i++) {
        let v = d[i]!;
        if (i % 2 === 1) {
          v *= 2;
          if (v > 9) v -= 9;
        }
        total += v;
      }
      return total % 10 === 0;
    };
    for (let i = 0; i < 2000; i++) {
      const len = 12 + (i % 6);
      let s = '';
      for (let j = 0; j < len; j++) {
        s += String(crypto.getRandomValues(new Uint8Array(1))[0]! % 10);
      }
      expect(luhnValid(s), s).toBe(luhnByReversal(s));
    }
  });

  it('builds a 16-digit card that passes its own check, for 5,000 random accounts', () => {
    for (let i = 0; i < 5000; i++) {
      const a = Math.floor(Math.random() * ACCOUNT_SPACE);
      const card = cardFromAccount(a);
      expect(card).toHaveLength(16);
      expect(card.startsWith(CARD_PREFIX)).toBe(true);
      expect(card.slice(6, 15)).toBe(String(a).padStart(9, '0'));
      expect(luhnValid(card)).toBe(true);
    }
  });

  it('builds the boundary cards', () => {
    expect(cardFromAccount(0)).toBe('4000000000000002');
    expect(luhnValid(cardFromAccount(0))).toBe(true);
    expect(cardFromAccount(ACCOUNT_SPACE - 1)).toBe('4000009999999991');
    expect(luhnValid(cardFromAccount(ACCOUNT_SPACE - 1))).toBe(true);
  });

  it('refuses an account outside the message space — fails closed', () => {
    expect(() => cardFromAccount(-1)).toThrow(/out of range/);
    expect(() => cardFromAccount(ACCOUNT_SPACE)).toThrow(/out of range/);
    expect(() => cardFromAccount(1.5)).toThrow(/out of range/);
  });

  it('rejects non-digit input rather than scoring it', () => {
    expect(luhnValid('4000 0012 3456 7899')).toBe(false);
    expect(luhnValid('')).toBe(false);
    expect(() => luhnCheckDigit('40000x')).toThrow(/not a digit string/);
  });

  it('groups a card for display', () => {
    expect(groupCard('4000001234567899')).toBe('4000 0012 3456 7899');
  });
});
