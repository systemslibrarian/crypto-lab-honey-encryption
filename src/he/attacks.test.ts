import { describe, expect, it } from 'vitest';
import {
  attackHoney,
  attackKnownPlaintext,
  attackPbe,
  attackPileUp,
  scoreAttack,
  scoreRecovery,
} from './attacks';
import { henc, hencWithSeed, keyForPassword, maulTopBit } from './he';
import { interval } from './dte';
import { pbeEncrypt } from './pbe';
import { ACCOUNT_SPACE, cardFromAccount, luhnValid } from './luhn';
import { syntheticDictionary } from './trials';

const B = BigInt(ACCOUNT_SPACE);
const R = new Uint8Array(Array.from({ length: 16 }, (_, i) => i));
const SEED = interval(123456789n, B).lo + 0x1234567n;
const VECTOR_DICT = ['correct horse', '123456', 'password', 'letmein', 'qwerty', 'correct horsf'];

describe('the dictionary attack on ordinary encryption — ACCEPTANCE D', () => {
  it('finds the true password in every one of 200 AES-CTR trials', async () => {
    const dict = syntheticDictionary(20);
    for (let t = 0; t < 200; t++) {
      const truePassword = dict[t % dict.length]!;
      const card = cardFromAccount(Math.floor(Math.random() * ACCOUNT_SPACE));
      const c = await pbeEncrypt(truePassword, card, 'aes-ctr');
      const result = await attackPbe(c, dict);
      expect(scoreAttack(result.guess, truePassword).succeeded, `trial ${t}`).toBe(true);
      expect(result.basis).toBe('all-digit plaintext');
    }
  });

  it('finds the true password in every one of 200 AES-GCM trials, on the tag alone', async () => {
    const dict = syntheticDictionary(20);
    for (let t = 0; t < 200; t++) {
      const truePassword = dict[t % dict.length]!;
      const c = await pbeEncrypt(truePassword, cardFromAccount(42), 'aes-gcm');
      const result = await attackPbe(c, dict);
      expect(scoreAttack(result.guess, truePassword).succeeded, `trial ${t}`).toBe(true);
      expect(result.basis).toBe('tag verified');
      // Every candidate before the right one was REJECTED, not decrypted.
      for (const row of result.rows.slice(0, -1)) {
        expect(row.attempt).toEqual({ kind: 'rejected' });
      }
    }
  });

  // EDGE CASE: a dictionary without the true password.
  it('reports "not found" when the dictionary misses the password', async () => {
    const c = await pbeEncrypt('not in the list', cardFromAccount(7), 'aes-ctr');
    const result = await attackPbe(c, syntheticDictionary(30));
    expect(result.guess).toBeNull();
    expect(result.basis).toBe('none');
    expect(result.tried).toBe(30);
    expect(scoreAttack(result.guess, 'not in the list').succeeded).toBe(false);
  });

  it('stops at the password it recognises rather than running the whole list', async () => {
    const dict = syntheticDictionary(50);
    const c = await pbeEncrypt(dict[9]!, cardFromAccount(1), 'aes-gcm');
    const result = await attackPbe(c, dict);
    expect(result.tried).toBe(10);
  });
});

describe('the dictionary attack on honey encryption', () => {
  it('gets a valid card from every candidate and can name no winner on evidence', () => {
    const c = hencWithSeed('correct horse', SEED, R);
    const result = attackHoney(c, VECTOR_DICT, B);
    expect(result.rows).toHaveLength(6);
    for (const row of result.rows) {
      expect(row.luhn, `${row.password} -> ${row.card}`).toBe(true);
      expect(luhnValid(row.card)).toBe(true);
    }
    expect(result.basis).toBe('no distinguisher — first candidate');
  });

  it('reproduces the published vector table in order', () => {
    const c = hencWithSeed('correct horse', SEED, R);
    expect(attackHoney(c, VECTOR_DICT, B).rows.map((r) => r.card)).toEqual([
      '4000001234567899',
      '4000002152029847',
      '4000004893076335',
      '4000005600717434',
      '4000007943404878',
      '4000005684553184',
    ]);
  });

  it('counts six distinct cards for the vector — no collision to disclose', () => {
    const c = hencWithSeed('correct horse', SEED, R);
    const result = attackHoney(c, VECTOR_DICT, B);
    expect(result.distinctCards).toBe(6);
    expect(result.distinctCards).toBe(result.rows.length);
  });

  // This is the point of the lab, stated as a test: the attacker is wrong
  // almost always, even though every answer it saw looked perfect.
  it('fails on 99 of 100 candidates even though all 100 decryptions are valid', () => {
    const dict = syntheticDictionary(100);
    let succeeded = 0;
    let validDecryptions = 0;
    for (let t = 0; t < 100; t++) {
      const truePassword = dict[t]!;
      const trueAccount = Math.floor(Math.random() * ACCOUNT_SPACE);
      const c = henc(truePassword, BigInt(trueAccount), B);
      const result = attackHoney(c, dict, B);
      validDecryptions += result.rows.filter((r) => r.luhn).length;
      if (scoreAttack(result.guess, truePassword).succeeded) succeeded++;
    }
    // Every decryption of every trial was a valid card...
    expect(validDecryptions).toBe(100 * 100);
    // ...and the attacker, naming the first candidate, was right exactly once:
    // on the trial where the first candidate happened to be the true password.
    expect(succeeded).toBe(1);
  });

  // The mistake mutation (7) makes: scoring on "looks valid" instead of "is
  // the truth". Asserted here as a difference, so the two can never be fused.
  it('separates "produced a valid card" from "recovered the password"', () => {
    const c = hencWithSeed('correct horse', SEED, R);
    const result = attackHoney(c, VECTOR_DICT, B);
    const qwerty = result.rows.find((r) => r.password === 'qwerty')!;
    expect(qwerty.luhn).toBe(true); // a perfectly valid card
    expect(scoreAttack('qwerty', 'correct horse').succeeded).toBe(false); // and wrong
  });
});

describe('the pile-up attack', () => {
  it('finds the largest pile and breaks ties toward the lowest message', () => {
    // A 3-digit space with a dictionary big enough to force collisions.
    const dict = syntheticDictionary(100);
    const c = henc(dict[0]!, 123n, 1000n);
    const result = attackPileUp(c, dict, 1000n);
    expect(result.largestPile).toBeGreaterThanOrEqual(1);
    let total = 0;
    for (const n of result.piles.values()) total += n;
    expect(total).toBe(100);
    // The reported pile really is the maximum over the piles.
    expect(result.largestPile).toBe(Math.max(...result.piles.values()));
    expect(result.piles.get(result.guess!)).toBe(result.largestPile);
  });

  it('agrees whether or not the caller supplies cached keys', () => {
    const dict = syntheticDictionary(40);
    const c = henc(dict[3]!, 7n, 1000n);
    const a = attackPileUp(c, dict, 1000n);
    const b = attackPileUp(c, dict, 1000n, dict.map(keyForPassword));
    expect(b.guess).toBe(a.guess);
    expect(b.largestPile).toBe(a.largestPile);
  });
});

describe('the known-plaintext attack — ACCEPTANCE F', () => {
  it('returns the true password in every one of 200 trials', () => {
    const dict = syntheticDictionary(100);
    for (let t = 0; t < 200; t++) {
      const truePassword = dict[t % dict.length]!;
      const knownAccount = Math.floor(Math.random() * ACCOUNT_SPACE);
      const targetAccount = Math.floor(Math.random() * ACCOUNT_SPACE);
      const known = henc(truePassword, BigInt(knownAccount), B);
      const target = henc(truePassword, BigInt(targetAccount), B);
      const result = attackKnownPlaintext({ c: known, account: knownAccount }, target, dict, B);
      expect(scoreAttack(result.guess, truePassword).succeeded, `trial ${t}`).toBe(true);
      expect(scoreRecovery(result.recovered, targetAccount).succeeded, `trial ${t}`).toBe(true);
    }
  });

  it('reports "not found" when the password is outside the dictionary', () => {
    const known = henc('outside', 11n, B);
    const target = henc('outside', 22n, B);
    const result = attackKnownPlaintext({ c: known, account: 11 }, target, syntheticDictionary(50), B);
    expect(result.guess).toBeNull();
    expect(result.recovered).toBeNull();
  });

  it('is the one attack that recovers the target, which is why it is a limit', () => {
    const dict = syntheticDictionary(100);
    const truePassword = dict[57]!;
    const known = henc(truePassword, 123456789n, B);
    const target = henc(truePassword, 987654321n, B);
    // Without the known pair the same dictionary yields nothing to choose between.
    expect(attackHoney(target, dict, B).basis).toBe('no distinguisher — first candidate');
    // With it, the target falls.
    const result = attackKnownPlaintext({ c: known, account: 123456789 }, target, dict, B);
    expect(result.recovered).toBe(987654321);
  });
});

describe('mauling as an attack', () => {
  it('moves the plaintext without the attacker ever learning it', () => {
    const account = 400000000;
    const c = henc('a password', BigInt(account), B);
    // The attacker has no password and learns nothing about the card...
    const mauled = maulTopBit(c);
    expect(mauled.C2).not.toBe(c.C2);
    // ...yet the recipient's decryption moved by exactly half the space.
    const moved = attackHoney(mauled, ['a password'], B).rows[0]!.account;
    expect(Math.abs(moved - account)).toBe(500_000_000);
    expect(luhnValid(cardFromAccount(moved))).toBe(true);
  });
});
