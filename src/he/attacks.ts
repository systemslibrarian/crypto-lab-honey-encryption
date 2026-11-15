/**
 * The attackers.
 *
 * INVARIANT 3 governs this whole file: an attack function receives the
 * ciphertext and the candidate password list, and NOTHING ELSE. It never sees
 * the true message or the true password. Whether it succeeded is decided by
 * the caller afterwards, by comparing the attacker's own output against the
 * truth the caller kept.
 *
 * That split is not decoration. If success were scored as "returned a card
 * that passes the Luhn check", every honey-encryption attack would score 100%
 * and the lab would report the opposite of its subject. The types below make
 * the mistake hard to write: an attack returns a `guess`, and only
 * `scoreAttack` — which takes the truth as a separate argument — produces a
 * verdict. That is mutation (7).
 */

import { ACCOUNT_SPACE, cardFromAccount, luhnValid } from './luhn';
import { hdec, hdecWithKey, keyForPassword, type HeCiphertext } from './he';
import type { HmacSha256Key } from './hmac';
import { pbeDecrypt, type PbeAttempt, type PbeCiphertext } from './pbe';

/** What a dictionary attacker on an ordinary ciphertext returns. */
export interface PbeAttackResult {
  /** The password the attacker names, or null for "not found". */
  guess: string | null;
  /** How the attacker claims to have recognised it. */
  basis: 'all-digit plaintext' | 'tag verified' | 'none';
  /** One row per candidate tried, in order, for the page to display. */
  rows: Array<{ password: string; attempt: PbeAttempt }>;
  /** How many candidates it had to try before stopping. */
  tried: number;
}

/**
 * The dictionary attack against ordinary PBE.
 *
 * It stops at the first candidate it can RECOGNISE as right:
 *   - AES-GCM: the tag verified. Nothing else can make that happen.
 *   - AES-CTR: the plaintext is sixteen ASCII digits.
 * Both tests are available to anyone holding the ciphertext. Neither consults
 * the true password or the true card.
 */
export async function attackPbe(
  c: PbeCiphertext,
  dictionary: readonly string[],
): Promise<PbeAttackResult> {
  const rows: PbeAttackResult['rows'] = [];
  for (const password of dictionary) {
    const attempt = await pbeDecrypt(password, c);
    rows.push({ password, attempt });
    if (attempt.kind === 'plaintext' && attempt.allDigits) {
      return {
        guess: password,
        basis: c.mode === 'aes-gcm' ? 'tag verified' : 'all-digit plaintext',
        rows,
        tried: rows.length,
      };
    }
  }
  return { guess: null, basis: 'none', rows, tried: rows.length };
}

/** One candidate's decryption of a honey ciphertext. */
export interface HeCandidate {
  password: string;
  account: number;
  card: string;
  /** Always true for this construction — computed, never assumed. */
  luhn: boolean;
}

/** What a dictionary attacker on a honey ciphertext returns. */
export interface HeAttackResult {
  rows: HeCandidate[];
  /** The attacker must commit to one. It has no basis for the choice. */
  guess: string | null;
  /** Why it chose: for a uniform message space there is nothing to go on. */
  basis: 'no distinguisher — first candidate' | 'most frequent plaintext' | 'none';
  /** Distinct cards among the rows; equal to rows.length unless two collide. */
  distinctCards: number;
}

/**
 * The dictionary attack against honey encryption.
 *
 * It decrypts under every candidate and gets a valid card every time, so no
 * test it can apply separates them. Forced to commit, it names the FIRST
 * candidate — equivalently, the most likely password, which is the strategy
 * the paper proves is optimal here and which achieves exactly w.
 */
export function attackHoney(
  c: HeCiphertext,
  dictionary: readonly string[],
  b: bigint = BigInt(ACCOUNT_SPACE),
): HeAttackResult {
  const rows: HeCandidate[] = [];
  for (const password of dictionary) {
    const account = Number(hdec(password, c, b));
    const card = cardFromAccount(account);
    rows.push({ password, account, card, luhn: luhnValid(card) });
  }
  const distinctCards = new Set(rows.map((r) => r.card)).size;
  return {
    rows,
    guess: rows.length > 0 ? rows[0]!.password : null,
    basis: rows.length > 0 ? 'no distinguisher — first candidate' : 'none',
    distinctCards,
  };
}

/**
 * The pile-up attack, for a message space small enough that collisions happen.
 *
 * With 100 candidate passwords and only 1,000 possible messages, several
 * candidates land on the same message by chance. The attacker outputs the most
 * frequent one — the largest pile in a balls-and-bins game with 100 balls and
 * 1,000 bins. The paper's simulation puts the mean largest pile at 2.14, so
 * this attacker wins about 2.14% of the time against w = 1%.
 *
 * Ties go to the lowest message, deterministically. Picking a tie at random
 * would make the measured rate depend on the tie-break, which is a thing to
 * measure rather than hide.
 */
export function attackPileUp(
  c: HeCiphertext,
  dictionary: readonly string[],
  b: bigint,
  keys?: readonly HmacSha256Key[],
): { guess: number | null; largestPile: number; piles: Map<number, number> } {
  const piles = new Map<number, number>();
  for (let i = 0; i < dictionary.length; i++) {
    const key = keys ? keys[i]! : keyForPassword(dictionary[i]!);
    const m = Number(hdecWithKey(key, c, b));
    piles.set(m, (piles.get(m) ?? 0) + 1);
  }
  let guess: number | null = null;
  let largestPile = 0;
  for (const [m, n] of [...piles.entries()].sort((a, x) => a[0] - x[0])) {
    if (n > largestPile) {
      largestPile = n;
      guess = m;
    }
  }
  return { guess, largestPile, piles };
}

/**
 * The known-plaintext attack: the limit the 2016 paper proves is general.
 *
 * The attacker holds one (card, ciphertext) pair under the same password, plus
 * the target ciphertext. Now it has a test again — decrypt the KNOWN
 * ciphertext under each candidate and see whether the known card comes back.
 * A wrong password passes that test with probability 1/b, which for b = 10^9
 * is 1e-9, so the first candidate that passes is the password, and the target
 * falls with it.
 *
 * Jaeger, Ristenpart and Tang, IACR ePrint 2016/174, section 4, prove the
 * general statement: an unbounded adversary holding a limited number of
 * encryptions of known plaintexts always succeeds at message recovery.
 */
export function attackKnownPlaintext(
  known: { c: HeCiphertext; account: number },
  target: HeCiphertext,
  dictionary: readonly string[],
  b: bigint = BigInt(ACCOUNT_SPACE),
): { guess: string | null; recovered: number | null; tried: number } {
  let tried = 0;
  for (const password of dictionary) {
    tried++;
    const key = keyForPassword(password);
    const m = Number(hdecWithKey(key, known.c, b));
    if (m === known.account) {
      return { guess: password, recovered: Number(hdecWithKey(key, target, b)), tried };
    }
  }
  return { guess: null, recovered: null, tried };
}

/**
 * Score an attack against the truth.
 *
 * The ONLY place a verdict is produced, and it needs the truth passed in.
 * `validLooking` is recorded separately and deliberately: it is what a naive
 * scorer would use, and showing it beside the real verdict is how the page
 * demonstrates that the two are different questions.
 */
export function scoreAttack(
  guess: string | null,
  truePassword: string,
): { succeeded: boolean; guess: string | null } {
  return { succeeded: guess !== null && guess === truePassword, guess };
}

/** Score a message-recovery attack: did the attacker name the true message? */
export function scoreRecovery(
  guess: number | null,
  trueMessage: number,
): { succeeded: boolean; guess: number | null } {
  return { succeeded: guess !== null && guess === trueMessage, guess };
}
