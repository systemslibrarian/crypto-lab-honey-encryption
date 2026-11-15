/**
 * Many-trial measurements.
 *
 * Every rate this lab prints is COUNTED FROM RUNS — there is no closed form
 * anywhere in this file and no expected value substituted for a measurement.
 * Each runner reports the number of trials alongside the count, because a
 * percentage without its denominator is not a measurement (invariant 6).
 *
 * The isolation of invariant 3 is kept here too: a trial encrypts, hands the
 * ciphertext and the dictionary to an attack function, and only then compares
 * the attacker's output with the truth it kept back. The attack functions in
 * attacks.ts never receive the truth, and the scoring functions cannot be
 * called without it.
 */

import { ACCOUNT_SPACE, cardFromAccount, luhnValid } from './luhn';
import { randomBelow, encode, type RandomSource, cryptoRandom } from './dte';
import { H, R_BYTES, keyForPassword, type HeCiphertext } from './he';
import { attackPileUp, scoreAttack, scoreRecovery } from './attacks';
import { hdecWithKey } from './he';
import type { HmacSha256Key } from './hmac';

/** The accumulated result of a card-trial run. */
export interface CardTrialTotals {
  trials: number;
  /** Trials in which the attacker named the true password. */
  successes: number;
  /** Trials in which all |dictionary| decryptions were Luhn-valid cards. */
  allValidTrials: number;
  /** Trials in which the |dictionary| decryptions were all distinct. */
  allDistinctTrials: number;
  /** The smallest number of distinct cards seen in any single trial. */
  minDistinct: number;
  /** The dictionary size, i.e. how many cards the attacker must choose between. */
  dictionarySize: number;
}

/** The accumulated result of a pile-up run. */
export interface PileUpTotals {
  trials: number;
  successes: number;
  /** Sum of the largest pile over all trials, for the mean. */
  pileSum: number;
  /** Sum of squares, for the standard deviation. */
  pileSumSquares: number;
  minPile: number;
  maxPile: number;
  dictionarySize: number;
  messageSpace: number;
}

export function emptyCardTotals(dictionarySize: number): CardTrialTotals {
  return {
    trials: 0,
    successes: 0,
    allValidTrials: 0,
    allDistinctTrials: 0,
    minDistinct: dictionarySize,
    dictionarySize,
  };
}

export function emptyPileUpTotals(dictionarySize: number, messageSpace: number): PileUpTotals {
  return {
    trials: 0,
    successes: 0,
    pileSum: 0,
    pileSumSquares: 0,
    minPile: dictionarySize,
    maxPile: 0,
    dictionarySize,
    messageSpace,
  };
}

/** Merge two accumulators, so a run can be sharded across workers. */
export function mergeCardTotals(a: CardTrialTotals, b: CardTrialTotals): CardTrialTotals {
  return {
    trials: a.trials + b.trials,
    successes: a.successes + b.successes,
    allValidTrials: a.allValidTrials + b.allValidTrials,
    allDistinctTrials: a.allDistinctTrials + b.allDistinctTrials,
    minDistinct: Math.min(a.minDistinct, b.minDistinct),
    dictionarySize: a.dictionarySize,
  };
}

export function mergePileUpTotals(a: PileUpTotals, b: PileUpTotals): PileUpTotals {
  return {
    trials: a.trials + b.trials,
    successes: a.successes + b.successes,
    pileSum: a.pileSum + b.pileSum,
    pileSumSquares: a.pileSumSquares + b.pileSumSquares,
    minPile: Math.min(a.minPile, b.minPile),
    maxPile: Math.max(a.maxPile, b.maxPile),
    dictionarySize: a.dictionarySize,
    messageSpace: a.messageSpace,
  };
}

/** A dictionary of `n` distinct, equally likely passwords. */
export function syntheticDictionary(n: number): string[] {
  return Array.from({ length: n }, (_, i) => `password-${String(i).padStart(4, '0')}`);
}

/**
 * Run `trials` card trials.
 *
 * Each trial: pick a true password uniformly from the dictionary (so the key
 * distribution's maximum weight is w = 1/|dictionary|), pick a card uniformly,
 * encrypt, then let the attacker see only the ciphertext and the dictionary.
 */
export function runCardTrials(
  trials: number,
  dictionary: readonly string[],
  opts: {
    rng?: RandomSource;
    keys?: readonly HmacSha256Key[];
    onProgress?: (done: number) => void;
    progressEvery?: number;
    shouldStop?: () => boolean;
  } = {},
): CardTrialTotals {
  const rng = opts.rng ?? cryptoRandom;
  const keys = opts.keys ?? dictionary.map(keyForPassword);
  const b = BigInt(ACCOUNT_SPACE);
  const totals = emptyCardTotals(dictionary.length);
  const progressEvery = opts.progressEvery ?? 50;

  for (let t = 0; t < trials; t++) {
    if (opts.shouldStop?.()) break;

    const trueIndex = Number(randomBelow(BigInt(dictionary.length), rng));
    const truePassword = dictionary[trueIndex]!;
    const trueAccount = Number(randomBelow(b, rng));

    // Encrypt. The truth lives here, in the caller's frame, and goes no further.
    const S = encode(BigInt(trueAccount), b, rng);
    const R = rng(R_BYTES);
    const c: HeCiphertext = { R, C2: H(R, truePassword) ^ S };

    // Attack. Sees the ciphertext and the dictionary. Nothing else.
    const cards: string[] = [];
    let allValid = true;
    for (let i = 0; i < dictionary.length; i++) {
      const account = Number(hdecWithKey(keys[i]!, c, b));
      const card = cardFromAccount(account);
      if (!luhnValid(card)) allValid = false;
      cards.push(card);
    }
    // With no distinguisher the optimal strategy is the most likely password;
    // the dictionary is uniform, so that is its first entry.
    const guess = dictionary[0]!;

    // Score, against the truth the attacker never saw.
    const verdict = scoreAttack(guess, truePassword);
    if (verdict.succeeded) totals.successes++;
    if (allValid) totals.allValidTrials++;
    const distinct = new Set(cards).size;
    if (distinct === dictionary.length) totals.allDistinctTrials++;
    if (distinct < totals.minDistinct) totals.minDistinct = distinct;
    totals.trials++;

    if (opts.onProgress && (t + 1) % progressEvery === 0) opts.onProgress(totals.trials);
  }
  return totals;
}

/**
 * Run `trials` pile-up trials over a message space of `messageSpace` values.
 *
 * This is the paper's CVV case: the message space is small enough that several
 * candidate passwords decrypt to the same value, so the attacker has something
 * to go on after all — the largest pile.
 */
export function runPileUpTrials(
  trials: number,
  dictionary: readonly string[],
  messageSpace: number,
  opts: {
    rng?: RandomSource;
    keys?: readonly HmacSha256Key[];
    onProgress?: (done: number) => void;
    progressEvery?: number;
    shouldStop?: () => boolean;
  } = {},
): PileUpTotals {
  const rng = opts.rng ?? cryptoRandom;
  const keys = opts.keys ?? dictionary.map(keyForPassword);
  const b = BigInt(messageSpace);
  const totals = emptyPileUpTotals(dictionary.length, messageSpace);
  const progressEvery = opts.progressEvery ?? 50;

  for (let t = 0; t < trials; t++) {
    if (opts.shouldStop?.()) break;

    const trueIndex = Number(randomBelow(BigInt(dictionary.length), rng));
    const truePassword = dictionary[trueIndex]!;
    const trueMessage = Number(randomBelow(b, rng));

    const S = encode(BigInt(trueMessage), b, rng);
    const R = rng(R_BYTES);
    const c: HeCiphertext = { R, C2: H(R, truePassword) ^ S };

    const attack = attackPileUp(c, dictionary, b, keys);
    const verdict = scoreRecovery(attack.guess, trueMessage);

    if (verdict.succeeded) totals.successes++;
    totals.pileSum += attack.largestPile;
    totals.pileSumSquares += attack.largestPile * attack.largestPile;
    if (attack.largestPile < totals.minPile) totals.minPile = attack.largestPile;
    if (attack.largestPile > totals.maxPile) totals.maxPile = attack.largestPile;
    totals.trials++;

    if (opts.onProgress && (t + 1) % progressEvery === 0) opts.onProgress(totals.trials);
  }
  return totals;
}

/**
 * The pure balls-and-bins game, with no cryptography in it at all.
 *
 * The paper's own figure (mean largest pile 2.14 over 100,000 runs) comes from
 * a simulation like this one. Running it beside the real attack is how the page
 * shows that the construction is behaving the way the abstract model predicts:
 * if the two disagree, the encoder is the thing to suspect.
 */
export function runBallsAndBins(
  runs: number,
  balls: number,
  bins: number,
  rng: RandomSource = cryptoRandom,
): { runs: number; sum: number; sumSquares: number; min: number; max: number } {
  const counts = new Int32Array(bins);
  let sum = 0;
  let sumSquares = 0;
  let min = balls;
  let max = 0;
  const binsBig = BigInt(bins);
  for (let r = 0; r < runs; r++) {
    counts.fill(0);
    let largest = 0;
    for (let i = 0; i < balls; i++) {
      const k = Number(randomBelow(binsBig, rng));
      const n = ++counts[k]!;
      if (n > largest) largest = n;
    }
    sum += largest;
    sumSquares += largest * largest;
    if (largest < min) min = largest;
    if (largest > max) max = largest;
  }
  return { runs, sum, sumSquares, min, max };
}

/** Mean and sample standard deviation from a sum/sum-of-squares accumulator. */
export function meanAndSd(
  n: number,
  sum: number,
  sumSquares: number,
): { mean: number; sd: number } {
  if (n === 0) return { mean: 0, sd: 0 };
  const mean = sum / n;
  if (n === 1) return { mean, sd: 0 };
  const variance = (sumSquares - n * mean * mean) / (n - 1);
  return { mean, sd: Math.sqrt(Math.max(0, variance)) };
}

/** A rate as a percentage, with its denominator kept beside it. */
export function rate(successes: number, trials: number): number {
  return trials === 0 ? 0 : (successes / trials) * 100;
}
