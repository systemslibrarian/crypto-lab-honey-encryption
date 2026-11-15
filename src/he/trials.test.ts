import { describe, expect, it } from 'vitest';
import {
  emptyCardTotals,
  emptyPileUpTotals,
  meanAndSd,
  mergeCardTotals,
  mergePileUpTotals,
  rate,
  runBallsAndBins,
  runCardTrials,
  runPileUpTrials,
  syntheticDictionary,
} from './trials';

/**
 * The slow rate measurements are tagged and skipped by default. Run them with
 *   npm run test:slow
 * The figures they bracket are in README.md under "Build & Verify", measured
 * with scripts/measure-rates.mjs, which shards the same functions.
 */
const slow = process.env.SLOW === '1' ? it : it.skip;

describe('trial accumulators', () => {
  it('merges card totals so a run can be sharded', () => {
    const a = { ...emptyCardTotals(100), trials: 10, successes: 1, allValidTrials: 10, allDistinctTrials: 9, minDistinct: 99 };
    const b = { ...emptyCardTotals(100), trials: 5, successes: 2, allValidTrials: 5, allDistinctTrials: 5, minDistinct: 100 };
    const m = mergeCardTotals(a, b);
    expect(m.trials).toBe(15);
    expect(m.successes).toBe(3);
    expect(m.allValidTrials).toBe(15);
    expect(m.allDistinctTrials).toBe(14);
    expect(m.minDistinct).toBe(99);
  });

  it('merges pile-up totals, keeping the extremes', () => {
    const a = { ...emptyPileUpTotals(100, 1000), trials: 3, successes: 1, pileSum: 7, pileSumSquares: 17, minPile: 2, maxPile: 3 };
    const b = { ...emptyPileUpTotals(100, 1000), trials: 2, successes: 0, pileSum: 5, pileSumSquares: 13, minPile: 1, maxPile: 4 };
    const m = mergePileUpTotals(a, b);
    expect([m.trials, m.successes, m.pileSum, m.pileSumSquares, m.minPile, m.maxPile]).toEqual([
      5, 1, 12, 30, 1, 4,
    ]);
  });

  it('computes mean and sample standard deviation', () => {
    // 2, 2, 3, 3: mean 2.5, sample sd 0.5773502692
    const { mean, sd } = meanAndSd(4, 10, 26);
    expect(mean).toBe(2.5);
    expect(sd).toBeCloseTo(0.5773502692, 9);
    expect(meanAndSd(0, 0, 0)).toEqual({ mean: 0, sd: 0 });
    expect(meanAndSd(1, 3, 9).sd).toBe(0);
  });

  it('keeps a rate tied to its denominator', () => {
    expect(rate(33, 3000)).toBeCloseTo(1.1, 10);
    expect(rate(0, 0)).toBe(0);
  });

  it('builds a dictionary of distinct passwords', () => {
    const d = syntheticDictionary(100);
    expect(d).toHaveLength(100);
    expect(new Set(d).size).toBe(100);
  });
});

describe('balls and bins (no cryptography)', () => {
  it('throws every ball into some bin', () => {
    const r = runBallsAndBins(50, 100, 1000);
    expect(r.runs).toBe(50);
    expect(r.min).toBeGreaterThanOrEqual(1);
    expect(r.max).toBeLessThanOrEqual(100);
    expect(r.sum / r.runs).toBeGreaterThan(1);
  });

  it('puts the mean largest pile near the paper’s 2.14 for 100 balls in 1,000 bins', () => {
    // 4,000 runs: the standard error on the mean is about 0.372/sqrt(4000)
    // = 0.006, so a 0.06 window is ten sigma. The paper's figure is 2.14.
    const r = runBallsAndBins(4000, 100, 1000);
    const { mean } = meanAndSd(r.runs, r.sum, r.sumSquares);
    expect(mean).toBeGreaterThan(2.08);
    expect(mean).toBeLessThan(2.20);
    expect(r.min).toBe(1);
    expect(r.max).toBeGreaterThanOrEqual(4);
  });

  // FACTS 7, first bullet: the brief author's rerun over 100,000 runs gave
  // mean 2.138, min 1, max 5, sd 0.373.
  slow('reproduces the 100,000-run figure: mean 2.13-2.15, min 1, max 5', () => {
    const r = runBallsAndBins(100_000, 100, 1000);
    const { mean, sd } = meanAndSd(r.runs, r.sum, r.sumSquares);
    console.log(`balls-and-bins: runs=${r.runs} mean=${mean.toFixed(3)} sd=${sd.toFixed(3)} min=${r.min} max=${r.max}`);
    expect(mean).toBeGreaterThan(2.12);
    expect(mean).toBeLessThan(2.16);
    expect(r.min).toBe(1);
    expect(r.max).toBe(5);
    expect(sd).toBeGreaterThan(0.35);
    expect(sd).toBeLessThan(0.40);
  });
});

describe('card trials', () => {
  it('runs, counts, and keeps every decryption valid', () => {
    const dict = syntheticDictionary(100);
    const t = runCardTrials(20, dict);
    expect(t.trials).toBe(20);
    expect(t.allValidTrials).toBe(20);
    expect(t.dictionarySize).toBe(100);
    expect(t.successes).toBeLessThanOrEqual(t.trials);
  });

  it('reports progress and honours cancellation', () => {
    const seen: number[] = [];
    const t = runCardTrials(100, syntheticDictionary(10), {
      progressEvery: 2,
      onProgress: (n) => seen.push(n),
      shouldStop: () => seen.length >= 3,
    });
    expect(seen.length).toBeGreaterThanOrEqual(3);
    expect(t.trials).toBeLessThan(100);
  });

  // ACCEPTANCE E, cards. Tagged slow: 3,000 trials x 100 passwords is 300,000
  // PBKDF2 evaluations.
  slow('ACCEPTANCE E — 3,000 card trials: all decryptions valid, success 0.4%-1.8%', () => {
    const dict = syntheticDictionary(100);
    const t = runCardTrials(3000, dict);
    const pct = rate(t.successes, t.trials);
    console.log(
      `cards: trials=${t.trials} successes=${t.successes} (${pct.toFixed(2)}%) ` +
        `allValid=${t.allValidTrials} allDistinct=${t.allDistinctTrials} minDistinct=${t.minDistinct}`,
    );
    expect(t.trials).toBe(3000);
    // Every one of the 100 decryptions, in every trial, was a valid card.
    expect(t.allValidTrials).toBe(3000);
    // w = 1/100, and the attacker achieves w.
    expect(pct).toBeGreaterThan(0.4);
    expect(pct).toBeLessThan(1.8);
  });
});

describe('pile-up trials', () => {
  it('runs and counts', () => {
    const t = runPileUpTrials(20, syntheticDictionary(100), 1000);
    expect(t.trials).toBe(20);
    expect(t.messageSpace).toBe(1000);
    expect(t.minPile).toBeGreaterThanOrEqual(1);
    expect(t.maxPile).toBeGreaterThanOrEqual(t.minPile);
  });

  // ACCEPTANCE E, verification values.
  slow('ACCEPTANCE E — 20,000 pile-up trials: success 1.8%-2.5%, mean pile 2.10-2.18', () => {
    const t = runPileUpTrials(20_000, syntheticDictionary(100), 1000);
    const pct = rate(t.successes, t.trials);
    const { mean, sd } = meanAndSd(t.trials, t.pileSum, t.pileSumSquares);
    console.log(
      `pile-up: trials=${t.trials} successes=${t.successes} (${pct.toFixed(2)}%) ` +
        `meanPile=${mean.toFixed(3)} sd=${sd.toFixed(3)} min=${t.minPile} max=${t.maxPile}`,
    );
    expect(t.trials).toBe(20_000);
    expect(pct).toBeGreaterThan(1.8);
    expect(pct).toBeLessThan(2.5);
    expect(mean).toBeGreaterThan(2.10);
    expect(mean).toBeLessThan(2.18);
  });
});
