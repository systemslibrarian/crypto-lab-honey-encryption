import { describe, expect, it } from 'vitest';
import {
  SEED_SPACE,
  decode,
  encode,
  interval,
  maxIntervalDeviation,
  randomBelow,
} from './dte';

const B = 1_000_000_000n;
const B3 = 1000n;

describe('the distribution-transforming encoder', () => {
  // ACCEPTANCE B. These bounds were computed independently of this source, in
  // Python, before the source existed.
  it('gives account 123456789 the documented interval', () => {
    const iv = interval(123456789n, B);
    expect(iv.lo).toBe(0x1f9add3739635f32n);
    expect(iv.hi).toBe(0x1f9add3b84e6593bn);
    expect(iv.size).toBe(18_446_744_073n);
  });

  it('decodes that interval’s edges and their neighbours', () => {
    const { lo, hi } = interval(123456789n, B);
    expect(decode(lo, B)).toBe(123456789n);
    expect(decode(hi - 1n, B)).toBe(123456789n);
    expect(decode(hi, B)).toBe(123456790n);
    expect(decode(lo - 1n, B)).toBe(123456788n);
  });

  it('decodes the ends of the seed space', () => {
    expect(decode(0n, B)).toBe(0n);
    expect(decode(SEED_SPACE - 1n, B)).toBe(B - 1n);
    expect(decode(0n, B3)).toBe(0n);
    expect(decode(SEED_SPACE - 1n, B3)).toBe(B3 - 1n);
  });

  it('gives every interval one of two adjacent sizes (b = 10^9)', () => {
    const sizes = new Set<bigint>();
    for (let i = 0n; i < 20000n; i++) sizes.add(interval(i, B).size);
    for (let i = B - 20000n; i < B; i++) sizes.add(interval(i, B).size);
    expect([...sizes].sort()).toEqual([18_446_744_073n, 18_446_744_074n]);
  });

  it('gives every interval one of two adjacent sizes (b = 1000)', () => {
    const sizes = new Set<bigint>();
    for (let i = 0n; i < B3; i++) sizes.add(interval(i, B3).size);
    expect([...sizes].sort()).toEqual([18_446_744_073_709_551n, 18_446_744_073_709_552n]);
  });

  // INVARIANT 1, and the property the whole construction rests on: the
  // intervals TILE the seed space with no gap and no overlap.
  it('tiles the seed space exactly (b = 1000)', () => {
    let cursor = 0n;
    let total = 0n;
    for (let i = 0n; i < B3; i++) {
      const iv = interval(i, B3);
      expect(iv.lo).toBe(cursor);
      cursor = iv.hi;
      total += iv.size;
    }
    expect(cursor).toBe(SEED_SPACE);
    expect(total).toBe(SEED_SPACE);
  });

  it('round-trips decode(encode(i)) for 10,000 random accounts and both ends', () => {
    for (const i of [0n, B - 1n]) expect(decode(encode(i, B), B)).toBe(i);
    for (let n = 0; n < 10_000; n++) {
      const i = randomBelow(B);
      expect(decode(encode(i, B), B), `account ${i}`).toBe(i);
    }
  });

  it('round-trips every message of a small space', () => {
    for (let i = 0n; i < B3; i++) expect(decode(encode(i, B3), B3), `message ${i}`).toBe(i);
  });

  // Mutation (3) makes encode always return the lower bound. The fixed vector
  // alone cannot see that, because it supplies its own seed; this does.
  it('draws seeds that vary across the interval, not just its lower bound', () => {
    const { lo, hi } = interval(123456789n, B);
    const seeds = new Set<bigint>();
    for (let n = 0; n < 200; n++) {
      const s = encode(123456789n, B);
      expect(s >= lo && s < hi).toBe(true);
      seeds.add(s);
    }
    // 200 draws from 1.8e10 seeds: all distinct with overwhelming probability,
    // and the assertion that matters is simply that they are not all `lo`.
    expect(seeds.size).toBeGreaterThan(190);
    expect(seeds.has(lo) && seeds.size === 1).toBe(false);
  });

  it('spreads draws over both halves of an interval', () => {
    const { lo, hi } = interval(7n, B3);
    const mid = lo + (hi - lo) / 2n;
    let low = 0;
    let high = 0;
    for (let n = 0; n < 400; n++) (encode(7n, B3) < mid ? low++ : high++);
    expect(low).toBeGreaterThan(120);
    expect(high).toBeGreaterThan(120);
  });

  it('keeps the induced distribution within 2^-64 of uniform', () => {
    // Each interval's size differs from 2^64/b by less than one seed, so
    // |p_d(M) - p_m(M)| < 2^-64 — the bound of the paper's Theorem 8.
    expect(maxIntervalDeviation(B3)).toBeLessThanOrEqual(1n);
    expect(maxIntervalDeviation(B)).toBeLessThanOrEqual(1n);
  });

  it('refuses a seed outside the seed space, and a message outside the space', () => {
    expect(() => decode(-1n, B)).toThrow(/outside \[0, 2\^64\)/);
    expect(() => decode(SEED_SPACE, B)).toThrow(/outside \[0, 2\^64\)/);
    expect(() => interval(B, B)).toThrow(/outside/);
    expect(() => interval(-1n, B)).toThrow(/outside/);
    expect(() => decode(0n, 0n)).toThrow(/must be positive/);
  });

  describe('randomBelow', () => {
    it('stays in range and covers the whole range', () => {
      const seen = new Set<bigint>();
      for (let i = 0; i < 4000; i++) {
        const v = randomBelow(10n);
        expect(v >= 0n && v < 10n).toBe(true);
        seen.add(v);
      }
      expect(seen.size).toBe(10);
    });

    it('is unbiased: a chi-square over 10 bins stays inside the 99.9% point', () => {
      const bins = new Array(10).fill(0);
      const N = 60_000;
      for (let i = 0; i < N; i++) bins[Number(randomBelow(10n))]++;
      const exp = N / 10;
      const chi = bins.reduce((a, o) => a + ((o - exp) ** 2) / exp, 0);
      // 9 degrees of freedom: the 99.9% point is 27.88.
      expect(chi).toBeLessThan(27.88);
    });

    it('rejects rather than folding: a bounded generator never returns out of range', () => {
      // A generator pinned to the top of its byte range would, under a modulo
      // reduction, fold onto a low value. Rejection sampling must loop until
      // it draws something inside the limit instead.
      let calls = 0;
      const rng = (n: number) => {
        calls++;
        // 0xff..., in range for the first few calls, then a value under the limit.
        return new Uint8Array(n).fill(calls < 4 ? 0xff : 0x01);
      };
      const v = randomBelow(100n, rng);
      expect(calls).toBeGreaterThan(1);
      expect(v >= 0n && v < 100n).toBe(true);
    });

    it('handles the degenerate bound', () => {
      expect(randomBelow(1n)).toBe(0n);
      expect(() => randomBelow(0n)).toThrow(/positive bound/);
    });
  });
});
