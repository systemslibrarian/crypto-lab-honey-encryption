/**
 * The distribution-transforming encoder (DTE).
 *
 * A DTE is the piece that makes honey encryption work. `encode` turns a message
 * into a SEED drawn uniformly from the part of the seed space that message owns;
 * `decode` turns ANY seed back into a message. Because the intervals tile the
 * whole space, decode is defined on every seed — there is no "invalid seed", so
 * no decryption can ever be rejected, so a brute-force search never learns when
 * it has won.
 *
 * This is an inverse-sampling encoder in the style of Juels and Ristenpart,
 * "Honey Encryption: Security Beyond the Brute-Force Bound" (IACR ePrint
 * 2014/155) — its section 4 defines the ideal real-valued construction and its
 * Appendix C gives a generic fixed-point realisation. The differences between
 * that realisation and this one are documented in README.md under
 * "Build & Verify"; in short, this is the l = 64 specialisation for a UNIFORM
 * distribution, where the boundary is a ceiling rather than a round-to-nearest,
 * which is what makes the floor-division decoder below an exact inverse.
 *
 * Every value here is a BigInt. A seed is a 64-bit integer, which exceeds
 * Number.MAX_SAFE_INTEGER by eleven bits: passing one through a float would
 * silently round it onto a neighbouring seed and, near an interval boundary,
 * onto a neighbouring card.
 */

/** The size of the seed space, 2^64. Seeds are the integers in [0, 2^64). */
export const SEED_SPACE = 1n << 64n;

/** A half-open interval of seeds, `[lo, hi)`. */
export interface SeedInterval {
  lo: bigint;
  hi: bigint;
  /** hi - lo, the number of seeds the message owns. */
  size: bigint;
}

function requireBase(b: bigint): void {
  if (b <= 0n) throw new Error(`dte: base must be positive, got ${b}`);
  if (b > SEED_SPACE) throw new Error(`dte: base ${b} exceeds the seed space`);
}

/**
 * The lower bound of message `i`'s interval: ceil(i * 2^64 / b).
 *
 * The ceiling is load-bearing. With a floor, message i's first seed would fall
 * inside the floor-division bucket of message i-1 and `decode(encode(i))` would
 * fail for the i where the division is inexact — which is almost all of them.
 */
function boundary(i: bigint, b: bigint): bigint {
  const num = i * SEED_SPACE;
  // ceil(num / b) for non-negative num.
  return (num + b - 1n) / b;
}

/** The half-open seed interval owned by message `i` of a uniform space of `b`. */
export function interval(i: bigint, b: bigint): SeedInterval {
  requireBase(b);
  if (i < 0n || i >= b) throw new Error(`dte: message ${i} outside [0, ${b})`);
  const lo = boundary(i, b);
  const hi = boundary(i + 1n, b);
  return { lo, hi, size: hi - lo };
}

/**
 * Decode: the message owning seed `S`, i.e. floor(S * b / 2^64).
 *
 * Defined on every seed in [0, 2^64) — that total coverage is the property the
 * whole scheme rests on.
 */
export function decode(S: bigint, b: bigint): bigint {
  requireBase(b);
  if (S < 0n || S >= SEED_SPACE) throw new Error(`dte: seed outside [0, 2^64): ${S}`);
  return (S * b) / SEED_SPACE;
}

/**
 * A uniform random BigInt in `[0, n)`, by rejection sampling over whole bytes.
 *
 * Taking a random value modulo `n` would bias the low messages whenever `n`
 * does not divide the sampled range — here that would make some cards likelier
 * than others and quietly weaken the very property being demonstrated. So the
 * loop redraws instead, which terminates with probability > 1/2 per attempt.
 */
export function randomBelow(n: bigint, rng: RandomSource = cryptoRandom): bigint {
  if (n <= 0n) throw new Error(`dte: randomBelow needs a positive bound, got ${n}`);
  if (n === 1n) return 0n;
  const bits = n.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  const excess = BigInt(bytes * 8 - bits);
  // The largest multiple of n that fits in `bits` bits; draws at or above it
  // are rejected rather than folded in.
  const limit = (1n << BigInt(bits)) - ((1n << BigInt(bits)) % n);
  for (;;) {
    const buf = rng(bytes);
    let v = 0n;
    for (const byte of buf) v = (v << 8n) | BigInt(byte);
    v >>= excess;
    if (v < limit) return v % n;
  }
}

/** Where random bytes come from. Injectable so tests can pin a draw. */
export type RandomSource = (bytes: number) => Uint8Array;

export const cryptoRandom: RandomSource = (bytes) =>
  crypto.getRandomValues(new Uint8Array(bytes));

/**
 * Encode message `i`: a seed drawn uniformly from the interval it owns.
 *
 * Randomized, as the paper's `encode` is. Two encodings of the same card are
 * different seeds, and therefore different ciphertexts.
 */
export function encode(i: bigint, b: bigint, rng: RandomSource = cryptoRandom): bigint {
  const { lo, size } = interval(i, b);
  return lo + randomBelow(size, rng);
}

/**
 * How far this encoder's induced message distribution can sit from uniform.
 *
 * Each interval's size differs from the exact 2^64 / b by less than one seed,
 * so |p_d(M) - p_m(M)| < 2^-64 for every message — the same bound the paper's
 * Theorem 8 gives its own realisation. Returned as the numerator over 2^64 so
 * the page can show it without a float.
 */
export function maxIntervalDeviation(b: bigint): bigint {
  requireBase(b);
  const exact = SEED_SPACE / b;
  let worst = 0n;
  // The sizes of ceil-spaced intervals take only two values, and both occur
  // within the first b + 1 boundaries; sampling the first few hundred finds
  // both for every b this lab uses.
  const probe = b < 512n ? b : 512n;
  for (let i = 0n; i < probe; i++) {
    const d = interval(i, b).size - exact;
    const abs = d < 0n ? -d : d;
    if (abs > worst) worst = abs;
  }
  return worst;
}

/**
 * [extension] point — a non-uniform distribution seam.
 *
 * The paper's PIN encoder needs a CDF from a real PIN-frequency corpus (its
 * section 7.1 cites a 3.4-million-PIN study, in which `1234` alone has
 * frequency 10.713%). Implementing one here without that corpus would mean
 * inventing the frequencies, so the interface is shaped and left unbuilt: a
 * `Distribution` supplies cumulative weights over 2^64 and the two functions
 * below become a binary search over them instead of a division.
 *
 * NOT BUILT HERE. See README.md, "Non-goals".
 */
export interface Distribution {
  /** How many messages the distribution covers. */
  size(): bigint;
  /** The cumulative weight below message `i`, scaled to [0, 2^64]. */
  cumulativeBelow(i: bigint): bigint;
  /** The message whose cumulative band contains `S`. */
  messageAt(S: bigint): bigint;
}
