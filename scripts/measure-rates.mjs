/**
 * Measure the attacker success rates the README and the page quote.
 *
 * Sharded across worker threads, because the pile-up run is about two million
 * PBKDF2 evaluations and a single thread takes the better part of an hour on a
 * busy machine. Each worker runs the SAME functions the browser runs — Node 26
 * imports the TypeScript sources directly — and the shards are merged with the
 * same accumulator merge the Web Worker uses, so the figure reported here is
 * the figure the page would reach given the same number of trials.
 *
 *   node scripts/measure-rates.mjs [--cards N] [--pileup N] [--bnb N] [--workers N]
 *
 * Every number it prints carries its denominator.
 */
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import os from 'node:os';
import { registerHooks } from 'node:module';
import { fileURLToPath } from 'node:url';

const SELF = fileURLToPath(import.meta.url);

/**
 * Let Node follow the extensionless relative imports the sources use.
 *
 * Node 26 executes TypeScript directly but, unlike a bundler, will not guess
 * an extension. Rather than keep a second copy of the trial code or add a
 * build step, this hook appends `.ts` when the bare specifier does not exist
 * — so the script runs the SAME source files the browser bundle is built
 * from. It is registered in both the main thread and each worker.
 */
registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('.') && !/\.[cm]?[jt]s$/.test(specifier)) {
      try {
        return next(specifier, context);
      } catch {
        return next(`${specifier}.ts`, context);
      }
    }
    return next(specifier, context);
  },
});

const {
  runCardTrials,
  runPileUpTrials,
  runBallsAndBins,
  syntheticDictionary,
  mergeCardTotals,
  mergePileUpTotals,
  emptyCardTotals,
  emptyPileUpTotals,
  meanAndSd,
  rate,
} = await import('../src/he/trials.ts');

if (!isMainThread) {
  const { kind, trials, dictSize, messageSpace } = workerData;
  const dict = syntheticDictionary(dictSize);
  let out;
  if (kind === 'cards') out = runCardTrials(trials, dict);
  else if (kind === 'pileup') out = runPileUpTrials(trials, dict, messageSpace);
  else out = runBallsAndBins(trials, 100, 1000);
  parentPort.postMessage(out);
} else {
  const argv = process.argv.slice(2);
  const arg = (name, dflt) => {
    const i = argv.indexOf(`--${name}`);
    return i === -1 ? dflt : Number(argv[i + 1]);
  };
  const cardTrials = arg('cards', 3000);
  const pileTrials = arg('pileup', 20000);
  const bnbRuns = arg('bnb', 100000);
  const workers = arg('workers', Math.max(1, Math.min(os.cpus().length, 10)));
  const DICT = 100;
  const SPACE = 1000;

  console.log(`measuring with ${workers} workers on ${os.cpus().length} cores; ` +
    `loadavg ${os.loadavg().map((n) => n.toFixed(1)).join(' ')}`);

  /** Split `total` into `n` nearly equal shards. */
  const shards = (total, n) => {
    const base = Math.floor(total / n);
    return Array.from({ length: n }, (_, i) => base + (i < total % n ? 1 : 0)).filter((x) => x > 0);
  };

  const run = (kind, trials, extra = {}) =>
    new Promise((resolve, reject) => {
      const w = new Worker(SELF, { workerData: { kind, trials, dictSize: DICT, ...extra } });
      w.once('message', (m) => { resolve(m); w.terminate(); });
      w.once('error', reject);
    });

  const t0 = Date.now();

  // Balls and bins — no cryptography, so it is cheap and still worth sharding.
  const bnbParts = await Promise.all(shards(bnbRuns, workers).map((n) => run('bnb', n)));
  const bnb = bnbParts.reduce((a, b) => ({
    runs: a.runs + b.runs, sum: a.sum + b.sum, sumSquares: a.sumSquares + b.sumSquares,
    min: Math.min(a.min, b.min), max: Math.max(a.max, b.max),
  }));
  const bnbStats = meanAndSd(bnb.runs, bnb.sum, bnb.sumSquares);
  console.log(
    `\nBALLS AND BINS (100 balls, 1,000 bins, no crypto)\n` +
    `  runs=${bnb.runs}  mean largest pile=${bnbStats.mean.toFixed(3)}  ` +
    `sd=${bnbStats.sd.toFixed(3)}  min=${bnb.min}  max=${bnb.max}\n` +
    `  paper's simulation: mean 2.14, min 1, max 5, sd 0.372 over 100,000 runs`);

  // Cards.
  const cardParts = await Promise.all(shards(cardTrials, workers).map((n) => run('cards', n)));
  const cards = cardParts.reduce(mergeCardTotals, emptyCardTotals(DICT));
  console.log(
    `\nCARDS (b = 10^9, ${DICT} equally likely passwords, w = ${(100 / DICT).toFixed(0)}%)\n` +
    `  trials=${cards.trials}  attacker successes=${cards.successes}  ` +
    `rate=${rate(cards.successes, cards.trials).toFixed(3)}%\n` +
    `  trials in which all ${DICT} decryptions were valid cards: ${cards.allValidTrials}/${cards.trials}\n` +
    `  trials in which all ${DICT} decryptions were distinct:    ${cards.allDistinctTrials}/${cards.trials}` +
    `  (fewest distinct in any trial: ${cards.minDistinct})`);

  // Verification values.
  const pileParts = await Promise.all(
    shards(pileTrials, workers).map((n) => run('pileup', n, { messageSpace: SPACE })),
  );
  const pile = pileParts.reduce(mergePileUpTotals, emptyPileUpTotals(DICT, SPACE));
  const pileStats = meanAndSd(pile.trials, pile.pileSum, pile.pileSumSquares);
  console.log(
    `\nVERIFICATION VALUES (b = ${SPACE}, ${DICT} equally likely passwords)\n` +
    `  trials=${pile.trials}  attacker successes=${pile.successes}  ` +
    `rate=${rate(pile.successes, pile.trials).toFixed(3)}%\n` +
    `  mean largest pile=${pileStats.mean.toFixed(3)}  sd=${pileStats.sd.toFixed(3)}  ` +
    `min=${pile.minPile}  max=${pile.maxPile}\n` +
    `  paper's figure for this case: about 2.14%, twice w`);

  console.log(`\nelapsed ${((Date.now() - t0) / 1000).toFixed(0)}s`);
}
