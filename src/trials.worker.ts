/**
 * The many-trial worker.
 *
 * Measuring an attacker's success rate means running the attack thousands of
 * times, and each run is a hundred PBKDF2 evaluations. On the main thread that
 * freezes the page; here it reports progress and can be cancelled between
 * trials.
 *
 * The worker runs the same functions the unit tests and
 * scripts/measure-rates.mjs run. It computes nothing of its own.
 */

import {
  emptyCardTotals,
  emptyPileUpTotals,
  mergeCardTotals,
  mergePileUpTotals,
  runBallsAndBins,
  runCardTrials,
  runPileUpTrials,
  syntheticDictionary,
  type CardTrialTotals,
  type PileUpTotals,
} from './he/trials';
import { keyForPassword } from './he/he';

export type TrialRequest =
  | { kind: 'cards'; trials: number; dictSize: number }
  | { kind: 'pileup'; trials: number; dictSize: number; messageSpace: number }
  | { kind: 'cancel' };

export type TrialMessage =
  | { type: 'progress'; done: number; total: number }
  | { type: 'cards'; totals: CardTrialTotals; done: true }
  | { type: 'pileup'; totals: PileUpTotals; ballsAndBins: ReturnType<typeof runBallsAndBins>; done: true }
  | { type: 'cancelled'; done: true }
  | { type: 'error'; message: string; done: true };

let cancelled = false;

/**
 * Trials are run in chunks so the worker can see a cancel message between
 * them. A worker blocked in one long synchronous loop never reads its inbox,
 * so a cancel button wired to it would do nothing.
 */
const CHUNK = 100;

self.addEventListener('message', (ev: MessageEvent<TrialRequest>) => {
  const req = ev.data;
  if (req.kind === 'cancel') {
    cancelled = true;
    return;
  }
  cancelled = false;
  try {
    if (req.kind === 'cards') runCards(req.trials, req.dictSize);
    else runPileUp(req.trials, req.dictSize, req.messageSpace);
  } catch (e) {
    post({ type: 'error', message: e instanceof Error ? e.message : String(e), done: true });
  }
});

function post(m: TrialMessage): void {
  (self as unknown as Worker).postMessage(m);
}

function runCards(trials: number, dictSize: number): void {
  const dictionary = syntheticDictionary(dictSize);
  const keys = dictionary.map(keyForPassword);
  step(emptyCardTotals(dictSize), 0);

  function step(totals: CardTrialTotals, done: number): void {
    if (cancelled) {
      post({ type: 'cancelled', done: true });
      return;
    }
    const n = Math.min(CHUNK, trials - done);
    const next = mergeCardTotals(totals, runCardTrials(n, dictionary, { keys }));
    const advanced = done + n;
    post({ type: 'progress', done: advanced, total: trials });
    if (advanced < trials) {
      setTimeout(() => step(next, advanced), 0);
      return;
    }
    post({ type: 'cards', totals: next, done: true });
  }
}

function runPileUp(trials: number, dictSize: number, messageSpace: number): void {
  const dictionary = syntheticDictionary(dictSize);
  const keys = dictionary.map(keyForPassword);
  step(emptyPileUpTotals(dictSize, messageSpace), 0);

  function step(totals: PileUpTotals, done: number): void {
    if (cancelled) {
      post({ type: 'cancelled', done: true });
      return;
    }
    const n = Math.min(CHUNK, trials - done);
    const next = mergePileUpTotals(
      totals,
      runPileUpTrials(n, dictionary, messageSpace, { keys }),
    );
    const advanced = done + n;
    post({ type: 'progress', done: advanced, total: trials });
    if (advanced < trials) {
      setTimeout(() => step(next, advanced), 0);
      return;
    }
    // The abstract model, run alongside: 100 balls into 1,000 bins, no
    // cryptography. If the two disagree, the encoder is what to suspect.
    post({
      type: 'pileup',
      totals: next,
      ballsAndBins: runBallsAndBins(Math.max(2000, trials), dictSize, messageSpace),
      done: true,
    });
  }
}
