/**
 * The many-trial panel, shared by exhibits 4 and 5.
 *
 * Reports a measured success rate beside the bound w, with the number of
 * trials always on screen beside the count. Cancellable, because twenty
 * thousand trials is a couple of minutes of real work.
 */

import { meanAndSd, rate, type CardTrialTotals, type PileUpTotals } from '../he/trials';
import { el, field, fill, stat, verdict } from './dom';
import { commas, pct } from './shared';
import type { TrialMessage, TrialRequest } from '../trials.worker';

export type TrialKind = 'cards' | 'pileup';

interface Options {
  kind: TrialKind;
  heading: string;
  lede: string;
  choices: number[];
  dictSize: number;
  messageSpace: number;
  idPrefix: string;
}

const CARD_OPTIONS: Options = {
  kind: 'cards',
  heading: 'Measure it: how often does the attacker actually win?',
  lede:
    'Each trial encrypts a fresh random card under a password drawn uniformly from the hundred ' +
    'candidates, hands the ciphertext and the list to the attacker, and scores its answer ' +
    'against the card it never saw. The rate it converges on is w.',
  choices: [200, 1000, 3000],
  dictSize: 100,
  messageSpace: 1_000_000_000,
  idPrefix: 'cards',
};

const PILEUP_OPTIONS: Options = {
  kind: 'pileup',
  heading: 'Measure it: the pile-up attack on a three-digit value',
  lede:
    'Same shape, but the message space is a thousand values instead of a billion, so candidates ' +
    'collide. The attacker outputs whichever value the most passwords agree on.',
  choices: [500, 2000, 20000],
  dictSize: 100,
  messageSpace: 1000,
  idPrefix: 'pileup',
};

export function mountTrials(kind: TrialKind = 'cards'): HTMLElement {
  const o = kind === 'cards' ? CARD_OPTIONS : PILEUP_OPTIONS;

  const select = el(
    'select',
    { id: `${o.idPrefix}-trials` },
    o.choices.map((n, i) =>
      el('option', { value: String(n), selected: i === 0 }, [`${commas(n)} trials`]),
    ),
  );
  const runBtn = el('button', { class: 'btn', type: 'button', id: `${o.idPrefix}-run` }, ['Run']);
  const cancelBtn = el(
    'button',
    { class: 'btn btn-secondary', type: 'button', id: `${o.idPrefix}-cancel` },
    ['Cancel'],
  );
  cancelBtn.disabled = true;
  const fillBar = el('div', { class: 'progress-fill' });
  const bar = el('div', {
    class: 'progress',
    role: 'progressbar',
    'aria-label': 'Trial progress',
    'aria-valuemin': '0',
    'aria-valuemax': '100',
    'aria-valuenow': '0',
  }, [fillBar]);
  bar.hidden = true;
  const out = el('div', { id: `${o.idPrefix}-out` });

  let worker: Worker | null = null;

  function stop(): void {
    worker?.terminate();
    worker = null;
    cancelBtn.disabled = true;
    runBtn.disabled = false;
    bar.hidden = true;
  }

  select.addEventListener('change', () => {
    // A changed trial count retires the previous measurement.
    if (!worker) fill(out, []);
  });

  runBtn.addEventListener('click', () => {
    const trials = Number(select.value);
    stop();
    runBtn.disabled = true;
    cancelBtn.disabled = false;
    bar.hidden = false;
    fillBar.style.width = '0';
    bar.setAttribute('aria-valuenow', '0');
    fill(out, [
      verdict('stale', 'RUNNING', `0 of ${commas(trials)} trials complete.`, 'running'),
    ]);

    worker = new Worker(new URL('../trials.worker.ts', import.meta.url), { type: 'module' });
    worker.addEventListener('message', (ev: MessageEvent<TrialMessage>) => {
      const m = ev.data;
      if (m.type === 'progress') {
        const p = Math.round((m.done / m.total) * 100);
        fillBar.style.width = `${p}%`;
        bar.setAttribute('aria-valuenow', String(p));
        return;
      }
      if (m.type === 'cancelled') {
        fill(out, [
          verdict('stale', 'CANCELLED', 'No rate is reported, because the run did not finish.', 'cancelled'),
        ]);
        stop();
        return;
      }
      if (m.type === 'error') {
        fill(out, [verdict('rejected', 'FAILED', m.message, 'trial-error')]);
        stop();
        return;
      }
      if (m.type === 'cards') renderCards(out, m.totals);
      else renderPileUp(out, m.totals, m.ballsAndBins);
      stop();
    });

    const req: TrialRequest =
      o.kind === 'cards'
        ? { kind: 'cards', trials, dictSize: o.dictSize }
        : { kind: 'pileup', trials, dictSize: o.dictSize, messageSpace: o.messageSpace };
    worker.postMessage(req);
  });

  cancelBtn.addEventListener('click', () => {
    worker?.postMessage({ kind: 'cancel' } satisfies TrialRequest);
  });

  return el('div', { class: 'card' }, [
    el('h3', {}, [o.heading]),
    el('p', { class: 'lede' }, [o.lede]),
    el('div', { class: 'controls' }, [
      field(`${o.idPrefix}-trials`, 'Trials', select),
      runBtn,
      cancelBtn,
    ]),
    bar,
    out,
  ]);
}

function renderCards(out: HTMLElement, t: CardTrialTotals): void {
  const r = rate(t.successes, t.trials);
  const w = 100 / t.dictionarySize;
  fill(out, [
    el('div', { class: 'stat-row' }, [
      stat('Attacker successes', `${commas(t.successes)} / ${commas(t.trials)}`, pct(r)),
      stat('w, the bound', pct(w), 'most likely password'),
      stat(
        'Trials where every decryption was a valid card',
        `${commas(t.allValidTrials)} / ${commas(t.trials)}`,
      ),
      stat(
        'Trials where all were distinct',
        `${commas(t.allDistinctTrials)} / ${commas(t.trials)}`,
        `fewest distinct in any trial: ${commas(t.minDistinct)}`,
      ),
    ]),
    verdict(
      'held',
      `MEASURED ${pct(r)} AGAINST A BOUND OF ${pct(w)}`,
      `Counted over ${commas(t.trials)} trials. Every one of the ${commas(t.dictionarySize)} decryptions was a valid card in ${commas(t.allValidTrials)} of them, and the attacker still recovered the password ${commas(t.successes)} times — which is w, and not better.`,
      'cards-rate',
    ),
  ]);
}

function renderPileUp(
  out: HTMLElement,
  t: PileUpTotals,
  bnb: { runs: number; sum: number; sumSquares: number; min: number; max: number },
): void {
  const r = rate(t.successes, t.trials);
  const w = 100 / t.dictionarySize;
  const real = meanAndSd(t.trials, t.pileSum, t.pileSumSquares);
  const model = meanAndSd(bnb.runs, bnb.sum, bnb.sumSquares);
  fill(out, [
    el('div', { class: 'stat-row' }, [
      stat('Attacker successes', `${commas(t.successes)} / ${commas(t.trials)}`, pct(r)),
      stat('w, the bound for message recovery', pct(w)),
      stat('Mean largest pile (real attack)', real.mean.toFixed(3), `sd ${real.sd.toFixed(3)}, min ${t.minPile}, max ${t.maxPile}`),
      stat('Mean largest pile (balls and bins)', model.mean.toFixed(3), `sd ${model.sd.toFixed(3)} over ${commas(bnb.runs)} runs`),
    ]),
    verdict(
      'warned',
      `MEASURED ${pct(r)} — ABOUT TWICE w`,
      `Counted over ${commas(t.trials)} trials against a message space of ${commas(t.messageSpace)}. The paper's own simulation of this case gives a mean largest pile of 2.14 and a success rate of about 2.14%; this run measured ${real.mean.toFixed(3)} and ${pct(r)}. A small message space is where honey encryption gives back some of what it bought: the attacker has a distinguisher again, because candidates collide.`,
      'pileup-rate',
    ),
  ]);
}
