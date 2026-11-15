/**
 * Exhibit 5 — a small message space.
 *
 * Honey encryption's guarantee is a bound, not a wall, and the bound depends
 * on the message space being large next to the number of candidate keys. For a
 * three-digit verification value there are only a thousand messages and a
 * hundred candidate passwords, so several candidates land on the same value by
 * chance — and the attacker can output whichever value the most passwords
 * agree on. That attack beats w, by about a factor of two.
 *
 * The page shows one attack in full, then measures the rate.
 */

import { henc, hdec } from '../he/he';
import { attackPileUp, scoreRecovery } from '../he/attacks';
import { card, disclosure, el, fill, note, scopeNote, stat, tableWrap, verdict } from './dom';
import { commas, dictionaryOf, pct } from './shared';
import { mountTrials } from './trials-panel';

const SPACE = 1000n;
const DICT = 100;

export function mountSmall(root: HTMLElement): void {
  const runBtn = el('button', { class: 'btn', type: 'button', id: 'small-run' }, [
    'Run one pile-up attack',
  ]);
  const out = el('div', { id: 'small-out' });

  runBtn.addEventListener('click', () => {
    const dictionary = dictionaryOf(DICT);
    const trueIndex = Math.floor(Math.random() * dictionary.length);
    const truePassword = dictionary[trueIndex]!;
    const trueValue = Math.floor(Math.random() * Number(SPACE));
    const ct = henc(truePassword, BigInt(trueValue), SPACE);

    // The attacker sees the ciphertext and the list.
    const attack = attackPileUp(ct, dictionary, SPACE);
    const score = scoreRecovery(attack.guess, trueValue);

    // The piles, largest first, for display.
    const piles = [...attack.piles.entries()]
      .sort((a, b) => b[1] - a[1] || a[0] - b[0])
      .slice(0, 12);

    const table = el('table', {}, [
      el('caption', {}, [
        `The twelve biggest piles of ${commas(attack.piles.size)}. ` +
          `${commas(DICT)} candidate passwords fell into ${commas(attack.piles.size)} distinct values.`,
      ]),
      el('thead', {}, [
        el('tr', {}, [
          el('th', { scope: 'col' }, ['Verification value']),
          el('th', { scope: 'col' }, ['Passwords that decrypt to it']),
          el('th', { scope: 'col' }, ['The attacker’s choice']),
        ]),
      ]),
      el(
        'tbody',
        {},
        piles.map(([value, n]) =>
          el('tr', {}, [
            el('td', { class: 'num' }, [String(value).padStart(3, '0')]),
            el('td', { class: 'num' }, [String(n)]),
            el('td', {}, [value === attack.guess ? '=  this one' : '']),
          ]),
        ),
      ),
    ]);

    fill(out, [
      el('div', { class: 'stat-row' }, [
        stat('Message space', commas(SPACE), 'three digits'),
        stat('Candidate passwords', commas(DICT), `w = ${pct(100 / DICT)}`),
        stat('Largest pile', String(attack.largestPile), `on value ${String(attack.guess).padStart(3, '0')}`),
        stat('Distinct values hit', commas(attack.piles.size), `of ${commas(SPACE)}`),
      ]),
      verdict(
        score.succeeded ? 'broken' : 'held',
        score.succeeded
          ? `PILE-UP ATTACK SUCCEEDED — THE VALUE WAS ${String(trueValue).padStart(3, '0')}`
          : 'PILE-UP ATTACK FAILED',
        score.succeeded
          ? `The attacker output ${String(attack.guess).padStart(3, '0')}, backed by ${attack.largestPile} of the ${commas(DICT)} candidates, and it was right. Over many trials this strategy wins about twice as often as w — measure it below.`
          : `The attacker output ${String(attack.guess).padStart(3, '0')}, backed by ${attack.largestPile} candidates. The true value was ${String(trueValue).padStart(3, '0')}, which ${attack.piles.get(trueValue) ?? 0} candidate(s) produced. Run it again: it wins roughly one time in fifty.`,
        'pileup-single',
      ),
      tableWrap('Pile sizes', table),
      note([
        'The true password "',
        truePassword,
        '" decrypts to ',
        String(Number(hdec(truePassword, ct, SPACE))).padStart(3, '0'),
        ', which is the value this trial encrypted. That line is written by the page, which knows ',
        'the truth; the attacker above was not given it.',
      ]),
    ]);
  });

  root.append(
    card([
      el('h2', {}, ['Where the message space is small, the attacker gets a distinguisher back']),
      el('p', { class: 'lede' }, [
        'A card verification value is three digits: a thousand possibilities. Decrypt one honey ',
        'ciphertext under a hundred candidate passwords and you get a hundred values out of a ',
        'thousand, so by the pigeonhole of chance several candidates agree. That agreement is ',
        'information the attacker did not have in exhibit 4, and it is worth about a factor of two.',
      ]),
      el('div', { class: 'controls' }, [runBtn]),
      out,
      disclosure('Why this is a balls-and-bins question', [
        el('p', {}, [
          'Think of each candidate password as a ball and each possible message as a bin. A ball ',
          'lands in the bin its password decrypts to, and — with the hash modelled as a random ',
          'oracle — it lands independently of the others. The attacker outputs the fullest bin, so ',
          'its success is the expected size of the largest pile divided by the number of balls. ',
          'For a hundred balls in a thousand bins the paper simulates the mean largest pile at ',
          '2.14 over a hundred thousand runs (minimum 1, maximum 5, standard deviation 0.372), ',
          'i.e. about 2.14% against w = 1%.',
        ]),
        el('p', {}, [
          'Its own analytical bounds for this case are looser than that — Theorem 4 gives about ',
          '16.35% and its Corollary 2 about 4.094% — and the paper says plainly that simulation ',
          'gives the better estimate here, and that improving the bounds is future work. The ',
          'measurement button above runs both the real attack and the abstract balls-and-bins ',
          'game, so you can see them agree.',
        ]),
      ]),
      scopeNote([
        'What this is not: a PIN encoder. The paper also treats user-selected PINs, whose ',
        'distribution is wildly non-uniform — in the 3.4-million-PIN corpus it cites, "1234" alone ',
        'has a frequency of 10.713%, leaving roughly three bits of min-entropy — and that needs a ',
        'real frequency corpus plus the non-uniform balls-and-bins analysis of its Corollary 1. ',
        'Not built here.',
      ]),
      mountTrials('pileup'),
    ]),
  );

  runBtn.click();
}
