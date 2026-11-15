/**
 * Exhibit 4 — the search, again.
 *
 * The same dictionary attack as exhibit 1, against honey encryption. Now every
 * candidate yields a valid card and the attacker has nothing to choose between
 * them.
 *
 * THE LIST MUST NOT GIVE THE ANSWER AWAY. Before the learner asks to see it,
 * no row carries a class, a data attribute, an ordering or a colour that
 * separates the true card from the others — the true password's row is built
 * by exactly the same code path as every other row, and the index of the truth
 * is not written into the DOM at all. The reveal adds `is-true` to one row,
 * and the claims suite asserts the DOM carries nothing distinguishing before
 * that happens.
 *
 * This exhibit also carries the lab's NEGATIVE CLAIM, and the state it arrives
 * in is that claim's evidence fixture.
 */

import { ACCOUNT_SPACE, luhnValid } from '../he/luhn';
import { interval } from '../he/dte';
import { hencWithSeed, henc, type HeCiphertext } from '../he/he';
import { attackHoney, scoreAttack, type HeCandidate } from '../he/attacks';
import { card, disclosure, el, field, fill, note, stat, tableWrap, verdict } from './dom';
import {
  VECTOR_ACCOUNT,
  VECTOR_DICTIONARY,
  VECTOR_PASSWORD,
  commas,
  dictionaryOf,
  pct,
} from './shared';
import { mountTrials } from './trials-panel';

const B = BigInt(ACCOUNT_SPACE);
const VECTOR_R = new Uint8Array(Array.from({ length: 16 }, (_, i) => i));
const VECTOR_SEED = interval(BigInt(VECTOR_ACCOUNT), B).lo + 0x1234567n;

/** The negative claim, scoped to what this page puts on screen. */
export const NEGATIVE_CLAIM =
  'A decryption that looks like a valid card says nothing about whether the password was right: ' +
  'here every one of these passwords produced a valid card, and only one of them is the real one.';

interface Run {
  rows: HeCandidate[];
  truePassword: string;
  trueAccount: number;
  dictSize: number;
  revealed: boolean;
  /** The row the learner, playing the attacker, committed to. */
  picked: string | null;
}

export function mountSearch(root: HTMLElement): void {
  let run: Run | null = null;

  const sizeSelect = el('select', { id: 'search-size' }, [
    el('option', { value: 'vector', selected: true }, ['The 6 passwords of the published vector']),
    el('option', { value: '100' }, ['100 candidate passwords']),
  ]);
  const runBtn = el('button', { class: 'btn', type: 'button', id: 'search-run' }, [
    'Run the dictionary attack',
  ]);
  const revealBtn = el('button', { class: 'btn btn-secondary', type: 'button', id: 'search-reveal' }, [
    'Reveal which one is real',
  ]);
  const out = el('div', { id: 'search-out' });

  sizeSelect.addEventListener('change', () => {
    // Changing the dictionary retires the result; re-selecting the SAME value
    // must not, which is the no-op guard the claims suite checks.
    if (!run) return;
    const wanted = sizeSelect.value === 'vector' ? VECTOR_DICTIONARY.length : 100;
    if (wanted === run.dictSize) return;
    run = null;
    revealBtn.disabled = true;
    fill(out, [
      verdict(
        'stale',
        'RETIRED',
        'The candidate list changed, so the previous attack result no longer describes what is on screen. Run it again.',
        'retired',
      ),
    ]);
  });

  runBtn.addEventListener('click', () => {
    const useVector = sizeSelect.value === 'vector';
    const dictionary = useVector ? [...VECTOR_DICTIONARY] : dictionaryOf(100);
    // The true password is the first entry of the list in the vector case
    // (which is what the published table fixes) and a uniformly chosen entry
    // otherwise, so the key distribution has maximum weight w = 1/|dictionary|.
    const trueIndex = useVector ? 0 : Math.floor(Math.random() * dictionary.length);
    const truePassword = dictionary[trueIndex]!;
    const trueAccount = useVector ? VECTOR_ACCOUNT : Math.floor(Math.random() * ACCOUNT_SPACE);
    const ct: HeCiphertext = useVector
      ? hencWithSeed(VECTOR_PASSWORD, VECTOR_SEED, VECTOR_R)
      : henc(truePassword, BigInt(trueAccount), B);

    // The attacker gets the ciphertext and the list. It does not get the line above.
    const result = attackHoney(ct, dictionary, B);

    run = {
      rows: result.rows,
      truePassword,
      trueAccount,
      dictSize: dictionary.length,
      revealed: false,
      picked: null,
    };
    revealBtn.disabled = false;
    render();
  });

  revealBtn.addEventListener('click', () => {
    if (!run) return;
    run.revealed = true;
    render();
  });

  function pick(password: string): void {
    if (!run) return;
    run.picked = password;
    render();
  }

  function render(): void {
    if (!run) {
      fill(out, []);
      return;
    }
    const { rows, dictSize } = run;
    const validCount = rows.filter((r) => luhnValid(r.card)).length;
    const distinct = new Set(rows.map((r) => r.card)).size;

    const body = rows.map((r) => {
      const isTrue = run!.revealed && r.password === run!.truePassword;
      const pickBtn = el(
        'button',
        { class: 'btn btn-secondary', type: 'button', 'data-pick': r.password },
        ['Pick'],
      );
      pickBtn.addEventListener('click', () => pick(r.password));
      // The ONLY per-row difference before the reveal is the password and the
      // card, both of which the attacker can see anyway. `is-true` is added
      // here and nowhere else.
      return el('tr', isTrue ? { class: 'is-true' } : {}, [
        el('td', {}, [r.password === '' ? '(empty)' : r.password]),
        el('td', { class: 'num' }, [r.card.replace(/(.{4})(?=.)/g, '$1 ')]),
        el('td', {}, [r.luhn ? '=  passes' : 'x  FAILS']),
        el('td', {}, [pickBtn]),
      ]);
    });

    const table = el('table', { class: 'candidates', id: 'search-table' }, [
      el('caption', {}, [
        `${commas(dictSize)} candidate passwords, ${commas(validCount)} valid cards. ` +
          'Every row is the output of HDec under that password.',
      ]),
      el('thead', {}, [
        el('tr', {}, [
          el('th', { scope: 'col' }, ['Candidate password']),
          el('th', { scope: 'col' }, ['Card it decrypts to']),
          el('th', { scope: 'col' }, ['Luhn']),
          el('th', { scope: 'col' }, ['Your guess']),
        ]),
      ]),
      el('tbody', {}, body),
    ]);

    const parts: Array<Node | string> = [
      el('div', { class: 'stat-row' }, [
        stat('Passwords tried', commas(dictSize)),
        stat('Valid cards returned', commas(validCount), `of ${commas(dictSize)}`),
        stat('Distinct cards', commas(distinct), distinct === dictSize ? 'no collisions' : 'two candidates collided'),
        stat('w (most likely password)', pct(100 / dictSize), 'the bound the attacker cannot beat'),
      ]),
      verdict(
        'held',
        `${commas(dictSize)} PASSWORDS TRIED — ${commas(validCount)} VALID CARDS — NO WAY TO TELL`,
        NEGATIVE_CLAIM,
        'no-distinguisher',
      ),
    ];

    if (run.picked !== null) {
      const score = scoreAttack(run.picked, run.truePassword);
      const pickedRow = rows.find((r) => r.password === run!.picked)!;
      parts.push(
        verdict(
          score.succeeded ? 'broken' : 'held',
          score.succeeded ? 'ATTACK SUCCEEDED' : 'ATTACK FAILED',
          score.succeeded
            ? `You picked "${run.picked}", which really was the password. With ${commas(dictSize)} equally likely candidates that happens about ${pct(100 / dictSize)} of the time — which is exactly the bound, not a weakness.`
            : `You picked "${run.picked}". It decrypts to ${pickedRow.card}, which passes the Luhn check — and it is not the card. A valid-looking result is not evidence of a correct password.`,
          'attack-scored',
        ),
      );
    }

    if (run.revealed) {
      parts.push(
        verdict(
          'warned',
          `THE REAL CARD WAS ${run.rows.find((r) => r.password === run!.truePassword)!.card}`,
          `Produced by "${run.truePassword === '' ? '(empty)' : run.truePassword}". Before you pressed the button, nothing on this page or in its markup said so.`,
          'revealed',
        ),
      );
    }

    parts.push(tableWrap('Candidate decryptions', table));
    fill(out, parts);
  }

  root.append(
    card([
      el('h2', {}, ['The same attack, and now it has nothing to go on']),
      el('p', { class: 'lede' }, [
        'Exhibit 1’s attacker worked because it could recognise success. Give it a honey ',
        'ciphertext and the recognition test is gone: every candidate password produces a card, ',
        'every card passes its check digit, and the list below is all the attacker gets. Play the ',
        'attacker yourself — pick the row you think is real, and the page will score your ',
        'guess against the card it kept back.',
      ]),
      el('div', { class: 'controls' }, [
        field('search-size', 'Candidate list', sizeSelect),
        runBtn,
        revealBtn,
      ]),
      out,
      note([
        'The attacker code in ',
        el('code', {}, ['src/he/attacks.ts']),
        ' receives the ciphertext and the candidate list and returns a guess. Whether it succeeded ',
        'is decided by a separate function that takes the truth as its own argument, so ',
        '"returned a valid card" and "recovered the password" can never be scored as the same ',
        'thing. They are different questions, and this exhibit exists because the answers differ.',
      ]),
      disclosure('What the bound actually says', [
        el('p', {}, [
          'Theorem 4 of the paper: for a uniform message space of ',
          el('code', {}, ['b']),
          ' messages and a key distribution whose most likely password has probability ',
          el('code', {}, ['w']),
          ', no attacker recovers the message with probability much above ',
          el('code', {}, ['w']),
          ' — and the bound is tight, because the attacker who decrypts under the single most ',
          'likely password achieves exactly ',
          el('code', {}, ['w']),
          '. With nine uniform account digits, ',
          el('code', {}, ['b = 10^9']),
          ', and with a hundred equally likely passwords ',
          el('code', {}, ['w = 1%']),
          '. So honey encryption does not make a weak password strong. It makes a weak password ',
          'worth exactly what it is worth, instead of worth nothing.',
        ]),
        el('p', {}, [
          'The paper also notes the case where the last four digits are treated as public, which ',
          'shrinks the effective message space to ',
          el('code', {}, ['10^5']),
          ' and gives a bound of about 1.05%.',
        ]),
      ]),
      mountTrials(),
    ]),
  );

  runBtn.click();
}
