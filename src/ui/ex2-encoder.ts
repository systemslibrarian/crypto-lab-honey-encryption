/**
 * Exhibit 2 — the encoder.
 *
 * The one headline mechanism of the whole lab, shown rather than asserted: the
 * seed space is divided into one interval per card, the intervals tile it with
 * no gaps, and so EVERY seed decodes to a valid card. The learner types or
 * randomises a seed and watches which card owns it.
 */

import { ACCOUNT_SPACE, luhnValid, cardFromAccount } from '../he/luhn';
import { SEED_SPACE, decode, encode, interval, maxIntervalDeviation, randomBelow } from '../he/dte';
import { hex64, hex64Exclusive } from '../he/he';
import { card, disclosure, el, field, fill, note, scopeNote, stat, tableWrap, verdict } from './dom';
import { VECTOR_ACCOUNT, commas, displayCard, formatAccount, parseAccount } from './shared';

const B = BigInt(ACCOUNT_SPACE);

export function mountEncoder(root: HTMLElement): void {
  const accountInput = el('input', {
    type: 'text',
    id: 'enc-account',
    value: formatAccount(VECTOR_ACCOUNT),
    inputmode: 'numeric',
    maxlength: '19',
    'aria-describedby': 'enc-account-hint',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const seedInput = el('input', {
    type: 'text',
    id: 'enc-seed',
    value: hex64(interval(BigInt(VECTOR_ACCOUNT), B).lo + 0x1234567n),
    'aria-describedby': 'enc-seed-hint',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const drawBtn = el('button', { class: 'btn', type: 'button', id: 'enc-draw' }, [
    'Draw a seed for this account',
  ]);
  const randomBtn = el('button', { class: 'btn btn-secondary', type: 'button', id: 'enc-random' }, [
    'Random seed from the whole space',
  ]);
  const intervalOut = el('div', { id: 'enc-interval' });
  const decodeOut = el('div', { id: 'enc-decode' });

  function renderInterval(): void {
    const parsed = parseAccount(accountInput.value);
    if (!parsed.ok) {
      fill(intervalOut, [verdict('rejected', 'REFUSED', parsed.reason, 'account-refused')]);
      drawBtn.disabled = true;
      return;
    }
    drawBtn.disabled = false;
    const iv = interval(BigInt(parsed.account), B);
    const exact = SEED_SPACE / B;
    fill(intervalOut, [
      el('div', { class: 'stat-row' }, [
        stat('Card', displayCard(parsed.account)),
        stat('Seeds it owns', commas(iv.size), `of ${commas(SEED_SPACE)}`),
        stat('Share of the space', `1 in ${commas(B)}`, 'uniform by construction'),
      ]),
      tableWrap(
        'The interval this card owns',
        el('table', {}, [
        el('caption', {}, ['The half-open interval this card owns.']),
        el('tbody', {}, [
          el('tr', {}, [
            el('th', { scope: 'row' }, ['lower bound (inclusive)']),
            el('td', { class: 'num' }, [hex64(iv.lo)]),
          ]),
          el('tr', {}, [
            el('th', { scope: 'row' }, ['upper bound (exclusive)']),
            el('td', { class: 'num' }, [hex64Exclusive(iv.hi)]),
          ]),
          el('tr', {}, [
            el('th', { scope: 'row' }, ['width']),
            el('td', { class: 'num' }, [
              `${commas(iv.size)} seeds — the even share would be ${commas(SEED_SPACE)} / ${commas(B)}` +
                ` = ${commas(exact)} and a remainder, so intervals are this wide or one seed wider`,
            ]),
          ]),
        ]),
        ]),
      ),
    ]);
  }

  function renderDecode(): void {
    const raw = seedInput.value.trim();
    let S: bigint;
    try {
      const t = raw.replace(/^0x/i, '').replace(/[\s_]/g, '');
      if (!/^[0-9a-fA-F]{1,16}$/.test(t)) throw new Error('not hex');
      S = BigInt(`0x${t}`);
      if (S < 0n || S >= SEED_SPACE) throw new Error('range');
    } catch {
      fill(decodeOut, [
        verdict(
          'rejected',
          'REFUSED',
          'A seed is up to sixteen hexadecimal digits, i.e. a value in [0, 2^64). Anything else is not a point in the seed space.',
          'seed-refused',
        ),
      ]);
      return;
    }
    const account = Number(decode(S, B));
    const pan = cardFromAccount(account);
    const iv = interval(BigInt(account), B);
    const offset = S - iv.lo;

    // The figure: the seed's own interval and its immediate neighbours, drawn
    // to scale against each other. A whole-space view cannot work — one card
    // owns 1.8e10 of 1.8e19 seeds, far under a pixel — and drawing one anyway
    // would be a picture that contradicts the arithmetic beside it. Neighbouring
    // intervals, by contrast, really are equal to within a single seed in
    // eighteen billion, so equal blocks are an honest rendering of them.
    const first = Math.max(0, Math.min(account - 2, ACCOUNT_SPACE - 5));
    const blocks = [0, 1, 2, 3, 4].map((k) => first + k);
    const own = interval(BigInt(account), B);
    const withinPct = Number(((S - own.lo) * 10000n) / own.size) / 100;
    const blockIndex = blocks.indexOf(account);
    const markerPct = ((blockIndex + withinPct / 100) / blocks.length) * 100;

    fill(decodeOut, [
      el(
        'div',
        { class: 'spacebar' },
        [
          ...blocks.map((a, k) =>
            el(
              'div',
              {
                class: a === account ? 'spacebar-cell is-own' : 'spacebar-cell',
                style: `left:${(k / blocks.length) * 100}%;width:${100 / blocks.length}%`,
              },
              [formatAccount(a)],
            ),
          ),
          el('div', { class: 'spacebar-marker', style: `left:${markerPct}%` }),
        ],
      ),
      el('p', { class: 'field-hint' }, [
        'Five neighbouring intervals, drawn to scale against each other, with this seed marked ',
        'inside the one that owns it. They tile: each begins exactly where the last ends, so ',
        'there is no seed between them and none outside them. The whole space is not drawn, ',
        'because one card owns about 1.8 x 10^10 of 1.8 x 10^19 seeds and a true-to-scale slice ',
        'would be far thinner than a pixel.',
      ]),
      verdict(
        'held',
        `DECODES TO ${pan}`,
        `Seed ${hex64(S)} is offset ${commas(offset)} into the interval owned by account ${formatAccount(account)}. Luhn check: ${luhnValid(pan) ? 'passes' : 'FAILS'}.`,
        'decoded',
      ),
      el('div', { class: 'stat-row' }, [
        stat('Card', displayCard(account)),
        stat('Interval', `${hex64(iv.lo)} to ${hex64Exclusive(iv.hi)}`),
        stat('Offset into it', commas(offset), `of ${commas(iv.size)}`),
      ]),
    ]);
  }

  accountInput.addEventListener('input', renderInterval);
  seedInput.addEventListener('input', renderDecode);
  drawBtn.addEventListener('click', () => {
    const parsed = parseAccount(accountInput.value);
    if (!parsed.ok) return;
    seedInput.value = hex64(encode(BigInt(parsed.account), B));
    renderDecode();
  });
  randomBtn.addEventListener('click', () => {
    seedInput.value = hex64(randomBelow(SEED_SPACE));
    renderDecode();
  });

  root.append(
    card([
      el('h2', {}, ['Every seed is some valid card']),
      el('p', { class: 'lede' }, [
        'The encoder divides the 2^64 seeds into one interval per card number and gives each card ',
        'its own slice. Encoding picks a seed uniformly from the card’s slice; decoding asks ',
        'which slice a seed fell in. The slices leave no gaps, so there is no such thing as an ',
        'invalid seed — and that is the property the whole scheme is built on. Try it: type any ',
        'sixteen hexadecimal digits you like, or press the random button, and you will get a card ',
        'that passes its own check digit every single time.',
      ]),
      el('div', { class: 'controls' }, [
        field('enc-account', 'Account digits (9)', accountInput, 'Not a real card number.'),
        drawBtn,
      ]),
      intervalOut,
      el('h3', {}, ['Decode an arbitrary seed']),
      el('div', { class: 'controls' }, [
        field('enc-seed', 'Seed (hex, up to 16 digits)', seedInput, 'Any value in [0, 2^64).'),
        randomBtn,
      ]),
      decodeOut,
      note([
        'Message ',
        el('code', {}, ['i']),
        ' owns the seeds from ',
        el('code', {}, ['ceil(i x 2^64 / b)']),
        ' up to ',
        el('code', {}, ['ceil((i+1) x 2^64 / b)']),
        ', and ',
        el('code', {}, ['decode(S) = floor(S x b / 2^64)']),
        ' with ',
        el('code', {}, ['b = 10^9']),
        '. All of it is BigInt arithmetic: a 64-bit seed exceeds what a double can hold exactly, ',
        'so a single float would round a seed onto its neighbour and, at an interval edge, onto ',
        'the neighbouring card.',
      ]),
      disclosure('How close to uniform is this, exactly?', [
        el('p', {}, [
          'Not every interval can be the same width, because 2^64 is not divisible by 10^9. The ',
          'widths here differ by at most ',
          el('code', {}, [commas(maxIntervalDeviation(B))]),
          ' seed, so the probability the encoder gives any one card differs from a true ',
          el('code', {}, ['1/b']),
          ' by less than ',
          el('code', {}, ['2^-64']),
          '. That is the same bound the paper’s Theorem 8 gives its own fixed-point encoder, ',
          'and it is why the ceiling matters: with a floor, a card’s first seed would fall in ',
          'the previous card’s bucket and decoding would stop inverting encoding.',
        ]),
      ]),
      scopeNote([
        'What this is not: an encoder for a non-uniform message distribution. The paper also builds ',
        'one for user-selected PINs, which needs a real PIN-frequency corpus, and one for RSA ',
        'private keys. Neither is built here — there is a ',
        el('code', {}, ['Distribution']),
        ' interface in ',
        el('code', {}, ['src/he/dte.ts']),
        ' shaped for the first, and it is deliberately unimplemented, because inventing the ',
        'frequencies would teach something false.',
      ]),
    ]),
  );

  renderInterval();
  renderDecode();
}
