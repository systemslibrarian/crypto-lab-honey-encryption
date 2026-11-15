/**
 * Exhibit 6 — where it stops.
 *
 * Three panels, each a real failure run against the real code:
 *
 *   mauling            one flipped ciphertext bit moves the recipient's card by
 *                      exactly half the message space, and nothing detects it
 *   one known plaintext  the attacker's recognition test comes back and the
 *                      password falls again
 *   a typo             a mistyped password yields a plausible wrong card with
 *                      no error, by design, and that is the usability cost
 *
 * Each of these verdicts reads as success and failure at once, because that is
 * what they are: the construction did exactly what it promises, and the
 * promise does not cover this.
 */

import { ACCOUNT_SPACE, cardFromAccount, luhnValid } from '../he/luhn';
import { interval } from '../he/dte';
import { hdec, hdecSeed, henc, hencWithSeed, hex64, maulTopBit } from '../he/he';
import { attackKnownPlaintext, scoreAttack, scoreRecovery } from '../he/attacks';
import { card, disclosure, el, field, fill, note, stat, tableWrap, verdict } from './dom';
import {
  VECTOR_ACCOUNT,
  VECTOR_PASSWORD,
  commas,
  dictionaryOf,
  displayCard,
  formatAccount,
  parseAccount,
  randomAccount,
} from './shared';

const B = BigInt(ACCOUNT_SPACE);
const VECTOR_R = new Uint8Array(Array.from({ length: 16 }, (_, i) => i));
const VECTOR_SEED = interval(BigInt(VECTOR_ACCOUNT), B).lo + 0x1234567n;

export function mountLimits(root: HTMLElement): void {
  root.append(
    card([
      el('h2', {}, ['Three places where this stops working']),
      el('p', { class: 'lede' }, [
        'Honey encryption buys one thing: an attacker who tries every likely password cannot tell ',
        'which answer is the message. It does not buy integrity, it does not survive a known ',
        'plaintext, and it cannot tell you that you mistyped. All three are shown below with the ',
        'same code the other tabs use — nothing here is a mock-up of a failure.',
      ]),
    ]),
    maulingPanel(),
    knownPlaintextPanel(),
    typoPanel(),
    card([
      el('h3', {}, ['And one assumption underneath all of it']),
      el('p', {}, [
        'The 2014 paper assumes the key and the message are independent, and that the message ',
        'distribution is KNOWN and correctly modelled. This page models nine account digits as ',
        'uniform, which the paper says is reasonable for a cardholder account number. If the real ',
        'distribution were different — if issuers allocated account numbers in blocks, say — ',
        'then the decoy cards would be drawn from the wrong distribution, and an attacker who knew ',
        'the right one could tell the real card from the decoys without ever touching the ',
        'cryptography. A DTE is only as good as the distribution it encodes.',
      ]),
      el('p', {}, [
        'Jaeger, Ristenpart and Tang (ePrint 2016/174) make the first two limits general rather ',
        'than incidental: message recovery is a comparatively weak goal that permits partial ',
        'leakage and useful mauling of ciphertexts; they define stronger notions ',
        '(target-distribution semantic security and target-distribution non-malleability) that a ',
        'slight variant of this construction meets; and their section 4 proves the folklore result ',
        'that an unbounded attacker holding a limited number of encryptions of known plaintexts ',
        'can always recover messages. ',
        el('strong', {}, ['The variant and the stronger notions are not built here.']),
        ' There is a seam for a different cipher in ',
        el('code', {}, ['src/he/he.ts']),
        ', and it is deliberately unimplemented.',
      ]),
    ]),
  );
}

/* ---------- mauling ---------- */

function maulingPanel(): HTMLElement {
  const out = el('div', { id: 'maul-out' });
  const btn = el('button', { class: 'btn', type: 'button', id: 'maul-run' }, [
    'Flip the top bit of C2',
  ]);
  const randomBtn = el('button', { class: 'btn btn-secondary', type: 'button', id: 'maul-random' }, [
    'Try a random card instead',
  ]);

  function run(useVector: boolean): void {
    const account = useVector ? VECTOR_ACCOUNT : randomAccount();
    const ct = useVector
      ? hencWithSeed(VECTOR_PASSWORD, VECTOR_SEED, VECTOR_R)
      : henc(VECTOR_PASSWORD, BigInt(account), B);
    const seed = hdecSeed(VECTOR_PASSWORD, ct);
    const mauled = maulTopBit(ct);
    const moved = Number(hdec(VECTOR_PASSWORD, mauled, B));
    const delta = moved - account;

    fill(out, [
      el('div', { class: 'stat-row' }, [
        stat('The card the owner stored', displayCard(account)),
        stat('What the owner now decrypts', displayCard(moved)),
        stat('Moved by', `${delta > 0 ? '+' : ''}${commas(delta)}`, `top bit of the seed was ${seed >> 63n}`),
      ]),
      verdict(
        'broken',
        `DECRYPTED — AND MOVED BY EXACTLY ${delta > 0 ? '+' : ''}${commas(delta)}`,
        `C2 is a one-time pad, so a flipped ciphertext bit is a flipped SEED bit. The top bit moves the seed by 2^63, which is half the seed space, which is exactly half the message space: ${commas(ACCOUNT_SPACE / 2)}. The new card passes its check digit (${luhnValid(cardFromAccount(moved)) ? 'it does' : 'it does NOT'}), there is no tag to notice, and the attacker chose the amount without ever learning the card.`,
        'mauled',
      ),
      tableWrap(
        'Before and after the flipped bit',
        el('table', {}, [
          el('caption', {}, ['One bit of C2, and what it does to the seed and the card.']),
          el('thead', {}, [
            el('tr', {}, [
              el('th', { scope: 'col' }, ['']),
              el('th', { scope: 'col' }, ['C2']),
              el('th', { scope: 'col' }, ['Seed the owner recovers']),
              el('th', { scope: 'col' }, ['Card']),
            ]),
          ]),
          el('tbody', {}, [
            el('tr', {}, [
              el('th', { scope: 'row' }, ['as sent']),
              el('td', { class: 'num' }, [hex64(ct.C2)]),
              el('td', { class: 'num' }, [hex64(seed)]),
              el('td', { class: 'num' }, [cardFromAccount(account)]),
            ]),
            el('tr', {}, [
              el('th', { scope: 'row' }, ['top bit flipped']),
              el('td', { class: 'num' }, [hex64(mauled.C2)]),
              el('td', { class: 'num' }, [hex64(hdecSeed(VECTOR_PASSWORD, mauled))]),
              el('td', { class: 'num' }, [cardFromAccount(moved)]),
            ]),
          ]),
        ]),
      ),
    ]);
  }

  btn.addEventListener('click', () => run(true));
  randomBtn.addEventListener('click', () => run(false));

  const panel = card([
    el('h3', {}, ['1 · Mauling: the attacker can move your plaintext']),
    el('p', {}, [
      'Honey encryption as built here provides no integrity whatsoever. There is no tag, and the ',
      'cipher is a pad, so an attacker who can modify the stored ciphertext controls the ',
      'difference between what you stored and what you get back — without knowing either.',
    ]),
    el('div', { class: 'controls' }, [btn, randomBtn]),
    out,
  ]);
  run(true);
  return panel;
}

/* ---------- one known plaintext ---------- */

function knownPlaintextPanel(): HTMLElement {
  const out = el('div', { id: 'kpa-out' });
  const btn = el('button', { class: 'btn', type: 'button', id: 'kpa-run' }, [
    'Run the search with one known pair',
  ]);

  function run(): void {
    const dictionary = dictionaryOf(100);
    const trueIndex = Math.floor(Math.random() * dictionary.length);
    const truePassword = dictionary[trueIndex]!;
    const knownAccount = randomAccount();
    const targetAccount = randomAccount();
    const known = henc(truePassword, BigInt(knownAccount), B);
    const target = henc(truePassword, BigInt(targetAccount), B);

    const result = attackKnownPlaintext(
      { c: known, account: knownAccount },
      target,
      dictionary,
      B,
    );
    const pwScore = scoreAttack(result.guess, truePassword);
    const msgScore = scoreRecovery(result.recovered, targetAccount);

    fill(out, [
      el('div', { class: 'stat-row' }, [
        stat('Card the attacker already knows', displayCard(knownAccount)),
        stat('Card it is after', displayCard(targetAccount)),
        stat('Candidates tried', `${commas(result.tried)} / ${commas(dictionary.length)}`),
        stat('False positives expected', (1 / ACCOUNT_SPACE).toExponential(1), 'per wrong candidate'),
      ]),
      verdict(
        'broken',
        pwScore.succeeded && msgScore.succeeded
          ? 'PASSWORD RECOVERED — AND SO IS THE OTHER CARD'
          : 'SEARCH DID NOT FIND IT',
        pwScore.succeeded
          ? `The attacker decrypted the KNOWN ciphertext under each candidate and stopped when the known card came back. A wrong password passes that test with probability 1 in ${commas(ACCOUNT_SPACE)}, so the first candidate that passes is the password — and it then decrypts the target to ${displayCard(result.recovered!)}, which is the card. The recognition test is back, and honey encryption gives nothing against it.`
          : 'The true password was outside the candidate list, so the search ended empty — as it would against ordinary encryption too.',
        'known-plaintext',
      ),
      note([
        'This is not a flaw in the implementation. Jaeger, Ristenpart and Tang prove it is ',
        'unavoidable for any scheme of this kind: their section 4 shows an unbounded attacker ',
        'holding a limited number of encryptions of known plaintexts can always recover messages. ',
        'If you encrypt a vault of cards under one password and the attacker learns a single one ',
        'of them by other means, the rest go with it.',
      ]),
    ]);
  }

  btn.addEventListener('click', run);
  const panel = card([
    el('h3', {}, ['2 · One known plaintext, and the search works again']),
    el('p', {}, [
      'Suppose the attacker already knows one card you encrypted under this password — from a ',
      'receipt, a breach elsewhere, or a transaction it made itself — along with that ',
      'ciphertext. It now has a test it can apply to any candidate password, and the protection ',
      'is gone.',
    ]),
    el('div', { class: 'controls' }, [btn]),
    out,
  ]);
  run();
  return panel;
}

/* ---------- the typo ---------- */

function typoPanel(): HTMLElement {
  const out = el('div', { id: 'typo-out' });
  const accountInput = el('input', {
    type: 'text',
    id: 'typo-account',
    value: formatAccount(VECTOR_ACCOUNT),
    inputmode: 'numeric',
    maxlength: '19',
    'aria-describedby': 'typo-account-hint',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const rightInput = el('input', {
    type: 'text',
    id: 'typo-right',
    value: VECTOR_PASSWORD,
    'aria-describedby': 'typo-right-hint',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const typoInput = el('input', {
    type: 'text',
    id: 'typo-typed',
    value: 'correct horsf',
    'aria-describedby': 'typo-typed-hint',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const btn = el('button', { class: 'btn', type: 'button', id: 'typo-run' }, ['Decrypt with the typo']);

  function run(): void {
    const parsed = parseAccount(accountInput.value);
    if (!parsed.ok) {
      fill(out, [verdict('rejected', 'REFUSED', parsed.reason, 'account-refused')]);
      return;
    }
    const right = rightInput.value;
    const typed = typoInput.value;
    const isVector =
      parsed.account === VECTOR_ACCOUNT && right === VECTOR_PASSWORD;
    const ct = isVector
      ? hencWithSeed(right, VECTOR_SEED, VECTOR_R)
      : henc(right, BigInt(parsed.account), B);
    const got = Number(hdec(typed, ct, B));
    const real = Number(hdec(right, ct, B));
    const same = typed === right;

    fill(out, [
      el('div', { class: 'stat-row' }, [
        stat('Card you stored', displayCard(real)),
        stat('Card the typo gives you', displayCard(got)),
        stat('Error raised', 'none', 'none is possible'),
      ]),
      verdict(
        same ? 'held' : 'warned',
        same
          ? 'THAT IS THE RIGHT PASSWORD — THIS IS YOUR CARD'
          : `VALID CARD — AND THE WRONG ONE, WITH NO WARNING`,
        same
          ? 'Change one character of it to see the cost.'
          : `"${typed}" differs from "${right}", and the page cannot tell you so: there is no tag, no padding and no check that a wrong password could fail. You get ${cardFromAccount(got)}, it passes the Luhn check, and it is not your card. This is the usability price the paper names, and it is the same property that defeats the attacker in exhibit 4 — you cannot have one without the other.`,
        'typo',
      ),
    ]);
  }

  for (const i of [accountInput, rightInput, typoInput]) i.addEventListener('input', () => fill(out, [
    verdict('stale', 'RETIRED', 'An input changed. Decrypt again.', 'retired'),
  ]));
  btn.addEventListener('click', run);

  const panel = card([
    el('h3', {}, ['3 · A typo cannot be detected, by design']),
    el('p', {}, [
      'Ordinary authenticated encryption tells you when you mistyped your password. This cannot, ',
      'and the reason it cannot is the reason it works: a scheme that could reject a wrong ',
      'password would hand that same test to the attacker.',
    ]),
    el('div', { class: 'controls' }, [
      field('typo-account', 'Account digits (9)', accountInput, 'Not a real card number.'),
      field('typo-right', 'The real password', rightInput, 'The one the card was encrypted under.'),
      field('typo-typed', 'What you typed', typoInput, 'One character off, by default.'),
      btn,
    ]),
    out,
    disclosure('Could a honey scheme warn you anyway?', [
      el('p', {}, [
        'Only by giving up something. You could store a separate authenticator under a second ',
        'secret the attacker does not have, or accept a short list of typo-equivalent passwords, ',
        'or warn on a Levenshtein-close password at the cost of leaking that the stored password ',
        'is close to the one typed. The 2014 paper discusses typo-safety in its section 7; this ',
        'page does not implement any of those, and does not claim to have solved it.',
      ]),
    ]),
  ]);
  run();
  return panel;
}
