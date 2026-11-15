/**
 * Exhibit 1 — ordinary password-based encryption.
 *
 * The card is stored as sixteen ASCII digits under AES-CTR and under AES-GCM.
 * The learner drives a dictionary attack and watches HOW it knows it has won.
 * Everything on screen is produced by running the real schemes; there is no
 * canned "garbage" string anywhere in this file.
 */

import { cardFromAccount, groupCard } from '../he/luhn';
import { allDigitsLog2, allDigitsProbability, describeBytes, pbeEncrypt, type PbeCiphertext, type PbeMode } from '../he/pbe';
import { attackPbe, scoreAttack } from '../he/attacks';
import { PBKDF2_ITERATIONS } from '../he/he';
import { card, disclosure, el, field, fill, note, scopeNote, stat, tableWrap, verdict } from './dom';
import { VECTOR_ACCOUNT, commas, dictionaryOf, displayCard, formatAccount, parseAccount } from './shared';

interface State {
  account: number;
  password: string;
  mode: PbeMode;
  ct: PbeCiphertext | null;
  /** The inputs the ciphertext was made from, so a change can retire it. */
  madeFrom: string;
}

const DICT_SIZE = 40;

export function mountOrdinary(root: HTMLElement): void {
  const state: State = {
    account: VECTOR_ACCOUNT,
    password: 'qwerty',
    mode: 'aes-ctr',
    ct: null,
    madeFrom: '',
  };

  const accountInput = el('input', {
    type: 'text',
    id: 'ord-account',
    value: formatAccount(state.account),
    inputmode: 'numeric',
    maxlength: '19',
    'aria-describedby': 'ord-account-hint',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const passwordInput = el('input', {
    type: 'text',
    id: 'ord-password',
    value: state.password,
    'aria-describedby': 'ord-password-hint',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const modeSelect = el('select', { id: 'ord-mode' }, [
    el('option', { value: 'aes-ctr', selected: true }, ['AES-CTR (no tag)']),
    el('option', { value: 'aes-gcm' }, ['AES-GCM (authenticated)']),
  ]);
  const encryptBtn = el('button', { class: 'btn', type: 'button', id: 'ord-encrypt' }, ['Encrypt']);
  const attackBtn = el('button', { class: 'btn btn-secondary', type: 'button', id: 'ord-attack' }, [
    `Run the dictionary attack (${DICT_SIZE} candidates)`,
  ]);
  const out = el('div', { id: 'ord-out' });

  /** Any input change retires a stale ciphertext and its verdict. */
  function currentInputs(): string {
    return `${accountInput.value}|${passwordInput.value}|${modeSelect.value}`;
  }

  function retireIfChanged(): void {
    if (state.ct && state.madeFrom !== currentInputs()) {
      state.ct = null;
      attackBtn.disabled = true;
      fill(out, [
        verdict(
          'stale',
          'RETIRED',
          'The account, password or mode changed, so the ciphertext and any attack result no longer describe what is on screen. Encrypt again.',
          'retired',
        ),
      ]);
    }
  }

  for (const input of [accountInput, passwordInput]) {
    input.addEventListener('input', retireIfChanged);
  }
  modeSelect.addEventListener('change', retireIfChanged);

  encryptBtn.addEventListener('click', async () => {
    const parsed = parseAccount(accountInput.value);
    if (!parsed.ok) {
      state.ct = null;
      attackBtn.disabled = true;
      fill(out, [verdict('rejected', 'REFUSED', parsed.reason, 'account-refused')]);
      return;
    }
    state.account = parsed.account;
    state.password = passwordInput.value;
    state.mode = modeSelect.value as PbeMode;
    const pan = cardFromAccount(state.account);
    state.ct = await pbeEncrypt(state.password, pan, state.mode);
    state.madeFrom = currentInputs();
    attackBtn.disabled = false;
    renderCiphertext(out, state, pan);
  });

  attackBtn.addEventListener('click', async () => {
    if (!state.ct) return;
    const dictionary = dictionaryOf(DICT_SIZE);
    // The attacker receives the ciphertext and the candidate list. Nothing else.
    const result = await attackPbe(state.ct, dictionary);
    // Scored afterwards, against the password this frame kept back.
    const score = scoreAttack(result.guess, state.password);
    renderAttack(out, state, result, score, dictionary.length);
  });

  attackBtn.disabled = true;

  root.append(
    card([
      el('h2', {}, ['Ordinary encryption tells the attacker when it has won']),
      el('p', { class: 'lede' }, [
        'Store a card the obvious way — sixteen ASCII digits — and encrypt it under a password. ',
        'Now try the wrong password. With AES-CTR you get sixteen arbitrary bytes, which are almost ',
        'never all digits. With AES-GCM you do not even get that: the tag fails and the mode ',
        'refuses. Either way an attacker working through a list of likely passwords can recognise ',
        'the moment it succeeds, and that recognition is the whole attack.',
      ]),
      el('div', { class: 'controls' }, [
        field('ord-account', 'Account digits (9)', accountInput, 'Not a real card number.'),
        field('ord-password', 'Password', passwordInput, 'Weak on purpose.'),
        field('ord-mode', 'Mode', modeSelect),
        encryptBtn,
        attackBtn,
      ]),
      out,
      note([
        'The key comes from PBKDF2-HMAC-SHA-256 at ',
        el('strong', {}, [String(PBKDF2_ITERATIONS)]),
        ' iterations — the same derivation honey encryption uses on the next tabs, so the ',
        'comparison isolates the one thing that differs: whether a wrong key produces something ',
        'that could be a card.',
      ]),
      disclosure('Why sixteen wrong bytes are almost never sixteen digits', [
        el('p', {}, [
          'An ASCII digit is one of ten byte values out of 256. A wrong AES-CTR decryption is ',
          'effectively uniform bytes, so all sixteen land on digits with probability ',
          el('code', {}, ['(10/256)^16']),
          ' = ',
          el('code', {}, [allDigitsProbability().toExponential(2)]),
          ', which is below ',
          el('code', {}, [`2^${allDigitsLog2().toFixed(1)}`]),
          '. Over the forty candidates above, the expected number of false positives is ',
          el('code', {}, [(40 * allDigitsProbability()).toExponential(2)]),
          '. So the first all-digit result is the plaintext, and the search stops.',
        ]),
      ]),
      scopeNote([
        'What this is not: a demonstration that AES-CTR or AES-GCM is weak. Both are doing exactly ',
        'what they promise. The weakness being shown is the PASSWORD, and the fact that an ordinary ',
        'scheme lets an attacker test one.',
      ]),
    ]),
  );
}

function renderCiphertext(out: HTMLElement, state: State, pan: string): void {
  fill(out, [
    el('div', { class: 'stat-row' }, [
      stat('Card encrypted', groupCard(pan), 'sixteen ASCII digits'),
      stat('Mode', state.mode === 'aes-ctr' ? 'AES-CTR' : 'AES-GCM'),
      stat('Ciphertext', `${state.ct!.ct.length} bytes`, state.mode === 'aes-gcm' ? 'includes a 16-byte tag' : 'no tag'),
    ]),
    verdict(
      'held',
      'ENCRYPTED',
      'Now run the dictionary attack and watch the column that gives the password away.',
      'encrypted',
    ),
  ]);
}

function renderAttack(
  out: HTMLElement,
  state: State,
  result: Awaited<ReturnType<typeof attackPbe>>,
  score: { succeeded: boolean },
  dictSize: number,
): void {
  const rows = result.rows.map((row) => {
    const a = row.attempt;
    const recognised = a.kind === 'plaintext' && a.allDigits;
    return el('tr', {}, [
      el('td', {}, [row.password]),
      el(
        'td',
        { class: 'num' },
        [
          a.kind === 'rejected'
            ? 'rejected by the tag'
            : describeBytes(a.bytes),
        ],
      ),
      el('td', {}, [
        a.kind === 'rejected' ? 'x  no' : recognised ? '=  YES' : 'x  no',
      ]),
    ]);
  });

  const table = el('table', {}, [
    el('caption', {}, [
      `Every candidate tried, in order. The attacker stopped after ${result.tried} of ${dictSize}.`,
    ]),
    el('thead', {}, [
      el('tr', {}, [
        el('th', { scope: 'col' }, ['Candidate password']),
        el('th', { scope: 'col' }, ['What the mode returned']),
        el('th', { scope: 'col' }, ['Sixteen digits?']),
      ]),
    ]),
    el('tbody', {}, rows),
  ]);

  const headline =
    result.guess === null
      ? 'NOT FOUND'
      : state.mode === 'aes-gcm'
        ? 'PASSWORD RECOVERED — THE TAG SAID SO'
        : 'PASSWORD RECOVERED — THE PLAINTEXT SAID SO';

  const detail =
    result.guess === null
      ? `The true password was not among the ${dictSize} candidates, so the search ended with nothing. It would have recognised the password had the list contained it.`
      : `The attacker named "${result.guess}" after ${result.tried} ${result.tried === 1 ? 'try' : 'tries'}, on the basis of a ${result.basis}. Scored against the password this page kept back: ${score.succeeded ? 'correct' : 'wrong'}.`;

  fill(out, [
    el('div', { class: 'stat-row' }, [
      stat('Candidates tried', `${commas(result.tried)} / ${commas(dictSize)}`),
      stat('Recognition test', state.mode === 'aes-gcm' ? 'the GCM tag' : 'all sixteen bytes are digits'),
      stat('Card encrypted', displayCard(state.account)),
    ]),
    verdict(
      result.guess === null ? 'warned' : 'broken',
      headline,
      detail,
      result.guess === null ? 'pbe-not-found' : 'pbe-recovered',
    ),
    tableWrap('Dictionary attack against ordinary encryption', table),
  ]);
}
