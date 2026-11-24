/**
 * Exhibit 3 — honey encryption.
 *
 * Encrypt, decrypt with the right password, then decrypt with any other
 * password the learner types and get a valid Luhn-checked card every time.
 * Each row is produced by running HDec; no list of plausible-looking cards
 * exists anywhere in this code.
 */
import { ACCOUNT_SPACE, cardFromAccount, luhnValid } from '../he/luhn';
import { interval } from '../he/dte';
import {
  PBKDF2_ITERATIONS,
  hdec,
  hdecSeed,
  henc,
  hencWithSeed,
  hex64,
  hexBytes,
  type HeCiphertext,
} from '../he/he';
import { card, disclosure, el, field, fill, note, stat, tableWrap, verdict } from './dom';
import {
  VECTOR_ACCOUNT,
  VECTOR_PASSWORD,
  displayCard,
  formatAccount,
  parseAccount,
  randomAccount,
} from './shared';
const B = BigInt(ACCOUNT_SPACE);
const VECTOR_R = new Uint8Array(Array.from({ length: 16 }, (_, i) => i));
const VECTOR_SEED = interval(BigInt(VECTOR_ACCOUNT), B).lo + 0x1234567n;
export function mountHoney(root: HTMLElement): void {
  let ct: HeCiphertext | null = null;
  let trueAccount = VECTOR_ACCOUNT;
  let truePassword = VECTOR_PASSWORD;
  let madeFrom = '';
  const attempts: Array<{ password: string; account: number; card: string }> = [];
  const accountInput = el('input', {
    type: 'text',
    id: 'he-account',
    value: formatAccount(VECTOR_ACCOUNT),
    inputmode: 'numeric',
    maxlength: '19',
    'aria-describedby': 'he-account-hint',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const passwordInput = el('input', {
    type: 'text',
    id: 'he-password',
    value: VECTOR_PASSWORD,
    'aria-describedby': 'he-password-hint',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const tryInput = el('input', {
    type: 'text',
    id: 'he-try',
    value: '123456',
    'aria-describedby': 'he-try-hint',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const encryptBtn = el('button', { class: 'btn', type: 'button', id: 'he-encrypt' }, ['Encrypt']);
  const vectorBtn = el('button', { class: 'btn btn-secondary', type: 'button', id: 'he-vector' }, [
    'Load the published vector',
  ]);
  const randomBtn = el('button', { class: 'btn btn-secondary', type: 'button', id: 'he-random' }, [
    'Random card',
  ]);
  const decryptBtn = el('button', { class: 'btn', type: 'button', id: 'he-decrypt' }, [
    'Decrypt with this password',
  ]);
  const ctOut = el('div', { id: 'he-ct' });
  const attemptOut = el('div', { id: 'he-attempts' });
  const inputs = () => `${accountInput.value}|${passwordInput.value}`;
  function retireIfChanged(): void {
    if (ct && madeFrom !== inputs()) {
      ct = null;
      attempts.length = 0;
      decryptBtn.disabled = true;
      fill(attemptOut, []);
      fill(ctOut, [
        verdict(
          'stale',
          'RETIRED',
          'The account or password changed, so the ciphertext and every decryption below it no longer describe what is on screen. Encrypt again.',
          'retired',
        ),
      ]);
    }
  }
  accountInput.addEventListener('input', retireIfChanged);
  passwordInput.addEventListener('input', retireIfChanged);
  function encrypt(withVector: boolean): void {
    const parsed = parseAccount(accountInput.value);
    if (!parsed.ok) {
      ct = null;
      decryptBtn.disabled = true;
      fill(ctOut, [verdict('rejected', 'REFUSED', parsed.reason, 'account-refused')]);
      return;
    }
    trueAccount = parsed.account;
    truePassword = passwordInput.value;
    ct = withVector
      ? hencWithSeed(truePassword, VECTOR_SEED, VECTOR_R)
      : henc(truePassword, BigInt(trueAccount), B);
    madeFrom = inputs();
    attempts.length = 0;
    decryptBtn.disabled = false;
    fill(attemptOut, []);
    renderCiphertext(withVector);
  }
  function renderCiphertext(isVector: boolean): void {
    if (!ct) return;
    const seed = hdecSeed(truePassword, ct);
    const recovered = Number(hdec(truePassword, ct, B));
    fill(ctOut, [
      el('div', { class: 'stat-row' }, [
        stat('Card encrypted', displayCard(trueAccount)),
        stat('R (the nonce and PBKDF2 salt)', hexBytes(ct.R)),
        stat('C2 (the masked seed)', hex64(ct.C2)),
      ]),
      verdict(
        'held',
        `ENCRYPTED — AND THE RIGHT PASSWORD GIVES BACK ${cardFromAccount(recovered)}`,
        `The seed was ${hex64(seed)}, inside the interval owned by account ${formatAccount(recovered)}.${
          isVector ? ' These are the published vector values, so they match README.md exactly.' : ''
        }`,
        'encrypted',
      ),
      note([
        'There is no tag and no padding, so there is nothing for a wrong password to fail. ',
        el('code', {}, ['C2']),
        ' is just the seed XORed with ',
        el('code', {}, ['H(R, K)']),
        ', and any value of ',
        el('code', {}, ['K']),
        ' un-masks it to SOME seed, which decodes to SOME card.',
      ]),
    ]);
  }
  encryptBtn.addEventListener('click', () => encrypt(false));
  vectorBtn.addEventListener('click', () => {
    accountInput.value = formatAccount(VECTOR_ACCOUNT);
    passwordInput.value = VECTOR_PASSWORD;
    encrypt(true);
  });
  randomBtn.addEventListener('click', () => {
    accountInput.value = formatAccount(randomAccount());
    encrypt(false);
  });
  decryptBtn.addEventListener('click', () => {
    if (!ct) return;
    const password = tryInput.value;
    const account = Number(hdec(password, ct, B));
    const pan = cardFromAccount(account);
    attempts.unshift({ password, account, card: pan });
    renderAttempts();
  });
  function renderAttempts(): void {
    if (attempts.length === 0) {
      fill(attemptOut, []);
      return;
    }
    const allValid = attempts.every((a) => luhnValid(a.card));
    const wrongOnes = attempts.filter((a) => a.password !== truePassword);
    const table = el('table', {}, [
      el('caption', {}, [
        'Every password you have tried on this ciphertext, newest first. Each row is the output of ' +
          'HDec, not a sample from a list.',
      ]),
      el('thead', {}, [
        el('tr', {}, [
          el('th', { scope: 'col' }, ['Password']),
          el('th', { scope: 'col' }, ['Card it decrypts to']),
          el('th', { scope: 'col' }, ['Luhn']),
          el('th', { scope: 'col' }, ['Was it the real password?']),
        ]),
      ]),
      el(
        'tbody',
        {},
        attempts.map((a) =>
          el('tr', {}, [
            el('td', {}, [a.password === '' ? '(empty)' : a.password]),
            el('td', { class: 'num' }, [a.card.replace(/(.{4})(?=.)/g, '$1 ')]),
            el('td', {}, [luhnValid(a.card) ? '=  passes' : 'x  FAILS']),
            el('td', {}, [a.password === truePassword ? '=  yes' : 'x  no']),
          ]),
        ),
      ),
    ]);
    fill(attemptOut, [
      verdict(
        'held',
        `${attempts.length} ${attempts.length === 1 ? 'PASSWORD' : 'PASSWORDS'} TRIED — ${
          attempts.filter((a) => luhnValid(a.card)).length
        } VALID ${attempts.filter((a) => luhnValid(a.card)).length === 1 ? 'CARD' : 'CARDS'}`,
        allValid
          ? `Every one passed its own check digit, including ${wrongOnes.length} produced by a password that was wrong. Nothing in the output marks which was which.`
          : 'A decryption failed its check digit, which should be impossible for this construction. Report it.',
        'honey-attempts',
      ),
      tableWrap('Decryption attempts', table),
    ]);
  }
  root.append(
    card([
      el('h2', {}, ['Honey encryption: the wrong password gives you a card too']),
      el('p', { class: 'lede' }, [
        'Same card, same weak password, but now the plaintext is encoded into a seed before it is ',
        'masked with a value derived from the password and salt. Decrypt with the ',
        'password you chose and you get your card back. Every other password also gives a card with a valid check digit. Two passwords can decode to the same card.',
      ]),
      el('div', { class: 'controls' }, [
        field('he-account', 'Account digits (9)', accountInput, 'Do not type a real card number.'),
        field('he-password', 'Password', passwordInput, 'An empty password is allowed.'),
        encryptBtn,
        vectorBtn,
        randomBtn,
      ]),
      ctOut,
      el('h3', {}, ['Now try a password']),
      el('div', { class: 'controls' }, [
        field('he-try', 'Any password at all', tryInput, 'Right, wrong, or a typo of the right one.'),
        decryptBtn,
      ]),
      attemptOut,
      disclosure('The construction, exactly as the paper writes it', [
        el('p', {}, [
          el('code', {}, ['HEnc(K, M): S <- encode(M); R <- random n bits; C2 <- H(R, K) XOR S; return (R, C2)']),
        ]),
        el('p', {}, [el('code', {}, ['HDec(K, (R, C2)): S <- C2 XOR H(R, K); return decode(S)'])]),
        el('p', {}, [
          'Figure 4 of Juels and Ristenpart, ePrint 2014/155, section 5. Here ',
          el('code', {}, ['H(R, K)']),
          ' is the first eight bytes of PBKDF2-HMAC-SHA-256 over the password with ',
          el('code', {}, ['R']),
          ' as salt, at ',
          el('strong', {}, [String(PBKDF2_ITERATIONS)]),
          ' iterations. The paper notes that a password-based key-derivation function should be ',
          'applied to the key and omits it for simplicity; this page does apply one, but at a ',
          'deliberately tiny iteration count so the brute-force exhibits finish in a browser. ',
          'Honey encryption is about what happens when the key-derivation cost is NOT enough.',
        ]),
      ]),
      note([
        'Nothing you type is sent anywhere. There is no backend, and the page holds no state ',
        'between reloads beyond the pinned theme.',
      ]),
    ]),
  );
  encrypt(true);
}
