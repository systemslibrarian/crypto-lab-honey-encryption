/**
 * The Luhn (mod 10) checksum, ISO/IEC 7812-1.
 *
 * A Primary Account Number carries one check digit so that a single mistyped
 * digit is caught before the number reaches a payment network. It is a
 * TYPO check, not a security check: anyone can compute it, which is exactly
 * why it cannot tell a honey-encryption decryption apart from the real card.
 * That is the point this lab exists to make, so the digit is computed here
 * rather than hidden in a library.
 */

/**
 * Doubling runs right-to-left from the check digit: the digit immediately left
 * of the rightmost one is doubled, then every second digit leftward.
 *
 * Expressed over a left-to-right index, a digit at index `i` of a string of
 * length `n` is doubled when `i % 2 === n % 2`. Both the validator and the
 * check-digit generator below derive their parity from that one expression, so
 * they cannot disagree about which positions get doubled.
 */
function doubledAtIndex(i: number, length: number): boolean {
  return i % 2 === length % 2;
}

function digitsOf(s: string): number[] {
  if (!/^[0-9]+$/.test(s)) throw new Error(`luhn: not a digit string: ${JSON.stringify(s)}`);
  return Array.from(s, (c) => c.charCodeAt(0) - 48);
}

/** The Luhn sum of a digit string, taking its last character as a check digit. */
function luhnSum(s: string): number {
  const d = digitsOf(s);
  let total = 0;
  for (let i = 0; i < d.length; i++) {
    let v = d[i]!;
    if (doubledAtIndex(i, d.length)) {
      v *= 2;
      if (v > 9) v -= 9;
    }
    total += v;
  }
  return total;
}

/** True when `s` is a digit string whose final digit is a correct Luhn check digit. */
export function luhnValid(s: string): boolean {
  if (!/^[0-9]+$/.test(s)) return false;
  return luhnSum(s) % 10 === 0;
}

/**
 * The check digit that completes `body`.
 *
 * `body` is the number WITHOUT its check digit, so the appended digit sits at
 * index `body.length` in a string of length `body.length + 1`.
 */
export function luhnCheckDigit(body: string): number {
  const d = digitsOf(body);
  const length = d.length + 1;
  let total = 0;
  for (let i = 0; i < d.length; i++) {
    let v = d[i]!;
    if (doubledAtIndex(i, length)) {
      v *= 2;
      if (v > 9) v -= 9;
    }
    total += v;
  }
  return (10 - (total % 10)) % 10;
}

/**
 * The fixed public prefix this lab stamps on every card it builds.
 *
 * `400000` is a reserved TEST value. It is not an assertion about any issuer,
 * and no number this page produces belongs to anybody.
 */
export const CARD_PREFIX = '400000';

/** How many account digits the message space covers. */
export const ACCOUNT_DIGITS = 9;

/** The number of distinct account numbers: b = 10^9. */
export const ACCOUNT_SPACE = 10 ** ACCOUNT_DIGITS;

/**
 * Build the 16-digit card for an account number: prefix, nine account digits,
 * one Luhn check digit.
 */
export function cardFromAccount(account: number): string {
  if (!Number.isInteger(account) || account < 0 || account >= ACCOUNT_SPACE) {
    throw new Error(`cardFromAccount: account out of range: ${account}`);
  }
  const body = CARD_PREFIX + String(account).padStart(ACCOUNT_DIGITS, '0');
  return body + String(luhnCheckDigit(body));
}

/** Group a card number for display: `4000 0012 3456 7899`. */
export function groupCard(card: string): string {
  return card.replace(/(.{4})(?=.)/g, '$1 ');
}
