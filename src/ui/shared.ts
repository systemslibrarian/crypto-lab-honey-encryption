/**
 * State shared across the exhibits, and the input rules every exhibit obeys.
 */

import { ACCOUNT_DIGITS, ACCOUNT_SPACE, cardFromAccount, groupCard } from '../he/luhn';
import { randomBelow } from '../he/dte';

/** The dictionary of the published fixed vector — exhibit 4's evidence fixture. */
export const VECTOR_DICTIONARY = [
  'correct horse',
  '123456',
  'password',
  'letmein',
  'qwerty',
  'correct horsf',
] as const;

/** The true password of the published vector. */
export const VECTOR_PASSWORD = 'correct horse';

/** The account of the published vector. */
export const VECTOR_ACCOUNT = 123456789;

/**
 * A larger candidate list, for the hundred-candidate runs.
 *
 * The first entry is the one the attacker names when it has no distinguisher,
 * so it is the one whose being right or wrong decides a trial.
 */
export function dictionaryOf(n: number): string[] {
  const common = [
    'correct horse',
    '123456',
    'password',
    '123456789',
    'qwerty',
    'abc123',
    'letmein',
    'monkey',
    'dragon',
    'iloveyou',
    'trustno1',
    'sunshine',
    'princess',
    'football',
    'welcome',
    'shadow',
    'master',
    'baseball',
    'superman',
    'batman',
  ];
  const out = common.slice(0, Math.min(n, common.length));
  for (let i = out.length; i < n; i++) out.push(`candidate-${String(i).padStart(3, '0')}`);
  return out;
}

/** The result of validating the account input. */
export type AccountParse =
  | { ok: true; account: number }
  | { ok: false; reason: string };

/**
 * Parse the account field.
 *
 * INVARIANT 7. The field takes the NINE account digits and nothing else. A
 * sixteen-digit paste is refused by name, because a visitor who pastes
 * sixteen digits is pasting a card number, and this page must not accept one
 * even to throw it away.
 */
export function parseAccount(raw: string): AccountParse {
  const s = raw.trim().replace(/[\s-]/g, '');
  if (s.length === 0) return { ok: false, reason: 'Enter the nine account digits.' };
  if (!/^[0-9]+$/.test(s)) {
    return { ok: false, reason: 'Account digits only — no letters, spaces or punctuation.' };
  }
  if (s.length === 16) {
    return {
      ok: false,
      reason:
        'That is sixteen digits, which is a whole card number. This field takes the nine ' +
        'account digits only, and you should not type a real card number anywhere on this page.',
    };
  }
  if (s.length !== ACCOUNT_DIGITS) {
    return {
      ok: false,
      reason: `Exactly ${ACCOUNT_DIGITS} digits, not ${s.length}.`,
    };
  }
  const account = Number(s);
  if (!Number.isInteger(account) || account < 0 || account >= ACCOUNT_SPACE) {
    return { ok: false, reason: `Outside the message space 0 to ${ACCOUNT_SPACE - 1}.` };
  }
  return { ok: true, account };
}

/** A uniformly random account, drawn the way the encoder draws. */
export function randomAccount(): number {
  return Number(randomBelow(BigInt(ACCOUNT_SPACE)));
}

export function formatAccount(account: number): string {
  return String(account).padStart(ACCOUNT_DIGITS, '0');
}

/** The grouped card for an account, as every exhibit displays it. */
export function displayCard(account: number): string {
  return groupCard(cardFromAccount(account));
}

/** A number with thousands separators, for counts on screen. */
export function commas(n: number | bigint): string {
  return n.toLocaleString('en-US');
}

/** A percentage with two decimals, for rates on screen. */
export function pct(x: number): string {
  return `${x.toFixed(2)}%`;
}
