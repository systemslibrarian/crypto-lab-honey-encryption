import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG 2.1 A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, with
 * exhibit 1 active and the other five tabpanels hidden; the shared skip link
 * focused; AES-CTR encrypted and then broken by a dictionary attack; the same
 * against AES-GCM, where every wrong candidate is rejected instead; a password
 * outside the dictionary, taking the not-found branch; an account field given
 * a whole card number and given too few digits, both refused; the encoder on
 * the published seed, on a random seed, on seed 0, on seed 2^64-1 and on
 * nonsense; honey encryption decrypted under a wrong password and under the
 * empty password; the six-password fixture with its negative claim, a wrong
 * row picked and scored as a failure, and the reveal; a hundred candidates; a
 * measured run from its progress bar to its verdict; the pile-up attack in
 * both the branch where it wins and the branch where it loses; all three
 * limits; every retirement verdict; every disclosure opened through its own
 * summary; three hover states; and three focus rings. Every one of those
 * states is scanned, at desktop and at phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * revealed from script, why the lab's structure is asserted rather than
 * assumed, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
