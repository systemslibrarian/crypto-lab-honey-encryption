import { expect, test, type Page } from '@playwright/test';
import { boot } from './gate';

/**
 * The claims suite: does the page tell the truth?
 *
 * Separate from a11y.spec.ts on purpose. A failure here names COPY or a
 * COMPUTED CLAIM as the subject, where a failure there names accessibility —
 * and a setup helper that asserted product copy would fail every a11y test
 * under the wrong name (see the note at the top of gate.ts).
 *
 * Two rules shape every test below.
 *
 * 1. COMPARE TWO VALUES THE PAGE ITSELF PRINTED, rather than asserting
 *    against a hardcoded string. A test that re-derives the same expression
 *    the source uses will happily agree with a bug.
 *
 * 2. INTERNAL CONSISTENCY IS NOT ENOUGH — a page can be consistently wrong.
 *    So several of these re-derive the claim from the page's raw inputs by a
 *    DIFFERENT ROUTE than the source takes: the Luhn check is recomputed here
 *    by string reversal where the source uses index parity; the decoded
 *    account is recomputed here from the seed on screen by BigInt division
 *    where the source went through its interval arithmetic; the mauling delta
 *    is recomputed from the two cards on screen.
 */

/* ── independent re-derivations, written here rather than imported ───────── */

/**
 * Luhn, by reversing the string.
 *
 * src/he/luhn.ts decides which digits double from an index parity over the
 * forward string. This walks backwards instead, which is how the standard is
 * usually stated. Mutation (4) changes the source's parity; this does not
 * share the expression, so it sees the change.
 */
function luhnByReversal(card: string): boolean {
  if (!/^[0-9]+$/.test(card)) return false;
  const d = Array.from(card).reverse().map(Number);
  let total = 0;
  for (let i = 0; i < d.length; i++) {
    let v = d[i]!;
    if (i % 2 === 1) {
      v *= 2;
      if (v > 9) v -= 9;
    }
    total += v;
  }
  return total % 10 === 0;
}

/** decode(S) = floor(S * b / 2^64), recomputed here from the printed seed. */
function decodeHere(seedHex: string, b: bigint): bigint {
  return (BigInt(seedHex) * b) / (1n << 64n);
}

const B = 1_000_000_000n;

/** Every card-shaped string on screen, normalised (the page groups them). */
async function cardsOnScreen(page: Page, within = '#app'): Promise<string[]> {
  const text = (await page.locator(within).innerText()) ?? '';
  return (text.match(/\b4000 ?00\d{2} ?\d{4} ?\d{4}\b/g) ?? []).map((s) => s.replace(/ /g, ''));
}

async function activeTabPanel(page: Page): Promise<string> {
  return (await page.locator('.tab-btn[aria-selected="true"]').getAttribute('data-panel')) ?? '';
}

test.beforeEach(async ({ page }) => {
  await boot(page, 'dark');
});

/* ── the arrival state ───────────────────────────────────────────────────── */

test('arrives on exhibit 1 with the honest framing in place', async ({ page }) => {
  expect(await activeTabPanel(page)).toBe('ordinary');
  // The page says what it is not. Each non-goal carries its own note.
  await expect(page.locator('.scope-note').first()).toContainText('What this is not');
  await expect(page.locator('#app')).toContainText('not a real card number', { ignoreCase: true });
});

test('the hero names the construction and the paper', async ({ page }) => {
  await expect(page.locator('h1')).toHaveText('Honey Encryption');
  await expect(page.locator('.cl-hero-sub')).toContainText('DTE-then-encrypt');
  await expect(page.locator('.cl-hero-sub')).toContainText('2014/155');
});

test('the scripture footer is present exactly once, verbatim', async ({ page }) => {
  const f = page.locator('.scripture-footer p').last();
  await expect(f).toHaveText(
    'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
  );
  await expect(page.locator('.scripture-footer')).toHaveCount(1);
});

/* ── every card on screen is really a valid card ─────────────────────────── */

test('every card the page prints passes a Luhn check computed in this test', async ({ page }) => {
  const panels: Array<[RegExp, string]> = [
    [/The Encoder/, 'encoder'],
    [/Honey Encryption/, 'honey'],
    [/The Search, Again/, 'search'],
    [/Where It Stops/, 'limits'],
  ];
  let seen = 0;
  for (const [name] of panels) {
    await page.getByRole('tab', { name }).click();
    const cards = await cardsOnScreen(page);
    expect(cards.length, 'each of these panels prints at least one card').toBeGreaterThan(0);
    for (const c of cards) {
      expect(c, `card on screen: ${c}`).toHaveLength(16);
      expect(luhnByReversal(c), `Luhn (by reversal) for ${c}`).toBe(true);
      seen++;
    }
  }
  expect(seen).toBeGreaterThan(10);
});

/* ── exhibit 2: the decode claim, re-derived ─────────────────────────────── */

test('the decoded account is what floor(S x b / 2^64) gives, computed here', async ({ page }) => {
  await page.getByRole('tab', { name: /The Encoder/ }).click();
  for (let i = 0; i < 6; i++) {
    if (i > 0) await page.getByRole('button', { name: /Random seed from the whole space/ }).click();
    const seedHex = (await page.locator('#enc-seed').inputValue()).trim();
    await expect(page.locator('[data-claim="decoded"]')).toBeVisible();
    const headline = (await page.locator('[data-claim="decoded"] .verdict-text').innerText()).trim();
    const card = headline.replace(/^DECODES TO /, '');
    // Re-derived here, by BigInt division, from the seed the page is showing.
    const account = decodeHere(seedHex, B);
    const body = '400000' + String(account).padStart(9, '0');
    expect(card.slice(0, 15), `seed ${seedHex}`).toBe(body);
    expect(luhnByReversal(card)).toBe(true);
  }
});

test('the interval width on screen equals the difference of the bounds on screen', async ({ page }) => {
  await page.getByRole('tab', { name: /The Encoder/ }).click();
  const rows = page.locator('#enc-interval tbody tr');
  const lo = BigInt((await rows.nth(0).locator('td').innerText()).trim());
  const hi = BigInt((await rows.nth(1).locator('td').innerText()).trim());
  const widthText = (await rows.nth(2).locator('td').innerText()).trim();
  const width = BigInt(widthText.split(' ')[0]!.replace(/,/g, ''));
  expect(width).toBe(hi - lo);
});

test('a malformed seed is refused and the page names the cause', async ({ page }) => {
  await page.getByRole('tab', { name: /The Encoder/ }).click();
  await page.fill('#enc-seed', 'not a seed');
  const v = page.locator('[data-claim="seed-refused"]');
  await expect(v).toBeVisible();
  await expect(v).toContainText('hexadecimal');
  await expect(page.locator('[data-claim="decoded"]')).toHaveCount(0);
});

/* ── exhibit 3: the round trip the page claims ───────────────────────────── */

test('the right password returns exactly the card that was entered', async ({ page }) => {
  await page.getByRole('tab', { name: /Honey Encryption/ }).click();
  for (const account of ['123456789', '000000000', '999999999', '314159265']) {
    await page.fill('#he-account', account);
    await page.fill('#he-password', `pw-${account}`);
    await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
    const headline = await page.locator('#he-ct [data-claim="encrypted"] .verdict-text').innerText();
    // The page's own claim about what the right password gives back...
    const claimed = headline.match(/\d{16}/)![0];
    // ...checked against the account that was typed in, and the check digit
    // recomputed here.
    expect(claimed.slice(0, 15)).toBe('400000' + account);
    expect(luhnByReversal(claimed)).toBe(true);
    // And against the stat row, which prints the same card by another route.
    await expect(page.locator('#he-ct .stat-value').first()).toHaveText(
      claimed.replace(/(.{4})(?=.)/g, '$1 '),
    );
  }
});

test('a wrong password still returns a valid card, and the page says which was real', async ({ page }) => {
  await page.getByRole('tab', { name: /Honey Encryption/ }).click();
  await page.fill('#he-try', 'definitely not the password');
  await page.getByRole('button', { name: /Decrypt with this password/ }).click();
  const row = page.locator('#he-attempts tbody tr').first();
  const card = (await row.locator('td').nth(1).innerText()).replace(/ /g, '');
  expect(luhnByReversal(card)).toBe(true);
  await expect(row.locator('td').nth(2)).toContainText('passes');
  await expect(row.locator('td').nth(3)).toContainText('no');
});

/* ── retirement and the no-op guard ──────────────────────────────────────── */

test('changing the account retires the honey ciphertext and says it was retired', async ({ page }) => {
  await page.getByRole('tab', { name: /Honey Encryption/ }).click();
  await expect(page.locator('#he-ct [data-claim="encrypted"]')).toBeVisible();
  await page.fill('#he-account', '222222222');
  await expect(page.locator('#he-ct [data-claim="encrypted"]')).toHaveCount(0);
  const stale = page.locator('#he-ct [data-claim="retired"]');
  await expect(stale).toBeVisible();
  await expect(stale).toContainText('RETIRED');
  await expect(stale).toContainText('no longer describe');
});

test('changing the password retires the ordinary ciphertext', async ({ page }) => {
  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  await expect(page.locator('#ord-out [data-claim="encrypted"]')).toBeVisible();
  await page.fill('#ord-password', 'something else');
  await expect(page.locator('#ord-out [data-claim="retired"]')).toBeVisible();
});

test('changing the dictionary retires the search result', async ({ page }) => {
  await page.getByRole('tab', { name: /The Search, Again/ }).click();
  await expect(page.locator('[data-claim="no-distinguisher"]')).toBeVisible();
  await page.selectOption('#search-size', '100');
  await expect(page.locator('[data-claim="no-distinguisher"]')).toHaveCount(0);
  await expect(page.locator('[data-claim="retired"]')).toBeVisible();
});

test('NO-OP GUARD: re-selecting the same dictionary does not retire a fresh result', async ({ page }) => {
  await page.getByRole('tab', { name: /The Search, Again/ }).click();
  await expect(page.locator('[data-claim="no-distinguisher"]')).toBeVisible();
  // The same value, selected again. Nothing about the page changed, so the
  // result on screen still describes it and must survive.
  await page.selectOption('#search-size', 'vector');
  await expect(page.locator('[data-claim="retired"]')).toHaveCount(0);
  await expect(page.locator('[data-claim="no-distinguisher"]')).toBeVisible();
});

/* ── the [hidden] probe ──────────────────────────────────────────────────── */

test('[hidden] PROBE: no hidden element paints', async ({ page }) => {
  // A class rule setting `display` outranks the UA `[hidden]` rule, so an
  // element can paint while the code believes it is hidden.
  for (const tab of [/The Encoder/, /Where It Stops/]) {
    await page.getByRole('tab', { name: tab }).click();
    const leaking = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[hidden]'))
        .filter((el) => getComputedStyle(el).display !== 'none')
        .map((el) => el.id || el.className || el.tagName),
    );
    expect(leaking).toEqual([]);
  }
});

/* ── exhibit 1: the failure paths name their cause ───────────────────────── */

test('a 16-digit paste is refused, and the refusal says why', async ({ page }) => {
  await page.fill('#ord-account', '4000001234567899');
  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  const v = page.locator('[data-claim="account-refused"]');
  await expect(v).toBeVisible();
  await expect(v).toContainText('sixteen digits');
  await expect(v).toContainText('should not type a real card number');
});

test('a short account is refused and the message names the real length', async ({ page }) => {
  await page.fill('#ord-account', '1234');
  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  await expect(page.locator('[data-claim="account-refused"]')).toContainText('not 4');
});

test('AES-GCM rejects every wrong password, and the page reports a rejection not a decryption', async ({ page }) => {
  await page.selectOption('#ord-mode', 'aes-gcm');
  await page.fill('#ord-password', 'monkey');
  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  await page.getByRole('button', { name: /Run the dictionary attack/ }).click();
  // Wait on the completion signal, not a timeout: the attack is forty real
  // PBKDF2 derivations and the table does not exist until it finishes.
  await expect(page.locator('[data-claim="pbe-recovered"]')).toBeVisible();
  const rows = page.locator('#ord-out tbody tr');
  const n = await rows.count();
  expect(n).toBeGreaterThan(1);
  // Every row before the last is a rejection; the last is the recognised one.
  for (let i = 0; i < n - 1; i++) {
    await expect(rows.nth(i).locator('td').nth(1)).toContainText('rejected by the tag');
  }
  await expect(page.locator('[data-claim="pbe-recovered"]')).toContainText('TAG SAID SO');
});

test('a password outside the dictionary gives "not found", not a false positive', async ({ page }) => {
  await page.fill('#ord-password', 'nowhere in that list at all');
  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  await page.getByRole('button', { name: /Run the dictionary attack/ }).click();
  const v = page.locator('[data-claim="pbe-not-found"]');
  await expect(v).toBeVisible();
  await expect(v).toContainText('NOT FOUND');
  await expect(v).toContainText('not among');
});

/* ── exhibit 4: the headline counts ──────────────────────────────────────── */

test('the candidate list has exactly the dictionary size, all distinct, stated on screen', async ({ page }) => {
  await page.getByRole('tab', { name: /The Search, Again/ }).click();
  for (const [value, size] of [
    ['vector', 6],
    ['100', 100],
  ] as const) {
    await page.selectOption('#search-size', value);
    await page.getByRole('button', { name: /Run the dictionary attack/ }).click();
    await expect(page.locator('#search-table tbody tr')).toHaveCount(size);

    const cards = await page
      .locator('#search-table tbody tr td:nth-child(2)')
      .allInnerTexts();
    const normalised = cards.map((c) => c.replace(/ /g, ''));
    expect(normalised).toHaveLength(size);
    for (const c of normalised) expect(luhnByReversal(c), c).toBe(true);

    // The page's own "distinct cards" figure must equal what the rows show,
    // and if they ever collide the page must SAY so rather than quietly
    // printing a smaller number.
    const distinctOnScreen = Number(
      (await page.locator('.stat', { hasText: 'Distinct cards' }).locator('.stat-value').innerText())
        .replace(/,/g, ''),
    );
    expect(distinctOnScreen).toBe(new Set(normalised).size);
    const sub = await page
      .locator('.stat', { hasText: 'Distinct cards' })
      .locator('.stat-sub')
      .innerText();
    expect(sub).toBe(distinctOnScreen === size ? 'no collisions' : 'two candidates collided');

    // And the verdict's own counts must agree with the rows.
    const headline = await page.locator('[data-claim="no-distinguisher"] .verdict-text').innerText();
    const [tried, valid] = headline.match(/\d+/g)!.map(Number);
    expect(tried).toBe(size);
    expect(valid).toBe(normalised.filter(luhnByReversal).length);
  }
});

test('the true card appears among the candidates exactly once, and only after the reveal', async ({ page }) => {
  await page.getByRole('tab', { name: /The Search, Again/ }).click();

  // Before: nothing in the markup separates the true row from the others.
  const marked = await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('#search-table tbody tr'));
    return rows.map((r) => ({
      cls: r.className,
      attrs: Array.from(r.attributes).map((a) => a.name),
    }));
  });
  const shapes = new Set(marked.map((m) => `${m.cls}|${m.attrs.sort().join(',')}`));
  expect(shapes.size, 'every candidate row must be identical in the DOM before the reveal').toBe(1);
  expect(await page.locator('#search-table tr.is-true').count()).toBe(0);

  await page.getByRole('button', { name: /Reveal which one is real/ }).click();
  await expect(page.locator('#search-table tr.is-true')).toHaveCount(1);

  // The revealed card is one of the rows, and appears exactly once.
  const revealed = (await page.locator('[data-claim="revealed"] .verdict-text').innerText()).match(
    /\d{16}/,
  )![0];
  const cards = (await page.locator('#search-table tbody tr td:nth-child(2)').allInnerTexts()).map(
    (c) => c.replace(/ /g, ''),
  );
  expect(cards.filter((c) => c === revealed)).toHaveLength(1);
  const trueRow = (await page.locator('#search-table tr.is-true td').nth(1).innerText()).replace(
    / /g,
    '',
  );
  expect(trueRow).toBe(revealed);
});

test('a measured rate on screen is the success count over the trial count on screen', async ({ page }) => {
  await page.getByRole('tab', { name: /The Search, Again/ }).click();
  await page.selectOption('#cards-trials', '200');
  await page.getByRole('button', { name: 'Run', exact: true }).click();
  await expect(page.locator('[data-claim="cards-rate"]')).toBeVisible({ timeout: 300_000 });

  const successStat = page.locator('.stat', { hasText: 'Attacker successes' });
  const fraction = await successStat.locator('.stat-value').innerText();
  const printedPct = await successStat.locator('.stat-sub').innerText();
  const [successes, trials] = fraction.split('/').map((s) => Number(s.replace(/[,\s]/g, '')));

  // The percentage beside the fraction is that fraction.
  expect(Number(printedPct.replace('%', ''))).toBeCloseTo((successes! / trials!) * 100, 2);
  expect(trials).toBe(200);

  // And the headline verdict quotes the same percentage and the same denominator.
  const headline = await page.locator('[data-claim="cards-rate"] .verdict-text').innerText();
  expect(headline).toContain(printedPct.trim());
  const detail = await page.locator('[data-claim="cards-rate"] .verdict-detail').innerText();
  expect(detail).toContain(trials!.toLocaleString('en-US'));
  expect(detail).toContain(successes!.toLocaleString('en-US'));
});

/* ── exhibit 6: the limits, re-derived ───────────────────────────────────── */

test('the mauling delta on screen is the difference of the two cards on screen', async ({ page }) => {
  await page.getByRole('tab', { name: /Where It Stops/ }).click();
  for (let i = 0; i < 4; i++) {
    if (i > 0) await page.getByRole('button', { name: /Try a random card instead/ }).click();
    const stats = page.locator('#maul-out .stat-value');
    const stored = (await stats.nth(0).innerText()).replace(/ /g, '');
    const after = (await stats.nth(1).innerText()).replace(/ /g, '');
    const printedDelta = Number((await stats.nth(2).innerText()).replace(/[+,]/g, ''));
    // Re-derived here from the two cards, not from the page's arithmetic.
    const accountOf = (c: string) => Number(c.slice(6, 15));
    expect(accountOf(after) - accountOf(stored)).toBe(printedDelta);
    expect(Math.abs(printedDelta)).toBe(500_000_000);
    expect(luhnByReversal(stored) && luhnByReversal(after)).toBe(true);
  }
});

test('the typo panel reports a valid card AND the wrong one, with no error available', async ({ page }) => {
  await page.getByRole('tab', { name: /Where It Stops/ }).click();
  const v = page.locator('[data-claim="typo"]');
  await expect(v).toContainText('VALID CARD');
  await expect(v).toContainText('WRONG ONE');
  await expect(v).toContainText('NO WARNING');
  // The page states that no error is possible rather than inventing one.
  await expect(page.locator('#typo-out')).toContainText('none is possible');
  const stats = page.locator('#typo-out .stat-value');
  const stored = (await stats.nth(0).innerText()).replace(/ /g, '');
  const got = (await stats.nth(1).innerText()).replace(/ /g, '');
  expect(got).not.toBe(stored);
  expect(luhnByReversal(got)).toBe(true);
});

test('the known-plaintext panel recovers the password and says it is unavoidable', async ({ page }) => {
  await page.getByRole('tab', { name: /Where It Stops/ }).click();
  const v = page.locator('[data-claim="known-plaintext"]');
  await expect(v).toContainText('PASSWORD RECOVERED');
  await expect(page.locator('#kpa-out')).toContainText('2016/174');
});

/* ── §4.1d THE NEGATIVE CLAIM ────────────────────────────────────────────── */

/**
 * The claim, scoped to what this page puts on screen:
 *
 *   "A decryption that looks like a valid card says nothing about whether the
 *    password was right: here every one of these passwords produced a valid
 *    card, and only one of them is the real one."
 *
 * The evidence fixture is exhibit 4 on the published vector with the six
 * passwords of its table as the dictionary — a state in which EVERY check the
 * page performs reports success (six valid cards, six Luhn passes, no
 * collisions) and the named property is violated anyway: five of those six
 * valid cards are produced by a wrong password, and nothing distinguishes
 * them.
 */
const NEGATIVE_CLAIM =
  'A decryption that looks like a valid card says nothing about whether the password was right: ' +
  'here every one of these passwords produced a valid card, and only one of them is the real one.';

test('NEGATIVE CLAIM 1: the evidence fixture is reachable through the UI', async ({ page }) => {
  await page.getByRole('tab', { name: /The Search, Again/ }).click();
  await expect(page.locator('#search-size')).toHaveValue('vector');
  await expect(page.locator('#search-table tbody tr')).toHaveCount(6);
  // It is the arrival state of this exhibit, reached by clicking its tab.
  await expect(page.locator('[data-claim="no-distinguisher"]')).toBeVisible();
});

test('NEGATIVE CLAIM 2: in that state every check the page performs reports success', async ({ page }) => {
  await page.getByRole('tab', { name: /The Search, Again/ }).click();

  // Asserted against the RENDERED verdicts, not a flag this test sets.
  const verdicts = page.locator('#search-out .verdict');
  const kinds = await verdicts.evaluateAll((els) =>
    els.map((e) => e.getAttribute('data-verdict')),
  );
  expect(kinds.length).toBeGreaterThan(0);
  expect(kinds.every((k) => k === 'held'), `verdict tones in the fixture: ${kinds}`).toBe(true);

  // Every Luhn column says it passes, and this test agrees independently.
  const luhnCells = await page.locator('#search-table tbody tr td:nth-child(3)').allInnerTexts();
  expect(luhnCells).toHaveLength(6);
  expect(luhnCells.every((c) => c.includes('passes'))).toBe(true);
  const cards = (await page.locator('#search-table tbody tr td:nth-child(2)').allInnerTexts()).map(
    (c) => c.replace(/ /g, ''),
  );
  expect(cards.every(luhnByReversal)).toBe(true);
  expect(new Set(cards).size).toBe(6);

  // The headline reports total success: six tried, six valid.
  await expect(page.locator('[data-claim="no-distinguisher"] .verdict-text')).toHaveText(
    '6 PASSWORDS TRIED — 6 VALID CARDS — NO WAY TO TELL',
  );
});

test('NEGATIVE CLAIM 3: the limitation is visible on screen in exactly that state', async ({ page }) => {
  await page.getByRole('tab', { name: /The Search, Again/ }).click();
  const v = page.locator('[data-claim="no-distinguisher"]');
  await expect(v).toBeVisible();
  // Visible — not in the README, not behind a disclosure the reader must open.
  await expect(v.locator('.verdict-detail')).toHaveText(NEGATIVE_CLAIM);
  const openDisclosures = await page.locator('#panel-search details[open]').count();
  expect(openDisclosures, 'the claim must not depend on an opened disclosure').toBe(0);
});

test('NEGATIVE CLAIM BITE: a valid card from a wrong password is scored as a FAILED attack', async ({ page }) => {
  // The bite fixture for mutation (7). The attacker picks the `qwerty` row:
  // its card passes the Luhn check, so a page that scored success on "returned
  // a valid card" would call this a win. It is a loss, and the page says so.
  await page.getByRole('tab', { name: /The Search, Again/ }).click();
  const row = page.locator('#search-table tbody tr', { hasText: 'qwerty' });
  const card = (await row.locator('td').nth(1).innerText()).replace(/ /g, '');
  expect(luhnByReversal(card), 'the picked card really is valid').toBe(true);
  await expect(row.locator('td').nth(2)).toContainText('passes');

  await row.getByRole('button', { name: 'Pick' }).click();
  const scored = page.locator('[data-claim="attack-scored"]');
  await expect(scored).toBeVisible();
  await expect(scored).toHaveAttribute('data-verdict', 'held');
  await expect(scored.locator('.verdict-text')).toHaveText('ATTACK FAILED');
  await expect(scored).toContainText('passes the Luhn check');
  await expect(scored).toContainText('it is not the card');

  // And the true password, picked, IS scored as a success — so the scorer is
  // not simply always saying no.
  await page
    .locator('#search-table tbody tr', { hasText: 'correct horse' })
    .first()
    .getByRole('button', { name: 'Pick' })
    .click();
  await expect(page.locator('[data-claim="attack-scored"] .verdict-text')).toHaveText(
    'ATTACK SUCCEEDED',
  );
});
