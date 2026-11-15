import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the gate
 * this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the one rendering a reduced-motion reader actually gets — `.panel` and
 *     `.reveal` with their animations cancelled by the stylesheet's own rule —
 *     was never once the rendering that got scanned. This gate sets the
 *     preference through `emulateMedia`, asserts from inside the page that it
 *     took effect (`test.use({ reducedMotion })` silently does nothing on
 *     Playwright 1.61.1), and injects nothing.
 *
 *  2. IT FORCED EVERY PANEL VISIBLE FROM SCRIPT. The old drive stripped every
 *     `[hidden]` attribute and set every `<details>.open` by JS before its only
 *     scan. Stripping `hidden` puts all six tabpanels on screen AT ONCE — a
 *     rendering no reader can reach and axe then scans instead of the real one
 *     — and script-opening the disclosures means the SHUT state, which is what
 *     every reader arrives at, was never scanned at all. This gate switches
 *     tabs by clicking them and opens each disclosure through its `<summary>`,
 *     which is the route a reader has, and scans before and after.
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. The old drive clicked
 *     every button whose label matched a regex, swallowed every failure with
 *     `.catch(() => {})`, waited a fixed 120ms per tab, and scanned ONCE at the
 *     end — so the invalid-key rendering, the malformed-hex branch, the
 *     rejected-preset pipeline and the stepper's intermediate reveals were all
 *     overwritten before anything measured them, and a click that silently did
 *     nothing looked identical to one that worked. This drive names every
 *     control it touches, asserts a real completion signal after each, and
 *     scans after every step, in {dark, light} x {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The surfaces that carry
 *     this lab's meaning — every `.verdict-*` tone, both `.pill` states, the
 *     `.callout-danger` / `.callout-caveat` warnings, the `.learner-check`
 *     tint and the shared top bar's `color-mix()` ink — are all `color-mix()`
 *     fills axe files under `incomplete` rather than judging. So is an
 *     `aria-label` on a role-less element.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. The old
 *     spec hand-rolled one luminance check over two input selectors, reading
 *     the DECLARED `border-top-color` and `background-color` — blind to
 *     `color-mix()`, to composited backdrops, to every `.btn`, `.seg-btn`,
 *     `.tab-btn` and preset control, and to all states past first paint.
 *     `nontext.ts` replaces it with a measured oracle over every control at
 *     every driven state, and `expectNoHorizontalOverflow` adds the 1.4.10
 *     check axe has no rule for.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, `style.css`'s reduced-motion
 * block cancels `.panel` / `.reveal` animations and every transition, so
 * `getAnimations()` is normally empty and this returns on the sixth frame. It
 * stays because the shared top bar's `.cl-btn` transitions are declared
 * OUTSIDE the lab's `@media` block — `* { transition: none !important }` wins
 * today, but that is a property of the current stylesheet, not of the page.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * has EXACTLY that shape in miniature: `@keyframes fade` and `@keyframes
 * reveal` both start `from { opacity: 0 }`, and every tab panel and every
 * stepper line rides one of them. The reduced-motion block cancels both with
 * `animation: none`, which restores the static `opacity: 1` — correct today,
 * and this assertion is what makes that a measurement rather than a reading.
 *
 * `aria-hidden` subtrees are excluded; what this lab hides is decorative
 * verdict/pill glyphs beside their own words — see `contrast.ts`.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. Every panel here renders synchronously at first activation, so a
 * renderer that throws leaves that tabpanel EMPTY — and an empty region is
 * exactly what a scan reports as perfectly accessible. Attach before `boot`,
 * assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's own
 * hero is a `<div class="cl-hero">`, not a `<header>`, so nothing here implies
 * a second banner today — but the shared bar's `dedupeBanner()` exists because
 * other labs in this fleet DID ship one, and the hero markup is the part of
 * this page most likely to be re-templated from a lab that uses `<header>`.
 * Asserting the OUTCOME rather than the markup is what catches that edit.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * This lab's one list is the Verify Workbench pipeline: `ol.stage-list` styled
 * `list-style: none`, which is exactly the declaration that makes Safari and
 * VoiceOver DROP the list's implicit role. `verifyWorkbench.ts` compensates
 * the documented way — an explicit `role="list"` on the `<ol>` and
 * `role="listitem"` on every `.stage` — so here, unlike most of this fleet, an
 * explicit role on a list is the fix rather than the defect. What is asserted
 * is therefore the SHAPE of that fix: any explicit role on a `ul`/`ol` must be
 * `list` (any other value orphans every `<li>` under it), and a `role="list"`
 * must never sit on an empty element, because axe applies
 * `aria-required-children` to the explicit role and fails it the day the
 * pipeline renders with no stages. Roles can be assigned as JS properties in
 * an element-creation helper, so ask the DOM rather than grepping the source.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
      )
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children'
  ).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the structure every scan relies on is really there.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.x, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * ASSERTED from inside the page. This lab's only motion is the trial progress
 * bar and the interval marker, both tied to an action; the stylesheet's
 * reduced-motion block removes those transitions, and without the assertion we
 * would merely be believing we scanned that rendering.
 *
 * Nothing is injected into the page. The retired template gate pushed
 * `animation:none!important` through `addStyleTag`, which BYPASSES the lab's
 * own `@media (prefers-reduced-motion: reduce)` block rather than exercising
 * it, so the rendering a reduced-motion reader actually gets was never the one
 * scanned.
 *
 * Shared setup. Runs before EVERY test that imports it, so an assertion here
 * fails all of them at once, under whatever name those tests carry.
 *
 * SO THIS FUNCTION ASSERTS STRUCTURE AND NEVER PRODUCT COPY. On 2026-09-26
 * crypto-lab-mceliece-gate changed one textarea's default string; its gate.ts
 * still asserted the old sentence, boot() threw, both axe runs failed, the
 * build job failed, the deploy was skipped, and deploy-sync reported the lab
 * stale. The step that went red was called "Accessibility gate", and four of
 * its six a11y tests had passed. For three days the live site served security
 * claims that main had already corrected, and the one red thing in sight named
 * the wrong subject.
 *
 * Structure: a control EXISTS, counts, a verdict marker is PRESENT, a value
 * matches a SHAPE. What a verdict SAYS is a claim about this lab's wording and
 * belongs in e2e/claims.spec.ts, where a failure names copy as the subject.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('.tab-btn')).toHaveCount(6);
  await expect(page.locator('h1')).toHaveCount(1);

  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run
  // says nothing about.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);

  // Dark is the only theme, so the page must carry no theme control at all —
  // not the shared bar's, which was removed, and not a lab-local one. The
  // shared CSS hides any lab toggle with `display:none !important`, which would
  // leave a dead-but-known element; asserting the count at zero catches the day
  // one is added without going through that list.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]')
  ).toHaveCount(0);
  await expect(page.locator('#cl-theme-toggle')).toHaveCount(0);

  // ── The arrival state ───────────────────────────────────────────────────
  // Every panel is mounted at load and five of the six are `hidden`. They are
  // asserted NON-empty rather than empty: in this lab a blank panel is the
  // tell that a renderer threw, and an empty region is exactly what a scan
  // reports as perfectly accessible.
  await expect(page.locator('#panel-ordinary')).toBeVisible();
  await expect(page.locator('#panel-ordinary')).not.toBeEmpty();
  for (const id of ['encoder', 'honey', 'search', 'small', 'limits']) {
    await expect(page.locator(`#panel-${id}`)).toBeHidden();
    await expect(page.locator(`#panel-${id}`)).not.toBeEmpty();
  }

  // The [hidden] cascade probe. A class rule setting `display` outranks the UA
  // `[hidden]` rule, so an element can PAINT while the code believes it is
  // hidden. Four live instances of that were found across the fleet in a
  // single day. Checked here against every hidden panel, by computed style.
  const leaking = await page.evaluate(() =>
    Array.from(document.querySelectorAll('[hidden]'))
      .filter((el) => getComputedStyle(el).display !== 'none')
      .map((el) => el.id || el.className || el.tagName)
  );
  expect(leaking, '[hidden] elements that still paint').toEqual([]);

  // Every ARIA reference resolves. A dangling `aria-describedby` never reaches
  // axe's `violations` array — it surfaces only as `aria-valid-attr-value` in
  // the `incomplete` bucket, which a gate that skims violations alone cannot
  // see. One shipped here (an input described by a hint that was never
  // rendered) and this is what caught it.
  const danglingAria = await page.evaluate(() => {
    const bad: string[] = [];
    for (const attr of ['aria-describedby', 'aria-labelledby', 'aria-controls']) {
      for (const el of Array.from(document.querySelectorAll(`[${attr}]`))) {
        for (const id of (el.getAttribute(attr) || '').split(/\s+/).filter(Boolean)) {
          if (!document.getElementById(id)) bad.push(`${el.id || el.tagName} ${attr}="${id}"`);
        }
      }
    }
    return bad;
  });
  expect(danglingAria, 'ARIA references pointing at ids that do not exist').toEqual([]);

  // ── Shipped defaults, as SHAPES ─────────────────────────────────────────
  // Nine digits is structural; what the hint beside it says is copy.
  await expect(page.locator('#ord-account')).toHaveValue(/^[0-9]{9}$/);
  await expect(page.locator('#ord-password')).not.toHaveValue('');
  await expect(page.locator('#ord-mode')).toHaveValue('aes-ctr');

  // Exactly one tab arrives selected. WHICH one is a claim; claims.spec.ts
  // owns that.
  await expect(page.locator('.tab-btn[aria-selected="true"]')).toHaveCount(1);

  // ── Disclosures ship shut ───────────────────────────────────────────────
  // The retired template gate opened every one from script before its only
  // scan, so the state every reader actually arrives at went unscanned.
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. This lab's long
 * values are 64-byte hex runs — every `.field-value` and `.eq-derivation`
 * relies on `overflow-wrap: anywhere` instead of a scroll region, and the
 * `.sig-pair` grid collapses to one column at 640px — so the shapes at risk
 * are a new unwrapped `<code>` run or a grid item whose automatic minimum size
 * is the min-content of a 128-char line. At 380px that is precisely what this
 * check exists to catch.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab currently avoids scrollers on purpose — long hex wraps via
 * `overflow-wrap: anywhere` — so the assertion is usually vacuous here. It
 * runs at every state anyway, because the requirement MATERIALISES the moment
 * someone reaches for `overflow-x: auto` on a wide value or table (the
 * stylesheet already carries an unused `.table-wrap` rule inviting exactly
 * that), and a scroller born without a keyboard route is invisible to axe.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. The
 * `hidden` tabpanels here take the `display: none` route, which is why five
 * panels' worth of buttons are legitimately absent from the tab order.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` with
 * full opacity and slides in on focus. The drive scans it focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`, and this repo's baseline was
 * captured by that live path.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here because the surfaces carrying
 *    this lab's meaning are `color-mix()` fills axe cannot resolve: every
 *    verdict tone, both pill states, the danger/caveat callouts, the
 *    learner-check tint, the hero aside and the shared bar's ink. Everything
 *    else in that bucket is a real result axe simply could not finish —
 *    including `aria-prohibited-attr`, which is where an `aria-label` on a
 *    role-less element hides. This page leans on getting that right: the
 *    `.seg`, `.radio-row`, `.preset-row` and learner-check option groups all
 *    pair their labels with `role="group"`. Drop any of those roles and the
 *    label is silently discarded.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted —
 *    SC 1.4.3 is about what a reader SEES; see `contrast.ts` for what this
 *    lab hides and why it is measured anyway.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` holding an `<aside class="cl-hero-why">`, two `<nav>`s
  // (the shared actions and the tablist wrapper), one `<main>` and a footer.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // The aria-hidden walk, exemption lifted — axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the
  // ONLY thing that ever measures it. See `contrast.ts` for the inventory.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Switch to a tab by clicking it, and prove the switch happened. */
async function openTab(page: Page, name: RegExp, panelId: string): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator(panelId)).toBeVisible();
  await expect(page.locator(panelId)).not.toBeEmpty();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as a reader gets it: exhibit
 *    1 active with its ciphertext not yet made, five panels hidden, every
 *    disclosure shut.
 *
 *  - EVERY PANEL IS REACHED THROUGH ITS REAL TAB BUTTON, never by stripping
 *    `[hidden]` from script. Force-revealing the panels puts all six on screen
 *    at once — a rendering no reader can reach — and destroys the ability to
 *    catch the `[hidden]` cascade trap that boot() probes for.
 *
 *  - EVERY ERROR AND REFUSAL STATE. An account field that is not nine digits,
 *    a sixteen-digit paste (which this page refuses BY NAME), a malformed
 *    seed, a dictionary that does not contain the password, AES-GCM's
 *    rejection rows, and every retirement verdict. None of these is reachable
 *    without typing something wrong on purpose, and an unscanned failure
 *    verdict is the most likely place for a contrast regression to hide,
 *    because it is the state nobody looks at.
 *
 *  - HOVER IS A STATE, AND IT PERSISTS AFTER A CLICK. `:hover` stays on the
 *    element under the pointer after `page.click()` resolves, so it is the
 *    state a reader occupies the instant after pressing a button — and
 *    `.tab-btn:hover`, `.btn:hover` and `.cl-btn:hover` all repaint their
 *    fill. Each is scanned explicitly.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real DOM completion signal: a
 *    verdict marker appearing, a row count, `aria-selected`.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival: exhibit 1 active, five panels hidden, disclosures shut');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from top:-3rem');

  // ── 1 · Ordinary encryption ─────────────────────────────────────────────
  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  await expect(page.locator('#ord-out [data-claim="encrypted"]')).toBeVisible();
  await scanAt('Ordinary: AES-CTR ciphertext made');

  await page.getByRole('button', { name: /Run the dictionary attack/ }).click();
  await expect(page.locator('#ord-out [data-claim="pbe-recovered"]')).toBeVisible();
  await scanAt('Ordinary: AES-CTR dictionary attack recovered the password');

  // The GCM half: every wrong candidate is REJECTED rather than decrypted, so
  // the table paints a different set of rows.
  await page.selectOption('#ord-mode', 'aes-gcm');
  await expect(page.locator('#ord-out [data-claim="retired"]')).toBeVisible();
  await scanAt('Ordinary: mode changed — the stale verdict retired');

  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  await page.getByRole('button', { name: /Run the dictionary attack/ }).click();
  await expect(page.locator('#ord-out [data-claim="pbe-recovered"]')).toBeVisible();
  await scanAt('Ordinary: AES-GCM — wrong passwords rejected, the tag gives it away');

  // A dictionary that does not contain the password: the "not found" branch.
  await page.fill('#ord-password', 'a password that is not in the list at all');
  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  await page.getByRole('button', { name: /Run the dictionary attack/ }).click();
  await expect(page.locator('#ord-out [data-claim="pbe-not-found"]')).toBeVisible();
  await scanAt('Ordinary: password outside the dictionary — the not-found verdict');

  // INVARIANT 7: a sixteen-digit paste is refused by name.
  await page.fill('#ord-account', '4000001234567899');
  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  await expect(page.locator('#ord-out [data-claim="account-refused"]')).toBeVisible();
  await scanAt('Ordinary: a whole card number pasted — refused');

  await page.fill('#ord-account', '12345');
  await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
  await expect(page.locator('#ord-out [data-claim="account-refused"]')).toBeVisible();
  await scanAt('Ordinary: too few digits — refused');

  await page.locator('#panel-ordinary details > summary').first().click();
  await expect(page.locator('#panel-ordinary details[open]')).toHaveCount(1);
  await scanAt('Ordinary: the all-digit probability disclosure open');

  // ── 2 · The encoder ─────────────────────────────────────────────────────
  await openTab(page, /The Encoder/, '#panel-encoder');
  await expect(page.locator('#enc-decode [data-claim="decoded"]')).toBeVisible();
  await expect(page.locator('.spacebar-cell')).toHaveCount(5);
  await scanAt('Encoder: the vector seed decoded, five neighbouring intervals drawn');

  await page.getByRole('button', { name: /Random seed from the whole space/ }).click();
  await expect(page.locator('#enc-decode [data-claim="decoded"]')).toBeVisible();
  await scanAt('Encoder: a random seed from the whole space, still a valid card');

  // The boundary seeds, which decode to the extreme accounts.
  await page.fill('#enc-seed', '0x0000000000000000');
  await expect(page.locator('#enc-decode [data-claim="decoded"]')).toBeVisible();
  await scanAt('Encoder: seed 0');

  await page.fill('#enc-seed', '0xffffffffffffffff');
  await expect(page.locator('#enc-decode [data-claim="decoded"]')).toBeVisible();
  await scanAt('Encoder: seed 2^64 - 1');

  await page.fill('#enc-seed', 'nonsense');
  await expect(page.locator('#enc-decode [data-claim="seed-refused"]')).toBeVisible();
  await scanAt('Encoder: a malformed seed — refused');

  await page.fill('#enc-account', '123');
  await expect(page.locator('#enc-interval [data-claim="account-refused"]')).toBeVisible();
  await scanAt('Encoder: a short account — refused');

  await page.locator('#panel-encoder details > summary').first().click();
  await scanAt('Encoder: the uniformity disclosure open');

  // ── 3 · Honey encryption ────────────────────────────────────────────────
  await openTab(page, /Honey Encryption/, '#panel-honey');
  await expect(page.locator('#he-ct [data-claim="encrypted"]')).toBeVisible();
  await scanAt('Honey: the published vector encrypted');

  await page.getByRole('button', { name: /Decrypt with this password/ }).click();
  await expect(page.locator('#he-attempts [data-claim="honey-attempts"]')).toBeVisible();
  await scanAt('Honey: one wrong password tried — a valid card came back');

  await page.fill('#he-try', '');
  await page.getByRole('button', { name: /Decrypt with this password/ }).click();
  await expect(page.locator('#he-attempts tbody tr')).toHaveCount(2);
  await scanAt('Honey: the empty password, which is allowed and still gives a card');

  await page.fill('#he-account', '999999999');
  await expect(page.locator('#he-ct [data-claim="retired"]')).toBeVisible();
  await scanAt('Honey: account changed — ciphertext and every decryption retired');

  await page.getByRole('button', { name: /Load the published vector/ }).click();
  await expect(page.locator('#he-ct [data-claim="encrypted"]')).toBeVisible();

  await page.locator('#panel-honey details > summary').first().click();
  await scanAt('Honey: the construction disclosure open');

  // ── 4 · The search, again ───────────────────────────────────────────────
  await openTab(page, /The Search, Again/, '#panel-search');
  await expect(page.locator('[data-claim="no-distinguisher"]')).toBeVisible();
  await expect(page.locator('#search-table tbody tr')).toHaveCount(6);
  await scanAt('Search: the six-password fixture — six valid cards, nothing to tell');

  // The learner plays the attacker and picks a wrong row.
  await page.locator('#search-table tbody tr', { hasText: 'qwerty' }).getByRole('button').click();
  await expect(page.locator('[data-claim="attack-scored"]')).toBeVisible();
  await scanAt('Search: a valid-but-wrong row picked — the attack-failed verdict');

  await page.getByRole('button', { name: /Reveal which one is real/ }).click();
  await expect(page.locator('#search-table tr.is-true')).toHaveCount(1);
  await scanAt('Search: revealed — one row marked, after the learner asked');

  await page.selectOption('#search-size', '100');
  await expect(page.locator('[data-claim="retired"]')).toBeVisible();
  await scanAt('Search: candidate list changed — the stale result retired');

  await page.getByRole('button', { name: /Run the dictionary attack/ }).click();
  await expect(page.locator('#search-table tbody tr')).toHaveCount(100);
  await scanAt('Search: one hundred candidates, one hundred valid cards');

  await page.locator('#panel-search details > summary').first().click();
  await scanAt('Search: the bound disclosure open');

  // A short measured run, driven to completion so the result verdict is
  // scanned as well as the progress bar.
  await page.selectOption('#cards-trials', '200');
  await page.getByRole('button', { name: 'Run', exact: true }).click();
  await expect(page.locator('[data-claim="running"]')).toBeVisible();
  await scanAt('Search: a measurement running — the progress bar painted');
  await expect(page.locator('[data-claim="cards-rate"]')).toBeVisible({ timeout: 300_000 });
  await scanAt('Search: the measured rate beside w');

  // ── 5 · A small message space ───────────────────────────────────────────
  await openTab(page, /A Small Message Space/, '#panel-small');
  await expect(page.locator('#small-out [data-claim="pileup-single"]')).toBeVisible();
  await scanAt('Small: one pile-up attack run');

  // Run it until BOTH branches have been scanned: the attack succeeds about
  // one time in fifty, so the failing branch is the one on screen almost
  // always and the succeeding branch needs looking for. Both are real states
  // and both paint a different verdict tone.
  const seen = new Set<string>();
  for (let i = 0; i < 160 && seen.size < 2; i++) {
    const tone = await page.locator('#small-out .verdict').first().getAttribute('data-verdict');
    if (tone && !seen.has(tone)) {
      seen.add(tone);
      await scanAt(`Small: the pile-up attack's ${tone} branch`);
    }
    await page.getByRole('button', { name: /Run one pile-up attack/ }).click();
    await expect(page.locator('#small-out [data-claim="pileup-single"]')).toBeVisible();
  }

  await page.locator('#panel-small details > summary').first().click();
  await scanAt('Small: the balls-and-bins disclosure open');

  await page.selectOption('#pileup-trials', '500');
  await page.getByRole('button', { name: 'Run', exact: true }).click();
  await expect(page.locator('[data-claim="pileup-rate"]')).toBeVisible({ timeout: 600_000 });
  await scanAt('Small: the measured pile-up rate beside the paper\u2019s figure');

  // ── 6 · Where it stops ──────────────────────────────────────────────────
  await openTab(page, /Where It Stops/, '#panel-limits');
  await expect(page.locator('#maul-out [data-claim="mauled"]')).toBeVisible();
  await expect(page.locator('#kpa-out [data-claim="known-plaintext"]')).toBeVisible();
  await expect(page.locator('#typo-out [data-claim="typo"]')).toBeVisible();
  await scanAt('Limits: all three failure panels on arrival');

  await page.getByRole('button', { name: /Try a random card instead/ }).click();
  await expect(page.locator('#maul-out [data-claim="mauled"]')).toBeVisible();
  await scanAt('Limits: mauling a random card');

  await page.getByRole('button', { name: /Run the search with one known pair/ }).click();
  await expect(page.locator('#kpa-out [data-claim="known-plaintext"]')).toBeVisible();
  await scanAt('Limits: the known-plaintext search re-run');

  // The typo panel's other branch: the right password, which is the one state
  // where it paints a held verdict rather than a warning.
  const right = await page.locator('#typo-right').inputValue();
  await page.fill('#typo-typed', right);
  await page.getByRole('button', { name: /Decrypt with the typo/ }).click();
  await expect(page.locator('#typo-out [data-verdict="held"]')).toBeVisible();
  await scanAt('Limits: the typo panel given the right password');

  await page.fill('#typo-account', '4000001234567899');
  await page.getByRole('button', { name: /Decrypt with the typo/ }).click();
  await expect(page.locator('#typo-out [data-claim="account-refused"]')).toBeVisible();
  await scanAt('Limits: a whole card number pasted into the typo panel — refused');

  await page.locator('#panel-limits details > summary').first().click();
  await scanAt('Limits: the typo-safety disclosure open');

  // ── Hover, which persists after a click ─────────────────────────────────
  await page.getByRole('button', { name: /Run the search with one known pair/ }).hover();
  await scanAt('a primary button hovered');

  await page.getByRole('tab', { name: /The Encoder/ }).hover();
  await scanAt('an inactive tab hovered — its surface fill repainted');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');

  // ── Focus rings on the controls that take them ──────────────────────────
  await page.locator('#typo-typed').focus();
  await expect(page.locator('#typo-typed')).toBeFocused();
  await scanAt('a text input focused, showing its focus-visible outline');

  await page.getByRole('tab', { name: /Where It Stops/ }).focus();
  await scanAt('the active tab focused');

  // A scrollable table region focused: WCAG 2.1.1 requires it be reachable,
  // and its focus ring is painted over the region's own border.
  await page.locator('[role="region"][tabindex="0"]').first().focus();
  await scanAt('a scrollable table region focused');
}
