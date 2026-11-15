import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the production build served by `vite preview`, so what
 * passes here is what ships.
 *
 *   a11y.spec.ts    the axe WCAG 2.1 A/AA gate, plus the arithmetic contrast
 *                   and non-text oracles. Chromium only: it is a gate, and a
 *                   gate has to be deterministic.
 *   claims.spec.ts  what the page SAYS — the headline claim recomputed from
 *                   values on screen, the failure paths, verdict retirement,
 *                   and the negative claim's evidence fixture.
 *
 * Port 4243 is this lab's, assigned by `node tools/port-sync.js` in the
 * catalog repo and pinned in tools/playwright-ports.json. Never 4173: a shared
 * port means `reuseExistingServer` can silently scan another lab's preview,
 * and during a mutation check it can scan an unmutated checkout still running
 * from an earlier run, which reads as "the mutation was not caught".
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 90_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4243/crypto-lab-honey-encryption/',
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    {
      name: 'claims',
      testMatch: /claims\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // Build before serving: `vite preview` only serves whatever is already in
    // dist/, so without the build in front a run tests a stale bundle — and a
    // build that FAILS leaves the previous good bundle in place, so the whole
    // suite passes green against source that no longer compiles. That silently
    // invalidates mutation checking, which is the only way we prove a test has
    // teeth.
    command: 'npm run build && npm run preview -- --port 4243 --strictPort',
    url: 'http://localhost:4243/crypto-lab-honey-encryption/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
