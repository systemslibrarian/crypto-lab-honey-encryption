import { defineConfig, configDefaults } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-honey-encryption/
export default defineConfig({
  base: '/crypto-lab-honey-encryption/',
  worker: { format: 'es' },
  test: {
    // Colocated unit tests only; keep Playwright specs in e2e/ out of the Vitest run.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
    testTimeout: 120_000,
  },
});
