import { defineConfig } from 'vitest/config';

// Standalone Vitest config so the extension's Vite/Tailwind/React build plugins
// are not loaded for the pure unit tests in src/utils.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
