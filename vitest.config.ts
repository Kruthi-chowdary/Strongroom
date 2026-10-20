import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // express-rate-limit ships ESM-only; inline it so vitest transforms it
    // to CJS-compatible code when running under commonjs (Rule 8 – keep tests small).
    server: {
      deps: {
        inline: ['express-rate-limit'],
      },
    },
  },
});
