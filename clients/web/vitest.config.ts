import { defineConfig } from "vitest/config";
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

export default defineConfig({
  // Vitest does NOT merge vite.config.ts and vitest.config.ts when both
  // exist - it uses this file exclusively for `vitest run`/`npm test`. The
  // server.fs.allow entry and the wasm/topLevelAwait plugins therefore have
  // to be duplicated here too (see the matching entries and comments in
  // vite.config.ts, which cover `npm run dev`/`npm run build` instead).
  plugins: [wasm(), topLevelAwait()],
  server: {
    fs: {
      allow: ['../..'],
    },
  },
  test: {
    globals: true,
    // Default stays Node so tests/smoke.test.ts's Uint8Array (built from
    // Node's `crypto` module) compares equal against plaintext encoded via
    // the same realm's TextEncoder. jsdom is opted into per-file (see
    // banner.test.tsx's `@vitest-environment jsdom` docblock) rather than
    // globally, since a jsdom realm's typed-array globals are distinct from
    // Node's and fail toEqual against Node-built Uint8Arrays despite
    // identical bytes.
  },
});
