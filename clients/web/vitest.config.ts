import { defineConfig } from "vitest/config";

export default defineConfig({
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
