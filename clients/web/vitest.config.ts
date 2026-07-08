import { defineConfig } from "vitest/config";

export default defineConfig({
  // Vitest does NOT merge vite.config.ts and vitest.config.ts when both
  // exist - it uses this file exclusively for `vitest run`/`npm test`. The
  // server.fs.allow entry below therefore has to be duplicated here (see
  // the matching entry and comment in vite.config.ts, which covers
  // `npm run dev`/`npm run build` instead): the generated WASM package
  // (core/bindings/wasm/pkg) lives outside this project's root and Vite's
  // dev-server-style resolver (which Vitest uses internally to transform
  // files) denies filesystem access outside the root by default, without
  // this allow entry.
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
