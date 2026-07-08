import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

export default defineConfig({
  // wasm() + topLevelAwait(): the generated WASM package is built with
  // `wasm-pack build --target bundler` (see package.json's prepare-wasm
  // script), whose glue code uses a static `.wasm` import plus top-level
  // await for instantiation - these plugins are what actually teach
  // Vite/Vitest how to load that import (wasm-pack's --target web
  // alternative instead does a runtime fetch() of the .wasm binary, which
  // works in a real browser or under Vite's dev server but has no HTTP
  // server to hit under Vitest's Node-based test runner).
  plugins: [react(), wasm(), topLevelAwait()],
  server: {
    fs: {
      // The generated WASM package (core/bindings/wasm/pkg, produced by
      // `npm run prepare-wasm`) lives outside this project's root
      // (clients/web), which Vite's dev server denies access to by
      // default - allow the monorepo root so imports of that package
      // resolve instead of failing with "Failed to resolve import ...
      // Does the file exist?" even though the file is genuinely present.
      allow: ['../..'],
    },
  },
});
