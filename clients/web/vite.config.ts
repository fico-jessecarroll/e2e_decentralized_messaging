import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
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
