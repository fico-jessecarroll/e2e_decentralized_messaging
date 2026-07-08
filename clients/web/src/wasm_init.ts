/**
 * The WASM package is built with `wasm-pack build --target bundler` (see
 * package.json's prepare-wasm script), whose generated glue uses a static
 * `.wasm` import plus top-level await for instantiation, handled by the
 * vite-plugin-wasm/vite-plugin-top-level-await Vite plugins - there is no
 * separate exported init function to call (unlike the `--target web`
 * alternative, which exports an explicit async init function and loads the
 * .wasm binary via a runtime fetch() - that approach doesn't work under
 * Vitest's Node-based test runner, which has no HTTP server to fetch from;
 * see this file's git history for that earlier, reverted approach).
 *
 * ESM's top-level-await semantics guarantee that a module using top-level
 * await has finished its own top-level evaluation (i.e. the WASM instance
 * is ready) before any importer's own code runs past its `import`/`await
 * import(...)` of that module. This helper exists so every call site keeps
 * the same "await ensureWasmInit() before using wasm.*" shape regardless of
 * which underlying loading strategy is in effect - today that's just an
 * already-resolved promise, since readiness is guaranteed by the time this
 * module's own imports resolve.
 */

export function ensureWasmInit(): Promise<void> {
    return Promise.resolve();
}
