/**
 * wasm-bindgen's `--target web` output requires calling and awaiting its
 * default export (an async init function that instantiates the WebAssembly
 * module) exactly once before any other export is usable - calling e.g.
 * `wasm.generate_identity()` beforehand throws "Cannot read properties of
 * undefined" because the module's internal WebAssembly instance is not yet
 * set. This memoized helper ensures every caller shares the same init, run
 * only once regardless of how many components call it.
 */
import init from '../../../core/bindings/wasm/pkg/index.js';

let initPromise: ReturnType<typeof init> | null = null;

export function ensureWasmInit(): ReturnType<typeof init> {
    if (!initPromise) {
        initPromise = init();
    }
    return initPromise;
}
