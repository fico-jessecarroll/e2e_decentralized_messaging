// Wrapper around wasm bindings to provide type declarations
import * as wasmModule from './stub_wasm';
export const generate_identity = wasmModule.generate_identity;
export const derive_safety_number = wasmModule.derive_safety_number;
