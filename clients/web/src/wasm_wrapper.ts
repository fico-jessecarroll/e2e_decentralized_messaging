// Wrapper around wasm bindings to provide type declarations.
// Re-export ALL symbols from the stub so that every consumer (App.tsx,
// GroupConversation.tsx, SafetyNumberVerification.tsx) can import from a
// single module.  Using `export *` ensures that any new binding added to
// stub_wasm.ts is automatically available here without another edit.
export * from './stub_wasm';
