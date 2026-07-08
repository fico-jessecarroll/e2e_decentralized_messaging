/** @vitest-environment jsdom */
import { describe, it, expect, beforeAll } from 'vitest';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from '../src/wasm_init';

// wasm-bindgen's --target web output requires this async init to complete
// before any other export (generate_identity, derive_safety_number) is
// usable - see src/wasm_init.ts.
beforeAll(async () => {
  await ensureWasmInit();
});

// Helper to generate a key pair and get public bytes
async function genPublicBytes(): Promise<Uint8Array> {
  const identity = wasm.generate_identity();
  // The generated identity exposes a method `public_bytes` returning Uint8Array
  return identity.public_bytes();
}

describe('Safety number derivation', () => {
  it('derives same safety number for given keys via component and direct wasm call', async () => {
    const local = await genPublicBytes();
    const remote = await genPublicBytes();
    const expected = wasm.derive_safety_number(local, remote);

    // Render component to ensure it uses the same function. The component
    // derives asynchronously (see SafetyNumberVerification.tsx), so wait for
    // the derived text to appear rather than asserting immediately.
    const { render, screen, waitFor } = await import('@testing-library/react');
    const { SafetyNumberVerification } = await import('../src/SafetyNumberVerification.tsx');
    render(
      <SafetyNumberVerification localIdentityKey={local} remoteIdentityKey={remote} conversationId="conv1" />
    );

    await waitFor(() => expect(screen.getByText(expected)).toBeTruthy());
  });

  it('throws error on malformed key bytes', () => {
    const bad = new Uint8Array(32); // wrong length
    const good = new Uint8Array(33);
    expect(() => wasm.derive_safety_number(bad, good)).toThrow();
  });
});
