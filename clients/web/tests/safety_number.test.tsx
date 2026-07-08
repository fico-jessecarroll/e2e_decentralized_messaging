/** @vitest-environment jsdom */
import { describe, it, expect } from 'vitest';
import * as wasm from '../../core/bindings/wasm/pkg/index.js';

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

    // Render component to ensure it uses the same function
    const { render } = await import('@testing-library/react');
    const { SafetyNumberVerification } = await import('../../src/SafetyNumberVerification.tsx');
    const { getByText } = render(
      <SafetyNumberVerification localIdentityKey={local} remoteIdentityKey={remote} conversationId="conv1" />
    );

    expect(getByText(expected)).toBeTruthy();
  });

  it('throws error on malformed key bytes', () => {
    const bad = new Uint8Array(32); // wrong length
    const good = new Uint8Array(33);
    expect(() => wasm.derive_safety_number(bad, good)).toThrow();
  });
});