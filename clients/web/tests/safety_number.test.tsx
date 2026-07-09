/** @vitest-environment jsdom */
import { describe, it, expect, beforeAll } from 'vitest';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from '../src/wasm_init';

// wasm-bindgen's --target bundler output requires this async init to complete
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

/** @vitest-environment jsdom */
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { SafetyNumberVerification } from '../src/SafetyNumberVerification';
import * as wasmModule from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from '../src/wasm_init';

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
  derive_safety_number: vi.fn((localKey, remoteKey) => {
    const concat = new Uint8Array([...new Uint8Array(localKey), ...new Uint8Array(remoteKey)]);
    return btoa(String.fromCharCode(...concat));
  }),
}));
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: vi.fn(() => Promise.resolve()) }));

const localKey = new Uint8Array([1,2,3]);
const remoteKey = new Uint8Array([4,5,6]);
const conversationId = 'conv-123';

beforeEach(() => {
  window.localStorage.clear();
});

test('renders derived safety number', async () => {
  render(<SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={remoteKey} conversationId={conversationId} />);
  await waitFor(() => expect(screen.getByText(/Safety Number:/)).toBeInTheDocument());
  const concat = new Uint8Array([...new Uint8Array(localKey), ...new Uint8Array(remoteKey)]);
  const expectedSn = btoa(String.fromCharCode(...concat));
  expect(screen.getByText(`Safety Number: ${expectedSn}`)).toBeInTheDocument();
});

test('verification state persists across remount', async () => {
  const { unmount } = render(<SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={remoteKey} conversationId={conversationId} />);
  await waitFor(() => expect(screen.getByText(/Safety Number:/)).toBeInTheDocument());
  const button = screen.getByRole('button', { name: /Mark as Verified/i });
  fireEvent.click(button);
  expect(await screen.findByText(/Verified/)).toBeInTheDocument();
  unmount();
  render(<SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={remoteIdentityKey} conversationId={conversationId} />);
  await waitFor(() => expect(screen.getByText(/Verified/)).toBeInTheDocument());
});

test('TOFU violation clears verification and shows warning', async () => {
  const { rerender } = render(<SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={remoteKey} conversationId={conversationId} />);
  await waitFor(() => expect(screen.getByText(/Safety Number:/)).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: /Mark as Verified/i }));
  expect(await screen.findByText(/Verified/)).toBeInTheDocument();
  const newRemoteKey = new Uint8Array([7,8,9]);
  rerender(<SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={newRemoteKey} conversationId={conversationId} />);
  await waitFor(() => expect(screen.getByText(/Remote identity key changed; safety number invalidated/)).toBeInTheDocument());
  expect(screen.getByRole('button', { name: /Mark as Verified/i })).toBeInTheDocument();
});, () => {
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
