/** @vitest-environment jsdom */
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { SafetyNumberVerification } from '../src/SafetyNumberVerification';

// Mock wasm binding and init
vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
  derive_safety_number: (localKey: Uint8Array, remoteKey: Uint8Array) => {
    const local = Array.from(localKey).join('-');
    const remote = Array.from(remoteKey).join('-');
    return `SN-${local}-${remote}`;
  },
}));
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));

const localKey = new Uint8Array([1, 2, 3]);
const remoteKeyA = new Uint8Array([4, 5, 6]);
const remoteKeyB = new Uint8Array([7, 8, 9]);
const conversationId = 'conv-123';

beforeEach(() => {
  localStorage.clear();
});

describe('SafetyNumberVerification persistence', () => {
  it('persists verified state across reload', async () => {
    const { unmount } = render(
      <SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={remoteKeyA} conversationId={conversationId} />
    );
    const button = await screen.findByRole('button');
    fireEvent.click(button); // verify
    expect(button).toHaveTextContent('Unverify');
    unmount();
    render(
      <SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={remoteKeyA} conversationId={conversationId} />
    );
    const button2 = await screen.findByRole('button');
    expect(button2).toHaveTextContent('Unverify');
  });

  it('clears verified state and shows warning on TOFU violation', async () => {
    render(
      <SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={remoteKeyA} conversationId={conversationId} />
    );
    const button = await screen.findByRole('button');
    fireEvent.click(button); // verify
    expect(button).toHaveTextContent('Unverify');
    render(
      <SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={remoteKeyB} conversationId={conversationId} />
    );
    const button2 = await screen.findByRole('button');
    expect(button2).toHaveTextContent('Verify');
    expect(await screen.findByText(/Remote identity key changed/)).toBeInTheDocument();
  });
});
