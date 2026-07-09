/** @vitest-environment jsdom */
import '@testing-library/jest-dom';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { SafetyNumberVerification } from '../src/SafetyNumberVerification';

// Mutable fixture the mock reads at call time.
let mockStoredRecord: unknown = null;

// Mock StorageGate matching the REAL API.
vi.mock('../src/storage', () => {
  class MockStorageGate {
    async open() { return Promise.resolve(); }
    async get(_store: string, _id: string) { return mockStoredRecord; }
    async put(_store: string, _id: string, value: unknown) { mockStoredRecord = value; }
  }
  return { StorageGate: MockStorageGate, StoreName: undefined as any };
});

// Mock the real WASM module directly (never via a stub_wasm/wasm_wrapper
// indirection — production components import from the real path, so tests
// must mock that same path).
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

// Match the green "Verified" paragraph specifically — excludes
// "Mark as Verified" and "Unverify".
const VERIFIED_RE = /^Verified$/;

beforeEach(() => {
  mockStoredRecord = null;
});

describe('SafetyNumberVerification persistence', () => {
  it('persists verified state across reload (fresh component, same storage)', async () => {
    const { unmount } = render(
      <SafetyNumberVerification
        localIdentityKey={localKey}
        remoteIdentityKey={remoteKeyA}
        conversationId={conversationId}
      />,
    );
    // Wait for safety number to render, then click "Mark as Verified".
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: /Mark as Verified/i }),
      ).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole('button', { name: /Mark as Verified/i }));
    await waitFor(() =>
      expect(screen.getByText(VERIFIED_RE)).toBeInTheDocument(),
    );

    // Wait for the persist effect to write to storage.
    await waitFor(() => {
      const rec = mockStoredRecord as { verified: boolean } | null;
      expect(rec).not.toBeNull();
      expect(rec!.verified).toBe(true);
    });

    // Simulate a reload: unmount, then render a fresh instance backed by
    // the same mocked storage (mockStoredRecord retains the put value).
    unmount();
    render(
      <SafetyNumberVerification
        localIdentityKey={localKey}
        remoteIdentityKey={remoteKeyA}
        conversationId={conversationId}
      />,
    );
    // After reload, still verified because the remote key matches.
    await waitFor(() =>
      expect(screen.getByText(VERIFIED_RE)).toBeInTheDocument(),
    );
  });

  it('clears verified state and shows warning on TOFU violation', async () => {
    // Pre-seed storage as if the user previously verified with remoteKeyA.
    mockStoredRecord = {
      verified: true,
      remoteKeyBase64: btoa(String.fromCharCode(...remoteKeyA)),
    };

    render(
      <SafetyNumberVerification
        localIdentityKey={localKey}
        remoteIdentityKey={remoteKeyB}
        conversationId={conversationId}
      />,
    );

    // The remote key (B) differs from the stored key (A) — TOFU violation.
    // Verified state must be cleared and a warning shown.
    await waitFor(() =>
      expect(screen.queryByText(VERIFIED_RE)).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/Remote identity key changed/)).toBeInTheDocument();
    // Button should show "Mark as Verified" (not verified state).
    expect(
      screen.getByRole('button', { name: /Mark as Verified/i }),
    ).toBeInTheDocument();
  });
});
