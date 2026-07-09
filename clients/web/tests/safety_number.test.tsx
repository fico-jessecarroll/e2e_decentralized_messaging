/** @vitest-environment jsdom */
import '@testing-library/jest-dom';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { SafetyNumberVerification } from '../src/SafetyNumberVerification';

// Mutable fixture the mock reads at call time — each test sets it before
// rendering.  A vi.mock factory is hoisted and file-scoped, so a shared
// variable is the correct way to vary the mocked return value per test.
let mockStoredRecord: unknown = null;

// Mock StorageGate matching the REAL API: get(store, id) / put(store, id,
// value), both already (de)serializing JSON internally.
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
    const concat = new Uint8Array([...localKey, ...remoteKey]);
    return btoa(String.fromCharCode(...concat));
  },
}));
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: vi.fn(() => Promise.resolve()) }));

const localKey = new Uint8Array([1, 2, 3]);
const remoteKey = new Uint8Array([4, 5, 6]);
const conversationId = 'conv-123';

// Match the green "Verified" paragraph specifically — the regex /^Verified$/
// excludes "Mark as Verified" and "Unverify".
const VERIFIED_RE = /^Verified$/;

beforeEach(() => {
  mockStoredRecord = null;
});

test('displays the real derived safety number for a given key pair', async () => {
  render(
    <SafetyNumberVerification
      localIdentityKey={localKey}
      remoteIdentityKey={remoteKey}
      conversationId={conversationId}
    />,
  );
  await waitFor(() =>
    expect(screen.getByText(/Safety Number:/)).toBeInTheDocument(),
  );
  const concat = new Uint8Array([...localKey, ...remoteKey]);
  const expectedSn = btoa(String.fromCharCode(...concat));
  expect(screen.getByText(`Safety Number: ${expectedSn}`)).toBeInTheDocument();
});

test('marking verified persists across a simulated reload', async () => {
  const { unmount } = render(
    <SafetyNumberVerification
      localIdentityKey={localKey}
      remoteIdentityKey={remoteKey}
      conversationId={conversationId}
    />,
  );
  await waitFor(() =>
    expect(screen.getByText(/Safety Number:/)).toBeInTheDocument(),
  );
  fireEvent.click(screen.getByRole('button', { name: /Mark as Verified/i }));
  await waitFor(() =>
    expect(screen.getByText(VERIFIED_RE)).toBeInTheDocument(),
  );

  // Wait for the persist effect's async write to complete before
  // unmounting, otherwise the storage may not yet contain the verified
  // record when the fresh component reads it.
  await waitFor(() => {
    const rec = mockStoredRecord as { verified: boolean } | null;
    expect(rec).not.toBeNull();
    expect(rec!.verified).toBe(true);
  });

  // Simulate a reload: unmount, then render a fresh component instance
  // backed by the same mocked storage (mockStoredRecord retains the value
  // written by the put() call above).
  unmount();
  render(
    <SafetyNumberVerification
      localIdentityKey={localKey}
      remoteIdentityKey={remoteKey}
      conversationId={conversationId}
    />,
  );
  // After reload the component should still show Verified because the
  // persisted record has the same remote key.
  await waitFor(() =>
    expect(screen.getByText(VERIFIED_RE)).toBeInTheDocument(),
  );
});

test('TOFU violation: changing the remote key clears verified state and shows a warning', async () => {
  // Pre-seed storage as if the user previously verified with remoteKey.
  mockStoredRecord = {
    verified: true,
    remoteKeyBase64: btoa(String.fromCharCode(...remoteKey)),
  };

  const { rerender } = render(
    <SafetyNumberVerification
      localIdentityKey={localKey}
      remoteIdentityKey={remoteKey}
      conversationId={conversationId}
    />,
  );
  // Initially verified (loaded from storage, key matches).
  await waitFor(() =>
    expect(screen.getByText(VERIFIED_RE)).toBeInTheDocument(),
  );

  // Now the remote identity key changes — this is the TOFU violation.
  const newRemoteKey = new Uint8Array([7, 8, 9]);
  rerender(
    <SafetyNumberVerification
      localIdentityKey={localKey}
      remoteIdentityKey={newRemoteKey}
      conversationId={conversationId}
    />,
  );

  // Verified state must be cleared — never silently carried forward.
  await waitFor(() =>
    expect(screen.queryByText(VERIFIED_RE)).not.toBeInTheDocument(),
  );
  // A visible warning must be surfaced.
  expect(screen.getByRole('alert')).toBeInTheDocument();
  expect(screen.getByText(/Remote identity key changed/)).toBeInTheDocument();
  // The button should revert to "Mark as Verified".
  expect(
    screen.getByRole('button', { name: /Mark as Verified/i }),
  ).toBeInTheDocument();
});

test('handles empty key arrays without crashing (boundary validation)', async () => {
  render(
    <SafetyNumberVerification
      localIdentityKey={new Uint8Array(0)}
      remoteIdentityKey={new Uint8Array(0)}
      conversationId={conversationId}
    />,
  );
  // The stub derive_safety_number with empty arrays produces btoa("") = "".
  // The component should display the safety number without crashing.
  await waitFor(() =>
    expect(screen.getByText(/Safety Number:/)).toBeInTheDocument(),
  );
});
