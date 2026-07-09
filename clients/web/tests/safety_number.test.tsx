/** @vitest-environment jsdom */
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { SafetyNumberVerification } from '../src/SafetyNumberVerification';

// Mock wasm binding and init
vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
  derive_safety_number: vi.fn((localKey, remoteKey) => {
    const concat = new Uint8Array([...new Uint8Array(localKey), ...new Uint8Array(remoteKey)]);
    return btoa(String.fromCharCode(...concat));
  }),
}));
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: vi.fn(() => Promise.resolve()) }));

const localKey = new Uint8Array([1, 2, 3]);
const remoteKey = new Uint8Array([4, 5, 6]);
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
  render(<SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={remoteKey} conversationId={conversationId} />);
  await waitFor(() => expect(screen.getByText(/Verified/)).toBeInTheDocument());
});

test('TOFU violation clears verification and shows warning', async () => {
  const { rerender } = render(<SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={remoteKey} conversationId={conversationId} />);
  await waitFor(() => expect(screen.getByText(/Safety Number:/)).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: /Mark as Verified/i }));
  expect(await screen.findByText(/Verified/)).toBeInTheDocument();
  const newRemoteKey = new Uint8Array([7, 8, 9]);
  rerender(<SafetyNumberVerification localIdentityKey={localKey} remoteIdentityKey={newRemoteKey} conversationId={conversationId} />);
  expect(await screen.findByText(/Verified/)).not.toBeInTheDocument();
  expect(screen.getByText(/Remote identity key changed/)).toBeInTheDocument();
});
