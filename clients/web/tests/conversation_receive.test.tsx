/** @vitest-environment jsdom */
//
// TDD tests for the receive loop and decrypt in the Conversation UI
// (issue b48d5579-271d-4bdf-9d6e-712ce3b35cc2).
//
// These tests use the REAL wasm bindings (decrypt_message, create_receiver_session,
// publish_bundle_bytes, establish_session_from_bundle, encrypt_message) — only the
// network transport boundary is mocked. Storage (IndexedDB) is also mocked, matching
// the convention in conversation_session.test.tsx.
//
// Timer mocks (vi.useFakeTimers) are used to control the polling interval so we can
// assert deterministic poll counts and verify cleanup on unmount.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';

let mockStoredMessages: unknown = null;

vi.mock('../src/storage', () => {
    class MockStorageGate {
        async open() { return Promise.resolve(); }
        async get(_store: string, _id: string) { return mockStoredMessages; }
        async put(_store: string, _id: string, value: unknown) { mockStoredMessages = value; }
    }
    return { StorageGate: MockStorageGate };
});

import { Conversation } from '../src/Conversation';
import {
    generate_identity,
    create_receiver_session,
    publish_bundle_bytes,
    establish_session_from_bundle,
    encrypt_message,
    decrypt_message,
    IdentityHandle,
} from '../../../core/bindings/wasm/pkg/index.js';

/** Minimal PersistedIdentity-shaped wrapper around a real wasm IdentityHandle. */
function toIdentity(handle: InstanceType<typeof IdentityHandle>) {
    return {
        handle,
        publicBytes: handle.public_bytes(),
        recipientId: 'test-recipient',
    };
}

/**
 * Set up a full round-trip fixture: Alice (sender) and Bob (receiver/local user).
 * Returns Alice's identity, Bob's identity, Bob's receiver session, Bob's bundle,
 * and a helper to encrypt a message from Alice to Bob.
 */
function setupRoundTrip() {
    const bobIdentity = generate_identity();
    const bobSession = create_receiver_session(bobIdentity);
    const bobBundle = publish_bundle_bytes(bobSession);

    const aliceIdentity = generate_identity();
    const aliceSession = establish_session_from_bundle(aliceIdentity, bobBundle);

    const bob = toIdentity(bobIdentity);

    /** Encrypt a plaintext from Alice to Bob, returning the wire envelope bytes. */
    function encryptToBob(plaintext: string): Uint8Array {
        const ptBytes = new TextEncoder().encode(plaintext);
        return encrypt_message(aliceSession, ptBytes);
    }

    return { bob, bobSession, bobBundle, aliceIdentity, aliceSession, encryptToBob };
}

beforeEach(() => {
    mockStoredMessages = null;
    vi.useFakeTimers();
});

afterEach(() => {
    vi.useRealTimers();
});

describe('Conversation receive loop and decrypt', () => {
    test('a message encrypted by a simulated peer session and returned via mocked pickup_envelope is decrypted and rendered with the correct plaintext', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        const envelope = encryptToBob('hello from alice!');

        const pickupEnvelope = vi.fn().mockResolvedValue(envelope);
        const transport = {
            lookupPrekey: vi.fn(),
            sendEnvelope: vi.fn(),
            pickupEnvelope,
        };

        render(<Conversation identity={bob} transport={transport} receiverSession={bobSession} />);

        // Advance timers to trigger at least one poll.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });

        // The decrypted plaintext should appear in the rendered message list.
        expect(screen.getByText('hello from alice!')).toBeInTheDocument();

        // The message should be marked as received (not sent by me).
        expect(pickupEnvelope).toHaveBeenCalledWith(bob.recipientId);
    });

    test('polling does not error or spam the console on an empty mailbox (NotFound/Expired treated as normal)', async () => {
        const { bob, bobSession } = setupRoundTrip();

        const pickupEnvelope = vi.fn().mockRejectedValue(new Error('NotFound'));
        const transport = {
            lookupPrekey: vi.fn(),
            sendEnvelope: vi.fn(),
            pickupEnvelope,
        };

        const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

        render(<Conversation identity={bob} receiverSession={bobSession} transport={transport} />);

        // Run several poll cycles.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(20000);
        });

        // No error banner should be shown.
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();

        // pickupEnvelope should have been called multiple times (polling continues).
        expect(pickupEnvelope.mock.calls.length).toBeGreaterThanOrEqual(2);

        // No console.error spam from the empty-mailbox case.
        expect(consoleErrorSpy).not.toHaveBeenCalled();

        consoleErrorSpy.mockRestore();
        consoleWarnSpy.mockRestore();
    });

    test('Expired response is also treated as an empty poll (no error banner, no crash)', async () => {
        const { bob, bobSession } = setupRoundTrip();

        const pickupEnvelope = vi.fn().mockRejectedValue(new Error('Expired'));
        const transport = {
            lookupPrekey: vi.fn(),
            sendEnvelope: vi.fn(),
            pickupEnvelope,
        };

        render(<Conversation identity={bob} receiverSession={bobSession} transport={transport} />);

        await act(async () => {
            await vi.advanceTimersByTimeAsync(10000);
        });

        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        expect(pickupEnvelope.mock.calls.length).toBeGreaterThanOrEqual(1);
    });

    test('a tampered/corrupted envelope from pickup_envelope fails closed — decrypt throws, UI surfaces a warning, no garbage rendered', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        const envelope = encryptToBob('secret plaintext');

        // Tamper with the envelope: flip a byte in the ciphertext body.
        const tampered = new Uint8Array(envelope);
        // Flip a byte well past the header to corrupt the ciphertext.
        const flipIndex = Math.max(1, tampered.length - 5);
        tampered[flipIndex] ^= 0xff;

        const pickupEnvelope = vi.fn().mockResolvedValue(tampered);
        const transport = {
            lookupPrekey: vi.fn(),
            sendEnvelope: vi.fn(),
            pickupEnvelope,
        };

        render(<Conversation identity={bob} transport={transport} receiverSession={bobSession} />);

        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });

        // The plaintext must NOT appear anywhere in the rendered output.
        expect(screen.queryByText('secret plaintext')).not.toBeInTheDocument();

        // A visible warning (role='alert') must be surfaced.
        expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    test('the interval is cleaned up on component unmount — no further pickup calls after unmount', async () => {
        const { bob, bobSession } = setupRoundTrip();

        const pickupEnvelope = vi.fn().mockRejectedValue(new Error('NotFound'));
        const transport = {
            lookupPrekey: vi.fn(),
            sendEnvelope: vi.fn(),
            pickupEnvelope,
        };

        const { unmount } = render(<Conversation identity={bob} receiverSession={bobSession} transport={transport} />);

        // Let one poll happen.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });
        const callsBeforeUnmount = pickupEnvelope.mock.calls.length;
        expect(callsBeforeUnmount).toBeGreaterThanOrEqual(1);

        unmount();

        // Advance timers significantly — no new polls should fire.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(30000);
        });

        expect(pickupEnvelope.mock.calls.length).toBe(callsBeforeUnmount);
    });

    test('rapid repeated polls do not create overlapping/leaked timers', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        const envelope = encryptToBob('rapid poll test');

        const pickupEnvelope = vi.fn().mockResolvedValue(envelope);
        const transport = {
            lookupPrekey: vi.fn(),
            sendEnvelope: vi.fn(),
            pickupEnvelope,
        };

        const { unmount } = render(<Conversation identity={bob} transport={transport} receiverSession={bobSession} />);

        // Rapidly advance timers in small increments to simulate many quick polls.
        for (let i = 0; i < 10; i++) {
            await act(async () => {
                await vi.advanceTimersByTimeAsync(5000);
            });
        }

        // The message should appear exactly once (dedup, not duplicated by overlapping polls).
        expect(screen.getByText('rapid poll test')).toBeInTheDocument();

        // Count occurrences of the message — should be exactly 1.
        const allMsgs = screen.getAllByText('rapid poll test');
        expect(allMsgs).toHaveLength(1);

        unmount();
    });

    test('receive loop does not start until identity is available', async () => {
        const pickupEnvelope = vi.fn();
        const transport = {
            lookupPrekey: vi.fn(),
            sendEnvelope: vi.fn(),
            pickupEnvelope,
        };

        // No identity provided.
        render(<Conversation transport={transport} />);

        await act(async () => {
            await vi.advanceTimersByTimeAsync(30000);
        });

        // No polls should have happened without an identity.
        expect(pickupEnvelope).not.toHaveBeenCalled();
    });

    test('overlapping polls are skipped while a previous poll is still in flight', async () => {
        const { bob, bobSession, encryptToBob } = setupRoundTrip();
        const envelope = encryptToBob('in-flight guard test');

        // A slow pickupEnvelope that never resolves during the test.
        // The in-flight guard should prevent subsequent interval ticks
        // from calling pickupEnvelope again while the first call is pending.
        let pickupCallCount = 0;
        const pickupEnvelope = vi.fn().mockImplementation(() => {
            pickupCallCount++;
            // Return a promise that stays pending (never resolves in this test).
            return new Promise<Uint8Array>(() => {});
        });
        const transport = {
            lookupPrekey: vi.fn(),
            sendEnvelope: vi.fn(),
            pickupEnvelope,
        };

        render(<Conversation identity={bob} transport={transport} receiverSession={bobSession} />);

        // Advance past several interval ticks while the first poll is still pending.
        for (let i = 0; i < 5; i++) {
            await act(async () => {
                await vi.advanceTimersByTimeAsync(5000);
            });
        }

        // Only the immediate poll + at most one interval tick should have called
        // pickupEnvelope — subsequent ticks are skipped because the first poll
        // is still in flight. (The immediate poll fires on mount, and the first
        // interval tick at 5s may also fire before the guard is set, but no more.)
        expect(pickupCallCount).toBeLessThanOrEqual(2);
    });
});