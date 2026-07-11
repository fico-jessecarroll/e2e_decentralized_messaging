// @vitest-environment jsdom
//
// Regression test for the session-sharing bug (code review finding #1):
//
// `publishPrekeyForIdentity` must return the SAME receiver session whose
// bundle was published to the relay. A sender who fetches that bundle and
// encrypts to it must produce envelopes that the returned session can
// decrypt. If `publishPrekeyForIdentity` used `generate_prekey_bundle`
// (which drops the session) or if the receive loop created an independent
// session via `create_receiver_session`, the two sessions would be
// cryptographically distinct and every real inbound message would fail
// to decrypt — surfacing a false-positive tamper warning.
//
// This test uses REAL wasm crypto (no mocking at the crypto boundary).
// Only the transport is mocked to capture the published bundle.

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
import { publishPrekeyForIdentity, type PersistedIdentity } from '../src/identity';
import {
    generate_identity,
    establish_session_from_bundle,
    encrypt_message,
    type IdentityHandle,
    type SessionHandle,
} from '../../../core/bindings/wasm/pkg/index.js';

/** Minimal PersistedIdentity-shaped wrapper around a real wasm IdentityHandle. */
function toIdentity(handle: InstanceType<typeof IdentityHandle>): PersistedIdentity {
    return {
        handle,
        publicBytes: handle.public_bytes(),
        recipientId: 'test-recipient',
    };
}

beforeEach(() => {
    mockStoredMessages = null;
    vi.useFakeTimers();
});

afterEach(() => {
    vi.useRealTimers();
});

describe('receive loop integration: published bundle ↔ receiver session', () => {
    test('a message encrypted to the bundle from publishPrekeyForIdentity is decrypted by the session it returns', async () => {
        // ── Setup: real identity, real publishPrekeyForIdentity ──
        const bobIdentity = generate_identity();
        const bob = toIdentity(bobIdentity);

        // Capture the bundle that publishPrekeyForIdentity publishes.
        let publishedBundle: Uint8Array | null = null;
        const mockTransport = {
            publishPrekey: vi.fn(async (_id: string, bundle: Uint8Array) => {
                publishedBundle = bundle;
            }),
        };

        // This is the real integration call — it creates a receiver session,
        // publishes its bundle, and returns the session.
        const receiverSession: InstanceType<typeof SessionHandle> =
            await publishPrekeyForIdentity(bob, mockTransport);

        expect(publishedBundle).not.toBeNull();
        expect(mockTransport.publishPrekey).toHaveBeenCalledTimes(1);

        // ── Simulate a peer (Alice) who fetches the bundle and encrypts ──
        const aliceIdentity = generate_identity();
        const aliceSession = establish_session_from_bundle(aliceIdentity, publishedBundle!);
        const plaintext = 'integration: hello from alice!';
        const envelope = encrypt_message(
            aliceSession,
            new TextEncoder().encode(plaintext),
        );

        // ── Wire the receiver session into Conversation's receive loop ──
        const pickupEnvelope = vi.fn().mockResolvedValue(envelope);
        const conversationTransport = {
            lookupPrekey: vi.fn(),
            sendEnvelope: vi.fn(),
            pickupEnvelope,
        };

        render(
            <Conversation
                identity={bob}
                receiverSession={receiverSession}
                transport={conversationTransport}
            />,
        );

        // Advance timers to trigger a poll.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });

        // The decrypted plaintext must appear — proving the published bundle
        // and the receiver session share key material.
        expect(screen.getByText(plaintext)).toBeInTheDocument();

        // No tamper warning — this is a legitimate message.
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('receiverSession arriving after identity still decrypts (no stale-closure bug)', async () => {
        // Regression: App.tsx sets `identity` first, then `receiverSession` after
        // the async prekey publish completes. The receive-loop effect depends on
        // `[identity]`, so its closure captures `receiverSession === undefined`
        // at creation time. Without a ref mirroring the prop, every poll bails
        // out early and legitimate messages are never decrypted.
        const bobIdentity = generate_identity();
        const bob = toIdentity(bobIdentity);

        let publishedBundle: Uint8Array | null = null;
        const mockTransport = {
            publishPrekey: vi.fn(async (_id: string, bundle: Uint8Array) => {
                publishedBundle = bundle;
            }),
        };
        const receiverSession = await publishPrekeyForIdentity(bob, mockTransport);

        // Simulate a peer encrypting to the published bundle.
        const aliceIdentity = generate_identity();
        const aliceSession = establish_session_from_bundle(aliceIdentity, publishedBundle!);
        const plaintext = 'stale-closure: hello after delay!';
        const envelope = encrypt_message(
            aliceSession,
            new TextEncoder().encode(plaintext),
        );

        const pickupEnvelope = vi.fn().mockResolvedValue(envelope);
        const conversationTransport = {
            lookupPrekey: vi.fn(),
            sendEnvelope: vi.fn(),
            pickupEnvelope,
        };

        // Render with identity but NO receiverSession yet (mirrors App.tsx
        // where identity loads before the async publish completes).
        const { rerender } = render(
            <Conversation
                identity={bob}
                transport={conversationTransport}
            />,
        );

        // Advance timers — poll should bail (no session yet), no crash.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });
        expect(screen.queryByText(plaintext)).not.toBeInTheDocument();

        // Now receiverSession arrives (publish completed) — re-render.
        rerender(
            <Conversation
                identity={bob}
                receiverSession={receiverSession}
                transport={conversationTransport}
            />,
        );

        // Next poll should decrypt successfully despite the effect not re-running.
        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });

        expect(screen.getByText(plaintext)).toBeInTheDocument();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
});