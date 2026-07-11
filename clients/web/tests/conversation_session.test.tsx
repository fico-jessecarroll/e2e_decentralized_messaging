/** @vitest-environment jsdom */
//
// TDD tests for session establishment + encrypted send in the Conversation UI
// (core/bindings/wasm/src/lib.rs's establish_session_from_bundle / encrypt_message).
//
// Per this repo's "no mocking internal/application logic" rule (CLAUDE.md), these
// tests use the REAL wasm bindings (built via `npm run prepare-wasm`, see
// clients/web/package.json) — only the network transport boundary is mocked.
// Storage (IndexedDB) is also mocked, matching the existing convention in
// conversation.test.tsx: it's an external system boundary, and message-history
// persistence isn't what this suite is testing.

import '@testing-library/jest-dom';
import { describe, test, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

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
 * Flip a byte inside the signed-prekey signature field of a `generate_prekey_bundle`
 * blob, without touching any other field. Mirrors the exact `bundle_to_bytes` wire
 * layout documented in core/crypto/src/session.rs and the equivalent Rust test in
 * core/bindings/wasm/tests/wasm_prekey_session.rs, so this test proves specifically
 * that a *signature* failure is rejected — not an incidentally-corrupted identity key
 * or Kyber field.
 */
function tamperSignedPrekeySignature(bundleBytes: Uint8Array): Uint8Array {
    const tampered = new Uint8Array(bundleBytes);
    const dv = new DataView(tampered.buffer, tampered.byteOffset, tampered.byteLength);
    let offset = 0;
    offset += 4; // registration_id
    offset += 4; // device_id
    const identityKeyLen = dv.getUint32(offset, false);
    offset += 4 + identityKeyLen;
    offset += 4; // signed_pre_key_id
    const spkPubLen = dv.getUint32(offset, false);
    offset += 4 + spkPubLen;
    const spkSigLen = dv.getUint32(offset, false);
    offset += 4;
    if (spkSigLen === 0) throw new Error('signed-prekey signature field is empty');
    tampered[offset] ^= 0xff;
    return tampered;
}

beforeEach(() => {
    mockStoredMessages = null;
});

describe('Conversation session establishment and encrypted send', () => {
    test('sends ciphertext, not the plaintext message, to the transport', async () => {
        const alice = toIdentity(generate_identity());
        const bobIdentity = generate_identity();
        const bobSession = create_receiver_session(bobIdentity);
        const bobBundle = publish_bundle_bytes(bobSession);

        const sendEnvelope = vi.fn().mockResolvedValue(undefined);
        const transport = {
            lookupPrekey: vi.fn().mockResolvedValue(bobBundle),
            sendEnvelope,
        };

        render(<Conversation identity={alice} transport={transport} />);

        fireEvent.change(screen.getByLabelText(/recipient id/i), { target: { value: 'bob' } });
        fireEvent.change(screen.getByPlaceholderText(/type a message/i), {
            target: { value: 'hello world' },
        });
        fireEvent.click(screen.getByRole('button', { name: /send/i }));

        await waitFor(() => expect(sendEnvelope).toHaveBeenCalledTimes(1));

        const [recipientId, envelopeBytes] = sendEnvelope.mock.calls[0];
        expect(recipientId).toBe('bob');
        const plaintextBytes = new TextEncoder().encode('hello world');
        expect(envelopeBytes).not.toEqual(plaintextBytes);
        // The envelope must not even contain the plaintext as a substring of bytes —
        // a placeholder/no-op "encryption" would fail this even if lengths differed.
        const envelopeStr = Buffer.from(envelopeBytes).toString('latin1');
        expect(envelopeStr.includes('hello world')).toBe(false);
    });

    test('round trip: the real receiver session decrypts the exact original plaintext', async () => {
        const alice = toIdentity(generate_identity());
        const bobIdentity = generate_identity();
        const bobSession = create_receiver_session(bobIdentity);
        const bobBundle = publish_bundle_bytes(bobSession);

        let capturedEnvelope: Uint8Array | null = null;
        const transport = {
            lookupPrekey: vi.fn().mockResolvedValue(bobBundle),
            sendEnvelope: vi.fn().mockImplementation(async (_id: string, envelope: Uint8Array) => {
                capturedEnvelope = envelope;
            }),
        };

        render(<Conversation identity={alice} transport={transport} />);

        fireEvent.change(screen.getByLabelText(/recipient id/i), { target: { value: 'bob' } });
        fireEvent.change(screen.getByPlaceholderText(/type a message/i), {
            target: { value: 'secret message for bob' },
        });
        fireEvent.click(screen.getByRole('button', { name: /send/i }));

        await waitFor(() => expect(capturedEnvelope).not.toBeNull());

        const decrypted = decrypt_message(bobSession, capturedEnvelope!);
        expect(new TextDecoder().decode(decrypted)).toBe('secret message for bob');
    });

    test('a peer with no published bundle surfaces a clear "not found" state, no crash', async () => {
        const alice = toIdentity(generate_identity());
        const sendEnvelope = vi.fn();
        const transport = {
            lookupPrekey: vi.fn().mockRejectedValue(new Error('relay: recipient not found')),
            sendEnvelope,
        };

        render(<Conversation identity={alice} transport={transport} />);

        fireEvent.change(screen.getByLabelText(/recipient id/i), { target: { value: 'ghost' } });
        fireEvent.change(screen.getByPlaceholderText(/type a message/i), {
            target: { value: 'hello?' },
        });
        fireEvent.click(screen.getByRole('button', { name: /send/i }));

        await waitFor(() => expect(screen.getByText(/peer not found/i)).toBeInTheDocument());
        expect(sendEnvelope).not.toHaveBeenCalled();
    });

    test('a bundle with a tampered signed-prekey signature is rejected, session not established', async () => {
        const alice = toIdentity(generate_identity());
        const bobIdentity = generate_identity();
        const bobSession = create_receiver_session(bobIdentity);
        const bobBundle = publish_bundle_bytes(bobSession);
        const tamperedBundle = tamperSignedPrekeySignature(bobBundle);

        const sendEnvelope = vi.fn();
        const transport = {
            lookupPrekey: vi.fn().mockResolvedValue(tamperedBundle),
            sendEnvelope,
        };

        render(<Conversation identity={alice} transport={transport} />);

        fireEvent.change(screen.getByLabelText(/recipient id/i), { target: { value: 'bob' } });
        fireEvent.change(screen.getByPlaceholderText(/type a message/i), {
            target: { value: 'hello bob' },
        });
        fireEvent.click(screen.getByRole('button', { name: /send/i }));

        await waitFor(() =>
            expect(screen.getByText(/could not establish session/i)).toBeInTheDocument(),
        );
        expect(sendEnvelope).not.toHaveBeenCalled();

        // Sending again must retry establishment (no session was cached from the
        // failed attempt) rather than silently reusing a non-existent session.
        fireEvent.click(screen.getByRole('button', { name: /send/i }));
        await waitFor(() => expect(transport.lookupPrekey).toHaveBeenCalledTimes(2));
    });

    test('reports the real remote identity key from the looked-up bundle, not a placeholder', async () => {
        const alice = toIdentity(generate_identity());
        const bobIdentity = generate_identity();
        const bobSession = create_receiver_session(bobIdentity);
        const bobBundle = publish_bundle_bytes(bobSession);

        const transport = {
            lookupPrekey: vi.fn().mockResolvedValue(bobBundle),
            sendEnvelope: vi.fn().mockResolvedValue(undefined),
        };
        const onRemoteIdentityKeyChange = vi.fn();

        render(
            <Conversation
                identity={alice}
                transport={transport}
                onRemoteIdentityKeyChange={onRemoteIdentityKeyChange}
            />,
        );

        fireEvent.change(screen.getByLabelText(/recipient id/i), { target: { value: 'bob' } });
        fireEvent.change(screen.getByPlaceholderText(/type a message/i), {
            target: { value: 'hi' },
        });
        fireEvent.click(screen.getByRole('button', { name: /send/i }));

        await waitFor(() => {
            const call = onRemoteIdentityKeyChange.mock.calls.find(
                ([, key]) => key !== null,
            );
            expect(call).toBeDefined();
        });

        const [, remoteKey] = onRemoteIdentityKeyChange.mock.calls.find(([, key]) => key !== null)!;
        expect(remoteKey).toEqual(bobIdentity.public_bytes());
    });

    test('composer send is blocked until a peer id, a message, and an identity are all present', async () => {
        const alice = toIdentity(generate_identity());
        const transport = { lookupPrekey: vi.fn(), sendEnvelope: vi.fn() };

        const { rerender } = render(<Conversation transport={transport} />);
        // No identity at all: composer must not allow sending.
        expect(screen.getByRole('button', { name: /send/i })).toBeDisabled();

        rerender(<Conversation identity={alice} transport={transport} />);
        // Identity present, but no peer id / message yet.
        expect(screen.getByRole('button', { name: /send/i })).toBeDisabled();

        fireEvent.change(screen.getByLabelText(/recipient id/i), { target: { value: 'bob' } });
        expect(screen.getByRole('button', { name: /send/i })).toBeDisabled();

        fireEvent.change(screen.getByPlaceholderText(/type a message/i), {
            target: { value: 'hi' },
        });
        expect(screen.getByRole('button', { name: /send/i })).not.toBeDisabled();
    });
});
