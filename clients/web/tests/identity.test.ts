// @vitest-environment node
//
// Tests for the persistent-identity module: load-or-generate identity,
// persist across "reload" (two StorageGate instances against the same
// IndexedDB), publish exactly one prekey bundle on a fresh client, and
// derive a stable recipient ID from the identity's public bytes.
//
// The WASM module is mocked so this suite doesn't require a built pkg/.
// The mock simulates the real contract: generate_identity returns an
// IdentityHandle whose private_bytes/public_bytes round-trip through
// identity_from_bytes.

import fakeIndexedDB from 'fake-indexeddb';
(globalThis as any).indexedDB = fakeIndexedDB;
import { describe, test, expect, vi, beforeEach } from 'vitest';

// ── WASM mock ───────────────────────────────────────────────────────────────
//
// We simulate the real WASM contract with an in-JS keypair so that
// private_bytes → identity_from_bytes round-trips, and public_bytes is
// stable across reload.  Each generated identity gets a unique random
// 32-byte private key; the public key is derived deterministically so
// the same private bytes always produce the same public bytes.

const keypairs: { priv: Uint8Array; pub: Uint8Array }[] = [];

function makeKeypair() {
    const priv = new Uint8Array(32);
    for (let i = 0; i < 32; i++) priv[i] = Math.floor(Math.random() * 256);
    // Derive a deterministic "public" from the private so round-trips work.
    // This is NOT real crypto — it's a test fixture that preserves the
    // invariant "same private bytes → same public bytes".
    const pub = new Uint8Array(33);
    pub[0] = 5; // compressed-curve prefix byte
    for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
    return { priv, pub };
}

// Track how many times generate_identity was called so we can assert
// "fresh client generates exactly once" and "reload does not regenerate".
let generateIdentityCalls = 0;
let generatePrekeyBundleCalls = 0;

vi.mock('../../../core/bindings/wasm/pkg/index.js', () => ({
    generate_identity: () => {
        generateIdentityCalls++;
        const kp = makeKeypair();
        keypairs.push(kp);
        return {
            public_bytes: () => kp.pub.slice(),
            private_bytes: () => kp.priv.slice(),
        };
    },
    identity_from_bytes: (bytes: Uint8Array) => {
        // Find the keypair whose private bytes match, or reconstruct.
        const match = keypairs.find((kp) =>
            kp.priv.every((b, i) => b === bytes[i]),
        );
        if (match) {
            return {
                public_bytes: () => match.pub.slice(),
                private_bytes: () => match.priv.slice(),
            };
        }
        // Reconstruct from the raw private bytes (simulates real deserialization).
        const priv = bytes.slice();
        const pub = new Uint8Array(33);
        pub[0] = 5;
        for (let i = 0; i < 32; i++) pub[i + 1] = priv[i] ^ 0x5a;
        return {
            public_bytes: () => pub,
            private_bytes: () => priv,
        };
    },
    generate_prekey_bundle: (_identity: unknown) => {
        generatePrekeyBundleCalls++;
        return new Uint8Array([1, 2, 3, 4, 5]); // fake bundle bytes
    },
    create_receiver_session: (_identity: unknown) => ({ _mock: 'receiver-session' }),
    publish_bundle_bytes: (_session: unknown) => new Uint8Array([1, 2, 3, 4, 5]),
    derive_safety_number: () => '00000 00000',
}));
vi.mock('../src/wasm_init', () => ({ ensureWasmInit: async () => {} }));

import { StorageGate } from '../src/storage';
import { loadOrGenerateIdentity, recipientIdFromPublicBytes, publishPrekeyForIdentity } from '../src/identity';

const KEY_BYTES = new Uint8Array(32);

// ── Helpers ─────────────────────────────────────────────────────────────────

/** A fresh StorageGate against the same (shared) fake IndexedDB. */
function newGate(): StorageGate {
    return new StorageGate({ indexedDB: fakeIndexedDB, keyBytes: KEY_BYTES });
}

/** Reset call counters and wipe the fake IndexedDB between tests. */
beforeEach(async () => {
    generateIdentityCalls = 0;
    generatePrekeyBundleCalls = 0;
    keypairs.length = 0;
    // Delete all databases so the next open() re-creates cleanly.
    // fake-indexeddb persists across tests within a file, so we must
    // explicitly tear down between tests to avoid cross-contamination.
    // `_databases` is a Map<string, Database> on the fake indexedDB object.
    const dbs = (fakeIndexedDB as any)._databases;
    if (dbs && typeof dbs.clear === 'function') {
        dbs.clear();
    } else if (dbs) {
        for (const name of Object.keys(dbs)) {
            delete dbs[name];
        }
    }
});

// ── Tests ───────────────────────────────────────────────────────────────────

describe('persistent identity', () => {
    test('identity persists across two StorageGate instances (simulated reload)', async () => {
        // First "session": generate and persist.
        const gate1 = newGate();
        await gate1.open();
        const id1 = await loadOrGenerateIdentity(gate1);
        const pub1 = id1.publicBytes;
        const recipientId1 = id1.recipientId;

        expect(generateIdentityCalls).toBe(1);

        // Second "session": a brand-new StorageGate against the same IndexedDB.
        const gate2 = newGate();
        await gate2.open();
        const id2 = await loadOrGenerateIdentity(gate2);
        const pub2 = id2.publicBytes;
        const recipientId2 = id2.recipientId;

        // Reload must NOT regenerate — same public bytes and recipient ID.
        expect(generateIdentityCalls).toBe(1);
        expect(pub2).toEqual(pub1);
        expect(recipientId2).toBe(recipientId1);
    });

    test('a fresh client publishes exactly one prekey bundle', async () => {
        const gate = newGate();
        await gate.open();
        const id = await loadOrGenerateIdentity(gate);

        const mockTransport = {
            publishPrekey: vi.fn().mockResolvedValue(undefined),
        };

        await publishPrekeyForIdentity(id, mockTransport);

        // publish_prekey called exactly once, with the freshly generated bundle.
        expect(mockTransport.publishPrekey).toHaveBeenCalledTimes(1);
        const [recipientIdArg, bundleArg] = mockTransport.publishPrekey.mock.calls[0];
        expect(recipientIdArg).toBe(id.recipientId);
        expect(bundleArg).toBeInstanceOf(Uint8Array);
        expect(bundleArg.length).toBeGreaterThan(0);
        // The bundle came from publish_bundle_bytes (mocked above), not
        // generate_prekey_bundle — the old path dropped the session.
        expect(generatePrekeyBundleCalls).toBe(0);
    });

    test('recipient ID rendered matches the persisted identity public bytes', async () => {
        const gate = newGate();
        await gate.open();
        const id = await loadOrGenerateIdentity(gate);

        // recipientIdFromPublicBytes must match the identity's recipientId.
        const expected = recipientIdFromPublicBytes(id.publicBytes);
        expect(id.recipientId).toBe(expected);

        // Reload and confirm the recipient ID is still derived from the same
        // public bytes (not a new identity).
        const gate2 = newGate();
        await gate2.open();
        const id2 = await loadOrGenerateIdentity(gate2);
        expect(recipientIdFromPublicBytes(id2.publicBytes)).toBe(expected);
    });

    test('IndexedDB unavailable fails closed (no silent fallback to unpersisted identity)', async () => {
        const gate = new StorageGate({ indexedDB: undefined, keyBytes: KEY_BYTES });
        await expect(gate.open()).rejects.toThrow(/storage unavailable/i);
    });

    test('corrupt stored identity (wrong-length bytes) fails closed', async () => {
        // Write a corrupt identity record directly, then try to load.
        const gate = newGate();
        await gate.open();
        await gate.put('identity', 'self', { privateBytes: [1, 2, 3], publicBytes: [1, 2] });

        await expect(loadOrGenerateIdentity(gate)).rejects.toThrow();
    });

    test('publish_prekey failure surfaces a visible error state', async () => {
        const gate = newGate();
        await gate.open();
        const id = await loadOrGenerateIdentity(gate);

        const failingTransport = {
            publishPrekey: vi.fn().mockRejectedValue(new Error('relay unreachable')),
        };

        await expect(publishPrekeyForIdentity(id, failingTransport)).rejects.toThrow(
            /relay unreachable/i,
        );
    });
});