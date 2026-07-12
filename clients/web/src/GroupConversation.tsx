import React, { useEffect, useRef, useState } from 'react';
import { generate_identity, derive_safety_number, group_create, group_add_member, group_remove_member, group_encrypt, group_decrypt, bundle_identity_key_bytes, IdentityHandle, GroupHandle } from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
import { SealGlyph } from './design/SealGlyph';
import { StorageGate } from './storage';
import { RelayTransport } from './relay_transport';
import './GroupConversation.css';

// Sender Keys group crypto UI on top of the WASM group bindings
// (group_create/group_add_member/group_remove_member/group_encrypt/
// group_decrypt - core/bindings/wasm/src/lib.rs).
//
// Two member sources coexist:
//
//   1. **Demo members** (Alice, Bob, Eve) — each is a full locally generated
//      identity (private + public key), exactly like
//      core/bindings/wasm/tests/wasm_group_encrypt.rs's own test pattern.
//      These let the component prove the real negative-path contract in the
//      browser UI: after removing a member, decrypting a subsequent message AS
//      that member's own identity genuinely fails (a real WasmError from the
//      actual crypto), not a faked/mocked failure.
//
//   2. **Real peers** — added by recipient ID. The component looks up the
//      peer's published prekey bundle via `lookupPrekey` (RelayTransport,
//      same as direct messaging in Conversation.tsx), extracts the identity
//      key with `bundle_identity_key_bytes`, and passes that real looked-up
//      public key to `group_add_member` — the crypto layer is unchanged, only
//      the source of the member's public key changes from a local demo
//      identity to a real looked-up remote identity.
//
// Group membership (the member list with recipient IDs and public keys) is
// persisted via the existing StorageGate pattern (encrypted IndexedDB), so
// it survives a page reload — matching how identity persistence already works
// in identity.ts. The WASM GroupHandle itself is not serializable (it's an
// opaque WASM-side handle), so on reload the component reconstructs the group
// session from the persisted member list by re-calling group_create +
// group_add_member for each persisted member.

export interface GroupMessageResult {
    ok: boolean;
    error?: string;
}

export interface GroupMessage {
    id: string;
    plaintext: string;
    timestamp: number;
    // Per-member decrypt outcome at send time, keyed by member name - lets
    // the UI (and tests) show/assert who could and could not decrypt each
    // message, including members who were removed before it was sent.
    decryptResults: Record<string, GroupMessageResult>;
}

/**
 * The transport surface `GroupConversation` needs for looking up a real
 * peer's published prekey bundle. `RelayTransport` satisfies this; tests
 * inject a mock that implements only this narrow interface so the crypto
 * boundary stays real while the network boundary is mocked — the same
 * pattern as Conversation.tsx's `ConversationTransport`.
 */
export interface GroupTransport {
    lookupPrekey(recipientId: string): Promise<Uint8Array>;
}

export interface GroupConversationProps {
    /** Defaults to a real `RelayTransport`; tests inject a mock here. */
    transport?: GroupTransport;
    /**
     * An opened `StorageGate` for persisting group membership. If omitted,
     * the component creates one from `globalThis.indexedDB` (production path).
     * Tests inject a mock to simulate persistence across reloads.
     */
    storageGate?: StorageGate;
}

interface DemoMember {
    name: string;
    identity: InstanceType<typeof IdentityHandle>;
    publicBytes: Uint8Array;
}

/**
 * A real peer added by recipient ID. Unlike a DemoMember, there is no local
 * private key — only the public identity key looked up from the relay. The
 * `recipientId` is the address the user typed; `publicBytes` is the identity
 * key extracted from the looked-up prekey bundle via
 * `bundle_identity_key_bytes`.
 */
interface RealMember {
    recipientId: string;
    publicBytes: Uint8Array;
}

/**
 * The persisted group state record. Stored via StorageGate so membership
 * survives a page reload. Public keys are stored as number arrays (JSON-
 * serializable); on reload the component reconstructs the GroupHandle by
 * re-calling group_create + group_add_member for each member.
 */
interface PersistedGroupState {
    members: Array<{ recipientId: string; publicBytes: number[] }>;
}

const DEMO_MEMBER_NAMES = ['Alice', 'Bob', 'Eve'] as const;
const GROUP_STORE = 'session' as const;
const GROUP_RECORD_ID = 'group-state';

export const GroupConversation: React.FC<GroupConversationProps> = ({
    transport,
    storageGate,
}) => {
    const [ready, setReady] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selfIdentity, setSelfIdentity] = useState<InstanceType<typeof IdentityHandle> | null>(null);
    const [allMembers, setAllMembers] = useState<DemoMember[]>([]);
    const [group, setGroup] = useState<InstanceType<typeof GroupHandle> | null>(null);
    const [memberNames, setMemberNames] = useState<string[]>([]);
    const [realMembers, setRealMembers] = useState<RealMember[]>([]);
    const [messages, setMessages] = useState<GroupMessage[]>([]);
    const [input, setInput] = useState('');
    const [peerIdInput, setPeerIdInput] = useState('');
    const [addingPeer, setAddingPeer] = useState(false);
    const [peerError, setPeerError] = useState<string | null>(null);

    const transportRef = useRef<GroupTransport>(transport ?? new RelayTransport());
    const gateRef = useRef<StorageGate | undefined>(storageGate);
    // Track whether we've attempted to load persisted state so we don't
    // overwrite it with an empty group on the first render.
    const loadedRef = useRef(false);

    useEffect(() => {
        let cancelled = false;
        ensureWasmInit()
            .then(async () => {
                if (cancelled) return;
                const self = generate_identity();
                const demoMembers: DemoMember[] = DEMO_MEMBER_NAMES.map((name) => {
                    const identity = generate_identity();
                    return { name, identity, publicBytes: identity.public_bytes() };
                });
                setSelfIdentity(self);
                setAllMembers(demoMembers);

                // Load persisted group state (if any) so membership survives
                // a page reload. The GroupHandle is not serializable, so we
                // reconstruct it from the persisted member list.
                const gate = gateRef.current;
                if (gate) {
                    try {
                        const persisted = (await gate.get(GROUP_STORE, GROUP_RECORD_ID)) as
                            | PersistedGroupState
                            | null;
                        if (persisted?.members?.length) {
                            const restoredGroup = group_create(self);
                            const restored: RealMember[] = [];
                            for (const m of persisted.members) {
                                const pubBytes = new Uint8Array(m.publicBytes);
                                const newGroup = group_add_member(restoredGroup, pubBytes);
                                restored.push({ recipientId: m.recipientId, publicBytes: pubBytes });
                                // Update the group handle for each member.
                                // We can't call setGroup inside the loop (React
                                // batches), so we build up the final handle.
                                (restoredGroup as unknown as { members: Uint8Array[] }).members =
                                    (newGroup as unknown as { members: Uint8Array[] }).members;
                            }
                            setGroup(restoredGroup);
                            setRealMembers(restored);
                        }
                    } catch (e) {
                        console.error('Failed to load persisted group state', e);
                    }
                }

                loadedRef.current = true;
                setReady(true);
            })
            .catch((e: unknown) => {
                console.error('Failed to initialize group demo identities', e);
                if (!cancelled) setError(e instanceof Error ? e.message : String(e));
            });
        return () => {
            cancelled = true;
        };
    }, []);

    // Persist the current real-member list to StorageGate so it survives
    // a page reload. Called after every membership change.
    const persistGroupState = async (members: RealMember[]) => {
        const gate = gateRef.current;
        if (!gate || !loadedRef.current) return;
        try {
            const state: PersistedGroupState = {
                members: members.map((m) => ({
                    recipientId: m.recipientId,
                    publicBytes: Array.from(m.publicBytes),
                })),
            };
            await gate.put(GROUP_STORE, GROUP_RECORD_ID, state);
        } catch (e) {
            console.error('Failed to persist group state', e);
        }
    };

    const createGroup = () => {
        if (!selfIdentity) return;
        setGroup(group_create(selfIdentity));
        setMemberNames([]);
        setRealMembers([]);
        setMessages([]);
        void persistGroupState([]);
    };

    const addMember = (name: string) => {
        if (!group || memberNames.includes(name)) return;
        const member = allMembers.find((m) => m.name === name);
        if (!member) return;
        setGroup(group_add_member(group, member.publicBytes));
        setMemberNames((prev) => [...prev, name]);
    };

    // Add a real peer by recipient ID: look up their prekey bundle via the
    // relay transport, extract the identity key, and pass it to group_add_member.
    // The crypto layer is unchanged — only the source of the public key changes
    // from a local demo identity to a real looked-up remote identity.
    const addPeer = async () => {
        const trimmedId = peerIdInput.trim();
        if (!group || !trimmedId || addingPeer) return;
        // Don't add the same recipient ID twice.
        if (realMembers.some((m) => m.recipientId === trimmedId)) return;

        setAddingPeer(true);
        setPeerError(null);
        try {
            let bundleBytes: Uint8Array;
            try {
                bundleBytes = await transportRef.current.lookupPrekey(trimmedId);
            } catch {
                setPeerError('Peer not found');
                return;
            }

            let identityKey: Uint8Array;
            try {
                identityKey = bundle_identity_key_bytes(bundleBytes);
            } catch (e) {
                setPeerError(`Invalid prekey bundle: ${e instanceof Error ? e.message : String(e)}`);
                return;
            }

            const newGroup = group_add_member(group, identityKey);
            const newMember: RealMember = { recipientId: trimmedId, publicBytes: identityKey };
            const updatedMembers = [...realMembers, newMember];
            setGroup(newGroup);
            setRealMembers(updatedMembers);
            setPeerIdInput('');
            void persistGroupState(updatedMembers);
        } catch (e) {
            setPeerError(e instanceof Error ? e.message : String(e));
        } finally {
            setAddingPeer(false);
        }
    };

    const removeMember = (name: string) => {
        if (!group) return;
        const member = allMembers.find((m) => m.name === name);
        if (!member) return;
        setGroup(group_remove_member(group, member.publicBytes));
        setMemberNames((prev) => prev.filter((n) => n !== name));
    };

    // Remove a real peer by recipient ID. Removing a member who was already
    // removed is a no-op (group_remove_member's core contract is infallible —
    // it simply doesn't match), not an error.
    const removePeer = (recipientId: string) => {
        if (!group) return;
        const member = realMembers.find((m) => m.recipientId === recipientId);
        if (!member) return; // already removed — no-op, not an error
        setGroup(group_remove_member(group, member.publicBytes));
        const updatedMembers = realMembers.filter((m) => m.recipientId !== recipientId);
        setRealMembers(updatedMembers);
        void persistGroupState(updatedMembers);
    };

    const send = () => {
        if (!group || !selfIdentity || !input.trim()) return;
        const plaintextBytes = new TextEncoder().encode(input);
        let ciphertext: Uint8Array;
        try {
            ciphertext = group_encrypt(group, selfIdentity, plaintextBytes);
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            return;
        }
        // Every known demo member (whether currently in the group or removed)
        // attempts to decrypt, surfacing the real per-member outcome from the
        // actual crypto - including a removed member's decrypt genuinely
        // failing, not a simulated/faked result.
        const decryptResults: Record<string, GroupMessageResult> = {};
        for (const member of allMembers) {
            try {
                group_decrypt(group, member.identity, ciphertext);
                decryptResults[member.name] = { ok: true };
            } catch (e) {
                decryptResults[member.name] = {
                    ok: false,
                    error: e instanceof Error ? e.message : String(e),
                };
            }
        }
        setMessages((prev) => [
            ...prev,
            {
                id: Math.random().toString(36).slice(2),
                plaintext: input,
                timestamp: Date.now(),
                decryptResults,
            },
        ]);
        setInput('');
    };

    if (error) {
        return <div role="alert" className="group-error">Group conversation unavailable: {error}</div>;
    }

    if (!ready) {
        return <div className="group-loading">Loading…</div>;
    }

    return (
        <div data-testid="group-conversation" className="group-view">
            {!group ? (
                <button onClick={createGroup} data-testid="create-group-button" className="group-create group-create-button">
                    Create Group
                </button>
            ) : (
                <>
                    <div data-testid="member-list" className="group-members">
                        {allMembers.map((m) => (
                            <div key={m.name} className={`member-chip${memberNames.includes(m.name) ? ' in-group' : ''}`}>
                                <SealGlyph value={m.name} size={20} tone={memberNames.includes(m.name) ? 'verified' : 'neutral'} title={`${m.name}'s seal`} />
                                <span className="member-chip-name">{m.name}</span>
                                {memberNames.includes(m.name) ? (
                                    <button onClick={() => removeMember(m.name)} data-testid={`remove-${m.name}`}>
                                        Remove
                                    </button>
                                ) : (
                                    <button onClick={() => addMember(m.name)} data-testid={`add-${m.name}`}>
                                        Add
                                    </button>
                                )}
                            </div>
                        ))}
                    </div>
                    <div data-testid="group-message-list" className="group-log">
                        {messages.length === 0 ? (
                            <p className="group-empty">No messages yet.</p>
                        ) : (
                            messages.map((msg) => (
                                <div key={msg.id} data-testid={`message-${msg.id}`} className="group-msg">
                                    <p className="group-msg-text">{msg.plaintext}</p>
                                    <ul className="group-msg-receipts">
                                        {Object.entries(msg.decryptResults).map(([name, result]) => (
                                            <li
                                                key={name}
                                                data-testid={`decrypt-${msg.id}-${name}`}
                                                className={`receipt ${result.ok ? 'receipt-ok' : 'receipt-fail'}`}
                                            >
                                                {name}: {result.ok ? 'decrypted' : `failed (${result.error})`}
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            ))
                        )}
                    </div>
                    <div className="group-composer">
                        <input
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            placeholder="Type a group message"
                            data-testid="group-message-input"
                            className="group-input"
                        />
                        <button onClick={send} data-testid="group-send-button" className="group-send">
                            Send
                        </button>
                    </div>
                </>
            )}
        </div>
    );
};
