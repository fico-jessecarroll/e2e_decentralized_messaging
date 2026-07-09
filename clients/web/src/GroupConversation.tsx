import React, { useEffect, useState } from 'react';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';

// Sender Keys group crypto UI on top of the WASM group bindings
// (group_create/group_add_member/group_remove_member/group_encrypt/
// group_decrypt - core/bindings/wasm/src/lib.rs). There is no real
// multi-device networking yet (Conversation.tsx is likewise a single-
// session demo), so this component simulates other members locally: each
// demo member is a full generated identity (private + public key), exactly
// like core/bindings/wasm/tests/wasm_group_encrypt.rs's own test pattern,
// standing in for what would otherwise be a separate device/session. This
// lets the component prove the real negative-path contract in the browser
// UI: after removing a member, decrypting a subsequent message AS that
// member's own identity genuinely fails (a real WasmError from the actual
// crypto), not a faked/mocked failure.
//
// Group membership and message history are in-memory only for this story
// (not persisted via IndexedDB/StorageGate) - this story's scope is UI
// wiring to the WASM crypto, not storage; persistence can be added as a
// follow-up the same way Conversation.tsx's own persistence was its own
// dedicated story.

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

interface DemoMember {
    name: string;
    identity: InstanceType<typeof wasm.IdentityHandle>;
    publicBytes: Uint8Array;
}

const DEMO_MEMBER_NAMES = ['Alice', 'Bob', 'Eve'] as const;

export const GroupConversation: React.FC = () => {
    const [ready, setReady] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selfIdentity, setSelfIdentity] = useState<InstanceType<typeof wasm.IdentityHandle> | null>(null);
    const [allMembers, setAllMembers] = useState<DemoMember[]>([]);
    const [group, setGroup] = useState<InstanceType<typeof wasm.GroupHandle> | null>(null);
    const [memberNames, setMemberNames] = useState<string[]>([]);
    const [messages, setMessages] = useState<GroupMessage[]>([]);
    const [input, setInput] = useState('');

    useEffect(() => {
        let cancelled = false;
        ensureWasmInit()
            .then(() => {
                if (cancelled) return;
                const self = wasm.generate_identity();
                const demoMembers: DemoMember[] = DEMO_MEMBER_NAMES.map((name) => {
                    const identity = wasm.generate_identity();
                    return { name, identity, publicBytes: identity.public_bytes() };
                });
                setSelfIdentity(self);
                setAllMembers(demoMembers);
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

    const createGroup = () => {
        if (!selfIdentity) return;
        setGroup(wasm.group_create(selfIdentity));
        setMemberNames([]);
        setMessages([]);
    };

    const addMember = (name: string) => {
        if (!group || memberNames.includes(name)) return;
        const member = allMembers.find((m) => m.name === name);
        if (!member) return;
        setGroup(wasm.group_add_member(group, member.publicBytes));
        setMemberNames((prev) => [...prev, name]);
    };

    const removeMember = (name: string) => {
        if (!group) return;
        const member = allMembers.find((m) => m.name === name);
        if (!member) return;
        setGroup(wasm.group_remove_member(group, member.publicBytes));
        setMemberNames((prev) => prev.filter((n) => n !== name));
    };

    const send = () => {
        if (!group || !selfIdentity || !input.trim()) return;
        const plaintextBytes = new TextEncoder().encode(input);
        let ciphertext: Uint8Array;
        try {
            ciphertext = wasm.group_encrypt(group, selfIdentity, plaintextBytes);
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
                wasm.group_decrypt(group, member.identity, ciphertext);
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
        return <div role="alert">Group conversation unavailable: {error}</div>;
    }

    if (!ready) {
        return <div>Loading…</div>;
    }

    return (
        <div data-testid="group-conversation">
            <h2>Group Conversation</h2>
            {!group ? (
                <button onClick={createGroup} data-testid="create-group-button">
                    Create Group
                </button>
            ) : (
                <>
                    <div data-testid="member-list">
                        <h3>Members</h3>
                        {allMembers.map((m) => (
                            <div key={m.name}>
                                {m.name}{' '}
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
                    <div data-testid="group-message-list">
                        {messages.length === 0 ? (
                            <p>No messages yet.</p>
                        ) : (
                            messages.map((msg) => (
                                <div key={msg.id} data-testid={`message-${msg.id}`}>
                                    <p>{msg.plaintext}</p>
                                    <ul>
                                        {Object.entries(msg.decryptResults).map(([name, result]) => (
                                            <li key={name} data-testid={`decrypt-${msg.id}-${name}`}>
                                                {name}: {result.ok ? 'decrypted' : `failed (${result.error})`}
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            ))
                        )}
                    </div>
                    <input
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        placeholder="Type a group message"
                        data-testid="group-message-input"
                    />
                    <button onClick={send} data-testid="group-send-button">
                        Send
                    </button>
                </>
            )}
        </div>
    );
};
