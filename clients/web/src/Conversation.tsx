import React, { useEffect, useRef, useState } from 'react';
import {
    establish_session_from_bundle,
    encrypt_message,
    bundle_identity_key_bytes,
    SessionHandle,
} from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
import { StorageGate, StoreName } from './storage';
import { getStorageKey } from './storage_key';
import { RelayTransport } from './relay_transport';
import type { PersistedIdentity } from './identity';
import './Conversation.css';

export interface Message {
    id: string;
    body: string;
    timestamp: number; // epoch ms
    sentByMe: boolean;
}

/**
 * The transport surface `Conversation` needs for session establishment and sending: look up a
 * peer's published prekey bundle, and hand off an encrypted envelope for delivery. `RelayTransport`
 * satisfies this; tests inject a mock that implements only this narrow interface so the crypto
 * boundary stays real while the network boundary is mocked.
 */
export interface ConversationTransport {
    lookupPrekey(recipientId: string): Promise<Uint8Array>;
    sendEnvelope(recipientId: string, envelope: Uint8Array): Promise<void>;
}

export interface ConversationProps {
    /** The local persisted identity. Sending is blocked in the UI until this is available. */
    identity?: PersistedIdentity;
    /** Defaults to a real `RelayTransport`; tests inject a mock here. */
    transport?: ConversationTransport;
    /**
     * Called whenever the active peer's remote identity key becomes known (a session was just
     * established) or becomes unknown again (the peer changed and no session exists yet for the
     * new peer). The caller (App.tsx) uses this to feed the *real* remote key into
     * SafetyNumberVerification instead of a placeholder.
     */
    onRemoteIdentityKeyChange?: (peerId: string, remoteIdentityKey: Uint8Array | null) => void;
}

// StoreName is a type, not a runtime object - 'messages' is a plain string
// literal that satisfies it. HISTORY_ID is the single record id this
// component uses within that store (the whole message history is one blob).
const MESSAGES_STORE: StoreName = 'messages';
const HISTORY_ID = 'history';

interface PeerSession {
    session: InstanceType<typeof SessionHandle>;
    remoteIdentityKey: Uint8Array;
}

/** Extract a WasmError's message, falling back to a generic description for non-WASM errors. */
function describeError(e: unknown): string {
    if (e && typeof e === 'object' && 'message' in e) {
        return String((e as { message: unknown }).message);
    }
    return e instanceof Error ? e.message : String(e);
}

export const Conversation: React.FC<ConversationProps> = ({
    identity,
    transport,
    onRemoteIdentityKeyChange,
}) => {
    const [messages, setMessages] = useState<Message[]>([]);
    const [peerId, setPeerId] = useState('');
    const [input, setInput] = useState('');
    const [status, setStatus] = useState<string>('');
    const [sending, setSending] = useState(false);
    const loadedRef = React.useRef(false);
    // SessionHandle is a WASM-side opaque handle with no serialization support (see
    // core/bindings/wasm/src/lib.rs's SessionHandle doc comment) - it is kept in this
    // module-instance ref for the component's lifetime only. A page reload loses all
    // in-flight session state and the next send re-establishes from scratch.
    const sessionsRef = useRef<Map<string, PeerSession>>(new Map());
    const transportRef = useRef<ConversationTransport>(transport ?? new RelayTransport());

    // Load history from storage on mount
    useEffect(() => {
        const gate = new StorageGate({ indexedDB: (globalThis as any).indexedDB, keyBytes: getStorageKey() });
        gate.open().then(async () => {
            try {
                // StorageGate.get already returns the parsed value (or null).
                const stored = await gate.get(MESSAGES_STORE, HISTORY_ID);
                if (stored) setMessages(stored as Message[]);
                loadedRef.current = true;
            } catch (e) {
                console.error('storage load error', e);
            }
        }).catch(err => console.error('storage init failed', err));
    }, []);

    // Persist messages whenever they change
    useEffect(() => {
        if (!loadedRef.current) return;
        const gate = new StorageGate({ indexedDB: (globalThis as any).indexedDB, keyBytes: getStorageKey() });
        // StorageGate.put already serializes the value - don't stringify twice.
        gate.open().then(() => gate.put(MESSAGES_STORE, HISTORY_ID, messages)).catch(console.error);
    }, [messages]);

    // Report the active peer's remote identity key (or null, if no session exists for them
    // yet) whenever the peer id changes, so SafetyNumberVerification always reflects the
    // currently selected conversation rather than a stale or unrelated key.
    useEffect(() => {
        const existing = sessionsRef.current.get(peerId.trim());
        onRemoteIdentityKeyChange?.(peerId, existing ? existing.remoteIdentityKey : null);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [peerId]);

    const send = async () => {
        const trimmedPeerId = peerId.trim();
        const trimmedInput = input.trim();
        if (!identity || !trimmedPeerId || !trimmedInput || sending) return;

        setSending(true);
        setStatus('');
        try {
            let peerSession = sessionsRef.current.get(trimmedPeerId);

            if (!peerSession) {
                setStatus('Looking up peer…');
                await ensureWasmInit();

                let bundleBytes: Uint8Array;
                try {
                    bundleBytes = await transportRef.current.lookupPrekey(trimmedPeerId);
                } catch {
                    setStatus('Peer not found');
                    return;
                }

                let remoteIdentityKey: Uint8Array;
                try {
                    remoteIdentityKey = bundle_identity_key_bytes(bundleBytes);
                } catch (e) {
                    setStatus(`Invalid prekey bundle: ${describeError(e)}`);
                    return;
                }

                // bundle_identity_key_bytes does NOT verify the bundle's signatures (see its doc
                // comment in core/bindings/wasm/src/lib.rs) - only establish_session_from_bundle
                // does that. So remoteIdentityKey is held locally but not reported upward via
                // onRemoteIdentityKeyChange (and the session is not cached) until establishment
                // below succeeds - the safety number a user compares out-of-band must only ever
                // reflect a signature-verified identity key, never an attacker-supplied one from
                // a tampered bundle.
                let session: InstanceType<typeof SessionHandle>;
                try {
                    session = establish_session_from_bundle(
                        identity.handle as unknown as Parameters<typeof establish_session_from_bundle>[0],
                        bundleBytes,
                    );
                } catch (e) {
                    setStatus(`Could not establish session: ${describeError(e)}`);
                    return;
                }

                peerSession = { session, remoteIdentityKey };
                sessionsRef.current.set(trimmedPeerId, peerSession);
                onRemoteIdentityKeyChange?.(trimmedPeerId, remoteIdentityKey);
            }

            const plaintextBytes = new TextEncoder().encode(trimmedInput);
            let envelope: Uint8Array;
            try {
                envelope = encrypt_message(peerSession.session, plaintextBytes);
            } catch (e) {
                setStatus(`Encrypt failed: ${describeError(e)}`);
                return;
            }

            await transportRef.current.sendEnvelope(trimmedPeerId, envelope);

            const msg: Message = {
                id: Math.random().toString(36).substr(2, 9),
                body: trimmedInput,
                timestamp: Date.now(),
                sentByMe: true,
            };
            setMessages(prev => [...prev, msg]);
            setInput('');
            setStatus('Sent');
        } catch (e) {
            setStatus(describeError(e) || 'Failed to send');
        } finally {
            setSending(false);
        }
    };

    const canSend = !!identity && !!peerId.trim() && !!input.trim() && !sending;

    return (
        <div className="thread">
            <div className="composer-peer">
                <input
                    id="conversation-peer-id"
                    className="composer-peer-input"
                    type="text"
                    value={peerId}
                    onChange={e => setPeerId(e.target.value)}
                    placeholder="Recipient ID"
                    aria-label="Recipient ID"
                />
            </div>
            <div className="thread-log">
                {messages.length===0 ? (<p className="thread-empty">No messages yet.</p>) : (
                    messages.map(m => (
                        <div key={m.id} className={`msg-row${m.sentByMe ? ' mine' : ''}`}>
                            <div className="msg-bubble">
                                {m.body}
                                <small className="msg-time">
                                    {m.sentByMe ? 'You' : 'Them'} · {new Date(m.timestamp).toLocaleString()}
                                </small>
                            </div>
                        </div>
                    ))
                )}
            </div>
            <div className="composer">
                <input
                    className="composer-input"
                    type="text"
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    placeholder="Type a message"
                    disabled={!identity}
                />
                <button className="composer-send" onClick={send} disabled={!canSend}>Send</button>
            </div>
            {status && <p className="thread-status">{status}</p>}
        </div>
    );
}
