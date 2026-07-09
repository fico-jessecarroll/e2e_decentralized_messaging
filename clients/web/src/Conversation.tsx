import React, { useEffect, useState } from 'react';
import { StorageGate, StoreName } from './storage';
import { getStorageKey } from './storage_key';
import { WebSocketTransport } from './websocket_transport';
import './Conversation.css';

export interface Message {
    id: string;
    body: string;
    timestamp: number; // epoch ms
    sentByMe: boolean;
}

// StoreName is a type, not a runtime object - 'messages' is a plain string
// literal that satisfies it. HISTORY_ID is the single record id this
// component uses within that store (the whole message history is one blob).
const MESSAGES_STORE: StoreName = 'messages';
const HISTORY_ID = 'history';

export const Conversation: React.FC = () => {
    const [messages, setMessages] = useState<Message[]>([]);
    const [input, setInput] = useState('');
    const [status, setStatus] = useState<string>('');
    const [transportReady, setTransportReady] = useState<boolean>(false);
    const loadedRef = React.useRef(false);

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

    // Setup websocket transport
    useEffect(() => {
        const ws = new WebSocketTransport();
        ws.onopen = () => setTransportReady(true);
        ws.onerror = () => setTransportReady(false);
        ws.onmessage = (msg: string) => {
            try {
                const parsed = JSON.parse(msg);
                if (parsed.type === 'message') {
                    const newMsg: Message = {
                        id: parsed.id,
                        body: parsed.body,
                        timestamp: parsed.timestamp,
                        sentByMe: false
                    };
                    setMessages(prev => [...prev, newMsg]);
                }
            } catch (e) {
                console.error('message parse error', e);
            }
        };
        return () => ws.close();
    }, []);

    const send = async () => {
        if (!transportReady) { setStatus('Transport disconnected'); return; }
        const id = Math.random().toString(36).substr(2, 9);
        const msg: Message = { id, body: input, timestamp: Date.now(), sentByMe: true };
        setMessages(prev => [...prev, msg]);
        try {
            await WebSocketTransport.sendMessage(input);
            setStatus('Sent');
        } catch (e) {
            console.error(e); setStatus('Failed to send');
        }
    };

    return (
        <div className="thread">
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
                />
                <button className="composer-send" onClick={send} disabled={!transportReady}>Send</button>
            </div>
            {status && <p className="thread-status">{status}</p>}
        </div>
    );
}

