import React, { useEffect, useState } from 'react';
import { StorageGate, StoreName } from './storage';
import { WebSocketTransport } from './websocket_transport';

export interface Message {
    id: string;
    body: string;
    timestamp: number; // epoch ms
    sentByMe: boolean;
}

const MESSAGES_STORE: StoreName = 'messages';
const HISTORY_ID = 'history';

export const Conversation: React.FC = () => {
    const [messages, setMessages] = useState<Message[]>([]);
    const [input, setInput] = useState('');
    const [transportReady, setTransportReady] = useState<boolean>(false);
    const loadedRef = React.useRef(false);

    // Load history
    useEffect(() => {
        const gate = new StorageGate({ indexedDB: (globalThis as any).indexedDB, keyBytes: new Uint8Array(32) });
        gate.open().then(async () => {
            try {
                const stored = await gate.get(MESSAGES_STORE, HISTORY_ID);
                if (stored) setMessages(stored as Message[]);
                loadedRef.current = true;
            } catch (e) { console.error('storage load error', e); }
        }).catch(err => console.error('storage init failed', err));
    }, []);

    // Persist messages
    useEffect(() => {
        if (!loadedRef.current) return;
        const gate = new StorageGate({ indexedDB: (globalThis as any).indexedDB, keyBytes: new Uint8Array(32) });
        gate.open().then(() => gate.put(MESSAGES_STORE, HISTORY_ID, messages)).catch(console.error);
    }, [messages]);

    // WebSocket
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
            } catch (_) {}
        };
        return () => ws.close();
    }, []);

    const sendMessage = async () => {
        if (!input.trim() || !transportReady) return;
        const newMsg: Message = { id: crypto.randomUUID(), body: input, timestamp: Date.now(), sentByMe: true };
        setMessages(prev => [...prev, newMsg]);
        setInput('');
        try {
            await WebSocketTransport.sendMessage(input);
        } catch (e) {
            console.error('Failed to send', e);
        }
    };

    return (
        <div>
            <h2>Conversation</h2>
            <ul data-testid="message-list">
                {messages.length === 0 ? (
                    <li>No messages yet</li>
                ) : (
                    messages.map(m => (
                        <li key={m.id}>{m.body} ({m.sentByMe ? 'me' : 'them'})</li>
                    ))
                )}
            </ul>
            <input
                value={input}
                onChange={e => setInput(e.target.value)}
                disabled={!transportReady}
                placeholder="Type a message"
            />
            <button onClick={sendMessage} disabled={!transportReady || !input.trim()}>Send</button>
        </div>
    );
};