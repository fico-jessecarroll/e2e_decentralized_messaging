import React, { useEffect, useState } from 'react';
import { StorageGate, StoreName } from './storage';
import { WebSocketTransport } from './websocket_transport';

export interface Message {
    id: string;
    body: string;
    timestamp: number; // epoch ms
    sentByMe: boolean;
}

const STORAGE_KEY = 'messages';

export const Conversation: React.FC = () => {
    const [messages, setMessages] = useState<Message[]>([]);
    const [input, setInput] = useState('');
    const [status, setStatus] = useState<string>('');
    const [transportReady, setTransportReady] = useState<boolean>(false);

    // Load history from storage on mount
    useEffect(() => {
        const gate = new StorageGate({ indexedDB: (globalThis as any).indexedDB, keyBytes: new Uint8Array(32) });
        gate.open().then(async () => {
            try {
                const stored = await gate.get(StoreName.messages);
                if (stored) setMessages(JSON.parse(stored));
            } catch (e) {
                console.error('storage load error', e);
            }
        }).catch(err => console.error('storage init failed', err));
    }, []);

    // Persist messages whenever they change
    useEffect(() => {
        const gate = new StorageGate({ indexedDB: (globalThis as any).indexedDB, keyBytes: new Uint8Array(32) });
        gate.open().then(() => gate.set(StoreName.messages, JSON.stringify(messages))).catch(console.error);
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
        <div style={{display:'flex', flexDirection:'column', height:'100vh'}}>
            <h2>Conversation</h2>
            <div style={{flex:1, overflowY:'auto', border:'1px solid #ccc', padding:'0.5rem'}}>
                {messages.length===0 ? (<p>No messages yet.</p>) : (
                    messages.map(m => (
                        <div key={m.id} style={{marginBottom: '0.5rem'}}>
                            <strong>{m.sentByMe ? 'You' : 'Them'}:</strong> {m.body}
                            <br/>
                            <small>{new Date(m.timestamp).toLocaleString()}</small>
                        </div>
                    ))
                )}
            </div>
            <div style={{display:'flex', gap:'0.5rem', padding:'0.5rem'}}>
                <input
                    type="text"
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    placeholder="Type a message"
                    style={{flex:1}}
                />
                <button onClick={send} disabled={!transportReady}>Send</button>
            </div>
            {status && <p>{status}</p>}
        </div>
    );
};n(() => gate.set(StoreName.messages, JSON.stringify(messages))).catch(console.error);
    }, [messages]);

    return (
        <div style={{display:'flex', flexDirection:'column', height:'100vh'}}>
            <h2>Conversation</h2>
            <div style={{flex:1, overflowY:'auto', border:'1px solid #ccc', padding:'0.5rem'}}>
                {messages.length===0 ? (<p>No messages yet.</p>) : (
                    messages.map(m=>(
                        <div key={m.id} style={{marginBottom:'0.5rem', textAlign:m.sentByMe?'right':'left'}}>
                            <span>{m.body}</span><br/>
                            <small>{new Date(m.timestamp).toLocaleString()}</small>
                        </div>
                    ))
                )}
            </div>
            <div style={{display:'flex', marginTop:'0.5rem'}}>
                <input type="text" value={input} onChange={e=>setInput(e.target.value)} style={{flex:1}}/>
                <button onClick={send}>Send</button>
            </div>
            <p>{status}</p>
        </div>
    );
};
