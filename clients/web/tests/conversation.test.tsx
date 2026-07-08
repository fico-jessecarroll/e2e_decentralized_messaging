import { vi } from 'vitest';

// Mock StorageGate to return preset messages on load
vi.mock('../src/storage', () => {
    const original = vi.importActual('../src/storage');
    class MockStorageGate extends original.StorageGate {
        async open() { return Promise.resolve(); }
        async get(name) {
            if (name === 'messages') {
                return JSON.stringify([
                    { id: '1', body: 'hello', timestamp: 1700000000, sentByMe: true },
                    { id: '2', body: 'hi back', timestamp: 1700000005, sentByMe: false }
                ]);
            }
            return null;
        }
        async set(name, value) { return Promise.resolve(); }
    }
    return { StorageGate: MockStorageGate };
});

// Mock WebSocketTransport to simulate ready state and message receiving
vi.mock('../src/websocket_transport', () => {
    class MockWebSocketTransport {
        onopen?: () => void;
        onerror?: (e: Event) => void;
        onmessage?: (msg: string) => void;
        constructor() { if (this.onopen) this.onopen(); }
        static async sendMessage(body: string) { return Promise.resolve(); }
        close() {}
    }
    return { WebSocketTransport: MockWebSocketTransport };
});

import { render, screen, waitFor } from '@testing-library/react';
import { Conversation } from '../src/Conversation';

describe('Conversation component', () => {
    test('renders empty state when no messages stored', async () => {
        // Override mock to return null for get
        vi.mock('../src/storage', () => ({ StorageGate: class { async open(){}; async get(){return null;} } }));
        render(<Conversation />);
        await waitFor(() => {
            expect(screen.getByText(/no messages yet/i)).toBeInTheDocument();
        });
    });

    test('renders loaded messages', async () => {
        render(<Conversation />);
        await waitFor(() => {
            expect(screen.getByText(/hello/)).toBeInTheDocument();
            expect(screen.getByText(/hi back/)).toBeInTheDocument();
        });
    });
});
