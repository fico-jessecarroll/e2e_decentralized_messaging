// @vitest-environment jsdom
import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Mutable fixture the mock reads at call time - each test sets it before
// rendering. A `vi.mock` factory is hoisted and file-scoped (not scoped to
// whichever test happens to be running), so a second `vi.mock` call inside a
// test body would silently override this mock for every test in the file,
// not just the one it's written in; this shared variable is the correct way
// to vary the mocked return value per test.
let mockStoredMessages: unknown = null;

// Mock StorageGate matching the REAL API: get(store, id) / put(store, id,
// value), both already (de)serializing JSON internally - no .set() method
// exists on the real class.
vi.mock('../src/storage', () => {
    class MockStorageGate {
        async open() { return Promise.resolve(); }
        async get(_store: string, _id: string) { return mockStoredMessages; }
        async put(_store: string, _id: string, value: unknown) { mockStoredMessages = value; }
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
        mockStoredMessages = null;
        render(<Conversation />);
        await waitFor(() => {
            expect(screen.getByText(/no messages yet/i)).toBeInTheDocument();
        });
    });

    test('renders loaded messages', async () => {
        mockStoredMessages = [
            { id: '1', body: 'hello', timestamp: 1700000000, sentByMe: true },
            { id: '2', body: 'hi back', timestamp: 1700000005, sentByMe: false },
        ];
        render(<Conversation />);
        await waitFor(() => {
            expect(screen.getByText(/hello/)).toBeInTheDocument();
            expect(screen.getByText(/hi back/)).toBeInTheDocument();
        });
    });
});
