// @vitest-environment jsdom
import '@testing-library/jest-dom';
import { render, screen, fireEvent, act } from '@testing-library/react';
import React from 'react';
import { describe, test, expect, vi } from 'vitest';
import { RelayConnectionPanel } from '../src/useRelayConnection';

// Mock identity and transport as in other tests
const fakeIdentity = { recipientId: 'testrecipient' } as any;

describe('RelayConnectionPanel warning logic', () => {
    const onRelayUrlChange = vi.fn();
    const renderPanel = (relayUrl: string) => {
        render(
            <RelayConnectionPanel
                status="connecting"
                error={null}
                resolvedUrl="ws://r:8000"
                relayUrl={relayUrl}
                onRelayUrlChange={onRelayUrlChange}
                onRetry={() => {}}
            />
        );
    };

    test('shows warning for ws://example.com', async () => {
        renderPanel('ws://r:8000');
        const input = screen.getByLabelText(/relay url/i);
        fireEvent.change(input, { target: { value: 'ws://example.com:8000' } });
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: /apply/i }));
        });
        expect(onRelayUrlChange).toHaveBeenCalledWith('ws://example.com:8000');
        expect(screen.getByText(/unencrypted relay connection to non-localhost host may expose metadata/i)).toBeInTheDocument();
    });

    test('does not show warning for ws://localhost', async () => {
        renderPanel('ws://r:8000');
        const input = screen.getByLabelText(/relay url/i);
        fireEvent.change(input, { target: { value: 'ws://localhost:8000' } });
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: /apply/i }));
        });
        expect(onRelayUrlChange).toHaveBeenCalledWith('ws://localhost:8000');
        expect(screen.queryByText(/unencrypted relay connection to non-localhost host may expose metadata/i)).not.toBeInTheDocument();
    });

    test('does not show warning for wss://example.com', async () => {
        renderPanel('ws://r:8000');
        const input = screen.getByLabelText(/relay url/i);
        fireEvent.change(input, { target: { value: 'wss://example.com:8000' } });
        await act(async () => {
            fireEvent.click(screen.getByRole('button', { name: /apply/i }));
        });
        expect(onRelayUrlChange).toHaveBeenCalledWith('wss://example.com:8000');
        expect(screen.queryByText(/unencrypted relay connection to non-localhost host may expose metadata/i)).not.toBeInTheDocument();
    });
});