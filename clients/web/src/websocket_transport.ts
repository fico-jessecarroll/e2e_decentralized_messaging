import { getRelayWsUrl } from './relay_transport';

/**
 * Legacy thin WebSocket wrapper used by the Conversation UI component.
 *
 * The real relay wire protocol lives in `relay_transport.ts` (`RelayTransport`).
 * This module is retained only because `Conversation.tsx` still references it;
 * it now sources its relay URL from the same configurable resolver so that no
 * hardcoded `ws://localhost:8000` literal remains anywhere in the codebase.
 */
export class WebSocketTransport {
    private ws: WebSocket | null = null;
    onopen?: () => void;
    onerror?: (e: Event) => void;
    onmessage?: (msg: string) => void;

    constructor(url?: string) {
        this.ws = new WebSocket(url ?? getRelayWsUrl());
        this.ws.onopen = () => { if (this.onopen) this.onopen(); };
        this.ws.onerror = e => { if (this.onerror) this.onerror(e); };
        this.ws.onmessage = m => { if (this.onmessage) this.onmessage(m.data as string); };
    }

    static async sendMessage(body: string): Promise<void> {
        // For simplicity, open a temporary connection for each message.
        const ws = new WebSocket(getRelayWsUrl());
        return new Promise((resolve, reject) => {
            ws.onopen = () => {
                ws.send(JSON.stringify({ type: 'message', body }));
                resolve();
                ws.close();
            };
            ws.onerror = e => { reject(e); };
        });
    }

    close() {
        this.ws?.close();
    }
}
