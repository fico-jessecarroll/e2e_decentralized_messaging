export class WebSocketTransport {
    private ws: WebSocket | null = null;
    onopen?: () => void;
    onerror?: (e: Event) => void;
    onmessage?: (msg: string) => void;

    constructor(url: string = 'ws://localhost:8000') {
        this.ws = new WebSocket(url);
        this.ws.onopen = () => { if (this.onopen) this.onopen(); };
        this.ws.onerror = e => { if (this.onerror) this.onerror(e); };
        this.ws.onmessage = m => { if (this.onmessage) this.onmessage(m.data as string); };
    }

    static async sendMessage(body: string): Promise<void> {
        // For simplicity, open a temporary connection for each message.
        const ws = new WebSocket('ws://localhost:8000');
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
