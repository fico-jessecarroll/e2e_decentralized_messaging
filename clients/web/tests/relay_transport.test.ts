// @vitest-environment jsdom
import '@testing-library/jest-dom';
import { vi, describe, test, expect, beforeEach, afterEach } from 'vitest';

// ── Mock WebSocket ──────────────────────────────────────────────────────────
//
// We install a minimal WebSocket mock on `globalThis` so the transport module
// (which calls `new WebSocket(url)`) can be exercised without a real network.
// Each test configures the mock's behaviour via `mockWs.instances` and the
// helper `lastWs()`.

interface MockWsInstance {
    url: string;
    readyState: number;
    onopen: ((ev: Event) => void) | null;
    onmessage: ((ev: MessageEvent) => void) | null;
    onerror: ((ev: Event) => void) | null;
    onclose: ((ev: CloseEvent) => void) | null;
    sent: string[];
    send(data: string): void;
    close(): void;
    // test helpers
    _open(): void;
    _message(data: string): void;
    _error(): void;
    _close(): void;
}

class MockWebSocket {
    static instances: MockWsInstance[] = [];
    url: string;
    readyState = 0; // CONNECTING
    onopen: ((ev: Event) => void) | null = null;
    onmessage: ((ev: MessageEvent) => void) | null = null;
    onerror: ((ev: Event) => void) | null = null;
    onclose: ((ev: CloseEvent) => void) | null = null;
    sent: string[] = [];

    static CLEAR() { MockWebSocket.instances = []; }

    constructor(url: string) {
        this.url = url;
        MockWebSocket.instances.push(this as unknown as MockWsInstance);
    }
    send(data: string) { this.sent.push(data); }
    close() { this.readyState = 3; }

    _open() {
        this.readyState = 1;
        if (this.onopen) this.onopen(new Event('open'));
    }
    _message(data: string) {
        if (this.onmessage) this.onmessage(new MessageEvent('message', { data }));
    }
    _error() {
        this.readyState = 3;
        if (this.onerror) this.onerror(new Event('error'));
    }
    _close() {
        this.readyState = 3;
        if (this.onclose) this.onclose(new CloseEvent('close'));
    }
}

function lastWs(): MockWsInstance {
    const inst = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    if (!inst) throw new Error('no WebSocket instance created');
    return inst;
}

// Install the mock before importing the module under test.
(globalThis as any).WebSocket = MockWebSocket;

import {
    RelayTransport,
    solvePow,
    parseChallengeWire,
    RelayError,
    getRelayWsUrl,
} from '../src/relay_transport';

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Build a valid challenge wire (context_len BE || context || nonce(16) || difficulty BE). */
function makeChallengeWire(context: Uint8Array, nonce: Uint8Array, difficulty: number): Uint8Array {
    const len = context.length;
    const wire = new Uint8Array(2 + len + 16 + 4);
    const dv = new DataView(wire.buffer);
    dv.setUint16(0, len, false); // big-endian
    wire.set(context, 2);
    wire.set(nonce, 2 + len);
    dv.setUint32(2 + len + 16, difficulty, false); // big-endian
    return wire;
}

function bytesToBase64(bytes: Uint8Array): string {
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Config / URL tests ───────────────────────────────────────────────────────

describe('relay URL configuration', () => {
    beforeEach(() => {
        localStorage.clear();
        MockWebSocket.CLEAR();
    });

    test('reads URL from localStorage override when present', () => {
        localStorage.setItem('relayWsUrl', 'ws://override.example:9000');
        expect(getRelayWsUrl()).toBe('ws://override.example:9000');
    });

    test('falls back to Vite env var when no localStorage override', () => {
        // VITE_RELAY_WS_URL is injected at build time via import.meta.env.
        // We can't easily set it per-test, but we can verify the function
        // does not return the old hardcoded value.
        const url = getRelayWsUrl();
        expect(url).not.toBe('ws://localhost:8000');
    });

    test('hardcoded ws://localhost:8000 is not present in the source', async () => {
        // Regression guard: the old hardcoded URL must be gone from the module.
        const src = await import('../src/relay_transport.ts?raw');
        expect(src.default).not.toContain("'ws://localhost:8000'");
        expect(src.default).not.toContain('"ws://localhost:8000"');
    });
});

// ── PoW solver tests ─────────────────────────────────────────────────────────

describe('PoW solver', () => {
    test('parseChallengeWire decodes context, nonce, and difficulty', () => {
        const context = new TextEncoder().encode('ws-relay-v1');
        const nonce = new Uint8Array(16).fill(7);
        const wire = makeChallengeWire(context, nonce, 20);
        const parsed = parseChallengeWire(wire);
        expect(parsed.context).toEqual(context);
        expect(parsed.nonce).toEqual(nonce);
        expect(parsed.difficulty).toBe(20);
    });

    test('solvePow produces a solution that meets the difficulty', () => {
        const context = new TextEncoder().encode('ws-relay-v1');
        const nonce = new Uint8Array(16).fill(3);
        const wire = makeChallengeWire(context, nonce, 20);
        const parsed = parseChallengeWire(wire);
        const solution = solvePow(parsed);
        // Verify: SHA-256(context || nonce || solution) has 20 leading zero bits.
        const preimage = new Uint8Array(context.length + nonce.length);
        preimage.set(context, 0);
        preimage.set(nonce, context.length);
        const full = new Uint8Array(preimage.length + solution.length);
        full.set(preimage, 0);
        full.set(solution, preimage.length);
        // Use Web Crypto SHA-256
        // (jsdom provides crypto.subtle)
        // We verify synchronously via a manual check using a small helper.
        const digest = sha256Sync(full);
        // 20 bits = 2 full zero bytes + 4 bits of the third byte zero
        expect(digest[0]).toBe(0);
        expect(digest[1]).toBe(0);
        expect(digest[2] & 0xf0).toBe(0);
    });

    test('solvePow solution is 8 bytes (u64 little-endian counter)', () => {
        const context = new TextEncoder().encode('ws-relay-v1');
        const nonce = new Uint8Array(16).fill(1);
        const wire = makeChallengeWire(context, nonce, 8);
        const parsed = parseChallengeWire(wire);
        const solution = solvePow(parsed);
        expect(solution.length).toBe(8);
    });
});

// Synchronous SHA-256 for test verification (avoids async crypto.subtle).
function sha256Sync(data: Uint8Array): Uint8Array {
    // Use Node's crypto in the test environment.
    const { createHash } = require('crypto');
    const h = createHash('sha256');
    h.update(Buffer.from(data));
    return new Uint8Array(h.digest());
}

// ── Outbound JSON shape tests ────────────────────────────────────────────────

describe('outbound request JSON shapes', () => {
    beforeEach(() => {
        localStorage.clear();
        MockWebSocket.CLEAR();
    });

    test('challenge op sends exact JSON shape', async () => {
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
        const transport = new RelayTransport();
        const challengePromise = transport.requestChallenge('alice');

        // The WebSocket is created lazily on first op; wait for it.
        await vi.waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThanOrEqual(1));
        const ws = lastWs();
        ws._open();

        // The first sent message must be the challenge request.
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        const sent = JSON.parse(ws.sent[0]);
        expect(sent).toEqual({ op: 'challenge', recipient_id: 'alice' });

        // Respond with a challenge so the promise resolves.
        const context = new TextEncoder().encode('ws-relay-v1');
        const nonce = new Uint8Array(16).fill(1);
        const wire = makeChallengeWire(context, nonce, 20);
        ws._message(JSON.stringify({
            ok: true,
            challenge: bytesToBase64(wire),
            challenge_id: bytesToHex(nonce),
        }));

        await challengePromise;
        transport.close();
    });

    test('publish_prekey op sends exact JSON shape', async () => {
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
        const transport = new RelayTransport();
        const ws = lastWs();
        ws._open();

        const bundle = new Uint8Array([1, 2, 3, 4, 5]);
        const publishPromise = transport.publishPrekey('bob', bundle);

        // First message: challenge request
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        expect(JSON.parse(ws.sent[0])).toEqual({ op: 'challenge', recipient_id: 'bob' });

        // Respond with challenge
        const context = new TextEncoder().encode('ws-relay-v1');
        const nonce = new Uint8Array(16).fill(2);
        const wire = makeChallengeWire(context, nonce, 20);
        ws._message(JSON.stringify({
            ok: true,
            challenge: bytesToBase64(wire),
            challenge_id: bytesToHex(nonce),
        }));

        // Second message: publish_prekey request
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(2));
        const sent2 = JSON.parse(ws.sent[1]);
        expect(sent2.op).toBe('publish_prekey');
        expect(sent2.recipient_id).toBe('bob');
        expect(sent2.bundle).toBe(bytesToBase64(bundle));
        expect(sent2.challenge_id).toBe(bytesToHex(nonce));
        // pow_solution must be base64 of 8 bytes
        const solBytes = base64ToBytes(sent2.pow_solution);
        expect(solBytes.length).toBe(8);

        // Respond ok
        ws._message(JSON.stringify({ ok: true }));
        await publishPromise;
        transport.close();
    });

    test('lookup_prekey op sends exact JSON shape', async () => {
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
        const transport = new RelayTransport();
        const ws = lastWs();
        ws._open();

        const lookupPromise = transport.lookupPrekey('carol');

        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        expect(JSON.parse(ws.sent[0])).toEqual({ op: 'lookup_prekey', recipient_id: 'carol' });

        ws._message(JSON.stringify({ ok: true, bundle: bytesToBase64(new Uint8Array([9, 9, 9])) }));
        const result = await lookupPromise;
        expect(result).toEqual(new Uint8Array([9, 9, 9]));
        transport.close();
    });

    test('send_envelope op sends exact JSON shape', async () => {
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
        const transport = new RelayTransport();
        const ws = lastWs();
        ws._open();

        const envelope = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        const sendPromise = transport.sendEnvelope('dave', envelope);

        // First: challenge
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        expect(JSON.parse(ws.sent[0])).toEqual({ op: 'challenge', recipient_id: 'dave' });

        const context = new TextEncoder().encode('ws-relay-v1');
        const nonce = new Uint8Array(16).fill(4);
        const wire = makeChallengeWire(context, nonce, 20);
        ws._message(JSON.stringify({
            ok: true,
            challenge: bytesToBase64(wire),
            challenge_id: bytesToHex(nonce),
        }));

        // Second: send_envelope
        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(2));
        const sent2 = JSON.parse(ws.sent[1]);
        expect(sent2.op).toBe('send_envelope');
        expect(sent2.recipient_id).toBe('dave');
        expect(sent2.envelope).toBe(bytesToBase64(envelope));
        expect(sent2.challenge_id).toBe(bytesToHex(nonce));
        const solBytes = base64ToBytes(sent2.pow_solution);
        expect(solBytes.length).toBe(8);

        ws._message(JSON.stringify({ ok: true }));
        await sendPromise;
        transport.close();
    });

    test('pickup_envelope op sends exact JSON shape', async () => {
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
        const transport = new RelayTransport();
        const ws = lastWs();
        ws._open();

        const pickupPromise = transport.pickupEnvelope('eve');

        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        expect(JSON.parse(ws.sent[0])).toEqual({ op: 'pickup_envelope', recipient_id: 'eve' });

        ws._message(JSON.stringify({ ok: true, envelope: bytesToBase64(new Uint8Array([0xaa, 0xbb])) }));
        const result = await pickupPromise;
        expect(result).toEqual(new Uint8Array([0xaa, 0xbb]));
        transport.close();
    });
});

// ── Error / negative cases ───────────────────────────────────────────────────

describe('error handling', () => {
    beforeEach(() => {
        localStorage.clear();
        MockWebSocket.CLEAR();
    });

    test('ok:false response propagates as a typed RelayError', async () => {
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
        const transport = new RelayTransport();
        const ws = lastWs();
        ws._open();

        const lookupPromise = transport.lookupPrekey('frank');

        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        ws._message(JSON.stringify({ ok: false, error: 'NotFound' }));

        await expect(lookupPromise).rejects.toBeInstanceOf(RelayError);
        await expect(lookupPromise).rejects.toMatchObject({ message: 'NotFound' });
        transport.close();
    });

    test('malformed JSON response fails closed with a caught error', async () => {
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
        const transport = new RelayTransport();
        const ws = lastWs();
        ws._open();

        const lookupPromise = transport.lookupPrekey('grace');

        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        ws._message('not valid json {{{');

        await expect(lookupPromise).rejects.toBeInstanceOf(RelayError);
        transport.close();
    });

    test('connection error surfaces a visible error (not a silent hang)', async () => {
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
        const transport = new RelayTransport();
        const ws = lastWs();
        ws._open();

        const lookupPromise = transport.lookupPrekey('heidi');

        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        // Simulate connection drop / error
        ws._error();
        ws._close();

        await expect(lookupPromise).rejects.toBeInstanceOf(RelayError);
        transport.close();
    });

    test('unreachable relay URL surfaces error on connect', async () => {
        localStorage.setItem('relayWsUrl', 'ws://unreachable.invalid:9999');
        const transport = new RelayTransport();
        const ws = lastWs();
        // Simulate connection failure (onerror fires before onopen)
        ws._error();

        const lookupPromise = transport.lookupPrekey('ivan');

        await expect(lookupPromise).rejects.toBeInstanceOf(RelayError);
        transport.close();
    });

    test('ok:false on challenge propagates as typed error for publishPrekey', async () => {
        localStorage.setItem('relayWsUrl', 'ws://test:8000');
        const transport = new RelayTransport();
        const ws = lastWs();
        ws._open();

        const publishPromise = transport.publishPrekey('judy', new Uint8Array([1]));

        await vi.waitFor(() => expect(ws.sent.length).toBeGreaterThanOrEqual(1));
        ws._message(JSON.stringify({ ok: false, error: 'RateLimitExceeded' }));

        await expect(publishPromise).rejects.toBeInstanceOf(RelayError);
        await expect(publishPromise).rejects.toMatchObject({ message: 'RateLimitExceeded' });
        transport.close();
    });
});