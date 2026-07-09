// Unit tests for the real relay WS wire protocol client.
//
// These tests use a mocked WebSocket (following the pattern in
// conversation.test.tsx) to assert exact outbound JSON shapes for each op,
// verify the PoW solver interoperates with the relay's algorithm, and cover
// negative/boundary cases (error propagation, malformed responses, unreachable
// relay, config-driven URL).

import { vi, describe, test, expect, beforeEach, afterEach } from 'vitest';
import {
  RelayWebSocketTransport,
  solvePow,
  parseChallengeWire,
  getRelayWsUrl,
  RelayError,
} from '../src/relay_websocket_transport';

// ── Mock WebSocket ───────────────────────────────────────────────────────────

// A minimal mock that captures sent messages and lets tests drive responses.
class MockWebSocket {
  static instances: MockWebSocket[] = [];
  static last(): MockWebSocket {
    return MockWebSocket.instances[MockWebSocket.instances.length - 1];
  }

  url: string;
  sent: string[] = [];
  onopen: ((ev: Event) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  readyState = 0; // CONNECTING

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  send(data: string) {
    this.sent.push(data);
  }

  close() {
    this.readyState = 3;
  }

  // Test helpers
  fireOpen() {
    this.readyState = 1;
    this.onopen?.(new Event('open'));
  }

  fireMessage(data: string) {
    this.onmessage?.({ data });
  }

  fireError() {
    this.onerror?.(new Event('error'));
  }
}

// Replace the global WebSocket with our mock.
vi.stubGlobal('WebSocket', MockWebSocket);

// Stub import.meta.env for VITE_RELAY_WS_URL
vi.stubEnv('VITE_RELAY_WS_URL', 'ws://test-relay:9999');

// Stub localStorage
const localStorageStore: Record<string, string> = {};
vi.stubGlobal('localStorage', {
  getItem: (key: string) => localStorageStore[key] ?? null,
  setItem: (key: string, value: string) => { localStorageStore[key] = value; },
  removeItem: (key: string) => { delete localStorageStore[key]; },
  clear: () => { for (const k of Object.keys(localStorageStore)) delete localStorageStore[k]; },
});

beforeEach(() => {
  MockWebSocket.instances = [];
  for (const k of Object.keys(localStorageStore)) delete localStorageStore[k];
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ── Config / URL tests ───────────────────────────────────────────────────────

describe('getRelayWsUrl', () => {
  test('reads VITE_RELAY_WS_URL from env', () => {
    expect(getRelayWsUrl()).toBe('ws://test-relay:9999');
  });

  test('localStorage override takes precedence over env', () => {
    localStorageStore['relayWsUrl'] = 'ws://override:7777';
    expect(getRelayWsUrl()).toBe('ws://override:7777');
  });

  test('falls back to default when neither env nor localStorage is set', () => {
    vi.stubEnv('VITE_RELAY_WS_URL', '');
    delete localStorageStore['relayWsUrl'];
    // Default should NOT be ws://localhost:8000 — it should be a documented default
    const url = getRelayWsUrl();
    expect(url).not.toBe('ws://localhost:8000');
    expect(url).toMatch(/^wss?:\/\//);
  });

  test('hardcoded ws://localhost:8000 is not the default', () => {
    // The old hardcoded URL must not appear as the default.
    vi.stubEnv('VITE_RELAY_WS_URL', '');
    delete localStorageStore['relayWsUrl'];
    const url = getRelayWsUrl();
    expect(url).not.toContain('localhost:8000');
  });
});

// ── PoW solver tests ─────────────────────────────────────────────────────────

describe('solvePow', () => {
  test('produces a solution that verifies against the relay algorithm', async () => {
    // Build a challenge wire matching relay's Challenge::to_wire():
    // context_len(2 BE) || context || nonce(16) || difficulty(4 BE)
    const context = new TextEncoder().encode('ws-relay-v1');
    const nonce = new Uint8Array(16); // all zeros for determinism
    const difficulty = 20;

    const wire = buildChallengeWire(context, nonce, difficulty);
    const solution = await solvePow(wire);

    // Solution must be 8 bytes (u64 little-endian, matching relay's counter.to_le_bytes())
    expect(solution.length).toBe(8);

    // Verify using the same algorithm as relay/src/pow/mod.rs::meets_difficulty
    const preimage = new Uint8Array(context.length + nonce.length);
    preimage.set(context, 0);
    preimage.set(nonce, context.length);
    expect(meetsDifficulty(preimage, solution, difficulty)).toBe(true);
  });

  test('rejects difficulty out of range (0)', async () => {
    const context = new TextEncoder().encode('ws-relay-v1');
    const nonce = new Uint8Array(16);
    const wire = buildChallengeWire(context, nonce, 0);
    await expect(solvePow(wire)).rejects.toThrow(RelayError);
  });

  test('rejects difficulty out of range (> 256)', async () => {
    const context = new TextEncoder().encode('ws-relay-v1');
    const nonce = new Uint8Array(16);
    const wire = buildChallengeWire(context, nonce, 300);
    await expect(solvePow(wire)).rejects.toThrow(RelayError);
  });

  test('rejects malformed challenge wire (too short)', async () => {
    const shortWire = new Uint8Array(3); // way too short
    await expect(solvePow(shortWire)).rejects.toThrow(RelayError);
  });

  test('has an iteration cap and rejects instead of looping forever', async () => {
    // Use a difficulty that requires more iterations than a small cap.
    const context = new TextEncoder().encode('ws-relay-v1');
    const nonce = new Uint8Array(16);
    const wire = buildChallengeWire(context, nonce, 40);
    // Use a very small cap so the test completes quickly
    await expect(solvePow(wire, 100)).rejects.toThrow(RelayError);
  });
});

// ── Wire protocol shape tests ────────────────────────────────────────────────

describe('RelayWebSocketTransport outbound JSON shapes', () => {
  test('challenge request shape', async () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();
    ws.fireOpen();

    const challengePromise = transport.requestChallenge('alice-123');

    // Assert exact outbound JSON
    const sent = JSON.parse(ws.sent[0]);
    expect(sent).toEqual({
      op: 'challenge',
      recipient_id: 'alice-123',
    });

    // Respond with a valid challenge
    const context = new TextEncoder().encode('ws-relay-v1');
    const nonce = new Uint8Array(16);
    const wire = buildChallengeWire(context, nonce, 20);
    const challengeB64 = base64Encode(wire);
    const challengeIdHex = bytesToHex(nonce);

    ws.fireMessage(JSON.stringify({
      ok: true,
      challenge: challengeB64,
      challenge_id: challengeIdHex,
    }));

    const result = await challengePromise;
    expect(result.challengeId).toBe(challengeIdHex);
    expect(result.challengeWire).toEqual(wire);
  });

  test('publish_prekey request shape', async () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();
    ws.fireOpen();

    // Get a challenge first
    const challengePromise = transport.requestChallenge('bob-456');
    const context = new TextEncoder().encode('ws-relay-v1');
    const nonce = new Uint8Array(16);
    const wire = buildChallengeWire(context, nonce, 20);
    ws.fireMessage(JSON.stringify({
      ok: true,
      challenge: base64Encode(wire),
      challenge_id: bytesToHex(nonce),
    }));
    const challenge = await challengePromise;

    // Solve PoW
    const solution = await solvePow(wire);
    const solutionB64 = base64Encode(solution);

    // Publish prekey
    const bundle = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);
    const publishPromise = transport.publishPrekey('bob-456', bundle, challenge, solution);

    const sent = JSON.parse(ws.sent[1]);
    expect(sent).toEqual({
      op: 'publish_prekey',
      recipient_id: 'bob-456',
      bundle: base64Encode(bundle),
      challenge_id: challenge.challengeId,
      pow_solution: solutionB64,
    });

    ws.fireMessage(JSON.stringify({ ok: true }));
    await publishPromise;
  });

  test('lookup_prekey request shape', async () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();
    ws.fireOpen();

    const bundle = new Uint8Array([0x11, 0x22, 0x33]);
    const lookupPromise = transport.lookupPrekey('carol-789');

    const sent = JSON.parse(ws.sent[0]);
    expect(sent).toEqual({
      op: 'lookup_prekey',
      recipient_id: 'carol-789',
    });

    ws.fireMessage(JSON.stringify({
      ok: true,
      bundle: base64Encode(bundle),
    }));

    const result = await lookupPromise;
    expect(result).toEqual(bundle);
  });

  test('send_envelope request shape', async () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();
    ws.fireOpen();

    // Get challenge
    const challengePromise = transport.requestChallenge('dave-000');
    const context = new TextEncoder().encode('ws-relay-v1');
    const nonce = new Uint8Array(16);
    const wire = buildChallengeWire(context, nonce, 20);
    ws.fireMessage(JSON.stringify({
      ok: true,
      challenge: base64Encode(wire),
      challenge_id: bytesToHex(nonce),
    }));
    const challenge = await challengePromise;

    const solution = await solvePow(wire);
    const envelope = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
    const sendPromise = transport.sendEnvelope('dave-000', envelope, challenge, solution);

    const sent = JSON.parse(ws.sent[1]);
    expect(sent).toEqual({
      op: 'send_envelope',
      recipient_id: 'dave-000',
      envelope: base64Encode(envelope),
      challenge_id: challenge.challengeId,
      pow_solution: base64Encode(solution),
    });

    ws.fireMessage(JSON.stringify({ ok: true }));
    await sendPromise;
  });

  test('pickup_envelope request shape', async () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();
    ws.fireOpen();

    const envelope = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
    const pickupPromise = transport.pickupEnvelope('eve-111');

    const sent = JSON.parse(ws.sent[0]);
    expect(sent).toEqual({
      op: 'pickup_envelope',
      recipient_id: 'eve-111',
    });

    ws.fireMessage(JSON.stringify({
      ok: true,
      envelope: base64Encode(envelope),
    }));

    const result = await pickupPromise;
    expect(result).toEqual(envelope);
  });
});

// ── Negative / boundary tests ────────────────────────────────────────────────

describe('RelayWebSocketTransport error handling', () => {
  test('{ok:false,error} response propagates as RelayError', async () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();
    ws.fireOpen();

    const lookupPromise = transport.lookupPrekey('nobody');
    ws.fireMessage(JSON.stringify({ ok: false, error: 'NotFound' }));

    await expect(lookupPromise).rejects.toThrow(RelayError);
    await expect(lookupPromise).rejects.toMatchObject({ message: 'NotFound' });
  });

  test('malformed JSON response fails closed with caught error', async () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();
    ws.fireOpen();

    const lookupPromise = transport.lookupPrekey('nobody');
    ws.fireMessage('this is not json {{{');

    await expect(lookupPromise).rejects.toThrow(); // caught, not unhandled
  });

  test('unreachable relay surfaces visible error, not silent hang', async () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();

    const lookupPromise = transport.lookupPrekey('nobody');

    // Simulate connection failure
    ws.fireError();

    await expect(lookupPromise).rejects.toThrow(RelayError);
  });

  test('connection timeout surfaces error', async () => {
    const transport = new RelayWebSocketTransport('ws://nowhere:1', 100); // 100ms timeout
    const ws = MockWebSocket.last();

    const lookupPromise = transport.lookupPrekey('nobody');

    // Don't fire open — let it time out
    await expect(lookupPromise).rejects.toThrow(RelayError);
  });

  test('ok:false with PowFailed error propagates', async () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();
    ws.fireOpen();

    const challengePromise = transport.requestChallenge('alice');
    const context = new TextEncoder().encode('ws-relay-v1');
    const nonce = new Uint8Array(16);
    const wire = buildChallengeWire(context, nonce, 20);
    ws.fireMessage(JSON.stringify({
      ok: true,
      challenge: base64Encode(wire),
      challenge_id: bytesToHex(nonce),
    }));
    const challenge = await challengePromise;

    // Use a bogus solution
    const bogusSolution = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    const publishPromise = transport.publishPrekey('alice', new Uint8Array([1]), challenge, bogusSolution);

    ws.fireMessage(JSON.stringify({ ok: false, error: 'PowFailed: invalid solution (20 bits)' }));

    await expect(publishPromise).rejects.toThrow(RelayError);
    await expect(publishPromise).rejects.toMatchObject({
      message: expect.stringContaining('PowFailed'),
    });
  });

  test('subsequent request after connection error also fails (no silent hang)', async () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();

    const lookupPromise = transport.lookupPrekey('nobody');
    ws.fireError();

    await expect(lookupPromise).rejects.toThrow(RelayError);

    // A second request must also reject, not hang.
    await expect(transport.lookupPrekey('nobody')).rejects.toThrow(RelayError);
  });

  test('close() closes the underlying WebSocket', () => {
    const transport = new RelayWebSocketTransport();
    const ws = MockWebSocket.last();
    ws.fireOpen();

    transport.close();
    expect(ws.readyState).toBe(3); // CLOSED
  });
});

// ── Hardcoded URL removal tests ──────────────────────────────────────────────

describe('hardcoded ws://localhost:8000 is removed from source', () => {
  test('websocket_transport.ts no longer contains the hardcoded URL', async () => {
    // Read the source file and assert the old hardcoded string is gone
    // (only the relay_websocket_transport.ts comment referencing it should remain).
    const fs = await import('node:fs');
    const path = await import('node:path');
    const wsTransportSrc = fs.readFileSync(
      path.resolve(__dirname, '../src/websocket_transport.ts'),
      'utf-8',
    );
    expect(wsTransportSrc).not.toContain('ws://localhost:8000');
    // It should import getRelayWsUrl from the new transport
    expect(wsTransportSrc).toContain('getRelayWsUrl');
  });
});

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Build a challenge wire matching relay's Challenge::to_wire(). */
function buildChallengeWire(
  context: Uint8Array,
  nonce: Uint8Array,
  difficulty: number,
): Uint8Array {
  const out = new Uint8Array(2 + context.length + 16 + 4);
  const view = new DataView(out.buffer);
  view.setUint16(0, context.length, false); // big-endian
  out.set(context, 2);
  out.set(nonce, 2 + context.length);
  view.setUint32(2 + context.length + 16, difficulty, false); // big-endian
  return out;
}

/** Mirror of relay/src/pow/mod.rs::meets_difficulty for test verification. */
function meetsDifficulty(preimage: Uint8Array, suffix: Uint8Array, difficulty: number): boolean {
  const data = new Uint8Array(preimage.length + suffix.length);
  data.set(preimage, 0);
  data.set(suffix, preimage.length);

  // Use Node's crypto for SHA-256 in the test environment
  const { createHash } = require('node:crypto');
  const digest = createHash('sha256').update(Buffer.from(data)).digest();

  const fullBytes = Math.floor(difficulty / 8);
  for (let i = 0; i < fullBytes; i++) {
    if (digest[i] !== 0) return false;
  }
  const extraBits = difficulty % 8;
  if (extraBits === 0) return true;
  const mask = 0xFF << (8 - extraBits);
  return (digest[fullBytes] & mask) === 0;
}

/** Base64 encode (standard, with padding) — matches relay's b64_encode. */
function base64Encode(buf: Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Convert bytes to hex string. */
function bytesToHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}