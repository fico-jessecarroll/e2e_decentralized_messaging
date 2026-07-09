/**
 * @vitest-environment jsdom
 *
 * Tests for the QR device-linking flow (web client).
 *
 * Covers:
 *  - Linking payload encode → decode round-trip (via WASM bindings).
 *  - Safety-number confirmation step: matching safety numbers allow the link
 *    to proceed; mismatched safety numbers abort the link (fail closed).
 *  - Negative/boundary: malformed QR payload is rejected (fail closed).
 *  - Negative/boundary: expired/tampered payload (wrong byte length) is rejected.
 *
 * The encode/decode logic lives in the Rust core (`crypto::device_qr`) and is
 * exposed to JS via WASM bindings (`encode_device_qr` / `decode_device_qr`).
 * The safety-number derivation uses `derive_safety_number`. The web-side
 * orchestration (state machine + confirmation gate) lives in
 * `src/device_linking.ts`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from '../src/wasm_init';
import {
    encodeLinkingPayload,
    decodeLinkingPayload,
    confirmSafetyNumber,
    type LinkingState,
} from '../src/device_linking';

beforeAll(async () => {
    await ensureWasmInit();
});

async function genPublicBytes(): Promise<Uint8Array> {
    const identity = wasm.generate_identity();
    return identity.public_bytes();
}

// ---------------------------------------------------------------------------
// Encode / decode round-trip
// ---------------------------------------------------------------------------

describe('QR linking payload encode/decode round-trip', () => {
    it('round-trips a valid identity key through encode → decode', async () => {
        const keyBytes = await genPublicBytes();
        const payload = encodeLinkingPayload(keyBytes);
        const decoded = decodeLinkingPayload(payload);
        expect(decoded).toEqual(new Uint8Array(keyBytes));
    });

    it('produces a hex string payload', async () => {
        const keyBytes = await genPublicBytes();
        const payload = encodeLinkingPayload(keyBytes);
        expect(payload).toMatch(/^[0-9a-f]+$/);
        expect(payload.length).toBe(66); // 33 bytes × 2 hex chars
    });
});

// ---------------------------------------------------------------------------
// Malformed / expired / tampered payloads — fail closed
// ---------------------------------------------------------------------------

describe('malformed QR payload rejection (fail closed)', () => {
    it('rejects a payload with non-hex characters', () => {
        expect(() => decodeLinkingPayload('zzzzzz')).toThrow();
    });

    it('rejects a payload with odd length (truncated hex)', () => {
        expect(() => decodeLinkingPayload('abc')).toThrow();
    });

    it('rejects a payload that decodes to the wrong byte length (tampered)', () => {
        // 32 bytes (64 hex chars) — not a valid 33-byte identity key
        expect(() => decodeLinkingPayload('00'.repeat(32))).toThrow();
    });

    it('rejects an empty payload', () => {
        expect(() => decodeLinkingPayload('')).toThrow();
    });

    it('rejects a payload with valid hex but wrong length (34 bytes)', () => {
        expect(() => decodeLinkingPayload('05' + 'ab'.repeat(33))).toThrow();
    });
});

// ---------------------------------------------------------------------------
// Safety-number confirmation step
// ---------------------------------------------------------------------------

describe('safety-number confirmation', () => {
    it('allows the link when the displayed safety number matches the expected', async () => {
        const localKey = await genPublicBytes();
        const remoteKey = await genPublicBytes();
        const expected = wasm.derive_safety_number(localKey, remoteKey);

        const result = confirmSafetyNumber(localKey, remoteKey, expected);
        expect(result.confirmed).toBe(true);
    });

    it('aborts the link when the safety number does not match (fail closed)', async () => {
        const localKey = await genPublicBytes();
        const remoteKey = await genPublicBytes();
        const wrong = '00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 000';

        const result = confirmSafetyNumber(localKey, remoteKey, wrong);
        expect(result.confirmed).toBe(false);
        expect(result.error).toBeDefined();
    });

    it('is symmetric — swapping key order yields the same safety number', async () => {
        const localKey = await genPublicBytes();
        const remoteKey = await genPublicBytes();
        const sn1 = wasm.derive_safety_number(localKey, remoteKey);
        const sn2 = wasm.derive_safety_number(remoteKey, localKey);
        expect(sn1).toBe(sn2);
    });
});

// ---------------------------------------------------------------------------
// Linking state machine — end-to-end orchestration
// ---------------------------------------------------------------------------

describe('linking state machine', () => {
    it('transitions: idle → displaying → confirming → linked on match', async () => {
        const newDeviceKey = await genPublicBytes();
        const primaryKey = await genPublicBytes();

        // Step 1: new device encodes its key as a QR payload
        const payload = encodeLinkingPayload(newDeviceKey);

        // Step 2: primary device decodes the scanned payload
        const decodedKey = decodeLinkingPayload(payload);
        expect(decodedKey).toEqual(new Uint8Array(newDeviceKey));

        // Step 3: primary derives the safety number for display
        const expectedSn = wasm.derive_safety_number(primaryKey, decodedKey);

        // Step 4: user confirms the safety number matches
        const confirmation = confirmSafetyNumber(primaryKey, decodedKey, expectedSn);
        expect(confirmation.confirmed).toBe(true);
        expect(confirmation.safetyNumber).toBe(expectedSn);
    });

    it('aborts on mismatched safety number — does not reach linked state', async () => {
        const newDeviceKey = await genPublicBytes();
        const primaryKey = await genPublicBytes();

        const payload = encodeLinkingPayload(newDeviceKey);
        const decodedKey = decodeLinkingPayload(payload);

        // User enters a wrong safety number
        const confirmation = confirmSafetyNumber(primaryKey, decodedKey, 'wrong-number');
        expect(confirmation.confirmed).toBe(false);
        // The link must NOT proceed — no linked state
        expect(confirmation.safetyNumber).toBeNull();
    });

    it('rejects a tampered payload mid-flow (fail closed)', async () => {
        const newDeviceKey = await genPublicBytes();
        const payload = encodeLinkingPayload(newDeviceKey);

        // Tamper: truncate the payload
        const tampered = payload.slice(0, payload.length - 2);
        expect(() => decodeLinkingPayload(tampered)).toThrow();
    });
});