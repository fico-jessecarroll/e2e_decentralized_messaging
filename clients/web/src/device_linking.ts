/**
 * QR device-linking flow (web client).
 *
 * Mirrors the Rust core's `crypto::device_qr` flow:
 *  1. New device encodes its identity public key as a QR payload (hex string).
 *  2. Primary device scans (or manually enters) the payload and decodes it.
 *  3. Both devices derive and display the safety number.
 *  4. User confirms the safety numbers match out-of-band.
 *  5. On match → link proceeds; on mismatch → link aborts (fail closed).
 *
 * The encode/decode and safety-number derivation are delegated to the WASM
 * bindings (`encode_device_qr`, `decode_device_qr`, `derive_safety_number`),
 * which are thin wrappers over the Rust core. This module provides the
 * web-side orchestration and the confirmation gate.
 *
 * Security properties:
 *  - **Fail closed**: any malformed, truncated, or tampered QR payload is
 *    rejected by `decodeLinkingPayload` (the WASM binding throws). The
 *    function does not return partial or best-effort results.
 *  - **Confirmation gate**: `confirmSafetyNumber` re-derives the expected
 *    safety number from the raw key bytes and compares it to the user-entered
 *    value. A mismatch returns `confirmed: false` and never produces a
 *    safety number, so the caller cannot accidentally proceed.
 *  - **No sensitive data in logs**: key bytes and payloads are never logged.
 */

import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';

/**
 * Extract a human-readable message from a thrown value. WASM binding errors
 * are `WasmError` structs (not JS `Error` instances) that expose a `.message()`
 * method, so we check for that before falling back to `String(e)`.
 */
function errorMessage(e: unknown): string {
    if (e instanceof Error) return e.message;
    if (e !== null && typeof e === 'object' && 'message' in e) {
        const msg = (e as { message: unknown }).message;
        if (typeof msg === 'string') return msg;
        if (typeof msg === 'function') {
            try { return String((e as { message: () => string }).message()); } catch { /* fall through */ }
        }
    }
    return String(e);
}

/**
 * Encode a device's identity public key bytes as a QR code payload string.
 * The returned hex string is what a QR renderer encodes into the image.
 *
 * @throws if the WASM binding rejects the key bytes (should not happen for
 *   valid 33-byte identity keys).
 */
export function encodeLinkingPayload(identityPublicKey: Uint8Array): string {
    return wasm.encode_device_qr(identityPublicKey);
}

/**
 * Decode a scanned or manually entered QR payload back to raw identity
 * public key bytes.
 *
 * Fail closed: any malformed payload (non-hex, odd length, wrong byte
 * count) causes the WASM binding to throw. This function does not catch
 * or swallow those errors — callers must handle the rejection and not
 * proceed with linking.
 *
 * @throws if the payload is malformed, truncated, or does not decode to
 *   a valid 33-byte identity key.
 */
export function decodeLinkingPayload(qrPayload: string): Uint8Array {
    const bytes = wasm.decode_device_qr(qrPayload);
    return new Uint8Array(bytes);
}

/**
 * Result of the safety-number confirmation step.
 */
export interface SafetyNumberConfirmation {
    /** True only when the user-entered safety number matches the derived one. */
    confirmed: boolean;
    /** The derived safety number string, or null if confirmation failed. */
    safetyNumber: string | null;
    /** Error message when confirmation fails (mismatch or derivation error). */
    error?: string;
}

/**
 * Confirm that the user-entered safety number matches the safety number
 * derived from the two devices' identity keys.
 *
 * This is the critical security gate: the link proceeds only if
 * `confirmed === true`. On any mismatch (or derivation error), the function
 * returns `confirmed: false` with `safetyNumber: null` so the caller cannot
 * accidentally use a derived value from a failed confirmation.
 *
 * @param primaryKey      - The primary device's identity public key bytes.
 * @param newDeviceKey    - The new device's identity public key bytes.
 * @param userInput       - The safety number string the user entered/compared.
 */
export function confirmSafetyNumber(
    primaryKey: Uint8Array,
    newDeviceKey: Uint8Array,
    userInput: string,
): SafetyNumberConfirmation {
    let derived: string;
    try {
        derived = wasm.derive_safety_number(primaryKey, newDeviceKey);
    } catch (e: unknown) {
        return {
            confirmed: false,
            safetyNumber: null,
            error: errorMessage(e),
        };
    }

    if (userInput.trim() === derived) {
        return { confirmed: true, safetyNumber: derived };
    }

    return {
        confirmed: false,
        safetyNumber: null,
        error: 'Safety number mismatch — link aborted',
    };
}

// ---------------------------------------------------------------------------
// Linking state machine
// ---------------------------------------------------------------------------

/** The phases of the device-linking flow. */
export type LinkingPhase = 'idle' | 'displaying' | 'confirming' | 'linked' | 'aborted';

/** Mutable linking state, driven by the UI. */
export interface LinkingState {
    phase: LinkingPhase;
    /** The QR payload string to render (when this device is the new device). */
    qrPayload: string | null;
    /** The decoded remote key (when this device is the primary/scanner). */
    remoteKey: Uint8Array | null;
    /** The derived safety number for display. */
    safetyNumber: string | null;
    /** Error message on failure. */
    error: string | null;
}

export function initialLinkingState(): LinkingState {
    return {
        phase: 'idle',
        qrPayload: null,
        remoteKey: null,
        safetyNumber: null,
        error: null,
    };
}

/**
 * Begin the flow as the new device: encode the local identity key as a QR
 * payload for display. Transitions to the `displaying` phase.
 */
export async function beginDisplay(
    state: LinkingState,
    localIdentityKey: Uint8Array,
): Promise<LinkingState> {
    await ensureWasmInit();
    try {
        const payload = encodeLinkingPayload(localIdentityKey);
        return { ...state, phase: 'displaying', qrPayload: payload, error: null };
    } catch (e: unknown) {
        return {
            ...state,
            phase: 'aborted',
            error: errorMessage(e),
        };
    }
}

/**
 * Begin the flow as the primary device: decode a scanned/manually-entered
 * QR payload and derive the safety number. Transitions to `confirming`.
 *
 * Fail closed: a malformed payload transitions to `aborted`, not
 * `confirming`.
 */
export async function beginScan(
    state: LinkingState,
    scannedPayload: string,
    localIdentityKey: Uint8Array,
): Promise<LinkingState> {
    await ensureWasmInit();
    let remoteKey: Uint8Array;
    try {
        remoteKey = decodeLinkingPayload(scannedPayload);
    } catch (e: unknown) {
        return {
            ...state,
            phase: 'aborted',
            error: errorMessage(e),
        };
    }

    let safetyNumber: string;
    try {
        safetyNumber = wasm.derive_safety_number(localIdentityKey, remoteKey);
    } catch (e: unknown) {
        return {
            ...state,
            phase: 'aborted',
            error: errorMessage(e),
        };
    }

    return {
        ...state,
        phase: 'confirming',
        remoteKey,
        safetyNumber,
        error: null,
    };
}

/**
 * User confirms or denies the safety number. On match → `linked`; on
 * mismatch → `aborted`.
 */
export function confirmLink(
    state: LinkingState,
    localIdentityKey: Uint8Array,
    userInput: string,
): LinkingState {
    if (state.phase !== 'confirming' || state.remoteKey === null) {
        return { ...state, error: 'Not in confirming phase' };
    }

    const result = confirmSafetyNumber(localIdentityKey, state.remoteKey, userInput);
    if (result.confirmed) {
        return { ...state, phase: 'linked', safetyNumber: result.safetyNumber, error: null };
    }
    return { ...state, phase: 'aborted', safetyNumber: null, error: result.error ?? 'Confirmation failed' };
}