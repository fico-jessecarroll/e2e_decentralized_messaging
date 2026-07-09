import React, { useEffect, useState } from 'react';

export interface SafetyNumberProps {
    localIdentityKey: Uint8Array;
    remoteIdentityKey: Uint8Array;
    conversationId: string;
}

// The SafetyNumberVerification component derives the safety number using the WASM binding
// (wasm.derive_safety_number). The WASM module requires an async init step before any export
// is usable (see wasm_init.ts), so derivation happens in an effect with a loading state rather
// than synchronously during render.
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';

export const SafetyNumberVerification: React.FC<SafetyNumberProps> = ({ localIdentityKey, remoteIdentityKey, conversationId }) => {
    const [verified, setVerified] = useState<boolean>(false);
    const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [warning, setWarning] = useState<string | null>(null);
    const STORAGE_KEY = `safety-number:${conversationId}`;

    // Derive safety number
    useEffect(() => {
        let cancelled = false;
        ensureWasmInit()
            .then(() => {
                if (cancelled) return;
                try {
                    const sn = wasm.derive_safety_number(localIdentityKey, remoteIdentityKey);
                    setSafetyNumber(sn);
                } catch (e: any) {
                    console.error('Failed to derive safety number', e);
                    if (!cancelled) setError(e?.message ?? String(e));
                }
            })
            .catch((e: unknown) => {
                console.error('Failed to init wasm', e);
                if (!cancelled) setError(e instanceof Error ? e.message : String(e));
            });
        return () => { cancelled = true; };
    }, [localIdentityKey, remoteIdentityKey]);

    // Load persisted verified state and handle TOFU violations
    useEffect(() => {
        const stored = window.localStorage.getItem(STORAGE_KEY);
        if (stored) {
            try {
                const parsed: { verified: boolean; remoteKeyBase64: string } = JSON.parse(stored);
                const currentRemoteBase64 = btoa(String.fromCharCode(...remoteIdentityKey));
                if (parsed.remoteKeyBase64 !== currentRemoteBase64) {
                    // TOFU violation
                    setVerified(false);
                    setWarning('Remote identity key changed; safety number invalidated');
                } else {
                    setVerified(parsed.verified);
                }
            } catch (_) {}
        } else {
            setVerified(false);
        }
    }, [conversationId, remoteIdentityKey]);

    // Persist verified state when it changes
    useEffect(() => {
        if (safetyNumber === null) return; // not derived yet
        const currentRemoteBase64 = btoa(String.fromCharCode(...remoteIdentityKey));
        const data = { verified, remoteKeyBase64: currentRemoteBase64 };
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    }, [verified, safetyNumber, remoteIdentityKey]);

    if (error) {
        return <div role="alert">Safety number unavailable: {error}</div>;
    }

    return (
        <div>
            <h3>Safety Number for {conversationId}</h3>
            <p>{safetyNumber === null ? 'Loading…' : safetyNumber}</p>
            {warning && <div role="alert" style={{ color: 'red' }}>{warning}</div>}
            <button onClick={() => setVerified(!verified)} disabled={safetyNumber === null}>
                {verified ? 'Unverify' : 'Verify'}
            </button>
        </div>
    );
};