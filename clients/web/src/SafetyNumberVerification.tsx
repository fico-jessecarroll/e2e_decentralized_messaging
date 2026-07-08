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
// Future work includes persisting verified/unverified state via BrowserStorage/StorageGate
// and handling TOFU violations (clearing "verified" if the remote key changes).
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';

export const SafetyNumberVerification: React.FC<SafetyNumberProps> = ({ localIdentityKey, remoteIdentityKey, conversationId }) => {
    const [verified, setVerified] = useState(false);
    const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let cancelled = false;
        ensureWasmInit()
            .then(() => {
                if (cancelled) return;
                setSafetyNumber(wasm.derive_safety_number(localIdentityKey, remoteIdentityKey));
            })
            .catch((e: unknown) => {
                console.error('Failed to derive safety number', e);
                if (!cancelled) setError(e instanceof Error ? e.message : String(e));
            });
        return () => {
            cancelled = true;
        };
    }, [localIdentityKey, remoteIdentityKey]);

    if (error) {
        return <div role="alert">Safety number unavailable: {error}</div>;
    }

    return (
        <div>
            <h3>Safety Number for {conversationId}</h3>
            <p>{safetyNumber === null ? 'Loading…' : safetyNumber}</p>
            <button onClick={() => setVerified(!verified)} disabled={safetyNumber === null}>
                {verified ? 'Unverify' : 'Verify'}
            </button>
        </div>
    );
};