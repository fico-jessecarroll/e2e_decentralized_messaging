import React, { useState } from 'react';

export interface SafetyNumberProps {
    localIdentityKey: Uint8Array;
    remoteIdentityKey: Uint8Array;
    conversationId: string;
}

// The SafetyNumberVerification component now derives the safety number using the WASM binding.
// It calls wasm.derive_safety_number with the local and remote identity keys.
// Future work includes persisting verified/unverified state via BrowserStorage/StorageGate
// and handling TOFU violations (clearing "verified" if the remote key changes).
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';

const deriveSafetyNumber = (local: Uint8Array, remote: Uint8Array): string => {
    try {
        return wasm.derive_safety_number(local, remote);
    } catch (e) {
        console.error('Failed to derive safety number', e);
        throw e;
    }
};

export const SafetyNumberVerification: React.FC<SafetyNumberProps> = ({ localIdentityKey, remoteIdentityKey, conversationId }) => {
    const [verified, setVerified] = useState(false);
    const safetyNumber = deriveSafetyNumber(localIdentityKey, remoteIdentityKey);

    return (
        <div>
            <h3>Safety Number for {conversationId}</h3>
            <p>{safetyNumber}</p>
            <button onClick={() => setVerified(!verified)}>
                {verified ? 'Unverify' : 'Verify'}
            </button>
        </div>
    );
};