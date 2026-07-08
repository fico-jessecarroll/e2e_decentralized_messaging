import React, { useState } from 'react';

export interface SafetyNumberProps {
    localIdentityKey: Uint8Array;
    remoteIdentityKey: Uint8Array;
    conversationId: string;
}

// PLACEHOLDER - not a real implementation. This returns a fixed string
// regardless of input and does not derive anything from the actual identity
// keys. The WASM binding now exists (core/bindings/wasm/src/lib.rs's
// derive_safety_number delegates to core/crypto/src/device_qr.rs's
// safety_number_for_display), but wiring this component to call it,
// persisting verified/unverified state via BrowserStorage/StorageGate,
// and handling the TOFU-violation case (clear "verified" if the remote key
// changes) are all tracked as follow-up work, not done here.
import * as wasm from '../../core/bindings/wasm/pkg/index.js';

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