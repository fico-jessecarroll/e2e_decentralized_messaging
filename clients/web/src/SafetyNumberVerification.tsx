import React, { useState } from 'react';

export interface SafetyNumberProps {
    localIdentityKey: Uint8Array;
    remoteIdentityKey: Uint8Array;
    conversationId: string;
}

// Placeholder for safety-number derivation – to be implemented.
const deriveSafetyNumber = (local: Uint8Array, remote: Uint8Array): string => {
    // TODO: implement proper fingerprint algorithm using wasm binding.
    return '00000 00000 00000 00000 00000';
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