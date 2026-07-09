import React from 'react';
import Banner from './Banner';
import { Conversation } from './Conversation';
import { SafetyNumberVerification } from './SafetyNumberVerification';
import { BackupPanel } from './BackupPanel';
import { GroupConversation } from './GroupConversation';
import { DeviceLinking } from './DeviceLinking';
import * as wasm from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';

// SafetyNumberVerification's deriveSafetyNumber calls the real
// wasm.derive_safety_number binding, which requires 33-byte compressed
// Curve25519 identity keys and throws on any other length - a fixed
// Uint8Array(32) (this demo's prior placeholder-era value) crashes render.
// Generate real identity keys instead, matching the pattern already used in
// tests/safety_number.test.tsx. Both this and the safety number derivation
// itself require wasm_init's async init to have completed first (see
// wasm_init.ts) - keys stay null (and SafetyNumberVerification unrendered)
// until that finishes.
class SafetyNumberErrorBoundary extends React.Component<
    { children: React.ReactNode },
    { error: Error | null }
> {
    constructor(props: { children: React.ReactNode }) {
        super(props);
        this.state = { error: null };
    }
    static getDerivedStateFromError(error: Error) {
        return { error };
    }
    render() {
        if (this.state.error) {
            return <div role="alert">Safety number unavailable: {this.state.error.message}</div>;
        }
        return this.props.children;
    }
}

export default function App() {
    const [keys, setKeys] = React.useState<{ local: Uint8Array; remote: Uint8Array } | null>(null);

    React.useEffect(() => {
        let cancelled = false;
        ensureWasmInit().then(() => {
            if (cancelled) return;
            setKeys({
                local: wasm.generate_identity().public_bytes(),
                remote: wasm.generate_identity().public_bytes(),
            });
        });
        return () => {
            cancelled = true;
        };
    }, []);

    return (
        <>
            <Banner />
            <Conversation />
            <SafetyNumberErrorBoundary>
                {keys && (
                    <SafetyNumberVerification localIdentityKey={keys.local} remoteIdentityKey={keys.remote} conversationId="demo" />
                )}
            </SafetyNumberErrorBoundary>
            <BackupPanel storagePassword="default" />
            <GroupConversation />
            <SafetyNumberErrorBoundary>
                {keys && (
                    <DeviceLinking localIdentityKey={keys.local} />
                )}
            </SafetyNumberErrorBoundary>
        </>
    );
}
