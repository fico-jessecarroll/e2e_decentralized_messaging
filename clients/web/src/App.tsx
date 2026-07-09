import React from 'react';
import Banner from './Banner';
import { Conversation } from './Conversation';
import { SafetyNumberVerification } from './SafetyNumberVerification';
import { BackupPanel } from './BackupPanel';
import { GroupConversation } from './GroupConversation';
import { DeviceLinking } from './DeviceLinking';
import { generate_identity } from '../../../core/bindings/wasm/pkg/index.js';
import { ensureWasmInit } from './wasm_init';
import { SealGlyph } from './design/SealGlyph';
import './design/AppShell.css';

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

type ViewId = 'direct' | 'group' | 'link' | 'backup';

const NAV_ITEMS: { id: ViewId; label: string; title: string; subtitle: string }[] = [
    { id: 'direct', label: 'Direct', title: 'Direct message', subtitle: 'One-to-one, Double Ratchet' },
    { id: 'group', label: 'Group', title: 'Group conversation', subtitle: 'Sender Keys group crypto' },
    { id: 'link', label: 'Link', title: 'Link a device', subtitle: 'QR code + safety-number confirmation' },
    { id: 'backup', label: 'Backup', title: 'Encrypted backup', subtitle: 'Passphrase-protected export / import' },
];

export default function App() {
    const [keys, setKeys] = React.useState<{ local: Uint8Array; remote: Uint8Array } | null>(null);
    const [view, setView] = React.useState<ViewId>('direct');

    React.useEffect(() => {
        let cancelled = false;
        ensureWasmInit().then(() => {
            if (cancelled) return;
            setKeys({
                local: generate_identity().public_bytes(),
                remote: generate_identity().public_bytes(),
            });
        });
        return () => {
            cancelled = true;
        };
    }, []);

    const identityFingerprint = keys ? btoa(String.fromCharCode(...keys.local)).slice(0, 24) : null;
    const activeItem = NAV_ITEMS.find((item) => item.id === view)!;

    return (
        <div className="shell">
            <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
                <Banner />
                <div className="shell-body">
                    <nav className="rail" aria-label="Sections">
                        <div className="rail-identity">
                            {identityFingerprint ? (
                                <SealGlyph value={identityFingerprint} size={40} title="Your identity seal" />
                            ) : (
                                <div style={{ width: 40, height: 40 }} />
                            )}
                            <span className="rail-identity-label">You</span>
                        </div>
                        <div className="rail-nav">
                            {NAV_ITEMS.map((item) => (
                                <button
                                    key={item.id}
                                    type="button"
                                    className="rail-nav-item"
                                    aria-current={view === item.id ? 'page' : undefined}
                                    onClick={() => setView(item.id)}
                                >
                                    {item.label}
                                </button>
                            ))}
                        </div>
                    </nav>
                    <div className="shell-main">
                        <header className="view-header">
                            <div>
                                <h1>{activeItem.title}</h1>
                                <div className="view-header-sub">{activeItem.subtitle}</div>
                            </div>
                        </header>
                        <div className="view-body">
                            <div className="view-content">
                                {view === 'direct' && <Conversation />}
                                {view === 'group' && <GroupConversation />}
                                {view === 'link' && (
                                    <SafetyNumberErrorBoundary>
                                        {keys && <DeviceLinking localIdentityKey={keys.local} />}
                                    </SafetyNumberErrorBoundary>
                                )}
                                {view === 'backup' && <BackupPanel storagePassword="default" />}
                            </div>
                            {view === 'direct' && (
                                <aside className="trust-drawer" aria-label="Conversation trust">
                                    <h2>Verify this conversation</h2>
                                    <SafetyNumberErrorBoundary>
                                        {keys && (
                                            <SafetyNumberVerification
                                                localIdentityKey={keys.local}
                                                remoteIdentityKey={keys.remote}
                                                conversationId="demo"
                                            />
                                        )}
                                    </SafetyNumberErrorBoundary>
                                </aside>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
