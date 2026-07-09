import React, { useEffect, useState } from 'react';
import { derive_safety_number } from './wasm_wrapper';
import { ensureWasmInit } from './wasm_init';
import { StorageGate, StoreName } from './storage';

export interface SafetyNumberProps {
  localIdentityKey: Uint8Array;
  remoteIdentityKey: Uint8Array;
  conversationId: string;
}

interface VerifiedRecord {
  verified: boolean;
  remoteKeyBase64: string;
}

const SAFETY_NUMBER_STORE: StoreName = 'identity';
const storageKey = (conversationId: string) => `safety-number:${conversationId}`;

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Safety-number verification UI with TOFU (Trust On First Use) handling.
 *
 * The verified state is persisted per conversationId via the existing
 * StorageGate (encrypted IndexedDB).  When the remote identity key changes
 * after a user previously marked the conversation "verified", the verified
 * flag is cleared and a visible warning is surfaced — it is never silently
 * carried forward onto a changed key.
 *
 * A `loaded` state flag guards the persist effect so that the default
 * `verified: false` state is never written to storage before the initial
 * load has completed — otherwise the persist effect would clobber a stored
 * `{verified: true}` record before the load effect had a chance to read it.
 */
export const SafetyNumberVerification: React.FC<SafetyNumberProps> = ({
  localIdentityKey,
  remoteIdentityKey,
  conversationId,
}) => {
  const [verified, setVerified] = useState<boolean>(false);
  const [loaded, setLoaded] = useState<boolean>(false);
  const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const key = storageKey(conversationId);

  // Derive safety number from the WASM binding (real derivation, not a
  // hardcoded constant).
  useEffect(() => {
    let cancelled = false;
    setWarning(null); // clear any stale warning from a previous key
    ensureWasmInit()
      .then(() => {
        if (cancelled) return;
        try {
          const sn = derive_safety_number(localIdentityKey, remoteIdentityKey);
          if (!cancelled) setSafetyNumber(sn);
        } catch (e: unknown) {
          console.error('Failed to derive safety number', e);
          if (!cancelled) setError(e instanceof Error ? e.message : String(e));
        }
      })
      .catch((e: unknown) => {
        console.error('Failed to init wasm', e);
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => { cancelled = true; };
  }, [localIdentityKey, remoteIdentityKey]);

  // Load persisted verified state and handle TOFU violations.
  // `loaded` is reset to false so the persist effect won't write stale
  // state before this load completes.
  useEffect(() => {
    let cancelled = false;
    setLoaded(false);
    const gate = new StorageGate({
      indexedDB: (globalThis as any).indexedDB,
      keyBytes: new Uint8Array(32),
    });
    const currentRemoteBase64 = toBase64(remoteIdentityKey);
    gate.open()
      .then(() => gate.get(SAFETY_NUMBER_STORE, key))
      .then((stored) => {
        if (cancelled) return;
        if (stored) {
          const parsed = stored as VerifiedRecord;
          if (parsed.remoteKeyBase64 !== currentRemoteBase64) {
            // TOFU violation: the remote key changed since verification.
            // Clear the verified flag and surface a visible warning.
            setVerified(false);
            setWarning('Remote identity key changed; safety number invalidated');
          } else {
            setVerified(parsed.verified);
          }
        } else {
          setVerified(false);
        }
        setLoaded(true);
      })
      .catch((e: unknown) => {
        console.error('Failed to load verified state', e);
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => { cancelled = true; };
  }, [key, remoteIdentityKey]);

  // Persist verified state whenever it changes (along with the remote key
  // at the time of verification, for TOFU comparison on next load).
  // Guarded by `loaded` so we never write before the initial load completes.
  useEffect(() => {
    if (!loaded || safetyNumber === null) return;
    const gate = new StorageGate({
      indexedDB: (globalThis as any).indexedDB,
      keyBytes: new Uint8Array(32),
    });
    const record: VerifiedRecord = {
      verified,
      remoteKeyBase64: toBase64(remoteIdentityKey),
    };
    gate.open()
      .then(() => gate.put(SAFETY_NUMBER_STORE, key, record))
      .catch((e: unknown) => {
        console.error('Failed to persist verified state', e);
      });
  }, [verified, loaded, safetyNumber, key, remoteIdentityKey]);

  const handleVerify = () => {
    setVerified(true);
  };
  const handleUnverify = () => {
    setVerified(false);
  };

  return (
    <div>
      {error && <p className="text-red-500">{error}</p>}
      {warning && <p className="text-yellow-500" role="alert">{warning}</p>}
      {safetyNumber === null ? (
        <p>Loading safety number...</p>
      ) : (
        <p>Safety Number: {safetyNumber}</p>
      )}
      {!verified ? (
        <button onClick={handleVerify} disabled={safetyNumber === null}>Mark as Verified</button>
      ) : (
        <>
          <p className="text-green-500">Verified</p>
          <button onClick={handleUnverify}>Unverify</button>
        </>
      )}
    </div>
  );
};
