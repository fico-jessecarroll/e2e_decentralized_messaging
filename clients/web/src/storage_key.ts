/**
 * Cryptographically strong AES-256 key for StorageGate at-rest encryption.
 *
 * Security rationale (OWASP A3 / Secure-by-Design):
 *
 * Previously, components passed `new Uint8Array(32)` as the key — a
 * zero-filled, completely predictable buffer.  That defeats the entire
 * purpose of at-rest encryption: anyone with read access to IndexedDB
 * (e.g. a malicious extension or a disk forensics tool) could trivially
 * decrypt every stored record because the key was a well-known constant.
 *
 * This module generates a 32-byte key via `crypto.getRandomValues` (the
 * WebCrypto CSPRNG) and persists it in `localStorage` as base64 so that:
 *
 *   - The key is random and unique per browser profile.
 *   - The same key is reused across page reloads and across all components
 *     (Conversation, SafetyNumberVerification, …) so that data written by
 *     one component can be read by another.
 *
 * Threat-model note: storing the key in localStorage is NOT ideal — a XSS
 * attacker who can read localStorage can also read IndexedDB directly, so
 * the key location does not meaningfully widen the attack surface in the
 * browser's reduced threat model (no secure enclave; see
 * core/bindings/wasm/src/lib.rs BrowserThreatModel).  The real protection
 * against XSS is CSP / input sanitisation, not key placement.  A future
 * story should migrate this to a user passphrase + PBKDF2/scrypt so the
 * key is derived from a secret the browser never stores in plaintext.
 */

const KEY_LENGTH = 32; // AES-256
const STORAGE_ITEM = 'messaging-storage-key';

function base64Encode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64Decode(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Returns a 32-byte cryptographically random key, generating and
 * persisting it on first call.  Subsequent calls (including after a page
 * reload) return the same key.
 *
 * Falls back gracefully when `localStorage` is unavailable (e.g. private
 * browsing in some browsers): a fresh random key is generated each time.
 * This means data from a previous session cannot be decrypted, which is
 * the correct fail-closed behaviour — we never fall back to a weak or
 * constant key.
 */
export function getStorageKey(): Uint8Array {
  // Try to reuse a persisted key.
  try {
    const stored = localStorage.getItem(STORAGE_ITEM);
    if (stored) {
      const key = base64Decode(stored);
      if (key.length === KEY_LENGTH) return key;
    }
  } catch {
    // localStorage unavailable — fall through to generate a fresh key.
  }

  // Generate a fresh cryptographically strong key.
  const key = crypto.getRandomValues(new Uint8Array(KEY_LENGTH));

  // Best-effort persist for reuse across reloads.
  try {
    localStorage.setItem(STORAGE_ITEM, base64Encode(key));
  } catch {
    // localStorage unavailable — key is session-scoped only.
  }

  return key;
}