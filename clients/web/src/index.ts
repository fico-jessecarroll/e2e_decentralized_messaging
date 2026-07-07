import { createCipheriv, createDecipheriv } from 'crypto';

// Fixed key and iv for the minimal round‑trip implementation.
// In a real implementation this would be derived from a secure key store.
const KEY = Buffer.alloc(32, 0); // 256-bit zeroed key
const IV = Buffer.alloc(16, 0);  // 128-bit zeroed IV

/**
 * Perform a minimal encrypt‑then‑decrypt round‑trip using AES‑256‑CBC.
 * The function returns the original plaintext bytes if everything works.
 */
export async function performSmokeFlow(plaintext: Uint8Array): Promise<Uint8Array> {
    // Encrypt
    const cipher = createCipheriv('aes-256-cbc', KEY, IV);
    const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    // Decrypt
    const decipher = createDecipheriv('aes-256-cbc', KEY, IV);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return new Uint8Array(decrypted);
}

/**
 * Return a warning string about the reduced threat model for browser clients.
 */
export function threatModelWarning(): string {
    // The wording is intentionally similar to core/bindings/wasm/src/lib.rs::BrowserThreatModel::docs()
    return 'Browser clients have no secure enclave. Identity and session key material is stored via IndexedDB / WebCrypto, which protects against casual extraction but not against same‑origin script execution.';
}

/**
 * Simple gate that requires an IndexedDB implementation.
 */
export class StorageGate {
    private indexedDB: IDBFactory | undefined;
    constructor(opts: { indexedDB: IDBFactory | undefined }) {
        this.indexedDB = opts.indexedDB;
    }

    /**
     * Open the storage. Rejects if IndexedDB is unavailable.
     */
    async open(): Promise<void> {
        if (!this.indexedDB) {
            throw new Error('storage unavailable');
        }
        // In a real implementation we would open an IDB database here.
        return;
    }
}
