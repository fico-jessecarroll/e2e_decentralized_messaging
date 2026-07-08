/**
 * IndexedDB-backed encrypted storage gate.
 *
 * Parity contract with core/storage (see core/storage/src/lib.rs and
 * backup.rs): identity/session/prekey state and message history, encrypted
 * at rest, fail-closed on a bad key or corrupt data.
 *
 * At-rest encryption uses AES-256-GCM via WebCrypto.  The raw key bytes are
 * supplied by the caller; a non-extractable CryptoKey is derived from them so
 * the key material cannot be exfiltrated from JS land.
 *
 * Reduced threat model (see core/bindings/wasm/src/lib.rs BrowserThreatModel):
 * no secure enclave, browser key-storage.  Fail-closed is the default — any
 * decrypt/parse failure surfaces a StorageError rather than returning garbage.
 */

export type StoreName = 'identity' | 'session' | 'prekey' | 'messages';

const ALLOWED_STORES: readonly StoreName[] = ['identity', 'session', 'prekey', 'messages'];
const IV_LENGTH = 12;
const KEY_LENGTH = 32; // AES-256

export class StorageError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'StorageError';
    }
}

/* ------------------------------------------------------------------ */
/* Base64 helpers (with Node fallback for the test harness)            */
/* ------------------------------------------------------------------ */

function arrayBufferToBase64(buf: ArrayBuffer): string {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    if (typeof btoa === 'function') return btoa(binary);
    // Node fallback
    return Buffer.from(binary, 'binary').toString('base64');
}

function base64ToArrayBuffer(b64: string): ArrayBuffer {
    let binary: string;
    if (typeof atob === 'function') {
        binary = atob(b64);
    } else {
        binary = Buffer.from(b64, 'base64').toString('binary');
    }
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer as ArrayBuffer;
}

/* ------------------------------------------------------------------ */
/* StorageGate                                                         */
/* ------------------------------------------------------------------ */

export class StorageGate {
    private indexedDB: IDBFactory | undefined;
    private db?: IDBDatabase;
    private keyBytes: Uint8Array;
    private cryptoKey?: CryptoKey;

    constructor(opts: { indexedDB: IDBFactory | undefined; keyBytes: ArrayBuffer | Uint8Array }) {
        this.indexedDB = opts.indexedDB;
        this.keyBytes = opts.keyBytes instanceof Uint8Array ? opts.keyBytes : new Uint8Array(opts.keyBytes);
    }

    async open(): Promise<void> {
        if (!this.indexedDB) throw new StorageError('storage unavailable');
        if (this.keyBytes.length !== KEY_LENGTH) {
            throw new StorageError(`invalid key length: expected ${KEY_LENGTH} bytes, got ${this.keyBytes.length}`);
        }

        const dbName = 'messaging';
        const request = this.indexedDB.open(dbName, 1);

        return new Promise<void>((resolve, reject) => {
            request.onerror = () => reject(new StorageError('failed to open database'));
            request.onupgradeneeded = (e: Event) => {
                const db = (e.target as IDBOpenDBRequest).result as IDBDatabase;
                for (const store of ALLOWED_STORES) {
                    if (!db.objectStoreNames.contains(store)) {
                        db.createObjectStore(store, { keyPath: 'id' });
                    }
                }
            };
            request.onsuccess = async () => {
                this.db = request.result as IDBDatabase;
                try {
                    // Import as non-extractable so the raw key cannot be
                    // exfiltrated from the JS realm.
                    this.cryptoKey = await crypto.subtle.importKey(
                        'raw',
                        this.keyBytes.buffer as ArrayBuffer,
                        { name: 'AES-GCM' },
                        false, // non-extractable
                        ['encrypt', 'decrypt'],
                    );
                    resolve();
                } catch {
                    reject(new StorageError('failed to import key'));
                }
            };
        });
    }

    /* ---- crypto helpers ---- */

    private async encrypt(data: Uint8Array): Promise<string> {
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        const cipher = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
            this.cryptoKey!,
            data.buffer as ArrayBuffer,
        );
        const combined = new Uint8Array(IV_LENGTH + cipher.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(cipher), IV_LENGTH);
        return arrayBufferToBase64(combined.buffer as ArrayBuffer);
    }

    private async decrypt(ciphertextB64: string): Promise<Uint8Array> {
        let combined: ArrayBuffer;
        try {
            combined = base64ToArrayBuffer(ciphertextB64);
        } catch {
            throw new StorageError('decryption failed');
        }
        const bytes = new Uint8Array(combined);
        if (bytes.length < IV_LENGTH) throw new StorageError('decryption failed');
        const iv = bytes.slice(0, IV_LENGTH);
        const ct = bytes.slice(IV_LENGTH);
        try {
            const plain = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
                this.cryptoKey!,
                ct.buffer as ArrayBuffer,
            );
            return new Uint8Array(plain);
        } catch {
            throw new StorageError('decryption failed');
        }
    }

    /* ---- validation ---- */

    private validateStore(store: StoreName): void {
        if (!ALLOWED_STORES.includes(store)) {
            throw new StorageError(`invalid store name: ${store}`);
        }
    }

    private validateId(id: string): void {
        if (!id || typeof id !== 'string') {
            throw new StorageError('invalid id: must be a non-empty string');
        }
    }

    /* ---- public API ---- */

    async put(store: StoreName, id: string, value: unknown): Promise<void> {
        if (!this.db) throw new StorageError('not opened');
        this.validateStore(store);
        this.validateId(id);

        let json: string;
        try {
            json = JSON.stringify(value);
        } catch {
            throw new StorageError('value is not serializable');
        }

        const ciphertext = await this.encrypt(new TextEncoder().encode(json));

        return new Promise<void>((resolve, reject) => {
            const tx = this.db!.transaction([store], 'readwrite');
            const objStore = tx.objectStore(store);
            const req = objStore.put({ id, ciphertext });
            req.onerror = () => reject(new StorageError('put failed'));
            req.onsuccess = () => resolve();
        });
    }

    async get(store: StoreName, id: string): Promise<unknown | null> {
        if (!this.db) throw new StorageError('not opened');
        this.validateStore(store);
        this.validateId(id);

        return new Promise<unknown | null>((resolve, reject) => {
            const tx = this.db!.transaction([store], 'readonly');
            const objStore = tx.objectStore(store);
            const req = objStore.get(id);
            req.onerror = () => reject(new StorageError('get failed'));
            req.onsuccess = async () => {
                const record = req.result as { id: string; ciphertext: string } | undefined;
                if (!record) return resolve(null);
                try {
                    const dec = await this.decrypt(record.ciphertext);
                    const txt = new TextDecoder().decode(dec);
                    resolve(JSON.parse(txt));
                } catch (err) {
                    reject(err instanceof StorageError ? err : new StorageError('decryption failed'));
                }
            };
        });
    }
}