/**
 * BrowserStorage — a simpler key/value encrypted store backed by IndexedDB.
 *
 * Uses PBKDF2 (SHA-256, 100k iterations) to derive a non-extractable
 * AES-256-GCM key from a password.  All values are encrypted at rest and
 * fail-closed on corruption or a wrong key.
 *
 * This is a convenience layer for callers that want a password-derived key
 * rather than supplying raw key bytes (as StorageGate does).
 */

export class BrowserStorage {
    private db?: IDBDatabase;
    private key?: CryptoKey;

    constructor(private password: string) {
        if (!password) throw new Error('invalid password: must be non-empty');
    }

    async open(): Promise<void> {
        if (!('indexedDB' in globalThis)) throw new Error('IndexedDB unavailable');
        this.db = await this.openDB();
        const salt = await this.getOrCreateSalt();
        this.key = await this.deriveKey(this.password, salt);
    }

    private async openDB(): Promise<IDBDatabase> {
        return new Promise<IDBDatabase>((resolve, reject) => {
            const req = (globalThis as any).indexedDB.open('browser_storage', 1) as IDBOpenDBRequest;
            req.onerror = () => reject(req.error || new Error('open failed'));
            req.onupgradeneeded = () => {
                const db: IDBDatabase = req.result;
                if (!db.objectStoreNames.contains('kv')) db.createObjectStore('kv');
                if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta');
            };
            req.onsuccess = () => resolve(req.result);
        });
    }

    // The PBKDF2 salt is not secret - it only needs to be unique per
    // installation so a precomputed rainbow table can't be reused across
    // every BrowserStorage instance. Generated once and persisted in
    // plaintext alongside the (encrypted) kv store, since a salt used to
    // derive the encryption key can't itself be encrypted with that key.
    private async getOrCreateSalt(): Promise<Uint8Array> {
        const db = this.db!;
        const existing = await new Promise<Uint8Array | undefined>((resolve, reject) => {
            const tx = db.transaction(['meta'], 'readonly');
            const req = tx.objectStore('meta').get('salt');
            req.onerror = () => reject(req.error || new Error('salt read failed'));
            req.onsuccess = () => resolve(req.result as Uint8Array | undefined);
        });
        if (existing) return existing;
        const salt = crypto.getRandomValues(new Uint8Array(16));
        await new Promise<void>((resolve, reject) => {
            const tx = db.transaction(['meta'], 'readwrite');
            const req = tx.objectStore('meta').put(salt, 'salt');
            req.onerror = () => reject(req.error || new Error('salt write failed'));
            req.onsuccess = () => resolve();
        });
        return salt;
    }

    private async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password).buffer as ArrayBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveKey'],
        );
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt.buffer as ArrayBuffer,
                iterations: 100_000,
                hash: 'SHA-256',
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false, // non-extractable
            ['encrypt', 'decrypt'],
        );
    }

    private async encrypt(data: Uint8Array): Promise<Uint8Array> {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cipher = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
            this.key!,
            data.buffer as ArrayBuffer,
        );
        const out = new Uint8Array(iv.byteLength + cipher.byteLength);
        out.set(iv, 0);
        out.set(new Uint8Array(cipher), iv.byteLength);
        return out;
    }

    private async decrypt(enc: Uint8Array): Promise<Uint8Array> {
        if (enc.length < 12) throw new Error('decrypt/parse fail');
        const iv = enc.slice(0, 12);
        const ct = enc.slice(12);
        try {
            const plain = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
                this.key!,
                ct.buffer as ArrayBuffer,
            );
            return new Uint8Array(plain);
        } catch {
            throw new Error('decrypt/parse fail');
        }
    }

    async setItem<T>(key: string, value: T): Promise<void> {
        if (!this.db) throw new Error('not opened');
        if (!key) throw new Error('invalid key: must be a non-empty string');
        let json: string;
        try {
            json = JSON.stringify(value);
        } catch {
            throw new Error('value is not serializable');
        }
        const blob = await this.encrypt(new TextEncoder().encode(json));
        return new Promise<void>((resolve, reject) => {
            const tx = this.db!.transaction(['kv'], 'readwrite');
            const store = tx.objectStore('kv');
            const req = store.put(blob, key);
            req.onerror = () => reject(req.error || new Error('put fail'));
            req.onsuccess = () => resolve();
        });
    }

    async getItem<T>(key: string): Promise<T | null> {
        if (!this.db) throw new Error('not opened');
        if (!key) throw new Error('invalid key: must be a non-empty string');
        return new Promise<T | null>((resolve, reject) => {
            const tx = this.db!.transaction(['kv'], 'readonly');
            const store = tx.objectStore('kv');
            const req = store.get(key);
            req.onerror = () => reject(req.error || new Error('get fail'));
            req.onsuccess = async () => {
                const blob = req.result as Uint8Array | undefined;
                if (!blob) return resolve(null);
                try {
                    const dec = await this.decrypt(blob);
                    const txt = new TextDecoder().decode(dec);
                    resolve(JSON.parse(txt) as T);
                } catch {
                    reject(new Error('decrypt/parse fail'));
                }
            };
        });
    }

    async deleteItem(key: string): Promise<void> {
        if (!this.db) throw new Error('not opened');
        if (!key) throw new Error('invalid key: must be a non-empty string');
        return new Promise<void>((resolve, reject) => {
            const tx = this.db!.transaction(['kv'], 'readwrite');
            const store = tx.objectStore('kv');
            const req = store.delete(key);
            req.onerror = () => reject(req.error || new Error('delete fail'));
            req.onsuccess = () => resolve();
        });
    }
}