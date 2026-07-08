// @vitest-environment node
import { StorageGate } from '../src';
import { describe, test, expect } from 'vitest';

/** Minimal in‑memory IndexedDB implementation for tests */
class FakeObjectStore {
    constructor(private store: Map<string, any>) {}
    put(value: any) {
        const req: any = { result: undefined, onerror: null as any, onsuccess: null as any };
        this.store.set(value.id, value);
        setTimeout(() => {
            if (req.onsuccess) req.onsuccess();
        }, 0);
        return req;
    }
    get(key: string) {
        const res = this.store.get(key);
        const req: any = { result: res, onerror: null as any, onsuccess: null as any };
        setTimeout(() => {
            if (req.onsuccess) req.onsuccess();
        }, 0);
        return req;
    }
}
class FakeTransaction {
    constructor(private storeMap: Map<string, Map<string, any>>) {}
    objectStore(name: string) {
        const map = this.storeMap.get(name)!;
        return new FakeObjectStore(map);
    }
}
class FakeIDBDatabase {
    constructor(public objectStoreNames: { contains: (name:string)=>boolean }) {}
    transaction(storeName: string, mode?: string) {
        return new FakeTransaction((this as any).storeMap);
    }
}
// Simplified factory that returns a database with pre‑created stores.
class FakeIndexedDBFactory {
    private db: FakeIDBDatabase | null = null;
    open(name: string, version: number) {
        const req: any = { result: undefined, onerror: null as any, onsuccess: null as any };
        if (!this.db) {
            const storeMap = new Map<string, Map<string, any>>();
            ['identity', 'session', 'prekey', 'messages'].forEach((s)=>{
                storeMap.set(s, new Map());
            });
            this.db = new FakeIDBDatabase({ contains: (name:string)=>storeMap.has(name) }) as any;
            // attach storeMap for transaction
            (this.db as any).storeMap = storeMap;
        }
        setTimeout(() => {
            req.result = this.db;
            if (req.onsuccess) req.onsuccess();
        }, 0);
        return req;
    }
}

const keyBytes = new Uint8Array(32); // zeroed key for tests

describe('StorageGate', () => {
    test('fails closed if IndexedDB is unavailable', async () => {
        const gate = new StorageGate({ indexedDB: undefined, keyBytes });
        await expect(gate.open()).rejects.toThrow(/storage unavailable/i);
    });

    test('write and read identity works', async () => {
        const factory = new FakeIndexedDBFactory();
        const gate = new StorageGate({ indexedDB: factory as any, keyBytes });
        await gate.open();
        await gate.put('identity', 'self', { name: 'Alice' });
        const val = await gate.get('identity', 'self');
        expect(val).toEqual({ name: 'Alice' });
    });

    test('tampered ciphertext fails closed', async () => {
        const factory = new FakeIndexedDBFactory();
        const gate = new StorageGate({ indexedDB: factory as any, keyBytes });
        await gate.open();
        await gate.put('identity', 'self', { name: 'Bob' });
        // Directly corrupt the stored record
        const db: any = (gate as any).db;
        const tx = db.transaction('identity');
        const store = tx.objectStore('identity');
        const rec = store.get('self').result;
        rec.ciphertext = 'corrupted';
        store.put(rec);
        await expect(gate.get('identity', 'self')).rejects.toThrow(/decryption failed/i);
    });

    test('wrong key fails closed', async () => {
        const factory = new FakeIndexedDBFactory();
        const gate1 = new StorageGate({ indexedDB: factory as any, keyBytes });
        await gate1.open();
        await gate1.put('identity', 'self', { name: 'Eve' });

        const wrongKey = new Uint8Array(32).fill(1);
        const gate2 = new StorageGate({ indexedDB: factory as any, keyBytes: wrongKey });
        await gate2.open();
        await expect(gate2.get('identity', 'self')).rejects.toThrow(/decryption failed/i);
    });

    test('concurrent writes do not corrupt state', async () => {
        const factory = new FakeIndexedDBFactory();
        const gate = new StorageGate({ indexedDB: factory as any, keyBytes });
        await gate.open();
        const write1 = gate.put('identity', 'self', { name: 'First' });
        const write2 = gate.put('identity', 'self', { name: 'Second' });
        await Promise.all([write1, write2]);
        const val = await gate.get('identity', 'self');
        expect(val).toMatchObject({ name: expect.stringMatching(/First|Second/) });
    });

    test('rejects invalid store name', async () => {
        const factory = new FakeIndexedDBFactory();
        const gate = new StorageGate({ indexedDB: factory as any, keyBytes });
        await gate.open();
        await expect(gate.put('invalid_store' as any, 'x', { a: 1 })).rejects.toThrow(/invalid store/i);
        await expect(gate.get('invalid_store' as any, 'x')).rejects.toThrow(/invalid store/i);
    });

    test('rejects empty id', async () => {
        const factory = new FakeIndexedDBFactory();
        const gate = new StorageGate({ indexedDB: factory as any, keyBytes });
        await gate.open();
        await expect(gate.put('identity', '', { a: 1 })).rejects.toThrow(/invalid id/i);
        await expect(gate.get('identity', '')).rejects.toThrow(/invalid id/i);
    });

    test('rejects non-serializable value', async () => {
        const factory = new FakeIndexedDBFactory();
        const gate = new StorageGate({ indexedDB: factory as any, keyBytes });
        await gate.open();
        const circular: any = {};
        circular.self = circular;
        await expect(gate.put('identity', 'self', circular)).rejects.toThrow(/serializ/i);
    });

    test('rejects wrong key length on open', async () => {
        const factory = new FakeIndexedDBFactory();
        const shortKey = new Uint8Array(16);
        const gate = new StorageGate({ indexedDB: factory as any, keyBytes: shortKey });
        await expect(gate.open()).rejects.toThrow(/invalid key length/i);
    });
});
