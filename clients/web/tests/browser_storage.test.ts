// browser_storage.test.ts
import fakeIndexedDB from 'fake-indexeddb';
(globalThis as any).indexedDB = fakeIndexedDB;
import { describe, expect, test } from 'vitest';
import { BrowserStorage } from '../src';

const PASSWORD = 'test-pass';

describe('BrowserStorage', () => {
    test('normal roundtrip', async () => {
        const storage = new BrowserStorage(PASSWORD);
        await storage.open();
        const data = { foo: 'bar', num: 42 };
        await storage.setItem('identity', data);
        const got = await storage.getItem<typeof data>('identity');
        expect(got).toEqual(data);
    });

    test('fails closed on corrupted ciphertext', async () => {
        const storage = new BrowserStorage(PASSWORD);
        await storage.open();
        await storage.setItem('identity', { a: 1 });
        // Corrupt stored blob directly via IDB
        const dbReq = indexedDB.open('browser_storage');
        await new Promise<void>((res, rej) => {
            dbReq.onerror = () => rej(dbReq.error || new Error('open fail'));
            dbReq.onsuccess = () => res();
        });
        const tx = dbReq.result.transaction(['kv'], 'readwrite');
        const store = tx.objectStore('kv');
        const corruptBlob = new Uint8Array([0, 1, 2, 3, 4]);
        await new Promise<void>((res, rej) => {
            const req = store.put(corruptBlob, 'identity');
            req.onerror = () => rej(req.error || new Error('put fail'));
            req.onsuccess = () => res();
        });
        await expect(storage.getItem<any>('identity')).rejects.toThrow(/decrypt/);
    });

    test('fails closed on wrong key', async () => {
        const storage1 = new BrowserStorage(PASSWORD);
        await storage1.open();
        await storage1.setItem('identity', { x: 9 });
        const storage2 = new BrowserStorage('wrong-pass');
        await storage2.open();
        await expect(storage2.getItem<any>('identity')).rejects.toThrow(/decrypt/);
    });

    test('concurrent writes do not corrupt state', async () => {
        const storageA = new BrowserStorage(PASSWORD);
        const storageB = new BrowserStorage(PASSWORD);
        await Promise.all([storageA.open(), storageB.open()]);
        const write1 = storageA.setItem('identity', { a: 1 });
        const write2 = storageB.setItem('identity', { b: 2 });
        await Promise.all([write1, write2]);
        const final = await storageA.getItem<any>('identity');
        expect(final).not.toBeNull();
        // It could be either value; we just ensure it's valid JSON
    });

    test('rejects empty key', async () => {
        const storage = new BrowserStorage(PASSWORD);
        await storage.open();
        await expect(storage.setItem('', { a: 1 })).rejects.toThrow(/invalid key/i);
        await expect(storage.getItem('')).rejects.toThrow(/invalid key/i);
    });

    test('rejects non-serializable value', async () => {
        const storage = new BrowserStorage(PASSWORD);
        await storage.open();
        const circular: any = {};
        circular.self = circular;
        await expect(storage.setItem('identity', circular)).rejects.toThrow(/serializ/i);
    });

    test('rejects empty password', () => {
        expect(() => new BrowserStorage('')).toThrow(/invalid password/i);
    });

    test('salt persists across separate instances so the same password derives the same key', async () => {
        // Regression guard: the PBKDF2 salt must be generated once and
        // persisted (not freshly randomized per open()), or a second
        // instance opening the same DB with the correct password would
        // still derive a different key and fail to decrypt data the first
        // instance wrote.
        const writer = new BrowserStorage(PASSWORD);
        await writer.open();
        await writer.setItem('cross-instance', { ok: true });

        const reader = new BrowserStorage(PASSWORD);
        await reader.open();
        const got = await reader.getItem<{ ok: boolean }>('cross-instance');
        expect(got).toEqual({ ok: true });
    });
});
