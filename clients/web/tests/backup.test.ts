// backup.test.ts — Encrypted backup export/import round-trip and negative cases.
//
// Mirrors core/storage/tests/backup_roundtrip.rs and
// clients/desktop-tauri/tests/backup_restore_polish.rs for the web client.
//
// Acceptance criteria:
//  - Export produces an encrypted blob; no plaintext record bytes appear in it.
//  - Import round-trips correctly (export → import → records match).
//  - Importing a corrupted/tampered backup fails closed with a clear error
//    and does NOT partially overwrite existing local state.
//  - Importing a backup produced by a different identity (different passphrase)
//    is rejected rather than silently merged.

import fakeIndexedDB from 'fake-indexeddb';
(globalThis as any).indexedDB = fakeIndexedDB;
import { describe, expect, test, beforeEach } from 'vitest';
import {
    exportBackup,
    importBackup,
    BackupErrorKind,
} from '../src/backup';
import { BrowserStorage } from '../src/browser_storage';

const PASSPHRASE = 'correct horse battery staple';
const OTHER_PASSPHRASE = 'a completely different passphrase';

const SAMPLE_RECORDS: Uint8Array[] = [
    new TextEncoder().encode('identity-blob'),
    new TextEncoder().encode('history-msg-1'),
    new TextEncoder().encode('history-msg-2'),
];

function recordsEqual(a: Uint8Array[], b: Uint8Array[]): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i].length !== b[i].length) return false;
        for (let j = 0; j < a[i].length; j++) {
            if (a[i][j] !== b[i][j]) return false;
        }
    }
    return true;
}

describe('Encrypted backup format', () => {
    test('export then import round-trips records', async () => {
        const blob = await exportBackup(PASSPHRASE, SAMPLE_RECORDS);
        expect(blob.length).toBeGreaterThan(0);
        const restored = await importBackup(PASSPHRASE, blob);
        expect(recordsEqual(restored, SAMPLE_RECORDS)).toBe(true);
    });

    test('exported blob does not contain plaintext record bytes', async () => {
        const blob = await exportBackup(PASSPHRASE, SAMPLE_RECORDS);
        for (const record of SAMPLE_RECORDS) {
            const blobStr = new TextDecoder().decode(blob);
            const recordStr = new TextDecoder().decode(record);
            expect(blobStr).not.toContain(recordStr);
        }
    });

    test('import rejects wrong passphrase with DecryptionFailed', async () => {
        const blob = await exportBackup(PASSPHRASE, SAMPLE_RECORDS);
        await expect(importBackup(OTHER_PASSPHRASE, blob)).rejects.toMatchObject({
            kind: BackupErrorKind.DecryptionFailed,
        });
    });

    test('import rejects tampered header (bad magic) with Tampered', async () => {
        const blob = await exportBackup(PASSPHRASE, SAMPLE_RECORDS);
        const tampered = blob.slice();
        tampered[0] ^= 0x01; // flip a magic byte
        await expect(importBackup(PASSPHRASE, tampered)).rejects.toMatchObject({
            kind: BackupErrorKind.Tampered,
        });
    });

    test('import rejects truncated blob with Tampered', async () => {
        const blob = await exportBackup(PASSPHRASE, SAMPLE_RECORDS);
        const truncated = blob.slice(0, 16);
        await expect(importBackup(PASSPHRASE, truncated)).rejects.toMatchObject({
            kind: BackupErrorKind.Tampered,
        });
    });

    test('import rejects tampered ciphertext byte with DecryptionFailed', async () => {
        const blob = await exportBackup(PASSPHRASE, SAMPLE_RECORDS);
        const tampered = blob.slice();
        // Flip a byte deep in the ciphertext (past header: magic(4)+ver(1)+salt(16)+nonce(12)=33)
        tampered[tampered.length - 1] ^= 0x01;
        await expect(importBackup(PASSPHRASE, tampered)).rejects.toMatchObject({
            kind: BackupErrorKind.DecryptionFailed,
        });
    });

    test('import rejects empty records list', async () => {
        await expect(exportBackup(PASSPHRASE, [])).rejects.toMatchObject({
            kind: BackupErrorKind.Empty,
        });
    });

    test('error messages do not leak plaintext-related terminology', async () => {
        const blob = await exportBackup(PASSPHRASE, SAMPLE_RECORDS);
        try {
            await importBackup(OTHER_PASSPHRASE, blob);
            expect.fail('should have thrown');
        } catch (e: any) {
            const msg = (e.message || '').toLowerCase();
            expect(msg).not.toContain('plaintext');
            expect(msg).not.toContain('ciphertext');
            expect(msg).not.toContain('key');
        }
    });
});

describe('Backup import does not partially overwrite existing state', () => {
    // This test verifies the fail-closed contract: if import fails, the
    // existing BrowserStorage state must be untouched.
    test('failed import leaves existing storage intact', async () => {
        // Set up storage with existing data
        const storage = new BrowserStorage(PASSPHRASE);
        await storage.open();
        await storage.setItem('identity', { id: 'existing-identity', value: 'preserved' });
        await storage.setItem('messages', { id: 'existing-messages', data: [1, 2, 3] });

        // Create a valid backup with different data
        const newRecords: Uint8Array[] = [
            new TextEncoder().encode(JSON.stringify({ id: 'identity', value: 'new-identity' })),
            new TextEncoder().encode(JSON.stringify({ id: 'messages', data: [9, 8, 7] })),
        ];
        const blob = await exportBackup(OTHER_PASSPHRASE, newRecords);

        // Attempt import with WRONG passphrase — must fail
        await expect(importBackup(PASSPHRASE, blob)).rejects.toMatchObject({
            kind: BackupErrorKind.DecryptionFailed,
        });

        // Verify existing state is untouched
        const identity = await storage.getItem<any>('identity');
        expect(identity).toEqual({ id: 'existing-identity', value: 'preserved' });
        const messages = await storage.getItem<any>('messages');
        expect(messages).toEqual({ id: 'existing-messages', data: [1, 2, 3] });
    });

    test('failed import of tampered blob leaves existing storage intact', async () => {
        const storage = new BrowserStorage(PASSPHRASE);
        await storage.open();
        await storage.setItem('identity', { id: 'existing', value: 'keep-me' });

        const blob = await exportBackup(PASSPHRASE, SAMPLE_RECORDS);
        const tampered = blob.slice();
        tampered[0] ^= 0x01;

        await expect(importBackup(PASSPHRASE, tampered)).rejects.toMatchObject({
            kind: BackupErrorKind.Tampered,
        });

        const identity = await storage.getItem<any>('identity');
        expect(identity).toEqual({ id: 'existing', value: 'keep-me' });
    });
});

describe('Backup from different identity is rejected, not silently merged', () => {
    test('backup encrypted under different passphrase cannot be imported', async () => {
        // Identity A creates a backup
        const blobA = await exportBackup('identity-A-passphrase', SAMPLE_RECORDS);

        // Identity B tries to import it with their own passphrase
        await expect(importBackup('identity-B-passphrase', blobA)).rejects.toMatchObject({
            kind: BackupErrorKind.DecryptionFailed,
        });
    });

    test('two exports under different passphrases produce different blobs', async () => {
        const blobA = await exportBackup('pass-A', SAMPLE_RECORDS);
        const blobB = await exportBackup('pass-B', SAMPLE_RECORDS);
        // Blobs must differ (different salts → different ciphertexts)
        expect(blobA).not.toEqual(blobB);
    });
});