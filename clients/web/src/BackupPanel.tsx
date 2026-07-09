/**
 * BackupPanel — UI for encrypted backup export (download) and import (upload).
 *
 * Export: reads all records from the BrowserStorage layer, encrypts them under
 * a user-supplied passphrase using the backup format (src/backup.ts), and
 * triggers a browser file download.
 *
 * Import: reads a user-selected file, decrypts it under the passphrase, and
 * restores the records into the BrowserStorage layer. Import is atomic —
 * on any failure (corrupted file, wrong passphrase, different identity), no
 * records are written and existing state is preserved.
 *
 * Security notes:
 *  - The passphrase is never logged or persisted beyond the input field's
 *    React state lifetime.
 *  - Error messages are non-leaky (no plaintext/ciphertext/key terminology).
 *  - Import validates the entire blob before writing anything to storage.
 */

import React, { useRef, useState } from 'react';
import { BrowserStorage } from './browser_storage';
import {
    exportBackup,
    importBackup,
    BackupError,
    BackupErrorKind,
} from './backup';
import './BackupPanel.css';

/**
 * Collect all key→value pairs from the `kv` store as serialized records.
 * Each record is a JSON-encoded {key, value} object converted to bytes.
 * This preserves the key association so import can restore the exact mapping.
 */
async function collectKeyedRecords(storage: BrowserStorage): Promise<Uint8Array[]> {
    const db = (storage as any).db as IDBDatabase | undefined;
    if (!db) throw new Error('storage not opened');

    return new Promise<Uint8Array[]>((resolve, reject) => {
        const tx = db.transaction(['kv'], 'readonly');
        const store = tx.objectStore('kv');
        const req = store.openCursor();
        const records: Uint8Array[] = [];

        req.onerror = () => reject(req.error || new Error('read failed'));
        req.onsuccess = () => {
            const cursor = req.result;
            if (cursor) {
                const key = cursor.key as string;
                const value = cursor.value as Uint8Array;
                // Serialize as {key, value: base64} to preserve the key→blob mapping.
                // The value is already an encrypted Uint8Array (iv ‖ ciphertext).
                const entry = JSON.stringify({
                    k: key,
                    v: Array.from(value),
                });
                records.push(new TextEncoder().encode(entry));
                cursor.continue();
            } else {
                if (records.length === 0) {
                    reject(new Error('no data to export'));
                    return;
                }
                resolve(records);
            }
        };
    });
}

/**
 * Restore key→value pairs into the `kv` store atomically.
 * Each record is a JSON-encoded {k, v} object.
 */
async function restoreKeyedRecords(
    storage: BrowserStorage,
    records: Uint8Array[],
): Promise<void> {
    const db = (storage as any).db as IDBDatabase | undefined;
    if (!db) throw new Error('storage not opened');

    // Parse all records first — if any fail to parse, we abort before
    // touching the database. This is the "validate before write" pattern
    // that ensures no partial overwrite on failure.
    const entries: { k: string; v: Uint8Array }[] = [];
    for (const record of records) {
        try {
            const text = new TextDecoder().decode(record);
            const obj = JSON.parse(text);
            if (typeof obj.k !== 'string' || !Array.isArray(obj.v)) {
                throw new Error('invalid record format');
            }
            entries.push({ k: obj.k, v: new Uint8Array(obj.v) });
        } catch {
            throw new Error('invalid record format');
        }
    }

    return new Promise<void>((resolve, reject) => {
        const tx = db.transaction(['kv'], 'readwrite');
        const store = tx.objectStore('kv');

        // Clear existing, then write all new entries in the same transaction.
        const clearReq = store.clear();
        clearReq.onerror = () => reject(clearReq.error || new Error('clear failed'));

        for (const entry of entries) {
            const putReq = store.put(entry.v, entry.k);
            putReq.onerror = () => reject(putReq.error || new Error('write failed'));
        }

        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error || new Error('transaction failed'));
        tx.onabort = () => reject(tx.error || new Error('transaction aborted'));
    });
}

/** Trigger a browser file download for the given blob bytes. */
function downloadBackup(bytes: Uint8Array, filename: string): void {
    const blob = new Blob([bytes as BlobPart], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/** Read a File as Uint8Array. */
function readFileAsBytes(file: File): Promise<Uint8Array> {
    return new Promise<Uint8Array>((resolve, reject) => {
        const reader = new FileReader();
        reader.onerror = () => reject(reader.error || new Error('file read failed'));
        reader.onload = () => {
            const result = reader.result;
            if (result instanceof ArrayBuffer) {
                resolve(new Uint8Array(result));
            } else {
                reject(new Error('unexpected file read result'));
            }
        };
        reader.readAsArrayBuffer(file);
    });
}

export interface BackupPanelProps {
    /** Password for the BrowserStorage instance (the at-rest encryption key source). */
    storagePassword: string;
}

export const BackupPanel: React.FC<BackupPanelProps> = ({ storagePassword }) => {
    const [passphrase, setPassphrase] = useState('');
    const [status, setStatus] = useState('');
    const [busy, setBusy] = useState(false);
    const fileInputRef = useRef<HTMLInputElement>(null);

    const handleExport = async () => {
        if (!passphrase) {
            setStatus('Please enter a backup passphrase.');
            return;
        }
        setBusy(true);
        setStatus('Preparing backup…');
        try {
            const storage = new BrowserStorage(storagePassword);
            await storage.open();
            const records = await collectKeyedRecords(storage);
            const blob = await exportBackup(passphrase, records);
            const date = new Date().toISOString().slice(0, 10);
            downloadBackup(blob, `encrypted-backup-${date}.ecb`);
            setStatus('Backup downloaded successfully.');
        } catch (e) {
            if (e instanceof BackupError) {
                setStatus(e.message);
            } else {
                setStatus('Backup failed: ' + (e as Error).message);
            }
        } finally {
            setBusy(false);
        }
    };

    const handleImport = async () => {
        const fileInput = fileInputRef.current;
        if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
            setStatus('Please select a backup file.');
            return;
        }
        if (!passphrase) {
            setStatus('Please enter a backup passphrase.');
            return;
        }
        setBusy(true);
        setStatus('Reading backup file…');
        try {
            const file = fileInput.files[0];
            const bytes = await readFileAsBytes(file);

            // Decrypt and validate the entire backup BEFORE touching storage.
            // importBackup is atomic — it either returns all records or throws.
            const records = await importBackup(passphrase, bytes);

            setStatus('Restoring into local storage…');
            const storage = new BrowserStorage(storagePassword);
            await storage.open();
            await restoreKeyedRecords(storage, records);
            setStatus('Backup restored successfully.');
        } catch (e) {
            if (e instanceof BackupError) {
                setStatus(e.message);
            } else {
                setStatus('Import failed: ' + (e as Error).message);
            }
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="backup-panel">
            <div className="backup-field">
                <label>
                    Backup passphrase:{' '}
                    <input
                        type="password"
                        value={passphrase}
                        onChange={e => setPassphrase(e.target.value)}
                        placeholder="Passphrase"
                        disabled={busy}
                        autoComplete="off"
                    />
                </label>
            </div>
            <div className="backup-actions">
                <button onClick={handleExport} disabled={busy}>
                    Export Backup
                </button>
                <input
                    ref={fileInputRef}
                    type="file"
                    accept=".ecb,application/octet-stream"
                    disabled={busy}
                    aria-label="Backup file"
                    className="backup-file-input"
                />
                <button onClick={handleImport} disabled={busy}>
                    Import Backup
                </button>
            </div>
            {status && <p className="backup-status">{status}</p>}
        </div>
    );
};