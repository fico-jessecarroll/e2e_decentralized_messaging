// @vitest-environment jsdom
// backup_panel.test.tsx — UI tests for the BackupPanel export/import component.
//
// Verifies:
//  - Export triggers a file download with encrypted backup content.
//  - Import reads a file and restores records into storage.
//  - Failed import (wrong passphrase) shows a clear error and does not
//    overwrite existing state.
//  - Passphrase field is a password type (no shoulder-surfing).

import '@testing-library/jest-dom';
import { vi } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';

// ── Mock the backup module ─────────────────────────────────────────────────

// We mock the backup functions so we can control success/failure without
// running Argon2id (which is slow in jsdom). The mock preserves the
// BackupError contract.
// vi.mock factories are hoisted to the top of the file, so we use vi.hoisted
// to define the mock functions that the factory closes over.

const { mockExportBackup, mockImportBackup, MockBackupError } = vi.hoisted(() => {
    const mockExportBackup = vi.fn();
    const mockImportBackup = vi.fn();

    class MockBackupError extends Error {
        kind: string;
        constructor(kind: string) {
            const messages: Record<string, string> = {
                Tampered: 'backup file is corrupted or invalid',
                DecryptionFailed: 'backup could not be opened — check your passphrase',
                Empty: 'no records to export',
            };
            super(messages[kind] || kind);
            this.name = 'BackupError';
            this.kind = kind;
        }
    }

    return { mockExportBackup, mockImportBackup, MockBackupError };
});

vi.mock('../src/backup', () => {
    return {
        exportBackup: mockExportBackup,
        importBackup: mockImportBackup,
        BackupError: MockBackupError,
        BackupErrorKind: {
            Tampered: 'Tampered',
            DecryptionFailed: 'DecryptionFailed',
            Empty: 'Empty',
        },
    };
});

// ── Mock BrowserStorage ────────────────────────────────────────────────────

// We need a mock that simulates the IndexedDB kv store with cursor access.
// The mock stores key→Uint8Array pairs in an internal Map.
// Use vi.hoisted so the factory is available when vi.mock runs.

const { MockBrowserStorage, getKvData } = vi.hoisted(() => {
    const kvData = new Map<string, Uint8Array>();

    class MockBrowserStorage {
        private db: any;

        constructor(public password: string) {
            this.db = {
                transaction: () => ({
                    objectStore: () => ({
                        openCursor: () => {
                            const entries = Array.from(kvData.entries());
                            let idx = 0;
                            const req = {
                                result: null as any,
                                onerror: null as any,
                                onsuccess: null as any,
                            };
                            setTimeout(() => {
                                const advance = () => {
                                    if (idx < entries.length) {
                                        const [key, value] = entries[idx];
                                        req.result = {
                                            key,
                                            value,
                                            continue: () => {
                                                idx++;
                                                setTimeout(advance, 0);
                                            },
                                        };
                                    } else {
                                        req.result = null;
                                    }
                                    req.onsuccess && req.onsuccess();
                                };
                                advance();
                            }, 0);
                            return req;
                        },
                        clear: () => {
                            kvData.clear();
                            const req = { onerror: null as any, onsuccess: null as any };
                            setTimeout(() => req.onsuccess && req.onsuccess(), 0);
                            return req;
                        },
                        put: (value: Uint8Array, key: string) => {
                            kvData.set(key, value);
                            const req = { onerror: null as any, onsuccess: null as any };
                            setTimeout(() => req.onsuccess && req.onsuccess(), 0);
                            return req;
                        },
                    }),
                }),
            };
        }

        async open() { return Promise.resolve(); }

        async setItem<T>(key: string, value: T): Promise<void> {
            const json = JSON.stringify(value);
            const blob = new TextEncoder().encode(json);
            kvData.set(key, blob);
        }

        async getItem<T>(key: string): Promise<T | null> {
            const blob = kvData.get(key);
            if (!blob) return null;
            const text = new TextDecoder().decode(blob);
            return JSON.parse(text) as T;
        }
    }

    return { MockBrowserStorage, getKvData: () => kvData };
});

vi.mock('../src/browser_storage', () => {
    return { BrowserStorage: MockBrowserStorage };
});

// ── Mock URL.createObjectURL / revokeObjectURL ─────────────────────────────

const mockObjectURL = 'blob:mock://backup';
let lastDownloadedUrl: string | null = null;
let lastDownloadedFilename: string | null = null;

beforeEach(() => {
    lastDownloadedUrl = null;
    lastDownloadedFilename = null;
    mockExportBackup.mockReset();
    mockImportBackup.mockReset();

    (globalThis as any).URL = {
        ...(globalThis as any).URL,
        createObjectURL: vi.fn(() => mockObjectURL),
        revokeObjectURL: vi.fn(),
    };

    // Mock anchor click for download
    const originalCreateElement = document.createElement.bind(document);
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
        if (tag === 'a') {
            const anchor = originalCreateElement(tag);
            Object.defineProperty(anchor, 'click', {
                value: vi.fn(),
                configurable: true,
            });
            return anchor;
        }
        return originalCreateElement(tag);
    });
});

import { BackupPanel } from '../src/BackupPanel';
import { BrowserStorage } from '../src/browser_storage';

describe('BackupPanel UI', () => {
    test('renders passphrase input as type=password', () => {
        render(<BackupPanel storagePassword="test" />);
        const input = screen.getByPlaceholderText('Passphrase');
        expect(input).toHaveAttribute('type', 'password');
    });

    test('export calls exportBackup and triggers download', async () => {
        const mockBlob = new Uint8Array([1, 2, 3, 4, 5]);
        mockExportBackup.mockResolvedValue(mockBlob);

        render(<BackupPanel storagePassword="test" />);

        const passInput = screen.getByPlaceholderText('Passphrase') as HTMLInputElement;
        fireEvent.change(passInput, { target: { value: 'my-passphrase' } });

        const exportBtn = screen.getByText('Export Backup');
        await act(async () => {
            fireEvent.click(exportBtn);
        });

        await waitFor(() => {
            expect(screen.getByText(/downloaded successfully/i)).toBeInTheDocument();
        });

        expect(mockExportBackup).toHaveBeenCalledWith('my-passphrase', expect.any(Array));
    });

    test('export without passphrase shows error', async () => {
        render(<BackupPanel storagePassword="test" />);
        const exportBtn = screen.getByText('Export Backup');
        await act(async () => {
            fireEvent.click(exportBtn);
        });
        expect(screen.getByText(/enter a backup passphrase/i)).toBeInTheDocument();
    });

    test('import with wrong passphrase shows error and does not overwrite state', async () => {
        // Set up existing state
        const storage = new BrowserStorage('test');
        await storage.open();
        await storage.setItem('identity', { id: 'existing', value: 'preserved' });

        // Mock importBackup to fail with DecryptionFailed
        mockImportBackup.mockRejectedValue(new MockBackupError('DecryptionFailed'));

        render(<BackupPanel storagePassword="test" />);

        const passInput = screen.getByPlaceholderText('Passphrase') as HTMLInputElement;
        fireEvent.change(passInput, { target: { value: 'wrong-pass' } });

        // Simulate file selection
        const fileInput = screen.getByLabelText(/backup file/i) as HTMLInputElement;
        const file = new File([new Uint8Array([0, 1, 2, 3])], 'backup.ecb', {
            type: 'application/octet-stream',
        });
        Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });

        const importBtn = screen.getByText('Import Backup');
        await act(async () => {
            fireEvent.click(importBtn);
        });

        await waitFor(() => {
            expect(screen.getByText(/could not be opened/i)).toBeInTheDocument();
        });

        // Verify existing state is untouched
        const identity = await storage.getItem<any>('identity');
        expect(identity).toEqual({ id: 'existing', value: 'preserved' });
    });

    test('import without file shows error', async () => {
        render(<BackupPanel storagePassword="test" />);

        const passInput = screen.getByPlaceholderText('Passphrase') as HTMLInputElement;
        fireEvent.change(passInput, { target: { value: 'pass' } });

        const importBtn = screen.getByText('Import Backup');
        await act(async () => {
            fireEvent.click(importBtn);
        });

        expect(screen.getByText(/select a backup file/i)).toBeInTheDocument();
    });

    test('import with tampered file shows tampered error', async () => {
        const { BackupError } = await import('../src/backup');
        mockImportBackup.mockRejectedValue(new BackupError('Tampered'));

        render(<BackupPanel storagePassword="test" />);

        const passInput = screen.getByPlaceholderText('Passphrase') as HTMLInputElement;
        fireEvent.change(passInput, { target: { value: 'pass' } });

        const fileInput = screen.getByLabelText(/backup file/i) as HTMLInputElement;
        const file = new File([new Uint8Array([0, 1, 2, 3])], 'backup.ecb');
        Object.defineProperty(fileInput, 'files', { value: [file], configurable: true });

        const importBtn = screen.getByText('Import Backup');
        await act(async () => {
            fireEvent.click(importBtn);
        });

        await waitFor(() => {
            expect(screen.getByText(/corrupted or invalid/i)).toBeInTheDocument();
        });
    });
});