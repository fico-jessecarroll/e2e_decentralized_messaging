// @vitest-environment jsdom
import { vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BackupPanel } from '../src/BackupPanel';
import { getStoragePassword } from '../src/storage_key';

// Mock BrowserStorage to capture constructor argument
vi.mock('../src/browser_storage', () => {
  return {
    BrowserStorage: class {
      constructor(password: string) {
        (globalThis as any).__lastBrowserStoragePassword = password;
      }
    },
  };
});

test('BackupPanel does not use hardcoded default literal for storage key', () => {
  render(<BackupPanel storagePassword={getStoragePassword()} />);
  const pwd = (globalThis as any).__lastBrowserStoragePassword;
  expect(pwd).not.toBe('default');
});

test('different persisted keys produce different derived passwords', () => {
  // Ensure localStorage is clear
  localStorage.removeItem('messaging-storage-key');
  const pwd1 = getStoragePassword();
  // Set a new random key in storage
  const fakeKey = crypto.getRandomValues(new Uint8Array(32));
  localStorage.setItem('messaging-storage-key', btoa(String.fromCharCode(...fakeKey)));
  const pwd2 = getStoragePassword();
  expect(pwd1).not.toBe(pwd2);
});
