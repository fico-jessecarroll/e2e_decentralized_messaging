/** @vitest-environment jsdom */
import { getStorageKey } from '../src/storage_key';

describe('storage_key (AES key for StorageGate)', () => {
  afterEach(() => {
    localStorage.clear();
  });

  it('returns a 32-byte key (AES-256)', () => {
    const key = getStorageKey();
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it('never returns an all-zero key (OWASP A3 regression guard)', () => {
    const key = getStorageKey();
    const allZero = key.every((b) => b === 0);
    expect(allZero).toBe(false);
  });

  it('returns the same key across calls (persisted in localStorage)', () => {
    const key1 = getStorageKey();
    const key2 = getStorageKey();
    expect(Array.from(key2)).toEqual(Array.from(key1));
  });

  it('returns the same key across a simulated reload (clear module cache)', async () => {
    const key1 = getStorageKey();
    // Simulate a reload: clear the module cache and re-import.
    vi.resetModules();
    const { getStorageKey: freshGetStorageKey } = await import('../src/storage_key');
    const key2 = freshGetStorageKey();
    expect(Array.from(key2)).toEqual(Array.from(key1));
  });

  it('generates a cryptographically strong key (high entropy)', () => {
    // A truly random 32-byte key should have a large number of distinct byte
    // values.  An all-zero or low-entropy key would fail this.
    const key = getStorageKey();
    const distinct = new Set(Array.from(key));
    // With 256 possible values and 32 bytes, a random key will almost
    // always have >20 distinct values.  Use a conservative threshold.
    expect(distinct.size).toBeGreaterThan(15);
  });
});