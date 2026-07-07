// React web client smoke test.
//!
//! Anchors PLAN.md Phase 8 acceptance criteria:
//!  - Web client performs the desktop smoke-test flow successfully
//!  - Warning about reduced threat model is shown before first use
//!  - Negative: web client fails closed if IndexedDB/storage access is unavailable

import { performSmokeFlow, threatModelWarning, StorageGate } from "../src";

describe("web smoke flow", () => {
    test("desktop smoke flow roundtrip succeeds", async () => {
        const plaintext = new TextEncoder().encode("hello from the web");
        const result = await performSmokeFlow(plaintext);
        expect(result).toEqual(plaintext);
    });

    test("reduced-threat-model warning is shown before first use", () => {
        const banner = threatModelWarning();
        expect(banner.length).toBeGreaterThan(0);
        expect(banner.toLowerCase()).toMatch(/reduced|no secure enclave|browser key-storage/);
    });

    test("fails closed if IndexedDB is unavailable", async () => {
        // Simulate IndexedDB missing: StorageGate.open() must throw rather
        // than fall back to a weaker in-memory store silently.
        const gate = new StorageGate({ indexedDB: undefined });
        await expect(gate.open()).rejects.toThrow(/storage unavailable/i);
    });
});
