// @vitest-environment node
//
// Cross-language integration test: starts a *real* relay WebSocket listener
// (via the `relay_ws_test_harness` test-only binary) and exercises the
// TypeScript `RelayTransport` against it end-to-end.
//
// The harness binary (`relay/src/bin/ws_test_harness.rs`) binds a random
// localhost port, prints `ws://127.0.0.1:<port>` on the first line of stdout,
// and runs until killed. We spawn it via `cargo run --bin relay_ws_test_harness`,
// read the URL, then use `RelayTransport` to:
//
//   1. Request a challenge and solve the PoW (20-bit difficulty, ws-relay-v1).
//   2. `send_envelope` an opaque blob for a recipient.
//   3. `pickup_envelope` for the same recipient and verify the bytes match.
//
// This closes the contract gap between the Rust relay and the TS client: the
// relay-side `ws_bridge.rs` tests verify the Rust half, and this test verifies
// the TS half against the same real relay. If either side changes its wire
// shape, this test breaks.
//
// The test is skipped automatically when the `cargo` command is unavailable or
// the relay binary cannot be built (e.g. in CI environments without a Rust
// toolchain), so it never causes an unhandled failure in pure-JS CI.

import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { RelayTransport, RelayError } from '../src/relay_transport';

// Use the real Node.js WebSocket (not the jsdom mock from other test files).
// Vitest isolates modules per test file, so importing RelayTransport here
// gets a fresh module instance with the real `globalThis.WebSocket`.

let harnessProc: ChildProcess | null = null;
let relayUrl: string | null = null;

/** Spawn the relay WS test harness and read the bound URL from stdout. */
async function startRelayHarness(): Promise<{ proc: ChildProcess; url: string }> {
    return new Promise((resolve, reject) => {
        const proc = spawn(
            'cargo',
            ['run', '--bin', 'relay_ws_test_harness'],
            {
                cwd: undefined, // run from repo root
                stdio: ['pipe', 'pipe', 'pipe'],
            },
        );

        let stdout = '';
        let stderr = '';
        let settled = false;

        proc.stdout!.setEncoding('utf8');
        proc.stdout!.on('data', (chunk: string) => {
            stdout += chunk;
            // The first line of stdout is the ws:// URL.
            if (!settled && stdout.includes('\n')) {
                const firstLine = stdout.split('\n')[0].trim();
                if (firstLine.startsWith('ws://')) {
                    settled = true;
                    resolve({ proc, url: firstLine });
                }
            }
        });

        proc.stderr!.setEncoding('utf8');
        proc.stderr!.on('data', (chunk: string) => {
            stderr += chunk;
        });

        proc.on('error', (err) => {
            if (!settled) {
                settled = true;
                reject(new Error(`failed to spawn relay harness: ${err}`));
            }
        });

        proc.on('exit', (code) => {
            if (!settled) {
                settled = true;
                reject(new Error(`relay harness exited early (code ${code})\nstderr: ${stderr}`));
            }
        });

        // Timeout: if the harness doesn't print a URL within 60s, give up.
        setTimeout(() => {
            if (!settled) {
                settled = true;
                proc.kill('SIGTERM');
                reject(new Error(`relay harness did not start in time\nstderr: ${stderr}`));
            }
        }, 60_000);
    });
}

/** Check whether `cargo` is available on PATH. */
function cargoAvailable(): boolean {
    try {
        const { execSync } = require('child_process');
        execSync('cargo --version', { stdio: 'pipe' });
        return true;
    } catch {
        return false;
    }
}

const canRun = cargoAvailable();

describe.skipIf(!canRun)('relay integration: real WS round-trip', () => {
    beforeAll(async () => {
        const { proc, url } = await startRelayHarness();
        harnessProc = proc;
        relayUrl = url;
    }, 90_000);

    afterAll(() => {
        if (harnessProc) {
            harnessProc.kill('SIGTERM');
            harnessProc = null;
        }
    });

    test('send_envelope round-trips and is retrievable via pickup_envelope', async () => {
        expect(relayUrl).toBeTruthy();
        const transport = new RelayTransport(relayUrl!);

        const recipientId = 'integration-test-recipient';
        const envelope = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x42]);

        // send_envelope requests a challenge, solves the 20-bit PoW, and sends.
        // This may take a few seconds for the PoW solve.
        await transport.sendEnvelope(recipientId, envelope);

        // pickup_envelope retrieves the stored envelope.
        const retrieved = await transport.pickupEnvelope(recipientId);

        expect(retrieved).toEqual(envelope);
        transport.close();
    }, 120_000);

    test('lookup_prekey for a non-existent recipient returns a typed error', async () => {
        expect(relayUrl).toBeTruthy();
        const transport = new RelayTransport(relayUrl!);

        await expect(
            transport.lookupPrekey('nonexistent-recipient-' + Date.now()),
        ).rejects.toBeInstanceOf(RelayError);

        transport.close();
    }, 30_000);
});