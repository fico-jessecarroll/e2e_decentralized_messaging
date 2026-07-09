# Web client

## Build prerequisites

The web client consumes the shared Rust core via WASM bindings (`core/bindings/wasm`). Building and running the client requires:

* **Rust** with the `wasm32-unknown-unknown` target installed (e.g., `rustup target add wasm32-unknown-unknown`).
* **wasm-pack** (installed via npm or Cargo). The build scripts invoke `wasm-pack build --target bundler` to generate ES‑module bindings.

These prerequisites are only needed for local development and CI builds; the published NPM package does not contain the generated WASM artifacts.

## Setup

```sh
npm install
```

## Build the WASM bindings

`npm run dev`, `npm run build`, and `npm test` all invoke this automatically via a
`prepare-wasm` pre-step, so you normally don't need to run it by hand:

```sh
npm run prepare-wasm
```

This runs `wasm-pack build --target bundler` against `core/bindings/wasm` and writes
the generated ES-module bindings to `pkg/` (gitignored, regenerated on demand).

## Run the dev server

```sh
npm run dev
```

## Run the test suite

```sh
npm test
```

Runs the Vitest suite (`vitest run`) after regenerating the WASM bindings.

## Build for production

```sh
npm run build
```

## Relay WebSocket transport

`src/relay_websocket_transport.ts` implements the relay's real WebSocket wire
protocol (as documented in `relay/src/ws.rs`):

1. **Challenge** — sends `{"op":"challenge","recipient_id":"..."}` and receives
   `{"ok":true,"challenge":"<base64>","challenge_id":"<hex>"}`. The `challenge`
   field is the base64-encoded wire bytes of `pow::Challenge::to_wire()`.
2. **PoW solve** — the client decodes the challenge wire bytes, then brute-forces
   an 8-byte little-endian u64 counter so that
   `SHA-256(context || nonce || solution)` has `difficulty` leading zero bits
   (20-bit difficulty, context `ws-relay-v1` — matching `relay/src/pow/mod.rs`).
3. **publish_prekey / send_envelope** — include `challenge_id` (hex) and
   `pow_solution` (base64 of the 8-byte solution) alongside the base64 payload.
4. **lookup_prekey / pickup_envelope** — read-only ops, no PoW required.

### Relay URL configuration

The relay URL is **not hardcoded**. It is resolved at runtime by
`getRelayWsUrl()` with this precedence:

1. `localStorage['relayWsUrl']` (runtime override, highest precedence)
2. `VITE_RELAY_WS_URL` environment variable (build-time, set in `.env`)
3. Default: `ws://127.0.0.1:8000`

```sh
# Build-time override via .env
echo 'VITE_RELAY_WS_URL=ws://relay.example.com:8000' > .env.local
npm run build
```

### Error handling

All relay errors propagate as `RelayError` (a typed `Error` subclass) — they are
never swallowed. This includes:

- `{ok:false,error:"..."}` responses from any op
- Malformed/invalid JSON responses (fail closed with a caught error)
- Connection failures and timeouts (visible error state, not a silent hang)
- PoW solve failures (out-of-range difficulty, exceeded iteration cap)

React app consuming the shared Rust core via WASM bindings (`core/bindings/wasm`).
See PLAN.md §5 for the documented reduced threat model on web (no secure enclave).

## Encrypted storage API

Two IndexedDB-backed encrypted storage modules are exported from `src/index.ts`:

### `StorageGate`

Parity with `core/storage` — identity/session/prekey state and message history,
encrypted at rest with AES-256-GCM via WebCrypto, fail-closed on a bad key or
corrupt data.

```ts
import { StorageGate } from '@e2e-decentralized-messaging/web-client';

const gate = new StorageGate({
  indexedDB: window.indexedDB,
  keyBytes: rawKey, // 32-byte AES-256 key
});
await gate.open(); // throws if IndexedDB unavailable or key is wrong length
await gate.put('identity', 'self', { name: 'Alice' });
const val = await gate.get('identity', 'self'); // null if missing, throws on tamper
```

Store names: `'identity' | 'session' | 'prekey' | 'messages'`. The CryptoKey is
imported as non-extractable so raw key material cannot be exfiltrated from JS.

### Safety-number verification (`SafetyNumberVerification`)

The `SafetyNumberVerification` component displays the safety number for a
conversation by calling the WASM `derive_safety_number` binding (real
derivation from the local and remote identity keys — not a placeholder).

**Persistence.** The verified/unverified state is persisted per
`conversationId` via `StorageGate` (encrypted IndexedDB, store `'identity'`,
key `safety-number:<conversationId>`). The stored record includes the remote
identity key (base64) that was present at the time of verification, so it
survives a page reload.

**TOFU (Trust On First Use) handling.** On load, if the current remote
identity key differs from the key stored alongside the last `verified: true`
record, the verified flag is **cleared** and a visible warning
(`role="alert"`) is surfaced — the verified state is never silently carried
forward onto a changed key. The user must explicitly re-verify against the
new safety number.

### `BrowserStorage`

A simpler key/value store that derives its AES-256-GCM key from a password via
PBKDF2 (SHA-256, 100k iterations). Same fail-closed guarantees.

```ts
import { BrowserStorage } from '@e2e-decentralized-messaging/web-client';

const storage = new BrowserStorage('user-password');
await storage.open();
await storage.setItem('identity', { name: 'Alice' });
const val = await storage.getItem('identity'); // null if missing, throws on tamper
await storage.deleteItem('identity');
```
