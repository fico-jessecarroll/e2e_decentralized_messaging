# Web client

React app consuming the shared Rust core via WASM bindings (`core/bindings/wasm`).
Scaffolded per PLAN.md §6 / Phase 8 — implementation not yet started. See PLAN.md §5 for the
documented reduced threat model on web (no secure enclave).

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
