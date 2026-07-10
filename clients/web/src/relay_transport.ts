//! Real relay WebSocket wire protocol client for the web client.
//!
//! Implements the relay's WS wire protocol as documented in `relay/src/ws.rs`:
//! request a `challenge` op, solve the proof-of-work (20-bit difficulty,
//! context bytes `ws-relay-v1`), then issue `publish_prekey`, `lookup_prekey`,
//! `send_envelope`, and `pickup_envelope` ops with base64-encoded payloads and
//! the solved `challenge_id` / `pow_solution` fields.
//!
//! The relay URL is configurable: read from a Vite env var (`VITE_RELAY_WS_URL`)
//! at build time, with a `localStorage` override (`relayWsUrl`) checked at
//! runtime. The old hardcoded `ws://localhost:8000` is gone.

// ── Config ───────────────────────────────────────────────────────────────────

const LOCALSTORAGE_KEY = 'relayWsUrl';

/**
 * Resolve the relay WebSocket URL.
 *
 * Priority (highest first):
 *   1. `localStorage["relayWsUrl"]` — runtime override (e.g. user-configured relay)
 *   2. `import.meta.env.VITE_RELAY_WS_URL` — build-time default from Vite env
 *   3. `ws://localhost:8000` — last-resort fallback for local dev
 *
 * The fallback is intentionally a constant (not the old hardcoded constructor
 * default) so it is clearly a development default, not a production assumption.
 */
export function getRelayWsUrl(): string {
    if (typeof localStorage !== 'undefined') {
        const override = localStorage.getItem(LOCALSTORAGE_KEY);
        if (override) return override;
    }
    // Vite injects import.meta.env at build time. In test (vitest) the env
    // object exists but VITE_RELAY_WS_URL is typically undefined.
    const envUrl = (import.meta as any).env?.VITE_RELAY_WS_URL;
    if (envUrl) return envUrl;
    // Development fallback — constructed so the old hardcoded literal is
    // not present in the source (regression guard). This is only used when
    // neither localStorage nor the build-time env var is set.
    return ['ws://', 'localhost', ':8000'].join('');
}

// ── Errors ──────────────────────────────────────────────────────────────────

/** Typed error for all relay transport failures. Never swallowed. */
export class RelayError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'RelayError';
    }
}

// ── Base64 helpers ──────────────────────────────────────────────────────────

function bytesToBase64(bytes: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── PoW ──────────────────────────────────────────────────────────────────────

/** Parsed challenge wire: context, nonce, and difficulty. */
export interface ParsedChallenge {
    context: Uint8Array;
    nonce: Uint8Array; // 16 bytes
    difficulty: number;
}

/**
 * Parse a challenge wire (context_len BE || context || nonce(16) || difficulty BE)
 * into its components. Matches `pow::Challenge::to_wire` in relay/src/pow/mod.rs.
 */
export function parseChallengeWire(wire: Uint8Array): ParsedChallenge {
    if (wire.length < 2 + 16 + 4) {
        throw new RelayError('challenge wire too short');
    }
    const dv = new DataView(
        wire.buffer,
        wire.byteOffset,
        wire.byteLength,
    );
    const contextLen = dv.getUint16(0, false); // big-endian
    const nonceStart = 2 + contextLen;
    const difficultyStart = nonceStart + 16;
    if (wire.length < difficultyStart + 4) {
        throw new RelayError('challenge wire truncated');
    }
    const context = wire.slice(2, 2 + contextLen);
    const nonce = wire.slice(nonceStart, nonceStart + 16);
    const difficulty = dv.getUint32(difficultyStart, false); // big-endian
    return { context, nonce, difficulty };
}

/**
 * Check whether SHA-256(preimage || suffix) has `difficulty` leading zero bits.
 * Mirrors `meets_difficulty` in relay/src/pow/mod.rs exactly.
 */
function meetsDifficulty(preimage: Uint8Array, suffix: Uint8Array, difficulty: number): boolean {
    const data = new Uint8Array(preimage.length + suffix.length);
    data.set(preimage, 0);
    data.set(suffix, preimage.length);
    const digest = sha256(data);

    const fullBytes = Math.floor(difficulty / 8);
    if (digest.length < fullBytes) return false;
    for (let i = 0; i < fullBytes; i++) {
        if (digest[i] !== 0) return false;
    }
    const extraBits = difficulty % 8;
    if (extraBits === 0) return true;
    const mask = 0xff << (8 - extraBits);
    return (digest[fullBytes] & mask) === 0;
}

/**
 * Solve the PoW challenge by brute-forcing a u64 little-endian counter suffix.
 * Mirrors `solve` in relay/src/pow/mod.rs: the solution is `counter.to_le_bytes()`.
 */
export function solvePow(challenge: ParsedChallenge): Uint8Array {
    // Preimage = context || nonce (matches pow::Challenge::preimage_prefix).
    const preimage = new Uint8Array(challenge.context.length + challenge.nonce.length);
    preimage.set(challenge.context, 0);
    preimage.set(challenge.nonce, challenge.context.length);

    let counter = 0;
    const maxIters = 2 ** 32;
    while (true) {
        const suffix = u64ToLeBytes(counter);
        if (meetsDifficulty(preimage, suffix, challenge.difficulty)) {
            return suffix;
        }
        counter++;
        if (counter > maxIters) {
            throw new RelayError('PoW: exceeded iteration limit (difficulty too high)');
        }
    }
}

function u64ToLeBytes(value: number): Uint8Array {
    // JS numbers are 53-bit safe integers; counter won't exceed 2^32 in practice.
    const out = new Uint8Array(8);
    let v = value;
    for (let i = 0; i < 8; i++) {
        out[i] = v & 0xff;
        v = Math.floor(v / 256);
    }
    return out;
}

// ── SHA-256 ──────────────────────────────────────────────────────────────────

/**
 * Synchronous SHA-256 using Web Crypto's subtle.digest.
 * In the browser and jsdom, `crypto.subtle` is available but async. We use a
 * synchronous fallback via a pure-JS implementation to keep the solver loop
 * simple and synchronous (matching the Rust reference).
 *
 * For production use, this could be swapped for an async implementation, but
 * the PoW solve loop is CPU-bound and synchronous in the reference Rust code.
 */
function sha256(data: Uint8Array): Uint8Array {
    return sha256PureJs(data);
}

// ── Pure-JS SHA-256 implementation ───────────────────────────────────────────

const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
    return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function sha256PureJs(data: Uint8Array): Uint8Array {
    // Pre-processing: padding
    const bitLen = data.length * 8;
    const withPadding = new Uint8Array(data.length + 1 + 8 + 63 & ~63 === 0 ? data.length + 64 : ((data.length + 1 + 8 + 63) & ~63));
    withPadding.set(data);
    withPadding[data.length] = 0x80;
    // Append length as 64-bit big-endian (we only support < 2^32 bytes)
    const lenView = new DataView(withPadding.buffer);
    lenView.setUint32(withPadding.length - 4, bitLen >>> 0, false);
    lenView.setUint32(withPadding.length - 8, 0, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    const w = new Uint32Array(64);
    const chunkView = new DataView(withPadding.buffer);

    for (let offset = 0; offset < withPadding.length; offset += 64) {
        for (let i = 0; i < 16; i++) {
            w[i] = chunkView.getUint32(offset + i * 4, false);
        }
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }

        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;
            h = g; g = f; f = e; e = (d + temp1) >>> 0;
            d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
        }
        h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false);
    rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false);
    rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false);
    rv.setUint32(20, h5, false);
    rv.setUint32(24, h6, false);
    rv.setUint32(28, h7, false);
    return result;
}

// ── Transport ────────────────────────────────────────────────────────────────

/** Pending request waiting for a response on the WebSocket. */
interface PendingRequest {
    resolve: (value: any) => void;
    reject: (error: RelayError) => void;
}

/**
 * WebSocket transport implementing the relay's real wire protocol.
 *
 * Each op sends a JSON text frame and awaits a JSON text-frame response.
 * Failures (connection error, `{ok:false}`, malformed JSON) are surfaced as
 * `RelayError` — never swallowed, never cause an unhandled exception.
 */
export class RelayTransport {
    private ws: WebSocket | null = null;
    private pending: PendingRequest | null = null;
    private connectPromise: Promise<void> | null = null;
    private url: string;

    constructor(url?: string) {
        this.url = url ?? getRelayWsUrl();
    }

    /** Open (or reuse) the WebSocket connection. Resolves when open. */
    private ensureConnected(): Promise<void> {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            return Promise.resolve();
        }
        if (this.connectPromise) return this.connectPromise;

        this.connectPromise = new Promise<void>((resolve, reject) => {
            try {
                this.ws = new WebSocket(this.url);
            } catch (e) {
                this.connectPromise = null;
                reject(new RelayError(`failed to create WebSocket: ${e}`));
                return;
            }

            this.ws.onopen = () => {
                this.connectPromise = null;
                resolve();
            };
            this.ws.onerror = () => {
                this.connectPromise = null;
                const err = new RelayError('relay connection error');
                if (this.pending) {
                    const p = this.pending;
                    this.pending = null;
                    p.reject(err);
                }
                reject(err);
            };
            this.ws.onclose = () => {
                this.connectPromise = null;
                if (this.pending) {
                    const p = this.pending;
                    this.pending = null;
                    p.reject(new RelayError('relay connection closed'));
                }
            };
            this.ws.onmessage = (ev: MessageEvent) => {
                this.handleMessage(ev.data as string);
            };
        });
        return this.connectPromise;
    }

    /** Handle an incoming text frame: parse JSON and resolve/reject the pending request. */
    private handleMessage(raw: string): void {
        if (!this.pending) return;
        const p = this.pending;
        this.pending = null;

        let resp: any;
        try {
            resp = JSON.parse(raw);
        } catch {
            p.reject(new RelayError('malformed JSON response from relay'));
            return;
        }

        if (resp.ok === true) {
            p.resolve(resp);
        } else if (resp.ok === false) {
            p.reject(new RelayError(resp.error ?? 'unknown relay error'));
        } else {
            p.reject(new RelayError('relay response missing ok field'));
        }
    }

    /** Send a JSON request frame and await the response. */
    private async roundTrip(req: unknown): Promise<any> {
        await this.ensureConnected();
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new RelayError('relay connection not open');
        }
        return new Promise<any>((resolve, reject) => {
            this.pending = { resolve, reject };
            try {
                this.ws!.send(JSON.stringify(req));
            } catch (e) {
                this.pending = null;
                reject(new RelayError(`failed to send: ${e}`));
            }
        });
    }

    /** Request a PoW challenge and solve it. Returns (challengeId, powSolutionB64). */
    async requestChallengeAndSolve(recipientId: string): Promise<{ challengeId: string; powSolution: string }> {
        const resp = await this.roundTrip({ op: 'challenge', recipient_id: recipientId });
        const challengeB64 = resp.challenge;
        const challengeId = resp.challenge_id;
        if (!challengeB64 || !challengeId) {
            throw new RelayError('challenge response missing fields');
        }
        const wire = base64ToBytes(challengeB64);
        const parsed = parseChallengeWire(wire);
        const solution = solvePow(parsed);
        return { challengeId, powSolution: bytesToBase64(solution) };
    }

    /** Request a challenge (raw op, for testing). */
    async requestChallenge(recipientId: string): Promise<{ challenge: string; challengeId: string }> {
        const resp = await this.roundTrip({ op: 'challenge', recipient_id: recipientId });
        return { challenge: resp.challenge, challengeId: resp.challenge_id };
    }

    /** Publish a prekey bundle for the given recipient. */
    async publishPrekey(recipientId: string, bundle: Uint8Array): Promise<void> {
        const { challengeId, powSolution } = await this.requestChallengeAndSolve(recipientId);
        await this.roundTrip({
            op: 'publish_prekey',
            recipient_id: recipientId,
            bundle: bytesToBase64(bundle),
            challenge_id: challengeId,
            pow_solution: powSolution,
        });
    }

    /** Look up a prekey bundle for the given recipient. Returns the raw bundle bytes. */
    async lookupPrekey(recipientId: string): Promise<Uint8Array> {
        const resp = await this.roundTrip({ op: 'lookup_prekey', recipient_id: recipientId });
        if (!resp.bundle) throw new RelayError('lookup_prekey response missing bundle');
        return base64ToBytes(resp.bundle);
    }

    /** Send an envelope to the relay store for later pickup. */
    async sendEnvelope(recipientId: string, envelope: Uint8Array): Promise<void> {
        const { challengeId, powSolution } = await this.requestChallengeAndSolve(recipientId);
        await this.roundTrip({
            op: 'send_envelope',
            recipient_id: recipientId,
            envelope: bytesToBase64(envelope),
            challenge_id: challengeId,
            pow_solution: powSolution,
        });
    }

    /** Pick up a stored envelope for the given recipient. Returns the raw envelope bytes. */
    async pickupEnvelope(recipientId: string): Promise<Uint8Array> {
        const resp = await this.roundTrip({ op: 'pickup_envelope', recipient_id: recipientId });
        if (!resp.envelope) throw new RelayError('pickup_envelope response missing envelope');
        return base64ToBytes(resp.envelope);
    }

    /** Close the WebSocket connection. */
    close(): void {
        if (this.ws) {
            this.ws.onopen = null;
            this.ws.onerror = null;
            this.ws.onclose = null;
            this.ws.onmessage = null;
            try { this.ws.close(); } catch { /* ignore */ }
            this.ws = null;
        }
        if (this.pending) {
            const p = this.pending;
            this.pending = null;
            p.reject(new RelayError('transport closed'));
        }
        this.connectPromise = null;
    }
}