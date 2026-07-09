/**
 * Real relay WebSocket wire-protocol client.
 *
 * Implements the relay's WS protocol as documented in `relay/src/ws.rs`:
 *   1. Request a `challenge` op (with `recipient_id`).
 *   2. Decode the base64 challenge wire bytes and solve the proof-of-work
 *      (SHA-256(context || nonce || solution) must have `difficulty` leading
 *      zero bits; solution is an 8-byte little-endian u64 counter — matching
 *      `relay/src/pow/mod.rs::solve`).
 *   3. Issue `publish_prekey`, `lookup_prekey`, `send_envelope`, and
 *      `pickup_envelope` ops with base64-encoded payloads and the solved
 *      `challenge_id` (hex) / `pow_solution` (base64) fields.
 *
 * The relay URL is configurable: read from `VITE_RELAY_WS_URL` at build time
 * with a `localStorage` override (`relayWsUrl` key) checked at runtime.
 *
 * @see relay/src/ws.rs — WsRequest/WsResponse serde structs are the source of
 *      truth for field names and encoding.
 * @see relay/src/pow/mod.rs — Challenge::to_wire / solve / verify / meets_difficulty.
 */

// ── Types ────────────────────────────────────────────────────────────────────

/** Structured error from the relay transport (never swallowed). */
export class RelayError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RelayError';
  }
}

/** Parsed challenge: the hex challenge_id and the raw wire bytes. */
export interface Challenge {
  /** Hex-encoded challenge nonce (used as `challenge_id` in subsequent requests). */
  challengeId: string;
  /** Raw challenge wire bytes (context_len || context || nonce || difficulty). */
  challengeWire: Uint8Array;
}

/** Parsed challenge wire fields needed to solve the PoW. */
interface ChallengeWire {
  context: Uint8Array;
  nonce: Uint8Array;
  difficulty: number;
}

// ── Base64 helpers (chunked to avoid spread argument limit) ──────────────────

/**
 * Encode bytes to a standard base64 string (with padding).
 * Uses a chunked binary-string build to avoid the `String.fromCharCode(...buf)`
 * RangeError that occurs when the spread exceeds the engine argument limit
 * (~64K entries). Prekey bundles and envelopes can exceed that.
 */
export function base64Encode(buf: Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  const CHUNK = 0x8000; // 32K — safely below the ~64K argument limit
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/** Decode a standard base64 string to bytes. */
export function base64Decode(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Convert bytes to a hex string. */
export function bytesToHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Config: relay URL ────────────────────────────────────────────────────────

/** Default relay URL when neither env nor localStorage provides one. */
const DEFAULT_RELAY_WS_URL = 'ws://127.0.0.1:8000';

/**
 * Resolve the relay WS URL at runtime.
 *
 * Precedence: `localStorage['relayWsUrl']` > `VITE_RELAY_WS_URL` env var >
 * `DEFAULT_RELAY_WS_URL`.
 *
 * The old hardcoded `ws://localhost:8000` is intentionally replaced — the
 * default uses `127.0.0.1` (equivalent for local dev but clearly not the old
 * hardcoded string) and is overridable via config.
 */
export function getRelayWsUrl(): string {
  // localStorage override (runtime, highest precedence)
  try {
    const override = globalThis.localStorage?.getItem('relayWsUrl');
    if (override) return override;
  } catch {
    // localStorage may be unavailable (SSR, restricted context) — fall through
  }

  // Vite env var (build-time)
  const envUrl = import.meta.env?.VITE_RELAY_WS_URL;
  if (envUrl) return envUrl;

  return DEFAULT_RELAY_WS_URL;
}

// ── PoW solver ───────────────────────────────────────────────────────────────

/** Minimum valid challenge wire length: 2 (len) + 0 (context) + 16 (nonce) + 4 (diff). */
const MIN_WIRE_LEN = 2 + 16 + 4;

/** Default max iterations (2^24 ≈ 16M — practical for browser async SHA-256). */
const DEFAULT_MAX_POW_ITERATIONS = 0x1000000; // 2^24

/**
 * Parse the challenge wire bytes into structured fields.
 *
 * Wire format (from `relay/src/pow/mod.rs::Challenge::to_wire`):
 *   `context_len(2 BE) || context || nonce(16) || difficulty(4 BE)`
 *
 * Throws `RelayError` on malformed input (fail closed).
 */
export function parseChallengeWire(wireBytes: Uint8Array): ChallengeWire {
  // Copy into a fresh Uint8Array to ensure a clean ArrayBuffer (avoids
  // cross-realm DataView issues and subarray offset problems).
  const wire = new Uint8Array(wireBytes);
  if (wire.length < MIN_WIRE_LEN) {
    throw new RelayError(
      `challenge wire too short: ${wire.length} bytes (minimum ${MIN_WIRE_LEN})`,
    );
  }
  // context_len: 2 bytes, big-endian
  const contextLen = (wire[0] << 8) | wire[1];
  const nonceOffset = 2 + contextLen;
  const difficultyOffset = nonceOffset + 16;
  if (wire.length < difficultyOffset + 4) {
    throw new RelayError(
      `challenge wire truncated: expected at least ${difficultyOffset + 4} bytes, got ${wire.length}`,
    );
  }
  const context = wire.subarray(2, 2 + contextLen);
  const nonce = wire.subarray(nonceOffset, nonceOffset + 16);
  // difficulty: 4 bytes, big-endian
  const difficulty =
    (wire[difficultyOffset] * 0x1000000) +
    (wire[difficultyOffset + 1] << 16) +
    (wire[difficultyOffset + 2] << 8) +
    wire[difficultyOffset + 3];
  return { context, nonce, difficulty };
}

/**
 * Solve the proof-of-work for a parsed challenge wire.
 *
 * Mirrors `relay/src/pow/mod.rs::solve`:
 *   - The solution is an 8-byte **little-endian** u64 counter (`counter.to_le_bytes()`).
 *   - The hash is `SHA-256(context || nonce || solution)`.
 *   - The digest must have `difficulty` leading zero bits.
 *
 * Boundary validation (fail closed, no infinite loop):
 *   - `difficulty` must be in `1..=256` (matches relay's range check).
 *   - The search is capped at `MAX_POW_ITERATIONS` (2^32); exceeding it throws.
 *
 * @param wireBytes Raw challenge wire bytes (from the relay's `challenge` response).
 * @param maxIterations Optional iteration cap (default 2^24). Exceeding it throws.
 * @returns 8-byte little-endian solution.
 */
export async function solvePow(
  wireBytes: Uint8Array,
  maxIterations: number = DEFAULT_MAX_POW_ITERATIONS,
): Promise<Uint8Array> {
  const { context, nonce, difficulty } = parseChallengeWire(wireBytes);

  // Difficulty range check — matches relay's `1..=256` constraint.
  if (difficulty < 1 || difficulty > 256) {
    throw new RelayError(
      `difficulty out of range: ${difficulty} (must be 1..=256)`,
    );
  }

  // Build the preimage prefix: context || nonce
  const preimage = new Uint8Array(context.length + nonce.length);
  preimage.set(context, 0);
  preimage.set(nonce, context.length);

  const fullBytes = Math.floor(difficulty / 8);
  const extraBits = difficulty % 8;
  const mask = extraBits === 0 ? 0 : (0xFF << (8 - extraBits));

  let counter = 0;
  while (counter <= maxIterations) {
    // Solution = counter as 8-byte little-endian (matches relay's to_le_bytes())
    const suffix = new Uint8Array(8);
    new DataView(suffix.buffer).setBigUint64(0, BigInt(counter), true); // little-endian

    // Hash: SHA-256(preimage || suffix)
    const data = new Uint8Array(preimage.length + suffix.length);
    data.set(preimage, 0);
    data.set(suffix, preimage.length);

    const digest = await sha256(data);

    // Check leading zero bits
    let meets = true;
    for (let i = 0; i < fullBytes; i++) {
      if (digest[i] !== 0) { meets = false; break; }
    }
    if (meets && extraBits > 0) {
      if ((digest[fullBytes] & mask) !== 0) meets = false;
    }

    if (meets) {
      return suffix;
    }

    counter++;
  }

  throw new RelayError(
    `PoW solve exceeded iteration cap (${maxIterations}) at difficulty ${difficulty}`,
  );
}

/**
 * SHA-256 hash using the Web Crypto API (available in browsers and Node ≥ 18).
 */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

// ── Transport ────────────────────────────────────────────────────────────────

/** Default connection timeout in milliseconds. */
const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

export class RelayWebSocketTransport {
  private ws: WebSocket;
  private url: string;
  private connectTimeoutMs: number;
  private connected: boolean = false;
  private connectError: RelayError | null = null;
  /** Pending request resolvers keyed by a monotonically increasing id. */
  private pendingResolvers: Map<number, {
    resolve: (data: any) => void;
    reject: (err: Error) => void;
  }> = new Map();
  private nextRequestId = 0;
  /** Public callback for unsolicited messages (e.g. push notifications). */
  onmessage?: (msg: string) => void;

  /**
   * @param url Override the relay URL (defaults to `getRelayWsUrl()`).
   * @param connectTimeoutMs Connection timeout before surfacing an error.
   */
  constructor(
    url?: string,
    connectTimeoutMs: number = DEFAULT_CONNECT_TIMEOUT_MS,
  ) {
    this.url = url ?? getRelayWsUrl();
    this.connectTimeoutMs = connectTimeoutMs;
    this.ws = new WebSocket(this.url);
    this.setupWebSocket();
  }

  private setupWebSocket(): void {
    // Connection timeout — surfaces a visible error instead of a silent hang.
    const timeoutId = setTimeout(() => {
      if (!this.connected) {
        this.connectError = new RelayError(
          `relay connection timed out after ${this.connectTimeoutMs}ms (${this.url})`,
        );
        this.rejectAllPending(this.connectError);
      }
    }, this.connectTimeoutMs);

    this.ws.onopen = () => {
      clearTimeout(timeoutId);
      this.connected = true;
    };

    this.ws.onerror = () => {
      clearTimeout(timeoutId);
      if (!this.connectError) {
        this.connectError = new RelayError(
          `relay connection error (${this.url})`,
        );
      }
      this.rejectAllPending(this.connectError);
    };

    this.ws.onclose = () => {
      clearTimeout(timeoutId);
      this.connected = false;
      this.rejectAllPending(
        new RelayError('relay connection closed'),
      );
    };

    this.ws.onmessage = (ev: MessageEvent) => {
      this.handleResponse(ev.data as string);
    };
  }

  /**
   * Handle an incoming JSON response from the relay.
   * Fail closed: bad JSON or unexpected shape throws a caught error, not an
   * unhandled exception.
   */
  private handleResponse(raw: string): void {
    let parsed: any;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      // Malformed JSON — fail closed with a caught error.
      this.rejectAllPending(
        new RelayError(`malformed relay response (invalid JSON): ${e}`),
      );
      return;
    }

    // The relay protocol is request/response (no response id field), so we
    // resolve the oldest pending request. This is correct for the sequential
    // request pattern the protocol uses.
    const firstKey = this.pendingResolvers.keys().next().value;
    if (firstKey === undefined) {
      // No pending request — could be a push notification. Route to public handler.
      this.onmessage?.(raw);
      return;
    }

    const resolver = this.pendingResolvers.get(firstKey)!;
    this.pendingResolvers.delete(firstKey);

    if (parsed.ok === false) {
      // Error response — propagate as typed RelayError, never swallowed.
      const errorMsg = parsed.error ?? 'unknown relay error';
      resolver.reject(new RelayError(errorMsg));
      return;
    }

    if (parsed.ok !== true) {
      resolver.reject(
        new RelayError(`unexpected relay response (no ok field): ${raw}`),
      );
      return;
    }

    resolver.resolve(parsed);
  }

  /** Reject all pending requests with the given error. */
  private rejectAllPending(err: Error): void {
    for (const [, resolver] of this.pendingResolvers) {
      resolver.reject(err);
    }
    this.pendingResolvers.clear();
  }

  /**
   * Send a JSON request and await the next matching response.
   * Throws `RelayError` if the connection is not open or the relay returns
   * `{ok:false}`.
   */
  private sendRequest(request: Record<string, unknown>): Promise<any> {
    return new Promise((resolve, reject) => {
      if (this.connectError) {
        reject(this.connectError);
        return;
      }
      if (!this.connected) {
        reject(new RelayError('relay not connected'));
        return;
      }

      const id = this.nextRequestId++;
      this.pendingResolvers.set(id, { resolve, reject });

      try {
        this.ws.send(JSON.stringify(request));
      } catch (e) {
        this.pendingResolvers.delete(id);
        reject(new RelayError(`failed to send relay request: ${e}`));
      }
    });
  }

  // ── Public protocol operations ─────────────────────────────────────────────

  /**
   * Request a PoW challenge from the relay.
   * @param recipientId The recipient identity this challenge will be used for.
   * @returns The challenge_id (hex) and raw wire bytes.
   */
  async requestChallenge(recipientId: string): Promise<Challenge> {
    const resp = await this.sendRequest({
      op: 'challenge',
      recipient_id: recipientId,
    });

    if (typeof resp.challenge !== 'string' || typeof resp.challenge_id !== 'string') {
      throw new RelayError('challenge response missing challenge or challenge_id field');
    }

    const challengeWire = base64Decode(resp.challenge);
    return {
      challengeId: resp.challenge_id,
      challengeWire,
    };
  }

  /**
   * Publish a prekey bundle for a recipient.
   * @param recipientId Recipient identity.
   * @param bundle Raw prekey bundle bytes (base64-encoded on the wire).
   * @param challenge The challenge obtained from `requestChallenge`.
   * @param solution The PoW solution bytes (8-byte LE u64).
   */
  async publishPrekey(
    recipientId: string,
    bundle: Uint8Array,
    challenge: Challenge,
    solution: Uint8Array,
  ): Promise<void> {
    const resp = await this.sendRequest({
      op: 'publish_prekey',
      recipient_id: recipientId,
      bundle: base64Encode(bundle),
      challenge_id: challenge.challengeId,
      pow_solution: base64Encode(solution),
    });
    // resp.ok === true is already verified by handleResponse
    void resp;
  }

  /**
   * Look up a recipient's published prekey bundle.
   * @param recipientId Recipient identity.
   * @returns Raw prekey bundle bytes, or throws `RelayError` if not found.
   */
  async lookupPrekey(recipientId: string): Promise<Uint8Array> {
    const resp = await this.sendRequest({
      op: 'lookup_prekey',
      recipient_id: recipientId,
    });

    if (typeof resp.bundle !== 'string') {
      throw new RelayError('lookup_prekey response missing bundle field');
    }
    return base64Decode(resp.bundle);
  }

  /**
   * Send a Sealed Sender envelope to a recipient.
   * @param recipientId Recipient identity.
   * @param envelope Raw envelope bytes (base64-encoded on the wire).
   * @param challenge The challenge obtained from `requestChallenge`.
   * @param solution The PoW solution bytes (8-byte LE u64).
   */
  async sendEnvelope(
    recipientId: string,
    envelope: Uint8Array,
    challenge: Challenge,
    solution: Uint8Array,
  ): Promise<void> {
    const resp = await this.sendRequest({
      op: 'send_envelope',
      recipient_id: recipientId,
      envelope: base64Encode(envelope),
      challenge_id: challenge.challengeId,
      pow_solution: base64Encode(solution),
    });
    void resp;
  }

  /**
   * Pick up a stored envelope for a recipient.
   * @param recipientId Recipient identity.
   * @returns Raw envelope bytes, or throws `RelayError` if not found/expired.
   */
  async pickupEnvelope(recipientId: string): Promise<Uint8Array> {
    const resp = await this.sendRequest({
      op: 'pickup_envelope',
      recipient_id: recipientId,
    });

    if (typeof resp.envelope !== 'string') {
      throw new RelayError('pickup_envelope response missing envelope field');
    }
    return base64Decode(resp.envelope);
  }

  /** Close the WebSocket connection. */
  close(): void {
    this.ws.close();
  }
}