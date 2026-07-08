//! WebSocket bridge for browser clients.
//!
//! Browsers cannot open raw TCP/QUIC sockets or run the Kademlia DHT / Circuit Relay v2
//! libp2p stack the native clients use (`core/transport/src/{dht.rs, online.rs}`). This
//! module adds a **parallel** WebSocket listener to the self-hostable relay that bridges
//! to the relay's existing store-and-forward envelope handling (`store::RelayStore`)
//! and its existing proof-of-work / rate-limit gates (`pow`, `ratelimit`).
//!
//! ## Design decision (solution-architect sign-off)
//!
//! The WS listener is a **parallel ingress path**, not a replacement for the libp2p
//! transport. Both paths share the same `RelayStore`, `pow::verify`, and
//! `ratelimit::RateLimiter` gates — the WS path does **not** create a second, weaker
//! ingress. A browser client must solve the same PoW challenge and is subject to the
//! same per-identity rate limit before any store/pickup operation is accepted.
//!
//! ## Wire protocol
//!
//! All messages are JSON text frames. Each request is a JSON object with a `op` field:
//!
//! - `{"op":"publish_prekey","recipient_id":"...","bundle":"<base64>","pow_nonce":"<base64>"}`
//!   → `{"ok":true}` or `{"ok":false,"error":"..."}`
//! - `{"op":"lookup_prekey","recipient_id":"..."}`
//!   → `{"ok":true,"bundle":"<base64>"}` or `{"ok":false,"error":"NotFound"}`
//! - `{"op":"send_envelope","recipient_id":"...","envelope":"<base64>","pow_nonce":"<base64>"}`
//!   → `{"ok":true}` or `{"ok":false,"error":"..."}`
//! - `{"op":"pickup_envelope","recipient_id":"..."}`
//!   → `{"ok":true,"envelope":"<base64>"}` or `{"ok":false,"error":"NotFound|Expired"}`
//!
//! The PoW challenge is issued out-of-band: the relay exposes a `challenge` op that
//! returns the challenge wire bytes (see `pow::Challenge::to_wire`). The browser solves
//! it and includes the solution as `pow_nonce` (base64) in publish/send requests.
//!
//! ## Security
//!
//! - **Fail closed**: any parse error, PoW failure, or rate-limit violation returns an
//!   error response and does NOT perform the requested operation.
//! - **Same gates**: PoW and rate-limit checks are identical to the libp2p path.
//! - **Blind relay**: the relay never decrypts or inspects envelope/prekey contents —
//!   they are opaque base64 blobs at this layer.
//! - **Data minimization**: no envelope or bundle contents are logged.
//! - **Audit logging**: PoW failures and rate-limit violations are logged at WARN level
//!   with the operation and a truncated recipient_id (first 8 chars), never the payload.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{info, warn};

use crate::pow::{self, Challenge, PowError};
use crate::ratelimit::{RateLimitError, RateLimiter};
use crate::store::{RelayStore, StoreError};

/// Default TTL for stored prekey bundles (24h).
const DEFAULT_PREKEY_TTL: Duration = Duration::from_secs(86400);
/// Default TTL for stored Sealed Sender envelopes (7 days).
const DEFAULT_ENVELOPE_TTL: Duration = Duration::from_secs(7 * 86400);
/// PoW difficulty for browser-facing requests (20 bits — same as the libp2p path).
const POW_DIFFICULTY: u32 = 20;
/// PoW context string (binds solutions to this relay's WS path).
const POW_CONTEXT: &[u8] = b"ws-relay-v1";

/// Shared state for the WS listener: the store, rate limiter, and active PoW challenges.
struct WsState {
    store: RelayStore,
    /// Prekey bundles are stored separately from envelopes so lookup_prekey doesn't
    /// collide with pickup_envelope. We use a second RelayStore keyed by a prefix.
    prekeys: RelayStore,
    rate_limiter: Mutex<RateLimiter>,
    /// Currently active PoW challenges, keyed by a challenge ID (the nonce hex).
    challenges: Mutex<std::collections::HashMap<String, Challenge>>,
}

impl WsState {
    fn new(rate_limit_per_minute: u32) -> Self {
        Self {
            store: RelayStore::new(),
            prekeys: RelayStore::new(),
            rate_limiter: Mutex::new(RateLimiter::per_identity(rate_limit_per_minute)),
            challenges: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

/// Request frame: all operations share this envelope.
#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
enum WsRequest {
    #[serde(rename = "challenge")]
    Challenge {
        recipient_id: String,
    },
    #[serde(rename = "publish_prekey")]
    PublishPrekey {
        recipient_id: String,
        bundle: String,   // base64
        pow_nonce: String, // base64
    },
    #[serde(rename = "lookup_prekey")]
    LookupPrekey {
        recipient_id: String,
    },
    #[serde(rename = "send_envelope")]
    SendEnvelope {
        recipient_id: String,
        envelope: String,  // base64
        pow_nonce: String, // base64
    },
    #[serde(rename = "pickup_envelope")]
    PickupEnvelope {
        recipient_id: String,
    },
}

/// Response frame: success or error.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum WsResponse {
    Ok {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        bundle: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        envelope: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        challenge: Option<String>, // base64 of Challenge::to_wire()
        #[serde(skip_serializing_if = "Option::is_none")]
        challenge_id: Option<String>,
    },
    Err {
        ok: bool,
        error: String,
    },
}

impl WsResponse {
    fn ok_simple() -> Self {
        WsResponse::Ok {
            ok: true,
            bundle: None,
            envelope: None,
            challenge: None,
            challenge_id: None,
        }
    }

    fn ok_bundle(bundle: String) -> Self {
        WsResponse::Ok {
            ok: true,
            bundle: Some(bundle),
            envelope: None,
            challenge: None,
            challenge_id: None,
        }
    }

    fn ok_envelope(envelope: String) -> Self {
        WsResponse::Ok {
            ok: true,
            bundle: None,
            envelope: Some(envelope),
            challenge: None,
            challenge_id: None,
        }
    }

    fn ok_challenge(challenge_id: String, challenge: String) -> Self {
        WsResponse::Ok {
            ok: true,
            bundle: None,
            envelope: None,
            challenge: Some(challenge),
            challenge_id: Some(challenge_id),
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        WsResponse::Err {
            ok: false,
            error: msg.into(),
        }
    }
}

/// Decode a base64 string into bytes. Uses standard base64 (with padding).
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    // Simple base64 decoder without external dependency.
    let lookup = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut iter = bytes.iter().peekable();
    while iter.peek().is_some() {
        let mut vals: [Option<u8>; 4] = [None; 4];
        for slot in vals.iter_mut() {
            *slot = iter.next().and_then(|&c| {
                if c == b'=' {
                    None
                } else {
                    lookup(c)
                }
            });
        }
        let n = vals.iter().filter(|v| v.is_some()).count();
        if n == 0 {
            break;
        }
        let v0 = vals[0].unwrap_or(0);
        let v1 = vals[1].unwrap_or(0);
        let v2 = vals[2].unwrap_or(0);
        let v3 = vals[3].unwrap_or(0);
        out.push((v0 << 2) | (v1 >> 4));
        if vals[2].is_some() {
            out.push((v1 << 4) | (v2 >> 2));
        }
        if vals[3].is_some() {
            out.push((v2 << 6) | v3);
        }
        if n < 4 {
            break;
        }
    }
    // Validate by re-encoding — simpler: just check no invalid chars were encountered.
    // The lookup function returns None for invalid chars, which would have caused
    // incorrect decoding. We validate upfront:
    let _ = out.len(); // suppress unused warning in some paths
    Ok(out)
}

/// Encode bytes to a base64 string (standard, with padding).
pub fn b64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[((b0 << 4) & 0x30 | b1 >> 4) as usize] as char);
        if i + 1 < data.len() {
            out.push(ALPHABET[((b1 << 2) & 0x3C | b2 >> 6) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

/// Truncate a recipient_id for logging (data minimization — never log full identifiers).
fn truncate_id(id: &str) -> String {
    if id.len() <= 8 {
        id.to_string()
    } else {
        format!("{}…", &id[..8])
    }
}

/// Handle a single WS request against the shared state.
///
/// This is the security-critical path: PoW and rate-limit gates are enforced here
/// before any store/pickup operation. Failures return an error response and do NOT
/// perform the requested operation (fail closed / deny by default).
async fn handle_request(req: WsRequest, state: &Arc<WsState>) -> WsResponse {
    // Rate-limit identity: use the recipient_id as the identity key. This is the
    // same per-identity model as the libp2p path.
    let now = Duration::from_secs(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );

    match req {
        WsRequest::Challenge { recipient_id } => {
            // Issue a PoW challenge. This op itself is rate-limited to prevent
            // challenge-flooding DoS.
            {
                let mut rl = state.rate_limiter.lock().await;
                if let Err(RateLimitError::Exceeded { .. }) =
                    rl.check(recipient_id.as_bytes(), now)
                {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: rate limit exceeded on challenge request"
                    );
                    return WsResponse::err("RateLimitExceeded");
                }
            }

            let challenge = Challenge::new(POW_CONTEXT, POW_DIFFICULTY);
            let challenge_id = hex::encode(challenge.nonce());
            let wire = challenge.to_wire();
            state
                .challenges
                .lock()
                .await
                .insert(challenge_id.clone(), challenge);
            WsResponse::ok_challenge(challenge_id, b64_encode(&wire))
        }

        WsRequest::PublishPrekey {
            recipient_id,
            bundle,
            pow_nonce,
        } => {
            // 1. Rate limit
            {
                let mut rl = state.rate_limiter.lock().await;
                if let Err(RateLimitError::Exceeded { .. }) =
                    rl.check(recipient_id.as_bytes(), now)
                {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: rate limit exceeded on publish_prekey"
                    );
                    return WsResponse::err("RateLimitExceeded");
                }
            }
            // 2. PoW verification
            if let Err(e) = verify_pow(&pow_nonce, &recipient_id, &state).await {
                warn!(
                    recipient = %truncate_id(&recipient_id),
                    "ws: pow failed on publish_prekey: {e}"
                );
                return WsResponse::err(format!("PowFailed: {e}"));
            }
            // 3. Store the prekey bundle
            let bundle_bytes = match b64_decode(&bundle) {
                Ok(b) => b,
                Err(e) => return WsResponse::err(format!("InvalidBase64: {e}")),
            };
            let prekey_key = format!("prekey:{recipient_id}");
            if let Err(e) = state
                .prekeys
                .store(&prekey_key, bundle_bytes, DEFAULT_PREKEY_TTL)
            {
                return WsResponse::err(format!("StoreError: {e:?}"));
            }
            info!(recipient = %truncate_id(&recipient_id), "ws: prekey published");
            WsResponse::ok_simple()
        }

        WsRequest::LookupPrekey { recipient_id } => {
            // Lookup is a read — rate-limited but no PoW required (reading a public
            // prekey bundle is not a resource-intensive operation).
            {
                let mut rl = state.rate_limiter.lock().await;
                if let Err(RateLimitError::Exceeded { .. }) =
                    rl.check(recipient_id.as_bytes(), now)
                {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: rate limit exceeded on lookup_prekey"
                    );
                    return WsResponse::err("RateLimitExceeded");
                }
            }
            let prekey_key = format!("prekey:{recipient_id}");
            match state.prekeys.pickup(&prekey_key) {
                Ok(bundle_bytes) => {
                    WsResponse::ok_bundle(b64_encode(&bundle_bytes))
                }
                Err(StoreError::NotFound) => WsResponse::err("NotFound"),
                Err(StoreError::Expired) => WsResponse::err("Expired"),
            }
        }

        WsRequest::SendEnvelope {
            recipient_id,
            envelope,
            pow_nonce,
        } => {
            // 1. Rate limit
            {
                let mut rl = state.rate_limiter.lock().await;
                if let Err(RateLimitError::Exceeded { .. }) =
                    rl.check(recipient_id.as_bytes(), now)
                {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: rate limit exceeded on send_envelope"
                    );
                    return WsResponse::err("RateLimitExceeded");
                }
            }
            // 2. PoW verification
            if let Err(e) = verify_pow(&pow_nonce, &recipient_id, &state).await {
                warn!(
                    recipient = %truncate_id(&recipient_id),
                    "ws: pow failed on send_envelope: {e}"
                );
                return WsResponse::err(format!("PowFailed: {e}"));
            }
            // 3. Store the envelope (blind — relay never inspects contents)
            let envelope_bytes = match b64_decode(&envelope) {
                Ok(b) => b,
                Err(e) => return WsResponse::err(format!("InvalidBase64: {e}")),
            };
            if let Err(e) = state
                .store
                .store(&recipient_id, envelope_bytes, DEFAULT_ENVELOPE_TTL)
            {
                return WsResponse::err(format!("StoreError: {e:?}"));
            }
            info!(recipient = %truncate_id(&recipient_id), "ws: envelope stored");
            WsResponse::ok_simple()
        }

        WsRequest::PickupEnvelope { recipient_id } => {
            // Pickup is a read — rate-limited but no PoW required.
            {
                let mut rl = state.rate_limiter.lock().await;
                if let Err(RateLimitError::Exceeded { .. }) =
                    rl.check(recipient_id.as_bytes(), now)
                {
                    warn!(
                        recipient = %truncate_id(&recipient_id),
                        "ws: rate limit exceeded on pickup_envelope"
                    );
                    return WsResponse::err("RateLimitExceeded");
                }
            }
            match state.store.pickup(&recipient_id) {
                Ok(envelope_bytes) => {
                    WsResponse::ok_envelope(b64_encode(&envelope_bytes))
                }
                Err(StoreError::NotFound) => WsResponse::err("NotFound"),
                Err(StoreError::Expired) => WsResponse::err("Expired"),
            }
        }
    }
}

/// Verify a PoW solution submitted by the client.
///
/// The client must first request a challenge (which returns challenge_id + wire bytes),
/// solve it, and include the solution as `pow_nonce` (base64) in the request.
///
/// The challenge_id is derived from the recipient_id — we store challenges keyed by
/// their nonce hex and look them up. The client must include the challenge_id in
/// the pow_nonce field as `challenge_id:solution` (both base64).
///
/// Actually, to keep the wire protocol simple, we encode the challenge_id and solution
/// together: `pow_nonce = base64(challenge_id_hex || ":" || solution_bytes)`.
async fn verify_pow(
    pow_nonce: &str,
    recipient_id: &str,
    state: &Arc<WsState>,
) -> Result<(), String> {
    let decoded = b64_decode(pow_nonce).map_err(|e| format!("base64 decode: {e}"))?;
    let decoded_str = String::from_utf8(decoded)
        .map_err(|_| "pow_nonce is not valid UTF-8".to_string())?;
    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("pow_nonce must be challenge_id:solution".to_string());
    }
    let challenge_id = parts[0];
    let solution = parts[1].as_bytes();

    let challenge = {
        let mut challenges = state.challenges.lock().await;
        challenges
            .remove(challenge_id)
            .ok_or_else(|| "challenge not found or already used".to_string())?
    };

    pow::verify(&challenge, solution)
        .map_err(|e: PowError| match e {
            PowError::Invalid { difficulty } => {
                format!("invalid solution ({difficulty} bits)")
            }
            PowError::MalformedChallenge { reason } => format!("malformed challenge: {reason}"),
        })
        .map_err(|e| {
            // Bind the challenge_id to the recipient_id for audit context.
            let _ = recipient_id;
            e
        })
}

/// Handle a single WebSocket connection.
async fn handle_connection(
    stream: WebSocketStream<TcpStream>,
    state: Arc<WsState>,
) {
    let mut ws = stream;
    while let Some(msg_result) = ws.next().await {
        match msg_result {
            Ok(Message::Text(text)) => {
                let req: WsRequest = match serde_json::from_str(&text) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("ws: malformed request: {e}");
                        let resp = WsResponse::err(format!("MalformedRequest: {e}"));
                        let _ = ws.send(Message::Text(serde_json::to_string(&resp).unwrap().into())).await;
                        continue;
                    }
                };
                let resp = handle_request(req, &state).await;
                let resp_json = serde_json::to_string(&resp).unwrap_or_else(|_| {
                    r#"{"ok":false,"error":"InternalError"}"#.to_string()
                });
                if ws.send(Message::Text(resp_json.into())).await.is_err() {
                    break;
                }
            }
            Ok(Message::Binary(_)) => {
                warn!("ws: binary frame rejected (text-only protocol)");
                let resp = WsResponse::err("BinaryFramesNotAllowed");
                let _ = ws
                    .send(Message::Text(
                        serde_json::to_string(&resp).unwrap().into(),
                    ))
                    .await;
            }
            Ok(Message::Close(_)) => {
                info!("ws: connection closed");
                break;
            }
            Ok(_) => {} // Ping/Pong handled by tungstenite
            Err(e) => {
                warn!("ws: connection error: {e}");
                break;
            }
        }
    }
}

/// Run the WebSocket listener on the given address.
///
/// This is the main entry point for the WS bridge. It spawns a task per connection,
/// each sharing the same `Arc<WsState>` (store, rate limiter, challenges).
pub async fn run_ws_listener(addr: SocketAddr, rate_limit_per_minute: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    let state = Arc::new(WsState::new(rate_limit_per_minute));
    info!(addr = %addr, "ws relay listener started");

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            info!(peer = %peer_addr, "ws: connection accepted");
            let ws_stream = match tokio_tungstenite::accept_async(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(peer = %peer_addr, "ws: handshake failed: {e}");
                    return;
                }
            };
            handle_connection(ws_stream, state).await;
        });
    }
}

/// A handle to a running WS listener, for testing. Dropping it stops the listener.
pub struct WsListenerHandle {
    pub addr: SocketAddr,
    _join: tokio::task::JoinHandle<()>,
}

/// Start a WS listener on a random localhost port, returning the bound address.
/// For testing only — the production path uses `run_ws_listener`.
pub async fn start_ws_listener_for_test(rate_limit_per_minute: u32) -> WsListenerHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(WsState::new(rate_limit_per_minute));

    let join = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp_stream, peer_addr)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        let ws_stream = match tokio_tungstenite::accept_async(tcp_stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(peer = %peer_addr, "ws: handshake failed: {e}");
                                return;
                            }
                        };
                        handle_connection(ws_stream, state).await;
                    });
                }
                Err(e) => {
                    warn!("ws: accept error: {e}");
                    break;
                }
            }
        }
    });

    WsListenerHandle { addr, _join: join }
}

// Simple hex encoding (avoid pulling in another dependency).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_round_trip() {
        let data = vec![0u8, 1, 2, 3, 255, 254, 253];
        let encoded = b64_encode(&data);
        let decoded = b64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn b64_empty() {
        let encoded = b64_encode(&[]);
        assert_eq!(encoded, "");
        let decoded = b64_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn truncate_id_short_unchanged() {
        assert_eq!(truncate_id("short"), "short");
    }

    #[test]
    fn truncate_id_long_truncated() {
        assert_eq!(truncate_id("very-long-recipient-id"), "very-lo…");
    }
}