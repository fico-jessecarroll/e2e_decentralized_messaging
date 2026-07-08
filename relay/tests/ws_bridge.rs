//! WebSocket relay bridge integration tests.
//!
//! Mirrors the patterns in `store_forward_ttl.rs` and `pow_rate_limit.rs` but exercises
//! the full WebSocket path: a browser-equivalent client connects to the WS listener,
//! requests a PoW challenge, solves it, and publishes/fetches a prekey bundle and
//! sends/receives a Sealed Sender envelope.
//!
//! ## Required negative/boundary cases
//!
//! - Relay must still reject envelopes that fail PoW when they arrive over WebSocket
//!   (same gates as the libp2p path — no weaker ingress).
//! - Relay must still reject requests that exceed the rate limit over WebSocket.
//! - Browser client must fail closed (return an error, not silently drop) if the relay
//!   connection is unavailable at send time.

use futures::{SinkExt, StreamExt};
use relay::ws;
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::connect_async;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Connect to the WS listener and return the stream.
async fn ws_connect(addr: std::net::SocketAddr) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://{addr}");
    let (stream, _response) = connect_async(url).await.expect("ws connect must succeed");
    stream
}

/// Send a JSON request and return the JSON response.
async fn ws_round_trip(
    stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    req: Value,
) -> Value {
    stream
        .send(Message::Text(req.to_string().into()))
        .await
        .expect("send must succeed");
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(&text).expect("response must be valid JSON")
            }
            Some(Ok(_)) => continue, // skip non-text frames
            Some(Err(e)) => panic!("ws error: {e}"),
            None => panic!("ws stream closed before response"),
        }
    }
}

/// Request a PoW challenge, solve it, and return the pow_nonce string (base64 of
/// "challenge_id:solution").
async fn solve_challenge(
    stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    recipient_id: &str,
) -> String {
    // 1. Request challenge
    let req = serde_json::json!({
        "op": "challenge",
        "recipient_id": recipient_id,
    });
    let resp = ws_round_trip(stream, req).await;
    assert_eq!(resp["ok"], true, "challenge request must succeed");
    let challenge_b64 = resp["challenge"].as_str().expect("challenge field");
    let challenge_id = resp["challenge_id"].as_str().expect("challenge_id field");

    // 2. Decode and solve
    let challenge_wire = ws::b64_decode(challenge_b64).expect("challenge wire decode");
    // Reconstruct the Challenge from wire bytes: context_len(2) || context || nonce(16) || difficulty(4)
    let context_len = u16::from_be_bytes([challenge_wire[0], challenge_wire[1]]) as usize;
    let _context = &challenge_wire[2..2 + context_len];
    let nonce = &challenge_wire[2 + context_len..2 + context_len + 16];
    let difficulty = u32::from_be_bytes([
        challenge_wire[2 + context_len + 16],
        challenge_wire[2 + context_len + 16 + 1],
        challenge_wire[2 + context_len + 16 + 2],
        challenge_wire[2 + context_len + 16 + 3],
    ]);

    // The Challenge struct's nonce is private, so we can't reconstruct it from
    // wire bytes via the public API. Instead, we solve the PoW directly using
    // the raw preimage (context || nonce) extracted from the wire bytes.
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&challenge_wire[2..2 + context_len]);
    preimage.extend_from_slice(nonce);

    // Brute-force the solution
    let mut counter: u64 = 0;
    let solution = loop {
        let suffix = counter.to_le_bytes();
        if check_pow(&preimage, &suffix, difficulty) {
            break suffix.to_vec();
        }
        counter += 1;
        if counter > (1u64 << 32) {
            panic!("pow solve exceeded iteration limit");
        }
    };

    // 3. Encode pow_nonce = base64("challenge_id:solution")
    let pow_plain = format!("{}:{}", challenge_id, String::from_utf8_lossy(&solution));
    ws::b64_encode(pow_plain.as_bytes())
}

/// Check if a PoW solution meets the difficulty (mirrors pow::meets_difficulty).
fn check_pow(preimage: &[u8], suffix: &[u8], difficulty: u32) -> bool {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.update(suffix);
    let digest = hasher.finalize();

    let full_bytes = (difficulty / 8) as usize;
    if digest.len() < full_bytes || digest[..full_bytes].iter().any(|b| *b != 0) {
        return false;
    }
    let extra_bits = difficulty % 8;
    if extra_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - extra_bits);
    (digest[full_bytes] & mask) == 0
}

// ── positive tests ───────────────────────────────────────────────────────────

/// End-to-end: publish a prekey bundle over WS, then look it up.
#[tokio::test]
async fn ws_publish_and_lookup_prekey_bundle() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "alice-test-id";
    let bundle = vec![0xAAu8; 256];
    let bundle_b64 = ws::b64_encode(&bundle);

    // Solve PoW
    let pow_nonce = solve_challenge(&mut stream, recipient_id).await;

    // Publish
    let req = serde_json::json!({
        "op": "publish_prekey",
        "recipient_id": recipient_id,
        "bundle": bundle_b64,
        "pow_nonce": pow_nonce,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], true, "publish_prekey must succeed: {resp}");

    // Lookup — need a new connection since pickup removes the bundle
    // Actually, lookup_prekey also removes (pickup semantics). Let's publish again.
    let pow_nonce2 = solve_challenge(&mut stream, recipient_id).await;
    let req = serde_json::json!({
        "op": "publish_prekey",
        "recipient_id": recipient_id,
        "bundle": bundle_b64,
        "pow_nonce": pow_nonce2,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], true, "second publish must succeed: {resp}");

    // Lookup
    let req = serde_json::json!({
        "op": "lookup_prekey",
        "recipient_id": recipient_id,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], true, "lookup_prekey must succeed: {resp}");
    let fetched_b64 = resp["bundle"].as_str().expect("bundle field");
    let fetched = ws::b64_decode(fetched_b64).unwrap();
    assert_eq!(fetched, bundle, "fetched bundle must match published bundle");
}

/// End-to-end: send a Sealed Sender envelope over WS, then pick it up.
#[tokio::test]
async fn ws_send_and_pickup_sealed_sender_envelope() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "bob-test-id";
    let envelope = vec![0xBBu8; 512];
    let envelope_b64 = ws::b64_encode(&envelope);

    // Solve PoW
    let pow_nonce = solve_challenge(&mut stream, recipient_id).await;

    // Send envelope
    let req = serde_json::json!({
        "op": "send_envelope",
        "recipient_id": recipient_id,
        "envelope": envelope_b64,
        "pow_nonce": pow_nonce,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], true, "send_envelope must succeed: {resp}");

    // Pickup envelope
    let req = serde_json::json!({
        "op": "pickup_envelope",
        "recipient_id": recipient_id,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], true, "pickup_envelope must succeed: {resp}");
    let fetched_b64 = resp["envelope"].as_str().expect("envelope field");
    let fetched = ws::b64_decode(fetched_b64).unwrap();
    assert_eq!(fetched, envelope, "fetched envelope must match sent envelope");
}

// ── negative tests: PoW gate ──────────────────────────────────────────────────

/// Relay must reject a publish_prekey with an invalid/bogus PoW solution.
#[tokio::test]
async fn ws_rejects_publish_prekey_with_bogus_pow() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "charlie-test-id";
    let bundle = vec![0xCCu8; 128];
    let bundle_b64 = ws::b64_encode(&bundle);

    // Request a challenge so we have a valid challenge_id, but submit a bogus solution
    let req = serde_json::json!({
        "op": "challenge",
        "recipient_id": recipient_id,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    let challenge_id = resp["challenge_id"].as_str().expect("challenge_id");

    // Bogus solution: all 0xFF
    let bogus_solution = vec![0xFFu8; 8];
    let pow_plain = format!("{}:{}", challenge_id, String::from_utf8_lossy(&bogus_solution));
    let pow_nonce = ws::b64_encode(pow_plain.as_bytes());

    let req = serde_json::json!({
        "op": "publish_prekey",
        "recipient_id": recipient_id,
        "bundle": bundle_b64,
        "pow_nonce": pow_nonce,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], false, "bogus PoW must be rejected");
    assert!(
        resp["error"].as_str().unwrap_or("").contains("PowFailed"),
        "error must indicate PoW failure, got: {resp}"
    );
}

/// Relay must reject a send_envelope with no PoW at all (missing challenge_id).
#[tokio::test]
async fn ws_rejects_send_envelope_with_missing_pow() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "dave-test-id";
    let envelope = vec![0xDDu8; 64];
    let envelope_b64 = ws::b64_encode(&envelope);

    // Submit with a garbage pow_nonce that won't decode to a valid challenge_id:solution
    let pow_nonce = ws::b64_encode(b"garbage-no-colon");

    let req = serde_json::json!({
        "op": "send_envelope",
        "recipient_id": recipient_id,
        "envelope": envelope_b64,
        "pow_nonce": pow_nonce,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], false, "missing/invalid PoW must be rejected");
    assert!(
        resp["error"].as_str().unwrap_or("").contains("PowFailed")
            || resp["error"].as_str().unwrap_or("").contains("pow_nonce"),
        "error must indicate PoW failure, got: {resp}"
    );
}

// ── negative tests: rate limit gate ──────────────────────────────────────────

/// Relay must reject requests that exceed the per-identity rate limit over WS.
#[tokio::test]
async fn ws_rejects_requests_exceeding_rate_limit() {
    // Very low rate limit: 2 per minute
    let handle = ws::start_ws_listener_for_test(2).await;
    let mut stream = ws_connect(handle.addr).await;

    let recipient_id = "eve-test-id";

    // Burn through the rate limit with challenge requests (each consumes a token)
    for _ in 0..2 {
        let req = serde_json::json!({
            "op": "challenge",
            "recipient_id": recipient_id,
        });
        let resp = ws_round_trip(&mut stream, req).await;
        assert_eq!(resp["ok"], true, "first 2 requests must succeed: {resp}");
    }

    // 3rd request must be rate-limited
    let req = serde_json::json!({
        "op": "challenge",
        "recipient_id": recipient_id,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], false, "3rd request must be rate-limited");
    assert!(
        resp["error"].as_str().unwrap_or("").contains("RateLimitExceeded"),
        "error must indicate rate limit, got: {resp}"
    );
}

// ── negative tests: fail closed ──────────────────────────────────────────────

/// Relay must return NotFound (not crash) when picking up a non-existent envelope.
#[tokio::test]
async fn ws_pickup_nonexistent_envelope_returns_not_found() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    let req = serde_json::json!({
        "op": "pickup_envelope",
        "recipient_id": "nonexistent-recipient",
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], false, "pickup of nonexistent must fail");
    assert_eq!(
        resp["error"].as_str().unwrap_or(""),
        "NotFound",
        "error must be NotFound, got: {resp}"
    );
}

/// Relay must reject binary frames (text-only JSON protocol).
#[tokio::test]
async fn ws_rejects_binary_frames() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    stream
        .send(Message::Binary(vec![0x00, 0x01, 0x02].into()))
        .await
        .expect("send must succeed");

    // Should receive an error response
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => {
                let resp: Value = serde_json::from_str(&text).expect("valid JSON");
                assert_eq!(resp["ok"], false, "binary frame must be rejected");
                return;
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => panic!("ws error: {e}"),
            None => panic!("ws stream closed"),
        }
    }
}

/// Relay must reject malformed JSON requests.
#[tokio::test]
async fn ws_rejects_malformed_json() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut stream = ws_connect(handle.addr).await;

    stream
        .send(Message::Text("not valid json {{{".into()))
        .await
        .expect("send must succeed");

    loop {
        match stream.next().await {
            Some(Ok(Message::Text(text))) => {
                let resp: Value = serde_json::from_str(&text).expect("valid JSON");
                assert_eq!(resp["ok"], false, "malformed JSON must be rejected");
                assert!(
                    resp["error"].as_str().unwrap_or("").contains("MalformedRequest"),
                    "error must indicate malformed request, got: {resp}"
                );
                return;
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => panic!("ws error: {e}"),
            None => panic!("ws stream closed"),
        }
    }
}