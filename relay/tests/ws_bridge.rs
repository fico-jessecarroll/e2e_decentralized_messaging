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
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Connect to the WS listener and return the stream.
async fn ws_connect(
    addr: std::net::SocketAddr,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
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

/// Request a PoW challenge, solve it, and return `(challenge_id, pow_solution)`.
///
/// `challenge_id` is the hex of the challenge nonce (used as the key to look up
/// the challenge on the server). `pow_solution` is the base64 of the raw solution
/// bytes that satisfy `SHA-256(context || nonce || solution)` at the required
/// difficulty.
async fn solve_challenge(
    stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    recipient_id: &str,
) -> (String, String) {
    // 1. Request challenge
    let req = serde_json::json!({
        "op": "challenge",
        "recipient_id": recipient_id,
    });
    let resp = ws_round_trip(stream, req).await;
    assert_eq!(resp["ok"], true, "challenge request must succeed");
    let challenge_b64 = resp["challenge"].as_str().expect("challenge field");
    let challenge_id = resp["challenge_id"]
        .as_str()
        .expect("challenge_id field")
        .to_string();

    // 2. Decode and solve
    let challenge_wire = ws::b64_decode(challenge_b64).expect("challenge wire decode");
    // Wire format: context_len(2 BE) || context || nonce(16) || difficulty(4 BE)
    let context_len = u16::from_be_bytes([challenge_wire[0], challenge_wire[1]]) as usize;
    let nonce = &challenge_wire[2 + context_len..2 + context_len + 16];
    let difficulty = u32::from_be_bytes([
        challenge_wire[2 + context_len + 16],
        challenge_wire[2 + context_len + 16 + 1],
        challenge_wire[2 + context_len + 16 + 2],
        challenge_wire[2 + context_len + 16 + 3],
    ]);

    // Solve the PoW directly using the raw preimage (context || nonce) extracted
    // from the wire bytes. The Challenge struct's fields are private, so we
    // reconstruct the preimage manually.
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

    // 3. Return (challenge_id, pow_solution) — pow_solution is base64 of raw solution bytes
    (challenge_id, ws::b64_encode(&solution))
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
    let (challenge_id, pow_solution) = solve_challenge(&mut stream, recipient_id).await;

    // Publish
    let req = serde_json::json!({
        "op": "publish_prekey",
        "recipient_id": recipient_id,
        "bundle": bundle_b64,
        "challenge_id": challenge_id,
        "pow_solution": pow_solution,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], true, "publish_prekey must succeed: {resp}");

    // Lookup — need a new connection since pickup removes the bundle
    // Actually, lookup_prekey also removes (pickup semantics). Let's publish again.
    let (challenge_id2, pow_solution2) = solve_challenge(&mut stream, recipient_id).await;
    let req = serde_json::json!({
        "op": "publish_prekey",
        "recipient_id": recipient_id,
        "bundle": bundle_b64,
        "challenge_id": challenge_id2,
        "pow_solution": pow_solution2,
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
    assert_eq!(
        fetched, bundle,
        "fetched bundle must match published bundle"
    );
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
    let (challenge_id, pow_solution) = solve_challenge(&mut stream, recipient_id).await;

    // Send envelope
    let req = serde_json::json!({
        "op": "send_envelope",
        "recipient_id": recipient_id,
        "envelope": envelope_b64,
        "challenge_id": challenge_id,
        "pow_solution": pow_solution,
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
    assert_eq!(
        fetched, envelope,
        "fetched envelope must match sent envelope"
    );
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

    // Bogus solution: all 0xFF — will never satisfy 20-bit difficulty
    let bogus_solution = ws::b64_encode(&[0xFFu8; 8]);

    let req = serde_json::json!({
        "op": "publish_prekey",
        "recipient_id": recipient_id,
        "bundle": bundle_b64,
        "challenge_id": challenge_id,
        "pow_solution": bogus_solution,
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

    // Submit with a bogus challenge_id (not in the server's challenge set) and a
    // bogus pow_solution — the server should reject because the challenge is not found.
    let bogus_challenge_id = "00000000000000000000000000000000";
    let bogus_solution = ws::b64_encode(b"garbage-solution");

    let req = serde_json::json!({
        "op": "send_envelope",
        "recipient_id": recipient_id,
        "envelope": envelope_b64,
        "challenge_id": bogus_challenge_id,
        "pow_solution": bogus_solution,
    });
    let resp = ws_round_trip(&mut stream, req).await;
    assert_eq!(resp["ok"], false, "missing/invalid PoW must be rejected");
    assert!(
        resp["error"].as_str().unwrap_or("").contains("PowFailed"),
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
        resp["error"]
            .as_str()
            .unwrap_or("")
            .contains("RateLimitExceeded"),
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

// ── browser-side client tests ─────────────────────────────────────────────────

/// The WsRelayClient can publish and look up a prekey bundle end-to-end.
#[tokio::test]
async fn ws_client_publish_and_lookup_prekey() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut client = ws::WsRelayClient::connect(handle.addr)
        .await
        .expect("client must connect");

    let recipient_id = "alice-client-test";
    let bundle = vec![0x11u8; 256];

    // Publish
    client
        .publish_prekey(recipient_id, &bundle)
        .await
        .expect("publish must succeed");

    // Lookup
    let fetched = client
        .lookup_prekey(recipient_id)
        .await
        .expect("lookup must succeed");
    assert_eq!(
        fetched, bundle,
        "fetched bundle must match published bundle"
    );
}

/// The WsRelayClient can send and pick up a Sealed Sender envelope end-to-end.
#[tokio::test]
async fn ws_client_send_and_pickup_envelope() {
    let handle = ws::start_ws_listener_for_test(60).await;
    let mut client = ws::WsRelayClient::connect(handle.addr)
        .await
        .expect("client must connect");

    let recipient_id = "bob-client-test";
    let envelope = vec![0x22u8; 512];

    // Send
    client
        .send_envelope(recipient_id, &envelope)
        .await
        .expect("send must succeed");

    // Pickup
    let fetched = client
        .pickup_envelope(recipient_id)
        .await
        .expect("pickup must succeed");
    assert_eq!(
        fetched, envelope,
        "fetched envelope must match sent envelope"
    );
}

/// The WsRelayClient must fail closed (return Err, not silently drop) when the
/// relay connection is unavailable at send time.
#[tokio::test]
async fn ws_client_fails_closed_when_relay_unavailable() {
    // Connect to a port that is not listening — connect_async will fail.
    let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let result = ws::WsRelayClient::connect(addr).await;

    // The client must return an error, not Ok — this is the fail-closed property.
    assert!(
        result.is_err(),
        "client must fail closed when relay is unavailable"
    );
    match result {
        Err(ws::WsClientError::ConnectionUnavailable) => { /* expected */ }
        Err(e) => panic!("expected ConnectionUnavailable, got: {e}"),
        Ok(_) => panic!("must not succeed when relay is unavailable"),
    }
}

/// The WsRelayClient must fail closed when the connection drops mid-session.
///
/// We simulate this by starting a minimal TCP server that completes the WebSocket
/// handshake, then immediately closes the connection. The client's next operation
/// must return `Err(ConnectionUnavailable)` — never silently drop the message.
#[tokio::test]
async fn ws_client_fails_closed_when_connection_drops() {
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    // Start a server that accepts one connection, completes the WS handshake,
    // then immediately drops the stream — simulating a relay that crashes mid-session.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_join = tokio::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.unwrap();
        // Complete the WS handshake so the client thinks it's connected...
        let ws_stream = accept_async(tcp_stream).await.unwrap();
        // ...then immediately drop the stream, closing the connection.
        drop(ws_stream);
    });

    // Give the server a moment to be ready.
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    let mut client = ws::WsRelayClient::connect(addr)
        .await
        .expect("client must connect before the drop");

    // Wait for the server to close the connection.
    let _ = server_join.await;
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // The next operation must fail closed — return an error, not silently drop.
    let result = client.send_envelope("dropped-test", &[0x33u8; 64]).await;
    assert!(
        result.is_err(),
        "client must fail closed when connection drops mid-session"
    );
    match result {
        Err(ws::WsClientError::ConnectionUnavailable) => { /* expected */ }
        Err(e) => panic!("expected ConnectionUnavailable, got: {e}"),
        Ok(_) => panic!("must not succeed when connection has dropped"),
    }
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
                    resp["error"]
                        .as_str()
                        .unwrap_or("")
                        .contains("MalformedRequest"),
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
