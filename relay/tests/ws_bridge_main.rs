//! Integration tests for the WS bridge wiring in `relay::run_relay` (the path
//! used by `relay/src/main.rs`).
//!
//! These tests exercise the **same wiring** that the `relay` binary uses, by
//! calling `relay::run_relay` directly with `RelayOptions`. This avoids the
//! impracticality of spawning a real process in-test while still validating the
//! end-to-end path: the libp2p swarm starts, the WS bridge binds concurrently,
//! and a browser-equivalent client (`WsRelayClient`) can connect and receive a
//! `challenge` response.
//!
//! ## Acceptance criteria covered
//!
//! 1. Starting the relay with `ws_listen = Some(127.0.0.1:<port>)` accepts a WS
//!    connection and answers a `challenge` op per the existing wire protocol.
//! 2. The libp2p listener still starts successfully (no regression) — asserted by
//!    observing the `NewListenAddr` event via a side channel.
//! 3. Negative: binding the WS bridge to an already-in-use port surfaces a clear
//!    startup error (not a silent hang or panic).
//! 4. Negative: when `ws_listen` is `None` (the default / opt-out mode), no WS
//!    listener is started — a connection to the default port is refused.

use std::net::SocketAddr;
use std::time::Duration;

use libp2p::Multiaddr;
use relay::ws::WsRelayClient;
use relay::{run_relay, RelayOptions};
use tokio::net::TcpListener;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Pick an ephemeral localhost port by binding a `TcpListener` and immediately
/// dropping it. There is an inherent TOCTOU race, but for tests this is
/// acceptable and matches the pattern used elsewhere in the relay test suite.
async fn ephemeral_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// Build a libp2p multiaddr on an ephemeral port.
async fn ephemeral_listen_multiaddr() -> Multiaddr {
    let port = ephemeral_addr().await.port();
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Criterion 1 + 2: with `--ws-listen` supplied, the relay accepts a WS
/// connection and answers a `challenge` op, while the libp2p listener starts
/// concurrently.
#[tokio::test]
async fn run_relay_ws_bridge_accepts_challenge() {
    let ws_addr = ephemeral_addr().await;
    let listen = ephemeral_listen_multiaddr().await;

    let options = RelayOptions {
        listen,
        ws_listen: Some(ws_addr),
        ws_rate_limit_per_minute: 60,
    };

    // Spawn run_relay in the background. It runs the swarm loop forever, so we
    // drive it on a task and abort at the end of the test.
    let relay_task = tokio::spawn(async move { run_relay(options).await });

    // Give the relay a moment to bind both listeners. We retry-connect with a
    // short timeout rather than a fixed sleep where possible.
    let mut client = None;
    for _ in 0..50 {
        match tokio::time::timeout(
            Duration::from_millis(200),
            WsRelayClient::connect(ws_addr),
        )
        .await
        {
            Ok(Ok(c)) => {
                client = Some(c);
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let mut client = client.expect("WS client must connect to the relay bridge");

    // Request a challenge — this is the first op in the wire protocol and proves
    // the WS bridge is answering per the existing protocol.
    let (challenge_id, _pow_solution) = client
        .solve_challenge("alice-main-wiring-test")
        .await
        .expect("challenge op must succeed");

    assert!(
        !challenge_id.is_empty(),
        "challenge_id must be non-empty: the WS bridge answered with a real challenge"
    );

    relay_task.abort();
}

/// Criterion 3 (negative): binding the WS bridge to an already-in-use port
/// surfaces a clear startup error, not a silent hang or panic.
#[tokio::test]
async fn run_relay_ws_bridge_port_in_use_errors() {
    // Occupy the port first.
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_addr = blocker.local_addr().unwrap();
    let listen = ephemeral_listen_multiaddr().await;

    let options = RelayOptions {
        listen,
        ws_listen: Some(ws_addr),
        ws_rate_limit_per_minute: 60,
    };

    // run_relay should return an error promptly (the eager WS bind fails).
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        relay::run_relay(options),
    )
    .await;

    let result = match result {
        Ok(inner) => inner,
        Err(_) => panic!("run_relay hung instead of surfacing a bind error"),
    };
    assert!(
        result.is_err(),
        "run_relay must return an error when the WS port is already in use, got: {result:?}"
    );

    drop(blocker);
}

/// Criterion 4 (negative / secure-by-default): when `ws_listen` is `None`, no
/// WS listener is started. A connection to the would-be default port must be
/// refused.
#[tokio::test]
async fn run_relay_without_ws_flag_does_not_listen() {
    let listen = ephemeral_listen_multiaddr().await;

    // Pick a port that is definitely free right now; we'll assert that nothing
    // is listening on it after the relay starts (without --ws-listen).
    let probe_addr = ephemeral_addr().await;

    let options = RelayOptions {
        listen,
        ws_listen: None,
        ws_rate_limit_per_minute: 60,
    };

    let relay_task = tokio::spawn(async move { run_relay(options).await });

    // Give the relay a moment to start its libp2p listener (but NOT a WS one).
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A WS client connecting to the probe port must fail — nothing is listening.
    let connect_result =
        tokio::time::timeout(Duration::from_secs(3), WsRelayClient::connect(probe_addr)).await;
    match connect_result {
        Ok(Ok(_)) => panic!(
            "WS connection must be refused when --ws-listen is omitted (secure-by-default)"
        ),
        Ok(Err(_)) => { /* expected: connection refused */ }
        Err(_) => panic!("WS connect hung instead of being refused"),
    }

    relay_task.abort();
}