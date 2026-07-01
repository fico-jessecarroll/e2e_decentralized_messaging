//! Two-node DM delivery: A sends, B receives and decrypts; unreachable peer errors.
//!
//! Anchors the PLAN.md Phase 3 acceptance criteria for end-to-end DM delivery. Tests are
//! written against the public `transport::online` API surface so they remain stable across
//! refactors of the libp2p stack internals. The session layer uses the real
//! `crypto::DoubleRatchetSession` (PQXDH bundle exchange + Double Ratchet encrypt/decrypt).

use crypto::{generate_identity_key_pair, DoubleRatchetSession, IdentityKeyPairExt};
use std::time::Duration;
use transport::online::{deliver, mark_peer_connected, DeliveryError, PeerStatus};

#[tokio::test]
async fn message_sent_by_a_is_received_and_decrypted_by_b() {
    // Two real PQXDH sessions: A (sender) and B (receiver). A establishes from B's bundle.
    let a_id = generate_identity_key_pair();
    let b_id = generate_identity_key_pair();

    let mut b_session = DoubleRatchetSession::new_bob(&b_id)
        .await
        .expect("bob session");
    let bundle = b_session.publish_bundle().expect("bob publishes bundle");
    let mut a_session = DoubleRatchetSession::new_alice(&a_id, &bundle)
        .await
        .expect("alice session");

    let payload = b"hello from A";
    let envelope = a_session.encrypt(payload).await.expect("A encrypts");

    // B is an online peer — register it with the connection registry, then deliver.
    let b_peer = b_id.identity_hash();
    mark_peer_connected(b_peer.to_vec());
    let delivered = deliver(&b_peer, envelope, Duration::from_secs(5))
        .await
        .expect("deliver ok");

    let plaintext = b_session
        .decrypt(&delivered)
        .await
        .expect("B decrypts A's payload");
    assert_eq!(
        plaintext.as_slice(),
        payload,
        "B must recover A's plaintext byte-for-byte"
    );
}

#[tokio::test]
async fn delivery_to_unreachable_peer_surfaces_defined_error() {
    let bogus_peer = [0u8; 32]; // no such peer — never registered as connected
    let envelope = vec![0xAB; 64];

    let res = deliver(&bogus_peer, envelope, Duration::from_millis(200)).await;
    assert!(
        matches!(res, Err(DeliveryError::PeerUnreachable { .. })),
        "unreachable peer must surface DeliveryError::PeerUnreachable, got {res:?}"
    );

    // Status query must reflect the unreachable state, not silently return Connected.
    let status = transport::online::peer_status(&bogus_peer).await;
    assert!(
        matches!(status, PeerStatus::Unreachable),
        "peer_status must report Unreachable, got {status:?}"
    );
}
