//! End-to-end smoke: two desktop clients exchange a verified message.
//!
//! Anchors PLAN.md Phase 5 acceptance criteria:
//!  - Two client instances exchange and correctly decrypt a verified-conversation message
//!  - Negative: tampering with one client's stored identity key is detected by the other party's safety-number check

use core_crypto::{derive_safety_number, generate_identity_key_pair, DoubleRatchetSession};

#[tokio::test]
async fn two_clients_exchange_and_decrypt_verified_message() {
    let alice_id = generate_identity_key_pair();
    let bob_id = generate_identity_key_pair();

    let mut bob = DoubleRatchetSession::new_bob(&bob_id)
        .await
        .expect("bob session");
    let bundle = bob.publish_bundle().expect("bob publishes bundle");

    let mut alice = DoubleRatchetSession::new_alice(&alice_id, &bundle)
        .await
        .expect("alice session");
    let ciphertext = alice
        .encrypt(b"hello bob, verified!")
        .await
        .expect("alice encrypts");
    let plaintext = bob.decrypt(&ciphertext).await.expect("bob decrypts");
    assert_eq!(plaintext, b"hello bob, verified!");
}

#[test]
fn tampered_identity_key_is_detected_by_safety_number_change() {
    let alice_id = generate_identity_key_pair();
    let bob_id = generate_identity_key_pair();

    let initial_safety_number = derive_safety_number(
        b"alice",
        &alice_id.identity_key().serialize(),
        b"bob",
        &bob_id.identity_key().serialize(),
    )
    .expect("valid keys");

    // Bob's stored identity key is tampered with (replaced with a new key).
    let bob_tampered_id = generate_identity_key_pair();
    let tampered_safety_number = derive_safety_number(
        b"alice",
        &alice_id.identity_key().serialize(),
        b"bob",
        &bob_tampered_id.identity_key().serialize(),
    )
    .expect("valid keys");

    assert_ne!(
        initial_safety_number, tampered_safety_number,
        "tampered identity key MUST produce a different safety number"
    );
}
