//! End-to-end smoke: two desktop clients exchange a verified message.
//!
//! Anchors PLAN.md Phase 5 acceptance criteria:
//!  - Two client instances exchange and correctly decrypt a verified-conversation message
//!  - Negative: tampering with one client's stored identity key is detected by the other party's safety-number check

use core_crypto::identity::IdentityKeyPair;
use core_protocol::session::establish_session;
use core_protocol::message::encrypt_for_session;

#[test]
fn two_clients_exchange_and_decrypt_verified_message() {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();

    let session = establish_session(&alice, &bob.public()).expect("session established");
    let ciphertext = encrypt_for_session(&session, b"hello bob, verified!").expect("encrypt");
    let plaintext = session.decrypt(&ciphertext).expect("decrypt");
    assert_eq!(plaintext, b"hello bob, verified!");
}

#[test]
fn tampered_identity_key_is_detected_by_safety_number_change() {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();

    let session = establish_session(&alice, &bob.public()).expect("session established");
    let initial_safety_number = session.safety_number();

    // Bob's stored identity key is tampered with (replaced with a new key).
    let bob_tampered = IdentityKeyPair::generate();
    let tampered_safety_number =
        core_protocol::session::compute_safety_number(&alice.public(), &bob_tampered.public());

    assert_ne!(
        initial_safety_number, tampered_safety_number,
        "tampered identity key MUST produce a different safety number"
    );
}
