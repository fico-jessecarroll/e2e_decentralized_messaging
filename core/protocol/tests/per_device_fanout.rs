//! Per-device session fan-out — multi-device recipient decryption; revocation stops delivery.
//!
//! Anchors PLAN.md Phase 6 acceptance criteria:
//!  - A message sent to a multi-device recipient is delivered and decryptable on every linked device
//!  - Negative: removing a linked device stops further messages from being encrypted to it

use core_crypto::identity::IdentityKeyPair;
use core_protocol::fanout::{FanoutSession, DeviceId};

#[test]
fn message_to_multi_device_recipient_decrypts_on_every_linked_device() {
    let sender = IdentityKeyPair::generate();
    let recipient_a = IdentityKeyPair::generate();
    let recipient_b = IdentityKeyPair::generate();
    let recipient_c = IdentityKeyPair::generate();

    let devices = vec![
        (DeviceId(1), &recipient_a),
        (DeviceId(2), &recipient_b),
        (DeviceId(3), &recipient_c),
    ];

    let fanout = FanoutSession::establish(&sender, &devices).expect("fanout session");
    let ciphertexts = fanout.encrypt_to_all(b"hi to all my devices").expect("encrypt fanout");

    assert_eq!(ciphertexts.len(), 3, "one ciphertext per linked device");
    assert_eq!(fanout.decrypt_as(&recipient_a, &ciphertexts[0]).unwrap(), b"hi to all my devices");
    assert_eq!(fanout.decrypt_as(&recipient_b, &ciphertexts[1]).unwrap(), b"hi to all my devices");
    assert_eq!(fanout.decrypt_as(&recipient_c, &ciphertexts[2]).unwrap(), b"hi to all my devices");
}

#[test]
fn removing_a_device_stops_subsequent_messages_encrypting_to_it() {
    let sender = IdentityKeyPair::generate();
    let recipient_a = IdentityKeyPair::generate();
    let recipient_b = IdentityKeyPair::generate();

    let mut fanout = FanoutSession::establish(
        &sender,
        &[(DeviceId(1), &recipient_a), (DeviceId(2), &recipient_b)],
    ).expect("establish");

    fanout.remove_device(DeviceId(1)).expect("remove device 1");

    let ciphertexts = fanout.encrypt_to_all(b"after removal").expect("encrypt");
    // Only device 2 should be encrypted to now.
    assert_eq!(
        ciphertexts.len(), 1,
        "removed device must not receive a new ciphertext, got: {ciphertexts:?}"
    );
}
