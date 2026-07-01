//! Sealed Sender envelope encryption — relay cannot recover sender identity.
//!
//! Anchors PLAN.md Phase 4 acceptance criteria:
//!  - Relay-side test asserts sender identity is not recoverable from the envelope
//!  - Negative: a malformed sealed-sender envelope is rejected by the recipient, not silently accepted

use core_transport::sealed_sender::{seal, open, SealedSenderError};
use core_crypto::identity::IdentityKeyPair;

#[test]
fn sealed_envelope_hides_sender_identity_from_observed_blob() {
    let sender = IdentityKeyPair::generate();
    let recipient = IdentityKeyPair::generate();

    let payload = b"hello, this is the actual message body";
    let envelope = seal(&sender, &recipient.public(), payload).expect("seal succeeds");

    // The sender's identity (public key) must NOT appear verbatim in the envelope.
    let sender_pub_bytes = sender.public().to_bytes();
    assert!(
        !envelope.windows(sender_pub_bytes.len()).any(|w| w == sender_pub_bytes),
        "envelope must not contain sender's raw public key bytes"
    );

    // The recipient must be able to open it back to the original payload.
    let opened = open(&recipient, &envelope).expect("recipient opens envelope");
    assert_eq!(opened, payload);
}

#[test]
fn malformed_sealed_envelope_is_rejected_not_accepted() {
    let recipient = IdentityKeyPair::generate();
    let garbage = vec![0xDEu8; 64];

    let result = open(&recipient, &garbage);
    assert!(
        matches!(result, Err(SealedSenderError::Malformed)),
        "malformed envelope must be rejected with SealedSenderError::Malformed, got: {result:?}"
    );
}

#[test]
fn envelope_addressed_to_other_recipient_cannot_be_opened() {
    let sender = IdentityKeyPair::generate();
    let intended = IdentityKeyPair::generate();
    let attacker = IdentityKeyPair::generate();

    let envelope = seal(&sender, &intended.public(), b"private").expect("seal succeeds");

    // A different recipient holding the wrong identity must NOT be able to open it.
    let result = open(&attacker, &envelope);
    assert!(
        matches!(result, Err(SealedSenderError::NotForRecipient) | Err(SealedSenderError::DecryptionFailed)),
        "wrong-recipient open must fail, got: {result:?}"
    );
}
