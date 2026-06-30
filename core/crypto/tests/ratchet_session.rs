//! High-level Double Ratchet session: PQXDH establishment + encrypt/decrypt round-trip.
//!
//! Wraps the done low-level crypto building blocks (InMemSignalProtocolStore,
//! build_prekey_bundle, establish_outbound_session, encrypt_message/decrypt_message)
//! behind a single async session type so callers establish from a peer's prekey
//! bundle and encrypt/decrypt without touching libsignal stores directly.

use crypto::{generate_identity_key_pair, DoubleRatchetSession, IdentityKeyPairExt, SessionError};

#[tokio::test]
async fn alice_encrypts_and_bob_decrypts_the_initial_message() {
    let a_id = generate_identity_key_pair();
    let b_id = generate_identity_key_pair();

    // Bob publishes a PQXDH prekey bundle from his own prekey store.
    let mut bob = DoubleRatchetSession::new_bob(&b_id)
        .await
        .expect("bob session");
    let bundle = bob.publish_bundle().expect("bob publishes bundle");

    // Alice establishes an outbound session from Bob's bundle and encrypts.
    let mut alice = DoubleRatchetSession::new_alice(&a_id, &bundle)
        .await
        .expect("alice session");
    let payload = b"hello from alice";
    let ciphertext = alice.encrypt(payload).await.expect("alice encrypts");

    // Bob decrypts and recovers Alice's plaintext byte-for-byte.
    let plaintext = bob.decrypt(&ciphertext).await.expect("bob decrypts");
    assert_eq!(
        plaintext.as_slice(),
        payload,
        "bob must recover alice's plaintext"
    );
}

#[tokio::test]
async fn tampered_ciphertext_fails_closed() {
    let a_id = generate_identity_key_pair();
    let b_id = generate_identity_key_pair();
    let mut bob = DoubleRatchetSession::new_bob(&b_id).await.unwrap();
    let bundle = bob.publish_bundle().unwrap();
    let mut alice = DoubleRatchetSession::new_alice(&a_id, &bundle)
        .await
        .unwrap();

    let mut ciphertext = alice.encrypt(b"hello").await.unwrap();
    // Flip a byte in the body — decryption must fail closed, not return wrong plaintext.
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xff;
    let res = bob.decrypt(&ciphertext).await;
    assert!(
        res.is_err(),
        "tampered ciphertext must fail closed, got {res:?}"
    );
}

#[tokio::test]
async fn too_short_envelope_is_rejected_as_malformed() {
    let b_id = generate_identity_key_pair();
    let mut bob = DoubleRatchetSession::new_bob(&b_id).await.unwrap();

    // Shorter than the 33-byte envelope prefix — must be rejected before any parsing.
    let res = bob.decrypt(&[0u8; 10]).await;
    assert!(
        matches!(res, Err(SessionError::MalformedEnvelope)),
        "too-short envelope must be malformed, got {res:?}"
    );
}

#[tokio::test]
async fn envelope_with_an_unknown_type_tag_is_rejected_as_malformed() {
    let b_id = generate_identity_key_pair();
    let mut bob = DoubleRatchetSession::new_bob(&b_id).await.unwrap();

    // 32-byte hash + an unknown type tag (9) + a throwaway body.
    let mut envelope = vec![0u8; 33];
    envelope[32] = 9;
    envelope.extend_from_slice(&[1, 2, 3, 4]);

    let res = bob.decrypt(&envelope).await;
    assert!(
        matches!(res, Err(SessionError::MalformedEnvelope)),
        "unknown type tag must be malformed, got {res:?}"
    );
}

#[tokio::test]
async fn first_contact_prekey_with_a_mismatched_sender_hash_is_rejected_without_preemption() {
    let b_id = generate_identity_key_pair();
    let v_id = generate_identity_key_pair(); // the real victim
    let m_id = generate_identity_key_pair(); // Mallory

    let mut bob = DoubleRatchetSession::new_bob(&b_id)
        .await
        .expect("bob session");
    let bundle = bob.publish_bundle().expect("bob publishes bundle");

    // Mallory establishes a genuine session with Bob (using Bob's bundle) and encrypts a real
    // PreKey message whose body embeds MALLORY's identity key.
    let mut mallory = DoubleRatchetSession::new_alice(&m_id, &bundle)
        .await
        .expect("mallory session");
    let mallory_envelope = mallory
        .encrypt(b"hi from mallory")
        .await
        .expect("mallory encrypts");

    // Re-wrap Mallory's valid PreKey body under the VICTIM's identity hash — a forged
    // sender_hash claiming to be the victim while the embedded identity key is Mallory's.
    let mut spoofed = Vec::with_capacity(mallory_envelope.len());
    spoofed.extend_from_slice(&v_id.identity_hash());
    spoofed.extend_from_slice(&mallory_envelope[32..]);

    let res = bob.decrypt(&spoofed).await;
    assert!(
        matches!(res, Err(SessionError::IdentityHashMismatch)),
        "a PreKey body whose embedded identity key does not hash to the declared sender_hash \
         must be rejected before TOFU binds Mallory's key to the victim's address, got {res:?}"
    );

    // No preemption: the spoof was rejected before libsignal bound anything to the victim's
    // address, so the real victim's first message still decrypts cleanly.
    let mut victim = DoubleRatchetSession::new_alice(&v_id, &bundle)
        .await
        .expect("victim session");
    let victim_envelope = victim
        .encrypt(b"hi from the real victim")
        .await
        .expect("victim encrypts");
    let plaintext = bob
        .decrypt(&victim_envelope)
        .await
        .expect("real victim's first message must still decrypt (no preemption)");
    assert_eq!(plaintext.as_slice(), b"hi from the real victim");
}
