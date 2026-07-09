use core_crypto::{derive_safety_number, generate_identity_key_pair, DoubleRatchetSession};

#[tokio::test]
async fn cross_client_smoke_test_simulated() {
    // Simulate a web client (Alice) and desktop-tauri client (Bob)
    let alice_id = generate_identity_key_pair();
    let bob_id = generate_identity_key_pair();

    // Bob creates a session as the responder
    let mut bob = DoubleRatchetSession::new_bob(&bob_id).await.expect("bob session");
    let bundle = bob.publish_bundle().expect("bob publishes bundle");

    // Alice creates a session as initiator using Bob's bundle
    let mut alice = DoubleRatchetSession::new_alice(&alice_id, &bundle)
        .await
        .expect("alice session");

    // Alice sends an encrypted message to Bob
    let ciphertext = alice.encrypt(b"hello bob, verified!")
        .await
        .expect("alice encrypts");
    let plaintext = bob.decrypt(&ciphertext).await.expect("bob decrypts");
    assert_eq!(plaintext, b"hello bob, verified!");

    // Verify safety numbers match
    let alice_safety = derive_safety_number(
        b"alice",
        &alice_id.identity_key().serialize(),
        b"bob",
        &bob_id.identity_key().serialize(),
    ).expect("safety number");
    let bob_safety = derive_safety_number(
        b"bob",
        &bob_id.identity_key().serialize(),
        b"alice",
        &alice_id.identity_key().serialize(),
    ).expect("safety number");
    assert_eq!(alice_safety, bob_safety);
    // Tamper ciphertext and expect decryption failure
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xFF;
    assert!(bob.decrypt(&tampered).await.is_err());
