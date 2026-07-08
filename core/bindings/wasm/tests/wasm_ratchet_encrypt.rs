//! WASM Double Ratchet encrypt/decrypt tests (PLAN.md Phase 8 — follow-on story).
//!
//! TDD tests for the new WASM-facing functions that operate on an established
//! `SessionHandle`:
//!  - `encrypt_message` — encrypts plaintext on an established session, returns envelope bytes
//!  - `decrypt_message` — decrypts an envelope on the matching receiver session, returns plaintext
//!
//! Required negative/boundary cases:
//!  - Tampered ciphertext fails AEAD authentication and returns Err (never silently passed
//!    through or a panic).
//!  - Decrypting with a mismatched/wrong session state is rejected as Err.
//!  - The Err path serializes as a structured JS-visible error (WasmError with kind + message),
//!    not a panic.
//!
//! These tests run natively (the same `#[test]` harness the CI `test` job uses) — the
//! `wasm-bindgen` attribute is a no-op outside `wasm32-unknown-unknown`, so the functions
//! are callable as ordinary Rust functions here.

use core_bindings_wasm::{
    create_receiver_session, decrypt_message, encrypt_message, establish_session_from_bundle,
    generate_identity, generate_prekey_bundle, publish_bundle_bytes,
};

// ---------------------------------------------------------------------------
// Positive path: encrypt produces a non-empty envelope
// ---------------------------------------------------------------------------

#[test]
fn encrypt_message_on_established_session_returns_non_empty_bytes() {
    let bob = generate_identity();
    let bundle_bytes = generate_prekey_bundle(&bob).expect("bundle generation must succeed");
    let alice = generate_identity();
    let mut alice_session =
        establish_session_from_bundle(&alice, &bundle_bytes).expect("session must establish");

    let plaintext = b"hello from alice";
    let envelope = encrypt_message(&mut alice_session, plaintext)
        .expect("encrypt must succeed on an established session");

    assert!(!envelope.is_empty(), "encrypted envelope must not be empty");
    // The envelope prefix is 32 bytes (sender hash) + 1 byte (type tag) = 33 bytes minimum.
    assert!(
        envelope.len() > 33,
        "envelope must be longer than the 33-byte prefix, got {} bytes",
        envelope.len()
    );
}

// ---------------------------------------------------------------------------
// Positive path: encrypt then decrypt round-trip
// ---------------------------------------------------------------------------

#[test]
fn encrypt_decrypt_round_trip_recovers_original_plaintext() {
    let bob_identity = generate_identity();
    // Create the receiver session first, then publish its bundle — so the same session
    // that generated the bundle can later decrypt messages encrypted against it.
    let mut bob_session =
        create_receiver_session(&bob_identity).expect("receiver session must establish");
    let bundle_bytes = publish_bundle_bytes(&bob_session).expect("bundle publication must succeed");

    let alice_identity = generate_identity();
    let mut alice_session = establish_session_from_bundle(&alice_identity, &bundle_bytes)
        .expect("session must establish");

    let plaintext = b"secret message for bob";
    let envelope = encrypt_message(&mut alice_session, plaintext).expect("encrypt must succeed");

    let decrypted = decrypt_message(&mut bob_session, &envelope)
        .expect("decrypt must succeed on matching session");

    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "decrypted plaintext must match original"
    );
}

// ---------------------------------------------------------------------------
// Negative path: tampered ciphertext fails AEAD authentication, returns Err
// ---------------------------------------------------------------------------

#[test]
fn tampered_ciphertext_rejected_as_err_not_panic() {
    let bob_identity = generate_identity();
    let mut bob_session =
        create_receiver_session(&bob_identity).expect("receiver session must establish");
    let bundle_bytes = publish_bundle_bytes(&bob_session).expect("bundle publication must succeed");

    let alice_identity = generate_identity();
    let mut alice_session = establish_session_from_bundle(&alice_identity, &bundle_bytes)
        .expect("session must establish");

    let plaintext = b"tamper test message";
    let mut envelope =
        encrypt_message(&mut alice_session, plaintext).expect("encrypt must succeed");

    // Flip a byte in the ciphertext body (after the 33-byte prefix) — this corrupts
    // the AEAD-encrypted payload. The MAC must catch this and decrypt must return Err.
    let body_start = 33; // 32 (sender hash) + 1 (type tag)
    if envelope.len() > body_start {
        envelope[body_start] ^= 0xFF;
    }

    let result = decrypt_message(&mut bob_session, &envelope);
    assert!(
        result.is_err(),
        "tampered ciphertext must fail AEAD authentication and return Err, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Negative path: decrypting with a mismatched/wrong session is rejected
// ---------------------------------------------------------------------------

#[test]
fn decrypt_with_wrong_session_rejected_as_err_not_panic() {
    // Alice establishes a session with Bob1, encrypts a message.
    let bob1_identity = generate_identity();
    let bob1_session =
        create_receiver_session(&bob1_identity).expect("receiver session must establish");
    let bundle1 = publish_bundle_bytes(&bob1_session).expect("bundle publication must succeed");
    let alice_identity = generate_identity();
    let mut alice_session =
        establish_session_from_bundle(&alice_identity, &bundle1).expect("session must establish");

    let plaintext = b"message for bob1 only";
    let envelope = encrypt_message(&mut alice_session, plaintext).expect("encrypt must succeed");

    // Bob2 is a completely different identity — he has no session with Alice.
    let bob2_identity = generate_identity();
    let mut bob2_session =
        create_receiver_session(&bob2_identity).expect("receiver session must establish");

    let result = decrypt_message(&mut bob2_session, &envelope);
    assert!(
        result.is_err(),
        "decrypting with a mismatched/wrong session must be rejected as Err, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Negative path: decrypting empty or too-short envelope returns Err
// ---------------------------------------------------------------------------

#[test]
fn decrypt_empty_envelope_rejected_as_err_not_panic() {
    let bob = generate_identity();
    let mut bob_session = create_receiver_session(&bob).expect("receiver session must establish");

    let result = decrypt_message(&mut bob_session, &[]);
    assert!(
        result.is_err(),
        "empty envelope must be rejected as Err, got: {result:?}"
    );
}

#[test]
fn decrypt_truncated_envelope_rejected_as_err_not_panic() {
    let bob = generate_identity();
    let mut bob_session = create_receiver_session(&bob).expect("receiver session must establish");

    // 10 bytes — shorter than the 33-byte prefix
    let result = decrypt_message(&mut bob_session, &[0u8; 10]);
    assert!(
        result.is_err(),
        "truncated envelope must be rejected as Err, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Contract: Err path serializes as a structured JS-visible error, not a panic
// ---------------------------------------------------------------------------

#[test]
fn decrypt_error_is_structured_wasm_error_with_kind_and_message() {
    let bob = generate_identity();
    let mut bob_session = create_receiver_session(&bob).expect("receiver session must establish");

    let result = decrypt_message(&mut bob_session, &[0u8; 10]);
    let err = result.expect_err("truncated envelope must return Err");

    assert!(
        !err.kind().is_empty(),
        "structured WasmError must carry a non-empty kind tag"
    );
    assert!(
        !err.message().is_empty(),
        "structured WasmError must carry a non-empty message"
    );
}

#[test]
fn encrypt_error_is_structured_wasm_error_with_kind_and_message() {
    // Encrypting on a receiver-only session (Bob) must fail with a structured error.
    let bob = generate_identity();
    let mut bob_session = create_receiver_session(&bob).expect("receiver session must establish");

    let result = encrypt_message(&mut bob_session, b"should fail");
    let err = result.expect_err("encrypt on receiver-only session must return Err");

    assert!(
        !err.kind().is_empty(),
        "structured WasmError must carry a non-empty kind tag"
    );
    assert!(
        !err.message().is_empty(),
        "structured WasmError must carry a non-empty message"
    );
}

// ---------------------------------------------------------------------------
// Contract: multiple messages ratchet forward correctly
// ---------------------------------------------------------------------------

#[test]
fn multiple_messages_ratchet_forward_and_decrypt_correctly() {
    let bob_identity = generate_identity();
    let mut bob_session =
        create_receiver_session(&bob_identity).expect("receiver session must establish");
    let bundle_bytes = publish_bundle_bytes(&bob_session).expect("bundle publication must succeed");

    let alice_identity = generate_identity();
    let mut alice_session = establish_session_from_bundle(&alice_identity, &bundle_bytes)
        .expect("session must establish");

    // First message (PreKey message — establishes Bob's session)
    let msg1 = b"first message";
    let env1 = encrypt_message(&mut alice_session, msg1).expect("encrypt 1 must succeed");
    let dec1 = decrypt_message(&mut bob_session, &env1).expect("decrypt 1 must succeed");
    assert_eq!(dec1.as_slice(), msg1.as_slice());

    // Second message (regular Ciphertext message — ratchets forward)
    let msg2 = b"second message after ratchet";
    let env2 = encrypt_message(&mut alice_session, msg2).expect("encrypt 2 must succeed");
    let dec2 = decrypt_message(&mut bob_session, &env2).expect("decrypt 2 must succeed");
    assert_eq!(dec2.as_slice(), msg2.as_slice());

    // Third message
    let msg3 = b"third message";
    let env3 = encrypt_message(&mut alice_session, msg3).expect("encrypt 3 must succeed");
    let dec3 = decrypt_message(&mut bob_session, &env3).expect("decrypt 3 must succeed");
    assert_eq!(dec3.as_slice(), msg3.as_slice());
}
