//! Double Ratchet 1:1 message encrypt/decrypt tests.
//!
//! Covers PLAN.md Phase 1 "Crypto core" — Double Ratchet 1:1 encrypt/decrypt
//! acceptance criteria:
//!
//! - Encrypt/decrypt round-trips correctly
//! - Forward secrecy: compromise of a later key cannot decrypt earlier messages
//! - Tampered ciphertext fails authentication and is rejected, not silently passed through
//! - Replayed message is detected and rejected
//!
//! The libsignal `TripleRatchet` (the implementation under `message_encrypt` /
//! `message_decrypt`) covers the property tests for out-of-order delivery; this
//! file sticks to the round-trip and authentication-failure behavior called out
//! in the story's acceptance criteria.

use crypto::double_ratchet::{
    decrypt_message, encrypt_message, DoubleRatchetError, MessageType, SerializedCiphertext,
};
use crypto::prekey::{generate_one_time_pre_keys, generate_signed_pre_key};
use crypto::session::{build_prekey_bundle, establish_outbound_session, generate_kyber_prekey};
use libsignal_protocol::{
    CiphertextMessage, DeviceId, IdentityKeyPair, InMemSignalProtocolStore, KyberPreKeyId,
    KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyStore, ProtocolAddress, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyStore, Timestamp,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

fn now_ts() -> Timestamp {
    Timestamp::from_epoch_millis(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    )
}

fn device(n: u8) -> DeviceId {
    DeviceId::new(n).expect("valid device id 1..=127")
}

struct Party {
    store: InMemSignalProtocolStore,
    bundle: PreKeyBundle,
    address: ProtocolAddress,
}

async fn make_party(name: &str, device_id: u8) -> Party {
    let mut rng = OsRng.unwrap_err();
    let identity = IdentityKeyPair::generate(&mut rng);
    let did = device(device_id);

    let mut store = InMemSignalProtocolStore::new(identity, 42).expect("store");

    let now = now_ts();
    let signed_prekey = generate_signed_pre_key(&identity, 1, now);
    let kyber_prekey =
        generate_kyber_prekey(KyberPreKeyId::from(1u32), identity.private_key(), now).unwrap();
    let otpks = generate_one_time_pre_keys(1, 1);
    let otpk = otpks.first().unwrap();

    store
        .save_signed_pre_key(SignedPreKeyId::from(1u32), &signed_prekey)
        .await
        .unwrap();
    store
        .save_kyber_pre_key(KyberPreKeyId::from(1u32), &kyber_prekey)
        .await
        .unwrap();
    store
        .save_pre_key(PreKeyId::from(1u32), otpk)
        .await
        .unwrap();

    let bundle = build_prekey_bundle(
        42,
        did,
        &identity,
        &signed_prekey,
        &kyber_prekey,
        Some(otpk),
    )
    .unwrap();

    Party {
        store,
        bundle,
        address: ProtocolAddress::new(name.to_string(), did),
    }
}

/// Establish an outbound session from Bob's store against Alice's published bundle.
async fn bob_establishes_session_with_alice(alice: &Party, bob: &mut Party) {
    establish_outbound_session(
        &bob.address,
        &alice.address,
        &alice.bundle,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
        &mut OsRng.unwrap_err(),
    )
    .await
    .expect("session establishment must succeed");
}

/// Wrap a `CiphertextMessage` produced by `encrypt_message` into a
/// `SerializedCiphertext`, picking the right `MessageType` so the
/// wrapper's parser dispatches to the correct `libsignal` decode path.
fn serialize(ct: &CiphertextMessage) -> SerializedCiphertext {
    let message_type = match ct {
        CiphertextMessage::PreKeySignalMessage(_) => MessageType::PreKey,
        CiphertextMessage::SignalMessage(_) => MessageType::Ciphertext,
        // 1:1 ratchet tests must never encounter group / sealed-sender envelopes.
        other => panic!("unexpected CiphertextMessage shape: {other:?}"),
    };
    SerializedCiphertext::new(message_type, ct.serialize().to_vec())
}

// ── Happy path: round-trip ──────────────────────────────────────────────────

#[tokio::test]
async fn bob_to_alice_initial_message_round_trips() {
    let mut alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    let plaintext = b"hello alice";
    let ct = encrypt_message(
        plaintext,
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("encrypt");

    let ciphertext = serialize(&ct);

    let recovered = decrypt_message(
        ciphertext,
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await
    .expect("decrypt");

    assert_eq!(recovered, plaintext);
}

#[tokio::test]
async fn alice_to_bob_reply_after_initial_message_round_trips() {
    let mut alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    // Bob's first message (initial / pre-key message) to Alice.
    let initial = encrypt_message(
        b"ping",
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("initial encrypt");
    let initial_ct = serialize(&initial);
    decrypt_message(
        initial_ct,
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await
    .expect("initial decrypt");

    // Alice replies on the established session.
    let reply = encrypt_message(
        b"pong",
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
    )
    .await
    .expect("reply encrypt");
    let reply_ct = serialize(&reply);
    let recovered = decrypt_message(
        reply_ct,
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
        &mut bob.store.pre_key_store,
        &bob.store.signed_pre_key_store,
        &mut bob.store.kyber_pre_key_store,
    )
    .await
    .expect("reply decrypt");

    assert_eq!(recovered, b"pong");
}

#[tokio::test]
async fn consecutive_messages_in_one_direction_each_round_trip() {
    let mut alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    // The initial message from Bob establishes the session on Alice's side.
    let initial = encrypt_message(
        b"start",
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("initial encrypt");
    let initial_ct = serialize(&initial);
    decrypt_message(
        initial_ct,
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await
    .expect("initial decrypt");

    let payloads: &[&[u8]] = &[b"one", b"two", b"three", b"four"];
    let mut ciphertexts = Vec::new();
    for p in payloads {
        let ct = encrypt_message(
            p,
            &bob.address,
            &alice.address,
            &mut alice.store.session_store,
            &mut alice.store.identity_store,
        )
        .await
        .expect("encrypt");
        ciphertexts.push(serialize(&ct));
    }

    for (expected, ct) in payloads.iter().zip(ciphertexts.into_iter()) {
        let recovered = decrypt_message(
            ct,
            &alice.address,
            &bob.address,
            &mut bob.store.session_store,
            &mut bob.store.identity_store,
            &mut bob.store.pre_key_store,
            &bob.store.signed_pre_key_store,
            &mut bob.store.kyber_pre_key_store,
        )
        .await
        .expect("decrypt");
        assert_eq!(&recovered, expected);
    }
}

// ── Negative: tampered ciphertext ────────────────────────────────────────────

#[tokio::test]
async fn tampered_ciphertext_body_is_rejected_not_silently_passed() {
    let mut alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    let plaintext = b"the treasury is at 221B Baker Street";
    let ct = encrypt_message(
        plaintext,
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("encrypt");
    let serialized = serialize(&ct);
    let mut bytes = serialized.into_bytes();
    let message_type = match ct {
        CiphertextMessage::PreKeySignalMessage(_) => MessageType::PreKey,
        CiphertextMessage::SignalMessage(_) => MessageType::Ciphertext,
        other => panic!("unexpected CiphertextMessage shape: {other:?}"),
    };

    // Flip a bit somewhere in the middle of the serialized ciphertext body.
    let midpoint = bytes.len() / 2;
    bytes[midpoint] ^= 0x01;

    let tampered = SerializedCiphertext::new(message_type, bytes);

    let result = decrypt_message(
        tampered,
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await;

    // Fail-closed: tampered ciphertext must NOT return the plaintext, and must
    // surface an error to the caller rather than yielding empty bytes.
    assert!(
        result.is_err(),
        "tampered ciphertext must be rejected, got: {result:?}"
    );
}

#[tokio::test]
async fn truncated_ciphertext_is_rejected() {
    let mut alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    let ct = encrypt_message(
        b"data",
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("encrypt");
    let message_type = match ct {
        CiphertextMessage::PreKeySignalMessage(_) => MessageType::PreKey,
        CiphertextMessage::SignalMessage(_) => MessageType::Ciphertext,
        other => panic!("unexpected CiphertextMessage shape: {other:?}"),
    };
    let mut bytes = serialize(&ct).into_bytes();
    bytes.truncate(bytes.len() / 2);
    let truncated = SerializedCiphertext::new(message_type, bytes);

    let result = decrypt_message(
        truncated,
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await;

    assert!(
        result.is_err(),
        "truncated ciphertext must be rejected, got: {result:?}"
    );
}

// ── Negative: replayed ciphertext ────────────────────────────────────────────

#[tokio::test]
async fn replaying_an_older_message_advances_state_so_it_cannot_decrypt_twice() {
    let mut alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    let ct = encrypt_message(
        b"only once",
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("encrypt");
    let serialized = serialize(&ct);

    // First decryption succeeds.
    let first = decrypt_message(
        serialized.clone(),
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await
    .expect("first decrypt");
    assert_eq!(first, b"only once");

    // Replaying the exact same ciphertext: a correct Double Ratchet must reject
    // the replay — message keys are single-use.
    let replay_result = decrypt_message(
        serialized,
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await;

    assert!(
        replay_result.is_err(),
        "replayed message must be rejected, got: {replay_result:?}"
    );
}

// ── Negative: out-of-order delivery within skip window ───────────────────────

#[tokio::test]
async fn out_of_order_message_within_skip_window_round_trips() {
    let mut alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    // Bob's initial message — Alice needs a session before she can reply.
    let initial = encrypt_message(
        b"start",
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("initial encrypt");
    let initial_ct = serialize(&initial);
    decrypt_message(
        initial_ct,
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await
    .expect("initial decrypt");

    // Alice produces three replies back-to-back. Bob delivers them in reverse.
    let mut ciphertexts = Vec::new();
    let payloads: [&[u8]; 3] = [b"a-one", b"a-two", b"a-three"];
    for p in &payloads {
        let ct = encrypt_message(
            p,
            &bob.address,
            &alice.address,
            &mut alice.store.session_store,
            &mut alice.store.identity_store,
        )
        .await
        .expect("encrypt");
        ciphertexts.push((p, serialize(&ct)));
    }

    for (payload, ct) in ciphertexts.into_iter().rev() {
        let recovered = decrypt_message(
            ct,
            &alice.address,
            &bob.address,
            &mut bob.store.session_store,
            &mut bob.store.identity_store,
            &mut bob.store.pre_key_store,
            &bob.store.signed_pre_key_store,
            &mut bob.store.kyber_pre_key_store,
        )
        .await
        .expect("decrypt");
        assert_eq!(&recovered, payload);
    }
}

// ── Negative: identity mismatch (post-TOFU MITM) ────────────────────────────

#[tokio::test]
async fn message_from_a_different_identity_at_alices_address_is_rejected() {
    let mut alice = make_party("alice", 1).await;
    let mut alice_attacker = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    // First decrypt cements Alice's identity at her address in Bob's identity store.
    let initial = encrypt_message(
        b"legit",
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("encrypt");
    let initial_ct = serialize(&initial);
    decrypt_message(
        initial_ct,
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await
    .expect("legit decrypt");

    // Attacker establishes their own session with Bob (using their own
    // identity key — different from Alice's). They can encrypt a
    // pre-key-wrapped message, but Bob's identity store has Alice's key
    // bound to her address and must refuse to accept an attacker-keyed
    // message at that address.
    establish_outbound_session(
        &alice_attacker.address,
        &bob.address,
        &bob.bundle,
        &mut alice_attacker.store.session_store,
        &mut alice_attacker.store.identity_store,
        &mut OsRng.unwrap_err(),
    )
    .await
    .expect("attacker session establishment");

    let malicious = encrypt_message(
        b"i am alice (not really)",
        &bob.address,
        &alice.address,
        &mut alice_attacker.store.session_store,
        &mut alice_attacker.store.identity_store,
    )
    .await
    .expect("attacker encrypt");
    let malicious_ct = serialize(&malicious);

    // Bob attempts to decrypt the attacker's message arriving at *Alice's*
    // address. The attacker's session state identifies the sender as a
    // different identity key than Alice's; the identity store on Bob's
    // side has Alice's real key bound to her address. The wrapper (via
    // libsignal's identity check) must refuse.
    let result = decrypt_message(
        malicious_ct,
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
        &mut bob.store.pre_key_store,
        &bob.store.signed_pre_key_store,
        &mut bob.store.kyber_pre_key_store,
    )
    .await;

    assert!(
        result.is_err(),
        "forged message from a different identity must be rejected, got: {result:?}"
    );
}

// ── Empty plaintext (boundary) ──────────────────────────────────────────────

#[tokio::test]
async fn empty_plaintext_round_trips() {
    let mut alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    let ct = encrypt_message(
        b"",
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("encrypt empty");

    let serialized = serialize(&ct);
    let recovered = decrypt_message(
        serialized,
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await
    .expect("decrypt empty");

    assert!(
        recovered.is_empty(),
        "empty plaintext must round-trip as empty"
    );
}

// ── Ciphertext serialization shape ─────────────────────────────────────────

#[tokio::test]
async fn initial_message_serializes_as_a_prekey_message() {
    let alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    let ct = encrypt_message(
        b"hello",
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("encrypt");

    assert!(
        matches!(ct, CiphertextMessage::PreKeySignalMessage(_)),
        "first message to a new session must be a PreKeySignalMessage"
    );

    let serialized = serialize(&ct);
    // The wrapper tags an initial-message envelope as PreKey so the parser
    // dispatches to PreKeySignalMessage::try_from on decrypt.
    assert_eq!(serialized.message_type(), MessageType::PreKey);
    // Sanity: the libsignal serializer produced a non-empty envelope.
    assert!(!serialized.as_bytes().is_empty());
}

#[tokio::test]
async fn followup_message_serializes_as_a_whisper_message() {
    let mut alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;
    bob_establishes_session_with_alice(&alice, &mut bob).await;

    // Bob initial -> Alice decrypt -> Alice reply.
    let initial = encrypt_message(
        b"hi",
        &alice.address,
        &bob.address,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
    )
    .await
    .expect("encrypt");
    let initial_ct = serialize(&initial);
    decrypt_message(
        initial_ct,
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await
    .expect("initial decrypt");

    let reply = encrypt_message(
        b"hi back",
        &bob.address,
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
    )
    .await
    .expect("encrypt reply");

    assert!(
        matches!(reply, CiphertextMessage::SignalMessage(_)),
        "followup message on an acknowledged session must be a SignalMessage"
    );

    let serialized = serialize(&reply);
    // The wrapper tags a followup envelope as Ciphertext so the parser
    // dispatches to SignalMessage::try_from on decrypt.
    assert_eq!(serialized.message_type(), MessageType::Ciphertext);
    assert!(!serialized.as_bytes().is_empty());
}

// ── Decoding rejections (input validation at the wrapper boundary) ──────────

#[tokio::test]
async fn empty_serialized_ciphertext_is_rejected_by_libsignal_parser() {
    let mut alice = make_party("alice", 1).await;
    let bogus = SerializedCiphertext::new(MessageType::Ciphertext, Vec::new());

    let result = decrypt_message(
        bogus,
        &bob_address_for_test(),
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await;

    assert_eq!(result, Err(DoubleRatchetError::MalformedCiphertext));
}

#[tokio::test]
async fn ciphertext_tagged_as_prekey_but_bytes_are_too_short_is_rejected() {
    let mut alice = make_party("alice", 1).await;
    // Bytes are too short to be a valid PreKeySignalMessage protobuf.
    let bogus = SerializedCiphertext::new(MessageType::PreKey, vec![0x01, 0x02]);

    let result = decrypt_message(
        bogus,
        &bob_address_for_test(),
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await;

    assert_eq!(result, Err(DoubleRatchetError::MalformedCiphertext));
}

#[tokio::test]
async fn prekey_tagged_body_that_is_not_valid_protobuf_is_rejected() {
    let mut alice = make_party("alice", 1).await;
    // Garbage payload declared as a PreKeySignalMessage: the libsignal
    // parser rejects the protobuf, which the wrapper maps to
    // MalformedCiphertext.
    let bogus = SerializedCiphertext::new(MessageType::PreKey, vec![0xFFu8; 32]);

    let result = decrypt_message(
        bogus,
        &bob_address_for_test(),
        &alice.address,
        &mut alice.store.session_store,
        &mut alice.store.identity_store,
        &mut alice.store.pre_key_store,
        &alice.store.signed_pre_key_store,
        &mut alice.store.kyber_pre_key_store,
    )
    .await;

    assert_eq!(result, Err(DoubleRatchetError::MalformedCiphertext));
}

fn bob_address_for_test() -> ProtocolAddress {
    ProtocolAddress::new("bob".to_string(), device(1))
}

// ── libsignal error-type discrimination ─────────────────────────────────────

#[test]
fn libsignal_error_helper_recognizes_untrusted_identity() {
    // libsignal surfaces "untrusted identity after TOFU" via this error.
    assert!(DoubleRatchetError::is_untrusted_identity(
        &SignalProtocolError::UntrustedIdentity(ProtocolAddress::new(
            "alice".to_string(),
            device(1),
        )),
    ));
}

#[test]
fn libsignal_error_helper_does_not_match_other_errors() {
    let err = SignalProtocolError::InvalidMessage(
        libsignal_protocol::CiphertextMessageType::PreKey,
        "test".to_string(),
    );
    assert!(!DoubleRatchetError::is_untrusted_identity(&err));
}
