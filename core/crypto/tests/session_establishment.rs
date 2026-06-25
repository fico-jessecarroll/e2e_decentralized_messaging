use crypto::prekey::{generate_one_time_pre_keys, generate_signed_pre_key};
use crypto::session::{build_prekey_bundle, establish_outbound_session, generate_kyber_prekey};
use libsignal_protocol::{
    DeviceId, GenericSignedPreKey, IdentityKeyPair, InMemSignalProtocolStore, KyberPreKeyId,
    KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyStore, ProtocolAddress, SessionStore,
    SessionUsabilityRequirements, SignalProtocolError, SignedPreKeyId, SignedPreKeyStore,
    Timestamp,
};
use rand::TryRngCore as _;
use rand::rngs::OsRng;

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

    let signed_prekey = generate_signed_pre_key(&identity, 1, now_ts());
    let kyber_prekey =
        generate_kyber_prekey(KyberPreKeyId::from(1u32), identity.private_key()).unwrap();
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
    store.save_pre_key(PreKeyId::from(1u32), otpk).await.unwrap();

    let bundle =
        build_prekey_bundle(42, did, &identity, &signed_prekey, &kyber_prekey, Some(otpk))
            .unwrap();

    Party {
        store,
        bundle,
        address: ProtocolAddress::new(name.to_string(), did),
    }
}

// ── Happy path ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn bob_establishes_pqxdh_session_from_alices_bundle() {
    let alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;

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

    let session = bob
        .store
        .session_store
        .load_session(&alice.address)
        .await
        .unwrap()
        .expect("session must be present after establishment");

    assert!(
        session
            .has_usable_sender_chain(
                std::time::SystemTime::now(),
                SessionUsabilityRequirements::empty()
            )
            .is_ok(),
        "established session must have a usable outbound ratchet chain"
    );
}

#[tokio::test]
async fn establishing_session_twice_overwrites_with_fresh_session() {
    let alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;

    for _ in 0..2 {
        establish_outbound_session(
            &bob.address,
            &alice.address,
            &alice.bundle,
            &mut bob.store.session_store,
            &mut bob.store.identity_store,
            &mut OsRng.unwrap_err(),
        )
        .await
        .expect("establishment must succeed");
    }

    let session = bob
        .store
        .session_store
        .load_session(&alice.address)
        .await
        .unwrap()
        .expect("session present");
    assert!(session
        .has_usable_sender_chain(
            std::time::SystemTime::now(),
            SessionUsabilityRequirements::empty()
        )
        .is_ok());
}

// ── Negative: tampered bundle fields ─────────────────────────────────────────

#[tokio::test]
async fn tampered_signed_prekey_signature_is_rejected() {
    let alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;

    let bad_bundle = PreKeyBundle::new(
        alice.bundle.registration_id().unwrap(),
        alice.bundle.device_id().unwrap(),
        alice
            .bundle
            .pre_key_id()
            .unwrap()
            .zip(alice.bundle.pre_key_public().unwrap()),
        alice.bundle.signed_pre_key_id().unwrap(),
        alice.bundle.signed_pre_key_public().unwrap(),
        vec![0u8; 64], // tampered signature
        alice.bundle.kyber_pre_key_id().unwrap(),
        alice.bundle.kyber_pre_key_public().unwrap().clone(),
        alice.bundle.kyber_pre_key_signature().unwrap().to_vec(),
        *alice.bundle.identity_key().unwrap(),
    )
    .unwrap();

    let result = establish_outbound_session(
        &bob.address,
        &alice.address,
        &bad_bundle,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
        &mut OsRng.unwrap_err(),
    )
    .await;

    assert!(
        matches!(result, Err(SignalProtocolError::SignatureValidationFailed)),
        "tampered signed-prekey signature must be rejected, got: {result:?}"
    );
}

#[tokio::test]
async fn tampered_kyber_prekey_signature_is_rejected() {
    let alice = make_party("alice", 1).await;
    let mut bob = make_party("bob", 1).await;

    let bad_bundle = PreKeyBundle::new(
        alice.bundle.registration_id().unwrap(),
        alice.bundle.device_id().unwrap(),
        alice
            .bundle
            .pre_key_id()
            .unwrap()
            .zip(alice.bundle.pre_key_public().unwrap()),
        alice.bundle.signed_pre_key_id().unwrap(),
        alice.bundle.signed_pre_key_public().unwrap(),
        alice.bundle.signed_pre_key_signature().unwrap().to_vec(),
        alice.bundle.kyber_pre_key_id().unwrap(),
        alice.bundle.kyber_pre_key_public().unwrap().clone(),
        vec![0u8; 64], // tampered Kyber signature
        *alice.bundle.identity_key().unwrap(),
    )
    .unwrap();

    let result = establish_outbound_session(
        &bob.address,
        &alice.address,
        &bad_bundle,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
        &mut OsRng.unwrap_err(),
    )
    .await;

    assert!(
        matches!(result, Err(SignalProtocolError::SignatureValidationFailed)),
        "tampered Kyber prekey signature must be rejected, got: {result:?}"
    );
}

#[tokio::test]
async fn bundle_with_different_identity_key_is_rejected_after_tofu() {
    let alice = make_party("alice", 1).await;
    let alice_imposter = make_party("alice_imposter", 1).await;
    let mut bob = make_party("bob", 1).await;

    // First contact — TOFU records Alice's real identity key.
    establish_outbound_session(
        &bob.address,
        &alice.address,
        &alice.bundle,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
        &mut OsRng.unwrap_err(),
    )
    .await
    .expect("first TOFU session");

    // Present imposter's bundle at Alice's address — must be rejected.
    let imposter_at_alice_addr = ProtocolAddress::new(
        alice.address.name().to_string(),
        alice.address.device_id(),
    );
    let result = establish_outbound_session(
        &bob.address,
        &imposter_at_alice_addr,
        &alice_imposter.bundle,
        &mut bob.store.session_store,
        &mut bob.store.identity_store,
        &mut OsRng.unwrap_err(),
    )
    .await;

    assert!(
        matches!(result, Err(SignalProtocolError::UntrustedIdentity(_))),
        "identity-key mismatch after TOFU must be rejected, got: {result:?}"
    );
}

// ── build_prekey_bundle / generate_kyber_prekey API ─────────────────────────

#[test]
fn build_prekey_bundle_without_one_time_prekey_succeeds() {
    let mut rng = OsRng.unwrap_err();
    let identity = IdentityKeyPair::generate(&mut rng);
    let signed_prekey = generate_signed_pre_key(&identity, 1, now_ts());
    let kyber_prekey =
        generate_kyber_prekey(KyberPreKeyId::from(1u32), identity.private_key()).unwrap();

    build_prekey_bundle(42, device(1), &identity, &signed_prekey, &kyber_prekey, None)
        .expect("bundle without OTC prekey must be valid");
}

#[test]
fn generated_kyber_prekey_signature_verifies_against_identity() {
    let mut rng = OsRng.unwrap_err();
    let identity = IdentityKeyPair::generate(&mut rng);
    let kyber_prekey =
        generate_kyber_prekey(KyberPreKeyId::from(1u32), identity.private_key()).unwrap();

    let public_key = kyber_prekey.public_key().unwrap();
    let signature = kyber_prekey.signature().unwrap();

    assert!(
        identity
            .identity_key()
            .public_key()
            .verify_signature(&public_key.serialize(), &signature),
        "Kyber prekey signature must verify against the generating identity key"
    );
}
