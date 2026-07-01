//! Auto-replenishment + signed-prekey fallback tests.
//!
//! Anchors PLAN.md Phase 4 acceptance criteria:
//!  - Replenish one-time prekeys when the pool drops below a low-watermark
//!  - Session establishment still succeeds via the signed-prekey fallback when
//!    no one-time prekey is available (no hard failure on OTPK exhaustion)
//!
//! Tests use the real `crypto` API surface: [`PreKeyPool`] for replenishment, and the
//! async store-based [`establish_outbound_session`] + PQXDH [`build_prekey_bundle`] for the
//! fallback path. At the pinned libsignal revision every bundle carries a Kyber KEM prekey
//! (PQXDH); the one-time prekey is the optional element whose absence exercises the
//! signed-prekey fallback.

use crypto::prekey::{generate_signed_pre_key, PreKeyPool};
use crypto::session::{build_prekey_bundle, establish_outbound_session, generate_kyber_prekey};

use libsignal_protocol::{
    DeviceId, InMemSignalProtocolStore, KyberPreKeyId, ProtocolAddress, Timestamp,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

/// Test registration id (matches the value `crypto::ratchet_session` uses).
const REGISTRATION_ID: u32 = 1;
/// A valid libp2p/Signal device id (1..=127).
const DEVICE_ID: u8 = 1;

fn device_id() -> DeviceId {
    DeviceId::new(DEVICE_ID).expect("DEVICE_ID is a valid device id (1..=127)")
}

#[test]
fn pool_replenishes_below_low_watermark() {
    let mut pool = PreKeyPool::with_low_watermark(10);
    // Drain the pool to below the watermark (5 remaining).
    for _ in 0..(pool.capacity() - 5) {
        let _ = pool.take_one_time().unwrap();
    }
    assert!(
        pool.below_watermark(),
        "5 remaining must be below watermark=10"
    );

    pool.replenish_to_target(20).expect("replenish ok");

    assert!(
        !pool.below_watermark(),
        "replenished pool must clear watermark"
    );
    assert!(
        pool.remaining() >= 20,
        "replenished pool must hold at least the target (got {})",
        pool.remaining()
    );
}

#[tokio::test]
async fn session_establishment_succeeds_with_signed_prekey_fallback_when_no_one_time() {
    // Provider (Bob): identity + signed prekey + Kyber prekey, ZERO one-time prekeys (exhausted).
    // At the pinned libsignal revision a PQXDH bundle always carries a Kyber KEM prekey; the
    // one-time prekey is the only optional element, so passing `None` for it exercises the
    // signed-prekey fallback path the story requires.
    let bob = crypto::generate_identity_key_pair();
    let signed = generate_signed_pre_key(&bob, 1, Timestamp::from_epoch_millis(0));
    let kyber =
        generate_kyber_prekey(KyberPreKeyId::from(1u32), bob.private_key()).expect("kyber prekey");
    let bundle = build_prekey_bundle(
        REGISTRATION_ID,
        device_id(),
        &bob,
        &signed,
        &kyber,
        // <- no one-time prekey: the signed-prekey fallback path
        None,
    )
    .expect("bundle built without one-time prekey (fallback)");

    // Sender (Alice): establishes an outbound session from Bob's no-OTPK bundle. A successful
    // return proves the signed-prekey fallback — establishment does NOT require a one-time
    // prekey and must not hard-fail on OTPK exhaustion.
    let alice = crypto::generate_identity_key_pair();
    let mut store = InMemSignalProtocolStore::new(alice, REGISTRATION_ID).expect("alice store");
    let alice_addr = ProtocolAddress::new("alice".to_string(), device_id());
    let bob_addr = ProtocolAddress::new("bob".to_string(), device_id());
    let mut rng = OsRng.unwrap_err();

    let res = establish_outbound_session(
        &alice_addr,
        &bob_addr,
        &bundle,
        &mut store.session_store,
        &mut store.identity_store,
        &mut rng,
    )
    .await;

    assert!(
        res.is_ok(),
        "establishment must succeed via signed-prekey fallback; got {:?}",
        res.err()
    );
}

#[test]
fn replenish_never_creates_duplicate_one_time_prekey_ids() {
    let mut pool = PreKeyPool::with_low_watermark(5);
    let ids_before: std::collections::HashSet<_> = pool.snapshot_ids().into_iter().collect();
    pool.replenish_to_target(15).unwrap();
    let ids_after: std::collections::HashSet<_> = pool.snapshot_ids().into_iter().collect();

    let new_ids: Vec<_> = ids_after.difference(&ids_before).copied().collect();
    let unique: std::collections::HashSet<_> = new_ids.iter().copied().collect();
    assert_eq!(
        new_ids.len(),
        unique.len(),
        "replenish produced duplicate one-time prekey ids"
    );
}
