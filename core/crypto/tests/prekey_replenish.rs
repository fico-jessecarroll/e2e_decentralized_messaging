//! Auto-replenishment + signed-prekey fallback tests.
//!
//! Anchors PLAN.md Phase 4 acceptance criteria:
//!  - Replenish one-time prekeys when the pool drops below a low-watermark
//!  - Session establishment still succeeds via the signed-prekey fallback when
//!    no one-time prekey is available (no hard failure on OTPK exhaustion)

use crypto::prekey::{
    build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey,
    PreKeyError, PreKeyPool,
};

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

    assert!(!pool.below_watermark(), "replenished pool must clear watermark");
    assert!(
        pool.remaining() >= 20,
        "replenished pool must hold at least the target (got {})",
        pool.remaining()
    );
}

#[test]
fn session_establishment_succeeds_with_signed_prekey_fallback_when_no_one_time() {
    // Provider has a signed prekey but ZERO one-time prekeys (exhausted).
    let identity = crypto::generate_identity_key_pair().unwrap();
    let signed = generate_signed_prekey(&identity.private_key(), 1).unwrap();
    let bundle = build_prekey_bundle(
        identity.registration_id(),
        identity.device_id(),
        &identity,
        &signed,
        /* one_time_prekey = */ None, // <- the fallback path
    )
    .expect("bundle built without one-time prekey (fallback)");

    let recipient = crypto::generate_identity_key_pair().unwrap();
    let session = crypto::session::establish_outbound(
        &recipient,
        &bundle,
        /* accept_no_one_time = */ true,
    );

    assert!(
        session.is_ok(),
        "establishment must succeed via signed-prekey fallback; got {:?}",
        session.err()
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
