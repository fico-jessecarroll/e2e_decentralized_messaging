//! Blind store-and-forward on the relay — ciphertext only, TTL bounded.
//!
//! Anchors PLAN.md Phase 4 acceptance criteria:
//!  - Message delivered correctly when recipient reconnects within TTL
//!  - Negative: relay cannot decrypt or read stored envelope contents
//!  - Negative: envelope expired past TTL is purged and not delivered

use relay::store::{RelayStore, StoreError};
use std::time::Duration;

#[test]
fn stored_envelope_delivered_when_recipient_picks_up_within_ttl() {
    let store = RelayStore::new();
    let envelope = vec![0xAAu8; 256];
    store.store("recipient-id", envelope.clone(), Duration::from_secs(60)).expect("store");

    let delivered = store.pickup("recipient-id").expect("pickup succeeds");
    assert_eq!(delivered, envelope);
}

#[test]
fn relay_cannot_read_or_decrypt_stored_envelope_contents() {
    // The store's public API must not expose any plaintext-meaningful operation
    // on the envelope bytes (no decrypt, no parse, no read-as-string).
    let store = RelayStore::new();
    let envelope = vec![0xBB; 512];
    store.store("recipient-id", envelope, Duration::from_secs(60)).expect("store");

    // The relay's documented API surface must consist only of: store / pickup / purge / count.
    let documented: &[&str] = &["store", "pickup", "purge", "count"];
    for name in documented {
        assert!(
            RelayStore::has_method(name),
            "RelayStore must expose `{name}` opaquely (no plaintext access)"
        );
    }
    // And it must NOT expose any of these:
    for forbidden in &["decrypt", "read_plaintext", "parse"] {
        assert!(
            !RelayStore::has_method(forbidden),
            "RelayStore must not expose `{forbidden}` — relay must remain blind to envelope contents"
        );
    }
}

#[test]
fn envelope_expired_past_ttl_is_purged_and_not_delivered() {
    let store = RelayStore::new();
    store.store("recipient-id", vec![0xCC; 128], Duration::from_millis(0)).expect("store");

    // Wait long enough for the TTL to elapse deterministically.
    std::thread::sleep(Duration::from_millis(5));

    let result = store.pickup("recipient-id");
    assert!(
        matches!(result, Err(StoreError::Expired) | Err(StoreError::NotFound)),
        "expired envelope must be purged and not delivered, got: {result:?}"
    );
}
