//! Round-trip + fail-closed persistence tests for identity/session/prekey state.
//!
//! These tests assert the concrete behavior the PLAN.md acceptance criteria call
//! out: state round-trips through persist/load without corruption, and corrupted
//! or truncated rows fail closed (no partial state leaks back to the caller).

use crypto::generate_identity_key_pair;
use storage::{EncryptedStore, StoreError};
use tempfile::tempdir;

#[test]
fn identity_pair_roundtrips_through_persist_load() {
    let dir = tempdir().unwrap();
    let key = [0x42u8; 32];
    let store = EncryptedStore::open(dir.path(), &key).expect("store opens");

    let id = generate_identity_key_pair();
    let serialized = id.serialize();

    store.put_identity(&serialized).expect("persist");
    let loaded = store.get_identity().expect("load").expect("present");

    assert_eq!(
        serialized.as_ref(),
        loaded.as_slice(),
        "round-trip must be byte-identical"
    );
}

#[test]
fn loading_truncated_blob_fails_closed() {
    let dir = tempdir().unwrap();
    let key = [0x42u8; 32];
    let store = EncryptedStore::open(dir.path(), &key).expect("store opens");

    // Write a deliberately truncated row directly to the underlying table,
    // bypassing the typed API so the corruption survives into load().
    let truncated: Vec<u8> = vec![0u8; 7];
    store.put_raw("identity", &truncated).expect("raw write");

    let res = store.get_identity();
    assert!(
        matches!(res, Err(StoreError::Corrupted { .. })),
        "truncated row must fail closed with StoreError::Corrupted, got {res:?}"
    );
}

#[test]
fn loading_with_wrong_key_fails_closed_not_returns_partial() {
    let dir = tempdir().unwrap();
    let key_a = [0x42u8; 32];
    let key_b = [0x99u8; 32];

    let id = generate_identity_key_pair();
    let serialized = id.serialize();
    {
        let store_a = EncryptedStore::open(dir.path(), &key_a).unwrap();
        store_a.put_identity(&serialized).unwrap();
    }

    // The store fails closed at open when the key cannot decrypt the existing file, so the
    // identity bytes are never reachable to a wrong-key holder. Key verification happens in
    // `open`, not deferred to `get_identity`.
    let res = EncryptedStore::open(dir.path(), &key_b);
    assert!(
        matches!(res, Err(StoreError::InvalidKey)),
        "wrong-key open must fail closed with StoreError::InvalidKey, got {res:?}"
    );
}
