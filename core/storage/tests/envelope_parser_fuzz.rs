use proptest::prelude::*;
use storage::{parse_envelope, StoreError};

/// Property-based test that `parse_envelope` never panics on arbitrary input.
proptest! {
    #[test]
    fn prop_parse_envelope(bytes in any::<Vec<u8>>()) {
        // The function should return either Ok or Err(StoreError::Corrupted), but must not panic.
        let _ = parse_envelope(&bytes);
    }
}

/// Explicit boundary-case tests for documentation and quick sanity checks.
#[test]
fn empty_input() {
    assert!(matches!(parse_envelope(&[]), Err(StoreError::Corrupted { .. })),
            "empty input should be corrupted");
}

#[test]
fn short_prefix() {
    // Less than 4 bytes, cannot contain a length prefix.
    let data = vec![1u8, 2, 3];
    assert!(matches!(parse_envelope(&data), Err(StoreError::Corrupted { .. })),
            "short prefix should be corrupted");
}

#[test]
fn mismatched_length() {
    // Prefix says length 5 but only 3 bytes of body.
    let mut data = Vec::new();
    data.extend_from_slice(&5u32.to_be_bytes());
    data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    assert!(matches!(parse_envelope(&data), Err(StoreError::Corrupted { .. })),
            "mismatched length should be corrupted");
}
