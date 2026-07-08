//! UniFFI binding layer — generated bindings expose documented core API.
//!
//! Anchors PLAN.md Phase 8 acceptance criteria:
//!  - Generated bindings expose the documented core API
//!  - Contract tests pass against the core API spec from both binding sides
//!  - Negative: an invalid input across the FFI boundary returns a defined error, not a crash

use core_bindings_uniffi::api::{encrypt_message, generate_identity, FfiError};

#[test]
fn bindings_expose_documented_identity_and_message_api() {
    // The function names below are the documented UniFFI surface.
    // If any of them is renamed/removed, the binding contract is broken.
    let id = generate_identity();
    let pub_bytes = id.public_bytes();
    assert!(
        !pub_bytes.is_empty(),
        "identity generation must produce non-empty pubkey"
    );
}

#[test]
fn ffi_boundary_returns_defined_error_for_invalid_input_not_panic() {
    // Garbage bytes through the FFI boundary must yield an Err, not a panic
    // or a process abort. This is the binding-layer equivalent of a panic-safe API.
    let garbage: Vec<u8> = vec![0xFF; 16];
    let result: Result<Vec<u8>, FfiError> = encrypt_message(&garbage, b"payload");
    assert!(
        result.is_err(),
        "invalid-input across FFI must return Err(FfiError), got: {result:?}"
    );
}
