//! WASM prekey bundle and X3DH/PQXDH session establishment tests.
//!
//! TDD tests for the new byte-oriented WASM-facing functions added in this story:
//!  - `generate_prekey_bundle` — produces a length-prefixed byte blob from an IdentityHandle
//!  - `establish_session_from_bundle` — consumes a peer's bundle bytes, returns a SessionHandle
//!  - `establish_with_malformed_prekey` — mirrors desktop's contract: returns Err, never panics
//!
//! Negative/boundary cases:
//!  - Malformed prekey bundle bytes rejected as Err (not a panic)
//!  - Tampered / unsigned prekey bundle rejected as Err
//!  - At least one Result::Err crosses the WASM boundary as a structured error

use core_bindings_wasm::{
    establish_session_from_bundle, establish_with_malformed_prekey, generate_identity,
    generate_prekey_bundle,
};

// ---------------------------------------------------------------------------
// Positive path: bundle generation + session establishment round-trip
// ---------------------------------------------------------------------------

#[test]
fn generate_prekey_bundle_returns_non_empty_bytes() {
    let identity = generate_identity();
    let bundle_bytes = generate_prekey_bundle(&identity).expect("bundle generation must succeed");
    assert!(
        !bundle_bytes.is_empty(),
        "prekey bundle bytes must not be empty"
    );
}

#[test]
fn establish_session_from_valid_bundle_succeeds() {
    let bob = generate_identity();
    let bundle_bytes = generate_prekey_bundle(&bob).expect("bundle generation must succeed");

    let alice = generate_identity();
    let session = establish_session_from_bundle(&alice, &bundle_bytes);
    assert!(
        session.is_ok(),
        "session establishment from a valid bundle must succeed, got: {:?}",
        session
    );
}

// ---------------------------------------------------------------------------
// Negative path: malformed bundle bytes rejected as Err, never a panic
// ---------------------------------------------------------------------------

#[test]
fn malformed_prekey_bundle_bytes_rejected_as_err_not_panic() {
    let alice = generate_identity();
    // Garbage bytes — not a valid length-prefixed bundle
    let result = establish_session_from_bundle(&alice, &[0u8; 3]);
    assert!(
        result.is_err(),
        "malformed bundle bytes must surface as Err, got: {result:?}"
    );
}

#[test]
fn empty_prekey_bundle_bytes_rejected_as_err_not_panic() {
    let alice = generate_identity();
    let result = establish_session_from_bundle(&alice, &[]);
    assert!(
        result.is_err(),
        "empty bundle bytes must surface as Err, got: {result:?}"
    );
}

#[test]
fn truncated_prekey_bundle_bytes_rejected_as_err_not_panic() {
    let bob = generate_identity();
    let bundle_bytes = generate_prekey_bundle(&bob).expect("bundle generation must succeed");
    // Truncate to half — the length prefix will claim more bytes than available
    let half = &bundle_bytes[..bundle_bytes.len() / 2];
    let alice = generate_identity();
    let result = establish_session_from_bundle(&alice, half);
    assert!(
        result.is_err(),
        "truncated bundle bytes must surface as Err, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Negative path: tampered / unsigned prekey bundle rejected
// ---------------------------------------------------------------------------

#[test]
fn tampered_prekey_bundle_rejected_as_err_not_panic() {
    let bob = generate_identity();
    let mut bundle_bytes = generate_prekey_bundle(&bob).expect("bundle generation must succeed");

    // Flip a byte in the middle of the bundle — this corrupts either the identity key,
    // the signed prekey, or the one-time prekey, all of which must cause rejection.
    let mid = bundle_bytes.len() / 2;
    bundle_bytes[mid] ^= 0xFF;

    let alice = generate_identity();
    let result = establish_session_from_bundle(&alice, &bundle_bytes);
    assert!(
        result.is_err(),
        "tampered bundle bytes must surface as Err, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Contract: establish_with_malformed_prekey mirrors desktop's contract
// ---------------------------------------------------------------------------

#[test]
fn establish_with_malformed_prekey_surfaces_err_not_panic() {
    let result = establish_with_malformed_prekey();
    assert!(
        result.is_err(),
        "malformed-prekey must surface as Err, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Contract: at least one Result::Err crosses the WASM boundary as a
// structured error (same shape contract as desktop's ShellError serialization)
// ---------------------------------------------------------------------------

#[test]
fn wasm_error_carries_kind_and_message_fields() {
    // The structured error must expose a `kind` (variant tag) and a `message`
    // (human-readable detail) so JS code can switch on `kind` and display
    // `message` — the same contract desktop's ShellError serialization shape
    // asserts in clients/desktop-tauri/src-tauri/src/commands.rs tests.
    let result = establish_with_malformed_prekey();
    let err = result.expect_err("malformed-prekey must return Err");
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
fn malformed_bundle_error_is_structured_wasm_error() {
    let alice = generate_identity();
    let result = establish_session_from_bundle(&alice, &[0u8; 3]);
    let err = result.expect_err("malformed bundle must return Err");
    assert!(
        !err.kind().is_empty(),
        "malformed-bundle error must carry a non-empty kind tag"
    );
    assert!(
        !err.message().is_empty(),
        "malformed-bundle error must carry a non-empty message"
    );
}
