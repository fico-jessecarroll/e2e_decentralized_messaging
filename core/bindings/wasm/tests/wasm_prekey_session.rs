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
    bundle_identity_key_bytes, establish_session_from_bundle, establish_with_malformed_prekey,
    generate_identity, generate_prekey_bundle,
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

// ---------------------------------------------------------------------------
// bundle_identity_key_bytes: extract the peer's identity key without
// establishing a session (used by callers that need the remote key for
// safety-number derivation, e.g. the web UI story wiring lookup_prekey to
// SafetyNumberVerification).
// ---------------------------------------------------------------------------

#[test]
fn bundle_identity_key_bytes_matches_the_bundle_owners_public_bytes() {
    let bob = generate_identity();
    let bundle_bytes = generate_prekey_bundle(&bob).expect("bundle generation must succeed");

    let extracted =
        bundle_identity_key_bytes(&bundle_bytes).expect("identity key extraction must succeed");

    assert_eq!(
        extracted,
        bob.public_bytes(),
        "extracted identity key bytes must match the bundle owner's public_bytes()"
    );
}

#[test]
fn bundle_identity_key_bytes_rejects_malformed_bytes() {
    let result = bundle_identity_key_bytes(&[0u8; 3]);
    let err = result.expect_err("malformed bundle bytes must surface as Err");
    assert_eq!(
        err.kind(),
        "MalformedBundle",
        "malformed bundle bytes must surface kind = MalformedBundle, got: {}",
        err.kind()
    );
}

// ---------------------------------------------------------------------------
// Contract: a tampered signed-prekey signature is rejected with a distinct
// kind = "PreKey" error (not the generic "Session" kind), so JS callers can
// tell "the bundle's signature didn't verify" apart from other establishment
// failures and surface a specific message to the user.
//
// The tamper flips a single byte inside the signed-prekey signature field
// only, located by parsing the exact `bundle_to_bytes` wire layout (see
// `core/crypto/src/session.rs`), so this test — unlike the existing
// `tampered_prekey_bundle_rejected_as_err_not_panic` test, which flips a byte
// at the bundle's midpoint and may corrupt any of several fields — proves
// specifically that a signature failure (not e.g. a malformed identity key)
// surfaces the "PreKey" kind.
// ---------------------------------------------------------------------------

fn read_u32_be(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// Byte range of the signed-prekey signature field within a `bundle_to_bytes`
/// blob: registration_id(4) + device_id(4) + identity_key(4+len) +
/// signed_pre_key_id(4) + signed_pre_key_pub(4+len) + signed_pre_key_sig(4+len).
fn signed_prekey_signature_range(bundle_bytes: &[u8]) -> std::ops::Range<usize> {
    let mut offset = 0usize;
    offset += 4; // registration_id
    offset += 4; // device_id
    let identity_key_len = read_u32_be(bundle_bytes, offset) as usize;
    offset += 4 + identity_key_len;
    offset += 4; // signed_pre_key_id
    let spk_pub_len = read_u32_be(bundle_bytes, offset) as usize;
    offset += 4 + spk_pub_len;
    let spk_sig_len = read_u32_be(bundle_bytes, offset) as usize;
    offset += 4;
    offset..offset + spk_sig_len
}

#[test]
fn tampered_signed_prekey_signature_surfaces_prekey_kind() {
    let bob = generate_identity();
    let mut bundle_bytes = generate_prekey_bundle(&bob).expect("bundle generation must succeed");

    let sig_range = signed_prekey_signature_range(&bundle_bytes);
    assert!(
        !sig_range.is_empty(),
        "signed-prekey signature field must be non-empty"
    );
    bundle_bytes[sig_range.start] ^= 0xFF;

    let alice = generate_identity();
    let result = establish_session_from_bundle(&alice, &bundle_bytes);
    let err = result.expect_err("tampered signed-prekey signature must be rejected");
    assert_eq!(
        err.kind(),
        "PreKey",
        "tampered signed-prekey signature must surface kind = PreKey, got: {}",
        err.kind()
    );
}
