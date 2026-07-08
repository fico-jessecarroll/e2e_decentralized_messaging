//! WASM safety-number / fingerprint derivation tests.
//!
//! TDD tests for the new byte-oriented WASM-facing function added in this story:
//!  - `derive_safety_number` — takes two parties' public identity key bytes and
//!    returns the display-formatted safety number string.
//!
//! Required cases:
//!  - Deterministic: same two keys → same safety number (called twice).
//!  - Differs for a different key pair.
//!  - Malformed / wrong-length key bytes rejected as a structured `WasmError`
//!    (Err, not a panic) — mirroring the existing WASM error-boundary contract.
//!
//! Negative/boundary cases:
//!  - Empty key bytes rejected as Err (not a panic)
//!  - Wrong-length key bytes rejected as Err (not a panic)
//!  - At least one Result::Err crosses the WASM boundary as a structured error
//!    with non-empty `kind` and `message` fields

use core_bindings_wasm::{derive_safety_number, generate_identity};

// ---------------------------------------------------------------------------
// Positive path: deterministic derivation
// ---------------------------------------------------------------------------

#[test]
fn safety_number_is_deterministic_same_keys_called_twice() {
    let alice = generate_identity();
    let bob = generate_identity();
    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();

    let first = derive_safety_number(&alice_pub, &bob_pub).expect("derivation must succeed");
    let second = derive_safety_number(&alice_pub, &bob_pub).expect("derivation must succeed");

    assert_eq!(
        first, second,
        "same two keys must yield the same safety number"
    );
    assert!(
        !first.is_empty(),
        "safety number must be a non-empty display string"
    );
}

// ---------------------------------------------------------------------------
// Positive path: different key pairs produce different safety numbers
// ---------------------------------------------------------------------------

#[test]
fn safety_number_differs_for_different_key_pair() {
    let alice = generate_identity();
    let bob = generate_identity();
    let carol = generate_identity();

    let alice_pub = alice.public_bytes();
    let bob_pub = bob.public_bytes();
    let carol_pub = carol.public_bytes();

    let sn_ab = derive_safety_number(&alice_pub, &bob_pub).expect("derivation must succeed");
    let sn_ac = derive_safety_number(&alice_pub, &carol_pub).expect("derivation must succeed");

    assert_ne!(
        sn_ab, sn_ac,
        "different key pairs must produce different safety numbers"
    );
}

// ---------------------------------------------------------------------------
// Negative path: malformed / wrong-length key bytes rejected as Err, never panic
// ---------------------------------------------------------------------------

#[test]
fn empty_key_bytes_rejected_as_err_not_panic() {
    let alice = generate_identity();
    let alice_pub = alice.public_bytes();

    let result = derive_safety_number(&alice_pub, &[]);
    assert!(
        result.is_err(),
        "empty remote key bytes must surface as Err, got: {result:?}"
    );
}

#[test]
fn wrong_length_key_bytes_rejected_as_err_not_panic() {
    let alice = generate_identity();
    let alice_pub = alice.public_bytes();
    let too_short = [0u8; 10]; // not 33 bytes — cannot be a serialized identity key

    let result = derive_safety_number(&alice_pub, &too_short);
    assert!(
        result.is_err(),
        "wrong-length key bytes must surface as Err, got: {result:?}"
    );
}

#[test]
fn both_keys_malformed_rejected_as_err_not_panic() {
    let garbage_a = [0xABu8; 5];
    let garbage_b = [0xCDu8; 20];

    let result = derive_safety_number(&garbage_a, &garbage_b);
    assert!(
        result.is_err(),
        "malformed keys must surface as Err, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Contract: structured error crosses the WASM boundary with kind + message
// ---------------------------------------------------------------------------

#[test]
fn malformed_key_error_is_structured_wasm_error() {
    let alice = generate_identity();
    let alice_pub = alice.public_bytes();
    let malformed = [0u8; 10];

    let result = derive_safety_number(&alice_pub, &malformed);
    let err = result.expect_err("malformed key must return Err");

    assert!(
        !err.kind().is_empty(),
        "structured WasmError must carry a non-empty kind tag"
    );
    assert!(
        !err.message().is_empty(),
        "structured WasmError must carry a non-empty message"
    );
}
