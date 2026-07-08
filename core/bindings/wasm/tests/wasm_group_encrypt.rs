//! WASM Sender Keys group encrypt/decrypt tests (PLAN.md Phase 8 — follow-on story).
//!
//! TDD tests for the new WASM-facing group crypto functions, backed by
//! `core/protocol/src/group.rs`'s Sender Keys implementation:
//!  - `group_create` — create a new group session from a sender identity
//!  - `group_add_member` — add a member by their public identity key bytes
//!  - `group_remove_member` — remove a member and rotate the sender key (forward-secure)
//!  - `group_encrypt` — encrypt plaintext as the sender, returning ciphertext bytes
//!  - `group_decrypt` — decrypt ciphertext as a member identity, returning plaintext
//!
//! Required negative/boundary cases:
//!  - A non-member cannot decrypt a group message (returns Err, not a panic).
//!  - A removed member's ciphertext is no longer decryptable after key rotation (mirrors
//!    the existing `member_removal_rotation.rs` negative test).
//!  - At least one `Result::Err` crosses the WASM boundary as a structured JS-visible
//!    `WasmError` (with `kind` + `message`), not a panic — the same contract desktop's
//!    `commands.rs` tests assert for `ShellError` serialization shape.
//!
//! These tests run natively (the same `#[test]` harness the CI `test` job uses) — the
//! `wasm-bindgen` attribute is a no-op outside `wasm32-unknown-unknown`, so the functions
//! are callable as ordinary Rust functions here.

use core_bindings_wasm::{
    generate_identity, group_add_member, group_create, group_decrypt, group_encrypt,
    group_remove_member, WasmError,
};

// ---------------------------------------------------------------------------
// Positive path: create a group, add members, encrypt, all members decrypt
// ---------------------------------------------------------------------------

#[test]
fn all_group_members_can_decrypt_a_group_message() {
    let sender = generate_identity();
    let member_a = generate_identity();
    let member_b = generate_identity();

    let group = group_create(&sender);
    let group = group_add_member(&group, &member_a.public_bytes());
    let group = group_add_member(&group, &member_b.public_bytes());

    let plaintext = b"group chat message";
    let ciphertext = group_encrypt(&group, &sender, plaintext).expect("encrypt must succeed");

    let plain_a = group_decrypt(&group, &member_a, &ciphertext).expect("member a decrypts");
    let plain_b = group_decrypt(&group, &member_b, &ciphertext).expect("member b decrypts");

    assert_eq!(plain_a.as_slice(), plaintext.as_slice());
    assert_eq!(plain_b.as_slice(), plaintext.as_slice());
}

// ---------------------------------------------------------------------------
// Negative path: a non-member cannot decrypt a group message
// ---------------------------------------------------------------------------

#[test]
fn non_member_cannot_decrypt_a_group_message() {
    let sender = generate_identity();
    let member = generate_identity();
    let outsider = generate_identity();

    let group = group_create(&sender);
    let group = group_add_member(&group, &member.public_bytes());

    let ciphertext =
        group_encrypt(&group, &sender, b"private to the group").expect("encrypt must succeed");

    let result = group_decrypt(&group, &outsider, &ciphertext);
    assert!(
        result.is_err(),
        "non-member must NOT be able to decrypt the group message, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Negative path: removed member cannot decrypt after key rotation
// (mirrors member_removal_rotation.rs's negative test)
// ---------------------------------------------------------------------------

#[test]
fn removed_member_cannot_decrypt_messages_sent_after_their_removal() {
    let sender = generate_identity();
    let alice = generate_identity();
    let bob = generate_identity();
    let eve = generate_identity();

    let group = group_create(&sender);
    let group = group_add_member(&group, &alice.public_bytes());
    let group = group_add_member(&group, &bob.public_bytes());
    let group = group_add_member(&group, &eve.public_bytes());

    // Remove Eve — remove_member rotates the sender key internally (forward-secure by default).
    let group = group_remove_member(&group, &eve.public_bytes());

    let ciphertext = group_encrypt(&group, &sender, b"eve is gone, this is private")
        .expect("encrypt must succeed");

    // Eve can no longer decrypt via the live group state.
    let result = group_decrypt(&group, &eve, &ciphertext);
    assert!(
        result.is_err(),
        "removed member must NOT decrypt post-removal message, got: {result:?}"
    );

    // Remaining members still can.
    let plain_a = group_decrypt(&group, &alice, &ciphertext).expect("alice still decrypts");
    let plain_b = group_decrypt(&group, &bob, &ciphertext).expect("bob still decrypts");
    assert_eq!(plain_a.as_slice(), b"eve is gone, this is private");
    assert_eq!(plain_b.as_slice(), b"eve is gone, this is private");
}

// ---------------------------------------------------------------------------
// Contract: at least one Result::Err crosses the WASM boundary as a structured
// JS-visible WasmError (kind + message), not a panic — mirroring desktop's
// ShellError serialization shape test.
// ---------------------------------------------------------------------------

#[test]
fn group_decrypt_error_surfaces_as_structured_wasm_error_not_panic() {
    let sender = generate_identity();
    let member = generate_identity();
    let outsider = generate_identity();

    let group = group_create(&sender);
    let group = group_add_member(&group, &member.public_bytes());

    let ciphertext =
        group_encrypt(&group, &sender, b"private to the group").expect("encrypt must succeed");

    let result = group_decrypt(&group, &outsider, &ciphertext);
    let err = result.expect_err("non-member decrypt must return Err, not Ok or a panic");

    // The WasmError must carry a non-empty kind tag and a non-empty message — the same
    // shape desktop's `commands.rs` asserts for `ShellError` serialization (err.kind +
    // err.message), so JS code can switch on kind and display message.
    assert!(
        !err.kind().is_empty(),
        "structured WasmError must carry a non-empty kind tag"
    );
    assert!(
        !err.message().is_empty(),
        "structured WasmError must carry a non-empty message"
    );
}

// ---------------------------------------------------------------------------
// Negative path: decrypting malformed/truncated ciphertext returns Err, not panic
// ---------------------------------------------------------------------------

#[test]
fn malformed_ciphertext_rejected_as_err_not_panic() {
    let sender = generate_identity();
    let member = generate_identity();

    let group = group_create(&sender);
    let group = group_add_member(&group, &member.public_bytes());

    let garbage = [0u8; 3]; // too short to be a valid ciphertext
    let result = group_decrypt(&group, &member, &garbage);
    assert!(
        result.is_err(),
        "malformed ciphertext must return Err, not Ok or a panic, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Boundary: multiple messages from the same session all decrypt correctly
// (chain-key ratchet produces distinct keys per message)
// ---------------------------------------------------------------------------

#[test]
fn multiple_messages_from_same_session_all_decrypt() {
    let sender = generate_identity();
    let member = generate_identity();

    let group = group_create(&sender);
    let group = group_add_member(&group, &member.public_bytes());

    let msg1 = b"first group message";
    let ct1 = group_encrypt(&group, &sender, msg1).expect("encrypt 1");
    let pt1 = group_decrypt(&group, &member, &ct1).expect("decrypt 1");
    assert_eq!(pt1.as_slice(), msg1.as_slice());

    let msg2 = b"second group message";
    let ct2 = group_encrypt(&group, &sender, msg2).expect("encrypt 2");
    let pt2 = group_decrypt(&group, &member, &ct2).expect("decrypt 2");
    assert_eq!(pt2.as_slice(), msg2.as_slice());

    let msg3 = b"third group message";
    let ct3 = group_encrypt(&group, &sender, msg3).expect("encrypt 3");
    let pt3 = group_decrypt(&group, &member, &ct3).expect("decrypt 3");
    assert_eq!(pt3.as_slice(), msg3.as_slice());
}

// ---------------------------------------------------------------------------
// Boundary: the WasmError type is usable from test code (verifies it's exported)
// ---------------------------------------------------------------------------

#[test]
fn wasm_error_type_is_exported_and_constructible() {
    // This is a compile-time check that WasmError is in the public API surface.
    // The non-member decrypt test above exercises the runtime path; this ensures
    // the type itself is importable (wasm-bindgen exports it for JS).
    let _ = std::marker::PhantomData::<WasmError>;
}
