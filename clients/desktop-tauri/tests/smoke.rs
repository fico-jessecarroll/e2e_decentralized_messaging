//! Tauri desktop shell smoke test — links /core, surfaces errors gracefully.
//!
//! Anchors PLAN.md Phase 5 acceptance criteria:
//!  - Tauri app builds and links against /core
//!  - Negative: a core API error surfaces to the UI as a defined error state, not a crash

use core_crypto::identity::IdentityKeyPair;

#[test]
fn tauri_shell_compiles_against_core_crypto_api() {
    // The Tauri shell must depend on core directly (no re-implementation).
    // This test forces the core API surface to be reachable from the client crate.
    let id = IdentityKeyPair::generate();
    let pub_bytes = id.public().to_bytes();
    assert!(
        !pub_bytes.is_empty(),
        "core identity API reachable from client"
    );
}

#[test]
fn core_api_error_becomes_defined_error_state_not_panic() {
    // Calling a deliberately-malformed core API operation must surface a Result::Err,
    // not panic. The Tauri UI side is then expected to render that Err as a state.
    use core_crypto::session::SessionError;
    let result: Result<(), SessionError> = core_crypto::session::establish_with_malformed_prekey();
    assert!(
        result.is_err(),
        "malformed-input core operation must return Err, not panic"
    );
}
