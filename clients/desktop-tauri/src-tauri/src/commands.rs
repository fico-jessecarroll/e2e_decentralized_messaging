//! Tauri commands invoked from the JS/TS UI (`dist/main.js`). Each one delegates directly to
//! `core_crypto` — no crypto or session logic is reimplemented here — and maps any core
//! `Result::Err` into a serializable [`crate::error::ShellError`], so a malformed-input failure
//! renders as a defined UI error state instead of propagating as an opaque panic across the IPC
//! boundary.

use crate::error::ShellError;

/// Generate a fresh identity keypair and return its public key bytes.
#[tauri::command]
pub fn generate_identity() -> Result<Vec<u8>, ShellError> {
    let identity = core_crypto::identity::IdentityKeyPair::generate();
    Ok(identity.public().to_bytes())
}

/// Deliberately attempt PQXDH session establishment against a malformed prekey bundle. Exercises
/// the "core error surfaces as a defined UI error state, not a crash" contract end-to-end from
/// the JS/TS side.
#[tauri::command]
pub fn establish_malformed_session() -> Result<(), ShellError> {
    core_crypto::session::establish_with_malformed_prekey().map_err(ShellError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises the actual `#[tauri::command]` entry points the JS/TS UI invokes over IPC
    // (see `dist/main.js`), not just the underlying `core_crypto` functions they delegate to —
    // a broken command signature or a broken `ShellError` mapping would otherwise compile and
    // pass CI undetected, since `commands` is a private module no external test can reach.

    #[test]
    fn generate_identity_returns_non_empty_public_key() {
        let result = generate_identity();
        let public_key_bytes = result.expect("generate_identity must succeed");
        assert!(
            !public_key_bytes.is_empty(),
            "public key bytes returned to the UI must not be empty"
        );
    }

    #[test]
    fn establish_malformed_session_surfaces_err_not_panic() {
        let result = establish_malformed_session();
        assert!(
            matches!(result, Err(ShellError::Session(_))),
            "malformed-prekey command must return Err(ShellError::Session), got: {result:?}"
        );
    }

    #[test]
    fn establish_malformed_session_error_serializes_to_the_shape_main_js_expects() {
        // `dist/main.js`'s `renderError` reads `err.kind` and `err.message` directly off the
        // rejected IPC value, so the serde tag/content field names are part of the UI contract.
        let result = establish_malformed_session();
        let err = result.expect_err("malformed-prekey command must return Err");
        let json = serde_json::to_value(&err).expect("ShellError must serialize");

        assert_eq!(json["kind"], "Session");
        assert!(
            json["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty()),
            "serialized error must carry a non-empty message, got: {json}"
        );
    }
}
