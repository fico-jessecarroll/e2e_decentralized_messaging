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
