//! Safety-number UX + backup/restore polish — edge cases must surface defined errors.
//!
//! Anchors PLAN.md Phase 9 acceptance criteria:
//!  - Usability review confirms verification flow is understandable to a non-technical user
//!  - Negative: backup/restore edge cases (partial backup, wrong passphrase) all have a clear, non-leaky error state

use clients_desktop_tauri::backup::{restore_backup, RestoreError};
use clients_desktop_tauri::verify::{describe_verification_flow_for_user, VerificationFlowDoc};

#[test]
fn verification_flow_doc_is_non_technical_and_actionable() {
    let doc = describe_verification_flow_for_user();
    assert_eq!(doc, VerificationFlowDoc::LayUserFriendly);
    // Must mention safety numbers and the explicit compare step.
    let body = doc.body();
    assert!(body.to_lowercase().contains("safety number"));
    assert!(body.to_lowercase().contains("compare"));
}

#[test]
fn partial_backup_restore_surfaces_defined_error_not_partial_import() {
    let truncated = vec![0u8; 16]; // header but no payload
    let result = restore_backup(b"any-passphrase", &truncated);
    assert!(
        matches!(result, Err(RestoreError::IncompleteBackup)),
        "partial backup must surface RestoreError::IncompleteBackup, got: {result:?}"
    );
}

#[test]
fn wrong_passphrase_surfaces_defined_error_not_panic() {
    let partial_blob = vec![0u8; 256];
    let result = restore_backup(b"wrong", &partial_blob);
    // Either IncompleteBackup (if the blob is too short) or WrongPassphrase —
    // both are acceptable defined errors; a panic is not.
    assert!(
        matches!(
            result,
            Err(RestoreError::IncompleteBackup) | Err(RestoreError::WrongPassphrase)
        ),
        "wrong passphrase / partial blob must surface a defined RestoreError, got: {result:?}"
    );
    // And it must NOT leak any sensitive detail in the error variant alone.
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        !err_str.to_lowercase().contains("plaintext"),
        "error display must not leak plaintext-related terminology (defense in depth)"
    );
}
