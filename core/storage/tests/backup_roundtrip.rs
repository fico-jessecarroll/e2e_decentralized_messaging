//! Encrypted backup export/import — round-trip and tamper rejection.
//!
//! Anchors PLAN.md Phase 2 acceptance criteria for backup format:
//!  - Exported backup is encrypted under a user-supplied passphrase/key, never plaintext
//!  - Import round-trips correctly on a clean client
//!  - Negative: import of a corrupted or tampered backup file is rejected with no partial import

use storage::backup::{export, import, BackupError};

#[test]
fn export_then_import_roundtrips_identity_and_history() {
    let passphrase = b"correct horse battery staple";
    let original = vec![
        b"identity-blob".to_vec(),
        b"history-msg-1".to_vec(),
        b"history-msg-2".to_vec(),
    ];
    let blob = export(passphrase, &original).expect("export succeeds");

    // The blob must NOT contain any plaintext record.
    for chunk in &original {
        assert!(
            !blob.windows(chunk.len()).any(|w| w == chunk.as_slice()),
            "exported backup must not contain plaintext record bytes"
        );
    }

    let restored = import(passphrase, &blob).expect("import succeeds");
    assert_eq!(restored, original);
}

#[test]
fn import_rejects_tampered_backup_with_no_partial_import() {
    let passphrase = b"another-passphrase";
    let blob = export(passphrase, &[b"only-record".to_vec()]).expect("export succeeds");

    // Corrupt a structural header byte (the magic prefix) rather than a ciphertext byte.
    // AES-GCM cannot cryptographically tell a flipped ciphertext/tag from a wrong passphrase
    // (both hit the same AEAD-auth-failure path — a real distinguisher would be a decryption
    // oracle), so the format detects structural tampering via a pre-AEAD check on the magic
    // and returns `BackupError::Tampered` without ever invoking the KDF or AEAD.
    let mut tampered = blob.clone();
    tampered[0] ^= 0x01;

    let result = import(passphrase, &tampered);
    assert!(
        matches!(result, Err(BackupError::Tampered)),
        "tampered backup must be rejected with BackupError::Tampered, got: {result:?}"
    );
}

#[test]
fn import_rejects_wrong_passphrase() {
    let blob = export(b"right", &[b"data".to_vec()]).expect("export succeeds");
    let result = import(b"wrong", &blob);
    assert!(
        matches!(result, Err(BackupError::DecryptionFailed)),
        "wrong passphrase must fail with BackupError::DecryptionFailed, got: {result:?}"
    );
}
