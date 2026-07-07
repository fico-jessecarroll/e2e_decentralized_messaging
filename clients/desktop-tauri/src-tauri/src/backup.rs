//! Backup restore logic for desktop‑tauri.
//!
//! The tests exercise the public `restore_backup` function which wraps
//! `core::storage::import`.  It maps the underlying `BackupError` into a
//! more UI‑friendly set of variants that are guaranteed not to leak
//! sensitive information.

use core_storage::backup::{import, BackupError};

/// Errors returned by :func:`restore_backup`.
#[derive(Debug)]
pub enum RestoreError {
    /// The backup blob was too short or otherwise structurally invalid.
    IncompleteBackup,
    /// The passphrase supplied does not match the one used to create the backup.
    WrongPassphrase,
    /// The backup data has been tampered with (corrupted header or body).
    Tampered,
}

/// Restore a backup blob using the provided *passphrase*.
///
/// This function performs minimal size checks and then delegates to
/// `core::storage::import`.  It translates the low‑level errors into
/// :enum:`RestoreError`.
pub fn restore_backup(passphrase: &[u8], blob: &[u8]) -> Result<Vec<Vec<u8>>, RestoreError> {
    // Minimal size check – magic(4)+ver(1)+salt(16)+nonce(12)+tag(16)+at least one u32
    const MIN_SIZE: usize = 4 + 1 + 16 + 12 + 16 + 4;
    if blob.len() < MIN_SIZE {
        return Err(RestoreError::IncompleteBackup);
    }

    match import(passphrase, blob) {
        Ok(records) => Ok(records),
        Err(e) => match e {
            BackupError::Tampered | BackupError::Malformed => {
                // Structural corruption – treat as incomplete.
                Err(RestoreError::IncompleteBackup)
            }
            BackupError::DecryptionFailed => Err(RestoreError::WrongPassphrase),
        },
    }
}
