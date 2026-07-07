//! UniFFI-facing API surface: a thin, byte-oriented facade over `crypto` for Swift/Kotlin
//! client shells (PLAN.md Phase 8). No cryptography is implemented here — every function
//! delegates to an already-audited primitive in `crypto`, per PLAN.md §8's "don't reinvent
//! crypto" rule.

pub mod api {
    use crypto::identity::{IdentityKeyPair, PublicIdentityKey};

    pub struct IdentityHandle {
        inner: IdentityKeyPair,
    }

    impl IdentityHandle {
        pub fn public_bytes(&self) -> Vec<u8> {
            self.inner.public().to_bytes()
        }
    }

    pub fn generate_identity() -> IdentityHandle {
        IdentityHandle {
            inner: IdentityKeyPair::generate(),
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum FfiError {
        /// `key_bytes` was not a well-formed type-tagged Curve25519 public identity key, or the
        /// sealed blob was structurally invalid on the decrypt side.
        #[error("invalid key material")]
        InvalidKey,
        /// The AEAD step failed (wrong recipient key or tampered ciphertext — the two are
        /// intentionally indistinguishable, matching `crypto::identity::SealError`'s own
        /// failure model).
        #[error("encryption failed")]
        EncryptionFailed,
    }

    impl From<crypto::identity::SealError> for FfiError {
        fn from(e: crypto::identity::SealError) -> Self {
            match e {
                crypto::identity::SealError::Malformed => FfiError::InvalidKey,
                crypto::identity::SealError::DecryptionFailed => FfiError::EncryptionFailed,
            }
        }
    }

    /// Encrypt `plaintext` to the recipient identified by `key_bytes` (their serialized public
    /// identity key).
    ///
    /// Delegates entirely to [`crypto::identity::PublicIdentityKey::seal`] — the same
    /// ephemeral-static-ECDH + HKDF + AEAD construction used elsewhere in this codebase (see
    /// `core/transport/src/sealed_sender.rs` and the sender-keys group wrapper sealing). A fresh
    /// ephemeral key and a fresh random nonce are generated internally on every call, so there
    /// is no nonce-reuse risk here regardless of how many times this function is called with the
    /// same `key_bytes`.
    ///
    /// This is a general-purpose "seal bytes to a public key" primitive, not the Signal session
    /// protocol — real 1:1/group message sending uses `crypto::DoubleRatchetSession` /
    /// `protocol::group::GroupSession` internally, which this FFI layer will expose via their
    /// own dedicated entry points in a later story. `encrypt_message` exists to prove the FFI
    /// error-boundary contract (malformed input across FFI returns `Err`, never panics).
    pub fn encrypt_message(key_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, FfiError> {
        let recipient = PublicIdentityKey::from_bytes(key_bytes);
        recipient.seal(plaintext).map_err(FfiError::from)
    }
}
