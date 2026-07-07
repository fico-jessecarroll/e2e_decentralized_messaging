pub mod api {
    use crypto::identity::IdentityKeyPair;

    pub struct IdentityHandle {
        inner: IdentityKeyPair,
    }

    impl IdentityHandle {
        pub fn public_bytes(&self) -> Vec<u8> {
            self.inner.public().to_bytes()
        }
    }

    pub fn generate_identity() -> IdentityHandle {
        IdentityHandle { inner: IdentityKeyPair::generate() }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum FfiError {
        #[error("invalid key material")]
        InvalidKey,
        #[error("encryption failed")]
        EncryptionFailed,
    }

    pub fn encrypt_message(key_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, FfiError> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        if key_bytes.len() != 32 {
            return Err(FfiError::InvalidKey);
        }
        let cipher = Aes256Gcm::new_from_slice(key_bytes).map_err(|_| FfiError::InvalidKey)?;
        let nonce = Nonce::from_slice(&[0u8; 12]);
        cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| FfiError::EncryptionFailed)
    }
}
