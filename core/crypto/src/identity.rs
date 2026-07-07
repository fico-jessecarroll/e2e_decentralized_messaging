//! Byte-oriented identity keypair facade for client shells (e.g. the Tauri desktop shell,
//! PLAN.md Phase 5) that only need "generate a keypair, get its public bytes" and shouldn't have
//! to depend on `libsignal_protocol` types directly to do it.
//!
//! No crypto is reimplemented here — [`IdentityKeyPair::generate`] delegates to
//! [`crate::generate_identity_key_pair`], the same CSPRNG-backed Curve25519 keypair generator the
//! rest of this crate uses.

use crate::generate_identity_key_pair;

/// A Curve25519 identity keypair.
pub struct IdentityKeyPair(libsignal_protocol::IdentityKeyPair);

impl IdentityKeyPair {
    /// Generate a new identity keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        Self(generate_identity_key_pair())
    }

    /// This keypair's public identity key.
    pub fn public(&self) -> PublicIdentityKey {
        PublicIdentityKey(self.0.identity_key().serialize())
    }
}

/// The public half of an [`IdentityKeyPair`]: a type-tagged Curve25519 point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentityKey(Box<[u8]>);

impl PublicIdentityKey {
    /// The serialized public key bytes (1-byte key-type tag + 32-byte point).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::IdentityKeyPair;

    #[test]
    fn generate_produces_nonempty_public_bytes() {
        let id = IdentityKeyPair::generate();
        assert_eq!(id.public().to_bytes().len(), 33);
    }

    #[test]
    fn generate_is_randomized_across_calls() {
        let a = IdentityKeyPair::generate();
        let b = IdentityKeyPair::generate();
        assert_ne!(a.public().to_bytes(), b.public().to_bytes());
    }
}
