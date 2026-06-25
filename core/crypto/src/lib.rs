//! Identity keypair generation and safety-number (fingerprint) derivation.
//!
//! Identity keys are Curve25519 keypairs generated via `libsignal`'s `IdentityKeyPair`
//! (PLAN.md §3). Safety numbers reuse `libsignal`'s own `Fingerprint` type — the exact
//! numeric-fingerprint algorithm Signal clients display for out-of-band verification — so this
//! crate does not reimplement or vary from the upstream algorithm; it only selects the
//! version/iteration parameters Signal's own clients use.

use std::fmt;

use libsignal_protocol::{Fingerprint, IdentityKey, IdentityKeyPair};
use rand::rngs::OsRng;
use rand::TryRngCore;

pub mod prekey;

/// Fingerprint version and iteration count Signal clients use for safety-number display
/// (matches `libsignal`'s own published test vectors for version 1).
const SAFETY_NUMBER_VERSION: u32 = 1;
const SAFETY_NUMBER_ITERATIONS: u32 = 5200;

/// Generate a new Curve25519 identity keypair from the OS CSPRNG.
///
/// The private key never leaves this struct; callers must keep it confidential per the
/// storage-layer threat model (`docs/threat-model.md` §4.3).
pub fn generate_identity_key_pair() -> IdentityKeyPair {
    IdentityKeyPair::generate(&mut OsRng.unwrap_err())
}

/// A safety-number derivation failed because an identity key was malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyNumberError {
    /// The key was the wrong length or carried an unrecognized key-type tag.
    InvalidIdentityKey,
}

impl fmt::Display for SafetyNumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentityKey => write!(f, "malformed or unrecognized identity key"),
        }
    }
}

impl std::error::Error for SafetyNumberError {}

/// Derive the 60-digit numeric safety number for a pair of identities, matching Signal's
/// published fingerprint algorithm (version 1, 5200 iterations).
///
/// `local_id`/`remote_id` are stable identifiers bound into the fingerprint (per Signal's
/// algorithm, typically each party's handle) so it can't be replayed against a different
/// pairing. The result is identical regardless of which party calls it — `local`/`remote` are
/// sorted internally — so both sides of a conversation can compare it out-of-band.
pub fn derive_safety_number(
    local_id: &[u8],
    local_identity_key: &[u8],
    remote_id: &[u8],
    remote_identity_key: &[u8],
) -> Result<String, SafetyNumberError> {
    let local_key = IdentityKey::decode(local_identity_key)
        .map_err(|_| SafetyNumberError::InvalidIdentityKey)?;
    let remote_key = IdentityKey::decode(remote_identity_key)
        .map_err(|_| SafetyNumberError::InvalidIdentityKey)?;

    let fingerprint = Fingerprint::new(
        SAFETY_NUMBER_VERSION,
        SAFETY_NUMBER_ITERATIONS,
        local_id,
        &local_key,
        remote_id,
        &remote_key,
    )
    .map_err(|_| SafetyNumberError::InvalidIdentityKey)?;

    fingerprint
        .display_string()
        .map_err(|_| SafetyNumberError::InvalidIdentityKey)
}

#[cfg(test)]
mod tests {
    use crate::{derive_safety_number, generate_identity_key_pair, SafetyNumberError};
    use libsignal_protocol::IdentityKeyPair;

    #[test]
    fn generate_identity_key_pair_produces_a_valid_curve25519_identity_key() {
        let identity = generate_identity_key_pair();

        // Curve25519 identity keys serialize as a 1-byte key-type tag plus a 32-byte point.
        assert_eq!(identity.identity_key().serialize().len(), 33);
    }

    #[test]
    fn generate_identity_key_pair_uses_a_csprng_and_is_not_deterministic() {
        let a = generate_identity_key_pair();
        let b = generate_identity_key_pair();

        assert_ne!(a.identity_key().serialize(), b.identity_key().serialize());
    }

    #[test]
    fn derive_safety_number_is_deterministic() {
        let alice = generate_identity_key_pair();
        let bob = generate_identity_key_pair();

        let first = derive_safety_number(
            b"alice",
            &alice.identity_key().serialize(),
            b"bob",
            &bob.identity_key().serialize(),
        )
        .expect("valid keys");

        let second = derive_safety_number(
            b"alice",
            &alice.identity_key().serialize(),
            b"bob",
            &bob.identity_key().serialize(),
        )
        .expect("valid keys");

        assert_eq!(first, second);
    }

    #[test]
    fn derive_safety_number_matches_signals_published_algorithm_test_vector() {
        // Test vector from libsignal's own fingerprint.rs (testVectorsVersion1 in the
        // upstream Java client) — pinned `libsignal-protocol` rev
        // 38428a7bb70509910d72b3f78208c1daf33774d8.
        let alice_identity: [u8; 33] = [
            0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d, 0x27, 0xb8, 0xd4, 0x9c, 0xa7,
            0xc0, 0x9e, 0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6, 0xfc, 0xca, 0x5c, 0xe1,
            0x3c, 0x70, 0x64, 0xd8, 0x68,
        ];
        let bob_identity: [u8; 33] = [
            0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba, 0x1c, 0xf2, 0xde, 0x97, 0x8d,
            0x4d, 0x5d, 0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81, 0x44, 0x02, 0xb5, 0xc0, 0xdb,
            0xd9, 0x6f, 0xda, 0x90, 0x7b,
        ];

        let safety_number = derive_safety_number(
            b"+14152222222",
            &alice_identity,
            b"+14153333333",
            &bob_identity,
        )
        .expect("valid keys");

        assert_eq!(
            safety_number,
            "300354477692869396892869876765458257569162576843440918079131"
        );
    }

    #[test]
    fn derive_safety_number_is_symmetric_regardless_of_calling_party() {
        let alice = generate_identity_key_pair();
        let bob = generate_identity_key_pair();

        let from_alice = derive_safety_number(
            b"alice",
            &alice.identity_key().serialize(),
            b"bob",
            &bob.identity_key().serialize(),
        )
        .expect("valid keys");

        let from_bob = derive_safety_number(
            b"bob",
            &bob.identity_key().serialize(),
            b"alice",
            &alice.identity_key().serialize(),
        )
        .expect("valid keys");

        assert_eq!(from_alice, from_bob);
    }

    #[test]
    fn derive_safety_number_differs_for_different_identity_keys() {
        let alice = generate_identity_key_pair();
        let bob = generate_identity_key_pair();
        let mallory = generate_identity_key_pair();

        let with_bob = derive_safety_number(
            b"alice",
            &alice.identity_key().serialize(),
            b"bob",
            &bob.identity_key().serialize(),
        )
        .expect("valid keys");

        let with_mallory = derive_safety_number(
            b"alice",
            &alice.identity_key().serialize(),
            b"bob",
            &mallory.identity_key().serialize(),
        )
        .expect("valid keys");

        assert_ne!(with_bob, with_mallory);
    }

    #[test]
    fn derive_safety_number_rejects_empty_local_key() {
        let bob = generate_identity_key_pair();

        let result = derive_safety_number(b"alice", &[], b"bob", &bob.identity_key().serialize());

        assert_eq!(result, Err(SafetyNumberError::InvalidIdentityKey));
    }

    #[test]
    fn derive_safety_number_rejects_short_remote_key() {
        let alice = generate_identity_key_pair();

        let result = derive_safety_number(
            b"alice",
            &alice.identity_key().serialize(),
            b"bob",
            &[0x05, 0x01, 0x02],
        );

        assert_eq!(result, Err(SafetyNumberError::InvalidIdentityKey));
    }

    #[test]
    fn derive_safety_number_rejects_unknown_key_type_tag() {
        let alice = generate_identity_key_pair();
        // 0xFF is not a recognized key-type tag (Curve25519/Djb is 0x05).
        let malformed_remote_key = [0xFFu8; 33];

        let result = derive_safety_number(
            b"alice",
            &alice.identity_key().serialize(),
            b"bob",
            &malformed_remote_key,
        );

        assert_eq!(result, Err(SafetyNumberError::InvalidIdentityKey));
    }

    #[test]
    fn keypair_type_is_reexported_for_downstream_crates() {
        let _identity: IdentityKeyPair = generate_identity_key_pair();
    }
}
