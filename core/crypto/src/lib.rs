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

/// Per-device identity keys and the primary-signed linking model (PLAN.md §4).
///
/// Each device already gets its own identity key for free — every call to
/// [`generate_identity_key_pair`] produces an independent keypair, so a device simply generates
/// one locally and never needs to see any other device's private key.
///
/// What's missing is the *link*: proof that a given device's identity key belongs to the same
/// account as a trusted primary device. We build that on `libsignal`'s own alternate-identity
/// signature (`IdentityKeyPair::sign_alternate_identity` / `IdentityKey::verify_alternate_identity`)
/// — the exact primitive Signal uses to bind a PNI identity key to an ACI identity key under the
/// same account. The semantics are exactly what we need ("this other identity key belongs to the
/// same logical account as me"), domain-separation prefix included, so we reuse it unmodified
/// rather than inventing a second signing scheme, per PLAN.md's "don't reinvent crypto" rule.
/// Errors signing or verifying a device-identity link, or admitting a device into a [`DeviceSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLinkError {
    /// The underlying `libsignal` signing call failed. Unreachable in practice for the
    /// Curve25519 keys this crate generates — the only key type it produces — but propagated
    /// rather than panicking, per the project's fail-securely posture.
    SigningFailed,
    /// `signature` is missing, malformed, or was not produced by the claimed primary identity
    /// key over this exact device identity key.
    InvalidSignature,
}

impl fmt::Display for DeviceLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningFailed => write!(f, "device-identity signing failed"),
            Self::InvalidSignature => write!(f, "invalid or missing device-identity signature"),
        }
    }
}

impl std::error::Error for DeviceLinkError {}

/// Sign `device_identity_key` with the primary device's identity key, attesting that the device
/// belongs to the same account as `primary`. Pass the result to [`DeviceSet::add_device`] (or
/// [`verify_device_identity`] directly) to admit the device.
pub fn sign_device_identity(
    primary: &IdentityKeyPair,
    device_identity_key: &IdentityKey,
) -> Result<Box<[u8]>, DeviceLinkError> {
    primary
        .sign_alternate_identity(device_identity_key, &mut OsRng.unwrap_err())
        .map_err(|_| DeviceLinkError::SigningFailed)
}

/// Verify that `signature` is a valid link from `primary_identity_key` to
/// `device_identity_key`, i.e. that the primary device vouched for this device's identity key.
///
/// Fails closed: any malformed or mismatched signature returns `false` rather than propagating
/// an error, so callers cannot accidentally treat a verification failure as anything but "not
/// linked".
pub fn verify_device_identity(
    _primary_identity_key: &IdentityKey,
    _device_identity_key: &IdentityKey,
    _signature: &[u8],
) -> bool {
    todo!("TDD placeholder — tests must fail here first")
}

/// An account: a primary device's identity key plus the set of other devices' identity keys it
/// has vouched for.
///
/// Admission is fail-closed — [`DeviceSet::add_device`] verifies the primary-signed link before
/// inserting and leaves the set unchanged on any failure, so an unsigned or improperly signed
/// device key can never appear in [`DeviceSet::linked_devices`].
pub struct DeviceSet {
    primary_identity_key: IdentityKey,
    linked_devices: Vec<IdentityKey>,
}

impl DeviceSet {
    /// Start a new account anchored to `primary_identity_key`.
    pub fn new(primary_identity_key: IdentityKey) -> Self {
        Self {
            primary_identity_key,
            linked_devices: Vec::new(),
        }
    }

    /// The account's primary identity key.
    pub fn primary_identity_key(&self) -> &IdentityKey {
        &self.primary_identity_key
    }

    /// Admit `device_identity_key` if `signature` is a valid primary-signed link for it.
    ///
    /// Returns [`DeviceLinkError::InvalidSignature`] — and leaves the set unchanged — if the
    /// signature is missing, malformed, or was not produced by this account's primary identity
    /// key over this exact device identity key.
    pub fn add_device(
        &mut self,
        _device_identity_key: IdentityKey,
        _signature: &[u8],
    ) -> Result<(), DeviceLinkError> {
        todo!("TDD placeholder — tests must fail here first")
    }

    /// The devices admitted so far, in admission order. Does not include the primary device
    /// itself — see [`DeviceSet::primary_identity_key`].
    pub fn linked_devices(&self) -> &[IdentityKey] {
        &self.linked_devices
    }
}

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

#[cfg(test)]
mod device_link_tests {
    use crate::{
        generate_identity_key_pair, sign_device_identity, verify_device_identity, DeviceLinkError,
        DeviceSet,
    };

    #[test]
    fn verify_device_identity_accepts_a_valid_primary_signed_link() {
        let primary = generate_identity_key_pair();
        let device = generate_identity_key_pair();

        let signature = sign_device_identity(&primary, device.identity_key()).expect("signs");

        assert!(verify_device_identity(
            primary.identity_key(),
            device.identity_key(),
            &signature,
        ));
    }

    #[test]
    fn sign_device_identity_is_randomized_across_calls() {
        let primary = generate_identity_key_pair();
        let device = generate_identity_key_pair();

        let first = sign_device_identity(&primary, device.identity_key()).expect("signs");
        let second = sign_device_identity(&primary, device.identity_key()).expect("signs");

        assert_ne!(first, second);
    }

    #[test]
    fn verify_device_identity_rejects_an_empty_unsigned_signature() {
        let primary = generate_identity_key_pair();
        let device = generate_identity_key_pair();

        assert!(!verify_device_identity(
            primary.identity_key(),
            device.identity_key(),
            &[],
        ));
    }

    #[test]
    fn verify_device_identity_rejects_a_signature_from_a_non_primary_key() {
        let primary = generate_identity_key_pair();
        let impostor = generate_identity_key_pair();
        let device = generate_identity_key_pair();

        // Signed by `impostor`, not the claimed `primary`.
        let signature = sign_device_identity(&impostor, device.identity_key()).expect("signs");

        assert!(!verify_device_identity(
            primary.identity_key(),
            device.identity_key(),
            &signature,
        ));
    }

    #[test]
    fn verify_device_identity_rejects_a_signature_for_a_different_device_key() {
        let primary = generate_identity_key_pair();
        let device = generate_identity_key_pair();
        let other_device = generate_identity_key_pair();

        let signature = sign_device_identity(&primary, device.identity_key()).expect("signs");

        // The signature was issued for `device`, not `other_device`.
        assert!(!verify_device_identity(
            primary.identity_key(),
            other_device.identity_key(),
            &signature,
        ));
    }

    #[test]
    fn verify_device_identity_rejects_truncated_signature_bytes() {
        let primary = generate_identity_key_pair();
        let device = generate_identity_key_pair();

        let signature = sign_device_identity(&primary, device.identity_key()).expect("signs");

        assert!(!verify_device_identity(
            primary.identity_key(),
            device.identity_key(),
            &signature[..signature.len() - 1],
        ));
    }

    #[test]
    fn device_set_starts_with_no_linked_devices() {
        let primary = generate_identity_key_pair();

        let set = DeviceSet::new(*primary.identity_key());

        assert!(set.linked_devices().is_empty());
    }

    #[test]
    fn device_set_admits_a_validly_signed_device() {
        let primary = generate_identity_key_pair();
        let device = generate_identity_key_pair();
        let signature = sign_device_identity(&primary, device.identity_key()).expect("signs");

        let mut set = DeviceSet::new(*primary.identity_key());
        set.add_device(*device.identity_key(), &signature)
            .expect("valid link admits");

        assert_eq!(set.linked_devices(), [*device.identity_key()]);
    }

    #[test]
    fn device_set_admits_multiple_validly_signed_devices() {
        let primary = generate_identity_key_pair();
        let device_a = generate_identity_key_pair();
        let device_b = generate_identity_key_pair();
        let signature_a = sign_device_identity(&primary, device_a.identity_key()).expect("signs");
        let signature_b = sign_device_identity(&primary, device_b.identity_key()).expect("signs");

        let mut set = DeviceSet::new(*primary.identity_key());
        set.add_device(*device_a.identity_key(), &signature_a)
            .expect("valid link admits");
        set.add_device(*device_b.identity_key(), &signature_b)
            .expect("valid link admits");

        assert_eq!(
            set.linked_devices(),
            [*device_a.identity_key(), *device_b.identity_key()]
        );
    }

    #[test]
    fn device_set_rejects_an_unsigned_device_key_and_leaves_the_set_unchanged() {
        let primary = generate_identity_key_pair();
        let device = generate_identity_key_pair();

        let mut set = DeviceSet::new(*primary.identity_key());
        let result = set.add_device(*device.identity_key(), &[]);

        assert_eq!(result, Err(DeviceLinkError::InvalidSignature));
        assert!(set.linked_devices().is_empty());
    }

    #[test]
    fn device_set_rejects_a_device_signed_by_a_non_primary_key_and_leaves_the_set_unchanged() {
        let primary = generate_identity_key_pair();
        let impostor = generate_identity_key_pair();
        let device = generate_identity_key_pair();
        let signature = sign_device_identity(&impostor, device.identity_key()).expect("signs");

        let mut set = DeviceSet::new(*primary.identity_key());
        let result = set.add_device(*device.identity_key(), &signature);

        assert_eq!(result, Err(DeviceLinkError::InvalidSignature));
        assert!(set.linked_devices().is_empty());
    }

    #[test]
    fn device_set_rejects_a_signature_replayed_for_a_different_device_key() {
        let primary = generate_identity_key_pair();
        let device = generate_identity_key_pair();
        let other_device = generate_identity_key_pair();
        let signature = sign_device_identity(&primary, device.identity_key()).expect("signs");

        let mut set = DeviceSet::new(*primary.identity_key());
        let result = set.add_device(*other_device.identity_key(), &signature);

        assert_eq!(result, Err(DeviceLinkError::InvalidSignature));
        assert!(set.linked_devices().is_empty());
    }
}
