//! Small extensions on libsignal's `IdentityKey` / `IdentityKeyPair`.
//!
//! These exist purely so downstream crates (e.g. `core/transport`'s Sealed Sender module)
//! can ask for a Curve25519 *public* key and its raw bytes from an `IdentityKeyPair` without
//! pulling the rest of `libsignal_protocol` into their public API. No crypto is added — the
//! serialized form is exactly what `libsignal` itself uses for `IdentityKey::serialize`.
//!
//! PLAN.md §2 ("we do not roll our own crypto") and PLAN.md §3 ("Identity = a device-generated
//! Ed25519/Curve25519 keypair"). The Curve25519 public key here is the 32-byte X25519 point
//! the Sealed Sender envelope's ephemeral-static ECDH runs against; the surrounding 1-byte
//! libsignal type tag is stripped in [`IdentityKeyExt::to_x25519_bytes`] so the bytes fed to
//! `x25519-dalek` match the point format it expects.

use libsignal_protocol::{IdentityKey, IdentityKeyPair};

/// Extension methods on `IdentityKeyPair` that return the public half without exposing
/// `libsignal_protocol` types to downstream crates.
pub trait IdentityKeyPairExt2 {
    /// The public identity key half of this keypair (a `Curve25519` / X25519 key).
    fn public(&self) -> IdentityKey;
}

impl IdentityKeyPairExt2 for IdentityKeyPair {
    fn public(&self) -> IdentityKey {
        // `IdentityKeyPair::identity_key` returns a reference to the inner `IdentityKey`,
        // which is a thin newtype around a `PublicKey`. We clone the wrapper so the caller
        // can hold the result without borrowing from the keypair.
        self.identity_key().clone()
    }
}

/// Extension methods on `IdentityKey` that return its raw bytes in the form downstream
/// crypto layers (x25519-dalek, etc.) expect.
pub trait IdentityKeyExt {
    /// The raw 32-byte X25519 public key, with the 1-byte libsignal type tag stripped.
    ///
    /// `IdentityKey::serialize()` returns a 33-byte buffer: 1 byte type tag + 32 bytes
    /// point. `x25519-dalek::PublicKey::from_bytes` rejects anything that isn't exactly
    /// 32 bytes, so we strip the tag here.
    fn to_bytes(&self) -> [u8; 32];
}

impl IdentityKeyExt for IdentityKey {
    fn to_bytes(&self) -> [u8; 32] {
        let mut serialized = Vec::new();
        // `IdentityKey::serialize` is the canonical libsignal encoding — used by
        // `derive_safety_number` and by every other interop point in this crate, so it is
        // the only acceptable source for the raw bytes here.
        let bytes = self.serialize();
        let tag = bytes[0];
        debug_assert_eq!(
            tag, 0x05,
            "libsignal identity keys are expected to be Curve25519 (type tag 0x05); got 0x{tag:02x}"
        );
        // 33 bytes total: 1 tag + 32 point. We've asserted the tag above; copy the point.
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[1..33]);
        out
    }
}
