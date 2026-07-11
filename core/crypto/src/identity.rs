//! Byte-oriented identity keypair facade for client shells (e.g. the Tauri desktop shell,
//! PLAN.md Phase 5) that only need "generate a keypair, get its public bytes" and shouldn't have
//! to depend on `libsignal_protocol` types directly to do it.
//!
//! No crypto is reimplemented here — [`IdentityKeyPair::generate`] delegates to
//! [`crate::generate_identity_key_pair`], the same CSPRNG-backed Curve25519 keypair generator the
//! rest of this crate uses. [`PublicIdentityKey::seal`]/[`IdentityKeyPair::open_sealed`] use the
//! same ephemeral-static ECDH + HKDF-SHA256 + AEAD construction as
//! `core/transport/src/sealed_sender.rs` — an observer of a sealed blob learns nothing about its
//! contents without the recipient's private identity key.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use libsignal_protocol::{IdentityKey, KeyPair, PublicKey};
use rand::rngs::OsRng;
use rand::{Rng, TryRngCore};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::generate_identity_key_pair;

/// HKDF salt for [`PublicIdentityKey::seal`]/[`IdentityKeyPair::open_sealed`] — a fixed
/// domain-separation string distinct from `sealed_sender.rs`'s `"SealedSender-v1"` so a key
/// derived for one purpose can never be confused with a key derived for the other, even though
/// both start from the same kind of ECDH shared secret.
const SEAL_HKDF_SALT: &[u8] = b"IdentitySeal-v1";
const KEY_LEN: usize = 32;
const EPH_PUB_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MIN_SEALED_LEN: usize = EPH_PUB_LEN + NONCE_LEN + TAG_LEN;

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

    /// Borrow the underlying libsignal `IdentityKeyPair`. Needed by callers (e.g. the WASM
    /// binding) that pass the identity into `DoubleRatchetSession::new_bob` / `new_alice`, which
    /// take `&libsignal_protocol::IdentityKeyPair` directly.
    pub fn as_libsignal(&self) -> &libsignal_protocol::IdentityKeyPair {
        &self.0
    }

    /// Deserialize a keypair from the byte vector produced by [`IdentityKeyPair::serialize`]
    /// (i.e. libsignal's `IdentityKeyPairStructure` protobuf).
    ///
    /// Fails closed: malformed, truncated, or otherwise unparseable bytes return an error and
    /// produce no keypair. This is the inverse of the WASM binding's `IdentityHandle::private_bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, libsignal_protocol::error::SignalProtocolError> {
        Ok(Self(libsignal_protocol::IdentityKeyPair::try_from(bytes)?))
    }

    /// Open a blob previously sealed to this keypair's public key with [`PublicIdentityKey::seal`].
    ///
    /// Fails closed: any structural or authentication failure returns [`SealError`] and no
    /// plaintext. A wrong recipient (not the intended holder) derives a different shared secret,
    /// which the AEAD step rejects — indistinguishable from a tampered blob, which is a feature,
    /// not a limitation (see `sealed_sender.rs`'s failure-model note).
    pub fn open_sealed(&self, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < MIN_SEALED_LEN {
            return Err(SealError::Malformed);
        }
        let eph_pub_bytes = &sealed[..EPH_PUB_LEN];
        let nonce_bytes = &sealed[EPH_PUB_LEN..EPH_PUB_LEN + NONCE_LEN];
        let ciphertext = &sealed[EPH_PUB_LEN + NONCE_LEN..];

        let eph_pub = PublicKey::from_djb_public_key_bytes(eph_pub_bytes)
            .map_err(|_| SealError::Malformed)?;
        let recipient_priv = self.0.private_key();
        let shared = recipient_priv
            .calculate_agreement(&eph_pub)
            .map_err(|_| SealError::Malformed)?;

        let mut key = [0u8; KEY_LEN];
        Hkdf::<Sha256>::new(Some(SEAL_HKDF_SALT), &shared)
            .expand(eph_pub_bytes, &mut key)
            .map_err(|_| SealError::DecryptionFailed)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .expect("ChaCha20-Poly1305 accepts any 32-byte key");
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: eph_pub_bytes,
                },
            )
            .map_err(|_| SealError::DecryptionFailed);

        key.zeroize();
        let mut shared = shared;
        shared.zeroize();

        plaintext
    }
}

/// The public half of an [`IdentityKeyPair`]: a type-tagged Curve25519 point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentityKey(Box<[u8]>);

impl PublicIdentityKey {
    /// Wrap raw bytes as a public identity key, without validating their structure.
    ///
    /// This constructor is intentionally infallible: [`seal`](Self::seal) already validates the
    /// bytes (via `IdentityKey::decode`) before using them and returns [`SealError::Malformed`]
    /// for anything that isn't a well-formed type-tagged Curve25519 point, so there is no need
    /// to duplicate that check here. Prefer constructing via [`IdentityKeyPair::public`] when you
    /// hold the keypair directly; use this only when a key arrives as opaque bytes (e.g. across
    /// an FFI boundary).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }

    /// The serialized public key bytes (1-byte key-type tag + 32-byte point).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Seal `plaintext` so that only the holder of the matching private identity key can recover
    /// it via [`IdentityKeyPair::open_sealed`]. An observer of the sealed bytes (e.g. a relay, or
    /// anyone reading a wire-format frame this blob is embedded in) learns nothing about
    /// `plaintext` — the ephemeral key is fresh per call, so sealing the same plaintext twice
    /// produces unlinkable ciphertexts.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let recipient = IdentityKey::decode(&self.0).map_err(|_| SealError::Malformed)?;

        let mut rng = OsRng.unwrap_err();
        let eph = KeyPair::generate(&mut rng);
        let eph_pub_bytes = eph.public_key.public_key_bytes();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes);

        let shared = eph
            .private_key
            .calculate_agreement(recipient.public_key())
            .map_err(|_| SealError::Malformed)?;

        let mut key = [0u8; KEY_LEN];
        Hkdf::<Sha256>::new(Some(SEAL_HKDF_SALT), &shared)
            .expand(eph_pub_bytes, &mut key)
            .map_err(|_| SealError::DecryptionFailed)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .expect("ChaCha20-Poly1305 accepts any 32-byte key");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: eph_pub_bytes,
                },
            )
            .map_err(|_| SealError::DecryptionFailed)?;

        let mut out = Vec::with_capacity(EPH_PUB_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(eph_pub_bytes);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        key.zeroize();
        let mut shared = shared;
        shared.zeroize();

        Ok(out)
    }
}

/// Errors raised by [`PublicIdentityKey::seal`]/[`IdentityKeyPair::open_sealed`]. All variants
/// fail closed: no plaintext is ever returned on any error path.
#[derive(Debug)]
pub enum SealError {
    /// The sealed blob (or the recipient's own serialized public key) was structurally invalid.
    Malformed,
    /// The AEAD rejected the ciphertext: wrong recipient key or tampered bytes. The two cases are
    /// intentionally indistinguishable (see `sealed_sender.rs`'s failure-model note).
    DecryptionFailed,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "sealed identity blob is structurally malformed"),
            Self::DecryptionFailed => write!(f, "sealed identity blob decryption failed"),
        }
    }
}

impl std::error::Error for SealError {}

#[cfg(test)]
mod tests {
    use super::{IdentityKeyPair, PublicIdentityKey, SealError, MIN_SEALED_LEN};

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

    #[test]
    fn sealed_blob_round_trips_for_the_intended_recipient() {
        let recipient = IdentityKeyPair::generate();
        let sealed = recipient
            .public()
            .seal(b"secret chain key material")
            .unwrap();
        let opened = recipient.open_sealed(&sealed).unwrap();
        assert_eq!(opened, b"secret chain key material");
    }

    #[test]
    fn sealed_blob_does_not_expose_the_plaintext_in_its_bytes() {
        // The whole point of sealing: an observer of the wire bytes must not be able to find the
        // plaintext by inspection, unlike the previous plaintext-chain-key wire format.
        let recipient = IdentityKeyPair::generate();
        let secret = b"super-secret-32-byte-chain-key!";
        let sealed = recipient.public().seal(secret).unwrap();
        assert!(
            !sealed.windows(secret.len()).any(|w| w == &secret[..]),
            "sealed blob must not contain the plaintext as a readable substring"
        );
    }

    #[test]
    fn non_recipient_cannot_open_a_sealed_blob() {
        let recipient = IdentityKeyPair::generate();
        let attacker = IdentityKeyPair::generate();
        let sealed = recipient.public().seal(b"chain key").unwrap();
        assert!(attacker.open_sealed(&sealed).is_err());
    }

    #[test]
    fn truncated_sealed_blob_is_malformed() {
        let recipient = IdentityKeyPair::generate();
        let short = vec![0u8; MIN_SEALED_LEN - 1];
        assert!(matches!(
            recipient.open_sealed(&short),
            Err(SealError::Malformed)
        ));
    }

    #[test]
    fn bit_flipped_sealed_blob_fails_authentication() {
        let recipient = IdentityKeyPair::generate();
        let mut sealed = recipient.public().seal(b"chain key").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(recipient.open_sealed(&sealed).is_err());
    }

    #[test]
    fn sealing_the_same_plaintext_twice_produces_unlinkable_ciphertexts() {
        let recipient = IdentityKeyPair::generate();
        let a = recipient.public().seal(b"chain key").unwrap();
        let b = recipient.public().seal(b"chain key").unwrap();
        assert_ne!(
            a, b,
            "fresh ephemeral key per seal() call must randomize the ciphertext"
        );
    }

    #[test]
    fn from_bytes_round_trips_through_seal_for_a_well_formed_key() {
        let recipient = IdentityKeyPair::generate();
        let key_bytes = recipient.public().to_bytes();

        let reconstructed = PublicIdentityKey::from_bytes(&key_bytes);
        let sealed = reconstructed.seal(b"payload").unwrap();

        assert_eq!(recipient.open_sealed(&sealed).unwrap(), b"payload");
    }

    #[test]
    fn from_bytes_with_garbage_fails_at_seal_not_at_construction() {
        // from_bytes is intentionally infallible; malformed bytes surface as a SealError only
        // once seal() actually tries to decode them.
        let garbage = PublicIdentityKey::from_bytes(&[0xFFu8; 16]);
        assert!(matches!(garbage.seal(b"x"), Err(SealError::Malformed)));
    }

    #[test]
    fn keypair_from_bytes_round_trips_the_public_key() {
        let kp = IdentityKeyPair::generate();
        let serialized = kp.as_libsignal().serialize();
        let restored = IdentityKeyPair::from_bytes(&serialized).unwrap();
        assert_eq!(kp.public().to_bytes(), restored.public().to_bytes());
    }

    #[test]
    fn keypair_from_bytes_rejects_garbage() {
        assert!(IdentityKeyPair::from_bytes(&[0u8; 10]).is_err());
    }
}
