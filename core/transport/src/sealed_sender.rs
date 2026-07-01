//! Sealed Sender envelope encryption — a relay carrying the envelope cannot determine the
//! sender's identity (PLAN.md Phase 4 "Sealed Sender envelope encryption").
//!
//! ## Design
//!
//! This is Signal's *Sealed Sender* idea at the envelope layer: the sender encrypts a payload to
//! the recipient's static identity key using a freshly generated ephemeral X25519 keypair
//! (ephemeral-static ECDH), so that only the holder of the recipient's private identity key can
//! recover the plaintext. The sender's identity travels *inside* the encrypted envelope, not on
//! the outside — a relay observing the envelope bytes sees only the ephemeral public key, a
//! nonce, and ciphertext, none of which reveal the sender.
//!
//! No cryptography is invented here. Every primitive is the audited one the rest of the core
//! already uses:
//! - **ECDH**: `libsignal_protocol`'s `PrivateKey::calculate_agreement` (Curve25519/X25519).
//! - **KDF**: HKDF-SHA256 (the `hkdf` + `sha2` crates — the same construction libsignal's own
//!   `sealed_sender` module uses internally).
//! - **AEAD**: ChaCha20-Poly1305 (12-byte nonce, 16-byte tag) via the `chacha20poly1305` crate.
//!
//! ## Wire format
//!
//! ```text
//! ┌──────────────────┬─────────────┬──────────────────────────────┐
//! │ eph_pub (32 B)   │ nonce (12 B)│ AEAD ciphertext + tag        │
//! │ ephemeral X25519 │ ChaCha20    │ (inner_plaintext ‖ 16-B tag) │
//! └──────────────────┴─────────────┴──────────────────────────────┘
//! ```
//!
//! The AEAD associated data is `eph_pub`, so the ephemeral key is bound into the authentication
//! tag and cannot be swapped. The inner plaintext is:
//!
//! ```text
//! ┌──────────────────────────────┬──────────────────┐
//! │ sender identity key (33 B)   │ payload (n B)    │
//! │ libsignal IdentityKey::serial│ the message body │
//! └──────────────────────────────┴──────────────────┘
//! ```
//!
//! The sender identity key is the libsignal 33-byte serialization (1-byte type tag + 32-byte
//! Curve25519 point). It is encrypted, so its raw bytes never appear in the envelope — that is
//! exactly what the relay-hiding acceptance test asserts. `open` strips the 33-byte sender prefix
//! and returns only the payload.
//!
//! ## Failure model (fail closed)
//!
//! Every failure returns a `SealedSenderError` and reveals **no plaintext**: a malformed envelope
//! is rejected before any decryption is attempted (`Malformed`); a ciphertext that fails AEAD
//! authentication — whether because the recipient holds the wrong identity key or because the
//! bytes were tampered with — returns `DecryptionFailed`/`NotForRecipient`. AES/ChaCha AEADs
//! cannot tell "wrong key" from "tampered ciphertext" apart, and that indistinguishability is a
//! feature (a distinguisher would be a decryption oracle); we therefore do not attempt to.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair, PrivateKey, PublicKey};
use rand::rngs::OsRng;
use rand::{Rng, TryRngCore};
use sha2::Sha256;
use zeroize::Zeroize;

/// Errors raised by [`seal`]/[`open`]. All variants fail closed: no plaintext is ever returned on
/// any error path.
#[derive(Debug)]
pub enum SealedSenderError {
    /// The envelope was structurally invalid — too short to carry the fixed header + a sender
    /// identity, or the ephemeral public key bytes did not deserialize as a Curve25519 point.
    Malformed,
    /// The AEAD authenticated the envelope but the inner plaintext was too short to contain the
    /// 33-byte sender identity prefix. Indicates a truncated or tampered inner frame.
    NotForRecipient,
    /// The AEAD rejected the ciphertext. For a well-formed envelope this means the opener does not
    /// hold the recipient identity key the envelope was sealed to; for a corrupt envelope it means
    /// a byte was flipped. The two cases are intentionally indistinguishable.
    DecryptionFailed,
}

/// HKDF salt — a fixed domain-separation string so Sealed Sender keys can never be confused with
/// keys derived for any other purpose from the same ECDH shared secret.
const HKDF_SALT: &[u8] = b"SealedSender-v1";
/// The AEAD key length (ChaCha20-Poly1305 takes a 32-byte key).
const KEY_LEN: usize = 32;
/// Fixed offsets in the envelope.
const EPH_PUB_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// The sender identity key prefix carried inside the encrypted plaintext (libsignal's 33-byte
/// `IdentityKey` serialization: 1-byte type tag + 32-byte Curve25519 point).
const SENDER_ID_LEN: usize = 33;
/// Minimum envelope size: ephemeral pub + nonce + tag + the sender-identity prefix that must be
/// inside every valid envelope's plaintext. Anything shorter is structurally malformed.
const MIN_ENVELOPE_LEN: usize = EPH_PUB_LEN + NONCE_LEN + TAG_LEN + SENDER_ID_LEN;

/// Seal `payload` from `sender` to `recipient_pub` (the recipient's public identity key).
///
/// Returns a self-contained envelope the recipient can open with [`open`] given its private
/// identity key. The envelope reveals no sender-identity bytes to an observer.
pub fn seal(
    sender: &IdentityKeyPair,
    recipient_pub: &IdentityKey,
    payload: &[u8],
) -> Result<Vec<u8>, SealedSenderError> {
    // 1. Fresh ephemeral X25519 keypair + AEAD nonce from the OS CSPRNG.
    let mut rng = OsRng.unwrap_err();
    let eph = KeyPair::generate(&mut rng);
    let eph_pub = &eph.public_key;
    let eph_pub_bytes = eph_pub.public_key_bytes();
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);

    // 2. Ephemeral-static ECDH: eph_priv × recipient_static_pub → shared secret.
    let recipient_static_pub = recipient_pub.public_key();
    let shared = eph
        .private_key
        .calculate_agreement(recipient_static_pub)
        .map_err(|_| SealedSenderError::DecryptionFailed)?;

    // 3. HKDF-SHA256(shared, salt=SealedSender-v1, info=eph_pub) → 32-byte AEAD key. Binding
    //    eph_pub into the info means the key is specific to this ephemeral key, so reusing the
    //    same shared secret under a different ephemeral key is cryptographically impossible.
    let mut key = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared)
        .expand(eph_pub_bytes, &mut key)
        .map_err(|_| SealedSenderError::DecryptionFailed)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).expect("ChaCha20-Poly1305 accepts any 32-byte key");

    // 4. Inner plaintext = sender identity (33 B) ‖ payload. The sender identity is encrypted,
    //    so its raw bytes never appear in the envelope.
    let sender_id = sender.identity_key().serialize();
    debug_assert_eq!(
        sender_id.len(),
        SENDER_ID_LEN,
        "libsignal IdentityKey serialization is always 33 bytes"
    );
    let mut plaintext = Vec::with_capacity(SENDER_ID_LEN + payload.len());
    plaintext.extend_from_slice(&sender_id);
    plaintext.extend_from_slice(payload);

    // 5. AEAD encrypt with eph_pub as associated data (binds the ephemeral key into the tag).
    let nonce = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: eph_pub_bytes,
            },
        )
        .map_err(|_| SealedSenderError::DecryptionFailed)?;

    // 6. Assemble the envelope and zeroize sensitive intermediate material.
    let mut envelope = Vec::with_capacity(EPH_PUB_LEN + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(eph_pub_bytes);
    envelope.extend_from_slice(nonce);
    envelope.extend_from_slice(&ciphertext);

    plaintext.zeroize();
    key.zeroize();
    // `shared` is a Box<[u8]>; zeroize its buffer in place before drop.
    let mut shared = shared;
    shared.zeroize();
    Ok(envelope)
}

/// Open a Sealed Sender `envelope` addressed to `recipient` (the holder of the private identity
/// key). Returns the original payload on success.
///
/// Fails closed on every error path — see [`SealedSenderError`] for the failure model.
pub fn open(recipient: &IdentityKeyPair, envelope: &[u8]) -> Result<Vec<u8>, SealedSenderError> {
    // Structural check first: anything too short to hold the header + sender identity is malformed
    // before we touch any crypto. This also makes the 64-byte-garbage negative test return
    // `Malformed` rather than falling through to an AEAD failure.
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(SealedSenderError::Malformed);
    }

    let eph_pub_bytes = &envelope[..EPH_PUB_LEN];
    let nonce_bytes = &envelope[EPH_PUB_LEN..EPH_PUB_LEN + NONCE_LEN];
    let ciphertext = &envelope[EPH_PUB_LEN + NONCE_LEN..];

    // Parse the ephemeral public key from its 32-byte DJB (raw Curve25519 point) form — the same
    // form `seal` wrote and that Signal's own Sealed Sender uses on the wire. Invalid bytes →
    // malformed envelope.
    let eph_pub = PublicKey::from_djb_public_key_bytes(eph_pub_bytes)
        .map_err(|_| SealedSenderError::Malformed)?;

    // ECDH: recipient_priv × eph_pub → shared secret. A wrong recipient derives a different shared
    // secret, which the AEAD step below will reject.
    let recipient_priv: &PrivateKey = recipient.private_key();
    let shared = recipient_priv
        .calculate_agreement(&eph_pub)
        .map_err(|_| SealedSenderError::Malformed)?;

    let mut key = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared)
        .expand(eph_pub_bytes, &mut key)
        .map_err(|_| SealedSenderError::DecryptionFailed)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).expect("ChaCha20-Poly1305 accepts any 32-byte key");

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: eph_pub_bytes,
            },
        )
        .map_err(|_| SealedSenderError::DecryptionFailed);

    key.zeroize();
    let mut shared = shared;
    shared.zeroize();

    let plaintext = plaintext?;

    // Strip the 33-byte sender-identity prefix; the remainder is the payload.
    if plaintext.len() < SENDER_ID_LEN {
        // Authenticated but truncated inner frame — the envelope was tampered after a valid seal,
        // which is impossible without the key, so treat it as not-for-recipient / tampered.
        return Err(SealedSenderError::NotForRecipient);
    }
    let payload = plaintext[SENDER_ID_LEN..].to_vec();
    Ok(payload)
}

#[cfg(test)]
mod tests {
    //! Implementation smoke tests. The acceptance tests that gate the Phase 4 story (relay cannot
    //! recover sender identity, malformed rejected, wrong recipient rejected) live in the
    //! read-only `core/transport/tests/sealed_sender.rs` and are the source of truth.

    use super::*;
    use crypto::{generate_identity_key_pair, IdentityKeyPairExt};

    #[test]
    fn round_trip_recovers_payload() {
        let sender = generate_identity_key_pair();
        let recipient = generate_identity_key_pair();
        let envelope = seal(&sender, &recipient.public_identity(), b"payload body").unwrap();
        let opened = open(&recipient, &envelope).unwrap();
        assert_eq!(opened, b"payload body");
    }

    #[test]
    fn envelope_is_at_least_the_minimum_size() {
        let sender = generate_identity_key_pair();
        let recipient = generate_identity_key_pair();
        let envelope = seal(&sender, &recipient.public_identity(), b"x").unwrap();
        // eph_pub(32) + nonce(12) + tag(16) + sender_id(33) + 1 payload byte = 94.
        assert!(envelope.len() > MIN_ENVELOPE_LEN);
    }

    #[test]
    fn truncated_envelope_is_malformed() {
        let recipient = generate_identity_key_pair();
        let short = vec![0u8; MIN_ENVELOPE_LEN - 1];
        assert!(matches!(
            open(&recipient, &short),
            Err(SealedSenderError::Malformed)
        ));
    }

    #[test]
    fn empty_payload_still_round_trips() {
        let sender = generate_identity_key_pair();
        let recipient = generate_identity_key_pair();
        let envelope = seal(&sender, &recipient.public_identity(), b"").unwrap();
        let opened = open(&recipient, &envelope).unwrap();
        assert!(opened.is_empty());
    }
}
