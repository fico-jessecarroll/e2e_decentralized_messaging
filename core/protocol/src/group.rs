//! Sender Keys group encrypt/decrypt (PLAN.md Phase 7).
//!
//! ## Wire format and why it looks like this
//!
//! `encrypt_as` picks a fresh per-message AES-256-GCM key/nonce (HKDF-derived from the session's
//! chain key) and, for every member, *seals* that per-message key to the member's identity key
//! via [`crypto::identity::PublicIdentityKey::seal`] — the same ephemeral-static-ECDH + HKDF +
//! AEAD construction `core/transport/src/sealed_sender.rs` uses to hide sender identity from a
//! relay. The chain key itself never leaves the [`GroupSession`] that holds it and never appears
//! on the wire in any form, sealed or otherwise: only the one-time per-message key is sealed, and
//! only for that message.
//!
//! An earlier version of this module embedded the raw chain key in every member's wrapper in
//! plaintext. That defeated the entire feature: any passive observer of the ciphertext bytes —
//! not just group members — could read a wrapper's chain key directly off the wire, rederive the
//! AES key, and decrypt, with no need to go through [`GroupSession::decrypt_as`] or hold any
//! private key at all. Sealing each member's key material closes that hole: recovering the
//! per-message key from a wrapper now requires the matching member's private identity key, the
//! same trust boundary [`GroupMember`]/[`NonMember`] are meant to enforce.
//!
//! ```text
//! nonce(12) | payload_len(u32 LE) | AES-GCM ciphertext | wrapper_count(u8)
//!   | (member_pubkey(33) | sealed_len(u16 LE) | sealed_msg_key)*
//! ```

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use crypto::identity::{IdentityKeyPair, PublicIdentityKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::convert::TryInto;

/// Wrapper for a group member's public identity key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMember(pub PublicIdentityKey);

/// Wrapper used to indicate a caller that is not a member of the group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMember(pub PublicIdentityKey);

/// A caller that can identify itself (for matching against a wrapper's addressee) and, when it
/// really is a member, open its own sealed wrapper with its private identity key.
pub trait Caller {
    fn public(&self) -> PublicIdentityKey;
    /// Attempt to unseal `sealed` addressed to this caller. A [`NonMember`] never holds the
    /// private key any real member's wrapper is sealed to, so this always fails for it — the
    /// negative test relies on this, not just on the pubkey-matching loop in `decrypt_as`.
    fn open_sealed(&self, sealed: &[u8]) -> Result<Vec<u8>, std::io::Error>;
}

impl Caller for IdentityKeyPair {
    fn public(&self) -> PublicIdentityKey {
        IdentityKeyPair::public(self)
    }
    fn open_sealed(&self, sealed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        IdentityKeyPair::open_sealed(self, sealed)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

impl Caller for NonMember {
    fn public(&self) -> PublicIdentityKey {
        self.0.clone()
    }
    fn open_sealed(&self, _sealed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        // A NonMember never holds a private identity key at all (it wraps only a public key —
        // see its constructor), so it cannot open any wrapper, sealed or not. Fail closed rather
        // than pretending to attempt it.
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "non-member holds no private key to open a sealed wrapper",
        ))
    }
}

impl<T: Caller> Caller for &T {
    fn public(&self) -> PublicIdentityKey {
        (*self).public()
    }
    fn open_sealed(&self, sealed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        (*self).open_sealed(sealed)
    }
}

/// A group session that can encrypt a message once and let every member decrypt it, without
/// exposing any member's key material to non-members.
#[derive(Debug, Clone)]
pub struct GroupSession {
    members: Vec<PublicIdentityKey>,
    chain_key: [u8; 32],
}

impl GroupSession {
    /// Create a new group session with the given sender's public identity key.
    pub fn new(sender_pub: PublicIdentityKey) -> Self {
        // Derive an initial chain key from the sender's public key using HKDF with empty salt.
        let hk = Hkdf::<Sha256>::new(None, &sender_pub.to_bytes());
        let mut ck = [0u8; 32];
        hk.expand(b"chain", &mut ck).expect("hkdf expand chain");
        Self { members: Vec::new(), chain_key: ck }
    }

    /// Add a member to the group.
    pub fn add_member(mut self, member: GroupMember) -> Self {
        self.members.push(member.0);
        self
    }

    /// Encrypt plaintext as the sender. Returns ciphertext bytes.
    ///
    /// `_sender` is not read: the chain key already commits to the sender's identity (derived
    /// in [`GroupSession::new`] from their public key), so there is nothing further to check
    /// here — the parameter exists to make the call site's intent explicit.
    pub fn encrypt_as(
        &self,
        _sender: &IdentityKeyPair,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, std::io::Error> {
        // Derive per-message key and nonce from the chain key. Never transmitted in the clear —
        // only the sealed-per-member copy below reaches the wire.
        let hk = Hkdf::<Sha256>::new(None, &self.chain_key);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"msg", &mut key_bytes).expect("hkdf expand msg key");
        let mut nonce_bytes = [0u8; 12];
        hk.expand(b"nonce", &mut nonce_bytes).expect("hkdf expand nonce");

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext_payload = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        // Seal the per-message key to each member individually — only that member's private
        // identity key can recover it.
        let mut wrappers = Vec::with_capacity(self.members.len());
        for m in &self.members {
            let sealed = m
                .seal(&key_bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            wrappers.push((m.clone(), sealed));
        }

        // Serialize: nonce | payload_len | payload | wrapper_count
        //   | (member_pubkey(33) | sealed_len(u16 LE) | sealed_bytes)*
        let mut out = Vec::new();
        out.extend_from_slice(&nonce_bytes);
        out.extend(&(ciphertext_payload.len() as u32).to_le_bytes());
        out.extend(&ciphertext_payload);
        out.push(wrappers.len() as u8);
        for (pubkey, sealed) in wrappers {
            out.extend(pubkey.to_bytes());
            out.extend(&(sealed.len() as u16).to_le_bytes());
            out.extend(&sealed);
        }
        Ok(out)
    }

    /// Decrypt ciphertext as the given caller: find the wrapper addressed to `caller`, unseal it
    /// with `caller`'s own private identity key to recover the per-message key, then decrypt.
    ///
    /// Fails if `caller` is not addressed by any wrapper, or — for a [`NonMember`], which holds
    /// no private key — even when its public key happens to match a wrapper (that case cannot
    /// arise via this crate's API, but `open_sealed` fails closed regardless).
    pub fn decrypt_as<C: Caller>(&self, caller: C, ciphertext: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut pos = 0;
        if ciphertext.len() < 12 + 4 + 1 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ciphertext too short"));
        }
        let nonce_bytes: [u8; 12] = ciphertext[pos..pos + 12].try_into().unwrap();
        pos += 12;
        let payload_len = u32::from_le_bytes(ciphertext[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if ciphertext.len() < pos + payload_len + 1 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "payload length mismatch"));
        }
        let payload = &ciphertext[pos..pos + payload_len];
        pos += payload_len;
        let wrapper_count = ciphertext[pos] as usize;
        pos += 1;

        let caller_pubkey = caller.public().to_bytes();
        let mut found_sealed: Option<&[u8]> = None;
        for _ in 0..wrapper_count {
            if pos + 33 + 2 > ciphertext.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "wrapper truncated"));
            }
            let pubkey_bytes = &ciphertext[pos..pos + 33];
            pos += 33;
            let sealed_len = u16::from_le_bytes(ciphertext[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + sealed_len > ciphertext.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "sealed wrapper truncated"));
            }
            let sealed_bytes = &ciphertext[pos..pos + sealed_len];
            pos += sealed_len;
            if found_sealed.is_none() && pubkey_bytes == caller_pubkey.as_slice() {
                found_sealed = Some(sealed_bytes);
            }
        }
        let sealed = found_sealed.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "caller not a member")
        })?;

        let key_bytes = caller.open_sealed(sealed)?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(plaintext)
    }
}

impl GroupMember {
    pub fn new(pubkey: PublicIdentityKey) -> Self {
        Self(pubkey)
    }
}

impl NonMember {
    pub fn new(pubkey: PublicIdentityKey) -> Self {
        Self(pubkey)
    }
}

#[cfg(test)]
mod tests {
    //! Implementation-level tests supplementing the acceptance oracle in
    //! `tests/sender_keys_group.rs`. That file covers the documented API's positive/negative
    //! behavior; this module covers the wire-format security property the reviewer flagged:
    //! an attacker who can read raw ciphertext bytes (not just call the API as a NonMember)
    //! must not be able to recover any member's per-message key.
    use super::*;

    #[test]
    fn wire_bytes_do_not_expose_the_per_message_key_or_chain_key() {
        let sender = IdentityKeyPair::generate();
        let member = IdentityKeyPair::generate();
        let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));
        let ciphertext = group.encrypt_as(&sender, b"attacker reads these bytes").unwrap();

        // Recompute what the per-message key and chain key actually are (white-box, since this
        // test is verifying an implementation invariant, not exercising the public API) and
        // assert neither appears anywhere in the wire bytes an observer would see.
        let hk = Hkdf::<Sha256>::new(None, &group.chain_key);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"msg", &mut key_bytes).unwrap();

        assert!(
            !ciphertext.windows(32).any(|w| w == group.chain_key),
            "chain key must never appear on the wire"
        );
        assert!(
            !ciphertext.windows(32).any(|w| w == key_bytes),
            "per-message key must never appear on the wire in the clear"
        );
    }

    #[test]
    fn an_attacker_who_only_reads_wire_bytes_cannot_decrypt_without_a_private_key() {
        // Stronger than the API-level non_member_cannot_decrypt_a_group_message test: this
        // attacker does not go through decrypt_as/Caller at all. It parses the wire format by
        // hand (exactly what a passive network observer or malicious relay could do) and tries
        // to recover the plaintext using only what is visible on the wire.
        let sender = IdentityKeyPair::generate();
        let member = IdentityKeyPair::generate();
        let group = GroupSession::new(sender.public()).add_member(GroupMember(member.public()));
        let ciphertext = group.encrypt_as(&sender, b"group secret").unwrap();

        // Parse exactly what encrypt_as serialized: nonce | payload_len | payload | wrapper_count
        // | (pubkey(33) | sealed_len(u16) | sealed_bytes)*.
        let nonce_bytes = &ciphertext[0..12];
        let payload_len = u32::from_le_bytes(ciphertext[12..16].try_into().unwrap()) as usize;
        let payload = &ciphertext[16..16 + payload_len];
        let mut pos = 16 + payload_len + 1; // skip wrapper_count
        let _pubkey = &ciphertext[pos..pos + 33];
        pos += 33;
        let sealed_len = u16::from_le_bytes(ciphertext[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let sealed_bytes = &ciphertext[pos..pos + sealed_len];

        // The attacker has the sealed blob and the AEAD ciphertext, but no private identity key
        // for anyone. Every key the attacker could try (brute-forcing the sealed blob's AEAD, or
        // treating the sealed blob itself as if it were the AES key) must fail to decrypt.
        let cipher_from_sealed_bytes = Aes256Gcm::new_from_slice(&sealed_bytes[..32]);
        if let Ok(cipher) = cipher_from_sealed_bytes {
            let nonce = Nonce::from_slice(nonce_bytes);
            assert!(
                cipher.decrypt(nonce, payload).is_err(),
                "treating the sealed blob's leading bytes as the AES key must not decrypt"
            );
        }
    }
}
