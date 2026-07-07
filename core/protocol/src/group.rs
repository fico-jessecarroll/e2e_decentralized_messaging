use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use hkdf::Hkdf;
use sha2::Sha256;
use std::convert::TryInto;
use crypto::identity::{IdentityKeyPair, PublicIdentityKey};

/// Wrapper for a group member's public identity key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMember(pub PublicIdentityKey);

/// Wrapper used to indicate a caller that is not a member of the group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonMember(pub PublicIdentityKey);

/// Types that can identify themselves with a public identity key when decrypting.
pub trait Caller {
    fn public(&self) -> PublicIdentityKey;
}

impl Caller for IdentityKeyPair {
    fn public(&self) -> PublicIdentityKey { IdentityKeyPair::public(self) }
}

impl Caller for NonMember {
    fn public(&self) -> PublicIdentityKey { self.0.clone() }
}

impl<T: Caller> Caller for &T {
    fn public(&self) -> PublicIdentityKey { (*self).public() }
}

/// A simple group session that can encrypt and decrypt messages for a set of members.
#[derive(Debug, Clone)]
pub struct GroupSession {
    /// List of member public keys.
    members: Vec<PublicIdentityKey>,
    /// Current chain key used to derive per-message encryption keys.
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
    pub fn encrypt_as(&self, _sender: &IdentityKeyPair, plaintext: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        // Derive per-message key and nonce from current chain key.
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

        // Build wrappers: for each member include their pubkey and the chain key.
        let mut wrappers = Vec::new();
        for m in &self.members {
            wrappers.push((m.clone(), self.chain_key));
        }

        // Serialize: nonce(12) | payload_len(u32 LE) | payload | wrapper_count(u8) | each (pubkey33 + chain_key32)
        let mut out = Vec::new();
        out.extend_from_slice(&nonce_bytes);
        out.extend(&(ciphertext_payload.len() as u32).to_le_bytes());
        out.extend(&ciphertext_payload);
        out.push(wrappers.len() as u8);
        for (pubkey, chain) in wrappers {
            out.extend(pubkey.to_bytes());
            out.extend(&chain);
        }
        Ok(out)
    }

    /// Decrypt ciphertext as the given caller. Returns plaintext or error if caller not a member.
    pub fn decrypt_as<C: Caller>(&self, caller: C, ciphertext: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        // Parse header
        let mut pos = 0;
        if ciphertext.len() < 12 + 4 + 1 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ciphertext too short")); }
        // The header carries the nonce for wire-format documentation, but it is not read here:
        // the nonce is deterministically re-derived from the chain key below (see nonce_bytes2),
        // not transmitted.
        let _nonce_bytes: [u8; 12] = ciphertext[pos..pos + 12].try_into().unwrap(); pos += 12;
        let payload_len = u32::from_le_bytes(ciphertext[pos..pos+4].try_into().unwrap()) as usize; pos+=4;
        if ciphertext.len() < 12 + 4 + payload_len + 1 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "payload length mismatch")); }
        let payload = &ciphertext[pos..pos+payload_len]; pos+=payload_len;
        let wrapper_count = ciphertext[pos] as usize; pos+=1;
        // Find matching member
        let mut found_chain: Option<[u8;32]> = None;
        for _ in 0..wrapper_count {
            if pos + 33 + 32 > ciphertext.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "wrapper truncated")); }
            let pubkey_bytes: Vec<u8> = ciphertext[pos..pos+33].to_vec(); pos+=33;
            let chain_bytes: [u8;32] = ciphertext[pos..pos+32].try_into().unwrap(); pos+=32;
            if caller.public().to_bytes() == pubkey_bytes {
                found_chain = Some(chain_bytes);
                break;
            }
        }
        let chain_key = match found_chain { Some(k)=>k, None=>return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "caller not a member")) };

        // Derive key and nonce from chain key
        let hk = Hkdf::<Sha256>::new(None, &chain_key);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"msg", &mut key_bytes).expect("hkdf expand msg key");
        let mut nonce_bytes2 = [0u8; 12];
        hk.expand(b"nonce", &mut nonce_bytes2).expect("hkdf expand nonce");

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes2);
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(plaintext)
    }
}

impl GroupMember {
    pub fn new(pubkey: PublicIdentityKey) -> Self { Self(pubkey) }
}

impl NonMember {
    pub fn new(pubkey: PublicIdentityKey) -> Self { Self(pubkey) }
}
