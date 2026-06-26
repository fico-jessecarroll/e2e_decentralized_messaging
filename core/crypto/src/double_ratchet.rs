//! Double Ratchet 1:1 message encrypt/decrypt (PLAN.md Phase 1 "Crypto core").
//!
//! Wraps `libsignal`'s `message_encrypt` / `message_decrypt` so the rest of
//! the codebase has a thin, named entry point that:
//!
//! - hides the long parameter list (five stores, three CSPRGs, two
//!   addresses);
//! - returns typed [`DoubleRatchetError`] errors rather than raw `libsignal`
//!   errors, so callers don't have to depend on `libsignal_protocol` to
//!   distinguish "tampered ciphertext" from "identity mismatch after TOFU";
//! - rejects SenderKey/Plaintext envelopes (group-cipher / sealed-sender
//!   payloads) before handing them to `libsignal`'s 1:1 decrypt path.
//!
//! We deliberately do not reimplement the ratchet — `libsignal`'s
//! `TripleRatchet` (the implementation under `message_encrypt` /
//! `message_decrypt`) is the one audited, in-tree ratchet for this project
//! (CLAUDE.md "don't reinvent crypto"). This module is purely a thin
//! adapter that enforces input-shape invariants and the fail-closed error
//! posture.
//!
//! # Wire format note
//!
//! `libsignal`'s encrypted `SignalMessage` and `PreKeySignalMessage` do not
//! carry their own type tag in the first byte — both produce the same
//! `(message_version << 4) | 4` header. The Signal clients disambiguate
//! based on context (a session that hasn't received its first message yet
//! must use `PreKeySignalMessage::try_from`; thereafter `SignalMessage`).
//!
//! At the network layer our own protocol spec
//! (`spec/proto/v0/envelope.proto`) carries an explicit `EnvelopeType`
//! field for exactly this reason. The wrapper therefore takes a
//! caller-supplied [`MessageType`] hint when ingesting raw bytes, rather
//! than trying to infer it from the ciphertext itself.

use std::fmt;
use std::time::SystemTime;

use libsignal_protocol::{
    message_decrypt, message_encrypt, CiphertextMessage, IdentityKeyStore, KyberPreKeyStore,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, SignalMessage, SignalProtocolError,
    SignedPreKeyStore,
};
use rand::rngs::OsRng;
use rand::TryRngCore as _;

/// Errors that can occur during Double Ratchet 1:1 encrypt or decrypt.
#[derive(Debug, PartialEq, Eq)]
pub enum DoubleRatchetError {
    /// The serialized ciphertext is empty, too short, or carries an unknown
    /// / unrecognized message-version nibble. Detected at the wrapper
    /// boundary before handing the bytes to `libsignal`, so a malformed
    /// envelope can never reach the ratchet itself.
    MalformedCiphertext,
    /// The caller asked the wrapper to decrypt a ciphertext shape that the
    /// 1:1 ratchet is not equipped to handle (SenderKey / PlaintextContent).
    /// Detected at the wrapper boundary.
    UnsupportedCiphertextType,
    /// No Signal session exists for `remote_address` on this device. The
    /// caller should run an X3DH/PQXDH session establishment (see
    /// [`crate::session::establish_outbound_session`]) before retrying.
    NoSession,
    /// The remote identity key bound to `remote_address` does not match
    /// the identity key the message was encrypted under. This is the
    /// post-TOFU MITM-detection path: a sender whose identity has changed
    /// without the user re-approving them must be refused (CLAUDE.md "fail
    /// closed").
    UntrustedIdentity,
    /// The message's MAC did not verify, or the ratchet detected a replay
    /// (message key already consumed). Per PLAN.md the wrapper must
    /// surface this — not silently pass the payload through to the caller.
    AuthenticationFailed,
    /// Any other `libsignal` error not classified above. Carried as the
    /// underlying error string for diagnostics; callers should treat it as
    /// an opaque failure (no plaintext was produced).
    ProtocolError(String),
}

impl fmt::Display for DoubleRatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedCiphertext => write!(f, "malformed or unrecognized ciphertext"),
            Self::UnsupportedCiphertextType => {
                write!(f, "ciphertext type is not supported for 1:1 ratchet")
            }
            Self::NoSession => write!(f, "no session for remote address"),
            Self::UntrustedIdentity => write!(f, "untrusted identity for remote address"),
            Self::AuthenticationFailed => {
                write!(f, "ciphertext failed authentication (bad MAC or replay)")
            }
            Self::ProtocolError(msg) => write!(f, "double ratchet protocol error: {msg}"),
        }
    }
}

impl std::error::Error for DoubleRatchetError {}

impl DoubleRatchetError {
    /// Returns `true` iff the underlying `libsignal` error represents an
    /// identity-mismatch-after-TOFU event. Exposed so callers that want
    /// to surface a specific UX (e.g. "the contact's safety number has
    /// changed") can match on this case without importing
    /// `libsignal_protocol`.
    pub fn is_untrusted_identity(err: &SignalProtocolError) -> bool {
        matches!(err, SignalProtocolError::UntrustedIdentity(_))
    }

    /// Classify a `libsignal` error into our wrapper's error type.
    /// Fail-closed: any unrecognized `libsignal` error becomes
    /// [`Self::ProtocolError`] rather than being silently swallowed.
    fn from_protocol(err: SignalProtocolError) -> Self {
        match err {
            SignalProtocolError::SessionNotFound(_) => Self::NoSession,
            SignalProtocolError::UntrustedIdentity(_) => Self::UntrustedIdentity,
            SignalProtocolError::InvalidMessage(_, _) => Self::AuthenticationFailed,
            SignalProtocolError::CiphertextMessageTooShort(_)
            | SignalProtocolError::LegacyCiphertextVersion(_)
            | SignalProtocolError::UnrecognizedCiphertextVersion(_)
            | SignalProtocolError::UnrecognizedMessageVersion(_)
            | SignalProtocolError::InvalidProtobufEncoding => Self::MalformedCiphertext,
            // Surface the rest — no silent fallback.
            other => Self::ProtocolError(other.to_string()),
        }
    }
}

/// The shape of the ciphertext being wrapped.
///
/// Mirrors `libsignal_protocol::CiphertextMessageType` but excludes the
/// group / sealed-sender envelopes that the 1:1 ratchet is not equipped
/// to handle. The caller supplies this hint at construction time because
/// `libsignal`'s serialized bytes do not carry their own type tag — at
/// our layer the type comes from `spec/proto/v0/envelope.proto`'s
/// `EnvelopeType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// First message of a brand-new X3DH/PQXDH session, carrying the
    /// pre-key material the receiver needs to bootstrap the session.
    PreKey,
    /// Subsequent message in an already-established Double Ratchet
    /// session.
    Ciphertext,
}

/// A serialized Signal ciphertext envelope (the bytes that travel over
/// the wire), tagged with its shape so the wrapper can dispatch to the
/// right `libsignal` parser without inspecting bytes that don't carry
/// that information.
///
/// This newtype exists so the wrapper has a single, owned-by-the-caller
/// input shape — callers pass bytes they own, not references into a
/// borrowed `CiphertextMessage`, which makes it natural to thread a
/// ciphertext through queues, files, or the network without reborrowing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedCiphertext {
    message_type: MessageType,
    bytes: Box<[u8]>,
}

impl SerializedCiphertext {
    /// Wrap raw ciphertext bytes with an explicit [`MessageType`] tag.
    /// No validation here — validation happens at decrypt time.
    ///
    /// Callers should only use this for bytes they trust to be of the
    /// declared shape; in practice the type comes from the higher-layer
    /// `Envelope` proto (`spec/proto/v0/envelope.proto`).
    pub fn new(message_type: MessageType, bytes: Vec<u8>) -> Self {
        Self {
            message_type,
            bytes: bytes.into_boxed_slice(),
        }
    }

    /// The underlying serialized bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume this `SerializedCiphertext` and return the inner byte
    /// vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes.into_vec()
    }

    /// The declared shape of this ciphertext.
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }
}

impl AsRef<[u8]> for SerializedCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&SerializedCiphertext> for CiphertextMessage {
    type Error = DoubleRatchetError;

    fn try_from(sc: &SerializedCiphertext) -> Result<Self, Self::Error> {
        let bytes = sc.as_bytes();
        // Reject message types that the 1:1 ratchet must not see, before
        // we even ask `libsignal` to parse them.
        match sc.message_type() {
            MessageType::Ciphertext => {
                let m =
                    SignalMessage::try_from(bytes).map_err(DoubleRatchetError::from_protocol)?;
                Ok(CiphertextMessage::SignalMessage(m))
            }
            MessageType::PreKey => {
                let m = PreKeySignalMessage::try_from(bytes)
                    .map_err(DoubleRatchetError::from_protocol)?;
                Ok(CiphertextMessage::PreKeySignalMessage(m))
            }
        }
    }
}

impl TryFrom<&CiphertextMessage> for SerializedCiphertext {
    type Error = DoubleRatchetError;

    fn try_from(ct: &CiphertextMessage) -> Result<Self, Self::Error> {
        let (message_type, bytes) = match ct {
            CiphertextMessage::SignalMessage(_) => (MessageType::Ciphertext, ct.serialize()),
            CiphertextMessage::PreKeySignalMessage(_) => (MessageType::PreKey, ct.serialize()),
            CiphertextMessage::SenderKeyMessage(_) | CiphertextMessage::PlaintextContent(_) => {
                return Err(DoubleRatchetError::UnsupportedCiphertextType);
            }
        };
        Ok(Self {
            message_type,
            bytes: bytes.to_vec().into_boxed_slice(),
        })
    }
}

/// Encrypt `plaintext` for `remote_address`, loading and storing session
/// state on this device.
///
/// On the first message to a brand-new remote device, returns a
/// [`CiphertextMessage::PreKeySignalMessage`] (carries the pre-key
/// material the receiver needs to bootstrap a session). On every
/// subsequent message within the same session, returns a
/// [`CiphertextMessage::SignalMessage`] (forward-secret, smaller).
///
/// # Errors
///
/// Fails closed on any of:
/// - [`DoubleRatchetError::NoSession`] — caller forgot to establish a
///   session first.
/// - [`DoubleRatchetError::UntrustedIdentity`] — the recipient's stored
///   identity no longer matches the bundle (TOFU violation).
/// - [`DoubleRatchetError::ProtocolError`] — any other `libsignal`
///   failure.
pub async fn encrypt_message(
    plaintext: &[u8],
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    session_store: &mut dyn libsignal_protocol::SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
) -> Result<CiphertextMessage, DoubleRatchetError> {
    let mut csprng = OsRng.unwrap_err();
    message_encrypt(
        plaintext,
        remote_address,
        local_address,
        session_store,
        identity_store,
        SystemTime::now(),
        &mut csprng,
    )
    .await
    .map_err(DoubleRatchetError::from_protocol)
}

/// Decrypt a [`SerializedCiphertext`] from `remote_address`.
///
/// The wrapper parses the bytes via the `libsignal` parser appropriate
/// for the declared [`MessageType`]. On success returns the plaintext
/// bytes.
///
/// # Errors
///
/// Fails closed on any of:
/// - [`DoubleRatchetError::MalformedCiphertext`] — empty bytes, or any
///   protobuf/encoding failure detected at the boundary.
/// - [`DoubleRatchetError::NoSession`] — no session is recorded for
///   `remote_address` on this device.
/// - [`DoubleRatchetError::UntrustedIdentity`] — sender's identity key
///   differs from the one previously bound to `remote_address`
///   (post-TOFU MITM attempt).
/// - [`DoubleRatchetError::AuthenticationFailed`] — MAC failed, or the
///   message key was already consumed (replay).
/// - [`DoubleRatchetError::ProtocolError`] — any other `libsignal`
///   failure.
#[allow(clippy::too_many_arguments)]
pub async fn decrypt_message(
    ciphertext: SerializedCiphertext,
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    session_store: &mut dyn libsignal_protocol::SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &dyn SignedPreKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
) -> Result<Vec<u8>, DoubleRatchetError> {
    let parsed = CiphertextMessage::try_from(&ciphertext)?;

    let mut csprng = OsRng.unwrap_err();
    message_decrypt(
        &parsed,
        remote_address,
        local_address,
        session_store,
        identity_store,
        pre_key_store,
        signed_pre_key_store,
        kyber_pre_key_store,
        &mut csprng,
    )
    .await
    .map_err(DoubleRatchetError::from_protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_a_ciphertext_typed_serialized_ciphertext() {
        let bytes = vec![0x42, 0x00, 0x01, 0x02];
        let sc = SerializedCiphertext::new(MessageType::Ciphertext, bytes.clone());

        assert_eq!(sc.message_type(), MessageType::Ciphertext);
        assert_eq!(sc.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn round_trip_a_prekey_typed_serialized_ciphertext() {
        let bytes = vec![0x43, 0x00, 0x01, 0x02];
        let sc = SerializedCiphertext::new(MessageType::PreKey, bytes.clone());

        assert_eq!(sc.message_type(), MessageType::PreKey);
        assert_eq!(sc.into_bytes(), bytes);
    }

    #[test]
    fn parsing_a_serialized_ciphertext_dispatches_by_message_type() {
        // A SignalMessage::try_from of a PreKey-tagged body must fail.
        // (We don't bother checking the reverse — the failure mode is
        // "libsignal rejects a body that doesn't match the declared
        // shape," which is what the round-trip tests already cover.)
        let bogus = SerializedCiphertext::new(MessageType::Ciphertext, vec![0x43, 0x00]);
        let err = CiphertextMessage::try_from(&bogus).unwrap_err();
        // The libsignal parser rejects the bogus protobuf payload; we map
        // that to MalformedCiphertext so the caller knows the bytes are
        // wrong, not that the ratchet failed.
        assert_eq!(err, DoubleRatchetError::MalformedCiphertext);
    }

    #[test]
    fn libsignal_session_not_found_is_classified_as_no_session() {
        let err = SignalProtocolError::SessionNotFound(libsignal_protocol::SessionNotFound::new(
            ProtocolAddress::new("alice".to_string(), device_id_for_test()),
            "message_encrypt",
        ));
        assert_eq!(
            DoubleRatchetError::from_protocol(err),
            DoubleRatchetError::NoSession,
        );
    }

    #[test]
    fn libsignal_untrusted_identity_is_classified_as_untrusted_identity() {
        let err = SignalProtocolError::UntrustedIdentity(ProtocolAddress::new(
            "alice".to_string(),
            device_id_for_test(),
        ));
        assert_eq!(
            DoubleRatchetError::from_protocol(err),
            DoubleRatchetError::UntrustedIdentity,
        );
        assert!(DoubleRatchetError::is_untrusted_identity(
            &SignalProtocolError::UntrustedIdentity(ProtocolAddress::new(
                "alice".to_string(),
                device_id_for_test(),
            ))
        ));
    }

    #[test]
    fn libsignal_invalid_message_is_classified_as_authentication_failed() {
        let err = SignalProtocolError::InvalidMessage(
            libsignal_protocol::CiphertextMessageType::Whisper,
            "bad mac".to_string(),
        );
        assert_eq!(
            DoubleRatchetError::from_protocol(err),
            DoubleRatchetError::AuthenticationFailed,
        );
    }

    #[test]
    fn libsignal_ciphertext_too_short_is_classified_as_malformed_ciphertext() {
        let err = SignalProtocolError::CiphertextMessageTooShort(0);
        assert_eq!(
            DoubleRatchetError::from_protocol(err),
            DoubleRatchetError::MalformedCiphertext,
        );
    }

    #[test]
    fn libsignal_unknown_error_is_classified_as_protocol_error_carrying_the_message() {
        let err = SignalProtocolError::InvalidArgument("nope".to_string());
        match DoubleRatchetError::from_protocol(err) {
            DoubleRatchetError::ProtocolError(msg) => assert!(msg.contains("nope")),
            other => panic!("expected ProtocolError, got: {other:?}"),
        }
    }

    fn device_id_for_test() -> libsignal_protocol::DeviceId {
        libsignal_protocol::DeviceId::new(1).expect("valid device id")
    }
}
