//! X3DH / PQXDH session establishment (PLAN.md §1 "Crypto core").
//!
//! At the pinned libsignal revision, `PreKeyBundle` always includes a Kyber KEM public key, so
//! every session established through this module uses PQXDH (Post-Quantum Extended
//! Diffie-Hellman) rather than classical X3DH.  The API is intentionally thin: `libsignal`'s
//! `process_prekey_bundle` does the cryptographic heavy lifting; this module provides the
//! helpers to assemble a publishable `PreKeyBundle` and a named entry point for the outbound
//! session-establishment step so callers don't have to reach into the underlying crate directly.

use libsignal_protocol::{
    kem, process_prekey_bundle, GenericSignedPreKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, PreKeyBundle, PreKeyRecord, ProtocolAddress, SessionStore,
    SignalProtocolError, SignedPreKeyRecord,
};
use rand::{CryptoRng, Rng};
use std::time::SystemTime;

/// Generate a Kyber1024 pre-key, signed by `signing_key`, for inclusion in a PQXDH bundle.
///
/// The signing key must be the holder's EC identity private key — the recipient verifies the
/// signature when processing the bundle to confirm the KEM key belongs to the declared identity.
pub fn generate_kyber_prekey(
    id: KyberPreKeyId,
    signing_key: &libsignal_protocol::PrivateKey,
) -> Result<KyberPreKeyRecord, SignalProtocolError> {
    KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, id, signing_key)
}

/// Assemble a PQXDH `PreKeyBundle` for publication to the DHT or relay.
///
/// `one_time_prekey` is optional — receivers prefer bundles with a one-time prekey (stronger
/// forward secrecy), but senders MUST still proceed if one is unavailable.
pub fn build_prekey_bundle(
    registration_id: u32,
    device_id: libsignal_protocol::DeviceId,
    identity_keypair: &IdentityKeyPair,
    signed_prekey: &SignedPreKeyRecord,
    kyber_prekey: &KyberPreKeyRecord,
    one_time_prekey: Option<&PreKeyRecord>,
) -> Result<PreKeyBundle, SignalProtocolError> {
    let otpk = one_time_prekey
        .map(|r| -> Result<_, SignalProtocolError> { Ok((r.id()?, r.public_key()?)) })
        .transpose()?;

    PreKeyBundle::new(
        registration_id,
        device_id,
        otpk,
        signed_prekey.id()?,
        signed_prekey.public_key()?,
        signed_prekey.signature()?.to_vec(),
        kyber_prekey.id()?,
        kyber_prekey.public_key()?,
        kyber_prekey.signature()?.to_vec(),
        *identity_keypair.identity_key(),
    )
}

/// Establish an outbound Signal (PQXDH) session from a remote peer's published pre-key bundle.
///
/// On success the session is stored under `remote_address` in `session_store` and the caller
/// can immediately encrypt an initial message with `message_encrypt`.  On any error the stores
/// are left unchanged — there is no partial or corrupt session written.
///
/// # Errors
///
/// Returns `Err` for any of the conditions `process_prekey_bundle` enforces:
/// - `SignatureValidationFailed` — the signed-prekey or Kyber-prekey signature does not verify
///   against the bundle's identity key (tampered bundle).
/// - `UntrustedIdentity` — the identity key in the bundle is already known under
///   `remote_address` but differs from the stored key (identity key changed, possible MITM).
pub async fn establish_outbound_session<R: Rng + CryptoRng>(
    local_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    remote_bundle: &PreKeyBundle,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    csprng: &mut R,
) -> Result<(), SignalProtocolError> {
    process_prekey_bundle(
        remote_address,
        local_address,
        session_store,
        identity_store,
        remote_bundle,
        SystemTime::now(),
        csprng,
    )
    .await
}
