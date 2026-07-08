//! X3DH / PQXDH session establishment (PLAN.md §1 "Crypto core").
//!
//! At the pinned libsignal revision, `PreKeyBundle` always includes a Kyber KEM public key, so
//! every session established through this module uses PQXDH (Post-Quantum Extended
//! Diffie-Hellman) rather than classical X3DH.  The API is intentionally thin: `libsignal`'s
//! `process_prekey_bundle` does the cryptographic heavy lifting; this module provides the
//! helpers to assemble a publishable `PreKeyBundle` and a named entry point for the outbound
//! session-establishment step so callers don't have to reach into the underlying crate directly.

use libsignal_protocol::{
    kem, process_prekey_bundle, GenericSignedPreKey, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, PreKeyBundle, PreKeyRecord,
    ProtocolAddress, SessionStore, SignalProtocolError, SignedPreKeyRecord,
};
use rand::{CryptoRng, Rng};
use std::time::SystemTime;

pub use crate::ratchet_session::SessionError;

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

/// Deliberately attempt PQXDH session establishment against a bundle with a tampered
/// signed-prekey signature, and return the resulting `Err` rather than panicking.
///
/// Exists so a client shell (e.g. the Tauri desktop shell, PLAN.md Phase 5) has a concrete,
/// zero-setup way to exercise the "a malformed core input surfaces as a defined error state, not
/// a crash" contract without assembling a full PQXDH handshake itself. The bundle is built from a
/// real, freshly generated receiver session (via [`crate::ratchet_session::DoubleRatchetSession`])
/// with its signed-prekey signature overwritten with zero bytes — the same tampering the
/// `tampered_signed_prekey_signature_is_rejected` acceptance test exercises at the lower-level
/// `establish_outbound_session` API.
pub fn establish_with_malformed_prekey() -> Result<(), SessionError> {
    use crate::ratchet_session::DoubleRatchetSession;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("building a current-thread tokio runtime cannot fail");

    runtime.block_on(async {
        let bob_identity = crate::generate_identity_key_pair();
        let bob = DoubleRatchetSession::new_bob(&bob_identity).await?;
        let bundle = bob.publish_bundle()?;

        let one_time_prekey = bundle
            .pre_key_id()
            .map_err(SessionError::Establishment)?
            .zip(
                bundle
                    .pre_key_public()
                    .map_err(SessionError::Establishment)?,
            );

        let malformed_bundle = PreKeyBundle::new(
            bundle
                .registration_id()
                .map_err(SessionError::Establishment)?,
            bundle.device_id().map_err(SessionError::Establishment)?,
            one_time_prekey,
            bundle
                .signed_pre_key_id()
                .map_err(SessionError::Establishment)?,
            bundle
                .signed_pre_key_public()
                .map_err(SessionError::Establishment)?,
            vec![0u8; 64], // deliberately malformed signed-prekey signature
            bundle
                .kyber_pre_key_id()
                .map_err(SessionError::Establishment)?,
            bundle
                .kyber_pre_key_public()
                .map_err(SessionError::Establishment)?
                .clone(),
            bundle
                .kyber_pre_key_signature()
                .map_err(SessionError::Establishment)?
                .to_vec(),
            *bundle.identity_key().map_err(SessionError::Establishment)?,
        )
        .map_err(SessionError::Establishment)?;

        let alice_identity = crate::generate_identity_key_pair();
        DoubleRatchetSession::new_alice(&alice_identity, &malformed_bundle)
            .await
            .map(|_| ())
    })
}

// ---------------------------------------------------------------------------
// PreKeyBundle byte serialization (for the WASM binding)
// ---------------------------------------------------------------------------

/// Serialize a libsignal `PreKeyBundle` to a self-delimiting byte vector.
///
/// The format is a length-prefixed concatenation of every field a sender needs to reconstruct
/// the bundle and call `process_prekey_bundle`:
///
/// ```text
///   [ registration_id        : 4 bytes BE ]
///   [ device_id              : 4 bytes BE ]
///   [ identity_key_len : 4 bytes BE ] [ identity_key_bytes ]
///   [ signed_pre_key_id      : 4 bytes BE ]
///   [ signed_pre_key_pub_len : 4 bytes BE ] [ signed_pre_key_pub_bytes ]
///   [ signed_pre_key_sig_len : 4 bytes BE ] [ signed_pre_key_sig_bytes ]
///   [ kyber_pre_key_id       : 4 bytes BE ]
///   [ kyber_pre_key_pub_len  : 4 bytes BE ] [ kyber_pre_key_pub_bytes ]
///   [ kyber_pre_key_sig_len  : 4 bytes BE ] [ kyber_pre_key_sig_bytes ]
///   [ one_time_pre_key_presence : 1 byte ]   // 0 = absent, 1 = present
///   [ one_time_pre_key_id      : 4 bytes BE ] // only if present
///   [ one_time_pre_key_pub_len : 4 bytes BE ] // only if present
///   [ one_time_pre_key_pub_bytes             ] // only if present
/// ```
///
/// This is an **internal** crate format — it does NOT match the `/spec` protobuf wire format.
/// It exists so the WASM binding can pass a bundle across the JS boundary as opaque bytes.
pub fn bundle_to_bytes(bundle: &PreKeyBundle) -> Result<Vec<u8>, SignalProtocolError> {
    let mut buf = Vec::new();

    let registration_id = bundle.registration_id()?;
    buf.extend_from_slice(&registration_id.to_be_bytes());

    let device_id: u32 = bundle.device_id()?.into();
    buf.extend_from_slice(&device_id.to_be_bytes());

    let identity_key = bundle.identity_key()?;
    let identity_bytes = identity_key.serialize();
    write_u32_prefixed(&mut buf, &identity_bytes);

    let signed_pre_key_id: u32 = bundle.signed_pre_key_id()?.into();
    buf.extend_from_slice(&signed_pre_key_id.to_be_bytes());

    let spk_pub = bundle.signed_pre_key_public()?;
    write_u32_prefixed(&mut buf, &spk_pub.serialize());

    let spk_sig = bundle.signed_pre_key_signature()?;
    write_u32_prefixed(&mut buf, spk_sig);

    let kyber_pre_key_id: u32 = bundle.kyber_pre_key_id()?.into();
    buf.extend_from_slice(&kyber_pre_key_id.to_be_bytes());

    let kyber_pub = bundle.kyber_pre_key_public()?;
    let kyber_pub_bytes = kyber_pub.serialize();
    write_u32_prefixed(&mut buf, &kyber_pub_bytes);

    let kyber_sig = bundle.kyber_pre_key_signature()?;
    write_u32_prefixed(&mut buf, kyber_sig);

    match bundle.pre_key_id()? {
        Some(otpk_id) => {
            buf.push(1u8); // present
            let otpk_id: u32 = otpk_id.into();
            buf.extend_from_slice(&otpk_id.to_be_bytes());
            let otpk_pub = bundle
                .pre_key_public()?
                .ok_or(SignalProtocolError::InvalidArgument(
                    "pre_key_id present but pre_key_public missing".into(),
                ))?;
            write_u32_prefixed(&mut buf, &otpk_pub.serialize());
        }
        None => {
            buf.push(0u8); // absent
        }
    }

    Ok(buf)
}

/// Deserialize a `PreKeyBundle` from the byte vector produced by [`bundle_to_bytes`].
///
/// Returns `Err` for any truncated, mis-length-prefixed, or structurally invalid input —
/// never panics. The caller SHOULD pass the result through `process_prekey_bundle` (via
/// `establish_outbound_session` / `DoubleRatchetSession::new_alice`), which verifies the
/// signed-prekey and Kyber-prekey signatures against the bundle's identity key.
pub fn bundle_from_bytes(bytes: &[u8]) -> Result<PreKeyBundle, SignalProtocolError> {
    let mut offset = 0usize;

    let registration_id = read_u32(bytes, &mut offset)?;
    let device_id_val = read_u32(bytes, &mut offset)?;
    let device_id = libsignal_protocol::DeviceId::new(
        device_id_val
            .try_into()
            .map_err(|_| SignalProtocolError::InvalidArgument("device id out of range".into()))?,
    )
    .map_err(|_| SignalProtocolError::InvalidArgument("invalid device id".into()))?;

    let identity_bytes = read_u32_prefixed(bytes, &mut offset)?;
    let identity_key = IdentityKey::try_from(identity_bytes)
        .map_err(|_| SignalProtocolError::InvalidArgument("malformed identity key".into()))?;

    let signed_pre_key_id = libsignal_protocol::SignedPreKeyId::from(read_u32(bytes, &mut offset)?);

    let spk_pub_bytes = read_u32_prefixed(bytes, &mut offset)?;
    let spk_pub = libsignal_protocol::PublicKey::try_from(spk_pub_bytes).map_err(|_| {
        SignalProtocolError::InvalidArgument("malformed signed prekey public".into())
    })?;

    let spk_sig = read_u32_prefixed(bytes, &mut offset)?.to_vec();

    let kyber_pre_key_id = libsignal_protocol::KyberPreKeyId::from(read_u32(bytes, &mut offset)?);

    let kyber_pub_bytes = read_u32_prefixed(bytes, &mut offset)?;
    let kyber_pub = kem::PublicKey::deserialize(kyber_pub_bytes).map_err(|_| {
        SignalProtocolError::InvalidArgument("malformed kyber prekey public".into())
    })?;

    let kyber_sig = read_u32_prefixed(bytes, &mut offset)?.to_vec();

    // one-time prekey presence flag
    if bytes.len() < offset + 1 {
        return Err(SignalProtocolError::InvalidArgument(
            "truncated: missing one-time prekey presence flag".into(),
        ));
    }
    let presence = bytes[offset];
    offset += 1;

    let one_time_prekey = match presence {
        0 => None,
        1 => {
            let otpk_id = libsignal_protocol::PreKeyId::from(read_u32(bytes, &mut offset)?);
            let otpk_pub_bytes = read_u32_prefixed(bytes, &mut offset)?;
            let otpk_pub =
                libsignal_protocol::PublicKey::try_from(otpk_pub_bytes).map_err(|_| {
                    SignalProtocolError::InvalidArgument("malformed one-time prekey public".into())
                })?;
            Some((otpk_id, otpk_pub))
        }
        _ => {
            return Err(SignalProtocolError::InvalidArgument(
                "invalid one-time prekey presence flag".into(),
            ));
        }
    };

    // Reject trailing bytes — a well-formed bundle consumes the entire input.
    if offset != bytes.len() {
        return Err(SignalProtocolError::InvalidArgument(
            "trailing bytes after prekey bundle".into(),
        ));
    }

    PreKeyBundle::new(
        registration_id,
        device_id,
        one_time_prekey,
        signed_pre_key_id,
        spk_pub,
        spk_sig,
        kyber_pre_key_id,
        kyber_pub,
        kyber_sig,
        identity_key,
    )
}

fn write_u32_prefixed(buf: &mut Vec<u8>, segment: &[u8]) {
    let len = segment.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(segment);
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, SignalProtocolError> {
    // `*offset` is guaranteed <= bytes.len() by prior checks, so subtraction is safe.
    if bytes.len() - *offset < 4 {
        return Err(SignalProtocolError::InvalidArgument(
            "truncated: missing 4-byte field".into(),
        ));
    }
    let val = u32::from_be_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]);
    *offset += 4;
    Ok(val)
}

fn read_u32_prefixed<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
) -> Result<&'a [u8], SignalProtocolError> {
    let len = read_u32(bytes, offset)? as usize;
    // Use checked subtraction to avoid integer overflow on 32-bit targets (wasm32)
    // where `*offset + len` could wrap if `len` is a malicious u32::MAX.  After
    // `read_u32` consumed 4 bytes, `*offset <= bytes.len()` still holds, so
    // `bytes.len() - *offset` cannot underflow.
    let remaining = bytes.len() - *offset;
    if len > remaining {
        return Err(SignalProtocolError::InvalidArgument(
            "truncated: declared segment longer than remaining bytes".into(),
        ));
    }
    let segment = &bytes[*offset..*offset + len];
    *offset += len;
    Ok(segment)
}

#[cfg(test)]
mod malformed_prekey_tests {
    use super::establish_with_malformed_prekey;
    use crate::ratchet_session::SessionError;

    #[test]
    fn malformed_signed_prekey_surfaces_as_an_error_not_a_panic() {
        let result = establish_with_malformed_prekey();
        assert!(
            matches!(result, Err(SessionError::Establishment(_))),
            "tampered signed-prekey signature must surface as Err, got: {result:?}"
        );
    }

    /// Regression test for integer-overflow DoS on 32-bit targets (wasm32).
    ///
    /// A malicious peer controlling the bundle bytes can set a length prefix to
    /// `u32::MAX`.  On a 32-bit `usize` target, `offset + len` would overflow and
    /// either panic (debug) or wrap (release), bypassing the bounds check.  The
    /// checked-arithmetic fix must reject this as `Err`, never panic.
    #[test]
    fn bundle_from_bytes_rejects_u32_max_length_prefix() {
        // registration_id (4) + device_id (4) = 8 bytes consumed, then the next
        // field is a u32-prefixed identity_key segment.  Set its length to u32::MAX.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 8]); // registration_id + device_id (both 0)
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // identity_key len = u32::MAX
        bytes.extend_from_slice(&[0u8; 8]); // filler

        let result = super::bundle_from_bytes(&bytes);
        assert!(
            result.is_err(),
            "u32::MAX length prefix must be rejected as Err"
        );
    }
}
