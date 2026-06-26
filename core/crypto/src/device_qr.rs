//! QR-code-based device linking: encode an identity public key as a QR payload,
//! decode a scanned payload back to raw bytes, and derive a human-readable safety
//! number for out-of-band verification before the primary device signs the link.
//!
//! # Flow
//!
//! 1. New device calls [`encode_device_qr`] to get a hex payload string.
//!    In a UI, this string is rendered as a QR code image for the user to scan.
//! 2. Primary device scans the QR code, obtaining the hex payload.
//! 3. Primary device calls [`decode_device_qr`] to recover the raw key bytes.
//! 4. Both devices call [`safety_number_for_display`] and compare the result
//!    out-of-band (e.g., verbally) to guard against QR-substitution attacks.
//! 5. Primary device calls `sign_device_identity` (from the parent crate) to
//!    authorise the link.

use qrcode::QrCode;

use crate::derive_safety_number;

/// Errors that can occur during QR-based device linking.
#[derive(Debug)]
pub enum QrError {
    /// QR code generation failed (payload too large or other encoding error).
    EncodeFailed(String),
    /// The QR payload is not valid hex, has the wrong byte length, or is otherwise
    /// malformed.
    InvalidPayload(String),
    /// The key bytes could not be used to derive a safety number.
    KeyError(String),
}

impl std::fmt::Display for QrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncodeFailed(msg) => write!(f, "QR encode failed: {msg}"),
            Self::InvalidPayload(msg) => write!(f, "invalid QR payload: {msg}"),
            Self::KeyError(msg) => write!(f, "key error: {msg}"),
        }
    }
}

impl std::error::Error for QrError {}

/// Encode a device's identity public key bytes as a QR code payload string.
///
/// The returned string is the hex-encoded key — the exact data a QR code scanner
/// would read when scanning a QR code that embeds this payload. Pass the returned
/// string to a QR renderer (e.g. `qrcode::QrCode::new(payload)`) to produce an
/// image for display.
///
/// Returns `Err(QrError::EncodeFailed)` if the bytes cannot be represented as a
/// valid QR code (in practice impossible for 33-byte identity keys).
pub fn encode_device_qr(identity_public_key_bytes: &[u8]) -> Result<String, QrError> {
    let hex_payload: String = identity_public_key_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Verify the payload is QR-encodable. A 33-byte key yields a 66-char hex string,
    // which fits easily within QR error-correction level M capacity.
    QrCode::new(hex_payload.as_bytes())
        .map_err(|e| QrError::EncodeFailed(e.to_string()))?;

    Ok(hex_payload)
}

/// Decode a QR code payload back to raw identity public key bytes.
///
/// `qr_payload` must be the hex string returned by [`encode_device_qr`] — i.e. the
/// string a QR code scanner would read after scanning a QR code produced from that
/// function's output.
///
/// Returns `Err(QrError::InvalidPayload)` if:
/// - `qr_payload` contains non-hex characters,
/// - its length is odd (malformed hex), or
/// - the decoded byte length is not 33 (the serialized size of a
///   `libsignal_protocol::IdentityKey`).
pub fn decode_device_qr(qr_payload: &str) -> Result<Vec<u8>, QrError> {
    // Only lowercase hex digits are valid; reject everything else eagerly.
    if !qr_payload.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(QrError::InvalidPayload(
            "payload contains non-hex characters".to_string(),
        ));
    }

    if qr_payload.len() % 2 != 0 {
        return Err(QrError::InvalidPayload(
            "payload has odd length, not valid hex encoding".to_string(),
        ));
    }

    let bytes: Vec<u8> = (0..qr_payload.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&qr_payload[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|e| QrError::InvalidPayload(e.to_string()))?;

    // A serialized `IdentityKey` from `libsignal_protocol` is always 33 bytes:
    // one key-type tag byte (0x05 for Curve25519) followed by 32 key bytes.
    if bytes.len() != 33 {
        return Err(QrError::InvalidPayload(format!(
            "decoded {} bytes, expected 33 (serialized identity key length)",
            bytes.len()
        )));
    }

    Ok(bytes)
}

/// Derive a human-readable safety number from the primary device's serialized
/// identity key and a new device's serialized identity key.
///
/// Delegates to [`crate::derive_safety_number`] using the key bytes as both the
/// identifier and the key for each party, making the result deterministic and
/// symmetric without requiring separate user identifiers in the device-linking flow.
///
/// Returns `Err(QrError::KeyError)` if either key slice is malformed or cannot be
/// decoded as an `IdentityKey`.
pub fn safety_number_for_display(
    primary_key: &[u8],
    new_device_key: &[u8],
) -> Result<String, QrError> {
    derive_safety_number(primary_key, primary_key, new_device_key, new_device_key)
        .map_err(|e| QrError::KeyError(e.to_string()))
}
