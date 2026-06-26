use crypto::device_qr::{decode_device_qr, encode_device_qr, safety_number_for_display, QrError};
use crypto::{generate_identity_key_pair, sign_device_identity, verify_device_identity};
use libsignal_protocol::IdentityKey;

/// Encoding a keypair's public key bytes and decoding the resulting payload yields
/// the original bytes.
#[test]
fn encode_decode_roundtrip() {
    let kp = generate_identity_key_pair();
    let key_bytes = kp.identity_key().serialize();

    let payload = encode_device_qr(&key_bytes).expect("encode should succeed");
    let decoded = decode_device_qr(&payload).expect("decode should succeed");

    assert_eq!(decoded, key_bytes.to_vec());
}

/// A payload containing non-hex characters must be rejected.
#[test]
fn decode_rejects_non_hex_payload() {
    let result = decode_device_qr("not-hex!!");
    assert!(
        matches!(result, Err(QrError::InvalidPayload(_))),
        "expected InvalidPayload, got {:?}",
        result
    );
}

/// A payload of 60 hex chars (30 bytes) must be rejected — a serialized identity key
/// is 33 bytes (66 hex chars).
#[test]
fn decode_rejects_wrong_length_hex() {
    let payload = "aa".repeat(30); // 60 hex chars = 30 bytes
    let result = decode_device_qr(&payload);
    assert!(
        matches!(result, Err(QrError::InvalidPayload(_))),
        "expected InvalidPayload, got {:?}",
        result
    );
}

/// Calling safety_number_for_display twice with the same keys returns the same string.
#[test]
fn safety_number_is_deterministic() {
    let primary = generate_identity_key_pair();
    let device = generate_identity_key_pair();
    let primary_key = primary.identity_key().serialize();
    let device_key = device.identity_key().serialize();

    let first = safety_number_for_display(&primary_key, &device_key).expect("ok");
    let second = safety_number_for_display(&primary_key, &device_key).expect("ok");

    assert_eq!(first, second);
}

/// Safety numbers from different keypair combinations must differ.
#[test]
fn safety_number_differs_for_different_keys() {
    let primary = generate_identity_key_pair();
    let device_a = generate_identity_key_pair();
    let device_b = generate_identity_key_pair();

    let primary_key = primary.identity_key().serialize();
    let key_a = device_a.identity_key().serialize();
    let key_b = device_b.identity_key().serialize();

    let sn_a = safety_number_for_display(&primary_key, &key_a).expect("ok");
    let sn_b = safety_number_for_display(&primary_key, &key_b).expect("ok");

    assert_ne!(sn_a, sn_b);
}

/// The full device-linking flow: encode new-device key as QR payload → decode → sign → verify.
#[test]
fn full_linking_flow() {
    let primary = generate_identity_key_pair();
    let new_device = generate_identity_key_pair();

    // New device encodes its identity key as a QR payload for display.
    let new_device_key_bytes = new_device.identity_key().serialize();
    let qr_payload = encode_device_qr(&new_device_key_bytes).expect("encode ok");

    // Primary device reads the QR payload and decodes the key bytes.
    let decoded_bytes = decode_device_qr(&qr_payload).expect("decode ok");
    assert_eq!(decoded_bytes, new_device_key_bytes.to_vec());

    // Reconstruct the IdentityKey from the decoded bytes.
    let decoded_identity_key = IdentityKey::decode(&decoded_bytes)
        .expect("decoded bytes must form a valid identity key");

    // Both parties compute the safety number for out-of-band comparison.
    let primary_key_bytes = primary.identity_key().serialize();
    let safety_num =
        safety_number_for_display(&primary_key_bytes, &decoded_bytes).expect("safety number ok");
    assert!(!safety_num.is_empty(), "safety number must be non-empty");

    // Primary device signs the new device's identity key to authorise the link.
    let signature = sign_device_identity(&primary, &decoded_identity_key).expect("sign ok");

    // Verify the link is valid.
    assert!(
        verify_device_identity(primary.identity_key(), &decoded_identity_key, &signature),
        "link must verify against the primary's identity key"
    );
}
