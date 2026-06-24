use libsignal_protocol::{IdentityKey, IdentityKeyPair};
use super::linking::{sign_linkage, verify_linkage};

#[test]
fn test_sign_and_verify_linkage() {
    // Generate a primary identity key pair and a device identity key pair.
    let primary_key_pair = IdentityKeyPair::generate(&mut rand::rngs::OsRng).unwrap();
    let device_key_pair = IdentityKeyPair::generate(&mut rand::rngs::OsRng).unwrap();

    // Create a message to bind the keys together.
    let message = b"linkage-token";

    // Sign the linkage.
    let signature = sign_linkage(&device_key_pair, &primary_key_pair.get_public_key(), message);

    // Verify the linkage.
    let is_valid = verify_linkage(&signature, &device_key_pair.get_public_key(), &primary_key_pair.get_public_key(), message);

    assert!(is_valid, "Failed to verify linkage signature");
}
