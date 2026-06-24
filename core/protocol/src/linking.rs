//! Per-device identity key linking using libsignal's alternate identity signature.

//!
//! This module implements the primary-signed linking model (PLAN.md §4) using
//! libsignal's `IdentityKeyPair::sign_alternate_identity` and `IdentityKey::verify_alternate_identity`.
//! 
//! Each device generates its own identity key, then signs a message binding that key to the
//! primary device's identity key. This proves that both keys belong to the same account.

use libsignal_protocol::{IdentityKey, IdentityKeyPair};

/// Signs a message binding a device's identity key to the primary device's identity key.
/// 
/// # Arguments
/// 
/// * `device_key_pair` - The identity key pair of the device requesting linkage.
/// * `primary_key` - The public identity key of the primary device.
/// * `message` - A message or token to bind the keys together (e.g., a timestamp or nonce).
/// 
/// # Returns
/// 
/// A signature that can be verified by other devices.
pub fn sign_linkage(
    device_key_pair: &IdentityKeyPair,
    primary_key: &IdentityKey,
    message: &[u8],
) -> Vec<u8> {
    // Generate a signature binding the device's key to the primary key.
    let message_with_prefix = [b"linkage", message].concat();
    device_key_pair.sign_alternate_identity(&message_with_prefix, &primary_key)
}

/// Verifies a linkage signature to ensure it was signed by the claimed device.
/// 
/// # Arguments
/// 
/// * `signature` - The signature to verify.
/// * `device_key` - The public identity key of the device that supposedly signed the message.
/// * `primary_key` - The public identity key of the primary device.
/// * `message` - The same message used during signing.
/// 
/// # Returns
/// 
/// `true` if the signature is valid, `false` otherwise.
pub fn verify_linkage(
    signature: &[u8],
    device_key: &IdentityKey,
    primary_key: &IdentityKey,
    message: &[u8],
) -> bool {
    // Verify the signature against the device's key and the primary key.
    device_key.verify_alternate_identity(&signature, &message_with_prefix, &primary_key)
}