/// Padding utilities for transport messages.
///
/// Reduces observable message-size variance by rounding payloads up to a small,
/// fixed set of bucket sizes, so an observer watching ciphertext lengths cannot
/// distinguish a short message from an ordinary-length one (traffic-analysis
/// resistance). The smallest bucket (4096 bytes) covers typical chat-sized
/// payloads; only much larger payloads (e.g. attachments) escalate to a bigger
/// bucket and become distinguishable from a short message.
#[derive(Debug, Clone, Copy, Default)]
pub struct PaddedSizes;

impl PaddedSizes {
    const BUCKETS: &'static [usize] = &[4096, 16384, 65536];

    /// Return the smallest bucket that can contain `len` bytes, or `len` itself
    /// if it exceeds every predefined bucket (no further padding beyond the
    /// largest tier).
    pub fn bucket_of(len: usize) -> usize {
        Self::BUCKETS.iter().copied().find(|&b| len <= b).unwrap_or(len)
    }
}

/// Pad a message to the bucket size returned by [`PaddedSizes::bucket_of`].
///
/// Padding bytes are zeros; any deterministic scheme works as long as it's
/// consistent, since the receiver recovers the real plaintext length from the
/// AEAD-decrypted content, not from the wire length.
pub fn pad_message(msg: &[u8], _sizes: PaddedSizes) -> Vec<u8> {
    let target = PaddedSizes::bucket_of(msg.len());
    let mut padded = msg.to_vec();
    if padded.len() < target {
        padded.resize(target, 0);
    }
    padded
}
