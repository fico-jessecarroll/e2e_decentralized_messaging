//! Metadata leakage mitigation — message size padding reduces content-length analysis.
//!
//! Anchors PLAN.md Phase 9 acceptance criteria:
//!  - Documented analysis of observable metadata at each layer
//!  - Message size padding reduces content-length-based traffic analysis (measurable in test)

use transport::padding::{pad_message, PaddedSizes};

#[test]
fn padded_message_sizes_fall_into_a_small_set_of_buckets() {
    // Two very different plaintext sizes, after padding, should land in
    // the same size bucket — so an observer cannot distinguish "short" from "long".
    let small = pad_message(b"hi", PaddedSizes::default());
    let large = pad_message(&vec![0u8; 4096], PaddedSizes::default());

    let small_bucket = PaddedSizes::bucket_of(small.len());
    let large_bucket = PaddedSizes::bucket_of(large.len());
    assert_eq!(
        small_bucket, large_bucket,
        "small and large padded messages must share a size bucket to defeat length analysis"
    );
}

#[test]
fn padding_is_documented_and_metadata_analysis_is_attached() {
    // The metadata analysis must live in the crate's docs (or a sibling file)
    // and enumerate what is observable at each layer.
    let analysis = transport::metadata::document_observable_metadata();
    assert!(!analysis.is_empty(), "metadata analysis must be non-empty");
    assert!(
        analysis.to_lowercase().contains("dht"),
        "analysis must cover DHT-layer metadata (peer IDs, lookup timing)"
    );
}
