//! Fuzz target for the wire/envelope parser — must reject, never crash.
//!
//! Anchors PLAN.md Phase 9 acceptance criteria:
//!  - Fuzzer runs in CI on a schedule against the parser
//!  - Negative: no crash/panic/UB on any fuzzer-found malformed input; all rejected cleanly

#![no_main]
use libfuzzer_sys::fuzz_target;
use core_protocol::envelope::parse_envelope;

fuzz_target!(|data: &[u8]| {
    // The parser must NEVER panic on arbitrary bytes. It may return Err for
    // any malformed input, but a panic / process abort is a fuzzer finding.
    let _ = parse_envelope(data);
});
