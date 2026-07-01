//! Wire protocol: message envelopes, prekey management, and per-device session fan-out.
//!
//! See submodule docs for each concern. The public surface is intentionally narrow — every
//! crypto primitive is delegated to the `core_crypto` (re-exported as `crypto`) facade, which
//! in turn wraps `libsignal` directly.

pub mod fanout;
