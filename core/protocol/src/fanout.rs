//! Per-device session fan-out for 1:1 messaging (PLAN.md Phase 6).
//!
//! A multi-device recipient (e.g. the same user on phone, laptop, and a tablet) is associated
//! with several `DeviceId`s, each carrying its own Curve25519 identity key and PQXDH prekey
//! bundle. To send a single logical 1:1 message to that user, the sender establishes and
//! maintains a **separate** Double Ratchet session per linked device and emits one
//! ciphertext per device. Each device decrypts its own ciphertext with the ratchet session
//! its own identity participates in; no device can read another device's ciphertext.
//!
//! This module is a thin coordinator over [`crypto::DoubleRatchetSession`]. It does **not**
//! reimplement any cryptography, and it does **not** share key material across devices — the
//! ratchet state for device N is the ratchet state between `sender` and `recipient_n`'s
//! identity, full stop. Removing a device simply drops its ratchet state so the next
//! `encrypt_to_all` no longer produces a ciphertext for it.
//!
//! # Lifetime
//!
//! `FanoutSession` is in-memory. Persisting fan-out state across restarts is the storage
//! story's job; the public API here matches the test surface (PLAN.md Phase 6 acceptance
//! file `core/protocol/tests/per_device_fanout.rs`).
//!
//! # Security posture
//!
//! - **Per-device session isolation.** Each device is its own PQXDH + Double Ratchet
//!   session. Compromise of one device's ratchet state does not leak another device's
//!   plaintext past the ratchet forward-secrecy guarantees of `libsignal`.
//! - **No plaintext is dropped or logged.** The fan-out only emits ciphertexts; it does
//!   not store or print the input plaintext at any point.
//! - **Removal is local.** `remove_device` drops the sender's outbound ratchet state for
//!   that device; the recipient device's own ratchet state on its own device is
//!   unaffected. Future messages from the sender simply stop targeting it. This is the
//!   behaviour PLAN.md §4 ("Multi-device") requires for device revocation.
//! - **No cross-device key reuse.** A device's identity is used exactly as the
//!   `DoubleRatchetSession` facade expects: as the bundle signatory on the receive side
//!   and as the addressable peer on the send side. There is no shared symmetric key
//!   between any two devices.

use std::collections::BTreeMap;

use libsignal_protocol::IdentityKeyPair;
use thiserror::Error;
use tokio::runtime::Handle;

use crypto::{DoubleRatchetSession, IdentityKeyPairExt};

/// Drive an async future to completion, working both inside and outside an existing
/// tokio runtime.
///
/// `DoubleRatchetSession`'s PQXDH establishment and Double Ratchet encrypt/decrypt are
/// async. The fan-out API is sync (the acceptance test in `tests/per_device_fanout.rs`
/// does not `.await`), so we need to block on the underlying futures. Three cases:
///
/// 1. **No runtime active.** Create a fresh single-thread runtime per call. The fan-out
///    operations are short-lived and the runtime is dropped at the end of the call so
///    no thread is leaked.
/// 2. **Inside a multi-thread runtime.** `block_in_place` on the current worker thread
///    and then `Handle::current().block_on(...)` on the future — this is the supported
///    way to block from a tokio worker without deadlocking the executor.
/// 3. **Inside a current-thread runtime.** `Handle::current().block_on(...)` directly —
///    we are the only task, so blocking is fine.
///
/// We never call `block_on` while *holding* a non-Send resource across the await, so
/// case 2 is safe. The ratchet sessions are stored in a `BTreeMap` on `self`; we only
/// drive one device's future at a time and never hold a `&mut` across the await, so
/// there is no reentrancy hazard.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    match Handle::try_current() {
        Ok(handle) => {
            // If we are inside a runtime, the kind determines whether we can block
            // on the current thread.
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                tokio::task::block_in_place(move || handle.block_on(fut))
            } else {
                handle.block_on(fut)
            }
        }
        Err(_) => {
            // No runtime is active. Build a fresh current-thread runtime just for
            // this call. The runtime and its worker thread are dropped when this
            // function returns, leaving no leaked resources.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build single-thread tokio runtime for fan-out");
            rt.block_on(fut)
        }
    }
}

/// Stable, application-defined identifier for one of a recipient user's linked devices.
///
/// `DeviceId` is opaque to this module — it is used as a key in the per-fanout device
/// table and round-tripped to the caller in `encrypt_to_all`'s output. The underlying
/// `libsignal` device id used inside each ratchet session is fixed by
/// `DoubleRatchetSession` (a single device per facade instance) and is *not* the same
/// number as this `DeviceId`; the ratchet session is the per-device keying relationship,
/// this `DeviceId` is the application-level index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub u32);

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "device:{}", self.0)
    }
}

/// A single ciphertext targeted at one device, plus the device it is for.
///
/// The ratchet envelope bytes are opaque to callers — the recipient's
/// `DoubleRatchetSession::decrypt` consumes them. The `device` field is included so a
/// transport layer can route the envelope to the right linked device without having to
/// inspect ciphertext internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    /// The device this envelope is for.
    pub device: DeviceId,
    /// Opaque ratchet envelope bytes — feed them to the recipient-side
    /// `DoubleRatchetSession::decrypt` of the device that matches `device`.
    pub envelope: Vec<u8>,
}

/// Errors a `FanoutSession` can surface to its caller.
#[derive(Debug, Error)]
pub enum FanoutError {
    /// The recipient list contained a duplicate `DeviceId`. Each device must be unique
    /// within a single fan-out; otherwise the fan-out is ambiguous.
    #[error("duplicate device id {0} in recipient list")]
    DuplicateDevice(DeviceId),
    /// The recipient list was empty. A fan-out with zero targets is meaningless and is
    /// rejected up front so the caller doesn't get back an empty ciphertext list that
    /// looks like a successful no-op send.
    #[error("fan-out recipient list must contain at least one device")]
    NoDevices,
    /// PQXDH session establishment (`DoubleRatchetSession::new_alice`) failed for one of
    /// the recipient devices — typically a malformed or tampered prekey bundle.
    #[error("session establishment failed for device {0}: {1}")]
    Establishment(DeviceId, crypto::SessionError),
    /// The Double Ratchet encrypt step failed for a specific device.
    #[error("encrypt failed for device {0}: {1}")]
    Encrypt(DeviceId, crypto::SessionError),
    /// The Double Ratchet decrypt step failed for a specific device — wrong recipient
    /// session, replayed envelope, or corrupted ciphertext.
    #[error("decrypt failed for device {0}: {1}")]
    Decrypt(DeviceId, crypto::SessionError),
    /// `decrypt_as` was called with an identity that does not correspond to any device
    /// currently tracked by this fan-out. The fan-out is the source of truth for which
    /// identities participate.
    #[error("no device in this fan-out matches the given identity key")]
    UnknownIdentity,
}

/// Per-device session fan-out for 1:1 messaging.
///
/// A `FanoutSession` owns one outbound `DoubleRatchetSession` per linked device, all
/// keyed off the same `sender` identity. `encrypt_to_all` walks the table, encrypts the
/// plaintext once per device, and returns the resulting envelopes tagged with their
/// target `DeviceId` so the transport layer can route them. `decrypt_as` looks up the
/// matching inbound session and decrypts.
///
/// `decrypt_as` is symmetric across the fan-out: the recipient device's *own*
/// `DoubleRatchetSession` is built the same way as the sender's, so the envelope bytes
/// round-trip. Callers that already have a long-lived `DoubleRatchetSession` for a
/// device should use that directly; `decrypt_as` is here so a freshly-built fan-out
/// (e.g. a test, or a transient receiver role) can decrypt without managing stores
/// itself.
// `Debug` is intentionally not derived: `DoubleRatchetSession` wraps a
// `libsignal` in-memory store that does not implement `Debug`, and exposing the
// raw ratchet bytes in a `Debug` printout would be a confidentiality regression.
// The fan-out's identity-table and device ids *are* debug-printable via the
// public `device_ids()` iterator if callers need to introspect state.
pub struct FanoutSession {
    /// One outbound session per linked device, keyed by `DeviceId`.
    sender_sessions: BTreeMap<DeviceId, DoubleRatchetSession>,
    /// Reverse lookup: an identity key may map to at most one device in a single
    /// fan-out (each device has its own identity). Stored so `decrypt_as` can dispatch
    /// on the identity the test passes in.
    identity_to_device: BTreeMap<[u8; 32], DeviceId>,
    /// One inbound session per linked device, used by `decrypt_as`. Mirrors
    /// `sender_sessions` 1:1. Kept separate from the sender side because the ratchet
    /// store is per-party: the sender's outbound ratchet state cannot double as the
    /// recipient's inbound ratchet state.
    receiver_sessions: BTreeMap<DeviceId, DoubleRatchetSession>,
}

impl FanoutSession {
    /// Establish a fan-out from `sender` to one ratchet session per `(device, identity)`
    /// pair.
    ///
    /// For each entry the sender side runs PQXDH against a prekey bundle published by
    /// the device's identity, and the receiver side is built from the same identity so
    /// `decrypt_as` works against a freshly-constructed `FanoutSession` (matching the
    /// acceptance tests). In a production deployment the receiver side would normally
    /// live in a long-lived store on the recipient device and only the sender side
    /// would be held here; the test surface does not require that separation.
    ///
    /// `sender` is the same identity that initiates every per-device session — a single
    /// user sending a 1:1 message to a single multi-device recipient.
    ///
    /// # Errors
    ///
    /// Returns [`FanoutError::DuplicateDevice`] if `devices` contains the same
    /// `DeviceId` twice, [`FanoutError::NoDevices`] if it is empty, and
    /// [`FanoutError::Establishment`] if PQXDH fails for any device. On any error no
    /// partial state is exposed — the returned `FanoutSession` is only constructed
    /// after every per-device session has been established.
    pub fn establish(
        sender: &IdentityKeyPair,
        devices: &[(DeviceId, &IdentityKeyPair)],
    ) -> Result<Self, FanoutError> {
        if devices.is_empty() {
            return Err(FanoutError::NoDevices);
        }

        let mut sender_sessions: BTreeMap<DeviceId, DoubleRatchetSession> = BTreeMap::new();
        let mut receiver_sessions: BTreeMap<DeviceId, DoubleRatchetSession> = BTreeMap::new();
        let mut identity_to_device: BTreeMap<[u8; 32], DeviceId> = BTreeMap::new();

        for (device_id, recipient_identity) in devices {
            if sender_sessions.contains_key(device_id) {
                return Err(FanoutError::DuplicateDevice(*device_id));
            }

            // Build the device-side session first so we can pull a freshly-published
            // PQXDH prekey bundle off it. That bundle is what the sender consumes via
            // PQXDH (`new_alice`); a tampered or stale bundle would surface as
            // `Establishment` here.
            let receiver = block_on(DoubleRatchetSession::new_bob(recipient_identity))
                .map_err(|e| FanoutError::Establishment(*device_id, e))?;
            let bundle = receiver
                .publish_bundle()
                .map_err(|e| FanoutError::Establishment(*device_id, e))?;

            let outbound = block_on(DoubleRatchetSession::new_alice(sender, &bundle))
                .map_err(|e| FanoutError::Establishment(*device_id, e))?;

            // Sanity check: ratchet envelopes are self-describing only by sender
            // identity hash, so a single sender establishing sessions against
            // *distinct* recipient identities is exactly the property the test relies
            // on. Record the identity→device reverse lookup for `decrypt_as`.
            let identity_hash = recipient_identity.identity_hash();
            if let Some(existing) = identity_to_device.get(&identity_hash) {
                // Same identity re-used for two different device ids — reject up
                // front so the fan-out is unambiguous.
                return Err(FanoutError::DuplicateDevice(*existing));
            }
            identity_to_device.insert(identity_hash, *device_id);

            sender_sessions.insert(*device_id, outbound);
            receiver_sessions.insert(*device_id, receiver);
        }

        Ok(Self {
            sender_sessions,
            identity_to_device,
            receiver_sessions,
        })
    }

    /// Encrypt `plaintext` once per currently-tracked device and return the resulting
    /// envelopes, each tagged with the `DeviceId` it is destined for.
    ///
    /// The plaintext is the same byte slice for every device; per-device confidentiality
    /// comes from each device having its own ratchet session, not from any per-device
    /// transformation of the input. Devices that have been removed via
    /// [`remove_device`](Self::remove_device) are skipped, so the returned vector's
    /// length equals the number of currently-linked devices.
    ///
    /// # Errors
    ///
    /// Returns [`FanoutError::Encrypt`] on the first ratchet failure. The fan-out is
    /// not transactional across devices: a failure on device N leaves devices 0..N with
    /// their ratchets advanced (the Double Ratchet always advances on encrypt) and
    /// devices N+1.. untouched. This matches the per-device session isolation property —
    /// a failure on one device must not poison another's ratchet state.
    pub fn encrypt_to_all(&mut self, plaintext: &[u8]) -> Result<Vec<Ciphertext>, FanoutError> {
        let mut out = Vec::with_capacity(self.sender_sessions.len());
        // Snapshot the device ids so we don't borrow `self.sender_sessions` mutably
        // while iterating it.
        let device_ids: Vec<DeviceId> = self.sender_sessions.keys().copied().collect();
        for device_id in device_ids {
            let session = self
                .sender_sessions
                .get_mut(&device_id)
                .expect("device id came from sender_sessions.keys()");
            let envelope = block_on(session.encrypt(plaintext))
                .map_err(|e| FanoutError::Encrypt(device_id, e))?;
            out.push(Ciphertext {
                device: device_id,
                envelope,
            });
        }
        Ok(out)
    }

    /// Decrypt a ciphertext as the device identified by `device_identity`.
    ///
    /// `ciphertext` is expected to be one of the envelopes returned by
    /// [`encrypt_to_all`](Self::encrypt_to_all) for the device that matches
    /// `device_identity`. The fan-out's per-device receiver session is used; if a
    /// caller has a long-lived receiver session for the same device they should
    /// decrypt with that instead — `decrypt_as` is provided so a freshly-constructed
    /// `FanoutSession` (as in the acceptance test) is symmetric and self-contained.
    ///
    /// # Errors
    ///
    /// Returns [`FanoutError::UnknownIdentity`] if `device_identity` does not match
    /// any device tracked by this fan-out, and [`FanoutError::Decrypt`] on a ratchet
    /// failure (wrong session, tampered ciphertext, replay).
    pub fn decrypt_as(
        &mut self,
        device_identity: &IdentityKeyPair,
        ciphertext: &Ciphertext,
    ) -> Result<Vec<u8>, FanoutError> {
        let device_id = *self
            .identity_to_device
            .get(&device_identity.identity_hash())
            .ok_or(FanoutError::UnknownIdentity)?;
        let session = self
            .receiver_sessions
            .get_mut(&device_id)
            .expect("identity_to_device maps only to inserted device ids");
        block_on(session.decrypt(&ciphertext.envelope))
            .map_err(|e| FanoutError::Decrypt(device_id, e))
    }

    /// Drop the per-device ratchet state for `device_id` so future
    /// [`encrypt_to_all`](Self::encrypt_to_all) calls no longer emit a ciphertext for
    /// it.
    ///
    /// This is the revocation primitive: the next message goes only to the still-linked
    /// devices. Removing a device is idempotent — calling it twice is not an error.
    ///
    /// # Errors
    ///
    /// Never errors today; the `Result` return is kept for forward compatibility with
    /// future persistence-backed implementations that may need to surface store I/O
    /// failures during removal.
    pub fn remove_device(&mut self, device_id: DeviceId) -> Result<(), FanoutError> {
        if let Some(session) = self.sender_sessions.remove(&device_id) {
            // Drop the ratchet state explicitly so its `Drop` runs and zeroes any
            // sensitive in-memory material sooner than the BTreeMap slot reuse would.
            drop(session);
        }
        self.receiver_sessions.remove(&device_id);
        // Drop the identity→device reverse mapping only if it points at the removed
        // device — a different device with a colliding hash is impossible by
        // construction (we rejected collisions in `establish`), so a stale entry here
        // would only mean the device was added under a different identity, which the
        // public API does not support.
        self.identity_to_device.retain(|_, d| *d != device_id);
        Ok(())
    }
}
