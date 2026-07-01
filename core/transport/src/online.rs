//! Direct message delivery to a connected peer (PLAN.md Phase 3).
//!
//! This module owns the public DM-delivery surface: given a peer's 32-byte identity hash
//! (the transport-level peer id — see [`crypto::IdentityKeyPairExt::identity_hash`]) and an
//! encrypted envelope produced by the Signal session layer, [`deliver`] hands the envelope to
//! the connected peer's stream and returns the bytes the recipient echoes back.
//!
//! Reachability is tracked in a process-global registry that the libp2p connection-management
//! layer updates via [`mark_peer_connected`] / [`mark_peer_disconnected`]. Delivery is
//! deny-by-default: a peer not registered as connected yields [`DeliveryError::PeerUnreachable`]
//! *without attempting any I/O*, so a message can never silently succeed against a peer we have
//! no live connection to (CLAUDE.md "fail securely / deny by default"). The Signal-Protocol E2E
//! layer (authentication, forward secrecy) sits *above* this transport and is the real
//! integrity gate; this layer only moves bytes between authenticated libp2p endpoints.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use tokio::time::timeout;

/// Errors returned by [`deliver`].
#[derive(Debug)]
pub enum DeliveryError {
    /// No connected peer for `peer_id`; delivery was not attempted. Returned before any I/O so
    /// that delivery can never silently succeed against a peer we have no connection to.
    PeerUnreachable { peer_id: Vec<u8>, within: Duration },
    /// The peer was connected but did not complete the round trip within `within`.
    TimedOut { peer_id: Vec<u8>, within: Duration },
    /// The recipient's session stream closed mid-delivery.
    SessionClosed { peer_id: Vec<u8> },
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliveryError::PeerUnreachable { peer_id, within } => {
                write!(f, "peer {peer_id:?} unreachable within {within:?}")
            }
            DeliveryError::TimedOut { peer_id, within } => {
                write!(f, "delivery to {peer_id:?} timed out after {within:?}")
            }
            DeliveryError::SessionClosed { peer_id } => {
                write!(f, "recipient session for {peer_id:?} closed")
            }
        }
    }
}

impl std::error::Error for DeliveryError {}

/// Reachability of a peer, per the connection registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    /// A live, registered connection exists for this peer.
    Connected,
    /// No registered connection exists for this peer.
    Unreachable,
}

/// Connection registry: the set of peers currently registered as connected.
///
/// A peer is "connected" iff the libp2p layer has called [`mark_peer_connected`] for it and not
/// since called [`mark_peer_disconnected`]. Absence is treated as unreachable (deny-by-default).
#[derive(Default)]
struct Registry {
    connected: HashMap<Vec<u8>, ()>,
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::default()));

/// Mark `peer_id` as connected (online). Called by the libp2p connection layer when a peer's
/// stream becomes usable. Idempotent.
pub fn mark_peer_connected(peer_id: Vec<u8>) {
    REGISTRY
        .lock()
        .expect("transport connection registry poisoned")
        .connected
        .insert(peer_id, ());
}

/// Forget `peer_id` — it went offline or its stream closed. Idempotent.
pub fn mark_peer_disconnected(peer_id: &[u8]) {
    REGISTRY
        .lock()
        .expect("transport connection registry poisoned")
        .connected
        .remove(peer_id);
}

/// Reachability of `peer_id`. Deny-by-default: a peer not registered as connected is
/// [`PeerStatus::Unreachable`], never silently [`PeerStatus::Connected`].
pub async fn peer_status(peer_id: &[u8]) -> PeerStatus {
    let connected = REGISTRY
        .lock()
        .expect("transport connection registry poisoned")
        .connected
        .contains_key(peer_id);
    if connected {
        PeerStatus::Connected
    } else {
        PeerStatus::Unreachable
    }
}

/// Deliver `envelope` to the connected `peer_id`, returning the bytes the recipient echoes.
///
/// Deny-by-default: a peer not registered as connected yields
/// [`DeliveryError::PeerUnreachable`] without attempting I/O. For a connected peer the round
/// trip is bounded by `timeout_dur`; exceeding it yields [`DeliveryError::TimedOut`].
///
/// The stub transport echoes the envelope verbatim — the bytes that arrive at the recipient are
/// exactly the bytes the sender passed in. The real libp2p path writes `envelope` to the peer's
/// authenticated stream and reads the echoed response; the timeout bounds that round trip.
pub async fn deliver(
    peer_id: &[u8],
    envelope: Vec<u8>,
    timeout_dur: Duration,
) -> Result<Vec<u8>, DeliveryError> {
    {
        let registry = REGISTRY
            .lock()
            .expect("transport connection registry poisoned");
        if !registry.connected.contains_key(peer_id) {
            return Err(DeliveryError::PeerUnreachable {
                peer_id: peer_id.to_vec(),
                within: timeout_dur,
            });
        }
    }

    // Connected peer: bound the round trip. The stub does no real I/O, so the body resolves
    // immediately; the timeout is in place for the real transport path.
    match timeout(timeout_dur, std::future::ready(envelope)).await {
        Ok(bytes) => Ok(bytes),
        Err(_) => Err(DeliveryError::TimedOut {
            peer_id: peer_id.to_vec(),
            within: timeout_dur,
        }),
    }
}
