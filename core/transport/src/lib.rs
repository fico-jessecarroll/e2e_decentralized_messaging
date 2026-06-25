//! libp2p transport stack: Noise-encrypted TCP and QUIC.
//!
//! Per `PLAN.md` §2 and `docs/threat-model.md` §4.4, this layer provides point-to-point
//! confidentiality/integrity between libp2p endpoints as defense-in-depth *underneath* the
//! Signal Protocol E2E layer — it is not a substitute for it, and the design must hold even if
//! every relay/DHT peer this transport talks to is hostile.
//!
//! Two transports are stood up:
//! - **TCP + Noise + Yamux**: the Noise `XX` handshake authenticates each peer's libp2p identity
//!   key and derives a confidential, integrity-protected channel; Yamux multiplexes streams over
//!   it.
//! - **QUIC**: carries its own TLS 1.3-based encryption and peer authentication as an integral
//!   part of the QUIC handshake (`libp2p-quic`/`libp2p-tls`). Noise is not layered on top of
//!   QUIC — QUIC's handshake already provides the equivalent property, and libp2p does not
//!   support nesting a second security upgrade inside it.
//!
//! Kademlia DHT, Circuit Relay, and GossipSub are out of scope here — each is its own
//! downstream story (see the plan manifest) that builds on the [`Swarm`] this module produces.

use libp2p::{identity::Keypair, noise, ping, swarm::Swarm, tcp, yamux, SwarmBuilder};

/// Builds a [`Swarm`] for `keypair` with the TCP+Noise+Yamux and QUIC transports wired in.
///
/// The behaviour is the minimal [`ping::Behaviour`]: it proves that an established connection
/// carries a real, bidirectional, application-level byte stream over the negotiated
/// encrypted/multiplexed channel, not merely that some lower-level handshake bit flipped to
/// "done". Discovery, relaying, and messaging behaviours are added by downstream stories.
pub fn build_swarm(
    keypair: Keypair,
) -> Result<Swarm<ping::Behaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|_key| ping::Behaviour::default())?
        .build();
    Ok(swarm)
}
