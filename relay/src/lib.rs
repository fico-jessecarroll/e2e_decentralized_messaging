//! Circuit Relay v2 server behaviour and swarm builder.
//!
//! The relay node provides a rendezvous point for NAT-traversal-resistant peers.
//! It implements the libp2p Circuit Relay v2 server protocol: peers that cannot
//! accept inbound connections make a **reservation** at the relay; other peers then
//! open a proxied **circuit** through the relay to reach them.
//!
//! Defence-in-depth note: the relay is deliberately blind — it forwards encrypted
//! streams between peers without being able to read or modify the Signal Protocol
//! E2E content.

use libp2p::{identity::Keypair, noise, ping, relay, swarm::Swarm, tcp, yamux, SwarmBuilder};

pub mod pow;
pub mod ratelimit;
pub mod store;
pub mod ws;

/// Combined network behaviour for the relay node: Circuit Relay v2 server + ping liveness.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct RelayBehaviour {
    pub relay: relay::Behaviour,
    pub ping: ping::Behaviour,
}

/// Builds a [`Swarm`] configured as a Circuit Relay v2 **server**.
///
/// Transport: TCP + Noise XX + Yamux (same stack as `core/transport`).
/// Behaviour: [`relay::Behaviour`] in server mode, plus [`ping::Behaviour`] for liveness.
pub fn build_relay_swarm(
    keypair: Keypair,
) -> Result<Swarm<RelayBehaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();
            Ok(RelayBehaviour {
                relay: relay::Behaviour::new(peer_id, relay::Config::default()),
                ping: ping::Behaviour::default(),
            })
        })?
        .build();
    Ok(swarm)
}
