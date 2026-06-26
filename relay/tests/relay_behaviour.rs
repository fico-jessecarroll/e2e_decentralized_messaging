//! Integration tests for the Circuit Relay v2 server behaviour.
//!
//! Covers the story's acceptance criteria:
//! - Positive: relay node starts up, listens, and reports its PeerId.
//! - Positive: relay accepts a reservation from a client that listens on a /p2p-circuit address.
//! - Negative: relay denies a circuit request when the destination peer has no reservation.

use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    identity::Keypair,
    multiaddr::Protocol,
    noise, ping, relay as lp_relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use relay::{build_relay_swarm, RelayBehaviour, RelayBehaviourEvent};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Drive `swarm` until it reports a `NewListenAddr`, returning that address.
async fn listen_and_get_addr(swarm: &mut libp2p::swarm::Swarm<RelayBehaviour>) -> Multiaddr {
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return address;
        }
    }
}

/// A minimal behaviour combining relay client + ping, used by test peers that
/// need to make or consume circuit reservations.
#[derive(NetworkBehaviour)]
struct ClientBehaviour {
    relay: lp_relay::client::Behaviour,
    ping: ping::Behaviour,
}

/// Build a swarm for a peer that acts as a Circuit Relay v2 **client**.
fn build_client_swarm(
    keypair: Keypair,
) -> Result<libp2p::swarm::Swarm<ClientBehaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|_key, relay_client| {
            Ok(ClientBehaviour {
                relay: relay_client,
                ping: ping::Behaviour::default(),
            })
        })?
        .build();
    Ok(swarm)
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// The relay node must start, bind to a port, and emit `NewListenAddr` without error.
/// The PeerId is deterministically derived from the keypair — it is stable before any
/// network event, so we assert it is not randomly generated after the fact.
#[tokio::test]
async fn relay_starts_and_listens() {
    let keypair = Keypair::generate_ed25519();
    let expected_peer_id = keypair.public().to_peer_id();

    let mut swarm = build_relay_swarm(keypair).unwrap();
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    let addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    })
    .await
    .expect("relay did not emit NewListenAddr within 5 s");

    // Address is on 127.0.0.1
    assert!(
        addr.to_string().contains("127.0.0.1"),
        "expected loopback listen addr, got {addr}"
    );
    // Swarm's local PeerId is the one derived from the keypair
    assert_eq!(
        *swarm.local_peer_id(),
        expected_peer_id,
        "relay PeerId does not match the keypair"
    );
}

/// A client peer that listens on a `/p2p-circuit` address through the relay
/// triggers a RESERVE request. The relay must respond with acceptance, emitting
/// `relay::Event::ReservationReqAccepted`.
#[tokio::test]
async fn relay_accepts_circuit_reservation() {
    // Start relay server
    let relay_keypair = Keypair::generate_ed25519();
    let relay_peer_id = relay_keypair.public().to_peer_id();
    let mut relay_swarm = build_relay_swarm(relay_keypair).unwrap();
    let relay_addr = listen_and_get_addr(&mut relay_swarm).await;

    // Build client A with relay client behaviour
    let client_a_keypair = Keypair::generate_ed25519();
    let mut client_a = build_client_swarm(client_a_keypair).unwrap();

    // Client A listens on a /p2p-circuit address rooted at the relay.
    // The relay client behaviour intercepts this and sends a RESERVE to the relay.
    let circuit_listen_addr = relay_addr
        .clone()
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit);
    client_a.listen_on(circuit_listen_addr).unwrap();

    let reservation_accepted = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = relay_swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(
                        RelayBehaviourEvent::Relay(
                            lp_relay::Event::ReservationReqAccepted { .. },
                        ),
                    ) = event
                    {
                        return true;
                    }
                }
                _ = client_a.select_next_some() => {}
            }
        }
    })
    .await;

    assert!(
        reservation_accepted.is_ok(),
        "relay did not accept the circuit reservation within 10 s"
    );
}

/// When a peer tries to route through the relay to a destination that has no
/// reservation, the relay must deny the circuit request. The initiating peer
/// receives an `OutgoingConnectionError`.
#[tokio::test]
async fn relay_rejects_unknown_peer_without_reservation() {
    // Start relay server
    let relay_keypair = Keypair::generate_ed25519();
    let relay_peer_id = relay_keypair.public().to_peer_id();
    let mut relay_swarm = build_relay_swarm(relay_keypair).unwrap();
    let relay_addr = listen_and_get_addr(&mut relay_swarm).await;

    // Peer B wants to reach a random peer that has never reserved at the relay.
    let peer_b_keypair = Keypair::generate_ed25519();
    let mut peer_b = build_client_swarm(peer_b_keypair).unwrap();
    let unreserved_peer_id = PeerId::random();

    // Dial: relay → circuit → unreserved peer
    let circuit_dial_addr = relay_addr
        .clone()
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(unreserved_peer_id));
    peer_b.dial(circuit_dial_addr).unwrap();

    // We expect either the relay to emit CircuitReqDenied, or peer B to receive
    // an OutgoingConnectionError — whichever arrives first proves the relay
    // refuses to route to an unreserved destination.
    let rejected = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = relay_swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                        lp_relay::Event::CircuitReqDenied { .. },
                    )) = event
                    {
                        return true;
                    }
                }
                event = peer_b.select_next_some() => {
                    if let SwarmEvent::OutgoingConnectionError { .. } = event {
                        return true;
                    }
                }
            }
        }
    })
    .await;

    assert!(
        rejected.is_ok(),
        "relay did not deny the circuit request within 10 s"
    );
}
