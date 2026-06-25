//! Integration tests for the libp2p transport stack (`transport::build_swarm`).
//!
//! Covers the story's acceptance criteria:
//! - Positive: two nodes establish a Noise-encrypted transport session and can exchange
//!   application data over it.
//! - Negative: a connection to a peer presenting an invalid identity during the Noise
//!   handshake is rejected, and a connection that sends garbage instead of a valid Noise
//!   handshake message is rejected.

use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    core::upgrade::InboundConnectionUpgrade,
    identity::Keypair,
    noise,
    swarm::{DialError, SwarmEvent},
    Multiaddr, PeerId,
};
use transport::build_swarm;

const LOCAL_TCP: &str = "/ip4/127.0.0.1/tcp/0";

/// Drives `swarm` until `addr` reports a listening address, returning that address.
async fn listen_and_get_addr(
    swarm: &mut libp2p::swarm::Swarm<libp2p::ping::Behaviour>,
) -> Multiaddr {
    swarm.listen_on(LOCAL_TCP.parse().unwrap()).unwrap();
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return address;
        }
    }
}

#[tokio::test]
async fn two_nodes_establish_noise_encrypted_session() {
    let mut node_a = build_swarm(Keypair::generate_ed25519()).unwrap();
    let mut node_b = build_swarm(Keypair::generate_ed25519()).unwrap();

    let addr_a = listen_and_get_addr(&mut node_a).await;
    node_b.dial(addr_a).unwrap();

    let mut a_connected = false;
    let mut b_connected = false;
    let mut ping_seen = false;

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = node_a.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = event {
                        a_connected = true;
                    }
                    if let SwarmEvent::Behaviour(libp2p::ping::Event { result: Ok(_), .. }) = event {
                        ping_seen = true;
                    }
                }
                event = node_b.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = event {
                        b_connected = true;
                    }
                    if let SwarmEvent::Behaviour(libp2p::ping::Event { result: Ok(_), .. }) = event {
                        ping_seen = true;
                    }
                }
            }

            if a_connected && b_connected && ping_seen {
                break;
            }
        }
    })
    .await
    .expect("nodes did not establish a working encrypted session in time");

    assert!(a_connected, "listener never observed a connection");
    assert!(b_connected, "dialer never observed a connection");
    assert!(
        ping_seen,
        "no ping round-trip observed: the Noise-encrypted channel did not carry data"
    );
}

#[tokio::test]
async fn dial_rejected_when_peer_presents_wrong_identity_in_noise_handshake() {
    let mut node_a = build_swarm(Keypair::generate_ed25519()).unwrap();
    let mut node_b = build_swarm(Keypair::generate_ed25519()).unwrap();

    let addr_a = listen_and_get_addr(&mut node_a).await;

    // Dial node A's real address, but tell the swarm to expect an unrelated identity. Noise's
    // XX handshake authenticates the remote's static key against its libp2p PeerId; since node
    // A will actually present its own (different) identity, this must be rejected rather than
    // silently accepted under the wrong identity.
    let wrong_peer_id = PeerId::random();
    node_b
        .dial(
            libp2p::swarm::dial_opts::DialOpts::peer_id(wrong_peer_id)
                .addresses(vec![addr_a])
                .build(),
        )
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                // Drive node A so it completes its side of the handshake/negotiation too.
                _ = node_a.select_next_some() => {}
                event = node_b.select_next_some() => {
                    if let SwarmEvent::OutgoingConnectionError { error, .. } = event {
                        return error;
                    }
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        panic!("connection wrongly established with unexpected peer {peer_id}");
                    }
                }
            }
        }
    })
    .await
    .expect("dial did not fail in time");

    assert!(
        matches!(result, DialError::WrongPeerId { .. }),
        "expected DialError::WrongPeerId, got {result:?}"
    );
}

#[tokio::test]
async fn noise_handshake_rejects_garbage_in_place_of_valid_handshake_message() {
    let honest_identity = Keypair::generate_ed25519();
    let (mut attacker_io, honest_io) = futures_ringbuf::Endpoint::pair(4096, 4096);

    let attacker = async move {
        use futures::AsyncWriteExt;
        attacker_io
            .write_all(b"this is not a valid noise handshake message")
            .await
            .unwrap();
        attacker_io.close().await.unwrap();
    };

    let honest = noise::Config::new(&honest_identity)
        .unwrap()
        .upgrade_inbound(honest_io, "");

    let (_, honest_result) = futures::future::join(attacker, honest).await;

    assert!(
        honest_result.is_err(),
        "honest peer should reject a connection presenting an invalid Noise handshake, got {:?}",
        honest_result.map(|_| "Ok")
    );
}
