//! Self-hostable Circuit Relay v2 binary.
//!
//! Accepts `--listen <multiaddr>` (default `/ip4/0.0.0.0/tcp/4001`) and runs an
//! infinite swarm event loop, logging relay events at INFO level.
//!
//! # Quick start
//!
//! ```text
//! cargo run -p relay -- --listen /ip4/0.0.0.0/tcp/4001
//! ```

use clap::Parser;
use libp2p::{futures::StreamExt, relay as lp_relay, swarm::SwarmEvent, Multiaddr};
use relay::{build_relay_swarm, RelayBehaviourEvent};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(about = "Self-hostable libp2p Circuit Relay v2 node")]
struct Cli {
    /// Multiaddr to listen on (e.g. /ip4/0.0.0.0/tcp/4001).
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/4001")]
    listen: Multiaddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("relay=info,warn")),
        )
        .init();

    let cli = Cli::parse();
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = keypair.public().to_peer_id();

    let mut swarm = build_relay_swarm(keypair)?;
    swarm.listen_on(cli.listen.clone())?;

    info!(peer_id = %local_peer_id, listen = %cli.listen, "relay node started");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(addr = %address, "listening on {}", address);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => match event {
                lp_relay::Event::ReservationReqAccepted {
                    src_peer_id,
                    renewed,
                } => {
                    info!(peer = %src_peer_id, renewed, "circuit reservation accepted");
                }
                lp_relay::Event::ReservationReqDenied { src_peer_id, .. } => {
                    info!(peer = %src_peer_id, "circuit reservation denied");
                }
                lp_relay::Event::ReservationTimedOut { src_peer_id } => {
                    info!(peer = %src_peer_id, "circuit reservation timed out");
                }
                lp_relay::Event::CircuitReqAccepted {
                    src_peer_id,
                    dst_peer_id,
                } => {
                    info!(src = %src_peer_id, dst = %dst_peer_id, "circuit accepted");
                }
                lp_relay::Event::CircuitReqDenied {
                    src_peer_id,
                    dst_peer_id,
                    ..
                } => {
                    info!(src = %src_peer_id, dst = %dst_peer_id, "circuit request denied (no reservation)");
                }
                other => {
                    info!("relay event: {:?}", other);
                }
            },
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!(peer = %peer_id, "connection established");
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                if let Some(err) = cause {
                    warn!(peer = %peer_id, err = %err, "connection closed with error");
                } else {
                    info!(peer = %peer_id, "connection closed");
                }
            }
            _ => {}
        }
    }
}
