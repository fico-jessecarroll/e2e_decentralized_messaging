//! Self-hostable Circuit Relay v2 binary.
//!
//! Accepts `--listen <multiaddr>` (default `/ip4/0.0.0.0/tcp/4001`) and runs an
//! infinite swarm event loop, logging relay events at INFO level.
//!
//! # WebSocket bridge (opt-in)
//!
//! The WS bridge exposes the relay's store-and-forward + PoW/rate-limit gates to
//! browser clients over WebSocket. It is **opt-in** and locked-down by default
//! (per CLAUDE.md "Secure by Design": new endpoints ship locked-down by default).
//! To enable it, pass `--ws-listen <addr>`:
//!
//! ```text
//! cargo run -p relay -- --listen /ip4/0.0.0.0/tcp/4001 --ws-listen 0.0.0.0:8000
//! ```
//!
//! When `--ws-listen` is omitted, **no** WS listener is started and the default
//! port (`0.0.0.0:8000`) is **not** bound. The `--ws-rate-limit <u32>` flag
//! (default 60, i.e. 60 requests/minute per identity) only takes effect when
//! `--ws-listen` is supplied.
//!
//! # Quick start
//!
//! ```text
//! cargo run -p relay -- --listen /ip4/0.0.0.0/tcp/4001
//! ```

use clap::Parser;
use libp2p::Multiaddr;
use relay::{run_relay, RelayOptions};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

/// Default per-identity WS rate limit (requests/minute). Matches the test default
/// used throughout `relay/tests/ws_bridge.rs`.
const DEFAULT_WS_RATE_LIMIT: u32 = 60;

#[derive(Parser)]
#[command(about = "Self-hostable libp2p Circuit Relay v2 node")]
struct Cli {
    /// Multiaddr to listen on (e.g. /ip4/0.0.0.0/tcp/4001).
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/4001")]
    listen: Multiaddr,

    /// Address for the optional WebSocket bridge (e.g. 0.0.0.0:8000).
    ///
    /// Omit this flag to keep the WS bridge disabled (secure-by-default). When
    /// omitted, no WS listener is started and the default port is not bound.
    #[arg(long)]
    ws_listen: Option<SocketAddr>,

    /// Per-identity rate limit (requests/minute) for the WS bridge.
    /// Only takes effect when `--ws-listen` is supplied. Default: 60.
    #[arg(long, default_value_t = DEFAULT_WS_RATE_LIMIT)]
    ws_rate_limit: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("relay=info,warn")),
        )
        .init();

    let cli = Cli::parse();

    let options = RelayOptions {
        listen: cli.listen,
        ws_listen: cli.ws_listen,
        ws_rate_limit_per_minute: cli.ws_rate_limit,
    };

    run_relay(options).await
}
