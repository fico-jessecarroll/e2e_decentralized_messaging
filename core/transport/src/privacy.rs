//! Optional Tor transport mode (PLAN.md §10 "Metadata via DHT participation"; full hardening
//! lands in Phase 9 per the roadmap).
//!
//! Scope of this module: the secure-default/fail-closed gate around enabling Tor, per
//! `CLAUDE.md`'s "Secure by Design" — Tor is off by default, and turning it on must never
//! silently degrade to clearnet if the local Tor SOCKS proxy isn't actually reachable. Wiring an
//! actual SOCKS5-proxied libp2p [`Transport`](libp2p::Transport) into [`crate::build_swarm`] for
//! outbound dials is tracked as Phase 9 hardening work, not this story's acceptance criteria.

use std::net::TcpStream;
use std::time::Duration;

/// The standard local port for the Tor daemon's SOCKS5 proxy.
pub const DEFAULT_TOR_SOCKS_ADDR: &str = "127.0.0.1:9050";

const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Transport-privacy configuration. `tor_enabled` defaults to `false`: clearnet is the default
/// transport, and Tor is strictly opt-in (PLAN.md §8 "Secure defaults").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPrivacyConfig {
    pub tor_enabled: bool,
    pub tor_socks_addr: String,
}

impl Default for TransportPrivacyConfig {
    fn default() -> Self {
        Self {
            tor_enabled: false,
            tor_socks_addr: DEFAULT_TOR_SOCKS_ADDR.to_string(),
        }
    }
}

/// Tor was requested but is not usable. Callers must treat this as fail-closed: refuse to
/// proceed rather than falling back to an unrequested clearnet path.
#[derive(Debug)]
pub enum TorUnavailable {
    /// `tor_socks_addr` does not parse as a socket address.
    InvalidProxyAddress(String),
    /// The configured SOCKS proxy address did not accept a connection within the timeout.
    ProxyUnreachable(String),
}

impl std::fmt::Display for TorUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProxyAddress(addr) => {
                write!(f, "invalid Tor SOCKS proxy address: {addr}")
            }
            Self::ProxyUnreachable(addr) => write!(f, "Tor SOCKS proxy unreachable at {addr}"),
        }
    }
}

impl std::error::Error for TorUnavailable {}

/// Verify the configured Tor SOCKS proxy is reachable before any traffic relies on it.
///
/// If `config.tor_enabled` is `false`, this is a no-op that always succeeds — Tor was never
/// requested, so there is nothing to verify and no proxy is contacted. If `tor_enabled` is
/// `true`, this returns `Err` unless a TCP connection to `tor_socks_addr` succeeds; callers must
/// not proceed to build a clearnet swarm on `Err`, since that would silently defeat the user's
/// opt-in choice.
pub fn verify_tor_available(config: &TransportPrivacyConfig) -> Result<(), TorUnavailable> {
    if !config.tor_enabled {
        return Ok(());
    }

    let addr = config
        .tor_socks_addr
        .parse()
        .map_err(|_| TorUnavailable::InvalidProxyAddress(config.tor_socks_addr.clone()))?;

    TcpStream::connect_timeout(&addr, PROXY_CONNECT_TIMEOUT)
        .map(|_| ())
        .map_err(|_| TorUnavailable::ProxyUnreachable(config.tor_socks_addr.clone()))
}
