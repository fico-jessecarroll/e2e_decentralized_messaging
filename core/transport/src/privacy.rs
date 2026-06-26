//! Optional Tor transport mode (PLAN.md §10 "Metadata via DHT participation").
//!
//! Scope of this module: the secure-default/fail-closed gate around enabling Tor, and a
//! [`Socks5TcpTransport`] that routes outbound libp2p dials through the local Tor daemon's SOCKS5
//! proxy. See [`crate::build_swarm_with_privacy`] for the entry point.

use std::io;
use std::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::future::BoxFuture;
use libp2p::core::{
    transport::{DialOpts, ListenerId, TransportError, TransportEvent},
    Multiaddr,
};
use libp2p::multiaddr::Protocol;
use tokio_socks::tcp::Socks5Stream;
use tokio_util::compat::TokioAsyncReadCompatExt;

/// The standard local address for the Tor daemon's SOCKS5 proxy.
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
#[derive(Debug, PartialEq)]
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

// ── SOCKS5 transport ──────────────────────────────────────────────────────────

type Socks5CompatStream =
    tokio_util::compat::Compat<tokio_socks::tcp::Socks5Stream<tokio::net::TcpStream>>;

/// A libp2p [`Transport`](libp2p::core::Transport) that dials all outbound connections through a
/// SOCKS5 proxy (e.g. a local Tor daemon). Inbound listening is not supported — Tor exit nodes
/// handle inbound routing at a higher layer.
///
/// This type is not exported as a standalone public API. Callers should use
/// [`crate::build_swarm_with_privacy`] which enforces the fail-closed invariant before
/// constructing this transport.
pub(crate) struct Socks5TcpTransport {
    proxy_addr: String,
}

impl Socks5TcpTransport {
    pub(crate) fn new(proxy_addr: String) -> Self {
        Self { proxy_addr }
    }
}

fn multiaddr_to_tcp_target(addr: &Multiaddr) -> Option<String> {
    let mut iter = addr.iter();
    let proto1 = iter.next()?;
    let proto2 = iter.next()?;
    match (proto1, proto2) {
        (Protocol::Ip4(ip), Protocol::Tcp(port)) => Some(format!("{ip}:{port}")),
        (Protocol::Ip6(ip), Protocol::Tcp(port)) => Some(format!("[{ip}]:{port}")),
        (Protocol::Dns(host), Protocol::Tcp(port))
        | (Protocol::Dns4(host), Protocol::Tcp(port))
        | (Protocol::Dns6(host), Protocol::Tcp(port)) => Some(format!("{host}:{port}")),
        _ => None,
    }
}

impl libp2p::core::Transport for Socks5TcpTransport {
    type Output = Socks5CompatStream;
    type Error = io::Error;
    type ListenerUpgrade = futures::future::Pending<Result<Self::Output, Self::Error>>;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        _id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        // Tor clients don't accept inbound connections via SOCKS5.
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _id: ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        _opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let proxy = self.proxy_addr.clone();
        let target =
            multiaddr_to_tcp_target(&addr).ok_or(TransportError::MultiaddrNotSupported(addr))?;

        Ok(Box::pin(async move {
            let stream = Socks5Stream::connect(proxy.as_str(), target.as_str())
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
            Ok(stream.compat())
        }))
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}
