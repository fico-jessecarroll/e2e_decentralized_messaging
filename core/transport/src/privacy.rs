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

/// Controls whether outbound transport connections are routed through Tor.
///
/// Tor is opt-in and disabled by default — we must not silently proxy traffic.
/// When enabled, `verify_tor_available` must be called at startup; if it fails,
/// the caller must not build a swarm (fail-closed). See `build_swarm_with_privacy`.
pub struct TransportPrivacyConfig {
    pub tor_enabled: bool,
    pub tor_socks_addr: String,
}

impl Default for TransportPrivacyConfig {
    fn default() -> Self {
        Self {
            tor_enabled: false,
            tor_socks_addr: "127.0.0.1:9050".to_string(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum TorUnavailable {
    InvalidProxyAddress(String),
    ProxyUnreachable(String),
}

impl std::fmt::Display for TorUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorUnavailable::InvalidProxyAddress(addr) => {
                write!(f, "invalid Tor proxy address: {}", addr)
            }
            TorUnavailable::ProxyUnreachable(addr) => {
                write!(f, "Tor proxy unreachable: {}", addr)
            }
        }
    }
}

impl std::error::Error for TorUnavailable {}

/// Verifies that the Tor SOCKS proxy is reachable when Tor is enabled.
///
/// Returns `Ok(())` immediately when `tor_enabled` is false — no network I/O
/// is performed. When enabled, parses the address (returning
/// `InvalidProxyAddress` on failure) then attempts a short TCP connection
/// (returning `ProxyUnreachable` on timeout or refusal).
pub fn verify_tor_available(config: &TransportPrivacyConfig) -> Result<(), TorUnavailable> {
    if !config.tor_enabled {
        return Ok(());
    }
    let addr: std::net::SocketAddr = config
        .tor_socks_addr
        .parse()
        .map_err(|_| TorUnavailable::InvalidProxyAddress(config.tor_socks_addr.clone()))?;
    TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map(|_| ())
        .map_err(|_| TorUnavailable::ProxyUnreachable(config.tor_socks_addr.clone()))
}

// ── SOCKS5 transport ──────────────────────────────────────────────────────────

type Socks5CompatStream =
    tokio_util::compat::Compat<tokio_socks::tcp::Socks5Stream<tokio::net::TcpStream>>;

/// A libp2p [`Transport`] that dials all outbound connections through a SOCKS5
/// proxy (e.g. a local Tor daemon). Inbound listening is not supported — Tor
/// exit nodes handle inbound routing at a higher layer.
///
/// This transport is intentionally not exported as a standalone public API.
/// Callers should use [`crate::build_swarm_with_privacy`] which enforces the
/// fail-closed invariant before constructing the transport.
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
        (Protocol::Ip4(ip), Protocol::Tcp(port)) => Some(format!("{}:{}", ip, port)),
        (Protocol::Ip6(ip), Protocol::Tcp(port)) => Some(format!("[{}]:{}", ip, port)),
        (Protocol::Dns(host), Protocol::Tcp(port))
        | (Protocol::Dns4(host), Protocol::Tcp(port))
        | (Protocol::Dns6(host), Protocol::Tcp(port)) => Some(format!("{}:{}", host, port)),
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
        let target = multiaddr_to_tcp_target(&addr)
            .ok_or(TransportError::MultiaddrNotSupported(addr))?;

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
