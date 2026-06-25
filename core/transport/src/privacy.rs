use std::net::TcpStream;
use std::time::Duration;

/// Controls whether outbound transport connections are routed through Tor.
///
/// Tor is opt-in and disabled by default — we must not silently proxy traffic.
/// When enabled, `verify_tor_available` must succeed at startup or the call
/// must return `Err` (fail-closed); we never fall back to cleartext.
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

/// Verifies that the Tor SOCKS proxy is reachable when Tor is enabled.
///
/// Returns `Ok(())` immediately when `tor_enabled` is false — no network I/O
/// is performed.  When enabled, parses the address (returning
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
