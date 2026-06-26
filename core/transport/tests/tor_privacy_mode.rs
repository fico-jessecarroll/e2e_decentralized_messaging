use std::net::TcpListener;

use transport::build_swarm_with_privacy;
use transport::privacy::{verify_tor_available, TransportPrivacyConfig, TorUnavailable};

#[test]
fn default_transport_privacy_config_disables_tor() {
    let config = TransportPrivacyConfig::default();
    assert!(
        !config.tor_enabled,
        "Tor must be off by default (secure default)"
    );
}

#[test]
fn disabled_tor_never_attempts_a_proxy_check() {
    // Garbage address: if this were ever dialed, parsing it would error. With Tor disabled,
    // verify_tor_available must short-circuit and succeed without touching it.
    let config = TransportPrivacyConfig {
        tor_enabled: false,
        tor_socks_addr: "not a real address".to_string(),
    };
    assert!(verify_tor_available(&config).is_ok());
}

#[test]
fn enabling_tor_with_no_reachable_proxy_fails_closed() {
    let config = TransportPrivacyConfig {
        tor_enabled: true,
        // Port 0 is never a connectable address — guaranteed unreachable.
        tor_socks_addr: "127.0.0.1:0".to_string(),
    };
    let result = verify_tor_available(&config);
    assert!(
        matches!(result, Err(TorUnavailable::ProxyUnreachable(_))),
        "must fail closed, not silently fall back to clearnet"
    );
}

#[test]
fn enabling_tor_with_an_unparseable_proxy_address_fails_closed() {
    let config = TransportPrivacyConfig {
        tor_enabled: true,
        tor_socks_addr: "not a real address".to_string(),
    };
    let result = verify_tor_available(&config);
    assert!(matches!(
        result,
        Err(TorUnavailable::InvalidProxyAddress(_))
    ));
}

#[test]
fn enabling_tor_with_a_reachable_proxy_succeeds() {
    // Stand in for a local Tor SOCKS port: any listener proves "reachable" for this check's
    // purpose (a full SOCKS5 handshake is out of scope for this story — see module docs).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local port");
    let addr = listener.local_addr().expect("local addr");
    let config = TransportPrivacyConfig {
        tor_enabled: true,
        tor_socks_addr: addr.to_string(),
    };
    assert!(verify_tor_available(&config).is_ok());
}

// ── System-level fail-closed gate ─────────────────────────────────────────────

#[test]
fn build_swarm_with_privacy_fails_closed_when_tor_enabled_and_proxy_unreachable() {
    // Port 0 is never connectable; the swarm must not be built — a clearnet swarm must never
    // be returned when the caller requested Tor.
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let config = TransportPrivacyConfig {
        tor_enabled: true,
        tor_socks_addr: "127.0.0.1:0".to_string(),
    };
    let result = build_swarm_with_privacy(keypair, &config);
    assert!(
        result.is_err(),
        "build_swarm_with_privacy must not produce a swarm when Tor is unavailable"
    );
}

#[test]
fn build_swarm_with_privacy_fails_closed_when_tor_enabled_and_address_unparseable() {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let config = TransportPrivacyConfig {
        tor_enabled: true,
        tor_socks_addr: "not a real address".to_string(),
    };
    let result = build_swarm_with_privacy(keypair, &config);
    assert!(
        result.is_err(),
        "build_swarm_with_privacy must not produce a swarm when Tor proxy address is unparseable"
    );
}

#[test]
fn build_swarm_with_privacy_builds_clearnet_swarm_when_tor_disabled() {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let config = TransportPrivacyConfig::default(); // tor_enabled = false
    let result = build_swarm_with_privacy(keypair, &config);
    assert!(
        result.is_ok(),
        "build_swarm_with_privacy must succeed when Tor is disabled"
    );
}
