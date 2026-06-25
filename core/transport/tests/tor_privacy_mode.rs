use transport::build_swarm_with_privacy;
use transport::privacy::{verify_tor_available, TransportPrivacyConfig, TorUnavailable};

#[test]
fn default_transport_privacy_config_disables_tor() {
    let config = TransportPrivacyConfig::default();
    assert!(!config.tor_enabled);
    assert_eq!(config.tor_socks_addr, "127.0.0.1:9050");
}

#[test]
fn disabled_tor_never_attempts_a_proxy_check() {
    // With tor_enabled = false, verify_tor_available must return Ok without
    // touching the network — even with a completely bogus address.
    let config = TransportPrivacyConfig {
        tor_enabled: false,
        tor_socks_addr: "not-an-address".to_string(),
    };
    assert!(verify_tor_available(&config).is_ok());
}

#[test]
fn enabling_tor_with_no_reachable_proxy_fails_closed() {
    // Port 19050 is chosen to be unpopulated on CI / dev machines.
    let config = TransportPrivacyConfig {
        tor_enabled: true,
        tor_socks_addr: "127.0.0.1:19050".to_string(),
    };
    assert_eq!(
        verify_tor_available(&config),
        Err(TorUnavailable::ProxyUnreachable(
            "127.0.0.1:19050".to_string()
        ))
    );
}

#[test]
fn enabling_tor_with_an_unparseable_proxy_address_fails_closed() {
    let config = TransportPrivacyConfig {
        tor_enabled: true,
        tor_socks_addr: "not-a-valid-addr".to_string(),
    };
    assert_eq!(
        verify_tor_available(&config),
        Err(TorUnavailable::InvalidProxyAddress(
            "not-a-valid-addr".to_string()
        ))
    );
}

#[test]
fn enabling_tor_with_a_reachable_proxy_succeeds() {
    // Bind a local listener to simulate a reachable Tor proxy.
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed").to_string();

    let config = TransportPrivacyConfig {
        tor_enabled: true,
        tor_socks_addr: addr,
    };
    assert!(verify_tor_available(&config).is_ok());
}

// ── System-level fail-closed gate ─────────────────────────────────────────────

#[test]
fn build_swarm_with_privacy_fails_closed_when_tor_enabled_and_proxy_unreachable() {
    // Port 19050 is chosen to be unpopulated on CI / dev machines; the swarm
    // must not be built — a clearnet swarm must never be returned when the
    // caller requested Tor.
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let config = TransportPrivacyConfig {
        tor_enabled: true,
        tor_socks_addr: "127.0.0.1:19050".to_string(),
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
        tor_socks_addr: "not-a-valid-addr".to_string(),
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
