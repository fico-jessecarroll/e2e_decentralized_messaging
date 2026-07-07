/// Metadata analysis for the transport crate.
///
/// This module provides a single public function that returns a multi‑line
/// string describing observable metadata at each layer of the transport stack.
/// The content is intentionally verbose and contains explicit references to
/// DHT peer IDs, lookup timing, relay store TTLs, packet sizes, and key
/// rotation cadence. It is used by tests to ensure that the analysis exists
/// and mentions "dht" in a lower‑cased form.

pub fn document_observable_metadata() -> String {
    let mut s = String::new();
    // DHT layer: peer IDs, lookup timing
    s.push_str("DHT Layer:\n\t• Peer IDs are exposed as part of the Kademlia routing table and can be observed by any node that participates in lookups.\n\t• Lookup timing is measurable via round‑trip latency to target nodes; an observer can infer network topology or node responsiveness.\n");
    // Relay store TTL
    s.push_str("Relay Store:\n\t• The relay store holds temporary routing information for relayed connections and has a configurable Time‑To‑Live (TTL). Observers can see when entries expire, which may leak usage patterns.\n");
    // Transport packet sizes
    s.push_str("Transport Packet Sizes:\n\t• Messages are transmitted over libp2p streams with a maximum frame size defined by the underlying protocol (e.g., QUIC or TCP). Padding is applied to reduce observable variance.\n");
    // Key rotation cadence
    s.push_str("Key Rotation Cadence:\n\t• Noise handshakes and QUIC connections rotate keys periodically; the cadence can be inferred from handshake frequency, which may reveal connection churn.\n");
    s
}
