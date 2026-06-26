//! Integration tests for Kademlia DHT prekey-bundle publication and lookup.
//!
//! These drive a real `libp2p::kad` behaviour end-to-end:
//! - Positive: a node publishes a bundle and can look it up again through the DHT.
//! - Positive: a second node, knowing only the publisher's address, fetches the published bundle
//!   and it passes full identity-binding + signature validation.
//! - Negative: a lookup for an identity that never published resolves to "not found", not a hang
//!   and not a bogus record.

use std::time::Duration;

use crypto::generate_identity_key_pair;
use crypto::prekey::{generate_one_time_pre_keys, generate_signed_pre_key, PreKeyBundle};
use futures::StreamExt;
use libp2p::{
    identity::Keypair,
    kad::{self, GetRecordError, GetRecordOk, QueryResult, Record},
    swarm::{Swarm, SwarmEvent},
    Multiaddr,
};
use libsignal_protocol::{IdentityKeyPair, Timestamp};
use transport::dht::{
    build_dht_swarm, decode_and_verify_bundle, lookup_pre_key_bundle, publish_pre_key_bundle,
};

type DhtSwarm = Swarm<kad::Behaviour<kad::store::MemoryStore>>;

fn bundle_for(identity: &IdentityKeyPair) -> PreKeyBundle {
    PreKeyBundle {
        identity_key: *identity.identity_key(),
        signed_pre_key: generate_signed_pre_key(
            identity,
            1,
            Timestamp::from_epoch_millis(1_700_000_000_000),
        ),
        one_time_pre_key: Some(generate_one_time_pre_keys(0, 1).remove(0)),
    }
}

async fn listen_and_get_addr(swarm: &mut DhtSwarm) -> Multiaddr {
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return address;
        }
    }
}

/// A node that publishes a bundle can immediately look it up again from its own DHT store, and the
/// fetched record passes full validation.
#[tokio::test]
async fn a_node_publishes_then_looks_up_its_own_bundle() {
    let identity = generate_identity_key_pair();
    let bundle = bundle_for(&identity);
    let expected = identity.identity_key().serialize().to_vec();

    let mut swarm = build_dht_swarm(Keypair::generate_ed25519()).unwrap();

    publish_pre_key_bundle(swarm.behaviour_mut(), &bundle).expect("publish");
    lookup_pre_key_bundle(swarm.behaviour_mut(), identity.identity_key());

    let record = await_found_record(&mut swarm)
        .await
        .expect("lookup did not return a record within the timeout");

    let verified = decode_and_verify_bundle(&record.key, &record.value).expect("record validates");
    assert_eq!(verified.identity_key.serialize().to_vec(), expected);
}

/// A second node that only knows the publisher's address fetches the published bundle through the
/// DHT, and it validates against the publisher's identity.
#[tokio::test]
async fn a_node_fetches_a_bundle_published_by_a_peer() {
    let publisher = generate_identity_key_pair();
    let bundle = bundle_for(&publisher);
    let expected = publisher.identity_key().serialize().to_vec();

    let mut node_a = build_dht_swarm(Keypair::generate_ed25519()).unwrap();
    let mut node_b = build_dht_swarm(Keypair::generate_ed25519()).unwrap();
    let a_peer = *node_a.local_peer_id();

    let a_addr = listen_and_get_addr(&mut node_a).await;

    // Node A publishes its owner's bundle into the DHT (stored in A's local store).
    publish_pre_key_bundle(node_a.behaviour_mut(), &bundle).expect("publish");

    // Node B learns A's address, then looks the bundle up by the publisher's identity key.
    node_b.behaviour_mut().add_address(&a_peer, a_addr);
    lookup_pre_key_bundle(node_b.behaviour_mut(), publisher.identity_key());

    let record = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                // Drive A so it answers B's query.
                _ = node_a.select_next_some() => {}
                event = node_b.select_next_some() => {
                    if let Some(record) = found_record(event) {
                        return record;
                    }
                }
            }
        }
    })
    .await
    .expect("node B did not fetch the bundle within 30 s");

    let verified =
        decode_and_verify_bundle(&record.key, &record.value).expect("fetched record validates");
    assert_eq!(verified.identity_key.serialize().to_vec(), expected);
}

/// A lookup for an identity that never published resolves to a definite "not found" result rather
/// than hanging or returning a record.
#[tokio::test]
async fn lookup_of_an_unpublished_identity_resolves_to_not_found() {
    let never_published = generate_identity_key_pair();

    let mut swarm = build_dht_swarm(Keypair::generate_ed25519()).unwrap();
    lookup_pre_key_bundle(swarm.behaviour_mut(), never_published.identity_key());

    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                result: QueryResult::GetRecord(result),
                ..
            }) = swarm.select_next_some().await
            {
                // A standalone node with no peers finishes the query without a record.
                match result {
                    Ok(GetRecordOk::FoundRecord(_)) => return false,
                    Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => return true,
                    Err(GetRecordError::NotFound { .. } | GetRecordError::QuorumFailed { .. }) => {
                        return true
                    }
                    Err(GetRecordError::Timeout { .. }) => return true,
                }
            }
        }
    })
    .await
    .expect("get-record query never resolved");

    assert!(outcome, "expected no record for an unpublished identity");
}

/// Drive `swarm` until its get-record query yields a found record.
async fn await_found_record(swarm: &mut DhtSwarm) -> Option<Record> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(record) = found_record(swarm.select_next_some().await) {
                return record;
            }
        }
    })
    .await
    .ok()
}

/// Extract the [`Record`] from a swarm event iff it is a successful get-record "found" progress.
fn found_record(event: SwarmEvent<kad::Event>) -> Option<Record> {
    match event {
        SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
            result: QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(peer_record))),
            ..
        }) => Some(peer_record.record),
        _ => None,
    }
}
