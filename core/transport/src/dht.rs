//! Kademlia DHT publication and lookup of prekey bundles (PLAN.md §3, Phase 3).
//!
//! A device publishes its [`PreKeyBundle`](crypto::prekey::PreKeyBundle) to the DHT under a key
//! derived from its identity key; a peer wanting to start a session looks the bundle up by the
//! same identity key. The DHT is treated as fully untrusted (`docs/threat-model.md` §4.6): any
//! node storing or relaying a record may tamper with it, so every fetched record is validated
//! before use and the validation **fails closed**:
//!
//! 1. **Identity binding** — the record must be stored under exactly the identity key it carries,
//!    so a malicious node cannot answer a lookup for Alice with Bob's (validly signed) bundle.
//! 2. **Signature** — the signed prekey must verify against that identity key
//!    ([`crypto::prekey::verify_pre_key_bundle`]).
//!
//! The wire format is a length-prefixed concatenation of the libsignal-serialized components; the
//! crypto itself is entirely libsignal's — this module only frames and routes it.

use crypto::prekey::{verify_pre_key_bundle, PreKeyBundle, PreKeyError};
use libp2p::{
    identity::Keypair,
    kad::{
        self,
        store::{self, MemoryStore},
        QueryId, Quorum, Record, RecordKey,
    },
    noise,
    swarm::Swarm,
    tcp, yamux, PeerId, SwarmBuilder,
};
use libsignal_protocol::{GenericSignedPreKey, IdentityKey, PreKeyRecord, SignedPreKeyRecord};

/// A prekey bundle fetched from the DHT could not be decoded or did not validate. Returned by
/// [`decode_and_verify_bundle`]; callers must treat any variant as "no usable bundle".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtPreKeyError {
    /// The record bytes are not a well-formed encoded bundle (truncated, trailing garbage, or a
    /// component libsignal refused to deserialize).
    MalformedRecord,
    /// The record's identity key does not match the DHT key it was stored under — a node tried to
    /// answer a lookup with a bundle belonging to a different identity.
    IdentityKeyMismatch,
    /// The signed prekey's signature does not verify against the bundle's identity key.
    InvalidBundle(PreKeyError),
}

impl std::fmt::Display for DhtPreKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedRecord => write!(f, "malformed DHT prekey-bundle record"),
            Self::IdentityKeyMismatch => {
                write!(f, "record identity key does not match its DHT key")
            }
            Self::InvalidBundle(e) => write!(f, "prekey bundle failed verification: {e}"),
        }
    }
}

impl std::error::Error for DhtPreKeyError {}

/// Derive the DHT record key under which `identity_key`'s bundle is published and looked up.
///
/// The key is the serialized identity key itself, which binds the storage location to a single
/// identity: a lookup result can be checked against the queried key (see [`decode_and_verify_bundle`]).
pub fn record_key_for_identity(identity_key: &IdentityKey) -> RecordKey {
    RecordKey::new(&identity_key.serialize())
}

/// Encode a prekey bundle into DHT record bytes.
///
/// Returns [`DhtPreKeyError::MalformedRecord`] only if libsignal fails to serialize a component,
/// which does not happen for bundles produced by `crypto`'s generators.
pub fn encode_bundle(bundle: &PreKeyBundle) -> Result<Vec<u8>, DhtPreKeyError> {
    let mut out = Vec::new();
    put_field(&mut out, &bundle.identity_key.serialize());

    let signed = bundle
        .signed_pre_key
        .serialize()
        .map_err(|_| DhtPreKeyError::MalformedRecord)?;
    put_field(&mut out, &signed);

    match &bundle.one_time_pre_key {
        None => out.push(0),
        Some(one_time) => {
            out.push(1);
            let one_time = one_time
                .serialize()
                .map_err(|_| DhtPreKeyError::MalformedRecord)?;
            put_field(&mut out, &one_time);
        }
    }
    Ok(out)
}

/// Decode and fully validate a DHT record `value` retrieved under `key`.
///
/// Fails closed: the record must decode, its identity key must match `key`, and its signed prekey
/// must verify. Only a bundle that passes all three is returned.
pub fn decode_and_verify_bundle(
    key: &RecordKey,
    value: &[u8],
) -> Result<PreKeyBundle, DhtPreKeyError> {
    let bundle = decode_bundle(value)?;

    // Identity binding: the record must live under exactly the identity key it claims.
    if key.as_ref() != bundle.identity_key.serialize().as_ref() {
        return Err(DhtPreKeyError::IdentityKeyMismatch);
    }

    verify_pre_key_bundle(&bundle).map_err(DhtPreKeyError::InvalidBundle)?;
    Ok(bundle)
}

fn decode_bundle(value: &[u8]) -> Result<PreKeyBundle, DhtPreKeyError> {
    let mut cursor = value;

    let identity_key = IdentityKey::decode(take_field(&mut cursor)?)
        .map_err(|_| DhtPreKeyError::MalformedRecord)?;
    let signed_pre_key = SignedPreKeyRecord::deserialize(take_field(&mut cursor)?)
        .map_err(|_| DhtPreKeyError::MalformedRecord)?;

    let (&flag, rest) = cursor
        .split_first()
        .ok_or(DhtPreKeyError::MalformedRecord)?;
    cursor = rest;
    let one_time_pre_key = match flag {
        0 => None,
        1 => Some(
            PreKeyRecord::deserialize(take_field(&mut cursor)?)
                .map_err(|_| DhtPreKeyError::MalformedRecord)?,
        ),
        _ => return Err(DhtPreKeyError::MalformedRecord),
    };

    if !cursor.is_empty() {
        return Err(DhtPreKeyError::MalformedRecord);
    }

    Ok(PreKeyBundle {
        identity_key,
        signed_pre_key,
        one_time_pre_key,
    })
}

fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take_field<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], DhtPreKeyError> {
    if cursor.len() < 4 {
        return Err(DhtPreKeyError::MalformedRecord);
    }
    let (len_bytes, rest) = cursor.split_at(4);
    let len = u32::from_be_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
    if rest.len() < len {
        return Err(DhtPreKeyError::MalformedRecord);
    }
    let (field, rest) = rest.split_at(len);
    *cursor = rest;
    Ok(field)
}

/// Build the Kademlia behaviour for `peer_id` in **server mode** with an in-memory record store.
///
/// Server mode is required for a node to answer lookups and store published records; clients that
/// only read may switch to client mode, but every node in this network both publishes its own
/// bundle and serves others', so server mode is the secure default here.
pub fn build_dht_behaviour(peer_id: PeerId) -> kad::Behaviour<MemoryStore> {
    let mut behaviour = kad::Behaviour::new(peer_id, MemoryStore::new(peer_id));
    behaviour.set_mode(Some(kad::Mode::Server));
    behaviour
}

/// Build a [`Swarm`] running the prekey-bundle DHT behaviour over the same TCP + Noise + Yamux
/// stack as the rest of `core/transport`.
pub fn build_dht_swarm(
    keypair: Keypair,
) -> Result<Swarm<kad::Behaviour<MemoryStore>>, Box<dyn std::error::Error + Send + Sync>> {
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| build_dht_behaviour(key.public().to_peer_id()))?
        .build();
    Ok(swarm)
}

/// Publish `bundle` to the DHT under its owner's identity key.
///
/// Returns the [`QueryId`] of the resulting `PUT_VALUE` query; progress arrives as
/// [`kad::Event::OutboundQueryProgressed`] on the swarm. The record is also stored in the local
/// node's store immediately, so a subsequent local lookup succeeds even before replication.
pub fn publish_pre_key_bundle(
    behaviour: &mut kad::Behaviour<MemoryStore>,
    bundle: &PreKeyBundle,
) -> Result<QueryId, PublishError> {
    let record = Record::new(
        record_key_for_identity(&bundle.identity_key),
        encode_bundle(bundle)?,
    );
    behaviour
        .put_record(record, Quorum::One)
        .map_err(PublishError::Store)
}

/// Issue a DHT lookup for the prekey bundle published under `identity_key`.
///
/// Returns the [`QueryId`]; the result arrives as a [`kad::Event::OutboundQueryProgressed`]
/// carrying a [`kad::QueryResult::GetRecord`]. Pass the returned record through
/// [`decode_and_verify_bundle`] before trusting it.
pub fn lookup_pre_key_bundle(
    behaviour: &mut kad::Behaviour<MemoryStore>,
    identity_key: &IdentityKey,
) -> QueryId {
    behaviour.get_record(record_key_for_identity(identity_key))
}

/// Publishing a bundle to the DHT failed before the query could even start.
#[derive(Debug)]
pub enum PublishError {
    /// The bundle could not be encoded into a record (see [`DhtPreKeyError`]).
    Encode(DhtPreKeyError),
    /// The local record store rejected the record (e.g. it exceeds the store's size limits).
    Store(store::Error),
}

impl From<DhtPreKeyError> for PublishError {
    fn from(e: DhtPreKeyError) -> Self {
        Self::Encode(e)
    }
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "could not encode bundle: {e}"),
            Self::Store(e) => write!(f, "local record store rejected the record: {e}"),
        }
    }
}

impl std::error::Error for PublishError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::generate_identity_key_pair;
    use crypto::prekey::{generate_one_time_pre_keys, generate_signed_pre_key};
    use libsignal_protocol::{IdentityKeyPair, KeyPair, SignedPreKeyId, Timestamp};
    use rand::rngs::OsRng;
    use rand::TryRngCore;

    fn now() -> Timestamp {
        Timestamp::from_epoch_millis(1_700_000_000_000)
    }

    fn bundle_for(identity: &IdentityKeyPair, with_one_time: bool) -> PreKeyBundle {
        PreKeyBundle {
            identity_key: *identity.identity_key(),
            signed_pre_key: generate_signed_pre_key(identity, 1, now()),
            one_time_pre_key: with_one_time.then(|| generate_one_time_pre_keys(0, 1).remove(0)),
        }
    }

    #[test]
    fn encode_decode_round_trips_a_bundle_with_a_one_time_prekey() {
        let identity = generate_identity_key_pair();
        let bundle = bundle_for(&identity, true);
        let key = record_key_for_identity(&bundle.identity_key);

        let encoded = encode_bundle(&bundle).expect("encode");
        let decoded = decode_and_verify_bundle(&key, &encoded).expect("decode+verify");

        assert_eq!(
            decoded.identity_key.serialize(),
            bundle.identity_key.serialize()
        );
        assert!(decoded.one_time_pre_key.is_some());
    }

    #[test]
    fn encode_decode_round_trips_a_bundle_without_a_one_time_prekey() {
        let identity = generate_identity_key_pair();
        let bundle = bundle_for(&identity, false);
        let key = record_key_for_identity(&bundle.identity_key);

        let decoded =
            decode_and_verify_bundle(&key, &encode_bundle(&bundle).expect("encode")).expect("ok");

        assert!(decoded.one_time_pre_key.is_none());
    }

    #[test]
    fn record_key_is_the_serialized_identity_key() {
        let identity = generate_identity_key_pair();
        let key = record_key_for_identity(identity.identity_key());
        assert_eq!(key.as_ref(), identity.identity_key().serialize().as_ref());
    }

    #[test]
    fn decode_and_verify_rejects_a_record_stored_under_a_different_identity() {
        let alice = generate_identity_key_pair();
        let bob = generate_identity_key_pair();
        let bob_bundle = bundle_for(&bob, false);

        // A malicious node returns Bob's (validly signed) bundle in answer to a lookup for Alice.
        let alice_key = record_key_for_identity(alice.identity_key());
        let result = decode_and_verify_bundle(&alice_key, &encode_bundle(&bob_bundle).unwrap());

        assert!(matches!(result, Err(DhtPreKeyError::IdentityKeyMismatch)));
    }

    #[test]
    fn decode_and_verify_rejects_a_tampered_signed_prekey() {
        let identity = generate_identity_key_pair();
        let signed = generate_signed_pre_key(&identity, 1, now());
        let signature = signed.signature().expect("sig");
        // Splice a different public key under the original signature.
        let swapped = KeyPair::generate(&mut OsRng.unwrap_err());
        let tampered =
            SignedPreKeyRecord::new(SignedPreKeyId::from(1u32), now(), &swapped, &signature);
        let bundle = PreKeyBundle {
            identity_key: *identity.identity_key(),
            signed_pre_key: tampered,
            one_time_pre_key: None,
        };
        let key = record_key_for_identity(identity.identity_key());

        let result = decode_and_verify_bundle(&key, &encode_bundle(&bundle).unwrap());

        assert!(matches!(
            result,
            Err(DhtPreKeyError::InvalidBundle(PreKeyError::InvalidSignature))
        ));
    }

    #[test]
    fn decode_and_verify_rejects_truncated_record_bytes() {
        let identity = generate_identity_key_pair();
        let bundle = bundle_for(&identity, false);
        let key = record_key_for_identity(&bundle.identity_key);
        let encoded = encode_bundle(&bundle).unwrap();

        let result = decode_and_verify_bundle(&key, &encoded[..encoded.len() / 2]);

        assert!(matches!(result, Err(DhtPreKeyError::MalformedRecord)));
    }

    #[test]
    fn decode_and_verify_rejects_empty_record_bytes() {
        let identity = generate_identity_key_pair();
        let key = record_key_for_identity(identity.identity_key());

        assert!(matches!(
            decode_and_verify_bundle(&key, &[]),
            Err(DhtPreKeyError::MalformedRecord)
        ));
    }

    #[test]
    fn decode_and_verify_rejects_trailing_garbage() {
        let identity = generate_identity_key_pair();
        let bundle = bundle_for(&identity, false);
        let key = record_key_for_identity(&bundle.identity_key);
        let mut encoded = encode_bundle(&bundle).unwrap();
        encoded.push(0xff);

        assert!(matches!(
            decode_and_verify_bundle(&key, &encoded),
            Err(DhtPreKeyError::MalformedRecord)
        ));
    }

    #[test]
    fn decode_and_verify_rejects_an_invalid_one_time_prekey_flag() {
        let identity = generate_identity_key_pair();
        let bundle = bundle_for(&identity, false);
        let key = record_key_for_identity(&bundle.identity_key);
        let mut encoded = encode_bundle(&bundle).unwrap();
        // Last byte is the one-time-prekey flag (0); flip it to an undefined value.
        *encoded.last_mut().unwrap() = 7;

        assert!(matches!(
            decode_and_verify_bundle(&key, &encoded),
            Err(DhtPreKeyError::MalformedRecord)
        ));
    }

    #[test]
    fn build_dht_swarm_uses_the_identity_keypairs_peer_id() {
        let keypair = Keypair::generate_ed25519();
        let expected = keypair.public().to_peer_id();
        let swarm = build_dht_swarm(keypair).expect("swarm builds");
        assert_eq!(*swarm.local_peer_id(), expected);
    }
}
