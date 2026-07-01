//! Signed and one-time prekey generation/verification for X3DH/PQXDH session setup
//! (PLAN.md §3, spec/proto/v0/prekey.proto).

use std::collections::{HashMap, HashSet};
use std::fmt;

use libsignal_protocol::{
    GenericSignedPreKey, IdentityKey, IdentityKeyPair, KeyPair, PreKeyId, PreKeyRecord,
    SignedPreKeyId, SignedPreKeyRecord, Timestamp,
};
use rand::rngs::OsRng;
use rand::TryRngCore;

/// A prekey operation failed: a signature didn't verify, a key was malformed, or a one-time
/// prekey was already spent or never existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreKeyError {
    /// The signed prekey's signature does not verify against the claimed identity key — covers
    /// both tampered key material and a missing/empty signature.
    InvalidSignature,
    /// A key or signature was the wrong length or otherwise malformed.
    MalformedKey,
    /// No one-time prekey with this ID exists in the pool (and was never issued).
    OneTimePreKeyNotFound,
    /// This one-time prekey ID was already taken from the pool once; one-time prekeys are
    /// single-use (spec/proto/v0/prekey.proto `OneTimePreKey` doc comment).
    OneTimePreKeyAlreadyConsumed,
}

impl fmt::Display for PreKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => {
                write!(
                    f,
                    "signed prekey signature does not verify against the identity key"
                )
            }
            Self::MalformedKey => write!(f, "malformed or unrecognized key encoding"),
            Self::OneTimePreKeyNotFound => write!(f, "no such one-time prekey"),
            Self::OneTimePreKeyAlreadyConsumed => write!(f, "one-time prekey already consumed"),
        }
    }
}

impl std::error::Error for PreKeyError {}

/// Generate a new signed prekey, XEdDSA-signed by `identity`'s private key over the prekey's
/// public key bytes. `timestamp` is the caller's notion of "now" (explicit, not read from the
/// system clock here, so callers control rotation policy and tests stay deterministic).
pub fn generate_signed_pre_key(
    identity: &IdentityKeyPair,
    id: u32,
    timestamp: Timestamp,
) -> SignedPreKeyRecord {
    let mut rng = OsRng.unwrap_err();
    let key_pair = KeyPair::generate(&mut rng);
    let signature = identity
        .private_key()
        .calculate_signature(&key_pair.public_key.serialize(), &mut rng)
        .expect("XEdDSA signing with a freshly generated Curve25519 key cannot fail");
    SignedPreKeyRecord::new(SignedPreKeyId::from(id), timestamp, &key_pair, &signature)
}

/// Verify a signed prekey's signature against the claimed owner's identity key. Rejects
/// tampered public keys, tampered signatures, and missing/empty signatures alike.
pub fn verify_signed_pre_key(
    identity_key: &IdentityKey,
    signed_pre_key: &SignedPreKeyRecord,
) -> Result<(), PreKeyError> {
    let public_key = signed_pre_key
        .public_key()
        .map_err(|_| PreKeyError::MalformedKey)?;
    let signature = signed_pre_key
        .signature()
        .map_err(|_| PreKeyError::MalformedKey)?;

    if identity_key
        .public_key()
        .verify_signature(&public_key.serialize(), &signature)
    {
        Ok(())
    } else {
        Err(PreKeyError::InvalidSignature)
    }
}

/// Generate `count` one-time prekeys with sequential IDs starting at `start_id`.
pub fn generate_one_time_pre_keys(start_id: u32, count: u32) -> Vec<PreKeyRecord> {
    let mut rng = OsRng.unwrap_err();
    (0..count)
        .map(|offset| {
            let key_pair = KeyPair::generate(&mut rng);
            PreKeyRecord::new(PreKeyId::from(start_id + offset), &key_pair)
        })
        .collect()
}

/// A device's pool of unused one-time prekeys. Each prekey can be taken exactly once; a second
/// `take` of the same ID is rejected rather than handed out again (spec/proto/v0/prekey.proto
/// `OneTimePreKey` doc comment — one-time prekeys are consumed on first use).
#[derive(Debug, Default)]
pub struct OneTimePreKeyPool {
    available: HashMap<u32, PreKeyRecord>,
    consumed: HashSet<u32>,
}

impl OneTimePreKeyPool {
    /// Build a pool from freshly generated (or loaded) one-time prekey records.
    pub fn new(records: Vec<PreKeyRecord>) -> Result<Self, PreKeyError> {
        let mut available = HashMap::with_capacity(records.len());
        for record in records {
            let id: u32 = record.id().map_err(|_| PreKeyError::MalformedKey)?.into();
            available.insert(id, record);
        }
        Ok(Self {
            available,
            consumed: HashSet::new(),
        })
    }

    /// Number of one-time prekeys still available to be taken.
    pub fn remaining(&self) -> usize {
        self.available.len()
    }

    /// Take (and consume) the one-time prekey with the given ID. Returns an error if it was
    /// never in the pool, or was already taken.
    pub fn take(&mut self, id: u32) -> Result<PreKeyRecord, PreKeyError> {
        if let Some(record) = self.available.remove(&id) {
            self.consumed.insert(id);
            Ok(record)
        } else if self.consumed.contains(&id) {
            Err(PreKeyError::OneTimePreKeyAlreadyConsumed)
        } else {
            Err(PreKeyError::OneTimePreKeyNotFound)
        }
    }
}

/// A device's replenishable pool of unused one-time prekeys (PLAN.md Phase 4 — prekey
/// auto-replenishment).
///
/// Wraps the single-use semantics of [`OneTimePreKeyPool`] with:
///  - a configurable **low-watermark** that callers poll between message sends to decide when
///    to mint fresh prekeys, and
///  - an **auto-replenish** step that tops the pool back up to a target count.
///
/// Replenishment assigns IDs monotonically from `next_id + 1` so a pool that has already
/// handed out IDs `1..=N` will mint `N+1, N+2, …` on its next refill. This is the
/// invariant that guarantees [`Self::replenish_to_target`] never produces a duplicate ID —
/// even after arbitrary `take_one_time` calls and arbitrary prior refills.
#[derive(Debug)]
pub struct PreKeyPool {
    inner: OneTimePreKeyPool,
    /// The size the pool is filled to when first constructed. `capacity()` always returns this
    /// value (it is the *initial* capacity, not a hard upper bound — replenishment can grow
    /// the pool arbitrarily).
    capacity: usize,
    /// When `remaining() < low_watermark`, [`Self::below_watermark`] returns `true` and the
    /// caller should run [`Self::replenish_to_target`].
    low_watermark: usize,
    /// The next prekey ID that will be issued by [`Self::replenish_to_target`]. Always greater
    /// than every ID currently in the pool or ever handed out, so refill cannot collide.
    next_id: u32,
    /// IDs that have been taken from the pool (already issued to a remote). Tracked so a future
    /// refill cannot accidentally re-mint an ID that was already handed out (one-time prekeys
    /// are single-use).
    issued: HashSet<u32>,
}

impl PreKeyPool {
    /// The default low-watermark for a freshly created pool, in number of one-time prekeys
    /// remaining. Matches PLAN.md Phase 4 ("at least 10").
    pub const DEFAULT_LOW_WATERMARK: usize = 10;

    /// Build a new pool filled to `low_watermark` one-time prekeys (IDs `1..=low_watermark`).
    ///
    /// After construction `below_watermark()` returns `false` and `remaining()` equals the
    /// watermark — callers can immediately start handing out prekeys.
    pub fn with_low_watermark(low_watermark: usize) -> Self {
        let count = low_watermark.max(1);
        let records = generate_one_time_pre_keys(1, count as u32);
        let inner = OneTimePreKeyPool::new(records).expect("freshly generated records are valid");
        Self {
            inner,
            capacity: count,
            low_watermark: count,
            next_id: (count as u32) + 1,
            issued: HashSet::new(),
        }
    }

    /// The size the pool was initialised to. After replenishment the actual remaining count
    /// can exceed this; this method reports the original capacity for tests that want to
    /// reason about the fill ratio (`remaining() / capacity()`).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of one-time prekeys still available to be taken.
    pub fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    /// `true` when `remaining()` has dropped below the configured low-watermark. Callers
    /// should schedule a [`Self::replenish_to_target`] when this returns `true`.
    pub fn below_watermark(&self) -> bool {
        self.inner.remaining() < self.low_watermark
    }

    /// Take (consume) the next available one-time prekey. Returns `None` if the pool is
    /// empty — callers must either replenish first or fall back to the signed-prekey-only
    /// session-establishment path.
    pub fn take_one_time(&mut self) -> Option<PreKeyRecord> {
        // Pick the lowest-ID available record. ID order doesn't affect security but keeps the
        // pool deterministic for tests.
        let id = {
            let mut ids: Vec<u32> = self.inner.available.keys().copied().collect();
            ids.sort_unstable();
            ids.first().copied()?
        };
        let record = self.inner.take(id).expect("id is in available map");
        self.issued.insert(id);
        Some(record)
    }

    /// Return a snapshot of every one-time prekey ID currently in the pool (i.e. not yet
    /// handed out). Order is unspecified. Used by acceptance tests to assert that
    /// [`Self::replenish_to_target`] introduced no duplicate IDs.
    pub fn snapshot_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.inner.available.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Mint new one-time prekeys until `remaining() >= target`.
    ///
    /// IDs are assigned strictly above `next_id`, which is itself strictly above every ID
    /// already in the pool or ever issued by a previous [`Self::take_one_time`] /
    /// [`Self::replenish_to_target`] call — so this method can never mint a duplicate ID.
    ///
    /// `target` may be larger than [`Self::capacity`]; the pool grows accordingly. Returns
    /// an error only if libsignal itself fails to construct a fresh `PreKeyRecord` (which in
    /// practice never happens with the OS CSPRNG).
    pub fn replenish_to_target(&mut self, target: usize) -> Result<(), PreKeyError> {
        let needed = target.saturating_sub(self.inner.remaining());
        if needed == 0 {
            return Ok(());
        }
        let new_records = generate_one_time_pre_keys(self.next_id, needed as u32);
        // Track the new IDs in `issued` too — even though they haven't been handed out yet,
        // they're "reserved" by this pool, so a future reload-from-disk can't collide.
        for record in &new_records {
            let id: u32 = record.id().map_err(|_| PreKeyError::MalformedKey)?.into();
            self.issued.insert(id);
            self.next_id = self.next_id.saturating_add(1).max(id + 1);
        }
        // Append the new records to the inner pool. We do this by rebuilding the pool because
        // `OneTimePreKeyPool::new` is the only public way to bulk-insert records — and it
        // deduplicates by ID, which is exactly the invariant we want here.
        let mut all_records: Vec<PreKeyRecord> = self.inner.available.values().cloned().collect();
        all_records.extend(new_records);
        self.inner = OneTimePreKeyPool::new(all_records)?;
        Ok(())
    }
}

/// The subset of a published prekey bundle a sender must verify before establishing a session
/// (spec/proto/v0/prekey.proto `PreKeyBundle` — the wire-level message also carries device
/// address, bundle version, and expiry, which belong to the protocol/transport layer fetching it;
/// this is the crypto-verifiable core).
pub struct PreKeyBundle {
    pub identity_key: IdentityKey,
    pub signed_pre_key: SignedPreKeyRecord,
    pub one_time_pre_key: Option<PreKeyRecord>,
}

/// Verify a fetched prekey bundle's signed prekey against its claimed identity key. A sender
/// MUST call this before using any bundle fetched via an untrusted channel
/// (docs/threat-model.md §4.6) — a tampered public key, tampered signature, or missing signature
/// all fail closed here.
pub fn verify_pre_key_bundle(bundle: &PreKeyBundle) -> Result<(), PreKeyError> {
    verify_signed_pre_key(&bundle.identity_key, &bundle.signed_pre_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        Timestamp::from_epoch_millis(1_700_000_000_000)
    }

    #[test]
    fn generate_signed_pre_key_carries_the_requested_id() {
        let identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());

        let signed_pre_key = generate_signed_pre_key(&identity, 42, now());

        let id: u32 = signed_pre_key.id().expect("valid record").into();
        assert_eq!(id, 42);
    }

    #[test]
    fn generate_signed_pre_key_signature_verifies_against_owning_identity() {
        let identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());

        let signed_pre_key = generate_signed_pre_key(&identity, 1, now());

        assert_eq!(
            verify_signed_pre_key(identity.identity_key(), &signed_pre_key),
            Ok(())
        );
    }

    #[test]
    fn verify_signed_pre_key_rejects_signature_from_a_different_identity() {
        let identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let attacker = IdentityKeyPair::generate(&mut OsRng.unwrap_err());

        let signed_pre_key = generate_signed_pre_key(&identity, 1, now());

        assert_eq!(
            verify_signed_pre_key(attacker.identity_key(), &signed_pre_key),
            Err(PreKeyError::InvalidSignature)
        );
    }

    #[test]
    fn verify_signed_pre_key_rejects_a_tampered_public_key() {
        let identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let signed_pre_key = generate_signed_pre_key(&identity, 1, now());
        let signature = signed_pre_key.signature().expect("valid record");

        // Splice in an unrelated public key but keep the original signature, simulating a DHT
        // peer that tampers with the published bundle.
        let swapped_key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
        let tampered = SignedPreKeyRecord::new(
            SignedPreKeyId::from(1u32),
            now(),
            &swapped_key_pair,
            &signature,
        );

        assert_eq!(
            verify_signed_pre_key(identity.identity_key(), &tampered),
            Err(PreKeyError::InvalidSignature)
        );
    }

    #[test]
    fn verify_signed_pre_key_rejects_an_unsigned_prekey() {
        let identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
        let unsigned = SignedPreKeyRecord::new(SignedPreKeyId::from(1u32), now(), &key_pair, &[]);

        assert_eq!(
            verify_signed_pre_key(identity.identity_key(), &unsigned),
            Err(PreKeyError::InvalidSignature)
        );
    }

    #[test]
    fn verify_signed_pre_key_rejects_malformed_signature_bytes() {
        let identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
        let malformed = SignedPreKeyRecord::new(
            SignedPreKeyId::from(1u32),
            now(),
            &key_pair,
            &[0x01, 0x02, 0x03],
        );

        assert_eq!(
            verify_signed_pre_key(identity.identity_key(), &malformed),
            Err(PreKeyError::InvalidSignature)
        );
    }

    #[test]
    fn generate_one_time_pre_keys_produces_the_requested_count_with_sequential_ids() {
        let records = generate_one_time_pre_keys(10, 5);

        let ids: Vec<u32> = records
            .iter()
            .map(|r| r.id().expect("valid record").into())
            .collect();
        assert_eq!(ids, vec![10, 11, 12, 13, 14]);
    }

    #[test]
    fn generate_one_time_pre_keys_returns_empty_vec_for_zero_count() {
        let records = generate_one_time_pre_keys(0, 0);

        assert!(records.is_empty());
    }

    #[test]
    fn generate_one_time_pre_keys_produces_unique_key_material() {
        let records = generate_one_time_pre_keys(0, 2);

        let first = records[0].public_key().expect("valid record").serialize();
        let second = records[1].public_key().expect("valid record").serialize();
        assert_ne!(first, second);
    }

    #[test]
    fn one_time_pre_key_pool_take_returns_the_matching_record() {
        let records = generate_one_time_pre_keys(5, 3);
        let expected_key = records[1].public_key().expect("valid record").serialize();
        let mut pool = OneTimePreKeyPool::new(records).expect("valid records");

        let taken = pool.take(6).expect("present and unconsumed");

        assert_eq!(
            taken.public_key().expect("valid record").serialize(),
            expected_key
        );
    }

    #[test]
    fn one_time_pre_key_pool_take_consumes_the_prekey_reducing_remaining_count() {
        let records = generate_one_time_pre_keys(0, 3);
        let mut pool = OneTimePreKeyPool::new(records).expect("valid records");
        assert_eq!(pool.remaining(), 3);

        pool.take(0).expect("present and unconsumed");

        assert_eq!(pool.remaining(), 2);
    }

    #[test]
    fn one_time_pre_key_pool_take_rejects_a_second_take_of_the_same_id() {
        let records = generate_one_time_pre_keys(0, 1);
        let mut pool = OneTimePreKeyPool::new(records).expect("valid records");
        pool.take(0).expect("present and unconsumed");

        let second = pool.take(0);

        assert_eq!(
            second.unwrap_err(),
            PreKeyError::OneTimePreKeyAlreadyConsumed
        );
    }

    #[test]
    fn one_time_pre_key_pool_take_rejects_an_id_that_was_never_issued() {
        let mut pool =
            OneTimePreKeyPool::new(generate_one_time_pre_keys(0, 1)).expect("valid records");

        let result = pool.take(999);

        assert_eq!(result.unwrap_err(), PreKeyError::OneTimePreKeyNotFound);
    }

    #[test]
    fn one_time_pre_key_pool_new_is_empty_for_an_empty_batch() {
        let pool = OneTimePreKeyPool::new(Vec::new()).expect("valid records");

        assert_eq!(pool.remaining(), 0);
    }

    #[test]
    fn verify_pre_key_bundle_accepts_a_validly_signed_bundle() {
        let identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let signed_pre_key = generate_signed_pre_key(&identity, 1, now());
        let one_time_pre_key = generate_one_time_pre_keys(0, 1).remove(0);
        let bundle = PreKeyBundle {
            identity_key: *identity.identity_key(),
            signed_pre_key,
            one_time_pre_key: Some(one_time_pre_key),
        };

        assert_eq!(verify_pre_key_bundle(&bundle), Ok(()));
    }

    #[test]
    fn verify_pre_key_bundle_accepts_a_bundle_with_no_one_time_pre_key() {
        let identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let signed_pre_key = generate_signed_pre_key(&identity, 1, now());
        let bundle = PreKeyBundle {
            identity_key: *identity.identity_key(),
            signed_pre_key,
            one_time_pre_key: None,
        };

        assert_eq!(verify_pre_key_bundle(&bundle), Ok(()));
    }

    #[test]
    fn verify_pre_key_bundle_rejects_a_tampered_signed_pre_key() {
        let identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let signed_pre_key = generate_signed_pre_key(&identity, 1, now());
        let signature = signed_pre_key.signature().expect("valid record");
        let swapped_key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
        let tampered = SignedPreKeyRecord::new(
            SignedPreKeyId::from(1u32),
            now(),
            &swapped_key_pair,
            &signature,
        );
        let bundle = PreKeyBundle {
            identity_key: *identity.identity_key(),
            signed_pre_key: tampered,
            one_time_pre_key: None,
        };

        assert_eq!(
            verify_pre_key_bundle(&bundle),
            Err(PreKeyError::InvalidSignature)
        );
    }

    #[test]
    fn verify_pre_key_bundle_rejects_an_unsigned_signed_pre_key() {
        let identity = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
        let unsigned = SignedPreKeyRecord::new(SignedPreKeyId::from(1u32), now(), &key_pair, &[]);
        let bundle = PreKeyBundle {
            identity_key: *identity.identity_key(),
            signed_pre_key: unsigned,
            one_time_pre_key: None,
        };

        assert_eq!(
            verify_pre_key_bundle(&bundle),
            Err(PreKeyError::InvalidSignature)
        );
    }
}
