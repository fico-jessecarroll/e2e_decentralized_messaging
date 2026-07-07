use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Errors returned by the blind store-and-forward.
#[derive(Debug, PartialEq)]
pub enum StoreError {
    /// The requested envelope has expired and was purged.
    Expired,
    /// No envelope found for the recipient.
    NotFound,
}

/// A blind in-memory store that holds ciphertext envelopes with TTL.
pub struct RelayStore {
    inner: Mutex<HashMap<String, (Vec<u8>, Instant)>>,
}

impl RelayStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Store an envelope for the given recipient with a TTL.
    pub fn store(&self, recipient_id: &str, envelope: Vec<u8>, ttl: Duration) -> Result<(), ()> {
        let expiry = Instant::now() + ttl;
        let mut map = self.inner.lock().unwrap();
        map.insert(recipient_id.to_string(), (envelope, expiry));
        Ok(())
    }

    /// Pick up the envelope for a recipient if it exists and is not expired.
    pub fn pickup(&self, recipient_id: &str) -> Result<Vec<u8>, StoreError> {
        let mut map = self.inner.lock().unwrap();
        match map.get(recipient_id) {
            None => Err(StoreError::NotFound),
            Some((_, expiry)) if Instant::now() > *expiry => {
                // expired, remove
                map.remove(recipient_id);
                Err(StoreError::Expired)
            }
            Some((envelope, _)) => {
                let data = envelope.clone();
                map.remove(recipient_id);
                Ok(data)
            }
        }
    }

    /// Purge the stored envelope for a recipient regardless of TTL.
    pub fn purge(&self, recipient_id: &str) -> Result<(), ()> {
        let mut map = self.inner.lock().unwrap();
        map.remove(recipient_id);
        Ok(())
    }

    /// Return the number of stored envelopes (including expired ones that haven't been cleaned yet).
    pub fn count(&self) -> usize {
        let map = self.inner.lock().unwrap();
        map.len()
    }

    /// Introspect whether a public method is exposed.
    pub fn has_method(name: &str) -> bool {
        match name {
            "store" | "pickup" | "purge" | "count" => true,
            _ => false,
        }
    }
}
