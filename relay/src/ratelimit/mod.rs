//! Per-identity rate limiting for relay first-contact requests.
//!
//! Each peer identity (e.g. its libp2p `PeerId` bytes, or any other opaque
//! identifier) gets a fixed-window request budget. A new request consumes one
//! token; when the budget for the current window is empty the request is
//! rejected with [`RateLimitError::Exceeded`].
//!
//! The window starts at the identity's first request and lasts `window`
//! seconds (default: 60). When `now` advances past the end of the window the
//! budget resets to its full `per_minute` capacity, regardless of how many
//! tokens remain — a partially-spent window does not carry leftover tokens
//! forward.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

/// Errors surfaced by [`RateLimiter::check`].
#[derive(Debug, PartialEq, Eq)]
pub enum RateLimitError {
    /// The identity has exhausted its token budget for the current window.
    Exceeded {
        /// Identity that was over-quota.
        identity: Vec<u8>,
        /// Tokens that would be needed to admit the request.
        needed: u32,
        /// Tokens remaining in the bucket at the moment of the call.
        available: u32,
        /// Time until the bucket refills enough to admit one more request.
        retry_after: Duration,
    },
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RateLimitError::Exceeded {
                needed,
                available,
                retry_after,
                ..
            } => write!(
                f,
                "rate limit exceeded: need {needed} tokens, have {available}, retry in {:?}",
                *retry_after
            ),
        }
    }
}

impl std::error::Error for RateLimitError {}

/// Per-identity fixed-window rate limiter.
///
/// `RateLimiter::per_identity(n)` configures a budget of `n` tokens refreshed
/// over a fixed 60-second window. The window starts at the first request for
/// each identity and resets to a full budget whenever the window elapses,
/// regardless of remaining tokens.
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum tokens per identity per window.
    capacity: u32,
    /// Window length over which `capacity` tokens are refreshed.
    window: Duration,
    /// Per-identity bucket state.
    buckets: HashMap<Vec<u8>, Bucket>,
}

#[derive(Debug, Clone)]
struct Bucket {
    /// Tokens left in the current window. Never exceeds `capacity`.
    tokens: u32,
    /// Virtual timestamp (in seconds since some origin) at which the window
    /// started. The bucket is "expired" once `now > start + window_secs` and
    /// no further requests have arrived.
    window_start_secs: u64,
}

impl RateLimiter {
    /// Build a limiter that allows `per_minute` requests per identity per 60s.
    pub fn per_identity(per_minute: u32) -> Self {
        Self::per_identity_in(per_minute, Duration::from_secs(60))
    }

    /// Build a limiter that allows `capacity` requests per identity per `window`.
    pub fn per_identity_in(capacity: u32, window: Duration) -> Self {
        Self {
            capacity: capacity.max(1),
            window,
            buckets: HashMap::new(),
        }
    }

    /// Returns the configured capacity.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Returns the configured window.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Record one request from `identity` at virtual time `now`.
    ///
    /// Returns `Ok(())` if the request fits in the current bucket, or
    /// [`RateLimitError::Exceeded`] if not.
    ///
    /// `now` is an absolute monotonic timestamp (e.g. seconds since process
    /// start); it does not need to come from a wall clock, but it MUST be
    /// monotonic non-decreasing for any given identity.
    pub fn check(&mut self, identity: &[u8], now: Duration) -> Result<(), RateLimitError> {
        let now_secs = now.as_secs();
        let window_secs = self.window.as_secs().max(1);

        // Look up (or initialise) the bucket for this identity.
        let bucket = self
            .buckets
            .entry(identity.to_vec())
            .or_insert_with(|| Bucket {
                tokens: self.capacity,
                window_start_secs: now_secs,
            });

        // Fixed window: once `now` has advanced past the window that started
        // at `window_start_secs`, reset to a fresh full bucket anchored at
        // `now` — regardless of how many tokens remain. Resetting only on
        // exhaustion would let a partially-spent bucket carry leftover tokens
        // across window boundaries, never refilling to full capacity.
        if now_secs.saturating_sub(bucket.window_start_secs) >= window_secs {
            bucket.tokens = self.capacity;
            bucket.window_start_secs = now_secs;
        }

        if bucket.tokens == 0 {
            // We can only land here when the window has not yet elapsed (the
            // reset above tops the bucket back up to capacity the moment it
            // does), so `elapsed < window_secs` holds and the wait until the
            // next full refill is exactly the remaining window.
            let elapsed = now_secs.saturating_sub(bucket.window_start_secs);
            let retry_after = Duration::from_secs(window_secs - elapsed);
            return Err(RateLimitError::Exceeded {
                identity: identity.to_vec(),
                needed: 1,
                available: 0,
                retry_after,
            });
        }

        bucket.tokens -= 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let l = RateLimiter::per_identity(0);
        assert_eq!(l.capacity(), 1);
    }

    #[test]
    fn independent_identities_do_not_share_budgets() {
        let mut l = RateLimiter::per_identity(1);
        l.check(b"alice", Duration::from_secs(0)).unwrap();
        l.check(b"bob", Duration::from_secs(0)).unwrap();
        assert!(l.check(b"alice", Duration::from_secs(1)).is_err());
        assert!(l.check(b"bob", Duration::from_secs(1)).is_err());
    }

    #[test]
    fn partial_use_refills_to_full_capacity_after_window() {
        // Regression guard: a partially-spent bucket must reset to full
        // capacity once the window elapses, not carry leftover tokens forward.
        let mut l = RateLimiter::per_identity_in(5, Duration::from_secs(60));
        let id = b"carol";

        // Spend only 3 of 5 tokens within the first window.
        for s in 0..3 {
            l.check(id, Duration::from_secs(s))
                .unwrap_or_else(|e| panic!("pre-window request {s} must succeed, got {e:?}"));
        }

        // Advance well past the window end. The full 5-token budget must be
        // available again — not 2 (the leftover).
        for i in 0..5 {
            l.check(id, Duration::from_secs(70 + i))
                .unwrap_or_else(|e| panic!("post-window request {i} must succeed, got {e:?}"));
        }
        // A 6th request within the new window must now be denied.
        assert!(
            l.check(id, Duration::from_secs(76)).is_err(),
            "post-window budget must be exactly capacity, not carried over"
        );
    }
}
