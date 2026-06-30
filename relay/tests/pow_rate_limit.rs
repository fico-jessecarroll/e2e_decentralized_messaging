//! PoW first-contact gate + per-identity rate limiting on the relay.
//!
//! Anchors PLAN.md Phase 4 acceptance criteria for relay hardening:
//!  - First contact requires a valid proof-of-work challenge response
//!  - Invalid / missing PoW is rejected before any session work
//!  - Per-identity rate limiting caps request rate; excess requests are denied

use relay::{
    pow::{solve, verify, Challenge, PowError},
    ratelimit::{RateLimitError, RateLimiter},
};
use std::time::Duration;

#[test]
fn valid_pow_solution_is_accepted() {
    let challenge = Challenge::new(b"first-contact", /* difficulty = */ 20);
    let solution = solve(&challenge).expect("solver runs");
    assert!(
        verify(&challenge, &solution).is_ok(),
        "freshly-solved challenge must verify"
    );
}

#[test]
fn invalid_pow_solution_is_rejected_with_defined_error() {
    let challenge = Challenge::new(b"first-contact", 20);
    let bogus = vec![0xFFu8; 32];

    let res = verify(&challenge, &bogus);
    assert!(
        matches!(res, Err(PowError::Invalid { .. })),
        "bogus PoW must surface PowError::Invalid, got {res:?}"
    );
}

#[test]
fn rate_limiter_caps_per_identity_request_rate() {
    let mut limiter = RateLimiter::per_identity(/* per_minute = */ 5);
    let id = b"alice-identity-bytes";

    // 5 requests within the window must succeed.
    for i in 0..5 {
        limiter
            .check(id, /* now */ Duration::from_secs(i))
            .unwrap_or_else(|e| panic!("request {i} must succeed, got {e:?}"));
    }

    // 6th within the same window must be denied.
    let res = limiter.check(id, Duration::from_secs(5));
    assert!(
        matches!(res, Err(RateLimitError::Exceeded { .. })),
        "6th request in the window must surface RateLimitError::Exceeded, got {res:?}"
    );
}

#[test]
fn rate_limit_window_resets_after_elapsed_time() {
    let mut limiter = RateLimiter::per_identity(5);
    let id = b"bob-identity-bytes";

    // Burn the budget, then advance past the window.
    for i in 0..5 {
        limiter.check(id, Duration::from_secs(i)).unwrap();
    }
    assert!(limiter.check(id, Duration::from_secs(5)).is_err());

    // After the window elapses, requests must be accepted again.
    limiter
        .check(id, Duration::from_secs(120))
        .expect("post-window request must succeed");
}
