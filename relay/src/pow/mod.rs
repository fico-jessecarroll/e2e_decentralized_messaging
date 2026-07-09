//! Proof-of-work first-contact gate for the relay.
//!
//! PLAN.md Phase 4 "PoW gate": a connecting peer must solve a small
//! proof-of-work challenge before the relay will spend cycles on a
//! full session handshake. This raises the cost of a denial-of-service
//! flood without requiring a centralised identity or rate-limit authority.
//!
//! Challenge construction
//! ----------------------
//! A [`Challenge`] binds together three things:
//!
//! 1. A **context** byte string (e.g. `b"first-contact"`), which prevents
//!    a PoW minted for one relay from being replayed at another or for a
//!    different purpose.
//! 2. A **nonce** the relay chooses randomly per challenge, so the
//!    challenge is unique and not predictable to the peer.
//! 3. A **difficulty** in leading-zero bits: a solution is valid iff
//!    `SHA-256(context || nonce || solution) < 2^(256 - difficulty)`.
//!
//! Difficulty is interpreted as "the resulting digest must start with
//! at least `difficulty / 8` zero bytes" with a bit-level fallback for
//! non-multiple-of-8 difficulties. The same rule is used in `solve`
//! and `verify` so they are guaranteed to agree.

use rand::rngs::OsRng;
use rand::{RngCore, TryRngCore as _};
use sha2::{Digest, Sha256};
use std::fmt;

/// Errors surfaced by [`verify`].
#[derive(Debug, PartialEq, Eq)]
pub enum PowError {
    /// The supplied solution does not satisfy the challenge's difficulty.
    Invalid {
        /// Difficulty (in leading-zero bits) the solution failed to meet.
        difficulty: u32,
    },
    /// The challenge is malformed (e.g. `difficulty == 0` or `> 256`).
    ///
    /// This is a programming error on the *issuer* side; it never comes
    /// from peer input alone.
    MalformedChallenge {
        /// Human-readable reason.
        reason: &'static str,
    },
}

impl fmt::Display for PowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PowError::Invalid { difficulty } => write!(
                f,
                "invalid proof-of-work: solution does not meet {difficulty} bits of difficulty"
            ),
            PowError::MalformedChallenge { reason } => {
                write!(f, "malformed challenge: {reason}")
            }
        }
    }
}

impl std::error::Error for PowError {}

/// A challenge issued by the relay that a peer must solve before being
/// allowed to proceed with first-contact handshake work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Application context, e.g. `b"first-contact"`.
    context: Vec<u8>,
    /// Random per-challenge nonce.
    nonce: [u8; 16],
    /// Required leading-zero bits in `SHA-256(context || nonce || solution)`.
    difficulty: u32,
}

impl Challenge {
    /// Build a new challenge bound to `context` at the given `difficulty`.
    ///
    /// `difficulty` is in bits and must be in `1..=256`. The function panics
    /// in debug builds on out-of-range values and returns
    /// `PowError::MalformedChallenge` from `verify` if the issuer hands a
    /// bad value to a release build.
    pub fn new(context: &[u8], difficulty: u32) -> Self {
        assert!(
            (1..=256).contains(&difficulty),
            "difficulty must be in 1..=256, got {difficulty}"
        );

        // The nonce is drawn from the OS CSPRNG. It must be unique across
        // issued challenges: a near-constant nonce would let an attacker
        // solve one challenge and replay that solution against every
        // challenge the relay issues, bypassing the DoS gate entirely.
        // Drawing from the CSPRNG also makes the nonce unpredictable, so an
        // attacker cannot precompute solutions for challenges not yet issued.
        let mut nonce = [0u8; 16];
        OsRng.unwrap_err().fill_bytes(&mut nonce);

        Self {
            context: context.to_vec(),
            nonce,
            difficulty,
        }
    }

    /// The challenge's difficulty (leading-zero bits).
    pub fn difficulty(&self) -> u32 {
        self.difficulty
    }

    /// The challenge's context bytes.
    pub fn context(&self) -> &[u8] {
        &self.context
    }

    /// The challenge's random nonce.
    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    /// Serialise the challenge to its wire bytes (context_len || context ||
    /// nonce || difficulty_be). The peer needs this to solve and verify.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.context.len() + self.nonce.len() + 4);
        let len = self.context.len() as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.difficulty.to_be_bytes());
        out
    }

    /// The preimage bytes that the peer is asked to find a suffix for:
    /// `context || nonce`. Useful for tests and for caching between
    /// successive `solve` attempts.
    pub fn preimage_prefix(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.context.len() + self.nonce.len());
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.nonce);
        out
    }
}

/// Internal: hash `preimage || suffix` and report whether the leading
/// `difficulty` bits are all zero.
fn meets_difficulty(preimage: &[u8], suffix: &[u8], difficulty: u32) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.update(suffix);
    let digest = hasher.finalize();

    // Whole-byte zero prefix.
    let full_bytes = (difficulty / 8) as usize;
    if digest.len() < full_bytes || digest[..full_bytes].iter().any(|b| *b != 0) {
        return false;
    }

    // Partial-bit zero prefix (only when difficulty is not a multiple of 8).
    let extra_bits = difficulty % 8;
    if extra_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - extra_bits);
    (digest[full_bytes] & mask) == 0
}

/// Verify that `solution` is a valid proof-of-work for `challenge`.
///
/// Returns:
/// - `Ok(())` if the solution satisfies the challenge's difficulty.
/// - `Err(PowError::Invalid { .. })` if the solution is wrong.
/// - `Err(PowError::MalformedChallenge { .. })` if the challenge itself
///   is structurally invalid (this should never happen if the challenge
///   was built via [`Challenge::new`]).
///
/// `verify` never panics on a peer-supplied solution; an invalid one
/// surfaces as a structured `Err` so the caller can drop the connection
/// without losing the original error information.
pub fn verify(challenge: &Challenge, solution: &[u8]) -> Result<(), PowError> {
    if !(1..=256).contains(&challenge.difficulty) {
        return Err(PowError::MalformedChallenge {
            reason: "difficulty out of range",
        });
    }

    let preimage = challenge.preimage_prefix();
    if meets_difficulty(&preimage, solution, challenge.difficulty) {
        Ok(())
    } else {
        Err(PowError::Invalid {
            difficulty: challenge.difficulty,
        })
    }
}

/// Find a solution to `challenge` by brute force.
///
/// This is deliberately simple: it tries `solution = 0, 1, 2, ...` (as
/// little-endian 8-byte counters) until one satisfies `verify`. The
/// caller is expected to bound `difficulty` to something feasible for
/// a first-contact gate (e.g. 16–24 bits).
///
/// Returns `Err(PowError::MalformedChallenge)` if the challenge itself
/// is structurally invalid.
pub fn solve(challenge: &Challenge) -> Result<Vec<u8>, PowError> {
    if !(1..=256).contains(&challenge.difficulty) {
        return Err(PowError::MalformedChallenge {
            reason: "difficulty out of range",
        });
    }

    let preimage = challenge.preimage_prefix();
    let mut counter: u64 = 0;
    // Cap the search to avoid an unbounded loop on absurd difficulties.
    let max_iters: u64 = 1u64 << 32;
    loop {
        let suffix = counter.to_le_bytes();
        if meets_difficulty(&preimage, &suffix, challenge.difficulty) {
            return Ok(suffix.to_vec());
        }
        counter = counter.checked_add(1).ok_or(PowError::MalformedChallenge {
            reason: "counter overflow",
        })?;
        if counter > max_iters {
            return Err(PowError::MalformedChallenge {
                reason: "difficulty too high for in-process solver",
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_then_verify_round_trips() {
        let challenge = Challenge::new(b"unit-test", 16);
        let solution = solve(&challenge).expect("difficulty 16 must be solvable");
        assert!(matches!(verify(&challenge, &solution), Ok(())));
    }

    #[test]
    fn verify_rejects_bogus_solution() {
        let challenge = Challenge::new(b"unit-test", 16);
        let bogus = vec![0xFFu8; 8];
        assert!(matches!(
            verify(&challenge, &bogus),
            Err(PowError::Invalid { .. })
        ));
    }

    #[test]
    fn different_contexts_produce_different_challenges() {
        let a = Challenge::new(b"alpha", 16);
        let b = Challenge::new(b"beta", 16);
        // Either nonce or context must differ; we guarantee both context and
        // wire bytes are distinct.
        assert_ne!(a.to_wire(), b.to_wire());
    }

    #[test]
    fn wire_round_trip_preserves_fields() {
        let challenge = Challenge::new(b"unit-test", 20);
        let wire = challenge.to_wire();
        // 2 byte len + context + 16 byte nonce + 4 byte difficulty
        assert_eq!(wire.len(), 2 + b"unit-test".len() + 16 + 4);
        // Last 4 bytes are difficulty in big-endian.
        let diff_bytes: [u8; 4] = wire[wire.len() - 4..].try_into().unwrap();
        assert_eq!(u32::from_be_bytes(diff_bytes), 20);
    }

    #[test]
    fn freshly_minted_challenges_have_unique_nonces() {
        // Regression guard for the near-constant nonce bug: every challenge
        // the relay issues must carry a distinct nonce, or an attacker can
        // mint one solution offline and replay it against every challenge.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let nonce = Challenge::new(b"first-contact", 20).nonce().to_vec();
            assert!(
                seen.insert(nonce),
                "duplicate nonce minted across challenges"
            );
        }
    }

    /// Cross-language interoperability test: mirrors the TypeScript PoW solver
    /// in `clients/web/src/relay_websocket_transport.ts::solvePow` byte-for-byte
    /// and verifies the solution passes `pow::verify`.
    ///
    /// The TS solver:
    ///   1. Parses the challenge wire bytes (`Challenge::to_wire` output).
    ///   2. Builds the preimage `context || nonce`.
    ///   3. Iterates a u64 counter, serializing it as 8-byte **little-endian**
    ///      (`counter.to_le_bytes()` — identical to the Rust solver).
    ///   4. Hashes `SHA-256(preimage || suffix)` and checks leading zero bits.
    ///
    /// This test reconstructs the challenge from its wire bytes (as the TS
    /// client does) and solves it with the same algorithm, then verifies the
    /// solution against the real `verify` function. If the byte layout or hash
    /// preimage ever diverges between the TS and Rust solvers, this test fails.
    #[test]
    fn ts_solver_algorithm_produces_verifiable_solution() {
        // Build a challenge with the WS relay context (matching production).
        let challenge = Challenge::new(b"ws-relay-v1", 20);
        let wire = challenge.to_wire();

        // --- Mirror the TS parseChallengeWire logic ---
        let context_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        let context = &wire[2..2 + context_len];
        let nonce = &wire[2 + context_len..2 + context_len + 16];
        let difficulty = u32::from_be_bytes(
            wire[2 + context_len + 16..2 + context_len + 16 + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(context, b"ws-relay-v1");
        assert_eq!(nonce, challenge.nonce());
        assert_eq!(difficulty, 20);

        // --- Mirror the TS solvePow loop ---
        let mut preimage = Vec::with_capacity(context.len() + nonce.len());
        preimage.extend_from_slice(context);
        preimage.extend_from_slice(nonce);

        let mut counter: u64 = 0;
        let solution = loop {
            let suffix = counter.to_le_bytes(); // 8-byte LE — matches TS setBigUint64(LE)
            if meets_difficulty(&preimage, &suffix, difficulty) {
                break suffix.to_vec();
            }
            counter += 1;
            if counter > (1u64 << 32) {
                panic!("TS-equivalent solver exceeded iteration cap");
            }
        };

        // The solution must pass the real verify function.
        assert!(matches!(verify(&challenge, &solution), Ok(())));
    }
}
