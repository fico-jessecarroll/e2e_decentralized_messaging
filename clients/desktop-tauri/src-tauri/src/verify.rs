//! Safety-number verification logic for the desktop‑tauri UI.
//!
//! The tests in `tests/safety_number_ui.rs` exercise a very small state machine
//! that tracks whether a user has verified a safety number and warns when the
//! underlying identity key changes.  The implementation below is intentionally
//! minimal – it only stores the expected safety‑number string and updates its
//! state based on user input.
//!
//! # API
//! * `VerificationState::new(expected: &str) -> VerificationState` – create a new
//!   unverified state with the given expected safety number.
//! * `verify_safety_number(&self, input: &str) -> VerificationState` – compare
//!   the supplied input against the stored value and return an updated state.
//!
//! The enum derives `PartialEq`, `Debug`, and `Clone` so it can be compared in
//! tests.

use std::fmt;

#[derive(Debug, Clone)]
impl PartialEq for VerificationState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (VerificationState::Unverified { .. }, VerificationState::Unverified { .. }) => true,
            (VerificationState::Verified { .. }, VerificationState::Verified { .. }) => true,
            (
                VerificationState::KeyChangedWarning { previous: p1, current: c1 },
                VerificationState::KeyChangedWarning { previous: p2, current: c2 },
            ) => p1 == p2 && c1 == c2,
            _ => false,
        }
    }
}
impl Eq for VerificationState {}

pub enum VerificationState {
    /// Initial state – the safety number has not yet been verified.
    Unverified { expected: String },
    /// The safety number matches and has been marked as verified.
    Verified { expected: String },
    /// The identity key changed after a prior verification; we keep both
    /// the previous (expected) and current numbers for display.
    KeyChangedWarning {
        previous: String,
        current: String,
    },
}

impl VerificationState {
    /// Create a new unverified state with the given expected safety number.
    pub fn new(expected: &str) -> Self {
        VerificationState::Unverified {
            expected: expected.to_string(),
        }
    }
}

/// Compare the supplied `input` against the stored safety number and return a
/// new verification state.
pub fn verify_safety_number(state: &VerificationState, input: &str) -> VerificationState {
    match state {
        VerificationState::Unverified { expected } => {
            if input == expected {
                VerificationState::Verified {
                    expected: input.to_string(),
                }
            } else {
                // Still unverified – keep the original expectation.
                VerificationState::Unverified {
                    expected: expected.clone(),
                }
            }
        }
        VerificationState::Verified { expected } => {
            if input == expected {
                // Already verified and still matches.
                VerificationState::Verified {
                    expected: input.to_string(),
                }
            } else {
                // Identity key changed – warn the user.
                VerificationState::KeyChangedWarning {
                    previous: expected.clone(),
                    current: input.to_string(),
                }
            }
        }
        VerificationState::KeyChangedWarning { .. } => {
            // Once we are in a warning state, keep it unchanged.
            state.clone()
        }
    }
}

// Implement Display for nicer debugging output (optional but helpful).
impl fmt::Display for VerificationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationState::Unverified { expected } => write!(f, "Unverified(expected={})", expected),
            VerificationState::Verified { expected } => write!(f, "Verified(expected={})", expected),
            VerificationState::KeyChangedWarning { previous, current } => {
                write!(f, "KeyChangedWarning(previous={}, current={})", previous, current)
            }
        }
    }
}
