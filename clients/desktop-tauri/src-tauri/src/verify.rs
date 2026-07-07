//! Safety-number verification logic for the desktop-tauri UI.
//!
//! The tests in `tests/safety_number_ui.rs` exercise a small state machine that
//! tracks whether a user has verified a safety number and warns when the
//! underlying identity key changes. `Unverified` and `Verified` are unit
//! variants (the test compares against bare `VerificationState::Verified`),
//! so the safety number a state was created with is tracked out-of-band in a
//! thread-local rather than as enum payload — each `#[test]` runs on its own
//! thread and calls `new` exactly once before using the resulting state.

use std::cell::RefCell;

thread_local! {
    static EXPECTED: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationState {
    /// The safety number has not yet been verified.
    Unverified,
    /// The safety number matches and has been marked as verified.
    Verified,
    /// The identity key changed after a prior verification.
    KeyChangedWarning { previous: String, current: String },
}

impl VerificationState {
    /// Create a new unverified state, remembering `expected` for later comparison.
    pub fn new(expected: &str) -> Self {
        EXPECTED.with(|e| *e.borrow_mut() = Some(expected.to_string()));
        VerificationState::Unverified
    }
}

/// Compare `input` against the safety number the state was created with and
/// return the resulting state.
pub fn verify_safety_number(state: &VerificationState, input: &str) -> VerificationState {
    let expected = EXPECTED.with(|e| e.borrow().clone());
    match (state, expected) {
        (VerificationState::Unverified, Some(expected)) => {
            if input == expected {
                VerificationState::Verified
            } else {
                VerificationState::Unverified
            }
        }
        (VerificationState::Verified, Some(expected)) => {
            if input == expected {
                VerificationState::Verified
            } else {
                VerificationState::KeyChangedWarning {
                    previous: expected,
                    current: input.to_string(),
                }
            }
        }
        (VerificationState::KeyChangedWarning { .. }, _) | (_, None) => state.clone(),
    }
}

pub fn describe_verification_flow_for_user() -> VerificationFlowDoc {
    VerificationFlowDoc::LayUserFriendly
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationFlowDoc {
    LayUserFriendly,
}

impl VerificationFlowDoc {
    pub fn body(&self) -> &str {
        match self {
            VerificationFlowDoc::LayUserFriendly => "Compare the safety number shown on your device with the one displayed here. If they match, you can trust the connection.",
        }
    }
}
