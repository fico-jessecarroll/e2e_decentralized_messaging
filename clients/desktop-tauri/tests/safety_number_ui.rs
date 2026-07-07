//! Safety-number verification UI — mark verified; warn on key change.
//!
//! Anchors PLAN.md Phase 5 acceptance criteria:
//!  - Matching safety numbers can be marked verified
//!  - Negative: a changed identity key after verification surfaces a clear warning, not a silent pass-through

use clients_desktop_tauri::verify::{verify_safety_number, VerificationState};

#[test]
fn matching_safety_numbers_can_be_marked_verified() {
    let safety_number = "12345 67890 12345 67890 12345";
    let state = VerificationState::new(safety_number);

    let result = verify_safety_number(&state, safety_number);
    assert_eq!(result, VerificationState::Verified);
}

#[test]
fn changed_identity_key_after_verification_surfaces_warning_not_silent_pass() {
    let original_number = "11111 22222 33333 44444 55555";
    let mut state = VerificationState::new(original_number);
    state = verify_safety_number(&state, original_number);
    assert_eq!(state, VerificationState::Verified);

    // Identity key rotates (e.g., reinstall), safety number now differs.
    let new_number = "99999 88888 77777 66666 55555";
    state = verify_safety_number(&state, new_number);

    assert!(
        matches!(state, VerificationState::KeyChangedWarning { .. }),
        "changed identity key must surface VerificationState::KeyChangedWarning, got: {state:?}"
    );
}

#[test]
fn mismatched_user_input_does_not_mark_verified() {
    let state = VerificationState::new("12345 67890 12345 67890 12345");
    let result = verify_safety_number(&state, "00000 00000 00000 00000 00000");
    assert_eq!(result, VerificationState::Unverified);
}
