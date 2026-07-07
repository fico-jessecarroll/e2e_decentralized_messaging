//! Audit findings tracker — every finding has a status; no critical/high open at release.
//!
//! Anchors PLAN.md Phase 9 acceptance criteria:
//!  - All audit findings are tracked with a resolution status
//!  - No critical or high-severity finding remains open at release
//!  - Negative: any finding marked won't-fix has an explicit documented risk acceptance

use docs_audit::{load_findings, Finding, Severity, Status};

#[test]
fn every_audit_finding_has_a_resolution_status() {
    let findings = load_findings();
    assert!(!findings.is_empty(), "expected at least one audit finding to track");
    for f in &findings {
        assert!(
            !matches!(f.status, Status::Untriaged),
            "finding {} has Status::Untriaged — must be Triaged/Fixed/WontFix",
            f.id
        );
    }
}

#[test]
fn no_critical_or_high_finding_remains_open_at_release() {
    let findings = load_findings();
    for f in &findings {
        if matches!(f.severity, Severity::Critical | Severity::High) {
            assert!(
                !matches!(f.status, Status::Open | Status::Untriaged),
                "critical/high finding {} is still open: {:?}", f.id, f
            );
        }
    }
}

#[test]
fn every_wontfix_finding_has_a_documented_risk_acceptance() {
    let findings = load_findings();
    for f in &findings {
        if matches!(f.status, Status::WontFix) {
            assert!(
                !f.risk_acceptance.is_empty(),
                "wont-fix finding {} must carry a non-empty risk_acceptance justification", f.id
            );
        }
    }
}
