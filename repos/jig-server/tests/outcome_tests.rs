use jig_server::runtime::outcome::{Outcome, OutcomeStatus};

#[test]
fn outcome_ok_default() {
    let outcome = Outcome::ok();
    assert_eq!(outcome.status, OutcomeStatus::Ok);
    assert!(outcome.affordances.is_empty());
    assert!(outcome.reason.is_none());
}

#[test]
fn outcome_soft_fail_with_reason() {
    let outcome = Outcome::soft_fail("timeout");
    assert_eq!(outcome.status, OutcomeStatus::SoftFail);
    assert_eq!(outcome.reason, Some("timeout".to_string()));
    assert!(outcome.affordances.is_empty());
}

#[test]
fn outcome_hard_fail_with_reason() {
    let outcome = Outcome::hard_fail("invalid_manifest");
    assert_eq!(outcome.status, OutcomeStatus::HardFail);
    assert_eq!(outcome.reason, Some("invalid_manifest".to_string()));
    assert!(outcome.affordances.is_empty());
}

#[test]
fn outcome_with_affordance() {
    let outcome = Outcome::ok().with_affordance("email.delivered");
    assert_eq!(outcome.status, OutcomeStatus::Ok);
    assert_eq!(outcome.affordances, vec!["email.delivered"]);
}

#[test]
fn outcome_multiple_affordances() {
    let outcome = Outcome::ok()
        .with_affordance("email.delivered")
        .with_affordance("bridge.forwarded");
    assert_eq!(outcome.affordances.len(), 2);
    assert!(outcome.affordances.contains(&"email.delivered".to_string()));
    assert!(
        outcome
            .affordances
            .contains(&"bridge.forwarded".to_string())
    );
}

#[test]
fn outcome_affordance_deduplication() {
    let outcome = Outcome::ok()
        .with_affordance("email.delivered")
        .with_affordance("email.delivered");
    // Should dedupe
    assert_eq!(outcome.affordances.len(), 1);
    assert_eq!(outcome.affordances[0], "email.delivered");
}

#[test]
fn outcome_status_display() {
    assert_eq!(OutcomeStatus::Ok.to_string(), "ok");
    assert_eq!(OutcomeStatus::SoftFail.to_string(), "soft_fail");
    assert_eq!(OutcomeStatus::HardFail.to_string(), "hard_fail");
}

#[test]
fn outcome_status_from_str() {
    use std::str::FromStr;

    assert_eq!(OutcomeStatus::from_str("ok").unwrap(), OutcomeStatus::Ok);
    assert_eq!(
        OutcomeStatus::from_str("soft_fail").unwrap(),
        OutcomeStatus::SoftFail
    );
    assert_eq!(
        OutcomeStatus::from_str("hard_fail").unwrap(),
        OutcomeStatus::HardFail
    );
    assert!(OutcomeStatus::from_str("invalid").is_err());
}

#[test]
#[cfg(feature = "telemetry_v0_2")]
fn outcome_converts_to_jig_core_outcome() {
    use jig_core::Outcome as CoreOutcome;

    let server_outcome = Outcome::ok().with_affordance("test.affordance");

    let core_outcome: CoreOutcome = server_outcome.into();
    assert_eq!(core_outcome.status, jig_core::OutcomeStatus::Ok);
    assert_eq!(core_outcome.affordances, vec!["test.affordance"]);
}
