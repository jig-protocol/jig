//! Outcome model for block execution results.
//!
//! Maps execution results to receipt v0.2 outcome fields with support for
//! retryable (soft fail) vs terminal (hard fail) error classification.

use std::fmt;
use std::str::FromStr;

/// Execution outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutcomeStatus {
    /// Execution succeeded.
    Ok,
    /// Execution failed but is retryable (e.g., timeout, rate limit).
    SoftFail,
    /// Execution failed terminally (e.g., invalid manifest, capability denied).
    HardFail,
}

impl fmt::Display for OutcomeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutcomeStatus::Ok => write!(f, "ok"),
            OutcomeStatus::SoftFail => write!(f, "soft_fail"),
            OutcomeStatus::HardFail => write!(f, "hard_fail"),
        }
    }
}

impl FromStr for OutcomeStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ok" => Ok(OutcomeStatus::Ok),
            "soft_fail" => Ok(OutcomeStatus::SoftFail),
            "hard_fail" => Ok(OutcomeStatus::HardFail),
            _ => Err(format!("invalid outcome status: {s}")),
        }
    }
}

/// Block execution outcome with optional affordances and reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: OutcomeStatus,
    pub affordances: Vec<String>,
    pub reason: Option<String>,
}

impl Outcome {
    /// Create a successful outcome.
    pub fn ok() -> Self {
        Self {
            status: OutcomeStatus::Ok,
            affordances: Vec::new(),
            reason: None,
        }
    }

    /// Create a soft fail outcome (retryable).
    ///
    /// Use for: timeouts, rate limits, temporary unavailability.
    pub fn soft_fail(reason: impl Into<String>) -> Self {
        Self {
            status: OutcomeStatus::SoftFail,
            affordances: Vec::new(),
            reason: Some(reason.into()),
        }
    }

    /// Create a hard fail outcome (terminal).
    ///
    /// Use for: invalid manifests, capability denied, malformed input.
    pub fn hard_fail(reason: impl Into<String>) -> Self {
        Self {
            status: OutcomeStatus::HardFail,
            affordances: Vec::new(),
            reason: Some(reason.into()),
        }
    }

    /// Add an affordance to signal task completion.
    ///
    /// Affordances are optional machine-readable signals that the block
    /// successfully performed a specific action (e.g., "email.delivered").
    ///
    /// Duplicates are automatically deduplicated.
    pub fn with_affordance(mut self, affordance: impl Into<String>) -> Self {
        let affordance = affordance.into();
        if !self.affordances.contains(&affordance) {
            self.affordances.push(affordance);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_status_roundtrip() {
        for status in [
            OutcomeStatus::Ok,
            OutcomeStatus::SoftFail,
            OutcomeStatus::HardFail,
        ] {
            let s = status.to_string();
            assert_eq!(OutcomeStatus::from_str(&s).unwrap(), status);
        }
    }

    #[test]
    fn affordance_dedup_preserves_order() {
        let outcome = Outcome::ok()
            .with_affordance("a")
            .with_affordance("b")
            .with_affordance("a"); // Duplicate
        assert_eq!(outcome.affordances, vec!["a", "b"]);
    }
}
