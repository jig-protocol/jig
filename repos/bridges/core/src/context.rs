//! [`BridgeContext`] + denial types.
//!
//! `BridgeContext` (Task A3) is what `Bridge::start` receives. It carries:
//! - `submit`: push translated blocks into ingest (may be denied)
//! - `subscribe`: watch channels for outbound-triggering events
//! - `config`: the bridge-specific `[bridge.<name>.config]` TOML table
//!
//! This task (A2) introduces the [`SubmitDenied`] error type that the
//! submit handle returns when server policy rejects a submission.

use thiserror::Error;

/// Reasons a bridge submission may be rejected by the server. The bridge
/// is responsible for translating the denial back to its transport's
/// failure semantics (e.g., SMTP 5xx bounce, IRC error message, etc.) —
/// silently dropping is never correct.
#[derive(Debug, Error)]
pub enum SubmitDenied {
    /// Server's allow_list / deny_list / allow_channels policy blocked
    /// the submission. `reason` is a short human-readable description.
    #[error("PolicyBlocked: {reason}")]
    PolicyBlocked { reason: String },

    /// Per-bridge rate limit exceeded. `retry_after_secs` is a hint for
    /// when the bridge may retry (best-effort, server may revise).
    #[error("RateLimited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Server is shutting down or otherwise not accepting submissions.
    #[error("Unavailable: server not accepting submissions")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_denied_display_includes_reason() {
        let d = SubmitDenied::PolicyBlocked {
            reason: "channel #secret not in allow_channels".into(),
        };
        let s = format!("{d}");
        assert!(s.contains("PolicyBlocked"), "got: {s}");
        assert!(s.contains("channel #secret"), "got: {s}");
    }

    #[test]
    fn submit_denied_rate_limited_carries_retry_after() {
        let d = SubmitDenied::RateLimited { retry_after_secs: 30 };
        match d {
            SubmitDenied::RateLimited { retry_after_secs } => {
                assert_eq!(retry_after_secs, 30)
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn submit_denied_unavailable_no_data() {
        let d = SubmitDenied::Unavailable;
        let s = format!("{d}");
        assert!(s.contains("Unavailable"), "got: {s}");
    }
}
