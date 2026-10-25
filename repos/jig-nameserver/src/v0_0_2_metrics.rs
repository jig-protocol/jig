//! `GET /metrics`: each suffix's registration pool and effort, in the
//! Prometheus text format, for the abuse runbook and the opening checklist.
//!
//! Ungated, like jig-server's `/metrics`: a scraper cannot sign. Nothing here
//! names a DID or an alias. The suggested effort is what any client already
//! learns from a challenge, and the counts are per suffix.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::{Router, extract::State, http::header, response::IntoResponse, routing::get};

use crate::v0_0_2::AppState;
use crate::v0_0_2_pow_policy::MarketStats;

/// A metric's name, type, help, and how to read it from a suffix's stats.
type Family = (
    &'static str,
    &'static str,
    &'static str,
    fn(&MarketStats) -> u64,
);

pub fn build_metrics_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        render(&state),
    )
}

fn render(state: &AppState) -> String {
    let stats: Vec<_> = state
        .suffixes
        .iter()
        .map(|p| (p.suffix.clone(), p.market().stats()))
        .collect();
    let mut out = String::new();
    let families: [Family; 5] = [
        (
            "jig_ns_registrations_admitted_total",
            "counter",
            "Stranger registrations the pool admitted.",
            |s| s.admitted,
        ),
        (
            "jig_ns_registrations_busy_total",
            "counter",
            "Stranger registrations refused 503 REGISTRATION_BUSY: bumped, timed out or the queue full.",
            |s| s.refused,
        ),
        (
            "jig_ns_suggested_effort",
            "gauge",
            "The controller's suggested effort, before the length and penalty multipliers.",
            |s| s.suggested_effort,
        ),
        (
            "jig_ns_pool_queued",
            "gauge",
            "Registrations waiting for a pool token.",
            |s| s.queued as u64,
        ),
        (
            "jig_ns_pool_tokens",
            "gauge",
            "Pool tokens available now.",
            |s| u64::from(s.tokens),
        ),
    ];
    for (name, kind, help, value) in families {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} {kind}");
        for (suffix, s) in &stats {
            // Suffixes are validated DNS-style labels: nothing to escape.
            let _ = writeln!(out, "{name}{{suffix=\"{suffix}\"}} {}", value(s));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn every_suffix_reports_its_pool_and_effort() {
        let state = Arc::new(
            crate::v0_0_2::AppState::for_test_with_suffixes(vec![
                jig_config::v0_0_2_server::SuffixConfig::new("dj.jig"),
                jig_config::v0_0_2_server::SuffixConfig::new("other.jig"),
            ])
            .unwrap(),
        );
        let resp = build_metrics_router(state)
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        for family in [
            "jig_ns_registrations_admitted_total",
            "jig_ns_registrations_busy_total",
            "jig_ns_suggested_effort",
            "jig_ns_pool_queued",
            "jig_ns_pool_tokens",
        ] {
            assert!(
                text.contains(&format!("# TYPE {family} ")),
                "{family}: {text}"
            );
            assert!(
                text.contains(&format!("{family}{{suffix=\"dj.jig\"}} ")),
                "{text}"
            );
            assert!(
                text.contains(&format!("{family}{{suffix=\"other.jig\"}} ")),
                "{text}"
            );
        }
        assert!(
            text.contains("jig_ns_suggested_effort{suffix=\"dj.jig\"} 262144"),
            "idle at the recommended floor: {text}"
        );
    }
}
