//! GET /v1/handles — debug-gated enumeration of all registered aliases.
//!
//! Per the v0.0.2 spec, this is debug-only (mounted only when
//! `config.debug.list_handles` is true). v0.0.3+ may add proper
//! search/discovery; v0.0.2 ships this as a demo affordance.

use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde::Serialize;

use crate::v0_0_2::AppState;
use crate::v0_0_2_register::{ErrorBody, err};

#[derive(Debug, Serialize)]
pub struct HandlesList {
    pub aliases: Vec<HandleEntry>,
}

#[derive(Debug, Serialize)]
pub struct HandleEntry {
    pub alias: String,
    pub did: String,
    pub valid_from: i64,
    pub valid_until: i64,
}

/// GET /v1/handles — enumerate currently-valid attestations.
pub async fn list_handles(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HandlesList>, (StatusCode, Json<ErrorBody>)> {
    let now = chrono::Utc::now().timestamp();
    let store = state.ingest_ctx.store.clone();
    let rows = tokio::task::spawn_blocking(move || store.list_alias_attestations(now))
        .await
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "JOIN_ERROR",
                e.to_string(),
            )
        })?
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PERSIST_ERROR",
                e.to_string(),
            )
        })?;

    let aliases = rows
        .into_iter()
        .map(|r| HandleEntry {
            alias: r.alias,
            did: r.did,
            valid_from: r.valid_from,
            valid_until: r.valid_until,
        })
        .collect();

    Ok(Json(HandlesList { aliases }))
}

/// Build the handles router. Caller is responsible for gating on
/// `config.debug.list_handles` — if the flag is off, don't merge this
/// router into the v0.0.2 server's route tree.
pub fn build_handles_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/handles", get(list_handles))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v0_0_2_register::build_register_router;
    use axum::{Router, body::Body, http::Request};
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use jig_core::Did;
    use tower::ServiceExt;

    fn fresh_did_and_key() -> (String, SigningKey) {
        use rand::Rng;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill(&mut secret);
        let key = SigningKey::from_bytes(&secret);
        let did = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
        (did.to_did_jig_string(), key)
    }

    async fn get_path(router: Router, path: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn post_json(
        router: Router,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn handles_returns_empty_when_no_registrations() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_handles_router(state);
        let (status, body) = get_path(router, "/v1/handles").await;
        assert_eq!(status, StatusCode::OK);
        let aliases = body["aliases"].as_array().unwrap();
        assert!(aliases.is_empty());
    }

    #[tokio::test]
    async fn handles_returns_registered_aliases() {
        let state = Arc::new(AppState::for_test().unwrap());
        let combined = build_register_router(state.clone()).merge(build_handles_router(state));

        // Register two aliases
        for nick in ["dj", "deji"] {
            let (_, ch) = get_path(combined.clone(), "/v1/challenge").await;
            let challenge = ch["challenge"].as_str().unwrap().to_string();
            let (did, key) = fresh_did_and_key();
            let sig = key.sign(challenge.as_bytes());
            let (status, _) = post_json(
                combined.clone(),
                "/v1/register",
                serde_json::json!({
                    "did": did,
                    "requested_alias": nick,
                    "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
                    "challenge": challenge,
                }),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }

        // Enumerate
        let (status, body) = get_path(combined, "/v1/handles").await;
        assert_eq!(status, StatusCode::OK);
        let aliases: Vec<&str> = body["aliases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["alias"].as_str().unwrap())
            .collect();
        assert!(aliases.contains(&"dj@dj.jig"));
        assert!(aliases.contains(&"deji@dj.jig"));
        assert_eq!(aliases.len(), 2);
    }
}
