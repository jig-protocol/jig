//! GET /v1/resolve/:alias for the v0.0.2 nameserver.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use serde::Serialize;

use crate::v0_0_2::AppState;

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

fn err(
    status: StatusCode,
    code: &'static str,
    msg: impl Into<String>,
) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            code: code.to_string(),
            message: msg.into(),
        }),
    )
}

pub async fn resolve(
    State(state): State<Arc<AppState>>,
    Path(alias): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let now = chrono::Utc::now().timestamp();
    let store = state.ingest_ctx.store.clone();
    let alias_for_lookup = alias.clone();
    let row =
        tokio::task::spawn_blocking(move || store.find_alias_attestation(&alias_for_lookup, now))
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
    let row = row.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            format!("no valid attestation for `{alias}`"),
        )
    })?;

    let attestation_json: serde_json::Value = serde_json::from_slice(&row.attestation_bytes)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PARSE_ERROR",
                e.to_string(),
            )
        })?;
    Ok(Json(attestation_json))
}

pub fn build_resolve_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/resolve/:alias", get(resolve))
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
    async fn resolve_returns_404_for_unknown_alias() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_resolve_router(state);
        let (status, body) = get_path(router, "/v1/resolve/nobody@dj.jig").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn register_then_resolve_round_trips() {
        let state = Arc::new(AppState::for_test().unwrap());
        // The register and resolve routers share the same state; build both
        // as separate Router<()>'s after with_state, then merge.
        let register_router = build_register_router(state.clone());
        let resolve_router = build_resolve_router(state.clone());
        let router = register_router.merge(resolve_router);

        // 1. Get challenge + register
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();
        let (did_str, key) = fresh_did_and_key();
        let sig = key.sign(challenge.as_bytes());
        let (status, _) = post_json(
            router.clone(),
            "/v1/register",
            serde_json::json!({
                "did": did_str.clone(),
                "requested_alias": "dj",
                "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
                "challenge": challenge,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // 2. Resolve
        let (status, body) = get_path(router, "/v1/resolve/dj@dj.jig").await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        assert_eq!(body["did"], did_str);
        assert_eq!(body["alias"], "dj@dj.jig");
    }
}
