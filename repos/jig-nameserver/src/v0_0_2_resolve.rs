//! GET /v1/resolve/{name} and GET /.well-known/jig-ns-delegation for the
//! v0.0.2 nameserver. Both serve signed objects a resolver verifies itself
//! (JEP-0004 rules 3 and 8), as unpadded base64url COSE_Sign1 envelopes.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use jig_core::naming::{Root, SuffixDelegation};

use crate::v0_0_2::AppState;
use crate::v0_0_2_register::{ApiError, b64u, current_binding, err, parse_name};

/// How long a served suffix delegation stays valid. It is re-signed on every
/// request, so this only bounds how long a resolver may cache it.
const DELEGATION_VALIDITY_SECS: i64 = 24 * 60 * 60;

/// GET /v1/resolve/{name} — `{attestation, links, reachability}` for the
/// current binding of `alias@suffix`, or 404 when none is valid now.
pub async fn resolve(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let alias = parse_name(&name)?.as_alias();
    match current_binding(&state, &alias).await? {
        Some(binding) => Ok(Json(binding.response())),
        None => Err(err(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            format!("no valid attestation for `{alias}`"),
        )),
    }
}

/// GET /.well-known/jig-ns-delegation — this nameserver's single-authority
/// delegation for its suffix, rooted in DNS (JEP-0004 rule 3). It is
/// authoritative only when served from `https://<suffix>/`.
pub async fn delegation(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let suffix = state.suffix().to_ascii_lowercase();
    let deleg = SuffixDelegation::sign(
        &[&state.ingest_ctx.server_key],
        &suffix,
        Root::Dns,
        &suffix,
        chrono::Utc::now().timestamp() + DELEGATION_VALIDITY_SECS,
    );
    let envelopes: Vec<String> = deleg.envelopes.iter().map(|e| b64u(e)).collect();
    Json(serde_json::json!({ "envelopes": envelopes }))
}

pub fn build_resolve_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/resolve/{alias}", get(resolve))
        .route("/.well-known/jig-ns-delegation", get(delegation))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v0_0_2_register::build_register_router;
    use crate::v0_0_2_register::test_support::{fresh_did_and_key, proof};
    use axum::{Router, body::Body, http::Request};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jig_core::naming::{self, Action, Name};
    use jig_pipeline::persist::StoredAliasAttestation;
    use tower::ServiceExt;

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

    fn router_for(state: &Arc<AppState>) -> Router {
        build_register_router(state.clone()).merge(build_resolve_router(state.clone()))
    }

    async fn register(router: &Router, state: &AppState, local: &str) -> String {
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();
        let (did, key) = fresh_did_and_key();
        let alias = format!("{local}@{}", state.suffix()).to_ascii_lowercase();
        let (status, body) = post_json(
            router.clone(),
            "/v1/register",
            serde_json::json!({
                "did": did,
                "requested_alias": local,
                "proof_of_control": proof(&key, state, Action::Register, &alias, &challenge),
                "challenge": challenge,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        did
    }

    fn attestation_of(body: &serde_json::Value) -> naming::Attestation {
        let envelope = URL_SAFE_NO_PAD
            .decode(body["attestation"].as_str().expect("attestation field"))
            .unwrap();
        naming::Attestation::from_envelope(&envelope).expect("attestation verifies")
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
    async fn resolve_refuses_a_malformed_name() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_resolve_router(state);
        let (status, body) = get_path(router, "/v1/resolve/no-suffix").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "INVALID_NAME");
    }

    #[tokio::test]
    async fn register_then_resolve_serves_a_verifiable_attestation() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = router_for(&state);
        let did = register(&router, &state, "dj").await;

        // Raw, percent-encoded and mixed-case names all find it.
        for path in [
            "/v1/resolve/dj@dj.jig",
            "/v1/resolve/dj%40dj.jig",
            "/v1/resolve/DJ@DJ.jig",
        ] {
            let (status, body) = get_path(router.clone(), path).await;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
            let att = attestation_of(&body);
            assert_eq!(att.did, did);
            assert_eq!(att.alias, "dj@dj.jig");
            assert_eq!(att.ns_did, state.ns_did_string());
            assert_eq!(body["links"], serde_json::json!([]));
            assert_eq!(body["reachability"], serde_json::Value::Null);
        }
    }

    #[tokio::test]
    async fn a_row_in_the_old_json_encoding_is_served_re_signed() {
        let state = Arc::new(AppState::for_test().unwrap());
        let (did, _) = fresh_did_and_key();
        let now = chrono::Utc::now().timestamp();
        state
            .ingest_ctx
            .store
            .upsert_alias_attestation(&StoredAliasAttestation {
                did: did.clone(),
                alias: "old@dj.jig".into(),
                ns_did: state.ns_did_string(),
                valid_from: now - 10,
                valid_until: now + 1000,
                attestation_bytes: br#"{"did":"x","sig":"y"}"#.to_vec(),
            })
            .unwrap();

        let (status, body) = get_path(
            build_resolve_router(state.clone()),
            "/v1/resolve/old@dj.jig",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        let att = attestation_of(&body);
        assert_eq!(att.did, did);
        assert_eq!((att.valid_from, att.valid_until), (now - 10, now + 1000));
    }

    #[tokio::test]
    async fn the_delegation_verifies_and_binds_a_served_attestation() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = router_for(&state);
        register(&router, &state, "dj").await;

        let (status, body) = get_path(router.clone(), "/.well-known/jig-ns-delegation").await;
        assert_eq!(status, StatusCode::OK);
        let envelopes: Vec<Vec<u8>> = body["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| URL_SAFE_NO_PAD.decode(e.as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(envelopes.len(), 1);
        let deleg = SuffixDelegation::from_envelopes(&envelopes).expect("delegation verifies");
        assert_eq!(deleg.suffix, "dj.jig");
        assert_eq!(deleg.authorities, vec![state.ns_did_string()]);
        assert_eq!(deleg.root, Root::Dns);
        assert_eq!(deleg.root_id, "dj.jig");

        let (_, resolved) = get_path(router, "/v1/resolve/dj@dj.jig").await;
        naming::verify_binding(
            &attestation_of(&resolved),
            &deleg,
            &Name::parse("dj@dj.jig").unwrap(),
            chrono::Utc::now().timestamp(),
        )
        .expect("a resolver accepts the binding");
    }
}
