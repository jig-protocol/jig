//! POST /v1/rotate (key rotation) and POST /v1/renew (TTL refresh) for the
//! v0.0.2 nameserver. Renew takes an action-bound proof of control; rotate
//! keeps signatures over the bare challenge until lane I's I3 moves it onto
//! dual-signed links (JEP-0004 rule 9).

use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use jig_core::naming::Action;
use serde::Deserialize;

use crate::v0_0_2::AppState;
use crate::v0_0_2_register::{
    ApiError, consume_challenge, current_binding, err, issue_and_persist, refuse_second_name,
    served_name, verify_action_proof, verify_bare_challenge_sig,
};

#[derive(Debug, Deserialize)]
pub struct RotateReq {
    pub alias: String,
    pub old_did: String,
    pub new_did: String,
    pub challenge: String,
    pub sig_by_old: String,
    pub sig_by_new: String,
    /// Reserved for lane R's admission proof-of-work (R1).
    #[serde(default)]
    pub pow: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct RenewReq {
    pub alias: String,
    pub did: String,
    pub challenge: String,
    /// Unpadded base64url of the DID's COSE_Sign1 over
    /// `naming::proof_payload(Renew, ns_did, alias, challenge)`.
    pub proof_of_control: String,
    /// Reserved for lane R's admission proof-of-work (R1).
    #[serde(default)]
    pub pow: Option<serde_json::Value>,
}

/// POST /v1/rotate — replace the DID binding for an alias. Requires
/// signatures by BOTH the old and new keys over the challenge.
pub async fn rotate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RotateReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = served_name(&state, &req.alias)?;
    let alias = name.as_alias();

    // 1. Consume challenge
    consume_challenge(&state, &req.challenge).await?;

    // 2. Verify BOTH signatures
    verify_bare_challenge_sig(&req.old_did, &req.challenge, &req.sig_by_old)?;
    verify_bare_challenge_sig(&req.new_did, &req.challenge, &req.sig_by_new)?;

    // 3. Check the alias currently binds to old_did
    let current_holder = state.alias_holder(&alias).await.map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PERSIST_ERROR",
            e.to_string(),
        )
    })?;
    match current_holder {
        Some(did) if did == req.old_did => {}
        Some(other) => {
            return Err(err(
                StatusCode::CONFLICT,
                "WRONG_HOLDER",
                format!(
                    "alias `{alias}` is held by `{other}`, not `{}`",
                    req.old_did
                ),
            ));
        }
        None => {
            return Err(err(
                StatusCode::NOT_FOUND,
                "ALIAS_NOT_FOUND",
                format!("no valid attestation for alias `{alias}`"),
            ));
        }
    }

    // The new DID must not already hold another name under this suffix, or
    // the rotation would silently drop it.
    refuse_second_name(&state, &req.new_did, &name).await?;

    // 4. Expire the old-DID row so it no longer matches alias queries.
    //    Without this, both the old and new rows would be valid for the same
    //    alias and the result would be non-deterministic when their valid_from
    //    timestamps are equal (common in tests). Setting valid_until = now on
    //    the old row is the cleanest fix within the (did, ns_did, suffix) PK
    //    model; a later refactor can add a proper `alias → did` unique index.
    let now = chrono::Utc::now().timestamp();
    let store_expire = state.ingest_ctx.store.clone();
    let old_did_clone = req.old_did.clone();
    let ns_did_clone = state.ns_did_string();
    let alias_clone = alias.clone();
    tokio::task::spawn_blocking(move || {
        store_expire.expire_alias_attestation(&old_did_clone, &ns_did_clone, &alias_clone, now)
    })
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

    // 5. Issue + sign new attestation under new_did. The old DID's
    //    reachability record does not carry over.
    issue_and_persist(&state, &req.new_did, &alias, None).await
}

/// POST /v1/renew — refresh the validity window of an existing
/// attestation. Same DID; new valid_from + valid_until. A reachability
/// record registered with the alias is kept.
pub async fn renew(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RenewReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let alias = served_name(&state, &req.alias)?.as_alias();

    // 1. Verify the proof, then consume the challenge, so a bad proof leaves
    //    the challenge usable.
    verify_action_proof(
        &state,
        Action::Renew,
        &req.did,
        &alias,
        &req.challenge,
        &req.proof_of_control,
    )?;
    consume_challenge(&state, &req.challenge).await?;

    // 2. Check current holder matches the renewing DID
    let binding = match current_binding(&state, &alias).await? {
        Some(b) if b.attestation.did == req.did => b,
        Some(_) => {
            return Err(err(
                StatusCode::UNAUTHORIZED,
                "NOT_HOLDER",
                "renewing DID does not currently hold this alias",
            ));
        }
        None => {
            return Err(err(
                StatusCode::NOT_FOUND,
                "ALIAS_NOT_FOUND",
                format!("no valid attestation for alias `{alias}`"),
            ));
        }
    };

    // 3. Issue + sign refreshed attestation. Same (did, ns_did, suffix) PK so
    //    the existing row is updated in place.
    issue_and_persist(&state, &req.did, &alias, binding.reachability).await
}

pub fn build_rotate_renew_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/rotate", post(rotate))
        .route("/v1/renew", post(renew))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v0_0_2_register::test_support::{fresh_did_and_key, proof};
    use crate::v0_0_2_register::{b64u, build_register_router};
    use crate::v0_0_2_resolve::build_resolve_router;
    use axum::{Router, body::Body, http::Request};
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use jig_core::naming::{self, ReachabilityRecord};
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

    fn full_router(state: Arc<AppState>) -> Router {
        build_register_router(state.clone())
            .merge(build_resolve_router(state.clone()))
            .merge(build_rotate_renew_router(state))
    }

    fn attestation_of(body: &serde_json::Value) -> naming::Attestation {
        let envelope = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body["attestation"].as_str().expect("attestation field"))
            .unwrap();
        naming::Attestation::from_envelope(&envelope).expect("attestation verifies")
    }

    async fn challenge(router: &Router) -> String {
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        ch["challenge"].as_str().unwrap().to_string()
    }

    async fn register_alias_with(
        router: &Router,
        state: &AppState,
        alias_local: &str,
        reachability: Option<&ReachabilityRecord>,
        key: &SigningKey,
    ) {
        let challenge = challenge(router).await;
        let did = crate::v0_0_2_register::test_support::naming_did(key);
        let alias = format!("{alias_local}@{}", state.suffix());
        let mut body = serde_json::json!({
            "did": did,
            "requested_alias": alias_local,
            "proof_of_control": proof(key, state, Action::Register, &alias, &challenge),
            "challenge": challenge,
        });
        if let Some(r) = reachability {
            body["reachability"] = b64u(&r.envelope).into();
        }
        let (status, body) = post_json(router.clone(), "/v1/register", body).await;
        assert_eq!(status, StatusCode::OK, "body={body}");
    }

    async fn register_alias(
        router: &Router,
        state: &AppState,
        alias_local: &str,
    ) -> (String, SigningKey) {
        let (did, key) = fresh_did_and_key();
        register_alias_with(router, state, alias_local, None, &key).await;
        (did, key)
    }

    async fn renew_body(
        router: &Router,
        state: &AppState,
        key: &SigningKey,
        did: &str,
        alias: &str,
    ) -> serde_json::Value {
        let challenge = challenge(router).await;
        serde_json::json!({
            "alias": alias,
            "did": did,
            "challenge": challenge,
            "proof_of_control": proof(key, state, Action::Renew, alias, &challenge),
        })
    }

    fn bare(key: &SigningKey, challenge: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(key.sign(challenge.as_bytes()).to_bytes())
    }

    // ---- rotate ----

    #[tokio::test]
    async fn rotate_replaces_did_binding() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());

        let (old_did, old_key) = register_alias(&router, &state, "dj").await;
        let (new_did, new_key) = fresh_did_and_key();
        let challenge = challenge(&router).await;

        let (status, body) = post_json(
            router.clone(),
            "/v1/rotate",
            serde_json::json!({
                "alias": "dj@dj.jig",
                "old_did": old_did,
                "new_did": new_did.clone(),
                "challenge": challenge,
                "sig_by_old": bare(&old_key, &challenge),
                "sig_by_new": bare(&new_key, &challenge),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        let att = attestation_of(&body);
        assert_eq!(att.did, new_did);
        assert_eq!(att.alias, "dj@dj.jig");

        // Resolve now returns the new DID
        let (status, body) = get_path(router, "/v1/resolve/dj@dj.jig").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(attestation_of(&body).did, new_did);
    }

    #[tokio::test]
    async fn rotate_rejects_when_old_did_doesnt_hold_alias() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());

        register_alias(&router, &state, "alice").await;

        let (fake_old, fake_old_key) = fresh_did_and_key();
        let (new_did, new_key) = fresh_did_and_key();
        let challenge = challenge(&router).await;

        let (status, body) = post_json(
            router,
            "/v1/rotate",
            serde_json::json!({
                "alias": "alice@dj.jig",
                "old_did": fake_old,
                "new_did": new_did,
                "challenge": challenge,
                "sig_by_old": bare(&fake_old_key, &challenge),
                "sig_by_new": bare(&new_key, &challenge),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "WRONG_HOLDER");
    }

    #[tokio::test]
    async fn rotate_rejects_bad_old_signature() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());

        let (old_did, _old_key) = register_alias(&router, &state, "dj").await;
        let (new_did, new_key) = fresh_did_and_key();
        let challenge = challenge(&router).await;
        let (_wrong_did, wrong_key) = fresh_did_and_key();

        let (status, body) = post_json(
            router,
            "/v1/rotate",
            serde_json::json!({
                "alias": "dj@dj.jig",
                "old_did": old_did,
                "new_did": new_did,
                "challenge": challenge,
                "sig_by_old": bare(&wrong_key, &challenge),
                "sig_by_new": bare(&new_key, &challenge),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "PROOF_FAILED");
    }

    // ---- renew ----

    #[tokio::test]
    async fn renew_extends_validity_window() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());

        let (did, key) = register_alias(&router, &state, "dj").await;
        let (_, before) = get_path(router.clone(), "/v1/resolve/dj@dj.jig").await;
        let original_from = attestation_of(&before).valid_from;

        // Sleep ~1s so the renewed valid_from advances
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let body = renew_body(&router, &state, &key, &did, "dj@dj.jig").await;
        let (status, renewed) = post_json(router.clone(), "/v1/renew", body).await;
        assert_eq!(status, StatusCode::OK, "body={renewed}");
        let att = attestation_of(&renewed);
        assert!(
            att.valid_from > original_from,
            "renew must advance valid_from (was {original_from}, now {})",
            att.valid_from
        );
        assert_eq!(att.did, did);
    }

    #[tokio::test]
    async fn renew_keeps_the_reachability_record() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());
        let (did, key) = fresh_did_and_key();
        let record = ReachabilityRecord::sign(&key, vec![], 3);
        register_alias_with(&router, &state, "dj", Some(&record), &key).await;

        let body = renew_body(&router, &state, &key, &did, "dj@dj.jig").await;
        let (status, renewed) = post_json(router, "/v1/renew", body).await;
        assert_eq!(status, StatusCode::OK, "body={renewed}");
        assert_eq!(renewed["reachability"], b64u(&record.envelope));
    }

    #[tokio::test]
    async fn a_register_proof_replayed_as_renew_is_refused() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());
        let (did, key) = register_alias(&router, &state, "dj").await;
        let challenge = challenge(&router).await;

        let (status, body) = post_json(
            router,
            "/v1/renew",
            serde_json::json!({
                "alias": "dj@dj.jig",
                "did": did,
                "challenge": challenge,
                "proof_of_control": proof(&key, &state, Action::Register, "dj@dj.jig", &challenge),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "PROOF_FAILED");
    }

    #[tokio::test]
    async fn a_renew_with_a_bad_proof_leaves_the_challenge_usable() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());
        let (did, key) = register_alias(&router, &state, "dj").await;
        let challenge = challenge(&router).await;
        let (_, other_key) = fresh_did_and_key();

        let (status, _) = post_json(
            router.clone(),
            "/v1/renew",
            serde_json::json!({
                "alias": "dj@dj.jig", "did": did, "challenge": challenge,
                "proof_of_control": proof(&other_key, &state, Action::Renew, "dj@dj.jig", &challenge),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, body) = post_json(
            router,
            "/v1/renew",
            serde_json::json!({
                "alias": "dj@dj.jig", "did": did, "challenge": challenge,
                "proof_of_control": proof(&key, &state, Action::Renew, "dj@dj.jig", &challenge),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={body}");
    }

    #[tokio::test]
    async fn a_consumed_challenge_is_refused_for_every_action() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());
        let (did, key) = register_alias(&router, &state, "dj").await;

        // Spend one challenge on a renew.
        let body = renew_body(&router, &state, &key, &did, "dj@dj.jig").await;
        let spent = body["challenge"].as_str().unwrap().to_string();
        let (status, _) = post_json(router.clone(), "/v1/renew", body).await;
        assert_eq!(status, StatusCode::OK);

        let (new_did, new_key) = fresh_did_and_key();
        let attempts = [
            (
                "/v1/register",
                serde_json::json!({
                    "did": did, "requested_alias": "dj", "challenge": spent,
                    "proof_of_control": proof(&key, &state, Action::Register, "dj@dj.jig", &spent),
                }),
            ),
            (
                "/v1/renew",
                serde_json::json!({
                    "alias": "dj@dj.jig", "did": did, "challenge": spent,
                    "proof_of_control": proof(&key, &state, Action::Renew, "dj@dj.jig", &spent),
                }),
            ),
            (
                "/v1/rotate",
                serde_json::json!({
                    "alias": "dj@dj.jig", "old_did": did, "new_did": new_did, "challenge": spent,
                    "sig_by_old": bare(&key, &spent), "sig_by_new": bare(&new_key, &spent),
                }),
            ),
        ];
        for (path, body) in attempts {
            let (status, body) = post_json(router.clone(), path, body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: {body}");
            assert_eq!(body["code"], "CHALLENGE_UNKNOWN", "{path}");
        }
    }

    #[tokio::test]
    async fn renew_rejects_when_did_doesnt_match_holder() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());

        register_alias(&router, &state, "alice").await;

        let (fake_did, fake_key) = fresh_did_and_key();
        let body = renew_body(&router, &state, &fake_key, &fake_did, "alice@dj.jig").await;
        let (status, body) = post_json(router, "/v1/renew", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "NOT_HOLDER");
    }

    #[tokio::test]
    async fn renew_404_for_unknown_alias() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());

        let (did, key) = fresh_did_and_key();
        let body = renew_body(&router, &state, &key, &did, "nobody@dj.jig").await;
        let (status, body) = post_json(router, "/v1/renew", body).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "ALIAS_NOT_FOUND");
    }
}
