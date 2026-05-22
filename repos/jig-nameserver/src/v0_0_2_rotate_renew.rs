//! POST /v1/rotate (key rotation) and POST /v1/renew (TTL refresh) for the
//! v0.0.2 nameserver. Both reuse the challenge + proof-of-control machinery
//! from v0_0_2_register.

use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::Engine as _;
use ed25519_dalek::Signer;
use jig_pipeline::persist::StoredAliasAttestation;
use serde::Deserialize;

use crate::v0_0_2::AppState;
use crate::v0_0_2_register::{
    Attestation, DEFAULT_TTL_SECONDS, ErrorBody, err, verify_proof_of_control,
};

#[derive(Debug, Deserialize)]
pub struct RotateReq {
    pub alias: String,
    pub old_did: String,
    pub new_did: String,
    pub challenge: String,
    pub sig_by_old: String,
    pub sig_by_new: String,
}

#[derive(Debug, Deserialize)]
pub struct RenewReq {
    pub alias: String,
    pub did: String,
    pub challenge: String,
    pub proof_of_control: String,
}

/// POST /v1/rotate — replace the DID binding for an alias. Requires
/// proof of control over BOTH the old and new keys.
pub async fn rotate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RotateReq>,
) -> Result<Json<Attestation>, (StatusCode, Json<ErrorBody>)> {
    // 1. Consume challenge
    if !state.take_challenge(&req.challenge).await {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_UNKNOWN",
            "challenge not recognized or already consumed",
        ));
    }

    // 2. Verify BOTH signatures
    verify_proof_of_control(&req.old_did, &req.challenge, &req.sig_by_old)?;
    verify_proof_of_control(&req.new_did, &req.challenge, &req.sig_by_new)?;

    // 3. Check the alias currently binds to old_did
    let current_holder = state.alias_holder(&req.alias).await.map_err(|e| {
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
                    "alias `{}` is held by `{other}`, not `{}`",
                    req.alias, req.old_did
                ),
            ));
        }
        None => {
            return Err(err(
                StatusCode::NOT_FOUND,
                "ALIAS_NOT_FOUND",
                format!("no valid attestation for alias `{}`", req.alias),
            ));
        }
    }

    // 4. Expire the old-DID row so it no longer matches alias queries.
    //    Without this, both the old and new rows would be valid for the same
    //    alias and the result would be non-deterministic when their valid_from
    //    timestamps are equal (common in tests). Setting valid_until = now on
    //    the old row is the cleanest fix within the v0.0.2 (did, ns_did) PK
    //    model; a v0.0.3+ refactor can add a proper `alias → did` unique index.
    let now = chrono::Utc::now().timestamp();
    let store_expire = state.ingest_ctx.store.clone();
    let old_did_clone = req.old_did.clone();
    let ns_did_clone = state.ns_did_string();
    tokio::task::spawn_blocking(move || {
        store_expire.expire_alias_attestation(&old_did_clone, &ns_did_clone, now)
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

    // 5. Issue + sign new attestation under new_did.
    issue_and_persist_attestation(&state, req.new_did, req.alias).await
}

/// POST /v1/renew — refresh the validity window of an existing
/// attestation. Same DID; new valid_from + valid_until.
pub async fn renew(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RenewReq>,
) -> Result<Json<Attestation>, (StatusCode, Json<ErrorBody>)> {
    // 1. Consume challenge
    if !state.take_challenge(&req.challenge).await {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_UNKNOWN",
            "challenge not recognized or already consumed",
        ));
    }

    // 2. Verify proof
    verify_proof_of_control(&req.did, &req.challenge, &req.proof_of_control)?;

    // 3. Check current holder matches the renewing DID
    let current_holder = state.alias_holder(&req.alias).await.map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PERSIST_ERROR",
            e.to_string(),
        )
    })?;
    match current_holder {
        Some(did) if did == req.did => {}
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
                format!("no valid attestation for alias `{}`", req.alias),
            ));
        }
    }

    // 4. Issue + sign refreshed attestation. Same (did, ns_did) PK so the
    //    existing row is updated in place.
    issue_and_persist_attestation(&state, req.did, req.alias).await
}

async fn issue_and_persist_attestation(
    state: &Arc<AppState>,
    did: String,
    full_alias: String,
) -> Result<Json<Attestation>, (StatusCode, Json<ErrorBody>)> {
    let now = chrono::Utc::now().timestamp();
    let mut attestation = Attestation {
        did: did.clone(),
        alias: full_alias.clone(),
        ns_did: state.ns_did_string(),
        valid_from: now,
        valid_until: now + DEFAULT_TTL_SECONDS,
        profile_ttl_seconds: DEFAULT_TTL_SECONDS as u64,
        sig: String::new(),
    };
    let canonical = serde_json::to_vec(&serde_json::json!({
        "did": attestation.did,
        "alias": attestation.alias,
        "ns_did": attestation.ns_did,
        "valid_from": attestation.valid_from,
        "valid_until": attestation.valid_until,
        "profile_ttl_seconds": attestation.profile_ttl_seconds,
    }))
    .map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SIGN_ERROR",
            e.to_string(),
        )
    })?;
    let sig = state.ingest_ctx.server_key.sign(&canonical);
    attestation.sig = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

    let stored = StoredAliasAttestation {
        did: attestation.did.clone(),
        alias: attestation.alias.clone(),
        ns_did: attestation.ns_did.clone(),
        valid_from: attestation.valid_from,
        valid_until: attestation.valid_until,
        attestation_bytes: serde_json::to_vec(&attestation).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PERSIST_ERROR",
                e.to_string(),
            )
        })?,
    };
    let store = state.ingest_ctx.store.clone();
    tokio::task::spawn_blocking(move || store.upsert_alias_attestation(&stored))
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

    Ok(Json(attestation))
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
    use crate::v0_0_2_register::build_register_router;
    use crate::v0_0_2_resolve::build_resolve_router;
    use axum::{Router, body::Body, http::Request};
    use ed25519_dalek::SigningKey;
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

    fn full_router(state: Arc<AppState>) -> Router {
        build_register_router(state.clone())
            .merge(build_resolve_router(state.clone()))
            .merge(build_rotate_renew_router(state))
    }

    async fn register_alias(router: &Router, alias_local: &str) -> (String, SigningKey) {
        use ed25519_dalek::Signer;
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();
        let (did_str, key) = fresh_did_and_key();
        let sig = key.sign(challenge.as_bytes());
        let body = serde_json::json!({
            "did": did_str.clone(),
            "requested_alias": alias_local,
            "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            "challenge": challenge,
        });
        let (status, _) = post_json(router.clone(), "/v1/register", body).await;
        assert_eq!(status, StatusCode::OK);
        (did_str, key)
    }

    // ---- rotate ----

    #[tokio::test]
    async fn rotate_replaces_did_binding() {
        use ed25519_dalek::Signer;
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());

        // Register original
        let (old_did, old_key) = register_alias(&router, "dj").await;

        // Generate new key + DID
        let (new_did, new_key) = fresh_did_and_key();

        // Fresh challenge for the rotation
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();
        let sig_old = old_key.sign(challenge.as_bytes());
        let sig_new = new_key.sign(challenge.as_bytes());

        let (status, body) = post_json(
            router.clone(),
            "/v1/rotate",
            serde_json::json!({
                "alias": "dj@dj.jig",
                "old_did": old_did,
                "new_did": new_did.clone(),
                "challenge": challenge,
                "sig_by_old": base64::engine::general_purpose::STANDARD.encode(sig_old.to_bytes()),
                "sig_by_new": base64::engine::general_purpose::STANDARD.encode(sig_new.to_bytes()),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        assert_eq!(body["did"], new_did);
        assert_eq!(body["alias"], "dj@dj.jig");

        // Resolve now returns the new DID
        let (status, body) = get_path(router, "/v1/resolve/dj@dj.jig").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["did"], new_did);
    }

    #[tokio::test]
    async fn rotate_rejects_when_old_did_doesnt_hold_alias() {
        use ed25519_dalek::Signer;
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());

        // Register alice under did_a
        let (_did_a, _key_a) = register_alias(&router, "alice").await;

        // Try to "rotate" alice's binding using a different (unregistered) DID as the old
        let (fake_old, fake_old_key) = fresh_did_and_key();
        let (new_did, new_key) = fresh_did_and_key();
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();
        let sig_old = fake_old_key.sign(challenge.as_bytes());
        let sig_new = new_key.sign(challenge.as_bytes());

        let (status, body) = post_json(
            router,
            "/v1/rotate",
            serde_json::json!({
                "alias": "alice@dj.jig",
                "old_did": fake_old,
                "new_did": new_did,
                "challenge": challenge,
                "sig_by_old": base64::engine::general_purpose::STANDARD.encode(sig_old.to_bytes()),
                "sig_by_new": base64::engine::general_purpose::STANDARD.encode(sig_new.to_bytes()),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "WRONG_HOLDER");
    }

    #[tokio::test]
    async fn rotate_rejects_bad_old_signature() {
        use ed25519_dalek::Signer;
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state);

        let (old_did, _old_key) = register_alias(&router, "dj").await;
        let (new_did, new_key) = fresh_did_and_key();
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();
        // Sign with the wrong key for "old"
        let (_wrong_did, wrong_key) = fresh_did_and_key();
        let sig_old = wrong_key.sign(challenge.as_bytes());
        let sig_new = new_key.sign(challenge.as_bytes());

        let (status, body) = post_json(
            router,
            "/v1/rotate",
            serde_json::json!({
                "alias": "dj@dj.jig",
                "old_did": old_did,
                "new_did": new_did,
                "challenge": challenge,
                "sig_by_old": base64::engine::general_purpose::STANDARD.encode(sig_old.to_bytes()),
                "sig_by_new": base64::engine::general_purpose::STANDARD.encode(sig_new.to_bytes()),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "PROOF_FAILED");
    }

    // ---- renew ----

    #[tokio::test]
    async fn renew_extends_validity_window() {
        use ed25519_dalek::Signer;
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state.clone());

        let (did_str, key) = register_alias(&router, "dj").await;

        // Capture original valid_from + valid_until
        let (_, before) = get_path(router.clone(), "/v1/resolve/dj@dj.jig").await;
        let original_from = before["valid_from"].as_i64().unwrap();

        // Sleep ~1s so the renewed valid_from advances
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        // Renew
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();
        let sig = key.sign(challenge.as_bytes());
        let (status, renewed) = post_json(
            router.clone(),
            "/v1/renew",
            serde_json::json!({
                "alias": "dj@dj.jig",
                "did": did_str.clone(),
                "challenge": challenge,
                "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={renewed}");
        let new_from = renewed["valid_from"].as_i64().unwrap();
        assert!(
            new_from > original_from,
            "renew must advance valid_from (was {original_from}, now {new_from})"
        );
        assert_eq!(renewed["did"], did_str);
    }

    #[tokio::test]
    async fn renew_rejects_when_did_doesnt_match_holder() {
        use ed25519_dalek::Signer;
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state);

        let (_did_a, _key_a) = register_alias(&router, "alice").await;

        // Try to renew with a different DID
        let (fake_did, fake_key) = fresh_did_and_key();
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();
        let sig = fake_key.sign(challenge.as_bytes());
        let (status, body) = post_json(
            router,
            "/v1/renew",
            serde_json::json!({
                "alias": "alice@dj.jig",
                "did": fake_did,
                "challenge": challenge,
                "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "NOT_HOLDER");
    }

    #[tokio::test]
    async fn renew_404_for_unknown_alias() {
        use ed25519_dalek::Signer;
        let state = Arc::new(AppState::for_test().unwrap());
        let router = full_router(state);

        let (did, key) = fresh_did_and_key();
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();
        let sig = key.sign(challenge.as_bytes());
        let (status, body) = post_json(
            router,
            "/v1/renew",
            serde_json::json!({
                "alias": "nobody@dj.jig",
                "did": did,
                "challenge": challenge,
                "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "ALIAS_NOT_FOUND");
    }
}
