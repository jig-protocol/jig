//! POST /v1/register and GET /v1/challenge for the v0.0.2 nameserver.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine as _;
use ed25519_dalek::{Signer, Verifier};
use jig_pipeline::persist::StoredAliasAttestation;
use serde::{Deserialize, Serialize};

use crate::v0_0_2::AppState;

/// v0.0.2 attestation default TTL: 90 days, per the design spec.
pub(crate) const DEFAULT_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;

#[derive(Debug, Deserialize)]
pub struct RegisterReq {
    pub did: String,
    pub requested_alias: String,
    pub proof_of_control: String, // base64(sig over challenge)
    pub challenge: String,        // the hex nonce returned by GET /v1/challenge
}

#[derive(Debug, Serialize, Clone)]
pub struct Attestation {
    pub did: String,
    pub alias: String,
    pub ns_did: String,
    pub valid_from: i64,
    pub valid_until: i64,
    pub profile_ttl_seconds: u64,
    /// base64 ed25519 signature by the nameserver over the canonical attestation JSON
    pub sig: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

pub(crate) fn err(
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

fn validate_local_part(s: &str) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if s.is_empty() || s.len() > 24 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "BAD_LOCAL_PART",
            "local part must be 1..=24 chars",
        ));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "BAD_LOCAL_PART",
            "local part must match ^[a-zA-Z0-9_-]+$",
        ));
    }
    Ok(())
}

pub(crate) fn verify_proof_of_control(
    did_str: &str,
    challenge: &str,
    proof_b64: &str,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let proof_bytes = base64::engine::general_purpose::STANDARD
        .decode(proof_b64)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "BAD_PROOF_B64", "proof_of_control is not base64"))?;
    let did = jig_core::Did::from_did_jig_string(did_str)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "BAD_DID", "DID is not did:jig:z<base32> canonical form"))?;
    let pubkey_bytes = did
        .as_bytes()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "BAD_DID", "DID does not decode to a 32-byte ed25519 pubkey"))?;
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "BAD_DID", "DID pubkey invalid"))?;
    let sig = ed25519_dalek::Signature::from_slice(&proof_bytes)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "BAD_PROOF", "signature wrong length"))?;
    pubkey
        .verify(challenge.as_bytes(), &sig)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "PROOF_FAILED", "proof_of_control signature did not verify"))?;
    Ok(())
}

/// GET /v1/challenge — issue a fresh hex nonce. POST /v1/register expects
/// the nonce echoed back AND signed by the DID's secret key, proving control.
pub async fn get_challenge(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut nonce = [0u8; 32];
    use rand::Rng;
    rand::thread_rng().fill(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    state.remember_challenge(&nonce_hex).await;
    Json(serde_json::json!({ "challenge": nonce_hex }))
}

/// POST /v1/register
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<Attestation>, (StatusCode, Json<ErrorBody>)> {
    // 1. Validate local part
    validate_local_part(&req.requested_alias)?;

    // 2. Consume the challenge (must have been issued by GET /v1/challenge)
    if !state.take_challenge(&req.challenge).await {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_UNKNOWN",
            "challenge not recognized or already consumed (call GET /v1/challenge first)",
        ));
    }

    // 3. Verify proof_of_control over the challenge
    verify_proof_of_control(&req.did, &req.challenge, &req.proof_of_control)?;

    // 4. Compose full alias and check uniqueness
    let full_alias = format!("{}@{}", req.requested_alias, state.suffix());
    if let Some(existing_did) = state
        .alias_holder(&full_alias)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "PERSIST_ERROR", e.to_string()))?
    {
        if existing_did != req.did {
            return Err(err(
                StatusCode::CONFLICT,
                "ALIAS_TAKEN",
                format!("alias `{full_alias}` is already attested to a different DID"),
            ));
        }
        // Same DID re-registering — that's idempotent re-issuance with a fresh TTL.
    }

    // 5. Build + sign attestation (90d TTL)
    let now = chrono::Utc::now().timestamp();
    let mut attestation = Attestation {
        did: req.did.clone(),
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
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "SIGN_ERROR", e.to_string()))?;
    let sig = state.ingest_ctx.server_key.sign(&canonical);
    attestation.sig = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

    // 6. Persist as alias_attestation row (via the underlying SqliteStore)
    let stored = StoredAliasAttestation {
        did: attestation.did.clone(),
        alias: attestation.alias.clone(),
        ns_did: attestation.ns_did.clone(),
        valid_from: attestation.valid_from,
        valid_until: attestation.valid_until,
        attestation_bytes: serde_json::to_vec(&attestation)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "PERSIST_ERROR", e.to_string()))?,
    };
    let store = state.ingest_ctx.store.clone();
    tokio::task::spawn_blocking(move || store.upsert_alias_attestation(&stored))
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "JOIN_ERROR", e.to_string()))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "PERSIST_ERROR", e.to_string()))?;

    Ok(Json(attestation))
}

pub fn build_register_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/challenge", get(get_challenge))
        .route("/v1/register", post(register))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[tokio::test]
    async fn challenge_returns_hex_nonce() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state);
        let (status, body) = get_path(router, "/v1/challenge").await;
        assert_eq!(status, StatusCode::OK);
        let nonce = body["challenge"].as_str().unwrap();
        assert_eq!(nonce.len(), 64, "32-byte hex == 64 chars");
        // Decodes as hex
        assert!(hex::decode(nonce).is_ok());
    }

    #[tokio::test]
    async fn register_happy_path_issues_90d_attestation() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state.clone());

        // 1. Get a challenge
        let (_, ch_body) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch_body["challenge"].as_str().unwrap().to_string();

        // 2. Sign the challenge with a fresh keypair
        let (did_str, signing_key) = fresh_did_and_key();
        let sig = signing_key.sign(challenge.as_bytes());

        // 3. Register
        let body = serde_json::json!({
            "did": did_str,
            "requested_alias": "dj",
            "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            "challenge": challenge,
        });
        let (status, body) = post_json(router, "/v1/register", body).await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        assert_eq!(body["alias"], format!("dj@{}", state.suffix()));
        let valid_from = body["valid_from"].as_i64().unwrap();
        let valid_until = body["valid_until"].as_i64().unwrap();
        assert_eq!(valid_until - valid_from, DEFAULT_TTL_SECONDS);
        assert_eq!(body["profile_ttl_seconds"], DEFAULT_TTL_SECONDS as u64);
        assert!(body["sig"].as_str().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn register_rejects_invalid_local_part() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state);
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();

        // Contains @
        let body = serde_json::json!({
            "did": "did:jig:zfake",
            "requested_alias": "dj@bad",
            "proof_of_control": "AAAA",
            "challenge": challenge,
        });
        let (status, body) = post_json(router, "/v1/register", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "BAD_LOCAL_PART");
    }

    #[tokio::test]
    async fn register_rejects_oversized_local_part() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state);
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();

        let body = serde_json::json!({
            "did": "did:jig:zfake",
            "requested_alias": "a".repeat(25),
            "proof_of_control": "AAAA",
            "challenge": challenge,
        });
        let (status, _) = post_json(router, "/v1/register", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_rejects_unknown_challenge() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state);
        let body = serde_json::json!({
            "did": "did:jig:zfake",
            "requested_alias": "dj",
            "proof_of_control": "AAAA",
            "challenge": "deadbeef",
        });
        let (status, body) = post_json(router, "/v1/register", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "CHALLENGE_UNKNOWN");
    }

    #[tokio::test]
    async fn register_rejects_failed_proof() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state);

        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        let challenge = ch["challenge"].as_str().unwrap().to_string();

        let (did_str, _signing_key) = fresh_did_and_key();
        // Sign WRONG bytes — proof should fail
        let (_other_did, other_key) = fresh_did_and_key();
        let sig = other_key.sign(challenge.as_bytes());

        let body = serde_json::json!({
            "did": did_str,
            "requested_alias": "dj",
            "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            "challenge": challenge,
        });
        let (status, body) = post_json(router, "/v1/register", body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "PROOF_FAILED");
    }

    #[tokio::test]
    async fn register_then_register_again_rejects_with_different_did() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state);

        // First registration
        let (_, ch1) = get_path(router.clone(), "/v1/challenge").await;
        let challenge1 = ch1["challenge"].as_str().unwrap().to_string();
        let (did1, key1) = fresh_did_and_key();
        let sig1 = key1.sign(challenge1.as_bytes());
        let (status, _) = post_json(
            router.clone(),
            "/v1/register",
            serde_json::json!({
                "did": did1,
                "requested_alias": "dj",
                "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig1.to_bytes()),
                "challenge": challenge1,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Second registration with DIFFERENT DID for SAME alias — must conflict
        let (_, ch2) = get_path(router.clone(), "/v1/challenge").await;
        let challenge2 = ch2["challenge"].as_str().unwrap().to_string();
        let (did2, key2) = fresh_did_and_key();
        let sig2 = key2.sign(challenge2.as_bytes());
        let (status, body) = post_json(
            router,
            "/v1/register",
            serde_json::json!({
                "did": did2,
                "requested_alias": "dj",
                "proof_of_control": base64::engine::general_purpose::STANDARD.encode(sig2.to_bytes()),
                "challenge": challenge2,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "ALIAS_TAKEN");
    }
}
