//! POST /v1/register and GET /v1/challenge for the v0.0.2 nameserver, plus
//! the pieces register, renew, rotate and resolve share: action-bound proofs
//! of control, and the signed binding the nameserver stores and serves
//! (JEP-0004 rules 8, 10 and 21).

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Verifier;
use jig_core::naming::{self, Action, Name, NamingError, ReachabilityRecord};
use jig_pipeline::persist::StoredAliasAttestation;
use serde::{Deserialize, Serialize};

use crate::v0_0_2::AppState;
use crate::v0_0_2_policy::{Admission, Refusal, SuffixPolicy};

/// v0.0.2 attestation default TTL: 90 days, per the design spec.
pub(crate) const DEFAULT_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;

#[derive(Debug, Deserialize)]
pub struct RegisterReq {
    pub did: String,
    pub requested_alias: String,
    /// Which served suffix to register under. May be left out when the
    /// nameserver serves exactly one.
    #[serde(default)]
    pub suffix: Option<String>,
    /// Unpadded base64url of the DID's COSE_Sign1 over
    /// `naming::proof_payload(Register, ns_did, alias@suffix, challenge)`.
    pub proof_of_control: String,
    /// The hex nonce returned by GET /v1/challenge.
    pub challenge: String,
    /// Optional unpadded base64url of a reachability record signed by `did`.
    #[serde(default)]
    pub reachability: Option<String>,
    /// Reserved for lane R's admission proof-of-work (R1). Accepted and
    /// ignored until R1 defines it.
    #[serde(default)]
    pub pow: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

pub(crate) type ApiError = (StatusCode, Json<ErrorBody>);

pub(crate) fn err(status: StatusCode, code: &'static str, msg: impl Into<String>) -> ApiError {
    (
        status,
        Json(ErrorBody {
            code: code.to_string(),
            message: msg.into(),
        }),
    )
}

fn internal(code: &'static str) -> impl Fn(String) -> ApiError {
    move |msg| err(StatusCode::INTERNAL_SERVER_ERROR, code, msg)
}

pub(crate) fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn from_b64u(field: &'static str, s: &str) -> Result<Vec<u8>, ApiError> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "BAD_ENCODING",
            format!("`{field}` is not unpadded base64url"),
        )
    })
}

fn validate_local_part(s: &str) -> Result<(), ApiError> {
    if s.is_empty() || s.len() > naming::MAX_ALIAS_LEN {
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

/// Parse and lowercase a full `alias@suffix` (JEP-0004 rule 1).
pub(crate) fn parse_name(full: &str) -> Result<Name, ApiError> {
    Name::parse(full).map_err(|e| err(StatusCode::BAD_REQUEST, "INVALID_NAME", e.to_string()))
}

fn unknown_suffix(suffix: &str) -> ApiError {
    err(
        StatusCode::NOT_FOUND,
        "UNKNOWN_SUFFIX",
        format!("this nameserver does not serve the suffix `{suffix}`"),
    )
}

/// Parse a full name and check this nameserver serves its suffix.
pub(crate) fn served_name(state: &AppState, full: &str) -> Result<Name, ApiError> {
    let name = parse_name(full)?;
    if state.suffixes.get(&name.suffix).is_none() {
        return Err(unknown_suffix(&name.suffix));
    }
    Ok(name)
}

/// The suffix a registration asks for, or the only one served.
fn requested_suffix<'a>(
    state: &'a AppState,
    suffix: Option<&str>,
) -> Result<&'a SuffixPolicy, ApiError> {
    match suffix {
        Some(s) => {
            let s = s.to_ascii_lowercase();
            state.suffixes.get(&s).ok_or_else(|| unknown_suffix(&s))
        }
        None => state.suffixes.only().ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "SUFFIX_REQUIRED",
                "this nameserver serves several suffixes; name one in `suffix`",
            )
        }),
    }
}

fn refused(refusal: Refusal, policy: &SuffixPolicy) -> ApiError {
    match refusal {
        Refusal::Closed => err(
            StatusCode::FORBIDDEN,
            "REGISTRATION_CLOSED",
            format!("registration on `{}` is closed", policy.suffix),
        ),
        Refusal::TooShort { min } => err(
            StatusCode::BAD_REQUEST,
            "ALIAS_TOO_SHORT",
            format!(
                "aliases on `{}` are at least {min} characters",
                policy.suffix
            ),
        ),
        Refusal::Reserved { word } => err(
            StatusCode::FORBIDDEN,
            "ALIAS_RESERVED",
            format!(
                "alias is reserved on `{}` (matches `{word}`)",
                policy.suffix
            ),
        ),
    }
}

/// The alias `did` already holds under `suffix` here, if any.
pub(crate) async fn name_held_by(
    state: &AppState,
    did: &str,
    suffix: &str,
) -> Result<Option<String>, ApiError> {
    let now = chrono::Utc::now().timestamp();
    let store = state.ingest_ctx.store.clone();
    let (did, ns_did, suffix) = (did.to_string(), state.ns_did_string(), suffix.to_string());
    tokio::task::spawn_blocking(move || store.alias_held_by(&did, &ns_did, &suffix, now))
        .await
        .map_err(|e| internal("JOIN_ERROR")(e.to_string()))?
        .map_err(|e| internal("PERSIST_ERROR")(e.to_string()))
}

/// Refuse to bind a second name under one suffix to `did`: the store keeps
/// one name per DID per suffix, so the first would be silently dropped.
pub(crate) async fn refuse_second_name(
    state: &AppState,
    did: &str,
    name: &Name,
) -> Result<(), ApiError> {
    let alias = name.as_alias();
    match name_held_by(state, did, &name.suffix).await? {
        Some(held) if held != alias => Err(err(
            StatusCode::CONFLICT,
            "DID_HOLDS_NAME",
            format!("this DID already holds `{held}`; one name per DID per suffix"),
        )),
        _ => Ok(()),
    }
}

/// Check that `did` signed a proof of control for `action` on `alias` at this
/// nameserver, over `challenge` (JEP-0004 rule 10). A proof over the bare
/// challenge, or one made for another action, alias or nameserver, fails.
pub(crate) fn verify_action_proof(
    state: &AppState,
    action: Action,
    did: &str,
    alias: &str,
    challenge: &str,
    proof_b64u: &str,
) -> Result<(), ApiError> {
    let envelope = from_b64u("proof_of_control", proof_b64u)?;
    naming::verify_proof(
        did,
        &envelope,
        action,
        &state.ns_did_string(),
        alias,
        challenge,
    )
    .map_err(|e| match e {
        NamingError::BadDid(_) => err(
            StatusCode::BAD_REQUEST,
            "BAD_DID",
            "DID is not did:jig:z<base32> canonical form",
        ),
        _ => err(
            StatusCode::UNAUTHORIZED,
            "PROOF_FAILED",
            "proof_of_control is not a proof by this DID for this action, alias and challenge",
        ),
    })
}

/// A raw ed25519 signature by `did_str` over the challenge's text. Only
/// `/v1/rotate` still takes these, until lane I's I3 moves rotation onto
/// links; register and renew take [`verify_action_proof`].
pub(crate) fn verify_bare_challenge_sig(
    did_str: &str,
    challenge: &str,
    sig_b64: &str,
) -> Result<(), ApiError> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|_| {
            err(
                StatusCode::BAD_REQUEST,
                "BAD_PROOF_B64",
                "signature is not base64",
            )
        })?;
    let did = jig_core::Did::from_did_jig_string(did_str).map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "BAD_DID",
            "DID is not did:jig:z<base32> canonical form",
        )
    })?;
    let pubkey_bytes = did.as_bytes().map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "BAD_DID",
            "DID does not decode to a 32-byte ed25519 pubkey",
        )
    })?;
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "BAD_DID", "DID pubkey invalid"))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "BAD_PROOF",
            "signature wrong length",
        )
    })?;
    pubkey.verify(challenge.as_bytes(), &sig).map_err(|_| {
        err(
            StatusCode::UNAUTHORIZED,
            "PROOF_FAILED",
            "signature did not verify",
        )
    })
}

/// Parse an optional reachability record and check it is `did`'s own
/// (JEP-0004 rule 21).
pub(crate) fn parse_reachability(
    did: &str,
    b64u_record: Option<&str>,
) -> Result<Option<ReachabilityRecord>, ApiError> {
    let Some(s) = b64u_record else {
        return Ok(None);
    };
    let record =
        ReachabilityRecord::from_envelope(&from_b64u("reachability", s)?).map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                "BAD_REACHABILITY",
                format!("reachability record does not verify: {e}"),
            )
        })?;
    if record.did != did {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "BAD_REACHABILITY",
            "reachability record is signed by a different DID than the registrant",
        ));
    }
    Ok(Some(record))
}

/// Consume a challenge for a request by `did` on `alias`. Called only after
/// the proof verified, so a bad proof leaves the challenge usable, and of two
/// proofs racing for one challenge only one gets `true`.
pub(crate) async fn consume_challenge(
    state: &AppState,
    challenge: &str,
    did: &str,
    alias: &str,
) -> Result<(), ApiError> {
    if state.take_challenge(challenge, did, alias).await {
        Ok(())
    } else {
        Err(err(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_UNKNOWN",
            "challenge not recognized, expired, already consumed or issued for another \
             DID or name (call GET /v1/challenge first)",
        ))
    }
}

/// One alias binding as the nameserver keeps and serves it: the attestation it
/// signed, and the holder's reachability record if one was registered.
pub(crate) struct Binding {
    pub attestation: naming::Attestation,
    pub reachability: Option<ReachabilityRecord>,
}

/// What `attestation_bytes` holds: the same envelopes the resolve body carries.
#[derive(Serialize, Deserialize)]
struct StoredBinding {
    attestation: String,
    reachability: Option<String>,
}

/// A stored row in the encoding from before attestations were COSE
/// envelopes. [`Binding::from_row`] re-signs these from the row's columns,
/// which is what makes rewriting those columns safe.
pub(crate) fn is_legacy_row(attestation_bytes: &[u8]) -> bool {
    serde_json::from_slice::<StoredBinding>(attestation_bytes).is_err()
}

impl Binding {
    /// The body of resolve, register, renew and rotate. `links` stays empty
    /// until lane I's I3 defines rotation links.
    ///
    /// `did`, `alias` and `valid_until` are unsigned, transitional hints,
    /// removed after F1 slice 6: they keep today's readers working, which
    /// already trust an unsigned `did`. A verified client reads only
    /// `attestation`. The test `the_response_keys_are_pinned` names the
    /// removal condition.
    pub fn response(&self) -> serde_json::Value {
        serde_json::json!({
            "attestation": b64u(&self.attestation.envelope),
            "links": [],
            "reachability": self.reachability.as_ref().map(|r| b64u(&r.envelope)),
            "did": self.attestation.did,
            "alias": self.attestation.alias,
            "valid_until": self.attestation.valid_until,
        })
    }

    fn stored_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&StoredBinding {
            attestation: b64u(&self.attestation.envelope),
            reachability: self.reachability.as_ref().map(|r| b64u(&r.envelope)),
        })
        .expect("serializing two strings cannot fail")
    }

    /// Read a stored row back. Rows written before attestations were COSE
    /// envelopes hold the old JSON; this nameserver re-signs those from the
    /// row's own fields, since the claim is unchanged.
    pub fn from_row(state: &AppState, row: &StoredAliasAttestation) -> Result<Self, ApiError> {
        let corrupt = internal("STORED_ATTESTATION_INVALID");
        match serde_json::from_slice::<StoredBinding>(&row.attestation_bytes) {
            Ok(stored) => {
                let decode = |s: &str| {
                    URL_SAFE_NO_PAD
                        .decode(s)
                        .map_err(|e| corrupt(e.to_string()))
                };
                let attestation = naming::Attestation::from_envelope(&decode(&stored.attestation)?)
                    .map_err(|e| corrupt(e.to_string()))?;
                let reachability = stored
                    .reachability
                    .as_deref()
                    .map(|r| {
                        ReachabilityRecord::from_envelope(&decode(r)?)
                            .map_err(|e| corrupt(e.to_string()))
                    })
                    .transpose()?;
                Ok(Self {
                    attestation,
                    reachability,
                })
            }
            Err(_) if row.ns_did == state.ns_did_string() => Ok(Self {
                attestation: naming::Attestation::sign(
                    &state.ingest_ctx.server_key,
                    &row.did,
                    &row.alias,
                    row.valid_from,
                    row.valid_until,
                ),
                reachability: None,
            }),
            Err(e) => Err(corrupt(e.to_string())),
        }
    }
}

/// The current binding for `alias`, if one is valid now.
pub(crate) async fn current_binding(
    state: &Arc<AppState>,
    alias: &str,
) -> Result<Option<Binding>, ApiError> {
    let now = chrono::Utc::now().timestamp();
    let store = state.ingest_ctx.store.clone();
    let alias = alias.to_string();
    let row = tokio::task::spawn_blocking(move || store.find_alias_attestation(&alias, now))
        .await
        .map_err(|e| internal("JOIN_ERROR")(e.to_string()))?
        .map_err(|e| internal("PERSIST_ERROR")(e.to_string()))?;
    row.map(|r| Binding::from_row(state, &r)).transpose()
}

/// Sign a fresh 90-day attestation binding `alias` to `did`, store it with
/// `reachability`, and return the response body.
pub(crate) async fn issue_and_persist(
    state: &Arc<AppState>,
    did: &str,
    alias: &str,
    reachability: Option<ReachabilityRecord>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let now = chrono::Utc::now().timestamp();
    let binding = Binding {
        attestation: naming::Attestation::sign(
            &state.ingest_ctx.server_key,
            did,
            alias,
            now,
            now + DEFAULT_TTL_SECONDS,
        ),
        reachability,
    };
    let att = &binding.attestation;
    let stored = StoredAliasAttestation {
        did: att.did.clone(),
        alias: att.alias.clone(),
        ns_did: att.ns_did.clone(),
        valid_from: att.valid_from,
        valid_until: att.valid_until,
        attestation_bytes: binding.stored_bytes(),
    };
    let store = state.ingest_ctx.store.clone();
    tokio::task::spawn_blocking(move || store.upsert_alias_attestation(&stored))
        .await
        .map_err(|e| internal("JOIN_ERROR")(e.to_string()))?
        .map_err(|e| internal("PERSIST_ERROR")(e.to_string()))?;
    Ok(Json(binding.response()))
}

#[derive(Debug, Deserialize)]
pub struct ChallengeQuery {
    /// The DID that will use the challenge.
    did: Option<String>,
    /// The full `alias@suffix` it will be used on.
    name: Option<String>,
}

/// GET /v1/challenge — issue a fresh hex nonce. Register and renew sign it
/// into an action-bound proof of control.
///
/// `?did=` and `?name=` bind it: it is then consumed only by that DID on that
/// name, and is what proof-of-work (lane R's R1) sets its effort from. Both
/// are optional until R1, so clients that send neither keep working.
pub async fn get_challenge(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let name = query
        .name
        .as_deref()
        .map(|n| parse_name(n).map(|n| n.as_alias()))
        .transpose()?;
    if let Some(did) = query.did.as_deref() {
        jig_core::Did::from_did_jig_string(did).map_err(|_| {
            err(
                StatusCode::BAD_REQUEST,
                "BAD_DID",
                "DID is not did:jig:z<base32> canonical form",
            )
        })?;
    }
    let mut nonce = [0u8; 32];
    use rand::Rng;
    rand::rng().fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    state.remember_challenge(&nonce_hex, query.did, name).await;
    Ok(Json(serde_json::json!({ "challenge": nonce_hex })))
}

/// POST /v1/register
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_local_part(&req.requested_alias)?;
    let policy = requested_suffix(&state, req.suffix.as_deref())?;
    let name = parse_name(&format!("{}@{}", req.requested_alias, policy.suffix))?;
    let alias = name.as_alias();
    let admission = policy
        .admit(&req.did, &name.alias)
        .map_err(|r| refused(r, policy))?;

    verify_action_proof(
        &state,
        Action::Register,
        &req.did,
        &alias,
        &req.challenge,
        &req.proof_of_control,
    )?;
    let reachability = parse_reachability(&req.did, req.reachability.as_deref())?;
    consume_challenge(&state, &req.challenge, &req.did, &alias).await?;

    // Same DID re-registering is idempotent re-issuance with a fresh TTL.
    if let Some(existing_did) = state
        .alias_holder(&alias)
        .await
        .map_err(|e| internal("PERSIST_ERROR")(e.to_string()))?
        && existing_did != req.did
    {
        return Err(err(
            StatusCode::CONFLICT,
            "ALIAS_TAKEN",
            format!("alias `{alias}` is already attested to a different DID"),
        ));
    }
    refuse_second_name(&state, &req.did, &name).await?;

    if admission == Admission::Allowlisted {
        tracing::info!(
            alias = %alias,
            did_tag = %jig_core::did::log_tag(&req.did),
            "registered an allowlisted alias"
        );
    }
    issue_and_persist(&state, &req.did, &alias, reachability).await
}

pub fn build_register_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/challenge", get(get_challenge))
        .route("/v1/register", post(register))
        .with_state(state)
}

/// Helpers for this crate's tests: a fresh identity and the proofs a client
/// sends.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use ed25519_dalek::SigningKey;

    pub fn fresh_did_and_key() -> (String, SigningKey) {
        use rand::Rng;
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let key = SigningKey::from_bytes(&secret);
        (naming_did(&key), key)
    }

    pub fn naming_did(key: &SigningKey) -> String {
        jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    /// The `proof_of_control` a client sends for `action` on `alias`.
    pub fn proof(
        key: &SigningKey,
        state: &AppState,
        action: Action,
        alias: &str,
        challenge: &str,
    ) -> String {
        b64u(&naming::sign_proof(
            key,
            action,
            &state.ns_did_string(),
            alias,
            challenge,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use axum::{Router, body::Body, http::Request};
    use ed25519_dalek::Signer;
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

    async fn challenge(router: &Router) -> String {
        let (_, ch) = get_path(router.clone(), "/v1/challenge").await;
        ch["challenge"].as_str().unwrap().to_string()
    }

    fn attestation_of(body: &serde_json::Value) -> naming::Attestation {
        let envelope = URL_SAFE_NO_PAD
            .decode(body["attestation"].as_str().expect("attestation field"))
            .unwrap();
        naming::Attestation::from_envelope(&envelope).expect("attestation verifies")
    }

    #[tokio::test]
    async fn challenge_returns_hex_nonce() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state);
        let (status, body) = get_path(router, "/v1/challenge").await;
        assert_eq!(status, StatusCode::OK);
        let nonce = body["challenge"].as_str().unwrap();
        assert_eq!(nonce.len(), 64, "32-byte hex == 64 chars");
        assert!(hex::decode(nonce).is_ok());
    }

    #[tokio::test]
    async fn register_issues_a_verifiable_90d_attestation() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state.clone());
        let challenge = challenge(&router).await;
        let (did, key) = fresh_did_and_key();
        let alias = format!("dj@{}", state.suffix());

        let (status, body) = post_json(
            router,
            "/v1/register",
            serde_json::json!({
                "did": did,
                "requested_alias": "DJ",
                "proof_of_control": proof(&key, &state, Action::Register, &alias, &challenge),
                "challenge": challenge,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        let att = attestation_of(&body);
        assert_eq!(att.alias, alias, "the alias is stored lowercase");
        assert_eq!(att.did, did);
        assert_eq!(att.ns_did, state.ns_did_string());
        assert_eq!(att.valid_until - att.valid_from, DEFAULT_TTL_SECONDS);
        assert_eq!(body["links"], serde_json::json!([]));
        assert_eq!(body["reachability"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn a_proof_over_the_bare_challenge_is_refused() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state.clone());
        let challenge = challenge(&router).await;
        let (did, key) = fresh_did_and_key();
        let bare = b64u(&key.sign(challenge.as_bytes()).to_bytes());

        let (status, body) = post_json(
            router,
            "/v1/register",
            serde_json::json!({
                "did": did,
                "requested_alias": "dj",
                "proof_of_control": bare,
                "challenge": challenge,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "PROOF_FAILED");
    }

    #[tokio::test]
    async fn a_failed_proof_leaves_the_challenge_usable() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state.clone());
        let challenge = challenge(&router).await;
        let (did, key) = fresh_did_and_key();
        let (_, other_key) = fresh_did_and_key();
        let alias = format!("dj@{}", state.suffix());

        let wrong = proof(&other_key, &state, Action::Register, &alias, &challenge);
        let (status, _) = post_json(
            router.clone(),
            "/v1/register",
            serde_json::json!({
                "did": did, "requested_alias": "dj",
                "proof_of_control": wrong, "challenge": challenge,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let right = proof(&key, &state, Action::Register, &alias, &challenge);
        let (status, body) = post_json(
            router.clone(),
            "/v1/register",
            serde_json::json!({
                "did": did, "requested_alias": "dj",
                "proof_of_control": right, "challenge": challenge,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={body}");

        // ...and the good proof consumed it.
        let (status, body) = post_json(
            router,
            "/v1/register",
            serde_json::json!({
                "did": did, "requested_alias": "dj",
                "proof_of_control": proof(&key, &state, Action::Register, &alias, &challenge),
                "challenge": challenge,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "CHALLENGE_UNKNOWN");
    }

    #[tokio::test]
    async fn a_proof_for_another_alias_or_nameserver_is_refused() {
        let state = Arc::new(AppState::for_test().unwrap());
        let other_ns = AppState::for_test().unwrap();
        let router = build_register_router(state.clone());
        let challenge = challenge(&router).await;
        let (did, key) = fresh_did_and_key();
        let alias = format!("dj@{}", state.suffix());

        for proof_of_control in [
            proof(&key, &state, Action::Register, "someone@dj.jig", &challenge),
            proof(&key, &other_ns, Action::Register, &alias, &challenge),
            proof(&key, &state, Action::Renew, &alias, &challenge),
        ] {
            let (status, body) = post_json(
                router.clone(),
                "/v1/register",
                serde_json::json!({
                    "did": did, "requested_alias": "dj",
                    "proof_of_control": proof_of_control, "challenge": challenge,
                }),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body}");
            assert_eq!(body["code"], "PROOF_FAILED");
        }
    }

    #[tokio::test]
    async fn register_rejects_invalid_local_part() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state);
        let challenge = challenge(&router).await;
        let (status, body) = post_json(
            router,
            "/v1/register",
            serde_json::json!({
                "did": "did:jig:zfake", "requested_alias": "dj@bad",
                "proof_of_control": "AAAA", "challenge": challenge,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "BAD_LOCAL_PART");
    }

    #[tokio::test]
    async fn register_rejects_oversized_local_part() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state);
        let challenge = challenge(&router).await;
        let (status, _) = post_json(
            router,
            "/v1/register",
            serde_json::json!({
                "did": "did:jig:zfake", "requested_alias": "a".repeat(25),
                "proof_of_control": "AAAA", "challenge": challenge,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_rejects_unknown_challenge() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state.clone());
        let (did, key) = fresh_did_and_key();
        let alias = format!("dj@{}", state.suffix());
        let (status, body) = post_json(
            router,
            "/v1/register",
            serde_json::json!({
                "did": did, "requested_alias": "dj",
                "proof_of_control": proof(&key, &state, Action::Register, &alias, "deadbeef"),
                "challenge": "deadbeef",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "CHALLENGE_UNKNOWN");
    }

    #[tokio::test]
    async fn register_then_register_again_rejects_with_different_did() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state.clone());
        let alias = format!("dj@{}", state.suffix());

        let challenge1 = challenge(&router).await;
        let (did1, key1) = fresh_did_and_key();
        let (status, _) = post_json(
            router.clone(),
            "/v1/register",
            serde_json::json!({
                "did": did1, "requested_alias": "dj",
                "proof_of_control": proof(&key1, &state, Action::Register, &alias, &challenge1),
                "challenge": challenge1,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let challenge2 = challenge(&router).await;
        let (did2, key2) = fresh_did_and_key();
        let (status, body) = post_json(
            router,
            "/v1/register",
            serde_json::json!({
                "did": did2, "requested_alias": "dj",
                "proof_of_control": proof(&key2, &state, Action::Register, &alias, &challenge2),
                "challenge": challenge2,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "ALIAS_TAKEN");
    }

    #[tokio::test]
    async fn register_stores_the_registrants_reachability_record() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state.clone());
        let challenge = challenge(&router).await;
        let (did, key) = fresh_did_and_key();
        let alias = format!("dj@{}", state.suffix());
        let record = ReachabilityRecord::sign(
            &key,
            vec![("did:jig:zserver".into(), "wss://example.org".into())],
            1,
        );

        let (status, body) = post_json(
            router,
            "/v1/register",
            serde_json::json!({
                "did": did, "requested_alias": "dj",
                "proof_of_control": proof(&key, &state, Action::Register, &alias, &challenge),
                "challenge": challenge,
                "reachability": b64u(&record.envelope),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        assert_eq!(body["reachability"], b64u(&record.envelope));
    }

    #[tokio::test]
    async fn register_refuses_someone_elses_reachability_record() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state.clone());
        let challenge = challenge(&router).await;
        let (did, key) = fresh_did_and_key();
        let (_, other_key) = fresh_did_and_key();
        let alias = format!("dj@{}", state.suffix());
        let record = ReachabilityRecord::sign(&other_key, vec![], 1);

        let (status, body) = post_json(
            router.clone(),
            "/v1/register",
            serde_json::json!({
                "did": did, "requested_alias": "dj",
                "proof_of_control": proof(&key, &state, Action::Register, &alias, &challenge),
                "challenge": challenge,
                "reachability": b64u(&record.envelope),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "BAD_REACHABILITY");
        // Refused before the challenge was consumed.
        assert!(state.take_challenge(&challenge, &did, &alias).await);
    }

    #[tokio::test]
    async fn an_arbitrary_pow_field_is_accepted_and_ignored() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_register_router(state.clone());
        let challenge = challenge(&router).await;
        let (did, key) = fresh_did_and_key();
        let alias = format!("dj@{}", state.suffix());

        let (status, body) = post_json(
            router,
            "/v1/register",
            serde_json::json!({
                "did": did, "requested_alias": "dj",
                "proof_of_control": proof(&key, &state, Action::Register, &alias, &challenge),
                "challenge": challenge,
                "pow": { "anything": [1, 2, 3] },
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={body}");
    }
}
