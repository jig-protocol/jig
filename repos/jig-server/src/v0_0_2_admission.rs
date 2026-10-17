//! `/api/v1/admission` — where a new DID does this server's proof of work.
//!
//! Under `[auth.admission] unknown_dids = "proof-of-work"`, a DID this server
//! has no record of is refused (`PROOF_OF_WORK_REQUIRED`) until it posts a
//! nonce worth `pow_bits` for this server and itself
//! ([`jig_core::admission_pow`]), signed with its key. The proof is recorded
//! and the DID is known from then on.

use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jig_core::admission_pow;
use serde::{Deserialize, Serialize};

use crate::v0_0_2::AppState;
use crate::v0_0_2_blocks::ErrorBody;

pub fn build_admission_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/admission", post(prove).get(status))
        .with_state(state)
}

/// Whether the caller is admitted here without further work, and how much
/// work this server asks of a new DID.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdmissionStatus {
    pub did: String,
    pub proven: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pow_bits: Option<u8>,
}

/// `GET /api/v1/admission`, signed: the caller's own standing. Gate 1, then
/// gate 2 without charging the rate — a DID that owes work must be able to
/// ask whether it does — and only ever about the DID that signed, so it is no
/// oracle for who else uses this server.
async fn status(
    State(state): State<Arc<AppState>>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<AdmissionStatus>, Refusal> {
    let disclose = |outcome: &crate::auth::GateOutcome| {
        let (status, code, message) = state.auth.disclosure.disclose(outcome);
        refuse(
            StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED),
            code,
            message,
        )
    };
    let proof = crate::auth::authenticate::proof_from_headers(&headers)
        .ok_or_else(|| disclose(&crate::auth::GateOutcome::AuthMissing))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let did = {
        let mut guard = state
            .auth
            .replay_guard
            .lock()
            .expect("replay guard mutex poisoned");
        crate::auth::authenticate(&proof, "GET", uri.path(), b"", now_ms, &mut guard)
            .map_err(|outcome| disclose(&outcome))?
    }
    .to_did_jig_string();
    // Owing work is the one refusal answered with a status; any other is the
    // refusal itself. A DID admitted without a proof (a configured record, a
    // floor it meets, an open server) owes nothing.
    let proven = match state.auth.admit(&did) {
        Ok(()) => true,
        Err(crate::auth::GateOutcome::AdmissionProofRequired { .. }) => false,
        Err(outcome) => return Err(disclose(&outcome)),
    };
    Ok(Json(AdmissionStatus {
        proven,
        pow_bits: state.auth.pow_bits(),
        did,
    }))
}

#[derive(Debug, Deserialize)]
pub struct Proof {
    pub did: String,
    pub nonce: String,
    pub sig_b64: String,
}

type Refusal = (StatusCode, Json<ErrorBody>);

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> Refusal {
    (
        status,
        Json(ErrorBody {
            code: code.to_string(),
            message: message.into(),
        }),
    )
}

/// Longer than any nonce [`admission_pow::solve`] produces by far; the cap
/// keeps a request from making the server hash megabytes for nothing.
const MAX_NONCE_LEN: usize = 64;

async fn prove(
    State(state): State<Arc<AppState>>,
    Json(proof): Json<Proof>,
) -> Result<Json<AdmissionStatus>, Refusal> {
    if proof.nonce.len() > MAX_NONCE_LEN {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "BAD_NONCE",
            format!("the nonce is longer than {MAX_NONCE_LEN} bytes"),
        ));
    }
    let did = jig_core::Did::from_did_jig_string(proof.did.trim())
        .map_err(|_| refuse(StatusCode::BAD_REQUEST, "BAD_DID", "not a did:jig DID"))?;
    let key_bytes = did
        .as_bytes()
        .map_err(|_| refuse(StatusCode::BAD_REQUEST, "BAD_DID", "not a did:jig key"))?;
    let did = jig_core::Did::from_ed25519_pubkey(&key_bytes).to_did_jig_string();
    let server = state.server_did.to_did_jig_string();

    // The key holder, for this server: work done for someone else's key, or
    // replayed from another server, proves nothing here.
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| refuse(StatusCode::BAD_REQUEST, "BAD_DID", "not an ed25519 key"))?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(&proof.sig_b64)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "BAD_SIGNATURE",
                "malformed signature",
            )
        })?;
    key.verify(
        &admission_pow::signed_message(&server, &did, &proof.nonce),
        &sig,
    )
    .map_err(|_| {
        refuse(
            StatusCode::UNAUTHORIZED,
            "BAD_SIGNATURE",
            "the proof is not signed by the DID's key",
        )
    })?;

    if state.auth.banned(&did) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "NOT_ADMITTED",
            "this identity is refused by this server",
        ));
    }

    // A server that asks for no work records none and needs none.
    let Some(bits) = state.auth.pow_bits() else {
        return Ok(Json(AdmissionStatus {
            proven: state.auth.proven(&did),
            pow_bits: None,
            did,
        }));
    };
    if !admission_pow::meets(&server, &did, &proof.nonce, bits) {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "PROOF_OF_WORK_INSUFFICIENT",
            format!("the nonce is not {bits} bits of work for this server and DID"),
        ));
    }
    state.auth.record_proof(&did, bits).map_err(|e| {
        tracing::error!(error = %e, did = %did, "recording an admission proof failed");
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PERSIST_ERROR",
            "could not record the proof",
        )
    })?;
    Ok(Json(AdmissionStatus {
        did,
        proven: true,
        pow_bits: Some(bits),
    }))
}
