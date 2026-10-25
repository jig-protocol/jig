//! `/api/v1/admission` — where a new DID does this server's proof of work.
//!
//! Under `[auth.admission] unknown_dids = "proof-of-work"`, a DID this server
//! has no record of is refused (`PROOF_OF_WORK_REQUIRED`) until it posts work
//! for this server and itself, signed with its key. The proof is recorded and
//! the DID is known from then on.
//!
//! The work is JEP-0008's `admit` puzzle (`{did, pow, sig_b64}`), at the
//! effort the admission controller asks ([`crate::auth::admission_effort`]).
//! The legacy `jig-admission-pow-v1` form (`{did, nonce, sig_b64}`) is
//! accepted for one release ([`jig_core::admission_pow`]).
//! Either way the work is checked before the signature (JEP-0008 rule 10).

use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jig_core::admission_pow;
use serde::{Deserialize, Serialize};

use crate::auth::admission_effort::bits_at_least;
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
    /// The same work as a JEP-0008 effort, `2^pow_bits`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effort: Option<u64>,
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
        effort: state.auth.admission_effort().map(|e| e.get()),
        did,
    }))
}

/// The body of `POST /api/v1/admission`: the JEP-0008 form, or the legacy
/// one for one release.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Proof {
    Pow {
        did: String,
        pow: jig_core::pow::Proof,
        sig_b64: String,
    },
    Legacy {
        did: String,
        nonce: String,
        sig_b64: String,
    },
}

impl Proof {
    fn did(&self) -> &str {
        match self {
            Proof::Pow { did, .. } | Proof::Legacy { did, .. } => did,
        }
    }

    fn sig_b64(&self) -> &str {
        match self {
            Proof::Pow { sig_b64, .. } | Proof::Legacy { sig_b64, .. } => sig_b64,
        }
    }
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
    if let Proof::Legacy { nonce, .. } = &proof
        && nonce.len() > MAX_NONCE_LEN
    {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "BAD_NONCE",
            format!("the nonce is longer than {MAX_NONCE_LEN} bytes"),
        ));
    }
    // Only the canonical DID and the bits are kept, never the proof itself,
    // so a re-cased spelling is read as its key.
    let did = jig_core::Did::canonicalize(proof.did().trim())
        .map_err(|_| refuse(StatusCode::BAD_REQUEST, "BAD_DID", "not a did:jig DID"))?;
    let key_bytes = did
        .as_bytes()
        .map_err(|_| refuse(StatusCode::BAD_REQUEST, "BAD_DID", "not a did:jig key"))?;
    let did = jig_core::Did::from_ed25519_pubkey(&key_bytes).to_did_jig_string();
    let server = state.server_did.to_did_jig_string();

    // Checked against the least effort asked within an offer's lifetime, so
    // a rise while the client solved does not refuse it. `None`: no work has
    // been asked lately, and none is checked or recorded.
    let floor = state.auth.admission_floor();

    // The work first: one digest, before the signature or any store read
    // (JEP-0008 rule 10). Work done for another server or another key fails
    // here, whoever signed it.
    if let Some(floor) = floor {
        match &proof {
            Proof::Pow { pow, .. } => admission_pow::puzzle(&server, &did)
                .check(pow, floor)
                .map_err(|e| {
                    refuse(
                        StatusCode::BAD_REQUEST,
                        "PROOF_OF_WORK_INSUFFICIENT",
                        format!("not an admission proof for this server and DID: {e}"),
                    )
                })?,
            Proof::Legacy { nonce, .. } => {
                let bits = bits_at_least(floor);
                if !admission_pow::meets(&server, &did, nonce, bits) {
                    return Err(refuse(
                        StatusCode::BAD_REQUEST,
                        "PROOF_OF_WORK_INSUFFICIENT",
                        format!("the nonce is not {bits} bits of work for this server and DID"),
                    ));
                }
            }
        }
    }
    let (proof_bits, message) = match &proof {
        Proof::Pow { pow, .. } => (
            admission_pow::bits_for_effort(pow.effort),
            admission_pow::proof_message(&server, &did, pow),
        ),
        Proof::Legacy { nonce, .. } => (
            floor.map_or(0, bits_at_least),
            admission_pow::signed_message(&server, &did, nonce),
        ),
    };

    // Then the key holder: work done for someone else's key proves nothing
    // here.
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| refuse(StatusCode::BAD_REQUEST, "BAD_DID", "not an ed25519 key"))?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(proof.sig_b64())
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "BAD_SIGNATURE",
                "malformed signature",
            )
        })?;
    key.verify(&message, &sig).map_err(|_| {
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

    // A server that asks for no work records none and needs none: a proof
    // recorded while idle would let anyone stock proven keys for free ahead
    // of a flood.
    if floor.is_none() {
        return Ok(Json(AdmissionStatus {
            proven: state.auth.proven(&did),
            pow_bits: None,
            effort: None,
            did,
        }));
    }

    state.auth.record_proof(&did, proof_bits).map_err(|e| {
        tracing::error!(
            error = %e,
            did = %jig_core::did::log_tag(&did),
            "recording an admission proof failed"
        );
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PERSIST_ERROR",
            "could not record the proof",
        )
    })?;
    Ok(Json(AdmissionStatus {
        did,
        proven: true,
        pow_bits: state.auth.pow_bits(),
        effort: state.auth.admission_effort().map(|e| e.get()),
    }))
}
