//! This server as a custodian of key packages (JEP-0005 rule 21).
//!
//! - `PUT  /api/v1/reach/:did` — keep a DID's reachability record, if it
//!   lists this server
//! - `GET  /api/v1/reach/:did` — serve it back
//! - `POST /api/v1/custody/:did/requests` — release one of the DID's key
//!   packages to a signed request
//! - `GET  /api/v1/custody/:did/releases` — the DID reads its release log
//! - `PUT  /api/v1/custody/:did/policy` — keep the DID's own release policy
//!   (JEP-0005 rule 21b)
//! - `GET  /api/v1/custody/:did/requests?state=held` — the DID reads the
//!   requests held for its decision (rule 21c)
//! - `POST /api/v1/custody/:did/requests/:request_id/decision` — the DID
//!   approves or refuses one
//!
//! A custodian of `D` is a server `D`'s reachability record lists and that
//! holds `D`'s packages (published through `v0_0_2_mls`). Another server's
//! member adding `D` to a channel asks a custodian directly, so the channel's
//! owner takes no part. A package is self-signed by `D`, so a custodian can
//! withhold one but never substitute one: the adder checks the package's
//! signature and DID before it commits.
//!
//! A DID that stored its own release policy here is released by it: a
//! requester it names, or any if it says so, is released to; anyone else is
//! held, answered `409 HELD`, until the DID decides. An approval lets that
//! requester's next request for the DID and channel through, once. For a DID
//! with no policy of its own, `[custody] release` is this server's policy
//! (DJ 2026-11-26). `closed` releases nothing whatever a DID's policy says:
//! the operator's choice not to serve others comes first. The limits below
//! bound how fast any requester, or all of them together, can draw down a
//! DID's stock, with a policy or without. A DID's
//! last-resort package is handed out but never consumed, so a drained stock
//! leaves the DID reachable.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post, put},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jig_config::v0_0_2_server::ReleasePolicy;
use jig_core::contract::{KpDecision, KpRequest, LocalAdds, ReleasePolicy as SignedPolicy};
use jig_core::naming::ReachabilityRecord;
use jig_pipeline::custody_policy::{Decided, Held, NewHold};
use jig_pipeline::persist::{LimitHit, Release, ReleaseAsk};
use serde::{Deserialize, Serialize};

use crate::v0_0_2::AppState;
use crate::v0_0_2_blocks::{ErrorBody, err, optional_caller, persist_err, refuse};

/// Most servers a reachability record kept here may list.
pub const MAX_RECORD_SERVERS: usize = 16;
/// Seconds within which the same requester asking again for the same DID and
/// channel gets the package it was already given, not a new one.
pub const REPEAT_WINDOW_SECS: i64 = 600;
/// Most release-log entries one read returns.
pub const MAX_LOG_ENTRIES: u32 = 200;
/// Most requests held for one DID at once (JEP-0005 rule 21c). Past it, a
/// new request is refused, not held: the DID decides the ones it has first.
pub const MAX_HELD_PER_DID: usize = 256;
/// How long an approval stays good for (rule 21c).
pub const GRANT_SECS: i64 = 24 * 60 * 60;

type Refusal = (StatusCode, Json<ErrorBody>);

#[derive(Debug, Serialize, Deserialize)]
pub struct RecordBody {
    pub record_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredBody {
    /// Whether this record replaced the one kept before.
    pub stored: bool,
    /// The `seq` of the record kept now.
    pub seq: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestBody {
    /// A `jig-kp-request-v1`, base64.
    pub request_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyBody {
    /// `did`'s `jig-kp-release-policy-v1`, base64.
    pub policy_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecisionBody {
    /// `did`'s `jig-kp-decision-v1`, base64.
    pub decision_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecidedBody {
    pub approved: bool,
}

/// `?state=held`, the one state listed.
#[derive(Debug, Default, Deserialize)]
pub struct HeldQuery {
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeldEntryBody {
    pub request_id_hex: String,
    pub requester: String,
    pub channel_id: String,
    pub held_at: i64,
    /// The signed request, base64.
    pub request_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeldBody {
    pub held: Vec<HeldEntryBody>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalAddsBody {
    /// Whether others may add the DID to channels this server sequences,
    /// as the marker kept now says.
    pub allow: bool,
    /// The `seq` of the marker kept now.
    pub seq: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReleasedBody {
    pub key_package_b64: String,
    /// Whether this is the DID's last-resort package, which is handed out
    /// again to later requests.
    pub last_resort: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntryBody {
    /// `custody` or `local` (JEP-0017 rule 32).
    pub kind: String,
    /// The released package's hash reference, lowercase hex.
    pub reference_hex: String,
    /// The entry's own identity, unique in the log, lowercase hex.
    pub id_hex: String,
    pub requester: String,
    pub channel_id: String,
    pub last_resort: bool,
    pub released_at: i64,
    /// The signed request the release answered, base64.
    pub request_b64: String,
}

/// `?offset=N`: skip the `N` newest entries. A page holds at most
/// [`MAX_LOG_ENTRIES`]; a shorter one is the last.
#[derive(Debug, Default, Deserialize)]
pub struct LogPage {
    #[serde(default)]
    pub offset: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogBody {
    pub releases: Vec<LogEntryBody>,
}

fn bad(code: &'static str, msg: impl Into<String>) -> Refusal {
    err(StatusCode::BAD_REQUEST, code, msg)
}

/// `did` has ended local adds here (JEP-0017 rule 16): no package of its is
/// handed out for a channel this server sequences.
pub(crate) fn local_adds_ended(did: &str) -> Refusal {
    err(
        StatusCode::FORBIDDEN,
        "LOCAL_ADDS_ENDED",
        format!("{did} has asked this server not to be added to the channels it sequences"),
    )
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The newest record `did` keeps here, if it verifies: one that lists this
/// server, or one that withdrew it.
fn kept_record(state: &AppState, did: &str) -> Result<Option<ReachabilityRecord>, Refusal> {
    let Some(envelope) = state
        .ingest_ctx
        .store
        .reachability(did)
        .map_err(persist_err)?
    else {
        return Ok(None);
    };
    Ok(ReachabilityRecord::from_envelope(&envelope)
        .ok()
        .filter(|r| r.did == did))
}

/// The record `did` keeps here, if it verifies and still lists this server.
/// After a withdrawal there is none: no custody, and nothing served.
fn listing_record(state: &AppState, did: &str) -> Result<Option<ReachabilityRecord>, Refusal> {
    let ours = state.server_did.to_did_jig_string();
    Ok(kept_record(state, did)?.filter(|r| r.servers.iter().any(|(s, _)| *s == ours)))
}

/// PUT /api/v1/reach/:did
///
/// No request signature: the record is signed by `did`, which is the
/// stronger proof. It is kept only if it lists this server, so a server
/// stores the records of DIDs that chose it and nobody else's. The DID still
/// passes admission.
pub async fn put_reachability(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Json(body): Json<RecordBody>,
) -> Result<Json<StoredBody>, Refusal> {
    let started = std::time::Instant::now();
    let did = jig_pipeline::effect::canonical_did_string(&did);
    let envelope = STANDARD
        .decode(&body.record_b64)
        .map_err(|e| bad("BAD_RECORD", format!("record_b64: {e}")))?;
    let record = ReachabilityRecord::from_envelope(&envelope)
        .map_err(|e| bad("BAD_RECORD", format!("reachability record: {e}")))?;
    if record.did != did {
        return Err(bad(
            "BAD_RECORD",
            format!("the record is {}'s, not {did}'s", record.did),
        ));
    }
    if record.servers.len() > MAX_RECORD_SERVERS {
        return Err(bad(
            "BAD_RECORD",
            format!("a record kept here lists at most {MAX_RECORD_SERVERS} servers"),
        ));
    }
    let ours = state.server_did.to_did_jig_string();
    // A record that leaves this server out is kept only as a withdrawal: it
    // replaces one that listed it, so an older record cannot bring custody
    // back. A server never starts keeping a record that does not list it.
    let listed = record.servers.iter().any(|(s, _)| *s == ours);
    if !listed && kept_record(&state, &did)?.is_none() {
        return Err(err(
            StatusCode::FORBIDDEN,
            "NOT_LISTED",
            format!("the record does not list this server ({ours})"),
        ));
    }
    state
        .auth
        .admit_and_charge(&did)
        .map_err(|outcome| refuse(&state, &outcome, started))?;
    let store = &state.ingest_ctx.store;
    // A withdrawal also retires what this server released through custody
    // before it, in the same transaction: those are never answered again as
    // repeats, since their owner deletes the keys (JEP-0017 rule 32), even if
    // custody is restored inside the window.
    let stored = store
        .put_reachability_retiring(&did, record.seq, &envelope, &ours, now(), !listed)
        .map_err(persist_err)?;
    let seq = kept_record(&state, &did)?.map_or(record.seq, |kept| kept.seq);
    Ok(Json(StoredBody { stored, seq }))
}

/// GET /api/v1/reach/:did
pub async fn get_reachability(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<RecordBody>, Refusal> {
    let started = std::time::Instant::now();
    let caller = optional_caller(&state, &headers, "GET", uri.path(), started)?;
    let did = jig_pipeline::effect::canonical_did_string(&did);
    // `did` itself gets the record kept here even when it is a withdrawal, so
    // each of its devices learns custody here ended and does not list this
    // server again (JEP-0017 rule 13). Anyone else gets no record.
    let own = caller
        .as_ref()
        .is_some_and(|c| c.to_did_jig_string() == did);
    let record = if own {
        kept_record(&state, &did)?
    } else {
        listing_record(&state, &did)?
    };
    match record {
        Some(record) => Ok(Json(RecordBody {
            record_b64: STANDARD.encode(&record.envelope),
        })),
        None => Err(err(
            StatusCode::NOT_FOUND,
            "NO_RECORD",
            format!("{did} keeps no reachability record here"),
        )),
    }
}

/// POST /api/v1/custody/:did/requests
///
/// The request is the authentication: signed by the requester, naming `did`,
/// the channel and this server's DID, and fresh. Answers:
///
/// - `200` with a package;
/// - `404 NO_CUSTODY`: this server is not `did`'s custodian (no record
///   listing it, or no packages);
/// - `403 OUT_OF_POLICY`: `[custody] release` is `closed`;
/// - `429 RATE_LIMITED`: a limit was reached; nothing was consumed.
pub async fn request_key_package(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Json(body): Json<RequestBody>,
) -> Result<Json<ReleasedBody>, Refusal> {
    let started = std::time::Instant::now();
    let did = jig_pipeline::effect::canonical_did_string(&did);
    let envelope = STANDARD
        .decode(&body.request_b64)
        .map_err(|e| bad("BAD_REQUEST", format!("request_b64: {e}")))?;
    let request = KpRequest::from_envelope(&envelope)
        .map_err(|e| bad("BAD_REQUEST", format!("key-package request: {e}")))?;
    if request.did != did {
        return Err(bad(
            "BAD_REQUEST",
            format!("the request is for {}, not {did}", request.did),
        ));
    }
    let ours = state.server_did.to_did_jig_string();
    if request.custodian != ours {
        return Err(bad(
            "WRONG_CUSTODIAN",
            format!(
                "the request is addressed to {}, not this server ({ours})",
                request.custodian
            ),
        ));
    }
    let custody = &state.config.custody;
    let now = now();
    let window = i64::try_from(custody.request_window_secs).unwrap_or(i64::MAX);
    if request.issued_at.abs_diff(now) > window.unsigned_abs() {
        return Err(bad(
            "STALE_REQUEST",
            format!(
                "the request was signed at {}, more than {window}s from this server's clock ({now})",
                request.issued_at
            ),
        ));
    }
    state
        .auth
        .admit_and_charge(&request.requester)
        .map_err(|outcome| refuse(&state, &outcome, started))?;
    let Some(listing) = listing_record(&state, &did)? else {
        return Err(no_custody(&did));
    };
    if custody.release == ReleasePolicy::Closed {
        return Err(err(
            StatusCode::FORBIDDEN,
            "OUT_OF_POLICY",
            "this server releases no key packages to other servers' members",
        ));
    }
    let store = &state.ingest_ctx.store;
    let channel_id = request.channel_id.to_string();
    // The DID's own policy, if it stored one: a requester it does not
    // release to is held, unless the DID approved this requester's earlier
    // request for the channel.
    let mut grant = None;
    if let Some(policy) = kept_policy(&state, &did)?
        && !policy.releases_to(&request.requester)
    {
        // A lost answer is answered again (rule 21a), before anything is
        // held or a grant is used.
        if let again @ Release::Again { .. } =
            release(&state, &did, &request, &envelope, &listing, now, false)?
        {
            return answer(&state, &did, &request, &channel_id, again);
        }
        grant = store
            .take_kp_grant(&did, &request.requester, &channel_id, now)
            .map_err(persist_err)?;
        if grant.is_none() {
            let hold = NewHold {
                request_id: &request.request_id(),
                did: &did,
                requester: &request.requester,
                channel_id: &channel_id,
                request: &envelope,
                now,
            };
            return match store
                .hold_kp_request(&hold, MAX_HELD_PER_DID)
                .map_err(persist_err)?
            {
                Held::New(id) | Held::Already(id) => {
                    tracing::info!(
                        did = %did,
                        requester = %request.requester,
                        channel = %channel_id,
                        "key-package request held for the DID's decision"
                    );
                    Err(held(&did, &id))
                }
                Held::Full => Err(err(
                    StatusCode::TOO_MANY_REQUESTS,
                    "RATE_LIMITED",
                    format!("{MAX_HELD_PER_DID} requests already wait on {did}'s decision here"),
                )),
            };
        }
    }
    let released = release(&state, &did, &request, &envelope, &listing, now, true);
    // An approval is used by a release; one the release did not happen for
    // stays for the next request.
    if let Some(grant) = grant
        && !matches!(
            released,
            Ok(Release::Released { .. } | Release::Again { .. })
        )
    {
        store
            .restore_kp_grant(&did, &request.requester, &channel_id, &grant)
            .map_err(persist_err)?;
    }
    answer(&state, &did, &request, &channel_id, released?)
}

/// The answer to a request, for what [`release`] did.
fn answer(
    state: &AppState,
    did: &str,
    request: &KpRequest,
    channel_id: &str,
    released: Release,
) -> Result<Json<ReleasedBody>, Refusal> {
    let custody = &state.config.custody;
    match released {
        Release::Released {
            package,
            last_resort,
        } => {
            tracing::info!(
                did = %did,
                requester = %request.requester,
                channel = %channel_id,
                last_resort,
                "key package released"
            );
            Ok(Json(ReleasedBody {
                key_package_b64: STANDARD.encode(package),
                last_resort,
            }))
        }
        Release::Again {
            package,
            last_resort,
        } => Ok(Json(ReleasedBody {
            key_package_b64: STANDARD.encode(package),
            last_resort,
        })),
        Release::Limited(hit) => Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            match hit {
                LimitHit::Did => format!(
                    "{did}'s packages were released {} times in the last hour",
                    custody.per_member_per_hour
                ),
                LimitHit::Requester => format!(
                    "{} was released {} packages in the last hour",
                    request.requester, custody.per_requester_per_hour
                ),
            },
        )),
        Release::Empty | Release::NotListed | Release::NotARepeat => Err(no_custody(did)),
        Release::LocalAddsEnded => Err(local_adds_ended(did)),
    }
}

/// Release one of `did`'s packages to `request`, within the limits: a new
/// one only if `fresh`, else only the one already released to it.
fn release(
    state: &AppState,
    did: &str,
    request: &KpRequest,
    envelope: &[u8],
    listing: &ReachabilityRecord,
    now: i64,
    fresh: bool,
) -> Result<Release, Refusal> {
    let custody = &state.config.custody;
    let hash = blake3::hash(envelope);
    let channel_id = request.channel_id.to_string();
    let ours = state.server_did.to_did_jig_string();
    let ask = ReleaseAsk {
        did,
        requester: &request.requester,
        channel_id: &channel_id,
        request_hash: hash.as_bytes(),
        request: envelope,
        now,
        repeat_window: REPEAT_WINDOW_SECS,
        repeat: true,
        fresh,
        per_did: custody.per_member_per_hour,
        per_requester: custody.per_requester_per_hour,
        // Re-checked inside the release's transaction: a withdrawal stored
        // since `listing_record` read it stops this release.
        listing: Some(&listing.envelope),
        kind: jig_pipeline::persist::ReleaseKind::Custody,
        server_did: &ours,
    };
    state
        .ingest_ctx
        .store
        .release_key_package(&ask)
        .map_err(persist_err)
}

/// A request held for `did`'s decision (JEP-0005 rule 21c): a refusal, so a
/// requester that does not know holds reports it as one, carrying the id
/// the DID decides it by.
fn held(did: &str, request_id: &[u8; 32]) -> Refusal {
    let id = hex::encode(request_id);
    let (status, Json(mut body)) = err(
        StatusCode::CONFLICT,
        "HELD",
        format!(
            "{did} releases key packages to you only with their approval; your request \
             {id} waits on it. Ask again once they approve"
        ),
    );
    body.request_id_hex = Some(id);
    (status, Json(body))
}

/// `did`'s own release policy as kept here, verified again on the way out.
fn kept_policy(state: &AppState, did: &str) -> Result<Option<SignedPolicy>, Refusal> {
    let ours = state.server_did.to_did_jig_string();
    Ok(state
        .ingest_ctx
        .store
        .release_policy(did)
        .map_err(persist_err)?
        .and_then(|e| SignedPolicy::from_envelope(&e).ok())
        .filter(|p| p.did == did && p.custodian == ours))
}

/// PUT /api/v1/custody/:did/policy (JEP-0005 rule 21b)
///
/// The body is `did`'s own `jig-kp-release-policy-v1`, naming this server.
/// Kept only at a `seq` above the one kept, and only for a DID whose record
/// lists this server: a policy is for a custodian. The answer is the `seq`
/// kept afterwards.
pub async fn put_policy(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Json(body): Json<PolicyBody>,
) -> Result<Json<StoredBody>, Refusal> {
    let did = jig_pipeline::effect::canonical_did_string(&did);
    let envelope = STANDARD
        .decode(&body.policy_b64)
        .map_err(|e| bad("BAD_REQUEST", format!("policy_b64: {e}")))?;
    let policy = SignedPolicy::from_envelope(&envelope)
        .map_err(|e| bad("BAD_REQUEST", format!("release policy: {e}")))?;
    if policy.did != did {
        return Err(bad(
            "BAD_REQUEST",
            format!("the policy is {}'s, not {did}'s", policy.did),
        ));
    }
    let ours = state.server_did.to_did_jig_string();
    if policy.custodian != ours {
        return Err(bad(
            "WRONG_CUSTODIAN",
            format!(
                "the policy is addressed to {}, not this server ({ours})",
                policy.custodian
            ),
        ));
    }
    if listing_record(&state, &did)?.is_none() {
        return Err(no_custody(&did));
    }
    let (stored, seq) = state
        .ingest_ctx
        .store
        .put_release_policy(&did, policy.seq, &envelope, now())
        .map_err(persist_err)?;
    Ok(Json(StoredBody { stored, seq }))
}

/// GET /api/v1/custody/:did/requests?state=held (JEP-0005 rule 21c)
///
/// The requests held for `did`'s decision, oldest first. Only `did` reads
/// them, with a read proof addressed to this server: they say who is trying
/// to add `did`, and to which channel.
pub async fn held_requests(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Query(query): Query<HeldQuery>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<HeldBody>, Refusal> {
    let started = std::time::Instant::now();
    let caller = optional_caller(&state, &headers, "GET", uri.path(), started)?;
    let did = jig_pipeline::effect::canonical_did_string(&did);
    if caller.as_ref().map(|c| c.as_str()) != Some(did.as_str()) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "NOT_YOURS",
            "only the DID itself reads the requests held for it, with a signed request",
        ));
    }
    if query.state.as_deref().is_some_and(|s| s != "held") {
        return Err(bad("BAD_REQUEST", "only `state=held` is listed"));
    }
    let held = state
        .ingest_ctx
        .store
        .held_kp_requests(&did, MAX_HELD_PER_DID as u32)
        .map_err(persist_err)?
        .into_iter()
        .map(|h| HeldEntryBody {
            request_id_hex: hex::encode(h.request_id),
            requester: h.requester,
            channel_id: h.channel_id,
            held_at: h.held_at,
            request_b64: STANDARD.encode(h.request),
        })
        .collect();
    Ok(Json(HeldBody { held }))
}

/// POST /api/v1/custody/:did/requests/:request_id/decision (rule 21c)
///
/// The body is `did`'s own `jig-kp-decision-v1`, naming this server and the
/// request. A request held for another DID, or none, is `404 NO_SUCH_REQUEST`,
/// whichever it is, so a decision tells nothing of another DID's holds; one
/// decided already is `409 DECIDED`.
pub async fn decide(
    State(state): State<Arc<AppState>>,
    Path((did, request_id)): Path<(String, String)>,
    Json(body): Json<DecisionBody>,
) -> Result<Json<DecidedBody>, Refusal> {
    let did = jig_pipeline::effect::canonical_did_string(&did);
    let envelope = STANDARD
        .decode(&body.decision_b64)
        .map_err(|e| bad("BAD_REQUEST", format!("decision_b64: {e}")))?;
    let decision = KpDecision::from_envelope(&envelope)
        .map_err(|e| bad("BAD_REQUEST", format!("decision: {e}")))?;
    if decision.did != did {
        return Err(bad(
            "BAD_REQUEST",
            format!("the decision is {}'s, not {did}'s", decision.did),
        ));
    }
    let ours = state.server_did.to_did_jig_string();
    if decision.custodian != ours {
        return Err(bad(
            "WRONG_CUSTODIAN",
            format!(
                "the decision is addressed to {}, not this server ({ours})",
                decision.custodian
            ),
        ));
    }
    if hex::encode(decision.request_id) != request_id.to_ascii_lowercase() {
        return Err(bad(
            "BAD_REQUEST",
            "the decision names another request than the route",
        ));
    }
    let now = now();
    match state
        .ingest_ctx
        .store
        .decide_kp_request(
            &did,
            &decision.request_id,
            decision.approve,
            &envelope,
            now,
            now.saturating_add(GRANT_SECS),
        )
        .map_err(persist_err)?
    {
        Decided::Approved => Ok(Json(DecidedBody { approved: true })),
        Decided::Refused => Ok(Json(DecidedBody { approved: false })),
        Decided::NoSuchRequest => Err(err(
            StatusCode::NOT_FOUND,
            "NO_SUCH_REQUEST",
            format!("no request {request_id} is held here for {did}"),
        )),
        Decided::AlreadyDecided => Err(err(
            StatusCode::CONFLICT,
            "DECIDED",
            format!("request {request_id} was decided already"),
        )),
    }
}

/// PUT /api/v1/local-adds/:did (JEP-0017 R2)
///
/// The body is `did`'s own `jig-local-adds-v1`, naming this server. The
/// marker is kept only at a `seq` above the one kept; the answer is the
/// marker kept afterwards, so a stale one is answered with what holds. While
/// it says `allow = false`, nobody else can add `did` to a channel this
/// server sequences; once custody is withdrawn too, `did`'s stock is
/// deleted (rule 19).
pub async fn put_local_adds(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Json(body): Json<RequestBody>,
) -> Result<Json<LocalAddsBody>, Refusal> {
    let started = std::time::Instant::now();
    let did = jig_pipeline::effect::canonical_did_string(&did);
    let envelope = STANDARD
        .decode(&body.request_b64)
        .map_err(|e| bad("BAD_REQUEST", format!("request_b64: {e}")))?;
    let marker = LocalAdds::from_envelope(&envelope)
        .map_err(|e| bad("BAD_REQUEST", format!("not a local-adds marker: {e}")))?;
    if marker.did != did {
        return Err(bad("BAD_REQUEST", "the marker is signed for another DID"));
    }
    let ours = state.server_did.to_did_jig_string();
    if marker.server != ours {
        return Err(bad(
            "WRONG_SERVER",
            "the marker names another server; send it to the server it names",
        ));
    }
    state
        .auth
        .admit_and_charge(&did)
        .map_err(|outcome| refuse(&state, &outcome, started))?;
    let kept = state
        .ingest_ctx
        .store
        .put_local_adds(&did, marker.seq, marker.allow, &envelope, &ours, now())
        .map_err(persist_err)?;
    Ok(Json(LocalAddsBody {
        allow: kept.allow,
        seq: kept.seq,
    }))
}

fn no_custody(did: &str) -> Refusal {
    err(
        StatusCode::NOT_FOUND,
        "NO_CUSTODY",
        format!("this server holds no key packages for {did} to release"),
    )
}

/// GET /api/v1/custody/:did/releases — `did`'s own release log, read with a
/// request proof by `did`.
pub async fn release_log(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Query(page): Query<LogPage>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<LogBody>, Refusal> {
    let started = std::time::Instant::now();
    let caller = optional_caller(&state, &headers, "GET", uri.path(), started)?;
    let did = jig_pipeline::effect::canonical_did_string(&did);
    if caller.as_ref().map(|c| c.as_str()) != Some(did.as_str()) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "NOT_YOURS",
            "only the DID itself reads its release log, with a signed request",
        ));
    }
    let releases = state
        .ingest_ctx
        .store
        .key_package_releases_page(&did, MAX_LOG_ENTRIES, page.offset)
        .map_err(persist_err)?
        .into_iter()
        .map(|e| LogEntryBody {
            kind: e.kind.as_str().to_string(),
            reference_hex: hex::encode(&e.reference),
            id_hex: hex::encode(&e.id),
            requester: e.requester,
            channel_id: e.channel_id,
            last_resort: e.last_resort,
            released_at: e.released_at,
            request_b64: STANDARD.encode(e.request),
        })
        .collect();
    Ok(Json(LogBody { releases }))
}

pub fn build_custody_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/api/v1/reach/{did}",
            get(get_reachability).put(put_reachability),
        )
        .route("/api/v1/local-adds/{did}", put(put_local_adds))
        .route(
            "/api/v1/custody/{did}/requests",
            post(request_key_package).get(held_requests),
        )
        .route("/api/v1/custody/{did}/policy", put(put_policy))
        .route(
            "/api/v1/custody/{did}/requests/{request_id}/decision",
            post(decide),
        )
        .route("/api/v1/custody/{did}/releases", get(release_log))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn did_of(seed: u8) -> String {
        jig_core::Did::from_ed25519_pubkey(&key(seed).verifying_key().to_bytes())
            .to_did_jig_string()
    }

    fn state() -> Arc<AppState> {
        Arc::new(AppState::for_test().unwrap())
    }

    fn ours(state: &AppState) -> String {
        state.server_did.to_did_jig_string()
    }

    fn channel() -> cid::Cid {
        jig_core::canonical_cid::of(b"channel-create")
    }

    /// `seed`'s record listing `servers`, kept by `state`.
    async fn keep(
        state: &Arc<AppState>,
        seed: u8,
        servers: Vec<(String, String)>,
        seq: u64,
    ) -> Result<Json<StoredBody>, Refusal> {
        let record = ReachabilityRecord::sign(&key(seed), servers, seq);
        put_reachability(
            State(state.clone()),
            Path(did_of(seed)),
            Json(RecordBody {
                record_b64: STANDARD.encode(&record.envelope),
            }),
        )
        .await
    }

    /// Stock `seed`'s packages on `state`: `n` ordinary and one last resort.
    async fn stock(state: &Arc<AppState>, seed: u8, n: usize) {
        let did = jig_core::Did::from_ed25519_pubkey(&key(seed).verifying_key().to_bytes());
        let m = jig_mls::member::Member::new(&[seed; 32], &did).unwrap();
        let mut kps = m.key_packages(n, false).unwrap();
        kps.extend(m.key_packages(1, true).unwrap());
        let _ = crate::v0_0_2_mls::publish_key_packages(
            State(state.clone()),
            "/api/v1/mls/key-packages".parse().unwrap(),
            axum::http::HeaderMap::new(),
            serde_json::to_vec(&crate::v0_0_2_mls::PublishBody {
                key_packages_b64: kps.iter().map(|p| STANDARD.encode(p)).collect(),
            })
            .unwrap()
            .into(),
        )
        .await
        .unwrap();
    }

    async fn ask(
        state: &Arc<AppState>,
        requester: u8,
        member: u8,
        custodian: &str,
        issued_at: i64,
    ) -> Result<Json<ReleasedBody>, Refusal> {
        let req = KpRequest::sign(
            &key(requester),
            &did_of(member),
            channel(),
            custodian,
            rand::random(),
            issued_at,
        );
        request_key_package(
            State(state.clone()),
            Path(did_of(member)),
            Json(RequestBody {
                request_b64: STANDARD.encode(&req.envelope),
            }),
        )
        .await
    }

    fn code(r: &Refusal) -> (StatusCode, String) {
        (r.0, r.1.0.code.clone())
    }

    /// `seed`'s local-adds marker for `server`, sent to `state`.
    async fn mark(
        state: &Arc<AppState>,
        seed: u8,
        server: &str,
        allow: bool,
        seq: u64,
    ) -> Result<Json<LocalAddsBody>, Refusal> {
        let marker = LocalAdds::sign(&key(seed), server, allow, seq);
        put_local_adds(
            State(state.clone()),
            Path(did_of(seed)),
            Json(RequestBody {
                request_b64: STANDARD.encode(&marker.envelope),
            }),
        )
        .await
    }

    async fn take(state: &Arc<AppState>, seed: u8) -> Result<(), Refusal> {
        let did = did_of(seed);
        crate::v0_0_2_mls::take_key_package(
            State(state.clone()),
            Path(did.clone()),
            format!("/api/v1/mls/key-packages/{did}").parse().unwrap(),
            axum::http::HeaderMap::new(),
        )
        .await
        .map(drop)
    }

    async fn publish(state: &Arc<AppState>, seed: u8) -> Result<(), Refusal> {
        let did = jig_core::Did::from_ed25519_pubkey(&key(seed).verifying_key().to_bytes());
        let m = jig_mls::member::Member::new(&[seed; 32], &did).unwrap();
        // Ordinary packages only: an unsigned upload stocks them.
        crate::v0_0_2_mls::publish_key_packages(
            State(state.clone()),
            "/api/v1/mls/key-packages".parse().unwrap(),
            axum::http::HeaderMap::new(),
            serde_json::to_vec(&crate::v0_0_2_mls::PublishBody {
                key_packages_b64: m
                    .key_packages(2, false)
                    .unwrap()
                    .iter()
                    .map(|p| STANDARD.encode(p))
                    .collect(),
            })
            .unwrap()
            .into(),
        )
        .await
        .map(drop)
    }

    fn open_reads() -> Arc<AppState> {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.auth.require_authenticated_reads = false;
        Arc::new(AppState::for_test_with_config(config).unwrap())
    }

    #[tokio::test]
    async fn a_local_adds_marker_must_be_the_members_and_name_this_server() {
        let state = state();
        let refused = mark(&state, 4, &did_of(90), false, 1).await.unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::BAD_REQUEST, "WRONG_SERVER".into())
        );
        let marker = LocalAdds::sign(&key(4), &ours(&state), false, 1);
        let refused = put_local_adds(
            State(state.clone()),
            Path(did_of(5)),
            Json(RequestBody {
                request_b64: STANDARD.encode(&marker.envelope),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::BAD_REQUEST, "BAD_REQUEST".into())
        );
        let refused = put_local_adds(
            State(state.clone()),
            Path(did_of(4)),
            Json(RequestBody {
                request_b64: STANDARD.encode(b"not a marker"),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::BAD_REQUEST, "BAD_REQUEST".into())
        );
    }

    #[tokio::test]
    async fn a_stale_local_adds_marker_is_answered_with_the_one_kept() {
        let state = state();
        let Json(kept) = mark(&state, 4, &ours(&state), false, 5).await.unwrap();
        assert_eq!((kept.allow, kept.seq), (false, 5));
        // A lower seq is not kept: the answer is the marker that holds, not
        // the one sent.
        let Json(kept) = mark(&state, 4, &ours(&state), true, 3).await.unwrap();
        assert_eq!((kept.allow, kept.seq), (false, 5));
        let Json(kept) = mark(&state, 4, &ours(&state), true, 6).await.unwrap();
        assert_eq!((kept.allow, kept.seq), (true, 6));
    }

    #[tokio::test]
    async fn ended_local_adds_close_this_servers_key_package_route() {
        let state = open_reads();
        stock(&state, 4, 2).await;
        let _ = mark(&state, 4, &ours(&state), false, 1).await.unwrap();
        let refused = take(&state, 4).await.unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::FORBIDDEN, "LOCAL_ADDS_ENDED".into())
        );
        let _ = mark(&state, 4, &ours(&state), true, 2).await.unwrap();
        take(&state, 4).await.unwrap();
    }

    /// Custody under R2 is refused for a channel this server sequences and
    /// released for one it does not know: the sequencer's own refusal of the
    /// `member-add` is what holds then (JEP-0017 rule 16).
    #[tokio::test]
    async fn ended_local_adds_refuse_custody_only_for_channels_sequenced_here() {
        let state = state();
        stock(&state, 4, 3).await;
        let here = (ours(&state), "https://here.example".to_string());
        let _ = keep(&state, 4, vec![here], 1).await.unwrap();
        let _ = mark(&state, 4, &ours(&state), false, 1).await.unwrap();
        // `channel()` is not a channel this server holds.
        let _ = ask(&state, 3, 4, &ours(&state), now()).await.unwrap();

        let sequenced = jig_pipeline::persist::StoredChannel {
            id: channel().to_string(),
            slug: "#here".into(),
            visibility: "open".into(),
            created_at: 0,
            owner_did: did_of(3),
            suite: "mls".into(),
            sequencer_did: ours(&state),
            co_owners: vec![],
            tiering: jig_pipeline::persist::ChannelTiering::current("open", "mls"),
        };
        state.ingest_ctx.store.upsert_channel(&sequenced).unwrap();
        let refused = ask(&state, 5, 4, &ours(&state), now()).await.unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::FORBIDDEN, "LOCAL_ADDS_ENDED".into())
        );
        // A channel another server sequences is covered in `persist`: a
        // channel's sequencer is fixed for its life.
    }

    #[tokio::test]
    async fn with_custody_and_local_adds_both_ended_the_stock_goes_and_uploads_stop() {
        let state = state();
        stock(&state, 4, 3).await;
        let here = (ours(&state), "https://here.example".to_string());
        let elsewhere = (did_of(90), "https://elsewhere.example".to_string());
        let _ = keep(&state, 4, vec![here], 1).await.unwrap();
        let _ = keep(&state, 4, vec![elsewhere], 2).await.unwrap();
        publish(&state, 4).await.unwrap();
        let _ = mark(&state, 4, &ours(&state), false, 1).await.unwrap();
        assert_eq!(
            state
                .ingest_ctx
                .store
                .key_package_stock(&did_of(4))
                .unwrap(),
            (0, false)
        );
        let refused = publish(&state, 4).await.unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::FORBIDDEN, "NOT_STOCKED_HERE".into())
        );
        assert!(
            !stocked(&state, 4).await,
            "the stock route says it is ended"
        );
        let _ = mark(&state, 4, &ours(&state), true, 2).await.unwrap();
        assert!(stocked(&state, 4).await);
        publish(&state, 4).await.unwrap();
    }

    /// The stock route's `stocked` is the server's own rule-19 state, not
    /// an empty stock: a stock emptied by takes, or under one of R1 and R2
    /// alone, is still in use (a released package is handed again to a
    /// repeated request), so its owner must keep the keys.
    #[tokio::test]
    async fn the_stock_route_says_stocked_until_both_are_ended() {
        let state = state();
        let here = (ours(&state), "https://here.example".to_string());
        let elsewhere = (did_of(90), "https://elsewhere.example".to_string());
        assert!(stocked(&state, 4).await, "nothing stocked yet");
        let _ = keep(&state, 4, vec![here.clone()], 1).await.unwrap();
        let _ = keep(&state, 4, vec![elsewhere], 2).await.unwrap();
        assert!(stocked(&state, 4).await, "R1 alone");
        let _ = keep(&state, 4, vec![here], 3).await.unwrap();
        let _ = mark(&state, 4, &ours(&state), false, 1).await.unwrap();
        assert!(stocked(&state, 4).await, "R2 alone");
    }

    async fn stocked(state: &Arc<AppState>, seed: u8) -> bool {
        let did = did_of(seed);
        let path = format!("/api/v1/mls/key-packages/{did}/stock");
        let reader = jig_client::identity::Identity::from_signing_key(key(seed));
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in jig_client::read_auth::ReadProof::sign(
            &reader,
            &state.server_did.to_did_jig_string(),
            "GET",
            &path,
        )
        .headers()
        {
            headers.insert(name, value.parse().unwrap());
        }
        let Json(body) = crate::v0_0_2_mls::key_package_stock(
            State(state.clone()),
            Path(did.clone()),
            path.parse().unwrap(),
            headers,
        )
        .await
        .unwrap();
        body.stocked
    }

    #[tokio::test]
    async fn a_record_is_kept_only_if_it_lists_this_server() {
        let state = state();
        let other = (did_of(90), "https://elsewhere.example".to_string());
        let refused = keep(&state, 1, vec![other.clone()], 1).await.unwrap_err();
        assert_eq!(code(&refused), (StatusCode::FORBIDDEN, "NOT_LISTED".into()));

        let here = (ours(&state), "https://here.example".to_string());
        let Json(kept) = keep(&state, 1, vec![other, here.clone()], 2).await.unwrap();
        assert!(kept.stored);
        let Json(older) = keep(&state, 1, vec![here], 1).await.unwrap();
        assert!(!older.stored, "a lower seq never replaces a higher one");
        assert_eq!(older.seq, 2);
    }

    #[tokio::test]
    async fn a_member_who_withdraws_this_server_is_no_longer_released() {
        let state = state();
        stock(&state, 4, 3).await;
        let here = (ours(&state), "https://here.example".to_string());
        let elsewhere = (did_of(90), "https://elsewhere.example".to_string());
        let _ = keep(&state, 4, vec![here.clone()], 1).await.unwrap();
        let _ = ask(&state, 3, 4, &ours(&state), now()).await.unwrap();

        // A higher record without this server is kept, as a withdrawal.
        let Json(withdrawn) = keep(&state, 4, vec![elsewhere.clone()], 2).await.unwrap();
        assert!(withdrawn.stored);
        let refused = ask(&state, 5, 4, &ours(&state), now()).await.unwrap_err();
        assert_eq!(code(&refused), (StatusCode::NOT_FOUND, "NO_CUSTODY".into()));
        assert!(
            listing_record(&state, &did_of(4)).unwrap().is_none(),
            "a withdrawn record is not served"
        );

        // The older listing cannot bring custody back; a newer one can.
        let Json(older) = keep(&state, 4, vec![here.clone()], 1).await.unwrap();
        assert!(!older.stored);
        assert_eq!(older.seq, 2);
        assert!(ask(&state, 5, 4, &ours(&state), now()).await.is_err());
        let _ = keep(&state, 4, vec![here], 3).await.unwrap();
        assert!(ask(&state, 5, 4, &ours(&state), now()).await.is_ok());
    }

    async fn read_record(
        state: &Arc<AppState>,
        reader: u8,
        did: u8,
    ) -> Result<RecordBody, Refusal> {
        let path = format!("/api/v1/reach/{}", did_of(did));
        let identity = jig_client::identity::Identity::from_signing_key(key(reader));
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in jig_client::read_auth::ReadProof::sign(
            &identity,
            &state.server_did.to_did_jig_string(),
            "GET",
            &path,
        )
        .headers()
        {
            headers.insert(name, value.parse().unwrap());
        }
        get_reachability(
            State(state.clone()),
            Path(did_of(did)),
            path.parse().unwrap(),
            headers,
        )
        .await
        .map(|Json(b)| b)
    }

    #[tokio::test]
    async fn a_withdrawal_is_served_to_its_did_alone() {
        let state = state();
        let here = (ours(&state), "https://here.example".to_string());
        let elsewhere = (did_of(90), "https://elsewhere.example".to_string());
        let _ = keep(&state, 4, vec![here], 1).await.unwrap();
        let _ = keep(&state, 4, vec![elsewhere.clone()], 2).await.unwrap();

        let refused = read_record(&state, 5, 4).await.unwrap_err();
        assert_eq!(code(&refused), (StatusCode::NOT_FOUND, "NO_RECORD".into()));

        let own = read_record(&state, 4, 4).await.unwrap();
        let record =
            ReachabilityRecord::from_envelope(&STANDARD.decode(own.record_b64).unwrap()).unwrap();
        assert_eq!((record.seq, record.servers), (2, vec![elsewhere]));
    }

    #[tokio::test]
    async fn without_required_reads_an_owner_proof_is_still_checked() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.auth.require_authenticated_reads = false;
        let state = Arc::new(AppState::for_test_with_config(config).unwrap());
        let here = (ours(&state), "https://here.example".to_string());
        let elsewhere = (did_of(90), "https://elsewhere.example".to_string());
        let _ = keep(&state, 4, vec![here], 1).await.unwrap();
        let _ = keep(&state, 4, vec![elsewhere], 2).await.unwrap();

        // The owner, signed, sees its withdrawal; another DID does not.
        assert!(read_record(&state, 4, 4).await.is_ok());
        let other = read_record(&state, 5, 4).await.unwrap_err();
        assert_eq!(code(&other), (StatusCode::NOT_FOUND, "NO_RECORD".into()));
        // Anonymous, with no proof at all: no record either.
        let path = format!("/api/v1/reach/{}", did_of(4));
        let anon = get_reachability(
            State(state.clone()),
            Path(did_of(4)),
            path.parse().unwrap(),
            axum::http::HeaderMap::new(),
        )
        .await
        .map(|_| ())
        .unwrap_err();
        assert_eq!(code(&anon), (StatusCode::NOT_FOUND, "NO_RECORD".into()));
        // A proof header that does not parse is refused too.
        let mut malformed = axum::http::HeaderMap::new();
        malformed.insert(
            jig_core::request_auth::headers::SIGNATURE,
            "not base64!".parse().unwrap(),
        );
        let refused = get_reachability(
            State(state.clone()),
            Path(did_of(4)),
            path.parse().unwrap(),
            malformed,
        )
        .await
        .map(|_| ())
        .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::UNAUTHORIZED, "INVALID_SIG".into()),
            "refused, not answered as anonymous with NO_RECORD"
        );
        // A proof that does not verify is refused, not read as anonymous.
        let mut forged = axum::http::HeaderMap::new();
        let identity = jig_client::identity::Identity::from_signing_key(key(4));
        for (name, value) in jig_client::read_auth::ReadProof::sign(
            &identity,
            &state.server_did.to_did_jig_string(),
            "GET",
            "/somewhere/else",
        )
        .headers()
        {
            forged.insert(name, value.parse().unwrap());
        }
        let refused = get_reachability(
            State(state.clone()),
            Path(did_of(4)),
            path.parse().unwrap(),
            forged,
        )
        .await
        .map(|_| ())
        .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::UNAUTHORIZED, "INVALID_SIG".into())
        );
    }

    #[tokio::test]
    async fn a_record_that_never_listed_this_server_is_not_kept() {
        let state = state();
        let elsewhere = (did_of(90), "https://elsewhere.example".to_string());
        let refused = keep(&state, 4, vec![elsewhere], 5).await.unwrap_err();
        assert_eq!(code(&refused), (StatusCode::FORBIDDEN, "NOT_LISTED".into()));
        assert!(
            state
                .ingest_ctx
                .store
                .reachability(&did_of(4))
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_record_put_under_another_did_is_refused() {
        let state = state();
        let record = ReachabilityRecord::sign(&key(1), vec![(ours(&state), "u".into())], 1);
        let refused = put_reachability(
            State(state.clone()),
            Path(did_of(2)),
            Json(RecordBody {
                record_b64: STANDARD.encode(&record.envelope),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::BAD_REQUEST, "BAD_RECORD".into())
        );
    }

    #[tokio::test]
    async fn a_listed_member_s_package_is_released_to_a_signed_request() {
        let state = state();
        stock(&state, 4, 2).await;
        let _ = keep(
            &state,
            4,
            vec![(ours(&state), "https://here.example".into())],
            1,
        )
        .await
        .unwrap();
        let Json(released) = ask(&state, 3, 4, &ours(&state), now()).await.unwrap();
        assert!(!released.last_resort);
        let package = STANDARD.decode(released.key_package_b64).unwrap();
        let info = jig_mls::delivery::validate_key_package(&package).unwrap();
        assert_eq!(info.did, did_of(4));
        assert_eq!(
            state
                .ingest_ctx
                .store
                .key_package_stock(&did_of(4))
                .unwrap(),
            (1, true)
        );
        let log = state
            .ingest_ctx
            .store
            .key_package_releases(&did_of(4), 10)
            .unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].requester, did_of(3));
    }

    #[tokio::test]
    async fn the_release_log_tells_custody_releases_from_local_takes() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.auth.require_authenticated_reads = false;
        let state = Arc::new(AppState::for_test_with_config(config).unwrap());
        stock(&state, 4, 3).await;
        let _ = keep(&state, 4, vec![(ours(&state), "u".into())], 1)
            .await
            .unwrap();
        let _ = ask(&state, 3, 4, &ours(&state), now()).await.unwrap();
        let _ = crate::v0_0_2_mls::take_key_package(
            State(state.clone()),
            Path(did_of(4)),
            format!("/api/v1/mls/key-packages/{}", did_of(4))
                .parse()
                .unwrap(),
            axum::http::HeaderMap::new(),
        )
        .await
        .unwrap();
        let mut kinds: Vec<_> = state
            .ingest_ctx
            .store
            .key_package_releases(&did_of(4), 10)
            .unwrap()
            .into_iter()
            .map(|e| (e.kind.as_str(), e.channel_id.is_empty()))
            .collect();
        kinds.sort();
        assert_eq!(kinds, [("custody", false), ("local", true)]);
    }

    #[tokio::test]
    async fn a_member_with_no_record_here_has_no_custodian_here() {
        let state = state();
        stock(&state, 4, 2).await;
        let refused = ask(&state, 3, 4, &ours(&state), now()).await.unwrap_err();
        assert_eq!(code(&refused), (StatusCode::NOT_FOUND, "NO_CUSTODY".into()));
        assert_eq!(
            state
                .ingest_ctx
                .store
                .key_package_stock(&did_of(4))
                .unwrap(),
            (2, true),
            "nothing was consumed"
        );
    }

    #[tokio::test]
    async fn a_request_for_another_custodian_or_out_of_time_is_refused() {
        let state = state();
        stock(&state, 4, 2).await;
        let _ = keep(&state, 4, vec![(ours(&state), "u".into())], 1)
            .await
            .unwrap();
        let elsewhere = ask(&state, 3, 4, &did_of(90), now()).await.unwrap_err();
        assert_eq!(code(&elsewhere).1, "WRONG_CUSTODIAN");
        let stale = ask(&state, 3, 4, &ours(&state), now() - 3600)
            .await
            .unwrap_err();
        assert_eq!(code(&stale).1, "STALE_REQUEST");
        let early = ask(&state, 3, 4, &ours(&state), now() + 3600)
            .await
            .unwrap_err();
        assert_eq!(code(&early).1, "STALE_REQUEST");
        assert_eq!(
            state
                .ingest_ctx
                .store
                .key_package_stock(&did_of(4))
                .unwrap(),
            (2, true)
        );
    }

    #[tokio::test]
    async fn a_request_signed_by_someone_else_is_refused() {
        let state = state();
        let mut req = KpRequest::sign(
            &key(3),
            &did_of(4),
            channel(),
            &ours(&state),
            rand::random(),
            now(),
        );
        req.requester = did_of(5);
        let forged = jig_core::cose::sign1(&key(3), &req.payload());
        let refused = request_key_package(
            State(state.clone()),
            Path(did_of(4)),
            Json(RequestBody {
                request_b64: STANDARD.encode(forged),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::BAD_REQUEST, "BAD_REQUEST".into())
        );
    }

    #[tokio::test]
    async fn a_member_s_stock_is_released_at_most_per_member_per_hour() {
        let mut inner = AppState::for_test().unwrap();
        inner.config.custody.per_member_per_hour = 2;
        let state = Arc::new(inner);
        stock(&state, 4, 5).await;
        let _ = keep(&state, 4, vec![(ours(&state), "u".into())], 1)
            .await
            .unwrap();
        for requester in [10, 11] {
            let _ = ask(&state, requester, 4, &ours(&state), now())
                .await
                .unwrap();
        }
        let refused = ask(&state, 12, 4, &ours(&state), now()).await.unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED".into())
        );
        assert_eq!(
            state
                .ingest_ctx
                .store
                .key_package_stock(&did_of(4))
                .unwrap(),
            (3, true)
        );
    }

    #[tokio::test]
    async fn asking_again_returns_the_same_package_and_consumes_nothing() {
        let state = state();
        stock(&state, 4, 3).await;
        let _ = keep(&state, 4, vec![(ours(&state), "u".into())], 1)
            .await
            .unwrap();
        let Json(first) = ask(&state, 3, 4, &ours(&state), now()).await.unwrap();
        let Json(again) = ask(&state, 3, 4, &ours(&state), now()).await.unwrap();
        assert_eq!(first.key_package_b64, again.key_package_b64);
        assert_eq!(
            state
                .ingest_ctx
                .store
                .key_package_stock(&did_of(4))
                .unwrap(),
            (2, true)
        );
    }

    #[tokio::test]
    async fn a_drained_member_is_still_reachable_through_last_resort() {
        let state = state();
        stock(&state, 4, 0).await;
        let _ = keep(&state, 4, vec![(ours(&state), "u".into())], 1)
            .await
            .unwrap();
        for requester in [10, 11] {
            let Json(r) = ask(&state, requester, 4, &ours(&state), now())
                .await
                .unwrap();
            assert!(r.last_resort);
        }
        assert_eq!(
            state
                .ingest_ctx
                .store
                .key_package_stock(&did_of(4))
                .unwrap(),
            (0, true)
        );
    }

    #[tokio::test]
    async fn a_closed_custodian_releases_nothing() {
        let mut inner = AppState::for_test().unwrap();
        inner.config.custody.release = ReleasePolicy::Closed;
        let state = Arc::new(inner);
        stock(&state, 4, 2).await;
        let _ = keep(&state, 4, vec![(ours(&state), "u".into())], 1)
            .await
            .unwrap();
        let refused = ask(&state, 3, 4, &ours(&state), now()).await.unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::FORBIDDEN, "OUT_OF_POLICY".into())
        );
    }

    // ---- Release policies and held requests (JEP-0005 rules 21b, 21c) ----

    async fn put_policy_of(
        state: &Arc<AppState>,
        seed: u8,
        custodian: &str,
        seq: u64,
        release_to: Vec<String>,
    ) -> Result<Json<StoredBody>, Refusal> {
        let policy = SignedPolicy::sign(&key(seed), custodian, seq, now(), release_to, false);
        put_policy(
            State(state.clone()),
            Path(did_of(seed)),
            Json(PolicyBody {
                policy_b64: STANDARD.encode(&policy.envelope),
            }),
        )
        .await
    }

    async fn read_held(state: &Arc<AppState>, reader: u8, did: u8) -> Result<HeldBody, Refusal> {
        let path = format!("/api/v1/custody/{}/requests", did_of(did));
        let identity = jig_client::identity::Identity::from_signing_key(key(reader));
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in jig_client::read_auth::ReadProof::sign(
            &identity,
            &state.server_did.to_did_jig_string(),
            "GET",
            &path,
        )
        .headers()
        {
            headers.insert(name, value.parse().unwrap());
        }
        held_requests(
            State(state.clone()),
            Path(did_of(did)),
            Query(HeldQuery {
                state: Some("held".into()),
            }),
            path.parse().unwrap(),
            headers,
        )
        .await
        .map(|Json(b)| b)
    }

    async fn decide_as(
        state: &Arc<AppState>,
        seed: u8,
        custodian: &str,
        request_id: [u8; 32],
        approve: bool,
    ) -> Result<Json<DecidedBody>, Refusal> {
        let decision = KpDecision::sign(&key(seed), custodian, request_id, approve, now());
        decide(
            State(state.clone()),
            Path((did_of(seed), hex::encode(request_id))),
            Json(DecisionBody {
                decision_b64: STANDARD.encode(&decision.envelope),
            }),
        )
        .await
    }

    /// A custodian of `member` (seed 4), with its packages stocked, and a
    /// policy releasing to `named` (seed 3) alone.
    async fn custodian_with_policy() -> Arc<AppState> {
        let state = state();
        let _ = keep(&state, 4, vec![(ours(&state), "https://here".into())], 1)
            .await
            .unwrap();
        stock(&state, 4, 4).await;
        let _ = put_policy_of(&state, 4, &ours(&state), 1, vec![did_of(3)])
            .await
            .unwrap();
        state
    }

    fn held_id(refusal: &Refusal) -> [u8; 32] {
        assert_eq!(code(refusal), (StatusCode::CONFLICT, "HELD".into()));
        hex::decode(refusal.1.0.request_id_hex.as_deref().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[tokio::test]
    async fn a_policy_releases_to_whom_it_names_and_holds_everyone_else() {
        let state = custodian_with_policy().await;
        let custodian = ours(&state);
        // Named: released.
        let _ = ask(&state, 3, 4, &custodian, now()).await.unwrap();
        // Not named: held, as a refusal carrying the request's id.
        let refused = ask(&state, 8, 4, &custodian, now()).await.unwrap_err();
        let id = held_id(&refused);
        // Asking again is the same hold.
        let again = ask(&state, 8, 4, &custodian, now()).await.unwrap_err();
        assert_eq!(held_id(&again), id);
        // Only the DID reads what is held for it.
        let held = read_held(&state, 4, 4).await.unwrap().held;
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].request_id_hex, hex::encode(id));
        assert_eq!(held[0].requester, did_of(8));
        let refused = read_held(&state, 8, 4).await.unwrap_err();
        assert_eq!(code(&refused), (StatusCode::FORBIDDEN, "NOT_YOURS".into()));
    }

    #[tokio::test]
    async fn an_approval_lets_the_next_request_through_once() {
        let state = custodian_with_policy().await;
        let custodian = ours(&state);
        let id = held_id(&ask(&state, 8, 4, &custodian, now()).await.unwrap_err());
        assert!(
            decide_as(&state, 4, &custodian, id, true)
                .await
                .unwrap()
                .approved
        );
        // Decided once.
        let refused = decide_as(&state, 4, &custodian, id, false)
            .await
            .unwrap_err();
        assert_eq!(code(&refused), (StatusCode::CONFLICT, "DECIDED".into()));
        assert!(read_held(&state, 4, 4).await.unwrap().held.is_empty());
        // The approved requester's next request is released, using the
        // approval up.
        let Json(first) = ask(&state, 8, 4, &custodian, now()).await.unwrap();
        let store = &state.ingest_ctx.store;
        let channel = channel().to_string();
        assert!(
            store
                .take_kp_grant(&did_of(4), &did_of(8), &channel, now())
                .unwrap()
                .is_none()
        );
        // A lost answer is answered again with the same package (rule 21a),
        // not held.
        let Json(again) = ask(&state, 8, 4, &custodian, now()).await.unwrap();
        assert_eq!(again.key_package_b64, first.key_package_b64);
    }

    #[tokio::test]
    async fn a_refusal_releases_nothing() {
        let state = custodian_with_policy().await;
        let custodian = ours(&state);
        let id = held_id(&ask(&state, 8, 4, &custodian, now()).await.unwrap_err());
        assert!(
            !decide_as(&state, 4, &custodian, id, false)
                .await
                .unwrap()
                .approved
        );
        let next = held_id(&ask(&state, 8, 4, &custodian, now()).await.unwrap_err());
        assert_ne!(next, id, "a new request is held anew");
    }

    #[tokio::test]
    async fn a_decision_answers_only_its_dids_hold_here() {
        let state = custodian_with_policy().await;
        let custodian = ours(&state);
        let id = held_id(&ask(&state, 8, 4, &custodian, now()).await.unwrap_err());
        // Another DID deciding 4's request: as though there were none.
        let refused = decide_as(&state, 9, &custodian, id, true)
            .await
            .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::NOT_FOUND, "NO_SUCH_REQUEST".into())
        );
        let refused = decide_as(&state, 4, &custodian, [7; 32], true)
            .await
            .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::NOT_FOUND, "NO_SUCH_REQUEST".into())
        );
        // Addressed to another custodian.
        let refused = decide_as(&state, 4, &did_of(90), id, true)
            .await
            .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::BAD_REQUEST, "WRONG_CUSTODIAN".into())
        );
        // The route and the decision must name the same request.
        let decision = KpDecision::sign(&key(4), &custodian, id, true, now());
        let refused = decide(
            State(state.clone()),
            Path((did_of(4), hex::encode([7; 32]))),
            Json(DecisionBody {
                decision_b64: STANDARD.encode(&decision.envelope),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::BAD_REQUEST, "BAD_REQUEST".into())
        );
        assert_eq!(read_held(&state, 4, 4).await.unwrap().held.len(), 1);
    }

    #[tokio::test]
    async fn a_policy_is_kept_only_for_this_custodian_and_a_listed_did() {
        let state = state();
        // No record lists this server for the DID: not its custodian.
        let refused = put_policy_of(&state, 4, &ours(&state), 1, vec![])
            .await
            .unwrap_err();
        assert_eq!(code(&refused), (StatusCode::NOT_FOUND, "NO_CUSTODY".into()));
        let _ = keep(&state, 4, vec![(ours(&state), "https://here".into())], 1)
            .await
            .unwrap();
        let refused = put_policy_of(&state, 4, &did_of(90), 1, vec![])
            .await
            .unwrap_err();
        assert_eq!(
            code(&refused),
            (StatusCode::BAD_REQUEST, "WRONG_CUSTODIAN".into())
        );
        let Json(kept) = put_policy_of(&state, 4, &ours(&state), 2, vec![])
            .await
            .unwrap();
        assert_eq!((kept.stored, kept.seq), (true, 2));
        let Json(kept) = put_policy_of(&state, 4, &ours(&state), 1, vec![did_of(3)])
            .await
            .unwrap();
        assert_eq!((kept.stored, kept.seq), (false, 2));
    }

    #[tokio::test]
    async fn without_a_policy_the_servers_own_applies() {
        let state = state();
        let _ = keep(&state, 4, vec![(ours(&state), "https://here".into())], 1)
            .await
            .unwrap();
        stock(&state, 4, 2).await;
        // `[custody] release = open` by default: a stranger is released to.
        let _ = ask(&state, 8, 4, &ours(&state), now()).await.unwrap();
    }
}
