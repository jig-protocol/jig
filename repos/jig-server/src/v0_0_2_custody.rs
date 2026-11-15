//! This server as a custodian of key packages (JEP-0005 rule 21).
//!
//! - `PUT  /api/v1/reach/:did` — keep a DID's reachability record, if it
//!   lists this server
//! - `GET  /api/v1/reach/:did` — serve it back
//! - `POST /api/v1/custody/:did/requests` — release one of the DID's key
//!   packages to a signed request
//! - `GET  /api/v1/custody/:did/releases` — the DID reads its release log
//!
//! A custodian of `D` is a server `D`'s reachability record lists and that
//! holds `D`'s packages (published through `v0_0_2_mls`). Another server's
//! member adding `D` to a channel asks a custodian directly, so the channel's
//! owner takes no part. A package is self-signed by `D`, so a custodian can
//! withhold one but never substitute one: the adder checks the package's
//! signature and DID before it commits.
//!
//! Until DIDs sign release policies, `[custody] release` is this server's
//! policy for every DID it holds, and the limits below bound how fast any
//! requester, or all of them together, can draw down a DID's stock. A DID's
//! last-resort package is handed out but never consumed, so a drained stock
//! leaves the DID reachable.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jig_config::v0_0_2_server::ReleasePolicy;
use jig_core::contract::KpRequest;
use jig_core::naming::ReachabilityRecord;
use jig_pipeline::persist::{LimitHit, Release, ReleaseAsk};
use serde::{Deserialize, Serialize};

use crate::v0_0_2::AppState;
use crate::v0_0_2_blocks::{ErrorBody, admit_caller, err, persist_err, refuse};

/// Most servers a reachability record kept here may list.
pub const MAX_RECORD_SERVERS: usize = 16;
/// Seconds within which the same requester asking again for the same DID and
/// channel gets the package it was already given, not a new one.
pub const REPEAT_WINDOW_SECS: i64 = 600;
/// Most release-log entries one read returns.
pub const MAX_LOG_ENTRIES: u32 = 200;

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
pub struct ReleasedBody {
    pub key_package_b64: String,
    /// Whether this is the DID's last-resort package, which is handed out
    /// again to later requests.
    pub last_resort: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntryBody {
    pub requester: String,
    pub channel_id: String,
    pub last_resort: bool,
    pub released_at: i64,
    /// The signed request the release answered, base64.
    pub request_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogBody {
    pub releases: Vec<LogEntryBody>,
}

fn bad(code: &'static str, msg: impl Into<String>) -> Refusal {
    err(StatusCode::BAD_REQUEST, code, msg)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The record `did` keeps here, if it lists this server and verifies.
fn listing_record(state: &AppState, did: &str) -> Result<Option<ReachabilityRecord>, Refusal> {
    let Some(envelope) = state
        .ingest_ctx
        .store
        .reachability(did)
        .map_err(persist_err)?
    else {
        return Ok(None);
    };
    let ours = state.server_did.to_did_jig_string();
    Ok(ReachabilityRecord::from_envelope(&envelope)
        .ok()
        .filter(|r| r.did == did && r.servers.iter().any(|(s, _)| *s == ours)))
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
    if !record.servers.iter().any(|(s, _)| *s == ours) {
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
    let stored = store
        .put_reachability(&did, record.seq, &envelope, now())
        .map_err(persist_err)?;
    let seq = match listing_record(&state, &did)? {
        Some(kept) => kept.seq,
        None => record.seq,
    };
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
    admit_caller(&state, &headers, "GET", uri.path(), started)?;
    let did = jig_pipeline::effect::canonical_did_string(&did);
    match listing_record(&state, &did)? {
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
    if listing_record(&state, &did)?.is_none() {
        return Err(no_custody(&did));
    }
    if custody.release == ReleasePolicy::Closed {
        return Err(err(
            StatusCode::FORBIDDEN,
            "OUT_OF_POLICY",
            "this server releases no key packages to other servers' members",
        ));
    }
    let hash = blake3::hash(&envelope);
    let channel_id = request.channel_id.to_string();
    let ask = ReleaseAsk {
        did: &did,
        requester: &request.requester,
        channel_id: &channel_id,
        request_hash: hash.as_bytes(),
        request: &envelope,
        now,
        repeat_window: REPEAT_WINDOW_SECS,
        per_did: custody.per_member_per_hour,
        per_requester: custody.per_requester_per_hour,
    };
    match state
        .ingest_ctx
        .store
        .release_key_package(&ask)
        .map_err(persist_err)?
    {
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
        Release::Empty => Err(no_custody(&did)),
    }
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
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<LogBody>, Refusal> {
    let started = std::time::Instant::now();
    let caller = admit_caller(&state, &headers, "GET", uri.path(), started)?;
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
        .key_package_releases(&did, MAX_LOG_ENTRIES)
        .map_err(persist_err)?
        .into_iter()
        .map(|e| LogEntryBody {
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
        .route("/api/v1/custody/{did}/requests", post(request_key_package))
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
            Json(crate::v0_0_2_mls::PublishBody {
                key_packages_b64: kps.iter().map(|p| STANDARD.encode(p)).collect(),
            }),
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
            [1; 16],
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
}
