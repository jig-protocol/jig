//! REST surface of the MLS delivery service.
//!
//! - `POST /api/v1/mls/key-packages` — publish a batch of key packages
//! - `GET  /api/v1/mls/key-packages/:did` — take one of a DID's packages
//! - `GET  /api/v1/mls/key-packages/:did/stock` — how many are left
//! - `GET  /api/v1/channels/:slug/mls/group-info` — for external joiners
//!
//! Commits, welcomes and application messages do not come through here: they
//! ride signed blocks through `ingest`, where `jig_pipeline::mls_gate`
//! validates them. This module only serves the material a member needs
//! *before* it can build such a block.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::v0_0_2::AppState;
use crate::v0_0_2_blocks::{
    ErrorBody, admit_caller, authorize_channel_read, err, persist_err, refuse,
};

/// Most packages one request may publish.
pub const MAX_BATCH: usize = 100;
/// Most unconsumed ordinary packages one DID may hold. Bounds what any one
/// self-minted identity can make this server store.
pub const MAX_STOCK: u64 = 200;

#[derive(Debug, Deserialize)]
pub struct PublishBody {
    pub key_packages_b64: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishResult {
    pub did: String,
    /// Packages stored by this request. Duplicates of packages already seen —
    /// including consumed ones — are skipped, not errors.
    pub accepted: usize,
    pub available: u64,
    pub last_resort: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPackageBody {
    pub key_package_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StockBody {
    pub available: u64,
    pub last_resort: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupInfoBody {
    pub slug: String,
    pub epoch: u64,
    pub group_info_b64: String,
}

fn bad(code: &'static str, msg: impl Into<String>) -> (StatusCode, Json<ErrorBody>) {
    err(StatusCode::BAD_REQUEST, code, msg)
}

/// POST /api/v1/mls/key-packages
///
/// No request signature: every key package is signed by its DID's own key and
/// names that DID in its credential (`jig_mls::credential`), which is a
/// stronger proof than a request header — nobody can publish for a DID whose
/// key they do not hold. The publisher still passes admission.
pub async fn publish_key_packages(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PublishBody>,
) -> Result<Json<PublishResult>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    if body.key_packages_b64.is_empty() || body.key_packages_b64.len() > MAX_BATCH {
        return Err(bad(
            "BAD_BATCH",
            format!("publish between 1 and {MAX_BATCH} key packages at a time"),
        ));
    }
    let mut validated = Vec::with_capacity(body.key_packages_b64.len());
    for (i, b64) in body.key_packages_b64.iter().enumerate() {
        let bytes = STANDARD
            .decode(b64)
            .map_err(|e| bad("BAD_KEY_PACKAGE", format!("key package {i}: {e}")))?;
        let info = jig_mls::delivery::validate_key_package(&bytes)
            .map_err(|e| bad("BAD_KEY_PACKAGE", format!("key package {i}: {e}")))?;
        validated.push((bytes, info));
    }
    let did = validated[0].1.did.clone();
    if validated.iter().any(|(_, info)| info.did != did) {
        return Err(bad(
            "BAD_BATCH",
            "every key package in a batch must belong to one DID",
        ));
    }
    state
        .auth
        .admit(&did)
        .map_err(|outcome| refuse(&state, &outcome, started))?;

    let store = &state.ingest_ctx.store;
    let (mut available, _) = store.key_package_stock(&did).map_err(persist_err)?;
    let now = chrono::Utc::now().timestamp();
    let mut accepted = 0;
    for (bytes, info) in validated {
        if !info.last_resort && available >= MAX_STOCK {
            break;
        }
        if store
            .insert_key_package(&info.reference, &did, &bytes, info.last_resort, now)
            .map_err(persist_err)?
        {
            accepted += 1;
            if !info.last_resort {
                available += 1;
            }
        }
    }
    let (available, last_resort) = store.key_package_stock(&did).map_err(persist_err)?;
    Ok(Json(PublishResult {
        did,
        accepted,
        available,
        last_resort,
    }))
}

/// GET /api/v1/mls/key-packages/:did — hand out one package, consuming it
/// unless it is the DID's last resort.
pub async fn take_key_package(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<KeyPackageBody>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    admit_caller(&state, &headers, "GET", uri.path(), started)?;
    let did = jig_pipeline::effect::canonical_did_string(&did);
    let now = chrono::Utc::now().timestamp();
    match state
        .ingest_ctx
        .store
        .take_key_package(&did, now)
        .map_err(persist_err)?
    {
        Some(bytes) => Ok(Json(KeyPackageBody {
            key_package_b64: STANDARD.encode(bytes),
        })),
        None => Err(err(
            StatusCode::NOT_FOUND,
            "NO_KEY_PACKAGE",
            format!("{did} has published no MLS key packages here; they need to run a jig client against this server once"),
        )),
    }
}

/// GET /api/v1/mls/key-packages/:did/stock
pub async fn key_package_stock(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<StockBody>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    admit_caller(&state, &headers, "GET", uri.path(), started)?;
    let did = jig_pipeline::effect::canonical_did_string(&did);
    let (available, last_resort) = state
        .ingest_ctx
        .store
        .key_package_stock(&did)
        .map_err(persist_err)?;
    Ok(Json(StockBody {
        available,
        last_resort,
    }))
}

/// GET /api/v1/channels/:slug/mls/group-info — the newest group info a
/// committer published, for joining by external commit. Same read gates as
/// the timeline: a restricted channel's group info goes to its members only.
pub async fn group_info(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<GroupInfoBody>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    let caller = admit_caller(&state, &headers, "GET", uri.path(), started)?;
    if let Some(caller) = caller.as_ref() {
        authorize_channel_read(&state, &slug, caller, started)?;
    }
    let group = state
        .ingest_ctx
        .store
        .get_mls_group(&slug)
        .map_err(persist_err)?;
    match group {
        Some(g) => match g.group_info {
            Some(info) => Ok(Json(GroupInfoBody {
                slug,
                epoch: g.epoch,
                group_info_b64: STANDARD.encode(info),
            })),
            None => Err(err(
                StatusCode::NOT_FOUND,
                "NO_GROUP_INFO",
                format!("no member of '{slug}' has published a group info for its current epoch"),
            )),
        },
        None => Err(err(
            StatusCode::NOT_FOUND,
            "NOT_ENCRYPTED",
            format!("'{slug}' is not an encrypted channel on this server"),
        )),
    }
}

pub fn build_mls_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/mls/key-packages", post(publish_key_packages))
        .route("/api/v1/mls/key-packages/:did", get(take_key_package))
        .route("/api/v1/mls/key-packages/:did/stock", get(key_package_stock))
        .route("/api/v1/channels/:slug/mls/group-info", get(group_info))
        .with_state(state)
}
