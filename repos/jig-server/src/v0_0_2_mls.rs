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
    ErrorBody, admit_caller, authorize_channel_ref_read, err, persist_err, refuse,
};

/// Most packages one request may publish.
pub const MAX_BATCH: usize = 100;
/// Most unconsumed ordinary packages one DID may hold. Bounds what any one
/// self-minted identity can make this server store.
pub const MAX_STOCK: u64 = 200;

#[derive(Debug, Serialize, Deserialize)]
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
/// No request signature is needed to stock: every key package is signed by
/// its DID's own key and names that DID in its credential
/// (`jig_mls::credential`), so nobody can make a package for a DID whose key
/// they do not hold. The publisher still passes admission.
///
/// Replacing the DID's last-resort package needs more, because a package
/// signature is not fresh: whoever was released an old last-resort package
/// could upload it here and replace a usable one with one whose key its owner
/// deleted. So a replacement needs the request itself signed by the DID, over
/// the exact body bytes, so the proof cannot be replayed with other packages.
/// An upload without such a proof while one is held is skipped, as before.
pub async fn publish_key_packages(
    State(state): State<Arc<AppState>>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    raw: axum::body::Bytes,
) -> Result<Json<PublishResult>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    // A proof that does not verify over these bytes is no owner's, but the
    // upload may still stock: package signatures carry that.
    let signer =
        crate::v0_0_2_blocks::verify_proof(&state, &headers, "POST", uri.path(), &raw, started)
            .ok()
            .flatten();
    let body: PublishBody =
        serde_json::from_slice(&raw).map_err(|e| bad("BAD_BATCH", format!("request body: {e}")))?;
    if body.key_packages_b64.is_empty() || body.key_packages_b64.len() > MAX_BATCH {
        return Err(bad(
            "BAD_BATCH",
            format!("publish between 1 and {MAX_BATCH} key packages at a time"),
        ));
    }
    let mut validated = Vec::new();
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
    let owner_signed = signer.is_some_and(|caller| caller.to_did_jig_string() == did);
    state
        .auth
        .admit_and_charge(&did)
        .map_err(|outcome| refuse(&state, &outcome, started))?;

    let store = &state.ingest_ctx.store;
    let now = chrono::Utc::now().timestamp();
    let packages: Vec<(Vec<u8>, Vec<u8>, bool)> = validated
        .into_iter()
        .map(|(bytes, info)| (info.reference, bytes, info.last_resort))
        .collect();
    let ours = state.server_did.to_did_jig_string();
    let accepted = match store
        .stock_key_packages(&did, &packages, MAX_STOCK, &ours, owner_signed, now)
        .map_err(persist_err)?
    {
        jig_pipeline::persist::Stocked::Accepted(n) => n as usize,
        // JEP-0017 rule 19: custody and local adds are both ended here.
        jig_pipeline::persist::Stocked::NotStockedHere => {
            return Err(err(
                StatusCode::FORBIDDEN,
                "NOT_STOCKED_HERE",
                format!(
                    "{did} has ended both custody and local adds at this server, so its key \
                     packages have no use here"
                ),
            ));
        }
    };
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
///
/// Held to the same hourly limits as a custodian's releases
/// (`[custody] per_member_per_hour`, `per_requester_per_hour`) and logged in
/// the same release log, so this route cannot drain a DID's stock past them.
/// The caller is the requester; with unauthenticated reads, every caller
/// shares one anonymous bucket. Nothing names the channel here, so a repeat
/// is never answered with an earlier package: one package must not serve two
/// channels.
pub async fn take_key_package(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<KeyPackageBody>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    let caller = admit_caller(&state, &headers, "GET", uri.path(), started)?;
    let did = jig_pipeline::effect::canonical_did_string(&did);
    let now = chrono::Utc::now().timestamp();
    let requester = caller.map(|c| c.as_str().to_string()).unwrap_or_default();
    let take_id: [u8; 32] = rand::random();
    let custody = &state.config.custody;
    let ours = state.server_did.to_did_jig_string();
    let ask = jig_pipeline::persist::ReleaseAsk {
        did: &did,
        requester: &requester,
        channel_id: "",
        request_hash: &take_id,
        request: &[],
        now,
        repeat_window: 0,
        repeat: false,
        per_did: custody.per_member_per_hour,
        per_requester: custody.per_requester_per_hour,
        listing: None,
        kind: jig_pipeline::persist::ReleaseKind::Local,
        server_did: &ours,
    };
    match state
        .ingest_ctx
        .store
        .release_key_package(&ask)
        .map_err(persist_err)?
    {
        jig_pipeline::persist::Release::Released { package, .. }
        | jig_pipeline::persist::Release::Again { package, .. } => Ok(Json(KeyPackageBody {
            key_package_b64: STANDARD.encode(package),
        })),
        jig_pipeline::persist::Release::Limited(_) => Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            format!("{did}'s key packages were taken too often in the last hour; try again later"),
        )),
        jig_pipeline::persist::Release::LocalAddsEnded => {
            Err(crate::v0_0_2_custody::local_adds_ended(&did))
        }
        jig_pipeline::persist::Release::Empty | jig_pipeline::persist::Release::NotListed => {
            Err(err(
                StatusCode::NOT_FOUND,
                "NO_KEY_PACKAGE",
                format!(
                    "{did} has published no MLS key packages here; they need to run a jig client against this server once"
                ),
            ))
        }
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

/// GET /api/v1/channels/:channel/mls/group-info — the newest group info a
/// committer published, for joining by external commit. Same read gates as
/// the timeline: a restricted channel's group info goes to its members only.
/// `:channel` is the channel's id or a slug this server sequences.
pub async fn group_info(
    State(state): State<Arc<AppState>>,
    Path(channel_ref): Path<String>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<GroupInfoBody>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    let caller = admit_caller(&state, &headers, "GET", uri.path(), started)?;
    let store = &state.ingest_ctx.store;
    let channel = match caller.as_ref() {
        Some(caller) => authorize_channel_ref_read(&state, &channel_ref, caller, started)?,
        None => store
            .get_channel_by_ref_including_archived(&channel_ref)
            .map_err(persist_err)?,
    };
    let group = match channel.as_ref() {
        Some(c) => store.get_mls_group_by_id(&c.id).map_err(persist_err)?,
        None => None,
    };
    let slug = channel.map_or(channel_ref, |c| c.slug);
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
        .route("/api/v1/mls/key-packages/{did}", get(take_key_package))
        .route(
            "/api/v1/mls/key-packages/{did}/stock",
            get(key_package_stock),
        )
        .route("/api/v1/channels/{channel}/mls/group-info", get(group_info))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(seed: u8) -> (jig_mls::member::Member, String) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let did = jig_core::Did::from_ed25519_pubkey(&key.verifying_key().to_bytes());
        (
            jig_mls::member::Member::new(&[seed; 32], &did).unwrap(),
            did.to_did_jig_string(),
        )
    }

    async fn publish(state: &Arc<AppState>, packages: &[Vec<u8>]) -> PublishResult {
        publish_as(state, packages, None).await
    }

    fn body_of(packages: &[Vec<u8>]) -> Vec<u8> {
        serde_json::to_vec(&PublishBody {
            key_packages_b64: packages.iter().map(|p| STANDARD.encode(p)).collect(),
        })
        .unwrap()
    }

    /// Publish `packages`, with the request signed by `signer` if given.
    async fn publish_as(
        state: &Arc<AppState>,
        packages: &[Vec<u8>],
        signer: Option<u8>,
    ) -> PublishResult {
        let body = body_of(packages);
        publish_signed_over(state, &body, signer.map(|s| (s, body.clone()))).await
    }

    /// Send `body`, with a proof by `signer` over `signed` (which may differ).
    async fn publish_signed_over(
        state: &Arc<AppState>,
        body: &[u8],
        signer: Option<(u8, Vec<u8>)>,
    ) -> PublishResult {
        let path = "/api/v1/mls/key-packages";
        let mut headers = axum::http::HeaderMap::new();
        if let Some((seed, signed)) = signer {
            let identity = jig_client::identity::Identity::from_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            );
            for (name, value) in
                jig_client::read_auth::ReadProof::sign_body(&identity, "POST", path, &signed)
                    .headers()
            {
                headers.insert(name, value.parse().unwrap());
            }
        }
        let Json(result) = publish_key_packages(
            State(state.clone()),
            path.parse().unwrap(),
            headers,
            body.to_vec().into(),
        )
        .await
        .unwrap();
        result
    }

    /// Each last-resort package has a fresh reference, so without a cap one
    /// DID could store as many as it liked. A new one replaces the old
    /// (JEP-0017 rule 32), and one batch replaces it at most once.
    #[tokio::test]
    async fn a_did_keeps_one_last_resort_package() {
        let state = Arc::new(AppState::for_test().unwrap());
        let (m, did) = member(7);
        let mut batch = m.key_packages(2, false).unwrap();
        batch.extend(m.key_packages(3, true).unwrap());
        let first = publish(&state, &batch).await;
        assert_eq!(first.did, did);
        assert_eq!(
            (first.accepted, first.available, first.last_resort),
            (3, 2, true)
        );

        let unsigned = publish(&state, &m.key_packages(1, true).unwrap()).await;
        assert_eq!(
            unsigned.accepted, 0,
            "an unsigned upload does not replace the held last-resort package"
        );
        let again = publish_as(&state, &m.key_packages(2, true).unwrap(), Some(7)).await;
        assert_eq!(
            (again.accepted, again.available, again.last_resort),
            (1, 2, true),
            "a new last-resort package replaces the old, once per batch"
        );
        let stranger = publish_as(&state, &m.key_packages(1, true).unwrap(), Some(8)).await;
        assert_eq!(
            stranger.accepted, 0,
            "a request signed by another DID does not replace it"
        );
        // The owner's proof for one body, replayed with another: the
        // packages it brings do not replace the held one.
        let signed_for = body_of(&m.key_packages(1, true).unwrap());
        let replayed = body_of(&m.key_packages(1, true).unwrap());
        let r = publish_signed_over(&state, &replayed, Some((7, signed_for))).await;
        assert_eq!(
            r.accepted, 0,
            "a proof over another body does not replace it"
        );
    }

    #[tokio::test]
    async fn taking_packages_here_is_held_to_the_custody_limits_and_logged() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.auth.require_authenticated_reads = false;
        config.custody.per_member_per_hour = 2;
        let state = Arc::new(AppState::for_test_with_config(config).unwrap());
        let (m, did) = member(7);
        publish(&state, &m.key_packages(5, false).unwrap()).await;
        let take = || {
            take_key_package(
                State(state.clone()),
                Path(did.clone()),
                format!("/api/v1/mls/key-packages/{did}").parse().unwrap(),
                axum::http::HeaderMap::new(),
            )
        };
        let Json(one) = take().await.unwrap();
        let Json(two) = take().await.unwrap();
        assert_ne!(
            one.key_package_b64, two.key_package_b64,
            "never one package twice"
        );
        let refused = take().await.unwrap_err();
        assert_eq!(refused.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            state.ingest_ctx.store.key_package_stock(&did).unwrap(),
            (3, false)
        );
        let log = state
            .ingest_ctx
            .store
            .key_package_releases(&did, 10)
            .unwrap();
        assert_eq!(log.len(), 2);
        assert!(
            log.iter()
                .all(|e| e.kind == jig_pipeline::persist::ReleaseKind::Local)
        );
    }

    #[tokio::test]
    async fn a_batch_must_belong_to_one_did() {
        let state = Arc::new(AppState::for_test().unwrap());
        let (a, _) = member(1);
        let (b, _) = member(2);
        let mut batch = a.key_packages(1, false).unwrap();
        batch.extend(b.key_packages(1, false).unwrap());
        let refused = publish_key_packages(
            State(state),
            "/api/v1/mls/key-packages".parse().unwrap(),
            axum::http::HeaderMap::new(),
            body_of(&batch).into(),
        )
        .await;
        assert!(matches!(refused, Err((StatusCode::BAD_REQUEST, _))));
    }
}
