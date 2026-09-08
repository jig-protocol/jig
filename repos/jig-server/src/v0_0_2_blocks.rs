//! v0.0.2 REST block endpoints under `/api/v1/blocks`.
//!
//! - POST /api/v1/blocks       non-streaming alternative to WSS Submit
//! - GET  /api/v1/blocks/:cid  fetch a stored block + all known receipts
//!
//! Same envelope + canonical-bytes conventions as the WSS handler
//! (`v0_0_2_ws.rs`); same error codes. REST is the easy on-ramp for
//! non-streaming integrations (curl, jig-cli's existing HTTP path
//! until Phase F replaces it).

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine as _;
use jig_core::BlockBundle;
use jig_pipeline::envelope::ReceiptRef;
use jig_pipeline::ingest::{IngestError, IngestSource, ingest};
use jig_pipeline::persist::MAX_HISTORY_LIMIT;
use serde::{Deserialize, Serialize};

use crate::v0_0_2::AppState;

#[derive(Debug, Deserialize)]
pub struct SubmitBody {
    pub bundle_b64: String,
    pub sig_b64: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitResult {
    pub block_cid: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

fn err(
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

/// Thin wrapper around the shared classifier (`v0_0_2_ingest_error`): decide
/// the (status, code) here once, wrap it in this endpoint's `ErrorBody`.
/// `pub(crate)` so the cross-wrapper agreement test in that module can call
/// it directly.
pub(crate) fn map_ingest_error(e: IngestError) -> (StatusCode, Json<ErrorBody>) {
    let (status, code, message) = crate::v0_0_2_ingest_error::classify_ingest_error(&e);
    err(status, code, message)
}

/// POST /api/v1/blocks — submit a signed block bundle (non-streaming alt to WSS).
///
/// Body: `{ "bundle_b64": "...", "sig_b64": "..." }` where `bundle_b64` is the
/// canonical-bytes representation (JSON-serialized `(manifest_bytes, code_bytes)` tuple,
/// base64-encoded). Returns `{ "block_cid": "bafy..." }` on success.
pub async fn submit_block(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SubmitBody>,
) -> Result<Json<SubmitResult>, (StatusCode, Json<ErrorBody>)> {
    let bundle_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.bundle_b64)
        .map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                "BAD_BUNDLE_B64",
                format!("bundle_b64 decode: {e}"),
            )
        })?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(&body.sig_b64)
        .map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                "BAD_SIG_B64",
                format!("sig_b64 decode: {e}"),
            )
        })?;

    // Decode the canonical-bytes tuple: (manifest_bytes, code_bytes).
    // BlockBundle has no from_canonical_bytes — decode manually (same as D3/D4 pattern).
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                "BAD_BUNDLE",
                format!("bundle tuple parse: {e}"),
            )
        })?;

    let bundle = BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    };

    // conn_id 0 signals REST origin — no persistent WebSocket connection.
    let cid = ingest(
        &state.ingest_ctx,
        bundle,
        sig,
        IngestSource::LocalClient { conn_id: 0 },
    )
    .await
    .map_err(map_ingest_error)?;

    Ok(Json(SubmitResult { block_cid: cid }))
}

#[derive(Debug, Serialize)]
pub struct BlockView {
    pub block_cid: String,
    pub sender_did: String,
    pub block_kind: String,
    pub bundle_b64: String,
    pub is_synthetic: bool,
    pub posted_at: i64,
    pub hlc_wall_ms: u64,
    pub hlc_logical: u32,
    pub hlc_origin: String,
    pub origin_server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federated_from: Option<String>,
    pub receipts: Vec<ReceiptView>,
}

#[derive(Debug, Serialize)]
pub struct ReceiptView {
    pub cid: String,
    pub server_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub render_hash: Option<String>,
    pub receipt_bytes_b64: String,
    pub produced_at: i64,
}

/// GET /api/v1/blocks/:cid — fetch a stored block and all known receipts.
///
/// Returns 404 with `{ code: "NOT_FOUND" }` if the CID is absent.
pub async fn get_block_by_cid(
    State(state): State<Arc<AppState>>,
    Path(cid): Path<String>,
) -> Result<Json<BlockView>, (StatusCode, Json<ErrorBody>)> {
    let stored = state
        .ingest_ctx
        .store
        .get_block(&cid)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PERSIST_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                format!("no block with cid {cid}"),
            )
        })?;

    let receipts = state
        .ingest_ctx
        .store
        .get_receipts_for_block(&cid)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PERSIST_ERROR",
                e.to_string(),
            )
        })?
        .into_iter()
        .map(|r| ReceiptView {
            cid: r.cid,
            server_id: r.server_id,
            render_hash: r.render_hash,
            receipt_bytes_b64: base64::engine::general_purpose::STANDARD.encode(&r.receipt_bytes),
            produced_at: r.produced_at,
        })
        .collect();

    Ok(Json(BlockView {
        block_cid: stored.cid,
        sender_did: stored.sender_did,
        block_kind: stored.block_kind,
        bundle_b64: base64::engine::general_purpose::STANDARD.encode(&stored.bundle_bytes),
        is_synthetic: stored.is_synthetic,
        posted_at: stored.posted_at,
        hlc_wall_ms: stored.hlc_wall_ms,
        hlc_logical: stored.hlc_logical,
        hlc_origin: stored.hlc_origin,
        origin_server: stored.origin_server,
        federated_from: stored.federated_from,
        receipts,
    }))
}

// ---- Channel list endpoint --------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ChannelView {
    pub slug: String,
    pub visibility: String,
    pub owner_did: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ChannelsResponse {
    pub channels: Vec<ChannelView>,
}

/// GET /api/v1/channels — list all channels known to this server.
///
/// Channels are public state in v0.0.2 (no per-channel ACL on listing — the
/// visibility flag governs join semantics, not listing). Not debug-gated.
pub async fn list_channels(
    State(state): State<Arc<AppState>>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<ChannelsResponse>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    // Phase 3 consumes this to filter restricted channels from the listing.
    let caller_did = authenticate_read(&state, &headers, "GET", uri.path(), started)?;
    let _ = &caller_did;

    let stored = state.ingest_ctx.store.list_channels().map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PERSIST_ERROR",
            e.to_string(),
        )
    })?;
    let channels = stored
        .into_iter()
        .map(|c| ChannelView {
            slug: c.slug,
            visibility: c.visibility,
            owner_did: c.owner_did,
            created_at: c.created_at,
        })
        .collect();
    Ok(Json(ChannelsResponse { channels }))
}

// ---- Channel history endpoint -----------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Omitted means "as much as the store will give" — the store clamps to
    /// `MAX_HISTORY_LIMIT` either way, so this is never unbounded.
    pub limit: Option<usize>,
}

/// One entry of a channel timeline.
///
/// ⚠️ CROSS-CRATE WIRE CONTRACT: a JSON array of these MUST deserialize into
/// `Vec<jig_client::DeliveredBlock>`, which is how the CLI reads history.
/// It is a deliberate mirror rather than a re-use of the client struct so the
/// server's response shape isn't welded to a client-crate definition; the
/// `channel_history_deserializes_into_delivered_blocks` test below is what
/// keeps the two honest.
#[derive(Debug, Serialize)]
pub struct TimelineBlock {
    pub bundle_b64: String,
    /// Sender's ed25519 signature over the canonical bundle bytes.
    ///
    /// NOT YET WIRED on the read side: `jig_client::DeliveredBlock` has no
    /// `sig_b64` field today, so clients discard this. It is emitted now so
    /// that adding the field client-side is a one-sided change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig_b64: Option<String>,
    pub receipts: Vec<ReceiptRef>,
    pub delivery_cid: String,
}

fn persist_err(e: impl std::fmt::Display) -> (StatusCode, Json<ErrorBody>) {
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "PERSIST_ERROR",
        e.to_string(),
    )
}

/// GET /api/v1/channels/:slug/blocks?limit=N — replay a channel's timeline.
///
/// Clients percent-encode the leading `#` (`%23hello`); axum's `Path`
/// extractor decodes the segment before this handler sees it.
///
/// Blocks come back **oldest-first**, capped to the newest `limit` (see
/// `SqliteStore::list_blocks_by_channel`), so a chat client renders the array
/// straight down the pane. An unknown or silent channel is `200` with `[]`.
/// Run gate 1 for a read, returning the authenticated caller.
///
/// `Ok(None)` means the server is running with `require_authenticated_reads =
/// false` — the migration escape hatch — and no identity was established.
///
/// `path` must be the path the caller actually requested, taken from the
/// request URI rather than rebuilt from extracted parameters. The signature
/// covers the path as sent, so reconstructing it invites an encoding mismatch
/// that would present as "every signature is invalid".
fn authenticate_read(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    method: &str,
    path: &str,
    started: std::time::Instant,
) -> Result<Option<jig_core::did::Did>, (StatusCode, Json<ErrorBody>)> {
    if !state.config.auth.require_authenticated_reads {
        return Ok(None);
    }

    let Some(proof) = crate::auth::authenticate::proof_from_headers(headers) else {
        return Err(refuse(
            state,
            &crate::auth::GateOutcome::AuthMissing,
            started,
        ));
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut guard = state
        .auth
        .replay_guard
        .lock()
        .expect("replay guard mutex poisoned");

    match crate::auth::authenticate(&proof, method, path, b"", now_ms, &mut guard) {
        Ok(did) => Ok(Some(did)),
        Err(outcome) => Err(refuse(state, &outcome, started)),
    }
}

/// Map a gate outcome to a response through this server's disclosure policy,
/// logging the true outcome regardless of what the policy emits.
///
/// **This is the single disclosure point for the read path.** Every refusal
/// routes through here, which is what lets a concealing policy be added later
/// without editing call sites — and what gives a timing mitigation somewhere to
/// live.
///
/// `started` is unused today and deliberately so: gates refuse at different
/// depths, so a future constant-time mitigation must know how long the request
/// has already taken in order to pad to a fixed floor. Threading it now costs
/// one parameter; adding it later would mean touching every call site again.
fn refuse(
    state: &AppState,
    outcome: &crate::auth::GateOutcome,
    started: std::time::Instant,
) -> (StatusCode, Json<ErrorBody>) {
    let _ = started; // reserved for timing normalization; see doc comment
    tracing::info!(audit = %crate::auth::audit_line(outcome), "read refused");

    let (status, code, message) = state.auth.disclosure.disclose(outcome);
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
    err(status, code, message)
}

pub async fn get_channel_history(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(query): Query<HistoryQuery>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<TimelineBlock>>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    // Phase 3 consumes this to enforce membership on restricted channels.
    let caller_did = authenticate_read(&state, &headers, "GET", uri.path(), started)?;
    let _ = &caller_did;

    let store = &state.ingest_ctx.store;
    let blocks = store
        .list_blocks_by_channel(&slug, query.limit.unwrap_or(MAX_HISTORY_LIMIT), None)
        .map_err(persist_err)?;

    let mut timeline = Vec::with_capacity(blocks.len());
    for block in blocks {
        let receipts = store
            .get_receipts_for_block(&block.cid)
            .map_err(persist_err)?
            .into_iter()
            .map(|r| ReceiptRef {
                server_did: r.server_id,
                render_hash: r.render_hash,
                receipt_bytes_b64: base64::engine::general_purpose::STANDARD
                    .encode(&r.receipt_bytes),
            })
            .collect();
        timeline.push(TimelineBlock {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(&block.bundle_bytes),
            sig_b64: (!block.sender_sig.is_empty())
                .then(|| base64::engine::general_purpose::STANDARD.encode(&block.sender_sig)),
            receipts,
            // Same `delivery:<cid>` shape the WSS fanout emits, so a client
            // that dedupes on delivery_cid sees replay and live delivery of
            // the same block as one identity.
            delivery_cid: format!("delivery:{}", block.cid),
        });
    }
    Ok(Json(timeline))
}

/// Construct the REST sub-router. Merged into the v0.0.2 router by
/// `v0_0_2_ws::build_v0_0_2_router`. Not debug-gated — these are
/// production endpoints.
pub fn build_blocks_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/blocks", post(submit_block))
        .route("/api/v1/blocks/:cid", get(get_block_by_cid))
        .route("/api/v1/channels", get(list_channels))
        .route("/api/v1/channels/:slug/blocks", get(get_channel_history))
        .with_state(state)
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request};
    use jig_client::{Identity, blocks::build_text_render};
    use jig_core::HlcTimestamp;
    use tempfile::tempdir;
    use tower::ServiceExt; // for `oneshot`

    /// State for tests about history/listing SEMANTICS rather than access
    /// control.
    ///
    /// Read handlers now require a proof of possession by default. These tests
    /// predate that and are not about it — making each one sign a request would
    /// bury what they actually assert. They run with the documented migration
    /// escape hatch instead; authentication itself is covered by
    /// `tests/authenticated_reads.rs` and `auth::authenticate`.
    fn unauthenticated_state() -> AppState {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.auth.require_authenticated_reads = false;
        AppState::for_test_with_config(config).unwrap()
    }

    fn test_identity() -> Identity {
        let dir = tempdir().unwrap();
        let path = dir.keep();
        Identity::generate_and_save(&path).unwrap()
    }

    fn test_hlc(id: &Identity) -> HlcTimestamp {
        HlcTimestamp {
            wall_ms: 1_747_680_000_000,
            logical: 0,
            server_did: id.did().clone(),
        }
    }

    /// Seed a channel row so `text-render` submissions clear ingest's
    /// channel-existence guard. Writing the row directly keeps these tests
    /// focused on the blocks endpoints rather than on channel-create.
    fn seed_channel(state: &AppState, slug: &str) {
        state
            .ingest_ctx
            .store
            .upsert_channel(&jig_pipeline::persist::StoredChannel {
                id: format!("bafySeed{slug}"),
                slug: slug.to_string(),
                visibility: "open".to_string(),
                created_at: 0,
                owner_did: "did:jig:zSeedOwner".to_string(),
            })
            .unwrap();
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

    #[tokio::test]
    async fn submit_block_round_trips_through_ingest() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_blocks_router(state.clone());
        seed_channel(&state, "#hello");

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            "sig_b64": base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });

        let (status, body) = post_json(router, "/api/v1/blocks", submission).await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        assert!(!body["block_cid"].as_str().unwrap_or("").is_empty());
    }

    #[tokio::test]
    async fn submit_rejects_invalid_signature() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_blocks_router(state);

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            "sig_b64": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
        });

        let (status, body) = post_json(router, "/api/v1/blocks", submission).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "INVALID_SIG");
    }

    #[tokio::test]
    async fn submit_rejects_bad_base64() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_blocks_router(state);

        let submission = serde_json::json!({
            "bundle_b64": "!!!not-base64!!!",
            "sig_b64": "also-not-base64-@@@",
        });
        let (status, body) = post_json(router, "/api/v1/blocks", submission).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "BAD_BUNDLE_B64");
    }

    #[tokio::test]
    async fn get_block_returns_404_for_unknown_cid() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_blocks_router(state);

        let (status, body) = get_path(router, "/api/v1/blocks/bafy_unknown").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn submit_then_get_round_trips() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_blocks_router(state.clone());
        seed_channel(&state, "#hello");

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            "sig_b64": base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });

        let (status, submit_body) = post_json(router.clone(), "/api/v1/blocks", submission).await;
        assert_eq!(status, StatusCode::OK);
        let cid = submit_body["block_cid"].as_str().unwrap().to_string();

        let (status, get_body) = get_path(router, &format!("/api/v1/blocks/{cid}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(get_body["block_cid"], cid);
        assert_eq!(get_body["block_kind"], "text-render");
        assert_eq!(get_body["sender_did"], id.did_string());
        assert!(
            !get_body["receipts"].as_array().unwrap().is_empty(),
            "must have at least one receipt"
        );
        assert!(!get_body["bundle_b64"].as_str().unwrap_or("").is_empty());
    }

    // ---- list_channels tests --------------------------------------------------

    #[tokio::test]
    async fn list_channels_returns_empty_when_no_channels_exist() {
        let state = Arc::new(unauthenticated_state());
        let router = build_blocks_router(state);

        let (status, body) = get_path(router, "/api/v1/channels").await;
        assert_eq!(status, StatusCode::OK);
        let channels = body["channels"].as_array().expect("channels array");
        assert!(channels.is_empty(), "fresh store has no channels");
    }

    #[tokio::test]
    async fn list_channels_returns_channels_after_admin_create() {
        // Round-trip: create a channel via the admin endpoint, then GET
        // /api/v1/channels and assert the new channel appears. This is the
        // happy-path coverage the F4 spec asks for.
        use jig_client::blocks::build_channel_create;

        let state = Arc::new(unauthenticated_state());

        // Build a combined router with both blocks (list_channels) and
        // admin (create_channel) routes mounted on the same state.
        let router = build_blocks_router(state.clone())
            .merge(crate::v0_0_2_admin::build_admin_router(state.clone()));

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_channel_create(&id, "#hello", "open", hlc);
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            "sig_b64": base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });

        let (status, _body) =
            post_json(router.clone(), "/_admin_v0_0_2/channels", submission).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = get_path(router, "/api/v1/channels").await;
        assert_eq!(status, StatusCode::OK);
        let channels = body["channels"].as_array().expect("channels array");
        assert_eq!(channels.len(), 1, "exactly one channel expected");
        assert_eq!(channels[0]["slug"], "#hello");
        assert_eq!(channels[0]["visibility"], "open");
        assert_eq!(channels[0]["owner_did"], id.did_string());
        assert!(
            channels[0]["created_at"].as_i64().unwrap_or(0) >= 0,
            "created_at must be present as an integer"
        );
    }

    #[tokio::test]
    async fn list_channels_returns_multiple_channels_sorted_by_slug() {
        // SqliteStore::list_channels ORDERs BY slug — confirm we surface
        // that ordering so CLI output is stable across invocations.
        use jig_client::blocks::build_channel_create;

        let state = Arc::new(unauthenticated_state());
        let router = build_blocks_router(state.clone())
            .merge(crate::v0_0_2_admin::build_admin_router(state.clone()));

        let id = test_identity();
        // Create channels in a non-sorted order; expect sorted output.
        for slug in ["#zulu", "#alpha", "#mike"] {
            let hlc = test_hlc(&id);
            let block = build_channel_create(&id, slug, "open", hlc);
            let submission = serde_json::json!({
                "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
                "sig_b64":    base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
            });
            let (status, _) =
                post_json(router.clone(), "/_admin_v0_0_2/channels", submission).await;
            assert_eq!(status, StatusCode::OK, "creating {slug}");
        }

        let (status, body) = get_path(router, "/api/v1/channels").await;
        assert_eq!(status, StatusCode::OK);
        let slugs: Vec<_> = body["channels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["slug"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(slugs, vec!["#alpha", "#mike", "#zulu"]);
    }

    // ---- channel history tests ------------------------------------------

    /// Submit `texts` to `slug` in order, each with a distinct HLC logical
    /// tick so the timeline order is deterministic. Seeds the channel first —
    /// ingest rejects text-render to a channel that doesn't exist.
    async fn submit_texts(
        state: &AppState,
        router: &Router,
        id: &Identity,
        slug: &str,
        texts: &[&str],
    ) {
        seed_channel(state, slug);
        for (i, text) in texts.iter().enumerate() {
            let mut hlc = test_hlc(id);
            hlc.logical = i as u32;
            let block = build_text_render(id, slug, text, hlc);
            let submission = serde_json::json!({
                "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
                "sig_b64": base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
            });
            let (status, body) = post_json(router.clone(), "/api/v1/blocks", submission).await;
            assert_eq!(status, StatusCode::OK, "submitting {text}: {body}");
        }
    }

    /// Decode the base64 bundle back to the text payload the sender wrote,
    /// so assertions read as message content rather than opaque CIDs.
    fn text_of(bundle_b64: &str) -> String {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(bundle_b64)
            .unwrap();
        let (manifest_bytes, _code): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&bytes).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        manifest["metadata"]["body"]
            .as_str()
            .expect("text-render manifest carries metadata.body")
            .to_string()
    }

    #[tokio::test]
    async fn channel_history_deserializes_into_delivered_blocks() {
        // Cross-lane wire contract: the CLI decodes this response body with
        // `serde_json::from_str::<Vec<DeliveredBlock>>`.
        let state = Arc::new(unauthenticated_state());
        let router = build_blocks_router(state.clone());
        let id = test_identity();
        submit_texts(&state, &router, &id, "#hello", &["one", "two"]).await;

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/channels/%23hello/blocks")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();

        let history: Vec<jig_client::DeliveredBlock> = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("not a Vec<DeliveredBlock>: {e}\nbody={bytes:?}"));
        assert_eq!(history.len(), 2);
        assert_eq!(text_of(&history[0].bundle_b64), "one");
        assert_eq!(text_of(&history[1].bundle_b64), "two");
        assert!(!history[0].delivery_cid.is_empty());
    }

    #[tokio::test]
    async fn channel_history_percent_decodes_the_slug_and_scopes_to_it() {
        let state = Arc::new(unauthenticated_state());
        let router = build_blocks_router(state.clone());
        let id = test_identity();
        submit_texts(&state, &router, &id, "#hello", &["h1", "h2"]).await;
        submit_texts(&state, &router, &id, "#other", &["o1"]).await;

        let (status, body) = get_path(router, "/api/v1/channels/%23hello/blocks").await;
        assert_eq!(status, StatusCode::OK);
        let texts: Vec<String> = body
            .as_array()
            .expect("history is a JSON array")
            .iter()
            .map(|b| text_of(b["bundle_b64"].as_str().unwrap()))
            .collect();
        assert_eq!(texts, vec!["h1", "h2"]);
    }

    #[tokio::test]
    async fn channel_history_honours_the_limit_query_param() {
        let state = Arc::new(unauthenticated_state());
        let router = build_blocks_router(state.clone());
        let id = test_identity();
        submit_texts(&state, &router, &id, "#hello", &["a", "b", "c"]).await;

        // A truncating limit keeps the newest window, still oldest-first.
        let (status, body) = get_path(router, "/api/v1/channels/%23hello/blocks?limit=2").await;
        assert_eq!(status, StatusCode::OK);
        let texts: Vec<String> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|b| text_of(b["bundle_b64"].as_str().unwrap()))
            .collect();
        assert_eq!(texts, vec!["b", "c"]);
    }

    #[tokio::test]
    async fn channel_history_returns_empty_array_for_unknown_channel() {
        let state = Arc::new(unauthenticated_state());
        let router = build_blocks_router(state);

        let (status, body) = get_path(router, "/api/v1/channels/%23nope/blocks").await;
        assert_eq!(status, StatusCode::OK, "an unread channel is not an error");
        assert_eq!(body.as_array().map(|a| a.len()), Some(0));
    }

    #[tokio::test]
    async fn channel_history_rejects_a_non_numeric_limit() {
        let state = Arc::new(AppState::for_test().unwrap());
        let router = build_blocks_router(state);

        let (status, _body) = get_path(router, "/api/v1/channels/%23hello/blocks?limit=lots").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn channel_history_carries_receipts_for_parity_checks() {
        let state = Arc::new(unauthenticated_state());
        let router = build_blocks_router(state.clone());
        let id = test_identity();
        submit_texts(&state, &router, &id, "#hello", &["only"]).await;

        let (status, body) = get_path(router, "/api/v1/channels/%23hello/blocks").await;
        assert_eq!(status, StatusCode::OK);
        let receipts = body[0]["receipts"].as_array().expect("receipts array");
        assert!(!receipts.is_empty(), "ingest always writes a local receipt");
        assert!(!receipts[0]["server_did"].as_str().unwrap_or("").is_empty());
    }
}
