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
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine as _;
use jig_core::BlockBundle;
use jig_pipeline::ingest::{IngestError, IngestSource, ingest};
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

fn map_ingest_error(e: IngestError) -> (StatusCode, Json<ErrorBody>) {
    match e {
        IngestError::InvalidSignature => err(
            StatusCode::UNAUTHORIZED,
            "INVALID_SIG",
            "signature verification failed",
        ),
        IngestError::DisallowedBlockKind { kind } => err(
            StatusCode::FORBIDDEN,
            "DISALLOWED_BLOCK_KIND",
            format!("kind not in allow list: {kind}"),
        ),
        IngestError::KindRequired => err(
            StatusCode::BAD_REQUEST,
            "KIND_REQUIRED",
            "manifest must declare block kind",
        ),
        IngestError::BundleMalformed(m) => {
            err(StatusCode::BAD_REQUEST, "BUNDLE_MALFORMED", m)
        }
        IngestError::Identity(ide) => err(
            StatusCode::UNAUTHORIZED,
            "IDENTITY_ERROR",
            ide.to_string(),
        ),
        IngestError::Persist(pe) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PERSIST_ERROR",
            pe.to_string(),
        ),
        IngestError::Other(o) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INGEST_ERROR",
            o.to_string(),
        ),
    }
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
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&bundle_bytes).map_err(|e| {
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
            receipt_bytes_b64: base64::engine::general_purpose::STANDARD
                .encode(&r.receipt_bytes),
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
) -> Result<Json<ChannelsResponse>, (StatusCode, Json<ErrorBody>)> {
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

/// Construct the REST sub-router. Merged into the v0.0.2 router by
/// `v0_0_2_ws::build_v0_0_2_router`. Not debug-gated — these are
/// production endpoints.
pub fn build_blocks_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/blocks", post(submit_block))
        .route("/api/v1/blocks/:cid", get(get_block_by_cid))
        .route("/api/v1/channels", get(list_channels))
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

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            "sig_b64": base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });

        let (status, submit_body) =
            post_json(router.clone(), "/api/v1/blocks", submission).await;
        assert_eq!(status, StatusCode::OK);
        let cid = submit_body["block_cid"].as_str().unwrap().to_string();

        let (status, get_body) =
            get_path(router, &format!("/api/v1/blocks/{cid}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(get_body["block_cid"], cid);
        assert_eq!(get_body["block_kind"], "text-render");
        assert_eq!(get_body["sender_did"], id.did_string());
        assert!(
            get_body["receipts"].as_array().unwrap().len() >= 1,
            "must have at least one receipt"
        );
        assert!(!get_body["bundle_b64"].as_str().unwrap_or("").is_empty());
    }

    // ---- list_channels tests --------------------------------------------------

    #[tokio::test]
    async fn list_channels_returns_empty_when_no_channels_exist() {
        let state = Arc::new(AppState::for_test().unwrap());
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

        let state = Arc::new(AppState::for_test().unwrap());

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

        let state = Arc::new(AppState::for_test().unwrap());
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
}
