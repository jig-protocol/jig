//! `/_admin_v0_0_2/*` debug-gated REST endpoints — synthetic-block
//! factories for v0.0.2 channel ops. Clients sign a channel-create or
//! member-add bundle locally and POST it here; the server runs it
//! through the v0.0.2 ingest pipeline as if it had arrived via WSS.
//!
//! These endpoints exist because v0.0.2 doesn't yet have Wasm-executed
//! channel ops (that lands in v0.0.3+). They're an admin-only short
//! path to mutate channel + membership state. Mounting is gated on
//! `[debug] admin_endpoints = true` in the server config.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use base64::Engine as _;
use jig_core::{BlockBundle, BlockKind, BlockManifest};
use jig_pipeline::ingest::{IngestError, IngestSource, ingest};
use serde::{Deserialize, Serialize};

use crate::v0_0_2::AppState;

#[derive(Debug, Deserialize)]
pub struct BundleSubmission {
    pub bundle_b64: String,
    pub sig_b64: String,
}

#[derive(Debug, Serialize)]
pub struct AdminResult {
    pub block_cid: String,
}

#[derive(Debug, Serialize)]
pub struct AdminError {
    pub code: String,
    pub message: String,
}

fn err(
    status: StatusCode,
    code: &'static str,
    msg: impl Into<String>,
) -> (StatusCode, Json<AdminError>) {
    (
        status,
        Json(AdminError {
            code: code.to_string(),
            message: msg.into(),
        }),
    )
}

/// Decode a BundleSubmission into (manifest_bytes, code_bytes, sig).
#[allow(clippy::type_complexity)]
fn decode_submission(
    body: &BundleSubmission,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), (StatusCode, Json<AdminError>)> {
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
    // The canonical-bytes format is a JSON-serialized (manifest_bytes, code_bytes) tuple.
    // BlockBundle has no from_canonical_bytes — decode manually here.
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&bundle_bytes)
        .map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                "BAD_BUNDLE",
                format!("bundle tuple parse: {e}"),
            )
        })?;
    Ok((manifest_bytes, code_bytes, sig))
}

fn parse_manifest(manifest_bytes: &[u8]) -> Result<BlockManifest, (StatusCode, Json<AdminError>)> {
    serde_json::from_slice(manifest_bytes).map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            "BAD_MANIFEST",
            format!("manifest parse: {e}"),
        )
    })
}

fn map_ingest_error(e: IngestError) -> (StatusCode, Json<AdminError>) {
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
        IngestError::BundleMalformed(m) => err(StatusCode::BAD_REQUEST, "BUNDLE_MALFORMED", m),
        IngestError::Identity(ide) => {
            err(StatusCode::UNAUTHORIZED, "IDENTITY_ERROR", ide.to_string())
        }
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

/// POST /_admin_v0_0_2/channels
///
/// Body: `{ "bundle_b64": "...", "sig_b64": "..." }` where the bundle is
/// a signed channel-create block. The block kind MUST be `channel-create`.
///
/// Returns `{ "block_cid": "bafy..." }` on success.
pub async fn create_channel(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BundleSubmission>,
) -> Result<Json<AdminResult>, (StatusCode, Json<AdminError>)> {
    let (manifest_bytes, code_bytes, sig) = decode_submission(&body)?;
    let manifest = parse_manifest(&manifest_bytes)?;

    if manifest.kind != Some(BlockKind::ChannelCreate) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "WRONG_KIND",
            format!("expected channel-create bundle, got {:?}", manifest.kind),
        ));
    }

    let bundle = BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    };

    // channel-create must be in server's allowed_block_kinds; if not, ingest
    // returns DisallowedBlockKind — the right error to surface to the caller.
    let cid = ingest(&state.ingest_ctx, bundle, sig, IngestSource::AdminEndpoint)
        .await
        .map_err(map_ingest_error)?;

    Ok(Json(AdminResult { block_cid: cid }))
}

/// POST /_admin_v0_0_2/channels/:slug/members
///
/// Body: signed `member-add` block. The `slug` path parameter is asserted
/// to match the `channel` metadata in the bundle (defense in depth).
///
/// Returns `{ "block_cid": "bafy..." }` on success.
pub async fn add_member(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Json(body): Json<BundleSubmission>,
) -> Result<Json<AdminResult>, (StatusCode, Json<AdminError>)> {
    let (manifest_bytes, code_bytes, sig) = decode_submission(&body)?;
    let manifest = parse_manifest(&manifest_bytes)?;

    if manifest.kind != Some(BlockKind::MemberAdd) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "WRONG_KIND",
            format!("expected member-add bundle, got {:?}", manifest.kind),
        ));
    }

    // Defense in depth: the bundle's metadata `channel` must match the URL slug.
    // Prevents accidentally submitting a bundle for the wrong channel via an
    // authoritative-looking URL.
    let bundle_slug = manifest
        .metadata
        .get("channel")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "MISSING_CHANNEL",
                "member-add bundle metadata missing `channel`",
            )
        })?;
    if bundle_slug != slug {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "SLUG_MISMATCH",
            format!("URL slug `{slug}` doesn't match bundle channel `{bundle_slug}`"),
        ));
    }

    let bundle = BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    };

    let cid = ingest(&state.ingest_ctx, bundle, sig, IngestSource::AdminEndpoint)
        .await
        .map_err(map_ingest_error)?;

    Ok(Json(AdminResult { block_cid: cid }))
}

/// Build the admin-only sub-router. Caller is responsible for gating this
/// on `state.config.debug.admin_endpoints`.
pub fn build_admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/_admin_v0_0_2/channels", post(create_channel))
        .route("/_admin_v0_0_2/channels/:slug/members", post(add_member))
        .with_state(state)
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request};
    use ed25519_dalek::SigningKey;
    use jig_client::{
        Identity,
        blocks::{build_channel_create, build_member_add, build_text_render},
    };
    use jig_core::{Did, HlcTimestamp};
    use jig_pipeline::{
        fanout::Fanout, hlc::HlcClock, identity::TofuResolver, ingest::IngestContext,
        persist::SqliteStore,
    };
    use rand::Rng;
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

    /// Build an AppState with channel-create AND member-add in the allow list.
    /// `AppState::for_test()` only allows text-render; we need a config with the
    /// channel-op kinds present for happy-path tests to succeed through ingest.
    fn state_with_channel_kinds_allowed() -> Arc<AppState> {
        use jig_config::v0_0_2_server::JigServerConfig;

        let mut config = JigServerConfig::default();
        for kind in ["channel-create", "member-add"] {
            if !config.server.allowed_block_kinds.iter().any(|x| x == kind) {
                config.server.allowed_block_kinds.push(kind.to_string());
            }
        }

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mut secret = [0u8; 32];
        rand::thread_rng().fill(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let server_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());
        let identity = Arc::new(TofuResolver::new(store.clone()));
        let hlc_clock = Arc::new(HlcClock::new(server_did.clone()));
        let fanout = Arc::new(Fanout::new());
        let server_url = format!("ws://{}", config.server.listen);

        let ingest_ctx = Arc::new(IngestContext {
            store,
            identity,
            hlc_clock,
            allowed_block_kinds: config.server.allowed_block_kinds.clone(),
            server_did: server_did.clone(),
            server_key: signing_key,
            fanout,
            server_url: server_url.clone(),
            naively_allow_unknown_handles_fallback: false,
        });

        let bridges = Arc::new(crate::v0_0_2_bridges::BridgeRegistry::new(&config));

        Arc::new(AppState {
            config,
            ingest_ctx,
            server_did,
            server_url,
            bridges,
        })
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

    fn submission_from(block: &jig_client::blocks::BuiltBlock) -> serde_json::Value {
        serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            "sig_b64":    base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        })
    }

    #[tokio::test]
    async fn create_channel_signed_request_succeeds() {
        let state = state_with_channel_kinds_allowed();
        let router = build_admin_router(state.clone());

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_channel_create(&id, "#hello", "open", hlc);

        let (status, body) =
            post_json(router, "/_admin_v0_0_2/channels", submission_from(&block)).await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        assert!(!body["block_cid"].as_str().unwrap_or("").is_empty());

        let channels = state.ingest_ctx.store.list_channels().unwrap();
        assert!(
            channels.iter().any(|c| c.slug == "#hello"),
            "channel #hello must be present; got: {channels:?}"
        );
    }

    #[tokio::test]
    async fn create_channel_rejects_wrong_kind_bundle() {
        let state = state_with_channel_kinds_allowed();
        let router = build_admin_router(state);

        let id = test_identity();
        let hlc = test_hlc(&id);
        // text-render instead of channel-create
        let block = build_text_render(&id, "#hello", "hi", hlc);

        let (status, body) =
            post_json(router, "/_admin_v0_0_2/channels", submission_from(&block)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "WRONG_KIND");
    }

    #[tokio::test]
    async fn add_member_signed_request_succeeds() {
        let state = state_with_channel_kinds_allowed();
        let router = build_admin_router(state.clone());

        let id = test_identity();
        let hlc = test_hlc(&id);

        // First create the channel
        let create_block = build_channel_create(&id, "#room", "restricted", hlc.clone());
        let (status, _) = post_json(
            router.clone(),
            "/_admin_v0_0_2/channels",
            submission_from(&create_block),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Then add a member — URL-encode the # in the slug
        let member_did = "did:jig:zMember";
        let add_block = build_member_add(&id, "#room", member_did, hlc);
        let (status, body) = post_json(
            router,
            "/_admin_v0_0_2/channels/%23room/members",
            submission_from(&add_block),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        assert!(!body["block_cid"].as_str().unwrap_or("").is_empty());

        let channel = state
            .ingest_ctx
            .store
            .get_channel_by_slug("#room")
            .unwrap()
            .unwrap();
        let members = state.ingest_ctx.store.list_members(&channel.id).unwrap();
        assert!(
            members.iter().any(|m| m.member_did == member_did),
            "member must be present; got: {members:?}"
        );
    }

    #[tokio::test]
    async fn add_member_rejects_slug_mismatch() {
        let state = state_with_channel_kinds_allowed();
        let router = build_admin_router(state);

        let id = test_identity();
        let hlc = test_hlc(&id);
        let add_block = build_member_add(&id, "#room", "did:jig:zMember", hlc);

        // URL says #wrong but bundle says #room
        let (status, body) = post_json(
            router,
            "/_admin_v0_0_2/channels/%23wrong/members",
            submission_from(&add_block),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "SLUG_MISMATCH");
    }

    #[tokio::test]
    async fn create_channel_rejects_invalid_signature() {
        let state = state_with_channel_kinds_allowed();
        let router = build_admin_router(state);

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_channel_create(&id, "#hello", "open", hlc);

        // Corrupt the signature — all zeros
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            "sig_b64":    base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
        });

        let (status, body) = post_json(router, "/_admin_v0_0_2/channels", submission).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "INVALID_SIG");
    }
}
