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

/// Thin wrapper around the shared classifier (`v0_0_2_ingest_error`): decide
/// the (status, code) here once, wrap it in this endpoint's `AdminError`.
/// `pub(crate)` so the cross-wrapper agreement test in that module can call
/// it directly.
pub(crate) fn map_ingest_error(e: IngestError) -> (StatusCode, Json<AdminError>) {
    let (status, code, message) = crate::v0_0_2_ingest_error::classify_ingest_error(&e);
    err(status, code, message)
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

/// POST /_admin_v0_0_2/channels/:slug/archive
///
/// The v0.0.2 channel delete. Body: signed `channel-archive` block. Archiving
/// is a **soft delete** — the channel stops being listed and stops resolving as
/// an active channel, but every block and receipt survives; the reasoning is in
/// `jig_pipeline::effect::apply_channel_archive`.
///
/// ## Authorization
///
/// These routes carry no request-level proof of their own (the signed block IS
/// the proof), and a delete is far more destructive than a create, so the
/// sender DID must equal the channel's `owner_did`. The check below is what
/// produces a precise 403/404/409; it reads the *claimed* sender from the
/// manifest, which is only meaningful because `ingest()` then refuses the
/// block unless that same DID actually signed it, and
/// `apply_channel_archive` re-checks ownership after verification. Neither
/// check alone is sufficient — together they are.
///
/// Returns `{ "block_cid": "bafy..." }` on success.
pub async fn archive_channel(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Json(body): Json<BundleSubmission>,
) -> Result<Json<AdminResult>, (StatusCode, Json<AdminError>)> {
    let (manifest_bytes, code_bytes, sig) = decode_submission(&body)?;
    let manifest = parse_manifest(&manifest_bytes)?;

    if manifest.kind != Some(BlockKind::ChannelArchive) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "WRONG_KIND",
            format!("expected channel-archive bundle, got {:?}", manifest.kind),
        ));
    }

    // Defense in depth, as for member-add: the URL must agree with the bundle
    // so an authoritative-looking URL can't retire a different channel.
    let bundle_slug = manifest
        .metadata
        .get("channel")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "MISSING_CHANNEL",
                "channel-archive bundle metadata missing `channel`",
            )
        })?;
    if bundle_slug != slug {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "SLUG_MISMATCH",
            format!("URL slug `{slug}` doesn't match bundle channel `{bundle_slug}`"),
        ));
    }

    let channel = state
        .ingest_ctx
        .store
        .get_channel_by_slug_including_archived(&slug)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PERSIST_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            // Explicit 404 rather than a cheerful 200: deleting a channel that
            // isn't there is a typo, and reporting success teaches operators to
            // trust a delete that never happened.
            err(
                StatusCode::NOT_FOUND,
                "NO_SUCH_CHANNEL",
                format!("no channel `{slug}` on this server"),
            )
        })?;

    let sender_did = manifest
        .authors
        .first()
        .map(|a| a.did.to_string())
        .unwrap_or_default();
    if channel.owner_did.is_empty() || channel.owner_did != sender_did {
        return Err(err(
            StatusCode::FORBIDDEN,
            "NOT_CHANNEL_OWNER",
            format!(
                "`{slug}` is owned by `{}`; only its owner can archive it",
                channel.owner_did
            ),
        ));
    }

    let already_archived = state
        .ingest_ctx
        .store
        .channel_archived_at(&slug)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PERSIST_ERROR",
                e.to_string(),
            )
        })?;
    if let Some(when) = already_archived {
        return Err(err(
            StatusCode::CONFLICT,
            "ALREADY_ARCHIVED",
            format!("`{slug}` was already archived at {when}"),
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
        .route(
            "/_admin_v0_0_2/channels/:slug/archive",
            post(archive_channel),
        )
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
        blocks::{
            build_channel_archive, build_channel_create, build_member_add, build_text_render,
        },
    };
    use jig_core::{Did, HlcTimestamp};
    use jig_pipeline::{
        executor::BlockExecutor, fanout::Fanout, hlc::HlcClock, identity::TofuResolver,
        ingest::IngestContext, persist::SqliteStore,
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
        rand::rng().fill_bytes(&mut secret);
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
            executor: Some(BlockExecutor::shared()),
        });

        let bridges = Arc::new(crate::v0_0_2_bridges::BridgeRegistry::new(&config));
        // Built before the literal: `config` moves into it below.
        let auth = Arc::new(crate::auth::AuthState::from_config(&config.auth));

        Arc::new(AppState {
            config,
            ingest_ctx,
            server_did,
            server_url,
            bridges,
            bridge_router_mount: jig_bridge_core::RouterMount::new(),
            auth,
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

    // ---- channel archive (the v0.0.2 channel delete) ------------------------

    /// Create `slug` owned by `owner` and return the router used to do it.
    async fn router_with_channel(state: Arc<AppState>, owner: &Identity, slug: &str) -> Router {
        let router = build_admin_router(state);
        let create = build_channel_create(owner, slug, "open", test_hlc(owner));
        let (status, body) = post_json(
            router.clone(),
            "/_admin_v0_0_2/channels",
            submission_from(&create),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "setup create failed: {body}");
        router
    }

    fn archive_path(slug: &str) -> String {
        format!(
            "/_admin_v0_0_2/channels/{}/archive",
            slug.replace('#', "%23")
        )
    }

    #[tokio::test]
    async fn archive_channel_by_owner_removes_it_from_the_channel_list() {
        let state = state_with_channel_kinds_allowed();
        let owner = test_identity();
        let router = router_with_channel(state.clone(), &owner, "#scratch").await;

        let block = build_channel_archive(&owner, "#scratch", test_hlc(&owner));
        let (status, body) =
            post_json(router, &archive_path("#scratch"), submission_from(&block)).await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        assert!(!body["block_cid"].as_str().unwrap_or("").is_empty());

        let channels = state.ingest_ctx.store.list_channels().unwrap();
        assert!(
            !channels.iter().any(|c| c.slug == "#scratch"),
            "archived channel must disappear from the list; got {channels:?}"
        );
    }

    /// The security case: any key can reach these routes, so a delete that
    /// only checked "is the signature valid" would let anyone with a DID
    /// destroy anyone's channel.
    #[tokio::test]
    async fn archive_channel_rejects_a_non_owner() {
        let state = state_with_channel_kinds_allowed();
        let owner = test_identity();
        let router = router_with_channel(state.clone(), &owner, "#scratch").await;

        // A *validly signed* block from a different identity — the signature
        // check passes and the request must still be refused.
        let attacker = test_identity();
        let block = build_channel_archive(&attacker, "#scratch", test_hlc(&attacker));
        let (status, body) =
            post_json(router, &archive_path("#scratch"), submission_from(&block)).await;

        assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
        assert_eq!(body["code"], "NOT_CHANNEL_OWNER");
        let channels = state.ingest_ctx.store.list_channels().unwrap();
        assert!(
            channels.iter().any(|c| c.slug == "#scratch"),
            "a rejected archive must leave the channel live; got {channels:?}"
        );
        assert_eq!(
            state
                .ingest_ctx
                .store
                .channel_archived_at("#scratch")
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn archive_channel_reports_a_missing_channel_instead_of_succeeding() {
        let state = state_with_channel_kinds_allowed();
        let router = build_admin_router(state);

        let owner = test_identity();
        let block = build_channel_archive(&owner, "#never-existed", test_hlc(&owner));
        let (status, body) = post_json(
            router,
            &archive_path("#never-existed"),
            submission_from(&block),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body={body}");
        assert_eq!(body["code"], "NO_SUCH_CHANNEL");
    }

    #[tokio::test]
    async fn archive_channel_is_not_silently_repeatable() {
        let state = state_with_channel_kinds_allowed();
        let owner = test_identity();
        let router = router_with_channel(state.clone(), &owner, "#scratch").await;

        let first = build_channel_archive(&owner, "#scratch", test_hlc(&owner));
        let (status, _) = post_json(
            router.clone(),
            &archive_path("#scratch"),
            submission_from(&first),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let again = build_channel_archive(&owner, "#scratch", test_hlc(&owner));
        let (status, body) =
            post_json(router, &archive_path("#scratch"), submission_from(&again)).await;
        assert_eq!(status, StatusCode::CONFLICT, "body={body}");
        assert_eq!(body["code"], "ALREADY_ARCHIVED");
    }

    #[tokio::test]
    async fn archive_channel_rejects_slug_mismatch() {
        let state = state_with_channel_kinds_allowed();
        let owner = test_identity();
        let router = router_with_channel(state, &owner, "#scratch").await;

        let block = build_channel_archive(&owner, "#scratch", test_hlc(&owner));
        let (status, body) =
            post_json(router, &archive_path("#other"), submission_from(&block)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body={body}");
        assert_eq!(body["code"], "SLUG_MISMATCH");
    }

    #[tokio::test]
    async fn archive_channel_rejects_wrong_kind_bundle() {
        let state = state_with_channel_kinds_allowed();
        let owner = test_identity();
        let router = router_with_channel(state, &owner, "#scratch").await;

        let block = build_member_add(&owner, "#scratch", "did:jig:zX", test_hlc(&owner));
        let (status, body) =
            post_json(router, &archive_path("#scratch"), submission_from(&block)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body={body}");
        assert_eq!(body["code"], "WRONG_KIND");
    }

    #[tokio::test]
    async fn archive_channel_rejects_invalid_signature() {
        let state = state_with_channel_kinds_allowed();
        let owner = test_identity();
        let router = router_with_channel(state, &owner, "#scratch").await;

        let block = build_channel_archive(&owner, "#scratch", test_hlc(&owner));
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            "sig_b64":    base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
        });
        let (status, body) = post_json(router, &archive_path("#scratch"), submission).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body}");
        assert_eq!(body["code"], "INVALID_SIG");
    }

    /// Pins the history decision at the HTTP boundary: `jig channel delete`
    /// must not be a way to destroy messages.
    #[tokio::test]
    async fn archiving_a_channel_keeps_its_message_history() {
        let state = state_with_channel_kinds_allowed();
        let owner = test_identity();
        let router = router_with_channel(state.clone(), &owner, "#scratch").await;

        // Seed one message directly through the store (the admin router has no
        // text-render endpoint; the history-retention claim is about storage).
        let msg = jig_pipeline::persist::StoredBlock {
            cid: "bafy_msg_1".into(),
            channel_id: Some("#scratch".into()),
            block_kind: "text-render".into(),
            sender_did: owner.did_string(),
            sender_sig: vec![0u8; 64],
            bundle_bytes: b"{}".to_vec(),
            is_synthetic: false,
            hlc_wall_ms: 1,
            hlc_logical: 0,
            hlc_origin: owner.did_string(),
            posted_at: 1,
            origin_server: "ws://test".into(),
            federated_from: None,
        };
        state.ingest_ctx.store.insert_block(&msg).unwrap();

        let block = build_channel_archive(&owner, "#scratch", test_hlc(&owner));
        let (status, _) =
            post_json(router, &archive_path("#scratch"), submission_from(&block)).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            state
                .ingest_ctx
                .store
                .get_block("bafy_msg_1")
                .unwrap()
                .is_some(),
            "archive must not delete blocks"
        );
        // The channel's timeline also carries the channel-create and
        // channel-archive blocks; what matters is that the message is still
        // readable from it.
        let timeline = state
            .ingest_ctx
            .store
            .list_blocks_by_channel("#scratch", 100, None)
            .unwrap();
        assert!(
            timeline.iter().any(|b| b.cid == "bafy_msg_1"),
            "channel history must still be readable from storage; got {:?}",
            timeline.iter().map(|b| &b.cid).collect::<Vec<_>>()
        );
        assert!(
            state
                .ingest_ctx
                .store
                .get_channel_by_slug_including_archived("#scratch")
                .unwrap()
                .is_some(),
            "the channel row itself must survive as an audit record"
        );
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
