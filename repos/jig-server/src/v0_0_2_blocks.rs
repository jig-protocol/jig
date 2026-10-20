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

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

pub(crate) fn err(
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
    /// The author's signature over the bundle, so a reader can check the
    /// block is the author's and not this server's. Absent only for blocks
    /// stored without one (server-synthesized).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig_b64: Option<String>,
    pub is_synthetic: bool,
    pub posted_at: i64,
    pub hlc_wall_ms: u64,
    pub hlc_logical: u32,
    pub hlc_origin: String,
    pub origin_server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federated_from: Option<String>,
    pub receipts: Vec<ReceiptView>,
    /// True while this server's own receipt is not yet written: the block has landed and is being
    /// rendered. Pending, not failed; omitted once the receipt exists.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub receipt_pending: bool,
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
/// Runs the same gates as the timeline the block lives in. A CID is a content
/// hash, not a secret — it appears in acks, receipts, delivery frames and
/// logs — so an ungated fetch-by-CID would be a detour around the channel
/// gate. A block with no channel (control-plane kinds) needs only a proof.
///
/// Returns 404 with `{ code: "NOT_FOUND" }` if the CID is absent.
pub async fn get_block_by_cid(
    State(state): State<Arc<AppState>>,
    Path(cid): Path<String>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<BlockView>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    let caller_did = admit_caller(&state, &headers, "GET", uri.path(), started)?;

    let stored = state
        .ingest_ctx
        .store
        .get_block(&cid)
        .map_err(persist_err)?
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                format!("no block with cid {cid}"),
            )
        })?;

    // `channel_id` is the channel's id (its creation-block CID); the read
    // gate goes by the channel row it names.
    if let (Some(caller), Some(channel_id)) = (caller_did.as_ref(), stored.channel_id.as_deref())
        && let Some(channel) = state
            .ingest_ctx
            .store
            .get_channel_by_id_including_archived(channel_id)
            .map_err(persist_err)?
    {
        authorize_channel_read(&state, &channel.slug, caller, started)?;
    }

    let receipts: Vec<ReceiptView> = state
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
        sig_b64: (!stored.sender_sig.is_empty())
            .then(|| base64::engine::general_purpose::STANDARD.encode(&stored.sender_sig)),
        is_synthetic: stored.is_synthetic,
        posted_at: stored.posted_at,
        hlc_wall_ms: stored.hlc_wall_ms,
        hlc_logical: stored.hlc_logical,
        hlc_origin: stored.hlc_origin,
        origin_server: stored.origin_server,
        federated_from: stored.federated_from,
        receipt_pending: !receipts.iter().any(|r| state.server_did == r.server_id),
        receipts,
    }))
}

// ---- Channel list endpoint --------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ChannelView {
    /// The CID of the block that created the channel. A client reads the
    /// channel's suite and owner from that signed block, not from the
    /// unsigned fields below.
    pub id: String,
    pub slug: String,
    pub visibility: String,
    pub owner_did: String,
    pub created_at: i64,
    /// `none` or `mls`, fixed at creation.
    pub suite: String,
}

#[derive(Debug, Serialize)]
pub struct ChannelsResponse {
    pub channels: Vec<ChannelView>,
}

/// GET /api/v1/channels — list the channels the caller may read.
///
/// Every channel runs the same `authorize_read` decision as a timeline read,
/// so a restricted channel a caller could not read is not listed to them
/// either. A 403 on the timeline conceals nothing if this endpoint still
/// names every restricted channel — and its `owner_did` — to whoever asks.
/// Not debug-gated.
pub async fn list_channels(
    State(state): State<Arc<AppState>>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<ChannelsResponse>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    let caller_did = admit_caller(&state, &headers, "GET", uri.path(), started)?;
    let store = &state.ingest_ctx.store;

    let stored = store.list_channels().map_err(persist_err)?;
    let mut channels = Vec::with_capacity(stored.len());
    for c in stored {
        // With no verified caller (the migration escape hatch) nobody is
        // filtered: the pre-authentication listing, exactly as documented.
        if let Some(caller) = caller_did.as_ref() {
            let visibility = crate::auth::Visibility::parse(&c.visibility);
            // Open channels need no membership query; the decision is the
            // same whatever the answer would have been.
            let is_member = match visibility {
                crate::auth::Visibility::Open => false,
                crate::auth::Visibility::Restricted => store
                    .is_member(&c.slug, caller.as_str())
                    .map_err(persist_err)?,
            };
            let is_owner = c.owner_did == caller.as_str();
            if crate::auth::authorize_read(visibility, is_member, is_owner).is_err() {
                continue;
            }
        }
        channels.push(ChannelView {
            id: c.id,
            slug: c.slug,
            visibility: c.visibility,
            owner_did: c.owner_did,
            created_at: c.created_at,
            suite: c.suite,
        });
    }
    Ok(Json(ChannelsResponse { channels }))
}

#[derive(Debug, Serialize)]
pub struct MemberView {
    pub did: String,
    pub role: String,
    pub joined_at: i64,
}

#[derive(Debug, Serialize)]
pub struct MembersResponse {
    pub slug: String,
    pub members: Vec<MemberView>,
}

/// GET /api/v1/channels/:slug/members — who is in a channel.
///
/// Whoever may read the channel may see its members: on an open channel that
/// is anyone admitted, on a restricted one its members and owner. The same
/// gates, in the same order, as the timeline.
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<MembersResponse>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    let caller_did = admit_caller(&state, &headers, "GET", uri.path(), started)?;
    if let Some(caller) = caller_did.as_ref() {
        authorize_channel_read(&state, &slug, caller, started)?;
    }
    let store = &state.ingest_ctx.store;
    let Some(channel) = store.get_channel_by_slug(&slug).map_err(persist_err)? else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "UNKNOWN_CHANNEL",
            format!("no live channel '{slug}' on this server"),
        ));
    };
    let members = store
        .list_members(&channel.id)
        .map_err(persist_err)?
        .into_iter()
        .map(|m| MemberView {
            did: m.member_did,
            role: m.role,
            joined_at: m.joined_at,
        })
        .collect();
    Ok(Json(MembersResponse { slug, members }))
}

// ---- Channel history endpoint -----------------------------------------------

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    /// Omitted means "as much as the store will give" — the store clamps to
    /// `MAX_HISTORY_LIMIT` either way, so this is never unbounded.
    pub limit: Option<usize>,
    /// A block CID: return the page of blocks just older than it, for paging
    /// back through history. Omitted means the newest page.
    pub before: Option<String>,
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
    /// True while this server's own receipt is not yet written (see [`BlockView`]).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub receipt_pending: bool,
    pub delivery_cid: String,
    /// The block's record in its channel's chain (JEP-0002 rule 9), when this
    /// server sequences the channel. History is checkable on any transport.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingest: Option<jig_pipeline::ingest_record::IngestRecord>,
}

/// Query string for [`get_channel_records`].
#[derive(Debug, Deserialize)]
pub struct RecordsQuery {
    /// The first `seq` wanted; omitted means the start of the chain.
    pub from: Option<u64>,
    /// At most this many; the store clamps to `MAX_HISTORY_LIMIT`.
    pub limit: Option<usize>,
}

pub(crate) fn persist_err(e: impl std::fmt::Display) -> (StatusCode, Json<ErrorBody>) {
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
/// Run gates 1 and 2 for a read, returning the authenticated AND admitted
/// caller. One function on purpose: every read surface calls it, so a route
/// added later cannot authenticate without also admitting.
///
/// `Ok(None)` means the server is running with `require_authenticated_reads =
/// false` — the migration escape hatch — and no identity was established, so
/// there is nobody to admit either.
///
/// `path` must be the path the caller actually requested, taken from the
/// request URI rather than rebuilt from extracted parameters. The signature
/// covers the path as sent, so reconstructing it invites an encoding mismatch
/// that would present as "every signature is invalid".
pub(crate) fn admit_caller(
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

    let did = crate::auth::authenticate(&proof, method, path, b"", now_ms, &mut guard)
        .map_err(|outcome| refuse(state, &outcome, started))?;
    drop(guard);

    // Gate 2, on the identity gate 1 just VERIFIED. Before any channel is
    // looked up: a refused caller must never learn from the answer whether the
    // channel exists.
    state
        .auth
        .admit_and_charge(did.as_str())
        .map_err(|outcome| refuse(state, &outcome, started))?;
    Ok(Some(did))
}

/// Gate 3 for a single channel: may `caller` read `slug`?
///
/// The decision itself is the pure `authorize_read`; this only gathers its
/// inputs.
///
/// A slug with no local row is NOT refused. Channel state does not replicate
/// between federated servers, so a channel that lives on a peer routinely has
/// blocks here and no row: refusing would break backfill for every federated
/// conversation. Live WSS delivery makes the same call for the same reason,
/// and a row that appears later is enforced from then on. Two costs, both
/// deliberate: relayed blocks of a peer's channel are readable here by any
/// authenticated caller (federation is trust-on-peer until its own gate
/// lands), and under a concealing disclosure policy an absent channel (empty
/// 200) is distinguishable from a restricted one (404).
///
/// "No local row" means no row at all. An ARCHIVED channel still has one —
/// archiving is a soft delete that keeps every block — and its visibility and
/// owner keep governing reads. The live-channel lookup filters archived rows
/// out (so writes fail loudly), which is exactly why it must not be the
/// lookup used here: with it, retiring a restricted channel published its
/// history to anyone with a key.
pub(crate) fn authorize_channel_read(
    state: &AppState,
    slug: &str,
    caller: &jig_core::did::Did,
    started: std::time::Instant,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let store = &state.ingest_ctx.store;
    let Some(channel) = store
        .get_channel_by_slug_including_archived(slug)
        .map_err(persist_err)?
    else {
        return Ok(());
    };
    let is_member = store
        .is_member(slug, caller.as_str())
        .map_err(persist_err)?;
    let is_owner = channel.owner_did == caller.as_str();

    crate::auth::authorize_read(
        crate::auth::Visibility::parse(&channel.visibility),
        is_member,
        is_owner,
    )
    .map_err(|outcome| refuse(state, &outcome, started))
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
pub(crate) fn refuse(
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
    let caller_did = admit_caller(&state, &headers, "GET", uri.path(), started)?;
    let store = &state.ingest_ctx.store;

    // Gate 3, before any block is fetched: a refusal must not be
    // distinguishable from an empty channel by how much work it took.
    if let Some(caller) = caller_did.as_ref() {
        authorize_channel_read(&state, &slug, caller, started)?;
    }

    let limit = query.limit.unwrap_or(MAX_HISTORY_LIMIT);
    let blocks = match query.before.as_deref() {
        None => store
            .list_blocks_by_channel(&slug, limit, None)
            .map_err(persist_err)?,
        Some(before) => store
            .list_blocks_before(&slug, limit, before)
            .map_err(persist_err)?
            .ok_or_else(|| {
                err(
                    StatusCode::BAD_REQUEST,
                    "BAD_CURSOR",
                    format!("`before` is not a block of {slug}"),
                )
            })?,
    };

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
            .collect::<Vec<ReceiptRef>>();
        let receipt_pending = !receipts.iter().any(|r| state.server_did == r.server_did);
        timeline.push(TimelineBlock {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(&block.bundle_bytes),
            sig_b64: (!block.sender_sig.is_empty())
                .then(|| base64::engine::general_purpose::STANDARD.encode(&block.sender_sig)),
            receipts,
            receipt_pending,
            // Same `delivery:<cid>` shape the WSS fanout emits, so a client
            // that dedupes on delivery_cid sees replay and live delivery of
            // the same block as one identity.
            delivery_cid: format!("delivery:{}", block.cid),
            ingest: store.get_ingest_record(&block.cid).map_err(persist_err)?,
        });
    }
    Ok(Json(timeline))
}

/// A channel's `ingest` records alone, in `seq` order: what a client needs to
/// check its chain from `seq` 0, or across a gap, without fetching blocks it
/// may not even be allowed to read. Gated like history: a record carries no
/// content, but who posted when is still the channel's to disclose.
pub async fn get_channel_records(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(query): Query<RecordsQuery>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<jig_pipeline::ingest_record::IngestRecord>>, (StatusCode, Json<ErrorBody>)> {
    let started = std::time::Instant::now();
    let caller_did = admit_caller(&state, &headers, "GET", uri.path(), started)?;
    if let Some(caller) = caller_did.as_ref() {
        authorize_channel_read(&state, &slug, caller, started)?;
    }
    let records = state
        .ingest_ctx
        .store
        .list_ingest_records(
            &slug,
            query.from.unwrap_or(0),
            query.limit.unwrap_or(MAX_HISTORY_LIMIT),
        )
        .map_err(persist_err)?;
    Ok(Json(records))
}

/// Construct the REST sub-router. Merged into the v0.0.2 router by
/// `v0_0_2_ws::build_v0_0_2_router`. Not debug-gated — these are
/// production endpoints.
pub fn build_blocks_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/blocks", post(submit_block))
        .route("/api/v1/blocks/{cid}", get(get_block_by_cid))
        .route("/api/v1/channels", get(list_channels))
        .route("/api/v1/channels/{slug}/blocks", get(get_channel_history))
        .route("/api/v1/channels/{slug}/records", get(get_channel_records))
        .route("/api/v1/channels/{slug}/members", get(list_members))
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
        Identity::generate_for_tests(&path)
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
                id: jig_pipeline::ingest_record::label_cid(slug),
                slug: slug.to_string(),
                visibility: "open".to_string(),
                created_at: 0,
                owner_did: "did:jig:zSeedOwner".to_string(),
                suite: "none".to_string(),
                sequencer_did: String::new(),
                co_owners: Vec::new(),
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

        let local = || jig_pipeline::metrics::ingested_by_source()[0];
        let before = local();
        let (status, body) = post_json(router, "/api/v1/blocks", submission).await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        assert!(!body["block_cid"].as_str().unwrap_or("").is_empty());
        // REST ingest used to be invisible to /metrics. Other tests ingest
        // concurrently, so assert growth, not an exact value.
        let after = local();
        assert_eq!(after.0, "local");
        assert!(after.1 > before.1, "REST ingest must count as local");
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
        // Unsigned GET, so the escape hatch; the proof requirement on this
        // route is covered in tests/restricted_reads.rs.
        let state = Arc::new(unauthenticated_state());
        let router = build_blocks_router(state);

        let (status, body) = get_path(router, "/api/v1/blocks/bafy_unknown").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn submit_then_get_round_trips() {
        let state = Arc::new(unauthenticated_state());
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
            .merge(crate::v0_0_2_admin::build_channel_ops_router(state.clone()));

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_channel_create(&id, "#hello", "open", hlc);
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            "sig_b64": base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });

        let (status, _body) = post_json(router.clone(), "/api/v1/channels", submission).await;
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
            .merge(crate::v0_0_2_admin::build_channel_ops_router(state.clone()));

        let id = test_identity();
        // Create channels in a non-sorted order; expect sorted output.
        for slug in ["#zulu", "#alpha", "#mike"] {
            let hlc = test_hlc(&id);
            let block = build_channel_create(&id, slug, "open", hlc);
            let submission = serde_json::json!({
                "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
                "sig_b64":    base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
            });
            let (status, _) = post_json(router.clone(), "/api/v1/channels", submission).await;
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

    /// The default config (no `[debug]` section) must carry the whole
    /// install.sh hello-world: create `#hello`, list it, post to it. The
    /// removed `/_admin_v0_0_2/*` aliases must 404.
    #[tokio::test]
    async fn channel_ops_work_with_the_default_config() {
        use jig_client::blocks::build_channel_create;

        let state = Arc::new(unauthenticated_state());
        let router = crate::v0_0_2_ws::build_v0_0_2_router(state.clone());

        let id = test_identity();
        let block = build_channel_create(&id, "#hello", "open", test_hlc(&id));
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            "sig_b64":    base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });

        let (status, _) = post_json(
            router.clone(),
            "/_admin_v0_0_2/channels",
            submission.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "removed legacy alias must 404"
        );

        let (status, body) = post_json(router.clone(), "/api/v1/channels", submission).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "create via /api/v1/channels: {body}"
        );
        assert!(body["block_cid"].is_string());

        let (status, body) = get_path(router.clone(), "/api/v1/channels").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["channels"][0]["slug"], "#hello");

        let mut hlc = test_hlc(&id);
        hlc.logical = 1;
        let again = build_channel_create(&id, "#hello", "open", hlc);
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(again.canonical_bytes()),
            "sig_b64":    base64::engine::general_purpose::STANDARD.encode(&again.sender_sig),
        });
        let (status, body) = post_json(router.clone(), "/api/v1/channels", submission).await;
        assert_eq!(status, StatusCode::CONFLICT, "re-create: {body}");
        assert_eq!(body["code"], "CHANNEL_EXISTS");

        let msg = build_text_render(&id, "#hello", "hello, world", test_hlc(&id));
        let submission = serde_json::json!({
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(msg.canonical_bytes()),
            "sig_b64":    base64::engine::general_purpose::STANDARD.encode(&msg.sender_sig),
        });
        let (status, body) = post_json(router, "/api/v1/blocks", submission).await;
        assert_eq!(status, StatusCode::OK, "hello, world: {body}");
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

    /// History carries each block's signed record, and the records endpoint
    /// serves the same chain alone, from any `seq`.
    #[tokio::test]
    async fn channel_history_and_records_carry_the_signed_chain() {
        use jig_pipeline::ingest_record::IngestRecord;
        let state = Arc::new(unauthenticated_state());
        let router = build_blocks_router(state.clone());
        let id = test_identity();
        submit_texts(&state, &router, &id, "#hello", &["one", "two", "three"]).await;

        let (status, body) = get_path(router.clone(), "/api/v1/channels/%23hello/blocks").await;
        assert_eq!(status, StatusCode::OK);
        let records: Vec<IngestRecord> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|b| serde_json::from_value(b["ingest"].clone()).expect("every block has one"))
            .collect();
        let server = state.server_did.to_did_jig_string();
        assert_eq!(records.iter().map(|r| r.seq).collect::<Vec<_>>(), [0, 1, 2]);
        for pair in records.windows(2) {
            pair[1].verify(&server).unwrap();
            assert!(pair[1].follows(&pair[0]));
        }

        let (status, body) =
            get_path(router, "/api/v1/channels/%23hello/records?from=1&limit=5").await;
        assert_eq!(status, StatusCode::OK);
        let alone: Vec<IngestRecord> = serde_json::from_value(body).unwrap();
        assert_eq!(alone, records[1..].to_vec());
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
    async fn channel_history_pages_back_from_a_before_cursor() {
        let state = Arc::new(unauthenticated_state());
        let router = build_blocks_router(state.clone());
        let id = test_identity();
        submit_texts(&state, &router, &id, "#hello", &["a", "b", "c"]).await;
        submit_texts(&state, &router, &id, "#other", &["elsewhere"]).await;

        let page = |body: &serde_json::Value| -> Vec<String> {
            body.as_array()
                .unwrap()
                .iter()
                .map(|b| text_of(b["bundle_b64"].as_str().unwrap()))
                .collect()
        };
        let (_, newest) =
            get_path(router.clone(), "/api/v1/channels/%23hello/blocks?limit=1").await;
        assert_eq!(page(&newest), vec!["c"]);
        let cid_of = |b: &serde_json::Value| {
            b["delivery_cid"]
                .as_str()
                .unwrap()
                .trim_start_matches("delivery:")
                .to_string()
        };
        let c = cid_of(&newest[0]);

        let (status, older) = get_path(
            router.clone(),
            &format!("/api/v1/channels/%23hello/blocks?limit=5&before={c}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page(&older), vec!["a", "b"]);

        // A cursor from another channel is refused, the same as an unknown one.
        let (_, other) = get_path(router.clone(), "/api/v1/channels/%23other/blocks").await;
        let foreign = cid_of(&other[0]);
        for cursor in [foreign.as_str(), "bafy-unknown"] {
            let (status, body) = get_path(
                router.clone(),
                &format!("/api/v1/channels/%23hello/blocks?before={cursor}"),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["code"], "BAD_CURSOR");
        }
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
