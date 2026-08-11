//! v0.0.2 WSS subscription endpoint at `/api/v1/ws`.
//!
//! CLI clients (Phase F's `jig chat`, `jig tail`, etc.) and federated
//! peers (Task D5) connect here. The envelope codec lives in
//! `jig_pipeline::envelope`; submissions flow through
//! `jig_pipeline::ingest()`.
//!
//! # Frame flow
//! ```text
//! Client → Frame::Subscribe  → register with Fanout
//! Client → Frame::Submit     → base64-decode, reconstruct BlockBundle,
//!                              call ingest(), reply Ack or Error
//! Client → Frame::CatchUp    → v0.0.2 stub; cursor replay deferred (Plan §D6/F)
//! Server → Frame::Block      → deliver ingested blocks to subscribed clients
//! Server → Frame::Ack        → confirm a submitted block was persisted
//! Server → Frame::Error      → report a protocol or ingest error
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
    routing::get,
};
use base64::Engine as _;
use jig_core::BlockBundle;
use jig_pipeline::{
    Envelope, Frame, ReceiptRef, Scope, SubscriptionScope,
    ingest::{IngestError, IngestSource, ingest},
};
use tokio::sync::mpsc;

use crate::v0_0_2::AppState;

/// Connection counter — used solely for logging and `IngestSource::LocalClient`
/// disambiguation. Not auth-significant.
static CONN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Process-lifetime counters behind `GET /metrics` (served from
/// [`crate::handler::build_router`]).
///
/// Hand-rolled Prometheus text on purpose: the exposition format is a dozen
/// lines and a metrics crate would be a new dependency.
///
/// SCOPE — read before trusting a number. Every counter here is bumped from
/// the WebSocket path in THIS module only. Blocks arriving over federation or
/// from a bridge are NOT counted; those paths live in other modules and are
/// not instrumented yet. Counters reset to zero on restart, which is normal
/// for Prometheus counters.
pub mod metrics {
    use std::collections::BTreeMap;
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CONNECTIONS_ACTIVE: AtomicU64 = AtomicU64::new(0);
    static SUBSCRIBERS_ACTIVE: AtomicU64 = AtomicU64::new(0);
    static BLOCKS_INGESTED: AtomicU64 = AtomicU64::new(0);
    /// Cardinality is bounded by the channels this server actually serves,
    /// which is the same bound the block store already carries.
    static CHANNEL_MESSAGES: RwLock<BTreeMap<String, u64>> = RwLock::new(BTreeMap::new());

    /// Point-in-time copy of every counter. Used by tests; rendering reads the
    /// atomics directly.
    #[derive(Debug, Clone)]
    pub struct Snapshot {
        pub connections_active: u64,
        pub subscribers_active: u64,
        pub blocks_ingested: u64,
        pub channels: BTreeMap<String, u64>,
    }

    pub fn connection_opened() {
        CONNECTIONS_ACTIVE.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed() {
        decrement(&CONNECTIONS_ACTIVE);
    }

    pub fn subscriber_added() {
        SUBSCRIBERS_ACTIVE.fetch_add(1, Ordering::Relaxed);
    }

    pub fn subscriber_removed() {
        decrement(&SUBSCRIBERS_ACTIVE);
    }

    /// Record one accepted block. `channel` is the slug lifted from the
    /// manifest; `None` for blocks that carry no channel metadata.
    pub fn block_ingested(channel: Option<&str>) {
        BLOCKS_INGESTED.fetch_add(1, Ordering::Relaxed);
        if let Some(slug) = channel {
            let mut map = CHANNEL_MESSAGES
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *map.entry(slug.to_string()).or_insert(0) += 1;
        }
    }

    /// Saturating decrement — a gauge that underflows to u64::MAX is worse
    /// than one that is briefly wrong.
    ///
    /// Recent nightlies deprecate `fetch_update` in favour of `try_update` and
    /// will suggest the rename. DO NOT APPLY IT: `try_update` is still gated
    /// behind the unstable `atomic_try_update` feature on our MSRV (1.94), so
    /// taking the suggestion breaks the build on the minimum toolchain we
    /// declare. Revisit once `try_update` is stable at or below the MSRV.
    fn decrement(counter: &AtomicU64) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        });
    }

    pub fn snapshot() -> Snapshot {
        let channels = CHANNEL_MESSAGES
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        Snapshot {
            connections_active: CONNECTIONS_ACTIVE.load(Ordering::Relaxed),
            subscribers_active: SUBSCRIBERS_ACTIVE.load(Ordering::Relaxed),
            blocks_ingested: BLOCKS_INGESTED.load(Ordering::Relaxed),
            channels,
        }
    }

    /// Prometheus text exposition (format version 0.0.4) of the live counters.
    pub fn render_prometheus() -> String {
        let snap = snapshot();
        render(
            snap.connections_active,
            snap.subscribers_active,
            snap.blocks_ingested,
            &snap.channels,
        )
    }

    /// Pure renderer — separated from the globals so its output format is
    /// testable without touching process-wide state.
    pub(crate) fn render(
        connections: u64,
        subscribers: u64,
        blocks: u64,
        channels: &BTreeMap<String, u64>,
    ) -> String {
        let mut out = String::new();
        out.push_str(
            "# HELP jig_ws_connections_active Open WebSocket connections on /api/v1/ws.\n\
             # TYPE jig_ws_connections_active gauge\n",
        );
        out.push_str(&format!("jig_ws_connections_active {connections}\n"));
        out.push_str(
            "# HELP jig_ws_subscribers_active WebSocket connections holding a live subscription.\n\
             # TYPE jig_ws_subscribers_active gauge\n",
        );
        out.push_str(&format!("jig_ws_subscribers_active {subscribers}\n"));
        out.push_str(
            "# HELP jig_ws_blocks_ingested_total Blocks accepted over WebSocket since start \
             (excludes federation and bridge ingest).\n\
             # TYPE jig_ws_blocks_ingested_total counter\n",
        );
        out.push_str(&format!("jig_ws_blocks_ingested_total {blocks}\n"));
        out.push_str(
            "# HELP jig_ws_channel_messages_total Blocks accepted over WebSocket per channel \
             slug.\n\
             # TYPE jig_ws_channel_messages_total counter\n",
        );
        for (slug, count) in channels {
            out.push_str(&format!(
                "jig_ws_channel_messages_total{{channel=\"{}\"}} {count}\n",
                escape_label(slug)
            ));
        }
        out
    }

    /// Escape a label value per the exposition format: backslash, double
    /// quote, and newline. An unescaped quote corrupts the whole scrape.
    fn escape_label(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
}

// ---- Public API ------------------------------------------------------------

/// Axum handler for `GET /api/v1/ws` — upgrades the HTTP request to WebSocket.
pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> Response {
    let conn_id = CONN_COUNTER.fetch_add(1, Ordering::SeqCst);
    ws.on_upgrade(move |socket| handle_socket(socket, state, conn_id))
}

/// Build a router that mounts the WSS endpoint on the v0.0.2 `AppState`.
/// Mount this alongside (not instead of) the v0.0.1 `build_router`.
///
/// When `state.config.debug.admin_endpoints` is true, the admin-only
/// `/_admin_v0_0_2/*` routes are merged in. Otherwise those paths return 404.
pub fn build_v0_0_2_router(state: Arc<AppState>) -> Router {
    let ws_router = Router::new()
        .route("/api/v1/ws", get(ws_handler))
        .with_state(state.clone());

    // REST block endpoints are always active (not debug-gated).
    let router = ws_router.merge(crate::v0_0_2_blocks::build_blocks_router(state.clone()));

    let mut router = if state.config.debug.admin_endpoints {
        router.merge(crate::v0_0_2_admin::build_admin_router(state.clone()))
    } else {
        router
    };

    // Merge bridge-contributed routes under `/_bridge/<name>/`. Each drained
    // sub-router is a `Router<()>` carrying its own state, so it nests cleanly
    // into the already-state-applied `Router<()>` here. In PR1 nothing mounts
    // (no real bridge is registered in the boot path yet), so this is a no-op;
    // PR2's EmailBridge mounts its inbound webhook into `bridge_router_mount`
    // during `start()`.
    for (bridge_name, sub) in state.bridge_router_mount.drain() {
        router = router.nest(&format!("/_bridge/{bridge_name}"), sub);
    }
    // Applied here as well as in `handler::build_router` because `Router::layer`
    // only wraps the routes already present; `server.rs` merges these two
    // routers afterwards, so a single layer on one of them would leave the
    // other's routes untraced.
    router.layer(crate::handler::http_trace_layer())
}

// ---- Per-connection handler ------------------------------------------------

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>, conn_id: u64) {
    metrics::connection_opened();
    // Per-connection channel: fanout delivers (StoredBlock, StoredReceipt) here.
    let (sub_tx, mut sub_rx) = mpsc::unbounded_channel();
    let mut sub_id: Option<u64> = None;

    loop {
        tokio::select! {
            // --- Client → Server ---
            client_msg = socket.recv() => {
                let Some(Ok(msg)) = client_msg else {
                    // Stream ended or error — clean disconnect.
                    break;
                };
                match msg {
                    Message::Text(text) => {
                        if let Err(e) = handle_client_frame(
                            &text, &state, &sub_tx, &mut sub_id, conn_id, &mut socket,
                        )
                        .await
                        {
                            tracing::warn!(conn_id, "ws frame error: {e}");
                        }
                    }
                    Message::Close(_) => break,
                    // Ignore Ping/Pong/Binary; axum handles Ping→Pong automatically.
                    _ => {}
                }
            }

            // --- Fanout delivery → Client ---
            delivery = sub_rx.recv() => {
                let Some((block, receipt)) = delivery else {
                    // Sub channel closed (server shutdown path).
                    break;
                };
                let receipts = vec![ReceiptRef {
                    server_did: receipt.server_id.clone(),
                    render_hash: receipt.render_hash.clone(),
                    receipt_bytes_b64: base64::engine::general_purpose::STANDARD
                        .encode(&receipt.receipt_bytes),
                }];
                let frame = Envelope::new(Frame::Block {
                    bundle_b64: base64::engine::general_purpose::STANDARD
                        .encode(&block.bundle_bytes),
                    sig_b64: if block.sender_sig.is_empty() {
                        None
                    } else {
                        Some(
                            base64::engine::general_purpose::STANDARD
                                .encode(&block.sender_sig),
                        )
                    },
                    receipts,
                    delivery_cid: format!("delivery:{}", block.cid),
                });
                let Ok(json) = serde_json::to_string(&frame) else {
                    continue;
                };
                if socket.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        }
    }

    // Clean up the subscription so the Fanout map doesn't grow without bound.
    if let Some(id) = sub_id {
        state.ingest_ctx.fanout.unsubscribe_local(id).await;
        metrics::subscriber_removed();
    }
    metrics::connection_closed();
    tracing::debug!(conn_id, "ws connection closed");
}

// ---- Per-frame dispatch ----------------------------------------------------

async fn handle_client_frame(
    text: &str,
    state: &Arc<AppState>,
    sub_tx: &mpsc::UnboundedSender<(
        jig_pipeline::persist::StoredBlock,
        jig_pipeline::persist::StoredReceipt,
    )>,
    sub_id: &mut Option<u64>,
    conn_id: u64,
    socket: &mut WebSocket,
) -> Result<(), String> {
    let env: Envelope = match serde_json::from_str(text) {
        Ok(e) => e,
        Err(e) => {
            // Best-effort error reply; ignore send failure (client may have gone away).
            let _ = send_error(
                socket,
                "BAD_JSON",
                None,
                &format!("envelope parse failed: {e}"),
            )
            .await;
            return Err(e.to_string());
        }
    };

    match env.frame {
        // ------------------------------------------------------------------ Subscribe
        Frame::Subscribe { scope } => {
            let sub_scope = match scope {
                Scope::Channel { slug } => SubscriptionScope::Channel(slug),
                Scope::Federation { block_kinds } => SubscriptionScope::Federation { block_kinds },
            };
            let id = state
                .ingest_ctx
                .fanout
                .subscribe_local(sub_scope, sub_tx.clone())
                .await;
            // The gauge counts connections holding a subscription, matching the
            // single `sub_id` slot that the disconnect path decrements. A
            // re-Subscribe on the same connection replaces that slot, so it
            // must not add a second unit.
            if sub_id.is_none() {
                metrics::subscriber_added();
            }
            *sub_id = Some(id);
            tracing::debug!(conn_id, sub_id = id, "ws subscription registered");
            Ok(())
        }

        // ------------------------------------------------------------------ Submit
        Frame::Submit {
            bundle_b64,
            sig_b64,
        } => {
            // 1. base64-decode the canonical-bytes tuple.
            let bundle_bytes = match base64::engine::general_purpose::STANDARD.decode(&bundle_b64) {
                Ok(b) => b,
                Err(_) => {
                    let _ = send_error(
                        socket,
                        "BAD_BUNDLE_B64",
                        None,
                        "bundle_b64 is not valid base64",
                    )
                    .await;
                    return Ok(());
                }
            };
            let sig = match base64::engine::general_purpose::STANDARD.decode(&sig_b64) {
                Ok(s) => s,
                Err(_) => {
                    let _ = send_error(socket, "BAD_SIG_B64", None, "sig_b64 is not valid base64")
                        .await;
                    return Ok(());
                }
            };

            // 2. Decode (manifest_bytes, code_bytes) tuple from the canonical bytes.
            //    These vecs must outlive the BlockBundle borrow below — keep them here.
            let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) =
                match serde_json::from_slice(&bundle_bytes) {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = send_error(
                            socket,
                            "BAD_BUNDLE",
                            None,
                            &format!("canonical-bytes tuple parse failed: {e}"),
                        )
                        .await;
                        return Ok(());
                    }
                };

            // 3. Construct a BlockBundle borrowing from the local vecs.
            //    Both vecs live for the duration of this block, so the lifetimes hold.
            let bundle = BlockBundle {
                manifest_bytes: &manifest_bytes,
                code_bytes: &code_bytes,
                resources: vec![],
            };

            // 4. Run ingest; reply Ack or a typed Error frame.
            match ingest(
                &state.ingest_ctx,
                bundle,
                sig,
                IngestSource::LocalClient { conn_id },
            )
            .await
            {
                Ok(block_cid) => {
                    metrics::block_ingested(channel_slug_peek(&manifest_bytes).as_deref());
                    let ack = Envelope::new(Frame::Ack { block_cid });
                    let Ok(json) = serde_json::to_string(&ack) else {
                        return Ok(());
                    };
                    let _ = socket.send(Message::Text(json)).await;
                }
                Err(IngestError::InvalidSignature) => {
                    let _ =
                        send_error(socket, "INVALID_SIG", None, "signature verification failed")
                            .await;
                }
                Err(IngestError::DisallowedBlockKind { kind }) => {
                    let _ = send_error(
                        socket,
                        "DISALLOWED_BLOCK_KIND",
                        None,
                        &format!("block kind not in allow list: {kind}"),
                    )
                    .await;
                }
                Err(IngestError::KindRequired) => {
                    let _ = send_error(
                        socket,
                        "KIND_REQUIRED",
                        None,
                        "manifest must declare a block kind",
                    )
                    .await;
                }
                // Distinct code (not the generic INGEST_ERROR) because this is
                // the one ingest failure an ordinary user causes by mistyping a
                // channel name; the Display text is already actionable prose.
                Err(e @ IngestError::UnknownChannel { .. }) => {
                    let _ = send_error(socket, "UNKNOWN_CHANNEL", None, &e.to_string()).await;
                }
                Err(e) => {
                    let _ = send_error(socket, "INGEST_ERROR", None, &e.to_string()).await;
                }
            }
            Ok(())
        }

        // ------------------------------------------------------------------ CatchUp
        Frame::CatchUp { since_hlc: _ } => {
            // v0.0.2 stub: cursor-based replay is deferred to Phase D6 / Phase F.
            // For now the handler is a no-op so clients can send CatchUp without
            // causing an error — they'll simply receive new blocks going forward.
            Ok(())
        }

        // ------------------------------------------------------------------ Server-only frames
        // These are server→client frames; ignore them when received from a client.
        Frame::Ack { .. } | Frame::Block { .. } | Frame::Error { .. } => Ok(()),
    }
}

// ---- Helpers ---------------------------------------------------------------

/// Read the channel slug out of manifest bytes for the per-channel metric,
/// without paying for a full `BlockManifest` deserialization.
///
/// Mirrors the lift in `jig_pipeline::ingest` — text-render / member-add put
/// the slug under `metadata.channel`, channel-create under `metadata.slug`.
/// Metrics-only: nothing downstream reads this value.
fn channel_slug_peek(manifest_bytes: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct MetadataOnly {
        #[serde(default)]
        metadata: serde_json::Map<String, serde_json::Value>,
    }

    let peeked: MetadataOnly = serde_json::from_slice(manifest_bytes).ok()?;
    peeked
        .metadata
        .get("channel")
        .or_else(|| peeked.metadata.get("slug"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

async fn send_error(
    socket: &mut WebSocket,
    code: &str,
    ref_cid: Option<String>,
    message: &str,
) -> Result<(), axum::Error> {
    let frame = Envelope::new(Frame::Error {
        code: code.to_string(),
        ref_cid,
        message: message.to_string(),
    });
    let json = serde_json::to_string(&frame).map_err(axum::Error::new)?;
    socket.send(Message::Text(json)).await
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    use axum::{Router, routing::get};
    use futures_util::{SinkExt, StreamExt};
    use jig_client::blocks::build_text_render;
    use jig_core::HlcTimestamp;
    use tempfile::tempdir;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{connect_async, tungstenite::Message as TMessage};

    /// Spin up the WSS handler on an ephemeral port and return the ws:// URL.
    async fn start_test_server() -> (Arc<AppState>, String) {
        let state = Arc::new(AppState::for_test().unwrap());
        let app = Router::new()
            .route("/api/v1/ws", get(ws_handler))
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let url = format!("ws://{addr}/api/v1/ws");

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (state, url)
    }

    fn test_identity() -> jig_client::Identity {
        let dir = tempdir().unwrap();
        let path = dir.keep();
        jig_client::Identity::generate_and_save(&path).unwrap()
    }

    fn test_hlc(id: &jig_client::Identity) -> HlcTimestamp {
        HlcTimestamp {
            wall_ms: 1_747_680_000_000,
            logical: 0,
            server_did: id.did().clone(),
        }
    }

    /// Seed a channel row so `text-render` submissions clear ingest's
    /// channel-existence guard. These tests are about the WS transport, not
    /// about channel-create, so the row is written directly.
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

    // --- submit → Ack -------------------------------------------------------

    #[tokio::test]
    async fn ws_submit_returns_ack() {
        let (state, url) = start_test_server().await;
        seed_channel(&state, "#hello");
        let (mut ws, _) = connect_async(&url).await.unwrap();

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);

        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });
        ws.send(TMessage::Text(serde_json::to_string(&submit).unwrap()))
            .await
            .unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("timeout waiting for ack")
            .expect("stream closed")
            .expect("ws error");
        let TMessage::Text(reply) = msg else {
            panic!("expected text frame, got {msg:?}");
        };
        let reply_env: Envelope = serde_json::from_str(&reply).unwrap();
        match reply_env.frame {
            Frame::Ack { block_cid } => {
                assert!(!block_cid.is_empty(), "ack must carry a block_cid");
            }
            other => panic!("expected Ack, got {other:?}"),
        }
    }

    // --- bad sig → Error{INVALID_SIG} ---------------------------------------

    #[tokio::test]
    async fn ws_rejects_invalid_sig_with_error_frame() {
        let (_state, url) = start_test_server().await;
        let (mut ws, _) = connect_async(&url).await.unwrap();

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);

        let bad_sig_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: bad_sig_b64,
        });
        ws.send(TMessage::Text(serde_json::to_string(&submit).unwrap()))
            .await
            .unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("timeout waiting for reply")
            .expect("stream closed")
            .expect("ws error");
        let TMessage::Text(reply) = msg else {
            panic!("expected text, got {msg:?}");
        };
        let reply_env: Envelope = serde_json::from_str(&reply).unwrap();
        match reply_env.frame {
            Frame::Error { code, .. } => assert_eq!(code, "INVALID_SIG"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ws_submit_to_unknown_channel_returns_an_actionable_error_frame() {
        // The whole point of the ingest guard is user-visible feedback: a
        // mistyped slug must come back as prose naming the slug, not an Ack
        // carrying a CID for a block nobody will ever read.
        let (_state, url) = start_test_server().await; // no channels seeded
        let (mut ws, _) = connect_async(&url).await.unwrap();

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#gigeu", "hi", hlc);
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });
        ws.send(TMessage::Text(serde_json::to_string(&submit).unwrap()))
            .await
            .unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("timeout waiting for reply")
            .expect("stream closed")
            .expect("ws error");
        let TMessage::Text(reply) = msg else {
            panic!("expected text, got {msg:?}");
        };
        let reply_env: Envelope = serde_json::from_str(&reply).unwrap();
        match reply_env.frame {
            Frame::Error { code, message, .. } => {
                assert_eq!(code, "UNKNOWN_CHANNEL");
                assert!(message.contains("#gigeu"), "must name the slug: {message}");
                assert!(
                    message.contains("jig channel create"),
                    "must say how to recover: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // --- subscribe + submit → Block delivered to subscriber -----------------

    #[tokio::test]
    async fn ws_subscribe_then_submit_delivers_block_to_subscriber() {
        // Single client subscribes federation-scope (matches all blocks), then
        // submits a text-render block and expects both Ack and Block frames.
        //
        // Federation scope with empty block_kinds is the kind-filter-off path,
        // which is what this test covers. Channel scope is exercised by
        // integration-tests/tests/h2_single_server.rs: `ingest` lifts the slug
        // from manifest metadata into `StoredBlock.channel_id`, so
        // `SubscriptionScope::Channel` does match text-render blocks. (An
        // earlier revision of this comment claimed otherwise — that caveat is
        // obsolete.)
        let (state, url) = start_test_server().await;
        seed_channel(&state, "#hello");
        let (mut ws, _) = connect_async(&url).await.unwrap();

        // 1. Subscribe federation-scope (no kind filter = all kinds).
        let sub = Envelope::new(Frame::Subscribe {
            scope: Scope::Federation {
                block_kinds: vec![],
            },
        });
        ws.send(TMessage::Text(serde_json::to_string(&sub).unwrap()))
            .await
            .unwrap();

        // Give the server a beat to register the subscription before submitting.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 2. Submit a block.
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });
        ws.send(TMessage::Text(serde_json::to_string(&submit).unwrap()))
            .await
            .unwrap();

        // 3. Expect both Ack and Block (order is non-deterministic).
        let mut got_ack = false;
        let mut got_block = false;
        for _ in 0..2 {
            let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
                .await
                .expect("timeout waiting for frame")
                .expect("stream closed")
                .expect("ws error");
            let TMessage::Text(text) = msg else { continue };
            let env: Envelope = serde_json::from_str(&text).unwrap();
            match env.frame {
                Frame::Ack { .. } => got_ack = true,
                Frame::Block { .. } => got_block = true,
                _ => {}
            }
        }
        assert!(got_ack, "must receive Ack for submitted block");
        assert!(got_block, "subscribed client must receive Block frame");
    }

    // --- observability counters ---------------------------------------------

    #[test]
    fn prometheus_render_emits_help_type_and_escaped_channel_labels() {
        let mut channels = std::collections::BTreeMap::new();
        channels.insert("#hello".to_string(), 3u64);
        channels.insert("weird\"name".to_string(), 1u64);
        let text = metrics::render(2, 1, 4, &channels);

        assert!(text.contains("# TYPE jig_ws_connections_active gauge"));
        assert!(text.contains("# TYPE jig_ws_blocks_ingested_total counter"));
        assert!(text.contains("\njig_ws_connections_active 2\n"));
        assert!(text.contains("\njig_ws_subscribers_active 1\n"));
        assert!(text.contains("\njig_ws_blocks_ingested_total 4\n"));
        assert!(text.contains("jig_ws_channel_messages_total{channel=\"#hello\"} 3"));
        // An unescaped quote in a label value corrupts the whole exposition.
        assert!(
            text.contains(r#"jig_ws_channel_messages_total{channel="weird\"name"} 1"#),
            "label values must be escaped; got:\n{text}"
        );
        assert!(text.ends_with('\n'), "exposition must end with a newline");
    }

    #[test]
    fn channel_slug_peek_reads_the_same_metadata_keys_as_ingest() {
        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);
        let (manifest_bytes, _code): (Vec<u8>, Vec<u8>) =
            serde_json::from_slice(&block.canonical_bytes()).unwrap();
        assert_eq!(
            channel_slug_peek(&manifest_bytes).as_deref(),
            Some("#hello")
        );

        // channel-create writes the slug under `slug`, not `channel`.
        let created = serde_json::to_vec(&serde_json::json!({
            "metadata": { "slug": "#other" }
        }))
        .unwrap();
        assert_eq!(channel_slug_peek(&created).as_deref(), Some("#other"));

        assert_eq!(channel_slug_peek(b"not json").as_deref(), None);
    }

    #[tokio::test]
    async fn ws_submit_increments_block_and_channel_counters() {
        let before = metrics::snapshot();

        let (state, url) = start_test_server().await;
        seed_channel(&state, "#metrics-probe");
        let (mut ws, _) = connect_async(&url).await.unwrap();

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#metrics-probe", "hi", hlc);
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });
        ws.send(TMessage::Text(serde_json::to_string(&submit).unwrap()))
            .await
            .unwrap();

        // Wait for the Ack so the counter bump has definitely happened.
        let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("timeout waiting for ack")
            .expect("stream closed")
            .expect("ws error");
        let TMessage::Text(reply) = msg else {
            panic!("expected text frame, got {msg:?}");
        };
        let reply_env: Envelope = serde_json::from_str(&reply).unwrap();
        assert!(matches!(reply_env.frame, Frame::Ack { .. }));

        let after = metrics::snapshot();
        assert!(
            after.blocks_ingested > before.blocks_ingested,
            "blocks_ingested must advance ({} -> {})",
            before.blocks_ingested,
            after.blocks_ingested
        );
        assert_eq!(
            after.channels.get("#metrics-probe").copied(),
            Some(1),
            "per-channel counter must record the slug lifted from the manifest"
        );
    }

    // --- bad JSON → connection stays alive ----------------------------------

    #[tokio::test]
    async fn ws_bad_json_does_not_crash_connection() {
        // Send non-JSON text; the handler sends back an Error frame (best-effort)
        // and must NOT drop the connection. If the reply comes back it must be
        // a well-formed Error{code=BAD_JSON}. A timeout is also acceptable — it
        // means the handler tried to reply but the send failed silently, which is
        // permitted for the BAD_JSON path in v0.0.2.
        let (_state, url) = start_test_server().await;
        let (mut ws, _) = connect_async(&url).await.unwrap();

        ws.send(TMessage::Text("not valid json at all".to_string()))
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_millis(500), ws.next()).await;
        if let Ok(Some(Ok(TMessage::Text(text)))) = result {
            let env: Envelope = serde_json::from_str(&text).unwrap();
            match env.frame {
                Frame::Error { code, .. } => assert_eq!(code, "BAD_JSON"),
                _ => {} // other frames are acceptable (e.g. if handler re-used the connection)
            }
        }
        // Timeout is acceptable — primary assertion is the server didn't panic.
    }
}
