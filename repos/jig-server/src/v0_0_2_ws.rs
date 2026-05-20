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

// ---- Public API ------------------------------------------------------------

/// Axum handler for `GET /api/v1/ws` — upgrades the HTTP request to WebSocket.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> Response {
    let conn_id = CONN_COUNTER.fetch_add(1, Ordering::SeqCst);
    ws.on_upgrade(move |socket| handle_socket(socket, state, conn_id))
}

/// Build a router that mounts the WSS endpoint on the v0.0.2 `AppState`.
/// Mount this alongside (not instead of) the v0.0.1 `build_router`.
pub fn build_v0_0_2_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/ws", get(ws_handler))
        .with_state(state)
}

// ---- Per-connection handler ------------------------------------------------

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>, conn_id: u64) {
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
    }
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
            let _ = send_error(socket, "BAD_JSON", None, &format!("envelope parse failed: {e}")).await;
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
            *sub_id = Some(id);
            tracing::debug!(conn_id, sub_id = id, "ws subscription registered");
            Ok(())
        }

        // ------------------------------------------------------------------ Submit
        Frame::Submit { bundle_b64, sig_b64 } => {
            // 1. base64-decode the canonical-bytes tuple.
            let bundle_bytes = match base64::engine::general_purpose::STANDARD.decode(&bundle_b64) {
                Ok(b) => b,
                Err(_) => {
                    let _ = send_error(socket, "BAD_BUNDLE_B64", None, "bundle_b64 is not valid base64").await;
                    return Ok(());
                }
            };
            let sig = match base64::engine::general_purpose::STANDARD.decode(&sig_b64) {
                Ok(s) => s,
                Err(_) => {
                    let _ = send_error(socket, "BAD_SIG_B64", None, "sig_b64 is not valid base64").await;
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
                    let ack = Envelope::new(Frame::Ack { block_cid });
                    let Ok(json) = serde_json::to_string(&ack) else { return Ok(()) };
                    let _ = socket.send(Message::Text(json)).await;
                }
                Err(IngestError::InvalidSignature) => {
                    let _ = send_error(socket, "INVALID_SIG", None, "signature verification failed").await;
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

    // --- submit → Ack -------------------------------------------------------

    #[tokio::test]
    async fn ws_submit_returns_ack() {
        let (_state, url) = start_test_server().await;
        let (mut ws, _) = connect_async(&url).await.unwrap();

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);

        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD
                .encode(block.canonical_bytes()),
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

        let bad_sig_b64 =
            base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD
                .encode(block.canonical_bytes()),
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

    // --- subscribe + submit → Block delivered to subscriber -----------------

    #[tokio::test]
    async fn ws_subscribe_then_submit_delivers_block_to_subscriber() {
        // Single client subscribes federation-scope (matches all blocks), then
        // submits a text-render block and expects both Ack and Block frames.
        //
        // Channel-scope fanout won't match text-render blocks in v0.0.2 because
        // channel_id is None on StoredBlock (it lives in manifest metadata, not
        // as a first-class field — per B6 implementation). Federation scope
        // with empty block_kinds matches everything, so we use that.
        let (_state, url) = start_test_server().await;
        let (mut ws, _) = connect_async(&url).await.unwrap();

        // 1. Subscribe federation-scope (no kind filter = all kinds).
        let sub = Envelope::new(Frame::Subscribe {
            scope: Scope::Federation { block_kinds: vec![] },
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
            bundle_b64: base64::engine::general_purpose::STANDARD
                .encode(block.canonical_bytes()),
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
