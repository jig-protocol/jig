//! Federation peer manager — connects to configured peers, exchanges
//! fed-hello bundles, relays blocks bidirectionally.
//!
//! v0.0.2 minimum-viable federation: block-relay only. Inbound blocks are
//! persisted (block + receipts) and fanned out to local CLI subscribers
//! but do NOT pass through apply_effect — channel + membership state stays
//! local on each server. Channel ops happen via /_admin_v0_0_2/* or
//! (v0.0.3+) Wasm-executed channel-create blocks; they don't replicate.
//!
//! Trust model: the configured peer's URL + expected_did is the trust
//! anchor. Inbound Block frames from a federated peer are NOT re-verified
//! through ingest's sig-verify path — that's the peer-connection
//! responsibility, established via fed-hello at session start.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::Signer;
use futures_util::{SinkExt, StreamExt};
use jig_core::{Author, BlockKind, BlockManifest};
use jig_pipeline::{
    Envelope, Frame, Scope,
    envelope::ReceiptRef,
    persist::{StoredBlock, StoredReceipt},
};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, info, warn};

use crate::v0_0_2::AppState;

/// Reconnect delay after a peer connection drops or fails to establish.
/// Constant in v0.0.2; exponential backoff is a v0.0.3+ refinement.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Spawn one long-running task per configured peer. Each task owns its own
/// reconnect loop and persists across the server's lifetime.
pub fn spawn_federation_peers(state: Arc<AppState>) {
    let peers = state.config.federation.peers.clone();
    for peer in peers {
        let state = state.clone();
        tokio::spawn(async move {
            run_peer_loop(state, peer).await;
        });
    }
}

async fn run_peer_loop(state: Arc<AppState>, peer: jig_config::v0_0_2_server::FederationPeer) {
    info!(peer_url = %peer.url, "federation peer task started");
    loop {
        match connect_and_relay(&state, &peer).await {
            Ok(()) => {
                warn!(
                    peer_url = %peer.url,
                    "peer connection ended cleanly; reconnecting in {RECONNECT_DELAY:?}"
                );
            }
            Err(e) => {
                warn!(
                    peer_url = %peer.url,
                    "peer connection failed: {e}; reconnecting in {RECONNECT_DELAY:?}"
                );
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

async fn connect_and_relay(
    state: &Arc<AppState>,
    peer: &jig_config::v0_0_2_server::FederationPeer,
) -> anyhow::Result<()> {
    let ws_url = format!("{}/api/v1/ws", peer.url.trim_end_matches('/'));
    let (ws, _resp) = connect_async(&ws_url).await?;
    let (mut sink, mut stream) = ws.split();
    info!(peer_url = %peer.url, "federation peer connected");

    // 1. Send fed-hello synthetic bundle as the handshake.
    let hello_bundle = build_fed_hello_bundle(state)?;
    let (hello_canonical, hello_sig) = sign_synthetic_bundle(state, &hello_bundle)?;
    let hello_env = Envelope::new(Frame::Submit {
        bundle_b64: base64::engine::general_purpose::STANDARD.encode(&hello_canonical),
        sig_b64: base64::engine::general_purpose::STANDARD.encode(&hello_sig),
    });
    sink.send(Message::Text(serde_json::to_string(&hello_env)?))
        .await?;

    // 2. Subscribe federation scope so the peer pushes us their block stream.
    let sub_env = Envelope::new(Frame::Subscribe {
        scope: Scope::Federation {
            block_kinds: vec![],
        },
    });
    sink.send(Message::Text(serde_json::to_string(&sub_env)?))
        .await?;

    // 3. Register a peer subscriber on our Fanout so OUR locally-ingested
    //    blocks are pushed out to this peer.
    let (peer_tx, mut peer_rx) = mpsc::unbounded_channel::<(StoredBlock, StoredReceipt)>();
    state
        .ingest_ctx
        .fanout
        .register_peer(peer.url.clone(), peer_tx)
        .await;

    // 4. Main relay loop (inlined to avoid generic sink/stream lifetime issues).
    //    Forward outbound deliveries to peer; persist inbound blocks locally.
    let result = loop {
        tokio::select! {
            // Inbound from peer
            msg = stream.next() => {
                let Some(msg) = msg else {
                    // Stream closed cleanly.
                    break Ok(());
                };
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => break Err(anyhow::anyhow!("ws read error: {e}")),
                };
                match msg {
                    Message::Text(text) => {
                        if let Err(e) = handle_inbound_frame(state, peer, &text).await {
                            warn!(peer_url = %peer.url, "inbound frame error: {e}");
                        }
                    }
                    Message::Close(_) => break Ok(()),
                    // Ignore Ping/Pong/Binary.
                    _ => {}
                }
            }

            // Outbound from our local fanout
            delivery = peer_rx.recv() => {
                let Some((block, receipt)) = delivery else {
                    // Channel closed (server shutdown).
                    break Ok(());
                };
                if let Err(e) = forward_outbound(&mut sink, &block, &receipt).await {
                    warn!(peer_url = %peer.url, "outbound forward error: {e}");
                    break Err(e);
                }
            }
        }
    };

    // 5. On loop exit (peer disconnect, error, or task cancellation), unregister
    //    the peer from Fanout so we don't accumulate dead senders.
    state.ingest_ctx.fanout.unregister_peer(&peer.url).await;

    result
}

async fn handle_inbound_frame(
    state: &Arc<AppState>,
    peer: &jig_config::v0_0_2_server::FederationPeer,
    text: &str,
) -> anyhow::Result<()> {
    let env: Envelope = serde_json::from_str(text)?;
    match env.frame {
        Frame::Block {
            bundle_b64,
            receipts,
            delivery_cid,
        } => ingest_peer_block(state, peer, &bundle_b64, &receipts, &delivery_cid).await,
        Frame::Ack { block_cid } => {
            debug!(peer_url = %peer.url, %block_cid, "peer acked our submission");
            Ok(())
        }
        Frame::Error { code, message, .. } => {
            warn!(peer_url = %peer.url, %code, %message, "peer returned error frame");
            Ok(())
        }
        // Ignore all other frame kinds (Subscribe, Submit, CatchUp).
        _ => Ok(()),
    }
}

async fn ingest_peer_block(
    state: &Arc<AppState>,
    peer: &jig_config::v0_0_2_server::FederationPeer,
    bundle_b64: &str,
    receipts: &[ReceiptRef],
    delivery_cid: &str,
) -> anyhow::Result<()> {
    let bundle_bytes = base64::engine::general_purpose::STANDARD.decode(bundle_b64)?;
    let (manifest_bytes, _code_bytes): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&bundle_bytes)?;
    let manifest: BlockManifest = serde_json::from_slice(&manifest_bytes)?;

    // Derive block_cid the same way ingest does (blake3 over bundle bytes).
    let block_cid = format!(
        "bafy_{}",
        hex::encode(blake3::hash(&bundle_bytes).as_bytes())
    );

    // Already have this block? Avoid duplicate insert.
    if state.ingest_ctx.store.get_block(&block_cid)?.is_some() {
        debug!(%delivery_cid, %block_cid, "already have block; skipping");
        return Ok(());
    }

    // Extract sender DID + HLC + kind from manifest (best-effort).
    let sender_did_str = manifest
        .authors
        .first()
        .map(|a| a.did.to_did_jig_string())
        .unwrap_or_default();
    let kind_str = manifest
        .kind
        .as_ref()
        .map(|k| k.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let (hlc_wall_ms, hlc_logical, hlc_origin) = manifest
        .hlc_ts
        .as_ref()
        .map(|h| (h.wall_ms, h.logical, h.server_did.to_did_jig_string()))
        .unwrap_or((0, 0, String::new()));

    let stored_block = StoredBlock {
        cid: block_cid.clone(),
        channel_id: None,
        block_kind: kind_str,
        sender_did: sender_did_str,
        // sig is not transmitted in Frame::Block; the peer connection itself is
        // the trust anchor (established via fed-hello). See trust model in doc comment.
        sender_sig: vec![],
        bundle_bytes: bundle_bytes.clone(),
        is_synthetic: false,
        hlc_wall_ms,
        hlc_logical,
        hlc_origin,
        posted_at: chrono::Utc::now().timestamp(),
        origin_server: peer.url.clone(),
        federated_from: Some(peer.url.clone()),
    };
    state.ingest_ctx.store.insert_block(&stored_block)?;

    // Persist each receipt from the frame.
    for r in receipts {
        let receipt_bytes = base64::engine::general_purpose::STANDARD
            .decode(&r.receipt_bytes_b64)
            .unwrap_or_default();
        // Derive a stable receipt CID from the block CID and server DID.
        let receipt_cid = format!(
            "r_{}_{}",
            &block_cid[..16.min(block_cid.len())],
            &r.server_did[..16.min(r.server_did.len())]
        );
        let stored_receipt = StoredReceipt {
            cid: receipt_cid,
            block_cid: block_cid.clone(),
            server_id: r.server_did.clone(),
            receipt_bytes,
            render_hash: r.render_hash.clone(),
            produced_at: chrono::Utc::now().timestamp(),
        };
        // Tolerant of duplicate-receipt error (same block_cid + server_id already exists).
        let _ = state.ingest_ctx.store.insert_receipt(&stored_receipt);
    }

    // Broadcast to local CLI subscribers ONLY — broadcast_local_only skips
    // peer fanout and prevents relay loops between federated servers.
    let receipts_in_db = state.ingest_ctx.store.get_receipts_for_block(&block_cid)?;
    if let Some(rep_receipt) = receipts_in_db.into_iter().next() {
        state
            .ingest_ctx
            .fanout
            .broadcast_local_only(&stored_block, &rep_receipt)
            .await?;
    }

    Ok(())
}

async fn forward_outbound(
    sink: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    block: &StoredBlock,
    receipt: &StoredReceipt,
) -> anyhow::Result<()> {
    let frame = Envelope::new(Frame::Block {
        bundle_b64: base64::engine::general_purpose::STANDARD.encode(&block.bundle_bytes),
        receipts: vec![ReceiptRef {
            server_did: receipt.server_id.clone(),
            render_hash: receipt.render_hash.clone(),
            receipt_bytes_b64: base64::engine::general_purpose::STANDARD
                .encode(&receipt.receipt_bytes),
        }],
        delivery_cid: format!("delivery:{}", block.cid),
    });
    let json = serde_json::to_string(&frame)?;
    sink.send(Message::Text(json)).await?;
    Ok(())
}

/// Build the fed-hello manifest + (empty) code bytes for the handshake.
///
/// The fed-hello bundle carries our server DID, URL, advertised block kinds,
/// and active unsafe options so the receiving peer can validate our config.
fn build_fed_hello_bundle(state: &Arc<AppState>) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    use serde_json::json;

    let manifest = BlockManifest::builder()
        .version(semver::Version::new(0, 1, 0))
        .author(Author {
            did: state.server_did.to_did_jig_string().into(),
            public_key: None,
            roles: vec!["jig-server".to_string()],
        })
        .metadata_entry("server_url", json!(state.server_url.clone()))
        .metadata_entry(
            "advertised_block_kinds",
            json!(state.config.server.allowed_block_kinds.clone()),
        )
        .metadata_entry("server_version", json!(env!("CARGO_PKG_VERSION")))
        .metadata_entry(
            "unsafe_options_active",
            json!(state.config.unsafe_options_active()),
        )
        .build()?
        .with_kind(BlockKind::FedHello);

    let manifest_bytes = manifest.to_canonical_bytes()?;
    Ok((manifest_bytes, vec![]))
}

/// Serialize and sign the fed-hello bundle with the server's own key.
fn sign_synthetic_bundle(
    state: &Arc<AppState>,
    bundle: &(Vec<u8>, Vec<u8>),
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let canonical = serde_json::to_vec(bundle)?;
    let sig = state.ingest_ctx.server_key.sign(&canonical);
    Ok((canonical, sig.to_bytes().to_vec()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_federation_peers_with_no_peers_is_noop() {
        // Default AppState has no peers configured; spawn should return immediately
        // (it iterates zero peers and spawns nothing).
        let state = Arc::new(AppState::for_test().unwrap());
        spawn_federation_peers(state);
        // No panic, no hang.
    }

    #[tokio::test]
    async fn build_fed_hello_bundle_carries_server_metadata() {
        let state = Arc::new(AppState::for_test().unwrap());
        let (manifest_bytes, code_bytes) = build_fed_hello_bundle(&state).unwrap();
        assert!(
            code_bytes.is_empty(),
            "fed-hello code payload must be empty in v0.0.2"
        );
        let manifest: BlockManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(manifest.kind, Some(BlockKind::FedHello));
        assert!(
            manifest
                .metadata
                .get("server_url")
                .and_then(|v| v.as_str())
                .is_some(),
            "fed-hello must carry server_url metadata"
        );
        assert!(
            manifest.metadata.get("unsafe_options_active").is_some(),
            "fed-hello must carry unsafe_options_active metadata"
        );
    }

    #[tokio::test]
    async fn sign_synthetic_bundle_produces_verifiable_signature() {
        use ed25519_dalek::Verifier;
        let state = Arc::new(AppState::for_test().unwrap());
        let bundle = build_fed_hello_bundle(&state).unwrap();
        let (canonical, sig_bytes) = sign_synthetic_bundle(&state, &bundle).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        let pubkey = state.ingest_ctx.server_key.verifying_key();
        assert!(
            pubkey.verify(&canonical, &sig).is_ok(),
            "signature over canonical bytes must verify against server verifying key"
        );
    }

    #[tokio::test]
    async fn ingest_peer_block_persists_and_dedupes() {
        use jig_core::{Author, BlockKind, BlockManifest, HlcTimestamp};

        let state = Arc::new(AppState::for_test().unwrap());
        let peer = jig_config::v0_0_2_server::FederationPeer {
            url: "wss://test-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
        };

        // Build a fake block bundle in the same (manifest_bytes, code_bytes) shape
        // that the ingest pipeline and federation module both expect.
        let did_str = "did:jig:zTest";
        let manifest = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: did_str.into(),
                public_key: None,
                roles: vec![],
            })
            .metadata_entry("body", serde_json::json!("hi"))
            .build()
            .unwrap()
            .with_kind(BlockKind::TextRender)
            .with_hlc(HlcTimestamp {
                wall_ms: 1_747_680_000_000,
                logical: 0,
                server_did: did_str.into(),
            });
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle_bytes = serde_json::to_vec(&(manifest_bytes, Vec::<u8>::new())).unwrap();
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle_bytes);

        let receipts = vec![ReceiptRef {
            server_did: "did:jig:zPeer".to_string(),
            render_hash: Some("rh_test".to_string()),
            receipt_bytes_b64: base64::engine::general_purpose::STANDARD.encode(b"{\"v\":\"0.2\"}"),
        }];

        // First ingest: must persist block + receipt.
        ingest_peer_block(&state, &peer, &bundle_b64, &receipts, "delivery:test1")
            .await
            .unwrap();
        let block_cid = format!(
            "bafy_{}",
            hex::encode(blake3::hash(&bundle_bytes).as_bytes())
        );
        let stored = state.ingest_ctx.store.get_block(&block_cid).unwrap();
        assert!(
            stored.is_some(),
            "block must be persisted after first ingest"
        );

        // Second ingest of the same bundle: must dedupe without error.
        ingest_peer_block(&state, &peer, &bundle_b64, &receipts, "delivery:test2")
            .await
            .unwrap();
        let receipts_in_db = state
            .ingest_ctx
            .store
            .get_receipts_for_block(&block_cid)
            .unwrap();
        assert_eq!(
            receipts_in_db.len(),
            1,
            "duplicate ingest must not produce duplicate receipt; got {} receipts",
            receipts_in_db.len()
        );
    }
}
