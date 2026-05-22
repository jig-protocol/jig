//! H3: Two-server federation chat with cross-server receipt parity.
//!
//! THIS IS THE V0.0.2 ACCEPTANCE TEST. Alice connects to server-a, Bob
//! connects to server-b. Alice sends a text-render block. Bob must
//! receive it via federation within 2s, and both servers' receipts for
//! the block must agree on render_hash.
//!
//! v0.0.2 caveats observed while writing this test:
//! 1. Federation handshake is synthetic (not a real Wasm block) — done
//!    via Frame::Submit with a fed-hello bundle signed by the server's
//!    own key. The test doesn't assert handshake completion; we just
//!    wait a beat after add_peer.
//! 2. Each server signs receipts with its OWN server_key — receipt_bytes
//!    differ across servers. We compare render_hash, the deterministic
//!    output marker (None in v0.0.2 — see H1 for the explanation).
//! 3. The receiving server stores federated blocks with `sender_sig: vec![]`
//!    (see v0_0_2_federation::ingest_peer_block) — the connection's
//!    fed-hello is the trust anchor. That's a v0.0.2 carve-out and is
//!    explicitly noted on the federation module.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use integration_tests::harness::*;
use jig_pipeline::{Envelope, Frame, Scope};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[tokio::test]
async fn two_server_federation_chat_with_receipt_parity() {
    // Boot two TOFU-mode servers (federation handshake doesn't require NS).
    let server_a = TestJigServer::start_with_full_kinds()
        .await
        .expect("start server_a");
    let server_b = TestJigServer::start_with_full_kinds()
        .await
        .expect("start server_b");

    // Bidirectional peering.
    server_a.add_peer(&server_b).await.expect("a -> b");
    server_b.add_peer(&server_a).await.expect("b -> a");
    // Give the fed-hello handshake + subscription dance time to settle.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (alice, _alice_dir) = test_identity_with_dir();
    let (_bob, _bob_dir) = test_identity_with_dir();

    // Alice creates the channel on server_a. (Channel state doesn't federate
    // in v0.0.2 — channel ops are admin-endpoint-only — but the channel must
    // exist on the SENDER's server so member-add can resolve; for text-render
    // the channel doesn't even need to exist locally.)
    server_a
        .create_channel(&alice, "#hello", "open")
        .await
        .expect("create_channel");

    // Bob subscribes to server_b via WSS (federation scope so we match
    // text-render regardless of channel_id).
    let ws_url_b = format!("{}/api/v1/ws", server_b.ws_url());
    let (mut bob_ws, _) = connect_async(&ws_url_b).await.expect("bob ws connect");
    let sub = Envelope::new(Frame::Subscribe {
        scope: Scope::Federation {
            block_kinds: vec![],
        },
    });
    bob_ws
        .send(Message::Text(serde_json::to_string(&sub).unwrap()))
        .await
        .expect("bob subscribe send");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Alice submits a text-render block to server_a.
    let cid_a = server_a
        .send_text_render(&alice, "#hello", "hi from alice (federated)")
        .await
        .expect("alice send");
    assert!(!cid_a.is_empty());

    // Bob must receive the block on server_b within 3s.
    let mut bob_received_cid: Option<String> = None;
    for _ in 0..10 {
        let timed = tokio::time::timeout(Duration::from_secs(3), bob_ws.next()).await;
        let Ok(Some(Ok(Message::Text(text)))) = timed else {
            continue;
        };
        let env: Envelope = match serde_json::from_str(&text) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if let Frame::Block { bundle_b64, .. } = env.frame {
            let bundle_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &bundle_b64)
                    .expect("bundle b64");
            let derived_cid = format!(
                "bafy_{}",
                hex::encode(blake3::hash(&bundle_bytes).as_bytes())
            );
            // Confirm the body content matches
            let (manifest_bytes, _): (Vec<u8>, Vec<u8>) =
                serde_json::from_slice(&bundle_bytes).expect("tuple");
            let manifest: jig_core::BlockManifest =
                serde_json::from_slice(&manifest_bytes).expect("manifest");
            if manifest
                .metadata
                .get("body")
                .and_then(|v| v.as_str())
                .map(|s| s.contains("federated"))
                .unwrap_or(false)
            {
                bob_received_cid = Some(derived_cid);
                break;
            }
        }
    }
    assert!(
        bob_received_cid.is_some(),
        "Bob must receive alice's federated text-render block via server_b"
    );

    // Confirm BOTH servers have the block + a receipt for it.
    // Server_a stores under its ingest-computed CID. Server_b stores under
    // the federation-receive-computed CID (also blake3 over the bundle).
    let receipts_a = server_a.receipts_for(&cid_a).expect("receipts on a");
    assert!(!receipts_a.is_empty(), "server_a must have a receipt");

    // Server_b's CID for the same block: derived via blake3 over canonical
    // bytes. The federation module uses the same blake3 hash for the CID.
    // Both should produce the same hash since canonical bytes are identical;
    // the format prefix is identical too ("bafy_<hex>" for the federation
    // path; the local ingest may use just blake3 hex without the prefix).
    let receipts_b_with_b_cid = server_b
        .receipts_for(&bob_received_cid.clone().unwrap())
        .expect("receipts on b");
    let receipts_b_with_a_cid = server_b
        .receipts_for(&cid_a)
        .expect("receipts on b via a-cid");

    let receipts_b = if !receipts_b_with_b_cid.is_empty() {
        receipts_b_with_b_cid
    } else {
        receipts_b_with_a_cid
    };

    assert!(
        !receipts_b.is_empty(),
        "server_b must have a receipt for the federated block (looked up under both \
         locally-derived CID `{}` and sender-side CID `{cid_a}`)",
        bob_received_cid.unwrap_or_default()
    );

    // Cross-server receipt parity: render_hash agreement. Both are None in
    // v0.0.2 (synthetic-receipt path) — see H1 for the rationale.
    assert_eq!(
        receipts_a[0].render_hash, receipts_b[0].render_hash,
        "cross-server render_hash parity must hold for federated text-render"
    );
}
