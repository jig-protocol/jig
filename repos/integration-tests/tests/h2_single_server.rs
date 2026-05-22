//! H2: Single-server two-client text-render chat round-trip.
//!
//! Alice creates `#hello` via the admin endpoint. Bob connects via WSS,
//! submits a text-render block, and Alice (subscribed via WSS) must
//! receive Bob's block within a few seconds.
//!
//! v0.0.2 caveat: channel-scope subscriptions don't fire for text-render
//! because `StoredBlock.channel_id` is `None` (channel slug lives in the
//! manifest metadata, not as a first-class column). We subscribe with
//! federation-scope (empty `block_kinds`) — same delivery semantics on
//! the receiving side, just a different filter shape. v0.0.3+ wires
//! `channel_id` into the ingest path; the test can switch back then.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use integration_tests::harness::*;
use jig_pipeline::{Envelope, Frame, Scope};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[tokio::test]
async fn single_server_two_client_text_render_round_trip() {
    let server = TestJigServer::start_with_full_kinds()
        .await
        .expect("start server");
    let (alice, _alice_dir) = test_identity_with_dir();
    let (bob, _bob_dir) = test_identity_with_dir();

    // Alice creates the channel (admin endpoint).
    server
        .create_channel(&alice, "#hello", "open")
        .await
        .expect("create_channel");

    // Alice opens WSS and subscribes federation-scope (matches all kinds).
    let ws_url = format!("{}/api/v1/ws", server.ws_url());
    let (mut alice_ws, _) = connect_async(&ws_url).await.expect("alice ws connect");
    let sub_env = Envelope::new(Frame::Subscribe {
        scope: Scope::Federation {
            block_kinds: vec![],
        },
    });
    alice_ws
        .send(Message::Text(serde_json::to_string(&sub_env).unwrap()))
        .await
        .expect("alice subscribe send");

    // Give the subscription a beat to register on the server side.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Bob submits a text-render block via REST.
    let cid = server
        .send_text_render(&bob, "#hello", "hi from bob")
        .await
        .expect("bob send");
    assert!(!cid.is_empty());

    // Alice waits for the delivered Block frame.
    let mut got_block_body = None;
    for _ in 0..5 {
        let msg = tokio::time::timeout(Duration::from_secs(2), alice_ws.next())
            .await
            .expect("alice timeout waiting for delivery")
            .expect("ws stream ended")
            .expect("ws read error");
        let Message::Text(text) = msg else { continue };
        let env: Envelope = serde_json::from_str(&text).expect("envelope parse");
        if let Frame::Block { bundle_b64, .. } = env.frame {
            let bundle_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &bundle_b64)
                    .expect("bundle b64");
            let (manifest_bytes, _code_bytes): (Vec<u8>, Vec<u8>) =
                serde_json::from_slice(&bundle_bytes).expect("bundle tuple");
            let manifest: jig_core::BlockManifest =
                serde_json::from_slice(&manifest_bytes).expect("manifest");
            assert_eq!(manifest.kind, Some(jig_core::BlockKind::TextRender));
            got_block_body = manifest
                .metadata
                .get("body")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            break;
        }
    }
    assert_eq!(
        got_block_body.as_deref(),
        Some("hi from bob"),
        "alice must receive bob's text-render block"
    );
}
