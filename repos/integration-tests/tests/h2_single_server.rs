//! H2: Single-server text-render chat round-trip over channel-scope subs.
//!
//! Alice creates `#hello` via the admin endpoint. Bob submits a text-render
//! block, and every channel-scope subscriber must receive it within a few
//! seconds.
//!
//! Two shapes are covered here because they are two different code paths:
//! - `single_server_two_client_text_render_round_trip` drives the raw
//!   envelope wire (tokio-tungstenite) with one subscriber.
//! - `three_concurrent_subscribers_each_receive_every_message` drives
//!   `jig_client::Client` — the exact library `jig-cli` uses — with three
//!   concurrent subscribers, which is the real product shape (group chat).
//!
//! Channel-scope delivery works because `jig_pipeline::ingest` lifts the
//! channel slug out of `manifest.metadata["channel"]` (or `["slug"]`) into
//! the first-class `StoredBlock.channel_id` column, which
//! `Fanout::broadcast_to_locals` then matches against
//! `SubscriptionScope::Channel`. (An earlier revision of this file
//! subscribed federation-scope and claimed channel-scope could not work —
//! that caveat is obsolete.)

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use integration_tests::harness::*;
use jig_client::Client;
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

    // Alice opens WSS and subscribes channel-scope — the same scope the CLI
    // uses. This is the path the product actually runs on.
    let ws_url = format!("{}/api/v1/ws", server.ws_url());
    let (mut alice_ws, _) = connect_async(&ws_url).await.expect("alice ws connect");
    let sub_env = Envelope::new(Frame::Subscribe {
        scope: Scope::Channel {
            slug: "#hello".to_string(),
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

/// Group chat is the product. Every other WSS test in this workspace has
/// exactly one listener, so nothing defended the N-subscriber case: a fanout
/// bug that delivered to only the first (or last) registered subscriber would
/// have passed every existing test.
///
/// This drives `jig_client::Client` rather than raw tungstenite because that
/// is the library `jig-cli` links against — same connect/subscribe/submit
/// path a human gets from the CLI.
#[tokio::test]
async fn three_concurrent_subscribers_each_receive_every_message() {
    const SUBSCRIBER_COUNT: usize = 3;
    const SLUG: &str = "#groupchat";
    let bodies = ["first", "second", "third"];

    let server = TestJigServer::start_with_full_kinds()
        .await
        .expect("start server");
    let owner = test_identity();
    server
        .create_channel(&owner, SLUG, "open")
        .await
        .expect("create_channel");

    // Three independent clients, three independent WSS connections, each
    // registering its own channel-scope subscription on the server's Fanout.
    let mut streams = Vec::with_capacity(SUBSCRIBER_COUNT);
    let mut clients = Vec::with_capacity(SUBSCRIBER_COUNT);
    for _ in 0..SUBSCRIBER_COUNT {
        let client = Client::connect(&server.ws_url(), test_identity())
            .await
            .expect("subscriber connect");
        streams.push(client.subscribe_channel(SLUG).await.expect("subscribe"));
        clients.push(client);
    }

    // Subscribe frames are fire-and-forget (no ack in v0.0.2), so give the
    // server a beat to register all three before the first send.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // `Client::connect` takes ownership of the Identity, so keep a second
    // handle on the same keyfile for signing the outbound blocks.
    let (sender_id, sender_dir) = test_identity_with_dir();
    let sender = Client::connect(
        &server.ws_url(),
        load_identity(&sender_dir, &sender_id.did_string()),
    )
    .await
    .expect("sender connect");
    for body in bodies {
        let hlc = jig_core::HlcTimestamp {
            wall_ms: chrono::Utc::now().timestamp_millis() as u64,
            logical: 0,
            server_did: sender_id.did().clone(),
        };
        let block = jig_client::blocks::build_text_render(&sender_id, SLUG, body, hlc);
        sender.submit(block).await.expect("submit");
    }

    for (i, stream) in streams.iter_mut().enumerate() {
        let mut received = Vec::new();
        for _ in 0..bodies.len() {
            let delivered = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .unwrap_or_else(|_| panic!("subscriber {i} timed out; got {received:?}"))
                .unwrap_or_else(|| panic!("subscriber {i} stream closed; got {received:?}"));
            received.push(body_of(&delivered.bundle_b64));
        }
        assert_eq!(
            received, bodies,
            "subscriber {i} must receive every message, in send order"
        );
    }
}

/// Extract the `body` metadata string from a delivered bundle. Panics on
/// anything malformed — in a test that IS the assertion.
fn body_of(bundle_b64: &str) -> String {
    let bundle_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, bundle_b64)
            .expect("bundle b64");
    let (manifest_bytes, _code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&bundle_bytes).expect("bundle tuple");
    let manifest: jig_core::BlockManifest =
        serde_json::from_slice(&manifest_bytes).expect("manifest");
    assert_eq!(manifest.kind, Some(jig_core::BlockKind::TextRender));
    manifest
        .metadata
        .get("body")
        .and_then(|v| v.as_str())
        .expect("body metadata")
        .to_string()
}
