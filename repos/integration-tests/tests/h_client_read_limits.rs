//! What a server legitimately sends a client fits the client's read limits:
//! the largest block a server takes is delivered over the WebSocket in one
//! message under `jig_client::limits::MAX_WS_MESSAGE_BYTES`.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use integration_tests::harness::*;
use jig_pipeline::{Envelope, Frame, Scope};
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// The largest block `server` takes on `#big`: a short text-render whose
/// metadata is padded, found by halving the step from past the bundle limit.
/// (A long body runs out of render fuel long before the bundle limit; the
/// padding is stored and relayed but never rendered.) Returns the padding.
async fn largest_accepted(server: &TestJigServer, alice: &jig_client::Identity) -> usize {
    let mut len = jig_core::bundle::MAX_BUNDLE_BYTES;
    let mut step = len / 2;
    let mut best = 0;
    while step >= 256 {
        let hlc = jig_core::HlcTimestamp::now_wall(alice.did().clone());
        let block = jig_client::blocks::build_with_metadata(
            alice,
            jig_core::BlockKind::TextRender,
            hlc,
            serde_json::json!({"channel": "#big", "body": "hi", "pad": "x".repeat(len)}),
        );
        match server.submit_block(&block).await {
            Ok(_) => {
                best = best.max(len);
                len += step;
            }
            Err(_) => len -= step,
        }
        step /= 2;
    }
    assert!(best > 0, "no block was accepted");
    best
}

#[tokio::test]
async fn the_largest_block_is_delivered_under_the_clients_ws_limit() {
    let server = TestJigServer::start().await.expect("start");
    let (alice, _dir) = test_identity_with_dir();
    server
        .create_channel(&alice, "#big", "open")
        .await
        .expect("create");

    let (mut ws, _) = connect_async(format!("{}/api/v1/ws", server.ws_url()))
        .await
        .expect("connect");
    jig_server::v0_0_2_federation::complete_client_handshake(&mut ws, None)
        .await
        .expect("handshake");
    let sub = signed_subscribe(
        &alice,
        Scope::Channel {
            slug: "#big".to_string(),
        },
    );
    ws.send(Message::Text(serde_json::to_string(&sub).unwrap().into()))
        .await
        .expect("subscribe");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let body_len = largest_accepted(&server, &alice).await;

    // The largest of the frames that arrive is the largest block's.
    let mut largest = 0;
    while let Ok(Some(Ok(Message::Text(text)))) =
        tokio::time::timeout(Duration::from_secs(5), ws.next()).await
    {
        if let Ok(Envelope {
            frame: Frame::Block { .. },
            ..
        }) = serde_json::from_str::<Envelope>(&text)
        {
            largest = largest.max(text.len());
        }
    }
    eprintln!(
        "largest block: {body_len} B of padding, delivered in a {largest} B frame; \
         the client takes up to {} B",
        jig_client::limits::MAX_WS_MESSAGE_BYTES
    );
    assert!(largest > 0, "no Block frame arrived");
    // Within a few kilobytes of the bundle limit: this is the worst case.
    assert!(
        body_len > jig_core::bundle::MAX_BUNDLE_BYTES / 4 - 4096,
        "the search stopped short of the bundle limit: {body_len}"
    );
    assert!(
        largest <= jig_client::limits::MAX_WS_MESSAGE_BYTES,
        "a legitimate Block frame of {largest} B is past the client's limit"
    );
}
