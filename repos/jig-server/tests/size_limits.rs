//! `[limits]`: the most bytes one request body or one WebSocket message may
//! carry. At the limit is served; one byte over is refused, with `413` on
//! REST and a closed connection on WebSocket.
//!
//! The limits are the defaults, so these also show the largest block a
//! client can send fits them ([`MAX_ENVELOPE_BYTES`]).

mod support;

use std::time::Duration;

use axum::http::StatusCode;
use futures_util::{SinkExt as _, StreamExt as _};
use jig_core::bundle::MAX_ENVELOPE_BYTES;
use jig_pipeline::{Envelope, Frame};
use support::{Identity, TestServer, submission};
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// `bytes` padded with trailing JSON whitespace to exactly `len`.
fn padded(mut bytes: Vec<u8>, len: usize) -> Vec<u8> {
    assert!(bytes.len() <= len, "{} > {len}", bytes.len());
    bytes.resize(len, b' ');
    bytes
}

#[tokio::test]
async fn a_request_body_at_the_limit_is_served_and_one_byte_over_is_413() {
    let server = TestServer::unauthenticated();
    let (owner, poster) = (Identity::new(1), Identity::new(2));
    server.create_channel(&owner, "#town", "open").await;

    let at = padded(
        serde_json::to_vec(&submission(&server.text(&poster, "#town", "at"))).unwrap(),
        MAX_ENVELOPE_BYTES,
    );
    let (status, body) = server.post_raw("/api/v1/blocks", at).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let over = padded(
        serde_json::to_vec(&submission(&server.text(&poster, "#town", "over"))).unwrap(),
        MAX_ENVELOPE_BYTES + 1,
    );
    let (status, body) = server.post_raw("/api/v1/blocks", over).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
}

/// The next frame, or `None` once the server has closed the connection.
async fn next_frame(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Option<Frame> {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("the server answers or closes")
        {
            Some(Ok(Message::Text(text))) => return Some(Envelope::parse(&text).unwrap().frame),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return None,
            Some(Ok(other)) => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_ws_message_at_the_limit_is_served_and_one_byte_over_closes() {
    let server = TestServer::unauthenticated();
    let (owner, poster) = (Identity::new(1), Identity::new(2));
    server.create_channel(&owner, "#town", "open").await;
    let url = server.serve_ws().await;
    let (mut ws, _) = connect_async(&url).await.expect("connect");
    jig_server::v0_0_2_federation::complete_client_handshake(&mut ws, None)
        .await
        .expect("handshake");

    let submit = |body: &str, len: usize| {
        let block = server.text(&poster, "#town", body);
        let frame = Envelope::new(Frame::Submit {
            bundle_b64: submission(&block)["bundle_b64"].as_str().unwrap().into(),
            sig_b64: submission(&block)["sig_b64"].as_str().unwrap().into(),
        });
        let text = padded(serde_json::to_vec(&frame).unwrap(), len);
        Message::Text(String::from_utf8(text).unwrap().into())
    };

    ws.send(submit("at", MAX_ENVELOPE_BYTES)).await.unwrap();
    match next_frame(&mut ws).await {
        Some(Frame::Ack { .. }) => {}
        other => panic!("expected an ack at the limit, got {other:?}"),
    }

    ws.send(submit("over", MAX_ENVELOPE_BYTES + 1))
        .await
        .unwrap();
    assert_eq!(
        next_frame(&mut ws).await,
        None,
        "one byte over the limit closes the connection"
    );
}

/// The bundle limit's headroom, measured. A `text-render` (every chat
/// message) names its program and is a few kilobytes. The largest bundle in
/// use is one that ships a component itself: the text-block component, whose
/// bytes serialize as a JSON number array, about 2.6 canonical bytes per raw
/// byte. Both stay under a third of [`MAX_BUNDLE_BYTES`].
#[tokio::test]
async fn the_largest_bundles_in_use_have_headroom_under_the_limit() {
    use jig_core::bundle::MAX_BUNDLE_BYTES;
    let server = TestServer::unauthenticated();
    let text = server
        .text(&Identity::new(2), "#town", &"x".repeat(4096))
        .canonical_bytes()
        .len();
    let component = jig_pipeline::text_block::canonical::CANONICAL_COMPONENT;
    let shipped = serde_json::to_vec(&(Vec::<u8>::new(), component.to_vec()))
        .unwrap()
        .len();
    println!(
        "text-render {text} B; text-block component {} B raw, {shipped} B canonical; limit {MAX_BUNDLE_BYTES} B",
        component.len()
    );
    for len in [text, shipped] {
        assert!(
            len * 3 < MAX_BUNDLE_BYTES,
            "{len} bytes of {MAX_BUNDLE_BYTES}"
        );
    }
}
