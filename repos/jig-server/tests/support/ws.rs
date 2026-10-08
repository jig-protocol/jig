//! WebSocket scaffolding: the real `/api/v1/ws` handler on an ephemeral port,
//! driven by a real client that signs its Subscribe the way `jig` does.

use std::time::Duration;

use axum::Router;
use axum::routing::get;
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use futures_util::{SinkExt as _, StreamExt as _};
use jig_pipeline::envelope::SubscribeAuth;
use jig_pipeline::{Envelope, Frame, Scope};
use jig_server::v0_0_2_ws::ws_handler;
use tokio::net::TcpListener;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

use super::{Identity, TestServer, now_ms};

/// How long a test waits for a frame it expects to arrive. Generous, because
/// a false failure under load would be blamed on the gate.
const EXPECTED: Duration = Duration::from_secs(3);
/// How long a test waits for a frame it expects NOT to arrive. Short, because
/// every test asserting silence pays it in full.
const SILENCE: Duration = Duration::from_millis(300);

impl TestServer {
    /// The server's fanout, for assertions about subscription bookkeeping.
    pub fn fanout(&self) -> &jig_pipeline::fanout::Fanout {
        &self.state.ingest_ctx.fanout
    }

    /// Serve the WebSocket endpoint and return its `ws://` URL. The server task
    /// lives until the runtime is dropped at the end of the test.
    pub async fn serve_ws(&self) -> String {
        let app = Router::new()
            .route("/api/v1/ws", get(ws_handler))
            .with_state(self.state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("ws://{}/api/v1/ws", listener.local_addr().expect("addr"));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        url
    }

    /// Delete a membership row directly. There is no `member-remove` block
    /// yet, so this is what revocation looks like today.
    pub fn revoke_membership(&self, slug: &str, member: &Identity) {
        let removed = self
            .state
            .ingest_ctx
            .store
            .remove_membership(slug, &member.did().to_did_jig_string())
            .expect("store");
        assert!(removed, "precondition: {slug} had no membership to revoke");
    }
}

pub struct WsClient {
    ws: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
}

impl WsClient {
    pub async fn connect(url: &str) -> Self {
        let (mut ws, _) = connect_async(url).await.expect("ws connect");
        // The server refuses every frame until this welcome is in hand.
        jig_server::v0_0_2_federation::complete_client_handshake(&mut ws)
            .await
            .expect("handshake");
        Self { ws }
    }

    /// Send a signed Subscribe for `slug` as `who`. A successful subscribe
    /// emits no frame, so this waits briefly for a refusal and returns it;
    /// `None` means the subscription was registered.
    pub async fn subscribe(&mut self, who: &Identity, slug: &str) -> Option<Frame> {
        let scope = Scope::Channel {
            slug: slug.to_string(),
        };
        let hlc_wall_ms = now_ms();
        let nonce = format!("ws-{hlc_wall_ms}-{}", slug.len());
        let hash = jig_core::request_auth::canonical_request_hash(
            "SUBSCRIBE",
            &scope.canonical_string(),
            b"",
            hlc_wall_ms,
            0,
            &nonce,
        );
        let frame = Envelope::new(Frame::Subscribe {
            auth: Some(SubscribeAuth {
                did: who.did().to_did_jig_string(),
                hlc_wall_ms,
                hlc_logical: 0,
                nonce,
                sig_b64: base64::engine::general_purpose::STANDARD
                    .encode(who.signing.sign(hash.as_bytes()).to_bytes()),
            }),
            scope,
        });
        self.send(&frame).await;
        self.next_frame(SILENCE).await
    }

    /// Submit a `text-render` over this socket and return the server's
    /// answer frame (Ack or Error).
    pub async fn submit_text(&mut self, who: &Identity, slug: &str, body: &str) -> Frame {
        let me = who.as_client();
        let block = jig_client::blocks::build_text_render(
            &me,
            slug,
            body,
            jig_core::HlcTimestamp::now_wall(me.did().clone()),
        );
        let frame = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });
        self.send(&frame).await;
        self.next_frame(EXPECTED).await.expect("a reply to Submit")
    }

    /// The next delivered block's `delivery_cid`, or `None` if nothing
    /// arrives in the time a real delivery would take.
    pub async fn next_block(&mut self) -> Option<String> {
        self.next_block_within(EXPECTED).await
    }

    /// Like [`next_block`](Self::next_block) but tuned for asserting silence.
    pub async fn no_block(&mut self) -> bool {
        self.next_block_within(SILENCE).await.is_none()
    }

    async fn next_block_within(&mut self, within: Duration) -> Option<String> {
        match self.next_frame(within).await? {
            Frame::Block { delivery_cid, .. } => Some(delivery_cid),
            other => panic!("expected a Block frame, got {other:?}"),
        }
    }

    async fn send(&mut self, frame: &Envelope) {
        let text = serde_json::to_string(frame).expect("frame serializes");
        self.ws
            .send(Message::Text(text.into()))
            .await
            .expect("ws send");
    }

    async fn next_frame(&mut self, within: Duration) -> Option<Frame> {
        let msg = tokio::time::timeout(within, self.ws.next()).await.ok()??;
        let Message::Text(text) = msg.expect("ws error") else {
            return None;
        };
        let env: Envelope = serde_json::from_str(&text).expect("frame parses");
        Some(env.frame)
    }
}
