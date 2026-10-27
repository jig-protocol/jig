//! v0.0.2 WSS subscription endpoint at `/api/v1/ws`.
//!
//! CLI clients (Phase F's `jig chat`, `jig tail`, etc.) and federated
//! peers (Task D5) connect here. The envelope codec lives in
//! `jig_pipeline::envelope`; submissions flow through
//! `jig_pipeline::ingest()`.
//!
//! # Frame flow
//! ```text
//! Client → Frame::Hello      → server signs Frame::Welcome (JEP-0002)
//! Client → Frame::Subscribe  → register with Fanout (only after welcome)
//! Client → Frame::Submit     → base64-decode, reconstruct BlockBundle,
//!                              call ingest(), reply Ack or Error
//! Client → Frame::CatchUp    → v0.0.2 stub; cursor replay deferred (Plan §D6/F)
//! Server → Frame::Welcome    → signed version, suites, capabilities, reputation
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
        ws::{CloseFrame, Message, WebSocket},
    },
    response::Response,
    routing::get,
};
use base64::Engine as _;
use jig_pipeline::{
    Envelope, Frame, ReceiptRef, Scope, SubscriptionScope,
    envelope::EnvelopeParseError,
    fanout::SubscriberIdentity,
    handshake::{HelloRefusal, close},
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
/// SCOPE — read before trusting a number. The `jig_ws_*` counters are bumped
/// from the WebSocket path in THIS module only. `jig_blocks_ingested_total`
/// comes from [`jig_pipeline::metrics`], which counts every accepted block by
/// source (local, federation, admin, bridge). Counters reset to zero on
/// restart, which is normal for Prometheus counters.
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
    /// Rust 1.99 deprecates `fetch_update` in favour of `try_update` and will
    /// suggest the rename. DO NOT APPLY IT: `try_update` is not stable on our
    /// MSRV (`rust-version` in repos/Cargo.toml), so taking the suggestion
    /// breaks the build on the minimum toolchain we declare. Revisit, and drop
    /// the `allow`, once `try_update` is stable at or below the MSRV.
    #[allow(deprecated)]
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
            &jig_pipeline::metrics::ingested_by_source(),
        )
    }

    /// Pure renderer — separated from the globals so its output format is
    /// testable without touching process-wide state.
    pub(crate) fn render(
        connections: u64,
        subscribers: u64,
        blocks: u64,
        channels: &BTreeMap<String, u64>,
        by_source: &[(&str, u64)],
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
             (see jig_blocks_ingested_total for every source).\n\
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
        out.push_str(
            "# HELP jig_blocks_ingested_total Blocks accepted since start, by source: local \
             (WebSocket and REST clients), federation, admin, bridge.\n\
             # TYPE jig_blocks_ingested_total counter\n",
        );
        for (source, count) in by_source {
            out.push_str(&format!(
                "jig_blocks_ingested_total{{source=\"{source}\"}} {count}\n"
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
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    exporter: Option<axum::Extension<crate::server::TlsExporter>>,
) -> Response {
    let conn_id = CONN_COUNTER.fetch_add(1, Ordering::SeqCst);
    let ip = peer.map(|p| p.0.0.ip());
    // What the welcome is bound to: this connection's TLS session, or
    // nothing over plaintext.
    let tls_exporter = exporter.map(|e| e.0.0.to_vec()).unwrap_or_default();
    // `[limits]`: a message or frame over these closes the connection.
    let limits = state.limits();
    ws.max_message_size(limits.ws_message)
        .max_frame_size(limits.ws_frame)
        .on_upgrade(move |socket| handle_socket(socket, state, conn_id, ip, tls_exporter))
}

/// `[auth.rate_limit]` per remote address, on every request this router
/// serves. A server started without connection info (tests driving the
/// router directly) has no address to charge.
async fn per_ip_rate(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());
    if let Some(ip) = ip
        && !state.auth.charge_ip(ip)
    {
        let outcome = crate::auth::GateOutcome::RateLimited;
        tracing::info!(%ip, audit = %crate::auth::audit_line(&outcome), "request refused");
        let (status, code, message) = state.auth.disclosure.disclose(&outcome);
        let status = axum::http::StatusCode::from_u16(status)
            .unwrap_or(axum::http::StatusCode::TOO_MANY_REQUESTS);
        let body = crate::v0_0_2_blocks::ErrorBody {
            code: code.to_string(),
            message,
        };
        return axum::response::IntoResponse::into_response((status, axum::Json(body)));
    }
    next.run(req).await
}

/// Build a router that mounts the WSS endpoint on the v0.0.2 `AppState`.
/// Mount this alongside (not instead of) the v0.0.1 `build_router`.
///
/// Channel ops (`POST /api/v1/channels*`) are always mounted.
pub fn build_v0_0_2_router(state: Arc<AppState>) -> Router {
    let ws_router = Router::new()
        .route("/api/v1/ws", get(ws_handler))
        .with_state(state.clone());

    // REST block and channel-op endpoints are always active (not debug-gated).
    let mut router = ws_router
        .merge(crate::v0_0_2_blocks::build_blocks_router(state.clone()))
        .merge(crate::v0_0_2_admin::build_channel_ops_router(state.clone()))
        .merge(crate::v0_0_2_mls::build_mls_router(state.clone()))
        .merge(crate::v0_0_2_admission::build_admission_router(
            state.clone(),
        ));

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
    // `[limits]`: a body over this is refused with 413 before it is parsed.
    let body_limit = axum::extract::DefaultBodyLimit::max(state.limits().request_body);
    router
        .layer(body_limit)
        .layer(axum::middleware::from_fn_with_state(state, per_ip_rate))
        .layer(crate::handler::http_trace_layer())
}

// ---- Per-connection handler ------------------------------------------------

async fn handle_socket(
    mut socket: WebSocket,
    state: Arc<AppState>,
    conn_id: u64,
    ip: Option<std::net::IpAddr>,
    tls_exporter: Vec<u8>,
) {
    metrics::connection_opened();
    // Per-connection channel: fanout delivers (StoredBlock, StoredReceipt) here.
    let (sub_tx, mut sub_rx) = mpsc::unbounded_channel();
    let mut session = ConnState {
        tls_exporter,
        ..ConnState::default()
    };

    let mut peer_rx: Option<mpsc::Receiver<Envelope>> = None;
    loop {
        // A dialer that named a peer DID has until here to prove it.
        let proof_deadline = session.awaiting_peer.as_ref().map(|p| p.deadline);
        if peer_rx.is_none() {
            peer_rx = session.peer_rx.take();
        }
        tokio::select! {
            // --- Peer frames this server sends unprompted → Peer ---
            Some(env) = async {
                match peer_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Ok(json) = serde_json::to_string(&env) else {
                    continue;
                };
                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            () = async {
                match proof_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => {
                tracing::info!(conn_id, "closing: no peer_proof within the handshake wait");
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: close::HANDSHAKE_FAILED,
                        reason: "no peer_proof".into(),
                    })))
                    .await;
                break;
            }
            // --- Client → Server ---
            client_msg = socket.recv() => {
                let Some(Ok(msg)) = client_msg else {
                    // Stream ended or error — clean disconnect.
                    break;
                };
                match msg {
                    // Every frame costs its sender's address, signed or not:
                    // one upgraded connection is not a licence to flood.
                    Message::Text(_) if ip.is_some_and(|ip| !state.auth.charge_ip(ip)) => {
                        let outcome = crate::auth::GateOutcome::RateLimited;
                        let (status, code, message) = state.auth.disclosure.disclose(&outcome);
                        let _ = send_error(&mut socket, Some(status), code, None, &message).await;
                    }
                    Message::Text(text) => {
                        if let Err(e) = handle_client_frame(
                            &text,
                            &state,
                            &sub_tx,
                            &mut session,
                            conn_id,
                            &mut socket,
                        )
                        .await
                        {
                            tracing::warn!(conn_id, "ws frame error: {e}");
                        }
                        if let Some((code, reason)) = session.close.take() {
                            let _ = socket
                                .send(Message::Close(Some(CloseFrame {
                                    code,
                                    reason: reason.into(),
                                })))
                                .await;
                            break;
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
                    // Stored in the same transaction as the block, so it is
                    // there by the time fanout delivers it. A store error
                    // sends the block without one, which the client sees as
                    // a block it cannot place, not as a forged record.
                    ingest: state
                        .ingest_ctx
                        .store
                        .get_ingest_record(&block.cid)
                        .unwrap_or_else(|e| {
                            tracing::warn!(cid = %block.cid, "ingest record lookup failed: {e}");
                            None
                        }),
                });
                let Ok(json) = serde_json::to_string(&frame) else {
                    continue;
                };
                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
        }
    }

    // Clean up the subscription so the Fanout map doesn't grow without bound.
    if let Some(id) = session.sub_id {
        state.ingest_ctx.fanout.unsubscribe_local(id).await;
        metrics::subscriber_removed();
    }
    if let Some(registration) = session.peer_registration.take() {
        state.peers.unregister(registration);
    }
    metrics::connection_closed();
    tracing::debug!(conn_id, "ws connection closed");
}

/// Mutable facts about one socket: the subscription it holds, the identity
/// it proved, and whether a welcome has been sent.
///
/// The identity is set by a verified Subscribe. Delivery re-checks
/// authorization long after that frame is gone, which is why it lives here
/// rather than per frame. `handshaken` flips once a welcome has been sent.
/// `close` is set by a frame that ends the connection (JEP-0002 rule 7): the
/// connection loop sends the close frame and stops.
#[derive(Default)]
struct ConnState {
    sub_id: Option<u64>,
    did: Option<jig_core::did::Did>,
    handshaken: bool,
    close: Option<(u16, &'static str)>,
    /// The TLS exporter value of this connection; empty over plaintext.
    tls_exporter: Vec<u8>,
    /// Set from the welcome until a dialer that named a `peer_did` proves it.
    awaiting_peer: Option<AwaitingPeer>,
    /// The server DID the dialer proved in the handshake (JEP-0002 rule 12).
    /// Authenticated, not authorized: what it may do is the federation
    /// rules' decision.
    peer: Option<jig_core::did::Did>,
    /// Once the peer is proven: sends to it unprompted
    /// ([`crate::v0_0_2_peer`]), registered in `AppState::peers`.
    peer_sender: Option<crate::v0_0_2_peer::PeerSender>,
    /// The other end of `peer_sender`, for the connection loop to take.
    peer_rx: Option<mpsc::Receiver<Envelope>>,
    peer_registration: Option<crate::v0_0_2_peer::Registration>,
}

/// A handshake that ends with the dialer's [`Frame::PeerProof`].
struct AwaitingPeer {
    peer_did: String,
    hello: String,
    welcome: String,
    deadline: tokio::time::Instant,
}

/// Why a channel subscription was not registered.
enum SubscribeRefusal {
    /// The gate said no; disclosed through the server's policy.
    Gate(crate::auth::GateOutcome),
    /// The store could not answer. Refuses — "could not look you up" is not
    /// "come in" — but is reported as what it is, so the audit log stays true.
    Store(String),
}

/// The channel row a channel scope names, archived or not: by id for
/// [`Scope::ChannelId`], and for [`Scope::Channel`] by slug among the
/// channels this server sequences only, so a slug never reaches a carried
/// channel. An archived channel still has a row and is still gated by it; the
/// live-channel lookup would read it as absent and let anyone in.
fn subscribed_channel(
    state: &AppState,
    scope: &Scope,
) -> Result<Option<jig_pipeline::persist::StoredChannel>, String> {
    let store = &state.ingest_ctx.store;
    match scope {
        Scope::Channel { slug } => store.get_channel_by_slug_including_archived(slug),
        Scope::ChannelId { channel_id } => store.get_channel_by_id_including_archived(channel_id),
        Scope::Federation { .. } => Ok(None),
    }
    .map_err(|e| e.to_string())
}

/// Gate 3 for a channel subscription: the same `authorize_read` decision the
/// REST timeline runs, over the same store facts, looked up by the channel's
/// id. A channel with no row at all is not gated here — see the call site.
fn authorize_subscribe(
    state: &AppState,
    channel: &jig_pipeline::persist::StoredChannel,
    did: &str,
) -> Result<(), SubscribeRefusal> {
    let is_member = state
        .ingest_ctx
        .store
        .is_member_by_id(&channel.id, did)
        .map_err(|e| SubscribeRefusal::Store(e.to_string()))?;
    let is_owner = channel.owner_did == did;
    crate::auth::authorize_read(
        crate::auth::Visibility::parse(&channel.visibility),
        is_member,
        is_owner,
    )
    .map_err(SubscribeRefusal::Gate)
}

// ---- Per-frame dispatch ----------------------------------------------------

async fn handle_client_frame(
    text: &str,
    state: &Arc<AppState>,
    sub_tx: &mpsc::UnboundedSender<(
        jig_pipeline::persist::StoredBlock,
        jig_pipeline::persist::StoredReceipt,
    )>,
    session: &mut ConnState,
    conn_id: u64,
    socket: &mut WebSocket,
) -> Result<(), String> {
    let env: Envelope = match Envelope::parse(text) {
        Ok(e) => e,
        Err(e) => {
            // A hello at a version or suite this server does not speak is an
            // incompatibility, and gets a signed refusal (JEP-0002 rule 3).
            if !session.handshaken
                && let EnvelopeParseError::Gate(gate) = &e
                && let Some(nonce) = unparsed_hello_nonce(text)
            {
                let refusal = if gate.code()
                    == jig_pipeline::envelope::EnvelopeGateError::UNSUPPORTED_VERSION_CODE
                {
                    HelloRefusal::UnsupportedVersion(gate.to_string())
                } else {
                    HelloRefusal::UnsupportedSuite(gate.to_string())
                };
                return refuse_hello(state, socket, session, &refusal, &nonce).await;
            }
            // Best-effort error reply; ignore send failure (client may have gone away).
            // A malformed frame is the WS analogue of REST's 400 Bad Request:
            // the envelope itself never parsed, so no IngestError was ever
            // constructed for classify_ingest_error to classify.
            let code = match &e {
                EnvelopeParseError::Gate(gate) => gate.code(),
                EnvelopeParseError::Malformed(_) => "BAD_JSON",
            };
            let _ = send_error(socket, Some(400), code, None, &e.to_string()).await;
            // Before the welcome nothing but a hello is acceptable. After it,
            // a frame outside the version or suite the client offered breaks
            // its own offer; a frame that is merely malformed is an ordinary
            // error.
            if !session.handshaken || matches!(e, EnvelopeParseError::Gate(_)) {
                session.close = Some((close::PROTOCOL_VIOLATION, code));
            }
            return Err(e.to_string());
        }
    };

    // Hello is taken first. A connection carries one (JEP-0002 rule 6).
    // A failed `if let` would drop `frame`, so this match rebinds it.
    let frame = match env.frame {
        Frame::Hello { .. } if session.handshaken => {
            let _ = send_error(
                socket,
                Some(400),
                jig_pipeline::handshake::PROTOCOL_VIOLATION_CODE,
                None,
                "a connection carries one hello; open a new connection for a new offer",
            )
            .await;
            session.close = Some((close::PROTOCOL_VIOLATION, "second hello"));
            return Ok(());
        }
        Frame::Hello {
            versions,
            suites,
            capabilities,
            nonce,
            peer_did,
        } => {
            return complete_hello(
                state,
                socket,
                session,
                jig_pipeline::handshake::HelloView {
                    versions,
                    suites,
                    capabilities,
                    nonce,
                    peer_did,
                },
                text,
            )
            .await;
        }
        other => other,
    };
    // A dialer that named a peer DID sends its proof next, and nothing else
    // (a class 1 failure otherwise). Nobody else sends one.
    if let Some(awaiting) = session.awaiting_peer.take() {
        let Frame::PeerProof { sig } = &frame else {
            session.close = Some((close::HANDSHAKE_FAILED, "expected peer_proof"));
            return Ok(());
        };
        return match jig_pipeline::handshake::verify_peer_proof(
            &awaiting.peer_did,
            sig,
            &awaiting.hello,
            &awaiting.welcome,
            &session.tls_exporter,
        ) {
            Ok(()) => {
                session.peer = jig_core::did::Did::from_did_jig_string(&awaiting.peer_did).ok();
                if let Some(peer) = session.peer.clone() {
                    let (sender, rx) = crate::v0_0_2_peer::PeerSender::new(peer);
                    session.peer_registration = Some(state.peers.register(sender.clone()));
                    session.peer_sender = Some(sender);
                    session.peer_rx = Some(rx);
                }
                tracing::debug!(conn_id, peer = %awaiting.peer_did, "peer proved its DID");
                Ok(())
            }
            Err(reason) => {
                tracing::info!(conn_id, peer = %awaiting.peer_did, "peer_proof refused: {reason}");
                session.close = Some((close::HANDSHAKE_FAILED, "peer_proof does not verify"));
                Ok(())
            }
        };
    }
    if matches!(frame, Frame::PeerProof { .. }) {
        let _ = send_error(
            socket,
            Some(400),
            jig_pipeline::handshake::PROTOCOL_VIOLATION_CODE,
            None,
            "peer_proof answers a hello that named a peer_did",
        )
        .await;
        session.close = Some((close::PROTOCOL_VIOLATION, "unexpected peer_proof"));
        return Ok(());
    }
    // A parsed frame that is not hello, before the welcome, is a protocol
    // violation: refused, then closed.
    if !session.handshaken {
        let _ = send_error(
            socket,
            Some(400),
            "HANDSHAKE_REQUIRED",
            None,
            "send hello before any other frame",
        )
        .await;
        session.close = Some((close::PROTOCOL_VIOLATION, "HANDSHAKE_REQUIRED"));
        return Ok(());
    }

    match frame {
        // Unreachable: Hello returned above. Kept so this match is exhaustive.
        Frame::Hello { .. } => Ok(()),
        // ------------------------------------------------------------------ Subscribe
        Frame::Subscribe { scope, auth } => {
            // An id has one spelling; any other is no channel id, refused as
            // a malformed scope before anything is looked up or verified.
            if let Scope::ChannelId { channel_id } = &scope
                && !jig_core::canonical_cid::is_canonical_text(channel_id)
            {
                let _ = send_error(
                    socket,
                    Some(400),
                    "BAD_SCOPE",
                    None,
                    &format!("`{channel_id}` is not a channel id in its canonical CID form"),
                )
                .await;
                return Ok(());
            }

            // Gate 1 on the WSS path. The scope's canonical string is what was
            // signed, so a proof for one channel cannot subscribe to another.
            // The federation stream is for configured peers only, so it is
            // authenticated whatever `require_authenticated_reads` says.
            let federation = matches!(scope, Scope::Federation { .. });
            if state.config.auth.require_authenticated_reads || federation {
                let scope_str = scope.canonical_string();

                let outcome = match auth {
                    // A peer that proved its DID in the handshake needs no
                    // second proof per subscription; it is still admitted
                    // and charged like any caller.
                    None => match session.peer.clone() {
                        Some(did) => match state.auth.admit_and_charge(did.as_str()) {
                            Ok(()) => {
                                session.did = Some(did);
                                None
                            }
                            Err(o) => Some(o),
                        },
                        None => Some(crate::auth::GateOutcome::AuthMissing),
                    },
                    Some(a) => {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);
                        let mut guard = state
                            .auth
                            .replay_guard
                            .lock()
                            .expect("replay guard mutex poisoned");
                        match crate::auth::authenticate::authenticate_subscribe(
                            &a, &scope_str, now_ms, &mut guard,
                        ) {
                            // Bind the VERIFIED did, never `a.did` as received —
                            // and only once gate 2 has admitted it, so a refused
                            // caller leaves no identity on the connection.
                            Ok(did) => match state.auth.admit_and_charge(did.as_str()) {
                                Ok(()) => {
                                    session.did = Some(did);
                                    None
                                }
                                Err(o) => Some(o),
                            },
                            Err(o) => Some(o),
                        }
                    }
                };

                let outcome = outcome.or_else(|| {
                    let peer = session
                        .did
                        .as_ref()
                        .is_some_and(|did| state.auth.is_federation_peer(did.as_str()));
                    (federation && !peer)
                        .then_some(crate::auth::GateOutcome::AuthzNotFederationPeer)
                });
                if let Some(outcome) = outcome {
                    tracing::info!(
                        conn_id,
                        audit = %crate::auth::audit_line(&outcome),
                        "ws subscribe refused"
                    );
                    let (status, code, message) = state.auth.disclosure.disclose(&outcome);
                    let _ = send_error(socket, Some(status), code, None, &message).await;
                    return Ok(());
                }
            }

            // Who this subscription belongs to, for the per-delivery check.
            // Only the identity `authenticate_subscribe` RETURNED is bound;
            // `Unchecked` is reserved for a server that does not authenticate
            // reads, and is the only way a subscription escapes filtering.
            let who = match (
                state.config.auth.require_authenticated_reads,
                session.did.as_ref(),
            ) {
                (false, _) => SubscriberIdentity::Unchecked,
                (true, Some(did)) => SubscriberIdentity::Did(did.to_did_jig_string()),
                (true, None) => {
                    // Unreachable by construction (a refused proof returned
                    // above), but a subscription with no DID on a server that
                    // requires one must never be registered.
                    let outcome = crate::auth::GateOutcome::AuthMissing;
                    tracing::info!(
                        conn_id,
                        audit = %crate::auth::audit_line(&outcome),
                        "ws subscribe refused"
                    );
                    let (status, code, message) = state.auth.disclosure.disclose(&outcome);
                    let _ = send_error(socket, Some(status), code, None, &message).await;
                    return Ok(());
                }
            };

            // Gate 3 at subscribe time, for a prompt and explicit refusal. The
            // authoritative check is the one fanout runs on every delivery;
            // this one only spares a caller an open connection that will never
            // carry anything. A channel with no local row is NOT refused here
            // — federated channels routinely have none — and is guarded at
            // delivery once a row exists.
            let channel = match subscribed_channel(state, &scope) {
                Ok(channel) => channel,
                Err(detail) => {
                    // Same word the REST path uses for a failing store.
                    let _ = send_error(socket, Some(500), "PERSIST_ERROR", None, &detail).await;
                    return Ok(());
                }
            };
            if let SubscriberIdentity::Did(did) = &who
                && let Some(channel) = &channel
            {
                match authorize_subscribe(state, channel, did) {
                    Ok(()) => {}
                    Err(SubscribeRefusal::Gate(outcome)) => {
                        tracing::info!(
                            conn_id,
                            audit = %crate::auth::audit_line(&outcome),
                            "ws subscribe refused"
                        );
                        let (status, code, message) = state.auth.disclosure.disclose(&outcome);
                        let _ = send_error(socket, Some(status), code, None, &message).await;
                        return Ok(());
                    }
                    Err(SubscribeRefusal::Store(detail)) => {
                        // Same word the REST path uses for a failing store.
                        let _ = send_error(socket, Some(500), "PERSIST_ERROR", None, &detail).await;
                        return Ok(());
                    }
                }
            }

            let sub_scope = match scope {
                // Fanout keys channels by their id (the channel-create CID).
                // A slug with no local row yet stays as it is until that
                // channel is created (see `Fanout::bind_pending_channel`).
                Scope::Channel { slug } => {
                    SubscriptionScope::Channel(channel.map(|c| c.id).unwrap_or(slug))
                }
                Scope::ChannelId { channel_id } => SubscriptionScope::Channel(channel_id),
                Scope::Federation { block_kinds } => SubscriptionScope::Federation { block_kinds },
            };
            // A connection holds ONE subscription. A re-Subscribe replaces it,
            // and the old one must actually go: left in the fanout map it
            // would keep delivering its old scope under its old identity for
            // the life of the process, long after this socket forgot it.
            if let Some(old) = session.sub_id.take() {
                state.ingest_ctx.fanout.unsubscribe_local(old).await;
            } else {
                // The gauge counts connections holding a subscription; a
                // replacement is not a second unit.
                metrics::subscriber_added();
            }
            let id = state
                .ingest_ctx
                .fanout
                .subscribe_local(sub_scope, who, sub_tx.clone())
                .await;
            session.sub_id = Some(id);
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
                    // Malformed wire content, never reaches ingest — the WS
                    // analogue of a REST 400.
                    let _ = send_error(
                        socket,
                        Some(400),
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
                    let _ = send_error(
                        socket,
                        Some(400),
                        "BAD_SIG_B64",
                        None,
                        "sig_b64 is not valid base64",
                    )
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
                        // Malformed wire content, never reaches ingest —
                        // the WS analogue of a REST 400 (kin to
                        // IngestError::BundleMalformed, which classify_ingest_error
                        // also maps to 400, but that variant is never
                        // constructed on this pre-ingest path).
                        let _ = send_error(
                            socket,
                            Some(400),
                            "BAD_BUNDLE",
                            None,
                            &format!("canonical-bytes tuple parse failed: {e}"),
                        )
                        .await;
                        return Ok(());
                    }
                };

            // 3. Post it: ingest here, or relayed to the channel's owner when
            //    this server carries the channel (JEP-0005 rule 15). Reply Ack
            //    or a typed Error frame.
            match crate::v0_0_2_relay::post(
                state,
                &manifest_bytes,
                &code_bytes,
                sig,
                conn_id,
                &format!("ws:{conn_id}"),
            )
            .await
            {
                Ok(block_cid) => {
                    metrics::block_ingested(channel_label(state, &manifest_bytes).as_deref());
                    let ack = Envelope::new(Frame::Ack { block_cid });
                    let Ok(json) = serde_json::to_string(&ack) else {
                        return Ok(());
                    };
                    let _ = socket.send(Message::Text(json.into())).await;
                }
                // One classifier for every surface (`Refusal::of`, over
                // `v0_0_2_ingest_error.rs`): two HTTP surfaces once drifted
                // apart on the same variant; a hand-copied table here was the
                // third copy.
                Err(refusal) => {
                    let _ = send_error(
                        socket,
                        Some(refusal.status.as_u16()),
                        &refusal.code,
                        None,
                        &refusal.message,
                    )
                    .await;
                }
            }
            Ok(())
        }

        // ------------------------------------------------------------------ Peer
        // Only between proven peers; F's federation contract handles them.
        Frame::Peer { kind, body } => {
            let Some(sender) = session.peer_sender.clone() else {
                let _ = send_error(
                    socket,
                    Some(400),
                    jig_pipeline::handshake::PROTOCOL_VIOLATION_CODE,
                    None,
                    "peer frames are for a server that proved its DID in the handshake",
                )
                .await;
                session.close = Some((close::PROTOCOL_VIOLATION, "peer frame from no peer"));
                return Ok(());
            };
            if let Err(reason) =
                crate::v0_0_2_peer::dispatch(state.peer_frame_handler(), &sender, &kind, &body)
            {
                tracing::info!(conn_id, code = reason.code, reason = %reason.reason, kind, "peer connection closed by its handler");
                session.close = Some((reason.code, "closed by the federation contract"));
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
        Frame::Ack { .. }
        | Frame::Block { .. }
        | Frame::Error { .. }
        | Frame::Welcome { .. }
        | Frame::Refusal { .. }
        | Frame::PeerProof { .. } => Ok(()),
    }
}

/// Capabilities the welcome may honestly claim. Block kinds and execution come
/// from the running server. Federation is on because this process accepts
/// peer relays on the same socket; MLS is not a capability and is not listed.
pub(crate) fn handshake_capabilities(state: &AppState) -> jig_pipeline::handshake::Capabilities {
    jig_pipeline::handshake::Capabilities {
        block_kinds: state.config.server.allowed_block_kinds.clone(),
        execution: state.ingest_ctx.executor.is_some(),
        federation: true,
        // The bound ingest enforces, so the signed claim is the enforced one.
        max_future_skew_ms: state.ingest_ctx.hlc_clock.max_future_skew_ms(),
    }
}

/// How long a welcome's admission ask holds. A client reads it just before
/// it solves; this covers the default `max_solve_secs` (10 s) many times over.
pub(crate) const ADMIT_OFFER_SECS: i64 = 120;

/// The admission work the welcome asks of a DID this server has not admitted
/// (JEP-0008 rule 15), from the configured bit count. `None` when admission
/// asks no work.
pub(crate) fn admit_offer(
    pow_bits: Option<u8>,
    now: i64,
) -> Option<jig_pipeline::handshake::PowOffer> {
    pow_bits.map(|bits| jig_pipeline::handshake::PowOffer {
        alg: jig_core::pow::Alg::Blake3.id(),
        effort: jig_core::admission_pow::effort_for_bits(bits).get(),
        salt_id: jig_core::pow::EMPTY_SALT_ID,
        expires_at: now.saturating_add(ADMIT_OFFER_SECS),
    })
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Sign a welcome, or refuse the hello and close.
async fn complete_hello(
    state: &AppState,
    socket: &mut WebSocket,
    session: &mut ConnState,
    hello: jig_pipeline::handshake::HelloView,
    hello_text: &str,
) -> Result<(), String> {
    if let Some(peer_did) = &hello.peer_did
        && jig_core::did::Did::from_did_jig_string(peer_did).is_err()
    {
        let refusal = HelloRefusal::Malformed("peer_did is not a did:jig".to_string());
        let _ = send_error(socket, Some(400), refusal.code(), None, refusal.message()).await;
        session.close = Some((close::PROTOCOL_VIOLATION, "malformed hello"));
        return Ok(());
    }
    let offer = jig_pipeline::handshake::ServerOffer {
        capabilities: handshake_capabilities(state),
        tls_exporter: session.tls_exporter.clone(),
        manifest: state
            .manifest
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone(),
        key_link: state.key_link.clone(),
        admit: admit_offer(state.auth.pow_bits(), unix_now()),
        prior_key_links: state.prior_key_links.clone(),
    };
    match jig_pipeline::handshake::negotiate(&hello, &offer) {
        Ok(statement) => {
            let welcome = jig_pipeline::handshake::seal(&state.ingest_ctx.server_key, statement);
            let json = serde_json::to_string(&welcome).map_err(|err| err.to_string())?;
            socket
                .send(Message::Text(json.clone().into()))
                .await
                .map_err(|err| err.to_string())?;
            session.handshaken = true;
            if let Some(peer_did) = hello.peer_did {
                session.awaiting_peer = Some(AwaitingPeer {
                    peer_did,
                    hello: hello_text.to_string(),
                    welcome: json,
                    deadline: tokio::time::Instant::now() + jig_pipeline::handshake::WELCOME_WAIT,
                });
            }
            Ok(())
        }
        Err(refusal @ HelloRefusal::Malformed(_)) => {
            let _ = send_error(socket, Some(400), refusal.code(), None, refusal.message()).await;
            session.close = Some((close::PROTOCOL_VIOLATION, "malformed hello"));
            Ok(())
        }
        Err(refusal) => refuse_hello(state, socket, session, &refusal, &hello.nonce).await,
    }
}

/// Answer an incompatible hello with a signed refusal, then close
/// ([`close::INCOMPATIBLE`]).
async fn refuse_hello(
    state: &AppState,
    socket: &mut WebSocket,
    session: &mut ConnState,
    refusal: &HelloRefusal,
    nonce: &str,
) -> Result<(), String> {
    session.close = Some((close::INCOMPATIBLE, refusal.code()));
    let frame = jig_pipeline::handshake::seal_refusal(&state.ingest_ctx.server_key, refusal, nonce);
    let json = serde_json::to_string(&frame).map_err(|err| err.to_string())?;
    socket
        .send(Message::Text(json.into()))
        .await
        .map_err(|err| err.to_string())
}

/// The nonce of a hello that did not parse at this version or suite. The
/// refusal echoes it, so the client can tell it answers its own hello.
fn unparsed_hello_nonce(text: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Probe {
        op: String,
        nonce: String,
    }
    let probe: Probe = serde_json::from_str(text).ok()?;
    (probe.op == "hello" && !probe.nonce.is_empty()).then_some(probe.nonce)
}

// ---- Helpers ---------------------------------------------------------------

/// Read the channel slug out of manifest bytes for the per-channel metric,
/// without paying for a full `BlockManifest` deserialization.
///
/// Uses the same kind-keyed rule as `jig_pipeline::ingest::channel_slug_of`,
/// so the metric counts the channel the block actually landed in.
/// Metrics-only: nothing downstream reads this value.
fn channel_slug_peek(manifest_bytes: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct KindAndMetadata {
        #[serde(default)]
        kind: Option<jig_core::BlockKind>,
        #[serde(default)]
        metadata: serde_json::Map<String, serde_json::Value>,
    }

    let peeked: KindAndMetadata = serde_json::from_slice(manifest_bytes).ok()?;
    let key = jig_pipeline::ingest::channel_metadata_key(peeked.kind?);
    peeked
        .metadata
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// The label the per-channel metric carries for a just-ingested block.
///
/// `/metrics` runs no gate — scrapers cannot sign — so it must not become the
/// one endpoint that names restricted channels to whoever asks. Open
/// channels are labelled by slug; everything else (restricted, unknown, or a
/// store that would not answer) shares one `(restricted)` bucket. Totals
/// stay exact; only the attribution is withheld.
///
/// On a server whose admission policy turns anyone away, "open" means open
/// to the admitted, and even open slugs are withheld: a banned or unknown
/// caller can still scrape `/metrics`.
fn channel_label(state: &AppState, manifest_bytes: &[u8]) -> Option<String> {
    let slug = channel_slug_peek(manifest_bytes)?;
    if state.auth.admission.refuses_anyone() {
        return Some(RESTRICTED_LABEL.to_string());
    }
    let open = matches!(
        state
            .ingest_ctx
            .store
            .get_channel_by_slug_including_archived(&slug),
        Ok(Some(row)) if jig_pipeline::visibility::is_open(&row.visibility)
    );
    Some(if open {
        slug
    } else {
        RESTRICTED_LABEL.to_string()
    })
}

/// The shared metrics label for channels whose slug is not disclosed.
pub const RESTRICTED_LABEL: &str = "(restricted)";

async fn send_error(
    socket: &mut WebSocket,
    status: Option<u16>,
    code: &str,
    ref_cid: Option<String>,
    message: &str,
) -> Result<(), axum::Error> {
    let frame = Envelope::new(Frame::Error {
        status,
        code: code.to_string(),
        ref_cid,
        message: message.to_string(),
    });
    let json = serde_json::to_string(&frame).map_err(axum::Error::new)?;
    socket.send(Message::Text(json.into())).await
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
        start_test_server_with(AppState::for_test().unwrap()).await
    }

    async fn start_test_server_with(state: AppState) -> (Arc<AppState>, String) {
        let state = Arc::new(state);
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

    /// Connect and finish the handshake. Tests that are about a later frame
    /// start here; tests about the handshake itself do not.
    async fn established(
        url: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let (mut ws, _) = connect_async(url).await.unwrap();
        let (hello, pending) =
            jig_pipeline::handshake::begin(&jig_pipeline::handshake::ClientOffer::default());
        ws.send(TMessage::Text(
            serde_json::to_string(&hello).unwrap().into(),
        ))
        .await
        .unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("welcome timeout")
            .expect("stream closed")
            .expect("ws error");
        let TMessage::Text(text) = msg else {
            panic!("expected a text welcome, got {msg:?}");
        };
        match pending.interpret(&text) {
            jig_pipeline::handshake::HandshakeResult::Established(_) => ws,
            other => panic!("handshake failed: {other:?}"),
        }
    }

    /// Build a signed `Frame::Subscribe`, as a real client does.
    ///
    /// Subscriptions require a proof of possession; a raw frame is refused.
    /// Tests about DELIVERY still need a valid one, so the ceremony lives here
    /// rather than in each test.
    fn signed_subscribe_frame(identity: &jig_client::Identity, scope: Scope) -> Envelope {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);

        let hlc_wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let nonce = format!("t-{hlc_wall_ms}-{}", SEQ.fetch_add(1, Ordering::Relaxed));

        let hash = jig_core::request_auth::canonical_request_hash(
            "SUBSCRIBE",
            &scope.canonical_string(),
            b"",
            hlc_wall_ms,
            0,
            &nonce,
        );

        Envelope::new(Frame::Subscribe {
            auth: Some(jig_pipeline::envelope::SubscribeAuth {
                did: identity.did_string(),
                hlc_wall_ms,
                hlc_logical: 0,
                nonce,
                sig_b64: base64::engine::general_purpose::STANDARD
                    .encode(identity.sign(hash.as_bytes()).to_bytes()),
            }),
            scope,
        })
    }

    fn test_identity() -> jig_client::Identity {
        let dir = tempdir().unwrap();
        let path = dir.keep();
        jig_client::Identity::generate_for_tests(&path)
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

    // --- submit → Ack -------------------------------------------------------

    #[tokio::test]
    async fn ws_submit_returns_ack() {
        let (state, url) = start_test_server().await;
        seed_channel(&state, "#hello");
        let mut ws = established(&url).await;

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);

        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });
        ws.send(TMessage::Text(
            serde_json::to_string(&submit).unwrap().into(),
        ))
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
        let mut ws = established(&url).await;

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#hello", "hi", hlc);

        let bad_sig_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: bad_sig_b64,
        });
        ws.send(TMessage::Text(
            serde_json::to_string(&submit).unwrap().into(),
        ))
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
            Frame::Error { status, code, .. } => {
                assert_eq!(code, "INVALID_SIG");
                // Pins the number actually on the wire. Both Frame::Error
                // consumers currently drop `status`, so without this nothing in
                // the system would notice a wrong value.
                assert_eq!(status, Some(401));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ws_submit_to_unknown_channel_returns_an_actionable_error_frame() {
        // The whole point of the ingest guard is user-visible feedback: a
        // mistyped slug must come back as prose naming the slug, not an Ack
        // carrying a CID for a block nobody will ever read.
        let (_state, url) = start_test_server().await; // no channels seeded
        let mut ws = established(&url).await;

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#gigeu", "hi", hlc);
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });
        ws.send(TMessage::Text(
            serde_json::to_string(&submit).unwrap().into(),
        ))
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
            Frame::Error {
                status,
                code,
                message,
                ..
            } => {
                assert_eq!(code, "UNKNOWN_CHANNEL");
                assert_eq!(status, Some(404));
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

    /// Read one frame, or fail loudly rather than hanging.
    async fn next_frame(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Envelope {
        let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("timeout waiting for reply")
            .expect("stream closed")
            .expect("ws error");
        let TMessage::Text(text) = msg else {
            panic!("expected text, got {msg:?}");
        };
        serde_json::from_str(&text).expect("frame parses")
    }

    /// An unsigned subscribe must be refused. Before this, `Frame::Subscribe`
    /// registered any scope for any connection with no identity involved.
    #[tokio::test]
    async fn ws_unsigned_subscribe_is_refused() {
        let (_state, url) = start_test_server().await;
        let mut ws = established(&url).await;

        let sub = Envelope::new(Frame::Subscribe {
            scope: Scope::Federation {
                block_kinds: vec![],
            },
            auth: None,
        });
        ws.send(TMessage::Text(serde_json::to_string(&sub).unwrap().into()))
            .await
            .unwrap();

        match next_frame(&mut ws).await.frame {
            Frame::Error { status, code, .. } => {
                assert_eq!(code, "AUTH_REQUIRED");
                assert_eq!(status, Some(401));
            }
            other => panic!("expected an error frame, got {other:?}"),
        }
    }

    /// THE test this task exists for: a client may not subscribe as someone
    /// else. The signature here is valid — it verifies against the ATTACKER's
    /// key — but the frame claims the victim's DID.
    ///
    /// If the server bound the claimed DID rather than the verified one, this
    /// would succeed and phase 3 would then authorize deliveries against an
    /// identity the caller never proved.
    #[tokio::test]
    async fn ws_subscribe_claiming_another_did_is_refused() {
        let (_state, url) = start_test_server().await;
        let mut ws = established(&url).await;

        let attacker = test_identity();
        let victim = test_identity();

        let scope = Scope::Federation {
            block_kinds: vec![],
        };
        let mut frame = signed_subscribe_frame(&attacker, scope);
        if let Frame::Subscribe { auth: Some(a), .. } = &mut frame.frame {
            a.did = victim.did_string();
        } else {
            panic!("expected a signed subscribe");
        }

        ws.send(TMessage::Text(
            serde_json::to_string(&frame).unwrap().into(),
        ))
        .await
        .unwrap();

        match next_frame(&mut ws).await.frame {
            Frame::Error { status, code, .. } => {
                assert_eq!(
                    code, "INVALID_SIG",
                    "a forged subscriber DID must be refused"
                );
                assert_eq!(status, Some(401));
            }
            other => panic!("expected an error frame, got {other:?}"),
        }
    }

    /// The federation stream is for listed peers. A stranger with a valid
    /// proof is refused, and on a server that does not authenticate reads an
    /// unsigned federation subscribe is still refused.
    #[tokio::test]
    async fn only_a_listed_peer_may_subscribe_to_the_federation_stream() {
        let federation = || Scope::Federation {
            block_kinds: vec![],
        };
        let (state, url) = start_test_server().await;

        let stranger = test_identity();
        let mut ws = established(&url).await;
        let sub = signed_subscribe_frame(&stranger, federation());
        ws.send(TMessage::Text(serde_json::to_string(&sub).unwrap().into()))
            .await
            .unwrap();
        match next_frame(&mut ws).await.frame {
            Frame::Error { status, code, .. } => {
                assert_eq!((status, code.as_str()), (Some(403), "NOT_A_PEER"));
            }
            other => panic!("expected NOT_A_PEER, got {other:?}"),
        }

        // Listed, the same caller's next subscribe registers and delivers.
        state
            .auth
            .trust_federation_peer(&stranger.did_string())
            .unwrap();
        seed_channel(&state, "#hello");
        let sub = signed_subscribe_frame(&stranger, federation());
        ws.send(TMessage::Text(serde_json::to_string(&sub).unwrap().into()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let author = test_identity();
        let block = build_text_render(&author, "#hello", "hi", test_hlc(&author));
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });
        ws.send(TMessage::Text(
            serde_json::to_string(&submit).unwrap().into(),
        ))
        .await
        .unwrap();
        let mut got_block = false;
        for _ in 0..2 {
            match next_frame(&mut ws).await.frame {
                Frame::Block { ingest, .. } => {
                    got_block = true;
                    let record = ingest.expect("a live block carries its record");
                    record
                        .verify(&state.server_did.to_did_jig_string())
                        .unwrap();
                    assert!(record.is_genesis(), "the first block of the seeded channel");
                }
                Frame::Ack { .. } => {}
                other => panic!("unexpected frame {other:?}"),
            }
        }
        assert!(
            got_block,
            "a listed peer's federation subscription delivers"
        );

        let mut open_reads = jig_config::v0_0_2_server::JigServerConfig::default();
        open_reads.auth.require_authenticated_reads = false;
        let (_state, url) =
            start_test_server_with(AppState::for_test_with_config(open_reads).unwrap()).await;
        let mut ws = established(&url).await;
        let unsigned = Envelope::new(Frame::Subscribe {
            scope: federation(),
            auth: None,
        });
        ws.send(TMessage::Text(
            serde_json::to_string(&unsigned).unwrap().into(),
        ))
        .await
        .unwrap();
        match next_frame(&mut ws).await.frame {
            Frame::Error { code, .. } => assert_eq!(code, "AUTH_REQUIRED"),
            other => panic!("expected AUTH_REQUIRED, got {other:?}"),
        }
    }

    /// A captured Subscribe frame must not be reusable, exactly as for REST.
    #[tokio::test]
    async fn ws_replayed_subscribe_is_refused() {
        let (_state, url) = start_test_server().await;
        let subscriber = test_identity();
        // A channel with no local row: subscribing to it is not refused.
        let frame = signed_subscribe_frame(
            &subscriber,
            Scope::Channel {
                slug: "#anywhere".to_string(),
            },
        );
        let text = serde_json::to_string(&frame).unwrap();

        // First use succeeds silently (a successful subscribe emits no frame),
        // so prove it took by sending a second and expecting REPLAYED.
        let mut first = established(&url).await;
        first
            .send(TMessage::Text(text.clone().into()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut second = established(&url).await;
        second.send(TMessage::Text(text.into())).await.unwrap();

        match next_frame(&mut second).await.frame {
            Frame::Error { status, code, .. } => {
                assert_eq!(
                    code, "REPLAYED",
                    "the same signed frame must not work twice"
                );
                assert_eq!(status, Some(401));
            }
            other => panic!("expected an error frame, got {other:?}"),
        }
    }

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
        let mut ws = established(&url).await;

        // 1. Subscribe federation-scope (no kind filter = all kinds), signed —
        //    the server refuses an unsigned subscribe — as a listed peer.
        let subscriber = test_identity();
        state
            .auth
            .trust_federation_peer(&subscriber.did_string())
            .unwrap();
        let sub = signed_subscribe_frame(
            &subscriber,
            Scope::Federation {
                block_kinds: vec![],
            },
        );
        ws.send(TMessage::Text(serde_json::to_string(&sub).unwrap().into()))
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
        ws.send(TMessage::Text(
            serde_json::to_string(&submit).unwrap().into(),
        ))
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
        let text = metrics::render(
            2,
            1,
            4,
            &channels,
            &[("local", 5), ("federation", 6), ("bridge", 7)],
        );

        assert!(text.contains("# TYPE jig_ws_connections_active gauge"));
        assert!(text.contains("# TYPE jig_ws_blocks_ingested_total counter"));
        assert!(text.contains("\njig_ws_connections_active 2\n"));
        assert!(text.contains("\njig_ws_subscribers_active 1\n"));
        assert!(text.contains("\njig_ws_blocks_ingested_total 4\n"));
        assert!(text.contains("jig_ws_channel_messages_total{channel=\"#hello\"} 3"));
        assert!(text.contains("# TYPE jig_blocks_ingested_total counter"));
        assert!(text.contains("\njig_blocks_ingested_total{source=\"local\"} 5\n"));
        assert!(text.contains("\njig_blocks_ingested_total{source=\"federation\"} 6\n"));
        assert!(text.contains("\njig_blocks_ingested_total{source=\"bridge\"} 7\n"));
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
            "kind": "channel-create",
            "metadata": { "slug": "#other", "channel": "#decoy" }
        }))
        .unwrap();
        assert_eq!(channel_slug_peek(&created).as_deref(), Some("#other"));

        // And a content block does not get to name a channel under `slug`:
        // the key is chosen by kind, exactly as ingest chooses it.
        let decoy = serde_json::to_vec(&serde_json::json!({
            "kind": "text-render",
            "metadata": { "slug": "#secret", "body": "hi" }
        }))
        .unwrap();
        assert_eq!(channel_slug_peek(&decoy).as_deref(), None);

        assert_eq!(channel_slug_peek(b"not json").as_deref(), None);
    }

    /// `/metrics` is ungated, so a restricted channel must not appear in it
    /// by name. Open channels keep their own label.
    #[tokio::test]
    async fn restricted_channels_share_one_metrics_label() {
        let state = AppState::for_test().unwrap();
        for (slug, visibility) in [("#open", "open"), ("#private", "restricted")] {
            state
                .ingest_ctx
                .store
                .upsert_channel(&jig_pipeline::persist::StoredChannel {
                    id: jig_pipeline::ingest_record::label_cid(slug),
                    slug: slug.to_string(),
                    visibility: visibility.to_string(),
                    created_at: 0,
                    owner_did: "did:jig:zSeedOwner".to_string(),
                    suite: "none".to_string(),
                    sequencer_did: String::new(),
                    co_owners: Vec::new(),
                })
                .unwrap();
        }
        let manifest = |slug: &str| {
            serde_json::to_vec(&serde_json::json!({
                "kind": "text-render",
                "metadata": { "channel": slug, "body": "hi" }
            }))
            .unwrap()
        };
        assert_eq!(
            channel_label(&state, &manifest("#open")).as_deref(),
            Some("#open")
        );
        assert_eq!(
            channel_label(&state, &manifest("#private")).as_deref(),
            Some(RESTRICTED_LABEL)
        );
        assert_eq!(
            channel_label(&state, &manifest("#nowhere")).as_deref(),
            Some(RESTRICTED_LABEL),
            "an unknown channel is not disclosed either"
        );
    }

    /// A server that refuses anyone at admission withholds even open slugs
    /// from the ungated metrics endpoint.
    #[tokio::test]
    async fn a_refusing_server_names_no_channel_in_metrics() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.auth.admission.unknown_dids = jig_config::v0_0_2_server::UnknownDidsPolicy::Refuse;
        let state = AppState::for_test_with_config(config).unwrap();
        state
            .ingest_ctx
            .store
            .upsert_channel(&jig_pipeline::persist::StoredChannel {
                id: jig_pipeline::ingest_record::label_cid("#open"),
                slug: "#open".to_string(),
                visibility: "open".to_string(),
                created_at: 0,
                owner_did: "did:jig:zSeedOwner".to_string(),
                suite: "none".to_string(),
                sequencer_did: String::new(),
                co_owners: Vec::new(),
            })
            .unwrap();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "kind": "text-render",
            "metadata": { "channel": "#open", "body": "hi" }
        }))
        .unwrap();
        assert_eq!(
            channel_label(&state, &manifest).as_deref(),
            Some(RESTRICTED_LABEL)
        );
    }

    #[tokio::test]
    async fn ws_submit_increments_block_and_channel_counters() {
        let before = metrics::snapshot();

        let (state, url) = start_test_server().await;
        seed_channel(&state, "#metrics-probe");
        let mut ws = established(&url).await;

        let id = test_identity();
        let hlc = test_hlc(&id);
        let block = build_text_render(&id, "#metrics-probe", "hi", hlc);
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });
        ws.send(TMessage::Text(
            serde_json::to_string(&submit).unwrap().into(),
        ))
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

        ws.send(TMessage::Text("not valid json at all".into()))
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_millis(500), ws.next()).await;
        if let Ok(Some(Ok(TMessage::Text(text)))) = result {
            let env: Envelope = serde_json::from_str(&text).unwrap();
            // other frames are acceptable (e.g. if handler re-used the connection)
            if let Frame::Error { code, .. } = env.frame {
                assert_eq!(code, "BAD_JSON");
            }
        }
        // Timeout is acceptable — primary assertion is the server didn't panic.
    }

    /// An upgraded connection is still charged to its address, frame by frame:
    /// past the burst a frame is refused, not processed.
    #[tokio::test]
    async fn frames_past_the_address_rate_are_refused() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.auth.rate_limit.per_ip_burst = 3;
        config.auth.rate_limit.per_ip_per_second = 1;
        let state = Arc::new(AppState::for_test_with_config(config).unwrap());
        let app = Router::new()
            .route("/api/v1/ws", get(ws_handler))
            .with_state(state)
            .into_make_service_with_connect_info::<SocketAddr>();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/api/v1/ws", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // The hello is the first of three. 1/s is the slowest refill there
        // is, so a slow runner may see one between frames: count frames up to
        // the first refusal rather than assume exactly two more get in.
        let start = std::time::Instant::now();
        let mut ws = established(&url).await;
        let mut processed = 0u32;
        loop {
            ws.send(TMessage::Text("not valid json".into()))
                .await
                .unwrap();
            match next_frame(&mut ws).await.frame {
                Frame::Error { status, code, .. } if code == "RATE_LIMITED" => {
                    assert_eq!(status, Some(429));
                    break;
                }
                Frame::Error { .. } => processed += 1,
                other => panic!("expected an error frame, got {other:?}"),
            }
            assert!(processed <= 64, "the address was never limited");
        }
        let refilled = start.elapsed().as_secs() as u32 + 1;
        assert!(
            (2..=2 + refilled).contains(&processed),
            "{processed} frames after the hello got in over {:?}",
            start.elapsed()
        );
    }

    /// A well-formed frame at a version or suite this server does not speak,
    /// sent before any hello, is refused with a code that says so and then
    /// closed as a protocol violation: never processed, never reported as
    /// garbage.
    #[tokio::test]
    async fn ws_refuses_unsupported_version_and_suite_by_code() {
        let (_state, url) = start_test_server().await;
        for (frame, expected) in [
            (
                r##"{"v":2,"op":"subscribe","scope":{"kind":"channel","slug":"#hello"}}"##,
                "UNSUPPORTED_VERSION",
            ),
            (
                r##"{"v":1,"suite":"mls","op":"subscribe","scope":{"kind":"channel","slug":"#hello"}}"##,
                "UNSUPPORTED_SUITE",
            ),
            (
                r##"{"v":1,"suite":"rot13","op":"subscribe","scope":{"kind":"channel","slug":"#hello"}}"##,
                "UNSUPPORTED_SUITE",
            ),
        ] {
            let (mut ws, _) = connect_async(&url).await.unwrap();
            ws.send(TMessage::Text(frame.into())).await.unwrap();
            match next_frame(&mut ws).await.frame {
                Frame::Error { status, code, .. } => {
                    assert_eq!(code, expected, "frame: {frame}");
                    assert_eq!(status, Some(400));
                }
                other => panic!("expected Error for {frame}, got {other:?}"),
            }
            assert_eq!(
                close_code(&mut ws).await,
                Some(close::PROTOCOL_VIOLATION),
                "frame: {frame}"
            );
        }
    }

    /// A dialing server that proves its DID in the handshake (JEP-0002 rule
    /// 12) is that DID on the connection: a listed peer subscribes to the
    /// federation stream without a second proof.
    #[tokio::test]
    async fn a_peer_that_proves_its_did_needs_no_second_proof() {
        let (state, url) = start_test_server().await;
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let peer_did =
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();
        state.auth.trust_federation_peer(&peer_did).unwrap();
        seed_channel(&state, "#hello");

        let (mut ws, _) = connect_async(&url).await.unwrap();
        crate::v0_0_2_federation::complete_peer_handshake(
            &mut ws,
            &state.server_did.to_did_jig_string(),
            &[],
            &key,
        )
        .await
        .unwrap();
        let sub = Envelope::new(Frame::Subscribe {
            scope: Scope::Federation {
                block_kinds: vec![],
            },
            auth: None,
        });
        ws.send(TMessage::Text(serde_json::to_string(&sub).unwrap().into()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let author = test_identity();
        let block = build_text_render(&author, "#hello", "hi", test_hlc(&author));
        let submit = Envelope::new(Frame::Submit {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
        });
        ws.send(TMessage::Text(
            serde_json::to_string(&submit).unwrap().into(),
        ))
        .await
        .unwrap();
        let mut got_block = false;
        for _ in 0..2 {
            match next_frame(&mut ws).await.frame {
                Frame::Block { .. } => got_block = true,
                Frame::Ack { .. } => {}
                other => panic!("unexpected frame {other:?}"),
            }
        }
        assert!(got_block, "the proven peer's subscription delivers");
    }

    /// A hello that names a peer DID ends with that DID's proof over this
    /// connection's transcript, or the connection (class 1, 4001).
    #[tokio::test]
    async fn a_dialer_that_does_not_prove_its_did_is_closed() {
        let (state, url) = start_test_server().await;
        let key = jig_core::crypto::ed25519::generate_signing_key();
        let peer_did =
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();
        state.auth.trust_federation_peer(&peer_did).unwrap();

        // Hello and welcome as the server saw them, for the dialer to sign.
        async fn dial(
            url: &str,
            peer_did: Option<&str>,
        ) -> (
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            String,
            String,
        ) {
            let (mut ws, _) = connect_async(url).await.unwrap();
            let (hello, _pending) =
                jig_pipeline::handshake::begin(&jig_pipeline::handshake::ClientOffer {
                    peer_did: peer_did.map(str::to_string),
                    ..Default::default()
                });
            let hello = serde_json::to_string(&hello).unwrap();
            ws.send(TMessage::Text(hello.clone().into())).await.unwrap();
            let Some(Ok(TMessage::Text(welcome))) = ws.next().await else {
                panic!("expected a welcome");
            };
            (ws, hello, welcome.to_string())
        }
        let send = |env: Envelope| TMessage::Text(serde_json::to_string(&env).unwrap().into());

        // Anything but the proof first.
        let (mut ws, _, _) = dial(&url, Some(&peer_did)).await;
        let sub = Envelope::new(Frame::Subscribe {
            scope: Scope::Federation {
                block_kinds: vec![],
            },
            auth: None,
        });
        ws.send(send(sub)).await.unwrap();
        assert_eq!(close_code(&mut ws).await, Some(close::HANDSHAKE_FAILED));

        // A proof by another key, or over another transcript.
        let stranger = jig_core::crypto::ed25519::generate_signing_key();
        let (mut ws, hello, welcome) = dial(&url, Some(&peer_did)).await;
        let proof = jig_pipeline::handshake::peer_proof(&stranger, &hello, &welcome, &[]);
        ws.send(send(proof)).await.unwrap();
        assert_eq!(close_code(&mut ws).await, Some(close::HANDSHAKE_FAILED));
        let (mut ws, hello, _) = dial(&url, Some(&peer_did)).await;
        let (_, _, other_welcome) = dial(&url, Some(&peer_did)).await;
        let proof = jig_pipeline::handshake::peer_proof(&key, &hello, &other_welcome, &[]);
        ws.send(send(proof)).await.unwrap();
        assert_eq!(close_code(&mut ws).await, Some(close::HANDSHAKE_FAILED));

        // A proof nobody asked for.
        let (mut ws, hello, welcome) = dial(&url, None).await;
        let proof = jig_pipeline::handshake::peer_proof(&key, &hello, &welcome, &[]);
        ws.send(send(proof)).await.unwrap();
        let _error = next_frame(&mut ws).await;
        assert_eq!(close_code(&mut ws).await, Some(close::PROTOCOL_VIOLATION));
    }

    /// Frames between proven peers reach the registered handler with the DID
    /// the handshake proved; it answers on the same connection, the server
    /// pushes on it unprompted, and a handler's refusal closes it. Nobody
    /// unproven gets that far.
    #[tokio::test]
    async fn peer_frames_flow_both_ways_between_proven_peers_only() {
        struct Echo(std::sync::Mutex<Vec<(String, String, Vec<u8>)>>);
        impl crate::v0_0_2_peer::PeerFrames for Echo {
            fn on_peer_frame(
                &self,
                peer: &jig_core::did::Did,
                kind: &str,
                body: &[u8],
                out: &crate::v0_0_2_peer::PeerSender,
            ) -> Result<(), crate::v0_0_2_peer::CloseReason> {
                self.0.lock().unwrap().push((
                    peer.to_did_jig_string(),
                    kind.to_string(),
                    body.to_vec(),
                ));
                if kind == "contract-end" {
                    return Err(crate::v0_0_2_peer::CloseReason {
                        code: 4010,
                        reason: "ended".into(),
                    });
                }
                out.send("contract-answer", body.to_vec()).unwrap();
                Ok(())
            }
        }
        let (state, url) = start_test_server().await;
        let echo = Arc::new(Echo(Default::default()));
        assert!(state.set_peer_frames(echo.clone()));

        let key = jig_core::crypto::ed25519::generate_signing_key();
        let peer_did =
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();
        let (mut ws, _) = connect_async(&url).await.unwrap();
        crate::v0_0_2_federation::complete_peer_handshake(
            &mut ws,
            &state.server_did.to_did_jig_string(),
            &[],
            &key,
        )
        .await
        .unwrap();
        let peer_frame = |kind: &str, body: &[u8]| {
            TMessage::Text(
                serde_json::to_string(&Envelope::new(Frame::Peer {
                    kind: kind.into(),
                    body: body.to_vec(),
                }))
                .unwrap()
                .into(),
            )
        };

        ws.send(peer_frame("contract-offer", b"offer"))
            .await
            .unwrap();
        match next_frame(&mut ws).await.frame {
            Frame::Peer { kind, body } => {
                assert_eq!(
                    (kind.as_str(), body.as_slice()),
                    ("contract-answer", &b"offer"[..])
                );
            }
            other => panic!("expected the handler's answer, got {other:?}"),
        }
        assert_eq!(
            echo.0.lock().unwrap()[0],
            (
                peer_did.clone(),
                "contract-offer".to_string(),
                b"offer".to_vec()
            ),
            "the handler sees the proven DID"
        );

        // Unprompted, through the registry, whichever side dialed.
        let peer = jig_core::did::Did::from_did_jig_string(&peer_did).unwrap();
        state
            .peers
            .sender_for(&peer)
            .expect("the proven peer is live")
            .send("contract-offer", b"pushed".to_vec())
            .unwrap();
        match next_frame(&mut ws).await.frame {
            Frame::Peer { body, .. } => assert_eq!(body, b"pushed"),
            other => panic!("expected the pushed frame, got {other:?}"),
        }

        ws.send(peer_frame("contract-end", b"")).await.unwrap();
        assert_eq!(close_code(&mut ws).await, Some(4010));

        // A connection that proved no peer cannot send one.
        let mut client = established(&url).await;
        client
            .send(peer_frame("contract-offer", b"x"))
            .await
            .unwrap();
        let _error = next_frame(&mut client).await;
        assert_eq!(
            close_code(&mut client).await,
            Some(close::PROTOCOL_VIOLATION)
        );
        assert_eq!(
            echo.0.lock().unwrap().len(),
            2,
            "the handler saw nothing from it"
        );
    }

    /// Records every peer frame; answers `contract-offer`, closes on
    /// `contract-end`.
    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<(String, String, Vec<u8>)>>);

    impl crate::v0_0_2_peer::PeerFrames for Recorder {
        fn on_peer_frame(
            &self,
            peer: &jig_core::did::Did,
            kind: &str,
            body: &[u8],
            out: &crate::v0_0_2_peer::PeerSender,
        ) -> Result<(), crate::v0_0_2_peer::CloseReason> {
            self.0
                .lock()
                .unwrap()
                .push((peer.to_did_jig_string(), kind.into(), body.to_vec()));
            match kind {
                "contract-end" => Err(crate::v0_0_2_peer::CloseReason {
                    code: 4010,
                    reason: "ended".into(),
                }),
                "contract-offer" => {
                    out.send("contract-answer", body.to_vec()).unwrap();
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    impl Recorder {
        fn seen(&self) -> Vec<(String, String, Vec<u8>)> {
            self.0.lock().unwrap().clone()
        }

        async fn wait_for(&self, n: usize) -> Vec<(String, String, Vec<u8>)> {
            for _ in 0..300 {
                if self.seen().len() >= n {
                    return self.seen();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("expected {n} peer frames, saw {:?}", self.seen());
        }
    }

    /// A server state allowed plaintext federation, with `peers`.
    fn federating(peers: Vec<jig_config::v0_0_2_server::FederationPeer>) -> AppState {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.federation.dangerously_allow_plaintext_federation = true;
        config.federation.peers = peers;
        AppState::for_test_with_config(config).unwrap()
    }

    /// The peer at `url` (a test server's WebSocket URL), expected to be
    /// `expected_did`.
    fn peer_at(url: &str, expected_did: String) -> jig_config::v0_0_2_server::FederationPeer {
        jig_config::v0_0_2_server::FederationPeer {
            url: url.trim_end_matches("/api/v1/ws").to_string(),
            expected_did,
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        }
    }

    /// The side that dialed is held to the same rules: peer frames reach its
    /// handler with the DID the welcome proved, both ways, and a handler's
    /// close ends the connection.
    #[tokio::test]
    async fn peer_frames_reach_the_dialing_side_too() {
        let dialing = Arc::new(federating(vec![]));
        // The dialed side lists the dialer as a peer, so it takes its
        // federation subscription.
        let dialed = federating(vec![peer_at(
            "ws://127.0.0.1:1",
            dialing.server_did.to_did_jig_string(),
        )]);
        let (dialed, url) = start_test_server_with(dialed).await;
        let dialed_seen = Arc::new(Recorder::default());
        assert!(dialed.set_peer_frames(dialed_seen.clone()));
        let peer = peer_at(&url, dialed.server_did.to_did_jig_string());
        let dialing_seen = Arc::new(Recorder::default());
        assert!(dialing.set_peer_frames(dialing_seen.clone()));
        let relay = tokio::spawn({
            let dialing = dialing.clone();
            async move { crate::v0_0_2_federation::connect_and_relay(&dialing, &peer).await }
        });

        let mut to_dialing = None;
        for _ in 0..300 {
            to_dialing = dialed.peers.sender_for(&dialing.server_did);
            if to_dialing.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let to_dialing = to_dialing.expect("the dialing server proved its DID");

        // From the dialed side to the dialer's handler, which answers.
        to_dialing
            .send("contract-offer", b"from-dialed".to_vec())
            .unwrap();
        let (dialed_did, dialing_did) = (
            dialed.server_did.to_did_jig_string(),
            dialing.server_did.to_did_jig_string(),
        );
        assert_eq!(
            dialing_seen.wait_for(1).await[0],
            (
                dialed_did.clone(),
                "contract-offer".into(),
                b"from-dialed".to_vec()
            ),
            "the dialer's handler sees the DID the welcome proved"
        );
        // The dialer's catch-up ask comes first ([`crate::v0_0_2_catch_up`]).
        let seen = dialed_seen.wait_for(2).await;
        assert_eq!(seen[0].1, crate::v0_0_2_catch_up::CATCH_UP_FRAME);
        assert_eq!(
            seen[1],
            (
                dialing_did.clone(),
                "contract-answer".into(),
                b"from-dialed".to_vec()
            )
        );

        // Unprompted from the dialer, through its own registry.
        dialing
            .peers
            .sender_for(&dialed.server_did)
            .expect("the dialed peer is live on the dialer too")
            .send("note", b"from-dialing".to_vec())
            .unwrap();
        assert_eq!(dialed_seen.wait_for(3).await[2].2, b"from-dialing");

        // The dialer's handler closes; the connection ends as a contract close.
        to_dialing.send("contract-end", vec![]).unwrap();
        let err = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("the dialer ends the connection")
            .unwrap()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("closed by the federation contract"),
            "{err}"
        );
        assert!(dialing.peers.sender_for(&dialed.server_did).is_none());
    }

    /// A peer that moved its key, along a link both keys signed, is not
    /// federated with until its operator lists the new DID: one connection
    /// does not carry two peer identities.
    #[tokio::test]
    async fn a_dialer_refuses_a_peer_that_moved_until_it_is_listed_anew() {
        let mut moved = federating(vec![]);
        let old = jig_core::crypto::ed25519::generate_signing_key();
        moved.key_link = Some(
            jig_core::key_link::SignedKeyLink::sign(
                &old,
                &moved.ingest_ctx.server_key,
                jig_core::key_link::Audience::Public,
                1,
            )
            .unwrap()
            .envelope()
            .to_vec(),
        );
        let (moved, url) = start_test_server_with(moved).await;
        let dialing = Arc::new(federating(vec![]));
        let old_did =
            jig_core::Did::from_ed25519_pubkey(old.verifying_key().as_bytes()).to_did_jig_string();
        let err = crate::v0_0_2_federation::connect_and_relay(&dialing, &peer_at(&url, old_did))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("set its expected_did"), "{err}");
        assert!(dialing.peers.sender_for(&moved.server_did).is_none());
    }

    /// A peer the dialer has not proven reaches no handler: one that sends a
    /// peer frame in place of a welcome, and one whose welcome is another
    /// DID's than the expected one.
    #[tokio::test]
    async fn the_dialer_hands_nothing_from_an_unproven_peer_to_its_handler() {
        // In place of a welcome.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/api/v1/ws", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let _hello = ws.next().await;
            let frame = Envelope::new(Frame::Peer {
                kind: "contract-offer".into(),
                body: b"early".to_vec(),
            });
            ws.send(TMessage::Text(
                serde_json::to_string(&frame).unwrap().into(),
            ))
            .await
            .unwrap();
            let _ = ws.next().await;
        });
        let stranger = jig_core::Did::from_ed25519_pubkey(&[7u8; 32]).to_did_jig_string();
        let dialing = Arc::new(federating(vec![]));
        let peer = peer_at(&url, stranger.clone());
        let seen = Arc::new(Recorder::default());
        assert!(dialing.set_peer_frames(seen.clone()));
        assert!(
            crate::v0_0_2_federation::connect_and_relay(&dialing, &peer)
                .await
                .is_err()
        );

        // A real server, but not the one expected.
        let (dialed, url) = start_test_server().await;
        let dialed_seen = Arc::new(Recorder::default());
        assert!(dialed.set_peer_frames(dialed_seen.clone()));
        let peer = peer_at(&url, stranger);
        assert!(
            crate::v0_0_2_federation::connect_and_relay(&dialing, &peer)
                .await
                .is_err()
        );
        assert!(seen.seen().is_empty(), "{:?}", seen.seen());
        assert!(
            dialed.peers.sender_for(&dialing.server_did).is_none(),
            "a dialer that refused the welcome proved nothing to the dialed side"
        );
        assert!(dialing.peers.sender_for(&dialed.server_did).is_none());
    }

    /// The close code the server ends the connection with.
    async fn close_code(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Option<u16> {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
                .await
                .expect("timeout waiting for the close");
            match msg {
                Some(Ok(TMessage::Close(frame))) => return frame.map(|f| u16::from(f.code)),
                Some(Ok(TMessage::Text(text))) => panic!("expected a close, got {text}"),
                Some(Ok(_)) => continue,
                Some(Err(_)) | None => return None,
            }
        }
    }

    async fn handshake(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) {
        let (hello, pending) =
            jig_pipeline::handshake::begin(&jig_pipeline::handshake::ClientOffer::default());
        ws.send(TMessage::Text(
            serde_json::to_string(&hello).unwrap().into(),
        ))
        .await
        .unwrap();
        assert!(matches!(
            pending.interpret(&recv_text(ws).await),
            jig_pipeline::handshake::HandshakeResult::Established(_)
        ));
    }

    async fn recv_text(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> String {
        let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("timeout")
            .expect("stream closed")
            .expect("ws error");
        let TMessage::Text(text) = msg else {
            panic!("expected text, got {msg:?}");
        };
        text.to_string()
    }

    #[tokio::test]
    async fn client_receives_a_signed_welcome() {
        let (state, url) = start_test_server().await;
        let client = jig_client::Client::connect(&url, test_identity())
            .await
            .unwrap();
        let welcome = client.welcome().expect("welcome");
        assert_eq!(welcome.version, 1);
        assert_eq!(welcome.suites, vec!["none".to_string(), "mls".to_string()]);
        assert!(welcome.reputation.is_null());
        assert_eq!(welcome.server_did, state.server_did.to_did_jig_string());
        assert_eq!(
            welcome.capabilities.block_kinds,
            state.config.server.allowed_block_kinds
        );
        assert!(welcome.capabilities.execution);
        assert!(welcome.capabilities.federation);
        // The default server admits anyone, so it asks no work.
        assert_eq!(welcome.admit, None);
    }

    #[tokio::test]
    async fn the_welcome_signs_the_admission_work_a_new_did_owes() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.auth.admission.unknown_dids =
            jig_config::v0_0_2_server::UnknownDidsPolicy::ProofOfWork;
        config.auth.admission.pow_bits = 8;
        let (_state, url) =
            start_test_server_with(AppState::for_test_with_config(config).unwrap()).await;
        let before = unix_now();
        let client = jig_client::Client::connect(&url, test_identity())
            .await
            .unwrap();
        let admit = client.welcome().expect("welcome").admit.expect("admit");
        assert_eq!(admit.alg(), Some(jig_core::pow::Alg::Blake3));
        assert_eq!(admit.effort().map(|e| e.get()), Some(256));
        assert_eq!(admit.salt_id, jig_core::pow::EMPTY_SALT_ID);
        assert!(
            (before + ADMIT_OFFER_SECS..=unix_now() + ADMIT_OFFER_SECS).contains(&admit.expires_at)
        );
    }

    #[tokio::test]
    async fn a_frame_before_hello_is_refused_and_closed() {
        let (_state, url) = start_test_server().await;
        let (mut ws, _) = connect_async(&url).await.unwrap();
        let sub = Envelope::new(Frame::Subscribe {
            scope: Scope::Channel {
                slug: "#hello".to_string(),
            },
            auth: None,
        });
        ws.send(TMessage::Text(serde_json::to_string(&sub).unwrap().into()))
            .await
            .unwrap();
        match next_frame(&mut ws).await.frame {
            Frame::Error { code, .. } => assert_eq!(code, "HANDSHAKE_REQUIRED"),
            other => panic!("expected HANDSHAKE_REQUIRED, got {other:?}"),
        }
        assert_eq!(close_code(&mut ws).await, Some(close::PROTOCOL_VIOLATION));
    }

    #[tokio::test]
    async fn an_incompatible_hello_gets_a_signed_refusal_and_a_close() {
        let (state, url) = start_test_server().await;
        for offer in [
            jig_pipeline::handshake::ClientOffer {
                versions: vec![2],
                ..jig_pipeline::handshake::ClientOffer::default()
            },
            jig_pipeline::handshake::ClientOffer {
                suites: vec!["mls".to_string()],
                ..jig_pipeline::handshake::ClientOffer::default()
            },
        ] {
            let (mut ws, _) = connect_async(&url).await.unwrap();
            let (hello, pending) = jig_pipeline::handshake::begin(&offer);
            ws.send(TMessage::Text(
                serde_json::to_string(&hello).unwrap().into(),
            ))
            .await
            .unwrap();
            match pending.interpret(&recv_text(&mut ws).await) {
                jig_pipeline::handshake::HandshakeResult::Incompatible(refusal) => {
                    assert_eq!(refusal.server_did, state.server_did.to_did_jig_string());
                    assert_eq!(refusal.versions, vec![1]);
                    assert_eq!(refusal.suites, vec!["none".to_string(), "mls".to_string()]);
                }
                other => panic!("expected a signed refusal for {offer:?}, got {other:?}"),
            }
            assert_eq!(close_code(&mut ws).await, Some(close::INCOMPATIBLE));
        }
    }

    /// A hello inside an envelope this server cannot parse still gets a
    /// signed refusal that echoes its nonce.
    #[tokio::test]
    async fn a_hello_at_an_unspoken_version_gets_a_signed_refusal() {
        let (_state, url) = start_test_server().await;
        let (mut ws, _) = connect_async(&url).await.unwrap();
        let (hello, pending) =
            jig_pipeline::handshake::begin(&jig_pipeline::handshake::ClientOffer::default());
        let mut value = serde_json::to_value(&hello).unwrap();
        value["v"] = serde_json::json!(2);
        ws.send(TMessage::Text(value.to_string().into()))
            .await
            .unwrap();
        assert!(matches!(
            pending.interpret(&recv_text(&mut ws).await),
            jig_pipeline::handshake::HandshakeResult::Incompatible(_)
        ));
        assert_eq!(close_code(&mut ws).await, Some(close::INCOMPATIBLE));
    }

    #[tokio::test]
    async fn a_second_hello_is_a_protocol_violation() {
        let (_state, url) = start_test_server().await;
        let (mut ws, _) = connect_async(&url).await.unwrap();
        handshake(&mut ws).await;
        let (hello, _) =
            jig_pipeline::handshake::begin(&jig_pipeline::handshake::ClientOffer::default());
        ws.send(TMessage::Text(
            serde_json::to_string(&hello).unwrap().into(),
        ))
        .await
        .unwrap();
        match next_frame(&mut ws).await.frame {
            Frame::Error { code, .. } => assert_eq!(code, "PROTOCOL_VIOLATION"),
            other => panic!("expected PROTOCOL_VIOLATION, got {other:?}"),
        }
        assert_eq!(close_code(&mut ws).await, Some(close::PROTOCOL_VIOLATION));
    }

    /// After the welcome, a frame outside the client's own offer ends the
    /// connection; a merely malformed one is an ordinary error.
    #[tokio::test]
    async fn after_the_welcome_only_a_frame_outside_the_offer_closes() {
        let (_state, url) = start_test_server().await;
        let (mut ws, _) = connect_async(&url).await.unwrap();
        handshake(&mut ws).await;

        ws.send(TMessage::Text("{not json".into())).await.unwrap();
        match next_frame(&mut ws).await.frame {
            Frame::Error { code, .. } => assert_eq!(code, "BAD_JSON"),
            other => panic!("expected BAD_JSON, got {other:?}"),
        }

        ws.send(TMessage::Text(
            r##"{"v":2,"op":"subscribe","scope":{"kind":"channel","slug":"#hello"}}"##.into(),
        ))
        .await
        .unwrap();
        match next_frame(&mut ws).await.frame {
            Frame::Error { code, .. } => assert_eq!(code, "UNSUPPORTED_VERSION"),
            other => panic!("expected UNSUPPORTED_VERSION, got {other:?}"),
        }
        assert_eq!(close_code(&mut ws).await, Some(close::PROTOCOL_VIOLATION));
    }
}
