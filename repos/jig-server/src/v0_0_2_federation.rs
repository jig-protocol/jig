//! Federation peer manager — connects to configured peers, catches up on
//! what each took while unconnected, relays blocks bidirectionally.
//!
//! A block a peer relays is ingested like a local submission
//! ([`ingest_peer_block`]): the same gates, the same write gate and suite
//! gate, the same effects, and this server's own receipt. A peer vouches for
//! nothing; every block stands on its author's signature and this server's
//! rules.
//!
//! Trust model: listing a peer in `[federation] peers` is what trusts it.
//! This server dials the peer's `url` and refuses a welcome signed by any
//! key but its `expected_did`, so blocks arrive only over a connection to a
//! server it chose. Only a listed DID may subscribe to this server's
//! federation stream (see `v0_0_2_ws`).
//!
//! A `ws://` (plaintext) peer is refused — at boot and at every dial — unless
//! `[federation] dangerously_allow_plaintext_federation` is set
//! ([`check_peer_transport`]). The welcome pins the peer's DID either way, but
//! on a plaintext link nothing after the welcome is protected.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::Signer;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use jig_core::{BlockKind, BlockManifest};
use jig_pipeline::{
    Envelope, Frame, Scope,
    envelope::ReceiptRef,
    fanout::DeliveryPolicy,
    ingest::IngestError,
    persist::{StoredBlock, StoredReceipt},
};
use tokio::sync::mpsc;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config, tungstenite::Message,
};
use tracing::{debug, info, warn};

use crate::v0_0_2::AppState;

/// Reconnect delay after a peer connection drops or fails to establish.
/// Constant in v0.0.2; exponential backoff is a v0.0.3+ refinement.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// The delay before redialing a peer whose federation contract closed the
/// connection ([`crate::v0_0_2_peer::CloseReason`]), doubling with each such
/// close in a row up to [`MAX_CONTRACT_CLOSE_DELAY`].
const CONTRACT_CLOSE_DELAY: Duration = Duration::from_secs(30);
const MAX_CONTRACT_CLOSE_DELAY: Duration = Duration::from_secs(15 * 60);

/// A connection the federation contract closed.
#[derive(Debug, thiserror::Error)]
#[error("closed by the federation contract ({}): {}", .0.code, .0.reason)]
struct ContractClosed(crate::v0_0_2_peer::CloseReason);

/// How long to wait before redialing, after `closes` contract closes in a row.
fn redial_delay(closes: u32) -> Duration {
    if closes == 0 {
        return RECONNECT_DELAY;
    }
    CONTRACT_CLOSE_DELAY
        .saturating_mul(1 << (closes - 1).min(16))
        .min(MAX_CONTRACT_CLOSE_DELAY)
}

/// Whether `url` names a plaintext WebSocket. Scheme comparison is
/// case-insensitive, as URL schemes are.
fn is_plaintext_url(url: &str) -> bool {
    url.trim()
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("ws://"))
}

/// Refuse a peer this server must not dial over plaintext: a `ws://` URL is
/// accepted only with `[federation] dangerously_allow_plaintext_federation`.
pub fn check_peer_transport(
    peer: &jig_config::v0_0_2_server::FederationPeer,
    federation: &jig_config::v0_0_2_server::FederationSection,
) -> Result<(), String> {
    if is_plaintext_url(&peer.url) && !federation.dangerously_allow_plaintext_federation {
        return Err(format!(
            "federation peer {} is plaintext ws://; use wss://, or set [federation] \
             dangerously_allow_plaintext_federation = true to accept an unprotected link",
            peer.url
        ));
    }
    Ok(())
}

/// Every configured peer's transport, checked. Called while building
/// `AppState`, so a plaintext peer nobody opted into is a boot error, like an
/// unparseable `expected_did`.
pub fn check_federation_transport(
    federation: &jig_config::v0_0_2_server::FederationSection,
) -> anyhow::Result<()> {
    for (i, peer) in federation.peers.iter().enumerate() {
        check_peer_transport(peer, federation)
            .map_err(|reason| anyhow::anyhow!("[federation] peers[{i}]: {reason}"))?;
    }
    Ok(())
}

/// The warning logged whenever a plaintext peer is dialed under the flag.
fn warn_plaintext_peer(peer_url: &str) {
    warn!(
        peer_url,
        "federation.dangerously_allow_plaintext_federation=true — dialing this peer over \
         plaintext ws://; its DID is checked at the handshake, but the relayed stream is \
         NOT protected"
    );
}

/// Sign a federation subscribe with this server's own identity.
///
/// The server authenticates to its peer exactly as a client does — same
/// canonical bytes, same verifier on the far side. Giving federation its own
/// bypass would mean a second authentication path to keep correct, and the
/// weaker of two paths is the one an attacker uses.
pub fn sign_federation_subscribe(
    state: &Arc<AppState>,
    scope: &Scope,
) -> jig_pipeline::envelope::SubscribeAuth {
    use base64::Engine as _;

    let hlc_wall_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    // Unique per attempt: a reconnect to the same peer inside the acceptance
    // window must not reuse a nonce the peer has already recorded.
    let seq = FED_SUBSCRIBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nonce = format!("fed-{hlc_wall_ms}-{seq}");

    let hash = jig_core::request_auth::canonical_request_hash(
        "SUBSCRIBE",
        &scope.canonical_string(),
        b"",
        hlc_wall_ms,
        0,
        &nonce,
    );

    jig_pipeline::envelope::SubscribeAuth {
        did: state.server_did.to_did_jig_string(),
        hlc_wall_ms,
        hlc_logical: 0,
        nonce,
        sig_b64: base64::engine::general_purpose::STANDARD
            .encode(state.ingest_ctx.server_key.sign(hash.as_bytes()).to_bytes()),
    }
}

/// Monotonic nonce source for federation subscribes.
static FED_SUBSCRIBE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Spawn one long-running task per configured peer. Each task owns its own
/// reconnect loop and persists across the server's lifetime.
pub fn spawn_federation_peers(state: Arc<AppState>) {
    let peers = state.config.federation.peers.clone();
    for mut peer in peers {
        // An operator typed `expected_did`, so it may be in any letter case;
        // the welcome, the TLS binding and ingest compare the one spelling.
        if let Ok(did) = jig_core::Did::canonicalize(&peer.expected_did) {
            peer.expected_did = did.to_did_jig_string();
        }
        // `AppState` refuses this at boot; repeated so no caller can spawn
        // a plaintext dialer the operator did not opt into.
        if let Err(reason) = check_peer_transport(&peer, &state.config.federation) {
            tracing::error!(peer_url = %peer.url, "refusing federation peer: {reason}");
            continue;
        }
        if is_plaintext_url(&peer.url) {
            warn_plaintext_peer(&peer.url);
        }
        let state = state.clone();
        tokio::spawn(async move {
            run_peer_loop(state, peer).await;
        });
    }
}

async fn run_peer_loop(state: Arc<AppState>, peer: jig_config::v0_0_2_server::FederationPeer) {
    info!(peer_url = %peer.url, "federation peer task started");
    let mut contract_closes = 0;
    loop {
        let outcome = connect_and_relay(&state, &peer).await;
        contract_closes = match &outcome {
            Err(e) if e.is::<ContractClosed>() => contract_closes + 1,
            _ => 0,
        };
        let delay = redial_delay(contract_closes);
        match outcome {
            Ok(()) => {
                warn!(
                    peer_url = %peer.url,
                    "peer connection ended cleanly; reconnecting in {delay:?}"
                );
            }
            Err(e) => {
                warn!(
                    peer_url = %peer.url,
                    "peer connection failed: {e}; reconnecting in {delay:?}"
                );
            }
        }
        tokio::time::sleep(delay).await;
    }
}

/// Speak JEP-0002 as the dialer: hello, then require a signed welcome.
///
/// Every outcome but a welcome is an error, so the reconnect loop tries again
/// later. A signed refusal means the peer speaks none of the offer, and the
/// peer closes. Anything else is a handshake failure: this sends a close
/// frame (4001) before returning.
///
/// `pinned_server_did` is the DID the peer must sign the welcome with: a
/// configured peer's `expected_did`. Any other key fails closed.
pub async fn complete_client_handshake<S>(
    ws: &mut S,
    pinned_server_did: Option<&str>,
) -> anyhow::Result<jig_pipeline::handshake::VerifiedWelcome>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    handshake_as(ws, pinned_server_did, &[], None).await
}

/// [`complete_client_handshake`] as a server dialing a peer (JEP-0002 rule
/// 12): the hello names this server's DID, the welcome must be bound to
/// `tls_exporter` (this connection's, empty over plaintext), and the
/// handshake ends with this server's `peer_proof` over the transcript.
pub async fn complete_peer_handshake<S>(
    ws: &mut S,
    pinned_server_did: &str,
    tls_exporter: &[u8],
    key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<jig_pipeline::handshake::VerifiedWelcome>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    handshake_as(ws, Some(pinned_server_did), tls_exporter, Some(key)).await
}

async fn handshake_as<S>(
    ws: &mut S,
    pinned_server_did: Option<&str>,
    tls_exporter: &[u8],
    key: Option<&ed25519_dalek::SigningKey>,
) -> anyhow::Result<jig_pipeline::handshake::VerifiedWelcome>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    let offer = jig_pipeline::handshake::ClientOffer {
        pinned_server_did: pinned_server_did.map(str::to_string),
        peer_did: key.map(|k| {
            jig_core::Did::from_ed25519_pubkey(k.verifying_key().as_bytes()).to_did_jig_string()
        }),
        ..Default::default()
    };
    let (hello, pending) = jig_pipeline::handshake::begin(&offer);
    // The transcript covers the hello exactly as sent.
    let hello_text = serde_json::to_string(&hello)?;
    ws.send(Message::Text(hello_text.clone().into())).await?;
    // Same absolute deadline as the client. Control frames must not restart it,
    // or the peer loop never reaches its reconnect delay.
    let deadline = tokio::time::Instant::now() + jig_pipeline::handshake::WELCOME_WAIT;
    let text = loop {
        let next = tokio::time::timeout_at(deadline, ws.next()).await;
        match next {
            Err(_) => anyhow::bail!("timed out waiting for a welcome"),
            Ok(None) => anyhow::bail!("connection closed before a welcome"),
            Ok(Some(Err(err))) => return Err(err.into()),
            Ok(Some(Ok(Message::Text(text)))) => break text,
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(Some(Ok(Message::Close(_)))) => anyhow::bail!("connection closed before a welcome"),
            Ok(Some(Ok(_))) => anyhow::bail!("first frame is not a welcome"),
        }
    };
    use jig_pipeline::handshake::{HandshakeResult, close};
    let close_with = |code: u16| {
        Message::Close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
            code: code.into(),
            reason: "handshake failed".into(),
        }))
    };
    match pending.interpret_on(&text, tls_exporter) {
        HandshakeResult::Established(welcome) => {
            // A peer is listed by DID, and that DID is what lets it
            // subscribe here and what its blocks are attributed to, so a
            // moved peer is not federated with under two DIDs: its
            // operator lists the new one.
            if let Some(from) = &welcome.moved_from {
                anyhow::bail!(
                    "the peer moved its key from {from} to {} along a public link both keys \
                     signed; set its expected_did to the new DID to federate with it",
                    welcome.server_did
                );
            }
            if let Some(key) = key {
                let proof =
                    jig_pipeline::handshake::peer_proof(key, &hello_text, &text, tls_exporter);
                ws.send(Message::Text(serde_json::to_string(&proof)?.into()))
                    .await?;
            }
            Ok(welcome)
        }
        HandshakeResult::Incompatible(refusal) => anyhow::bail!(
            "peer speaks none of this offer ({}): {}; it speaks versions {:?}, suites {:?}",
            refusal.code,
            refusal.message,
            refusal.versions,
            refusal.suites
        ),
        HandshakeResult::FailClosed { reason, .. } => {
            let _ = ws.send(close_with(close::HANDSHAKE_FAILED)).await;
            anyhow::bail!("handshake failed closed: {reason}")
        }
        HandshakeResult::Contradiction { reason, .. } => {
            let _ = ws.send(close_with(close::CONTRADICTION)).await;
            anyhow::bail!("peer contradicted what it signed: {reason}")
        }
    }
}

/// The TLS exporter value of a dialed connection (JEP-0002 rule 12), or
/// nothing over plaintext. A TLS session that cannot export one has nothing
/// to bind the welcome to, so the welcome check then refuses it.
pub(crate) fn tls_exporter_of(
    stream: &tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
) -> Vec<u8> {
    match stream {
        tokio_tungstenite::MaybeTlsStream::Rustls(tls) => tls
            .get_ref()
            .1
            .export_keying_material(
                [0u8; jig_pipeline::handshake::TLS_EXPORTER_LEN],
                jig_pipeline::handshake::TLS_EXPORTER_LABEL,
                None,
            )
            .map(|v| v.to_vec())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Dial a peer's `/api/v1/ws`, through `connector` when the peer is `wss://`.
/// The connection holds what the peer sends to `[limits]`: a message or frame
/// over them ends it.
pub(crate) async fn dial_peer(
    ws_url: &str,
    connector: Option<Connector>,
    limits: &crate::v0_0_2_limits::Limits,
) -> anyhow::Result<(
    WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::handshake::client::Response,
)> {
    Ok(connect_async_tls_with_config(ws_url, Some(limits.ws_config()), false, connector).await?)
}

pub(crate) async fn connect_and_relay(
    state: &Arc<AppState>,
    peer: &jig_config::v0_0_2_server::FederationPeer,
) -> anyhow::Result<()> {
    // This function dials, so it is the one that must refuse.
    check_peer_transport(peer, &state.config.federation)
        .map_err(|reason| anyhow::anyhow!(reason))?;
    if is_plaintext_url(&peer.url) {
        warn_plaintext_peer(&peer.url);
    }
    let ws_url = format!("{}/api/v1/ws", peer.url.trim_end_matches('/'));

    // A `wss://` peer is held to the certificate its expected DID vouches for
    // (or one a CA issued); `dangerously_disable_federation_tls` checks
    // nothing and is advertised in `/.well-known/jig`.
    let connector =
        crate::v0_0_2_federation_tls::peer_connector(&state.config.federation, peer).await?;
    let (mut ws, _resp) = dial_peer(&ws_url, connector, &state.limits()).await?;
    // Same hello/welcome a CLI client speaks.
    let tls_exporter = tls_exporter_of(ws.get_ref());
    let welcome = complete_peer_handshake(
        &mut ws,
        &peer.expected_did,
        &tls_exporter,
        &state.ingest_ctx.server_key,
    )
    .await?;
    let (mut sink, mut stream) = ws.split();
    // The handshake proved the peer's DID; peer frames on this connection
    // are from it and go to it ([`crate::v0_0_2_peer`]).
    let (peer_sender, mut peer_out) = crate::v0_0_2_peer::PeerSender::new(
        jig_core::did::Did::from_did_jig_string(&welcome.server_did)
            .map_err(|e| anyhow::anyhow!("the peer's welcome DID: {e}"))?,
    );
    let registration = state.peers.register(peer_sender.clone());
    info!(peer_url = %peer.url, "federation peer connected");

    // 1. Subscribe federation scope so the peer pushes us their block stream.
    //
    // Signed with this server's OWN identity. A peer that requires
    // authentication refuses an unsigned subscribe, so federation between two
    // authenticated servers only works because of this — the server is a
    // first-class caller here, not an exception to the rule.
    let sub_scope = Scope::Federation {
        block_kinds: vec![],
    };
    let sub_env = Envelope::new(Frame::Subscribe {
        auth: Some(sign_federation_subscribe(state, &sub_scope)),
        scope: sub_scope,
    });
    sink.send(Message::Text(serde_json::to_string(&sub_env)?.into()))
        .await?;

    // 2. Ask for what the peer took while we were not subscribed: the live
    //    push carries only what lands from now on
    //    ([`crate::v0_0_2_catch_up`]).
    let mut catching = crate::v0_0_2_catch_up::CatchingUp::start(state, peer, &peer_sender)?;

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
                        if let Some(refusal) = subscription_refusal(&text) {
                            break Err(anyhow::anyhow!("peer refused our federation subscription: {refusal}"));
                        }
                        match handle_inbound_frame(state, peer, &peer_sender, &mut catching, &text).await {
                            Ok(Some(reason)) => {
                                let _ = sink
                                    .send(Message::Close(Some(
                                        tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                            code: reason.code.into(),
                                            reason: reason.reason.clone().into(),
                                        },
                                    )))
                                    .await;
                                break Err(ContractClosed(reason).into());
                            }
                            Ok(None) => {}
                            Err(e) => warn!(peer_url = %peer.url, "inbound frame error: {e}"),
                        }
                    }
                    Message::Close(_) => break Ok(()),
                    // Ignore Ping/Pong/Binary.
                    _ => {}
                }
            }

            // Peer frames this server sends unprompted
            Some(env) = peer_out.recv() => {
                let json = serde_json::to_string(&env)?;
                if let Err(e) = sink.send(Message::Text(json.into())).await {
                    break Err(anyhow::anyhow!("peer frame send error: {e}"));
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
    state.peers.unregister(registration);

    result
}

/// Handle one frame from a peer this server dialed. `Ok(Some(_))` means the
/// federation contract closed the connection.
async fn handle_inbound_frame(
    state: &Arc<AppState>,
    peer: &jig_config::v0_0_2_server::FederationPeer,
    sender: &crate::v0_0_2_peer::PeerSender,
    catching: &mut crate::v0_0_2_catch_up::CatchingUp,
    text: &str,
) -> anyhow::Result<Option<crate::v0_0_2_peer::CloseReason>> {
    let env: Envelope = serde_json::from_str(text)?;
    if let Frame::Peer { kind, body } = &env.frame {
        if let Some(handled) =
            crate::v0_0_2_catch_up::on_dialer_frame(state, peer, sender, catching, kind, body).await
        {
            return Ok(handled.err());
        }
        return Ok(
            crate::v0_0_2_peer::dispatch(state.peer_frame_handler(), sender, kind, body).err(),
        );
    }
    handle_relayed_frame(state, peer, env).await.map(|()| None)
}

async fn handle_relayed_frame(
    state: &Arc<AppState>,
    peer: &jig_config::v0_0_2_server::FederationPeer,
    env: Envelope,
) -> anyhow::Result<()> {
    match env.frame {
        Frame::Block {
            bundle_b64,
            sig_b64,
            delivery_cid,
            ..
        } => ingest_peer_block(state, peer, &bundle_b64, sig_b64.as_deref(), &delivery_cid).await,
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

/// A relayed block's CID, derived exactly as `ingest` derives it — a CIDv1
/// over the bundle root — so one block has one identity on every server.
/// (Up to v0.1 this relay used `bafy_<blake3 of the tuple bytes>`, so a
/// federated block was stored under a different CID than its origin's.)
pub fn peer_block_cid(bundle_bytes: &[u8]) -> anyhow::Result<String> {
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) = serde_json::from_slice(bundle_bytes)?;
    let bundle = jig_core::BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    };
    Ok(bundle.block_cid()?.to_string())
}

/// Run one block a federation peer relayed through [`ingest`], exactly as a
/// local submission runs: manifest gates, signature, admission, kind
/// allowlist, archived channels, the write gate, the suite gate, effects,
/// this server's own execution and receipt, then fanout to local subscribers
/// and bridges (never back out to peers). Public so the integration-test
/// harness drives this exact path rather than a copy of it.
///
/// Receipts the peer relays alongside the block are not kept: nothing here
/// can verify them, and this server signs its own.
///
/// A refused block is logged and dropped: one bad block is no reason to drop
/// the peer. Only a failing store is an error.
///
/// [`ingest`]: jig_pipeline::ingest::ingest
pub async fn ingest_peer_block(
    state: &Arc<AppState>,
    peer: &jig_config::v0_0_2_server::FederationPeer,
    bundle_b64: &str,
    sig_b64: Option<&str>,
    delivery_cid: &str,
) -> anyhow::Result<()> {
    let bundle_bytes = base64::engine::general_purpose::STANDARD.decode(bundle_b64)?;
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&bundle_bytes)?;
    let manifest: BlockManifest = serde_json::from_slice(&manifest_bytes)?;

    // v0.2 federates only open, unencrypted channels (see
    // `DeliveryPolicy::federates`): an encrypted channel's group lives on one
    // server until the federation contract (D12) says how it spans two. So a
    // block for a local channel that does not federate, or one claiming an
    // encrypted suite, is dropped before the write gate sees it.
    if manifest.content_suite() != jig_core::EncryptionSuite::Unencrypted {
        warn!(peer_url = %peer.url, %delivery_cid, "rejecting peer block: encrypted content does not federate");
        return Ok(());
    }
    let bundle = jig_core::BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    };
    // The same resolver ingest gates with, so a block naming its channel by
    // `channel_id` is held to the same rule as one naming it by slug.
    let block_cid = bundle
        .block_cid()
        .map(|c| c.to_string())
        .unwrap_or_default();
    // A share and the contract's records are the sequencer's business, asked
    // of it and written by it: from a peer, a share would have this server
    // act as owner of its relayed copy, offering a channel it does not own.
    if let Some(
        kind @ (BlockKind::ChannelShare
        | BlockKind::ChannelUnshare
        | BlockKind::ContractAccept
        | BlockKind::ContractRefuse
        | BlockKind::ContractEnd),
    ) = manifest.kind
    {
        warn!(peer_url = %peer.url, %delivery_cid, kind = kind.as_str(), "rejecting peer block: shares and contract records are the channel's sequencer's own");
        return Ok(());
    }
    // A channel this server carries by contract takes its blocks from the
    // owner's stream only: the relay would make it a copy of its own again.
    if let Some(kind) = manifest.kind
        && let Some(named) = jig_pipeline::ingest::channel_id_of(
            &state.ingest_ctx.store,
            kind,
            &manifest,
            &block_cid,
        )?
        && let Some(id) = named.id.as_deref().or_else(|| {
            manifest
                .metadata
                .get(jig_pipeline::ingest::CHANNEL_ID_KEY)
                .and_then(|v| v.as_str())
        })
        && state.ingest_ctx.store.is_followed(id)?
    {
        debug!(peer_url = %peer.url, %delivery_cid, channel_id = id, "dropping peer block: the channel is carried by contract");
        return Ok(());
    }
    if let Some(kind) = manifest.kind
        && let Some(named) = jig_pipeline::ingest::channel_id_of(
            &state.ingest_ctx.store,
            kind,
            &manifest,
            &block_cid,
        )?
        && let Some(id) = named.id.as_deref()
        && let Some(chan) = state
            .ingest_ctx
            .store
            .get_channel_by_id_including_archived(id)?
        && !DeliveryPolicy::for_channel(&chan, vec![]).federates
    {
        warn!(peer_url = %peer.url, %delivery_cid, slug = %chan.slug, "rejecting peer block: the local channel does not federate");
        return Ok(());
    }

    let sig = sig_b64
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
        .unwrap_or_default();
    let source = jig_pipeline::ingest::IngestSource::FederatedPeer {
        peer_did: jig_core::Did::from_str_unchecked(jig_pipeline::effect::canonical_did_string(
            &peer.expected_did,
        )),
        peer_url: peer.url.clone(),
    };
    match jig_pipeline::ingest::ingest(&state.ingest_ctx, bundle, sig, source).await {
        Ok(block_cid) => {
            debug!(peer_url = %peer.url, %delivery_cid, %block_cid, "ingested peer block");
            Ok(())
        }
        Err(IngestError::DuplicateBlock { cid }) => {
            debug!(peer_url = %peer.url, %delivery_cid, block_cid = %cid, "already have block; skipping");
            Ok(())
        }
        Err(IngestError::Persist(e)) => Err(e.into()),
        Err(e) => {
            warn!(peer_url = %peer.url, %delivery_cid, "rejecting peer block: {e}");
            Ok(())
        }
    }
}

/// The refusal in `text`, if it is the peer turning down our federation
/// subscription: it does not list this server as a peer. Ends the connection,
/// so the reconnect loop tries again later, rather than leaving it open and
/// carrying nothing.
pub fn subscription_refusal(text: &str) -> Option<String> {
    match serde_json::from_str::<Envelope>(text).ok()?.frame {
        Frame::Error { code, message, .. } if code == "NOT_A_PEER" => Some(message),
        _ => None,
    }
}

async fn forward_outbound(
    sink: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    block: &StoredBlock,
    receipt: &StoredReceipt,
) -> anyhow::Result<()> {
    let frame = Envelope::new(Frame::Block {
        bundle_b64: base64::engine::general_purpose::STANDARD.encode(&block.bundle_bytes),
        sig_b64: if block.sender_sig.is_empty() {
            None
        } else {
            Some(base64::engine::general_purpose::STANDARD.encode(&block.sender_sig))
        },
        receipts: vec![ReceiptRef {
            server_did: receipt.server_id.clone(),
            render_hash: receipt.render_hash.clone(),
            receipt_bytes_b64: base64::engine::general_purpose::STANDARD
                .encode(&receipt.receipt_bytes),
        }],
        delivery_cid: format!("delivery:{}", block.cid),
        ingest: None,
    });
    let json = serde_json::to_string(&frame)?;
    sink.send(Message::Text(json.into())).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::{Author, BlockKind};

    /// A peer that sends one text message of each length in `lens`, in order.
    async fn peer_sending(lens: Vec<usize>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/api/v1/ws", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            for len in lens {
                let _ = ws.send(Message::Text(" ".repeat(len).into())).await;
            }
            // Hold the connection until the dialer closes it.
            while ws.next().await.is_some() {}
        });
        url
    }

    /// `[limits]` hold on the connections this server dials, not only on
    /// the ones it accepts: what a peer sends past them ends the connection.
    #[tokio::test]
    async fn a_dialed_peer_is_held_to_the_message_limit() {
        let limits = crate::v0_0_2_limits::Limits::resolve(&Default::default());
        let max = limits.ws_message;
        let url = peer_sending(vec![max, max + 1]).await;
        let (mut ws, _) = dial_peer(&url, None, &limits).await.unwrap();

        match ws.next().await {
            Some(Ok(Message::Text(text))) => assert_eq!(text.len(), max),
            other => panic!("a message at the limit is read, got {other:?}"),
        }
        match ws.next().await {
            Some(Err(tokio_tungstenite::tungstenite::Error::Capacity(_))) => {}
            other => panic!("one byte over the limit is refused, got {other:?}"),
        }
    }

    fn plaintext_peer() -> jig_config::v0_0_2_server::FederationPeer {
        jig_config::v0_0_2_server::FederationPeer {
            // Port 1 on loopback: a dial attempt fails fast with a connection
            // error, so an error that names the flag proves no dial happened.
            url: "ws://127.0.0.1:1".to_string(),
            expected_did: jig_core::Did::from_ed25519_pubkey(&[9u8; 32]).to_did_jig_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        }
    }

    #[test]
    fn a_peer_that_keeps_closing_is_redialed_ever_more_slowly() {
        assert_eq!(redial_delay(0), RECONNECT_DELAY);
        assert_eq!(redial_delay(1), CONTRACT_CLOSE_DELAY);
        assert_eq!(redial_delay(2), CONTRACT_CLOSE_DELAY * 2);
        assert_eq!(redial_delay(6), MAX_CONTRACT_CLOSE_DELAY);
        assert_eq!(redial_delay(u32::MAX), MAX_CONTRACT_CLOSE_DELAY);
    }

    #[test]
    fn check_peer_transport_refuses_plaintext_unless_opted_in() {
        let mut federation = jig_config::v0_0_2_server::FederationSection::default();
        let mut peer = plaintext_peer();
        for url in [
            "ws://peer.example",
            "WS://peer.example",
            "  ws://peer.example",
        ] {
            peer.url = url.to_string();
            let err = check_peer_transport(&peer, &federation).unwrap_err();
            assert!(
                err.contains("dangerously_allow_plaintext_federation"),
                "{url}: {err}"
            );
        }
        peer.url = "wss://peer.example".to_string();
        assert!(check_peer_transport(&peer, &federation).is_ok());

        federation.dangerously_allow_plaintext_federation = true;
        peer.url = "ws://peer.example".to_string();
        assert!(check_peer_transport(&peer, &federation).is_ok());
    }

    /// A configured plaintext peer is a boot error without the flag, and boots
    /// with it.
    #[test]
    fn a_plaintext_peer_in_config_is_refused_at_boot() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.federation.peers = vec![plaintext_peer()];
        let err = AppState::for_test_with_config(config.clone())
            .err()
            .expect("a plaintext peer must not boot")
            .to_string();
        assert!(
            err.contains("dangerously_allow_plaintext_federation"),
            "{err}"
        );
        assert!(err.contains("peers[0]"), "{err}");

        config.federation.dangerously_allow_plaintext_federation = true;
        assert!(AppState::for_test_with_config(config).is_ok());
    }

    /// The dialer refuses a plaintext peer before connecting, whoever hands
    /// it the peer.
    #[tokio::test]
    async fn dialer_refuses_plaintext_without_the_flag() {
        let state = Arc::new(AppState::for_test().unwrap());
        let err = connect_and_relay(&state, &plaintext_peer())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("dangerously_allow_plaintext_federation"),
            "{err}"
        );
    }

    /// With the flag, the dialer goes ahead (and fails only on the network).
    #[tokio::test]
    async fn dialer_dials_plaintext_with_the_flag() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.federation.dangerously_allow_plaintext_federation = true;
        let state = Arc::new(AppState::for_test_with_config(config).unwrap());
        let err = connect_and_relay(&state, &plaintext_peer())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("dangerously_allow_plaintext_federation"),
            "the flag must let the dial proceed: {err}"
        );
    }

    #[tokio::test]
    async fn spawn_federation_peers_with_no_peers_is_noop() {
        // Default AppState has no peers configured; spawn should return immediately
        // (it iterates zero peers and spawns nothing).
        let state = Arc::new(AppState::for_test().unwrap());
        spawn_federation_peers(state);
        // No panic, no hang.
    }

    #[tokio::test]
    async fn ingest_peer_block_persists_and_dedupes() {
        use ed25519_dalek::SigningKey;
        use jig_core::{Author, BlockKind, BlockManifest, Did, HlcTimestamp};

        let state = Arc::new(AppState::for_test().unwrap());
        let peer = jig_config::v0_0_2_server::FederationPeer {
            url: "wss://test-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        };

        // Build a fake block bundle in the same (manifest_bytes, code_bytes) shape
        // that the ingest pipeline and federation module both expect. The sig
        // MUST verify against the manifest's claimed author DID — v0.0.3+ peer
        // ingest re-verifies on every inbound block.
        let secret: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&secret);
        let sender_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());
        let manifest = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: sender_did.clone(),
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
                server_did: sender_did.clone(),
            });
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle_bytes = serde_json::to_vec(&(manifest_bytes, Vec::<u8>::new())).unwrap();
        let sig = signing_key.sign(&bundle_bytes).to_bytes().to_vec();
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

        // First ingest: must persist block + receipt.
        ingest_peer_block(&state, &peer, &bundle_b64, Some(&sig_b64), "delivery:test1")
            .await
            .unwrap();
        let block_cid = peer_block_cid(&bundle_bytes).unwrap();
        let stored = state.ingest_ctx.store.get_block(&block_cid).unwrap();
        assert!(
            stored.is_some(),
            "block must be persisted after first ingest"
        );
        assert_eq!(
            stored.unwrap().sender_sig,
            sig,
            "verified peer block must store the sender_sig, not vec![]"
        );

        // Second ingest of the same bundle: must dedupe without error.
        ingest_peer_block(&state, &peer, &bundle_b64, Some(&sig_b64), "delivery:test2")
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
        // The receipt is this server's own: it executed the block.
        assert_eq!(receipts_in_db[0].server_id, state.server_did.to_string());
    }

    #[tokio::test]
    async fn federated_peer_block_reaches_bridge_sink_for_managed_member() {
        use ed25519_dalek::SigningKey;
        use jig_core::{Author, BlockKind, BlockManifest, Did, HlcTimestamp};
        use jig_pipeline::persist::{StoredChannel, StoredMembership};

        let state = Arc::new(AppState::for_test().unwrap());
        let peer = jig_config::v0_0_2_server::FederationPeer {
            url: "wss://test-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        };

        // A managed (bridge-owned) DID is a member of open channel "#dm/x". Channels
        // key by their channel-create CID (distinct from the slug); register the
        // membership under that CID, and wire a bridge sink for the managed DID.
        let managed_did = "did:jig:zManagedShadow".to_string();
        state
            .ingest_ctx
            .store
            .upsert_channel(&StoredChannel {
                id: jig_pipeline::ingest_record::label_cid("chan x"),
                slug: "#dm/x".into(),
                // Open: in v0.2 only open, unencrypted channels federate; see
                // `peer_blocks_for_channels_that_do_not_federate_are_dropped`.
                visibility: "open".into(),
                created_at: 0,
                owner_did: managed_did.clone(),
                suite: "none".to_string(),
                sequencer_did: String::new(),
                co_owners: Vec::new(),
                tiering: jig_pipeline::persist::ChannelTiering::current("open", "none"),
            })
            .unwrap();
        state
            .ingest_ctx
            .store
            .upsert_membership(&StoredMembership {
                channel_id: jig_pipeline::ingest_record::label_cid("chan x"),
                member_did: managed_did.clone(),
                role: "member".into(),
                joined_at: 0,
                source_block_cid: "seed".into(),
            })
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        state
            .ingest_ctx
            .fanout
            .register_bridge_did(managed_did.clone(), tx);

        // A peer relays a text-render authored by a DIFFERENT DID, posted to
        // "#dm/x" (carried in metadata["channel"]).
        let secret: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&secret);
        let sender_did = Did::from_ed25519_pubkey(signing_key.verifying_key().as_bytes());
        let manifest = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: sender_did.clone(),
                public_key: None,
                roles: vec![],
            })
            .metadata_entry("channel", serde_json::json!("#dm/x"))
            .metadata_entry("body", serde_json::json!("hello from a peer"))
            .build()
            .unwrap()
            .with_kind(BlockKind::TextRender)
            .with_hlc(HlcTimestamp {
                wall_ms: 1_747_680_000_000,
                logical: 0,
                server_did: sender_did.clone(),
            });
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle_bytes = serde_json::to_vec(&(manifest_bytes, Vec::<u8>::new())).unwrap();
        let sig = signing_key.sign(&bundle_bytes).to_bytes().to_vec();
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

        ingest_peer_block(
            &state,
            &peer,
            &bundle_b64,
            Some(&sig_b64),
            "delivery:fed-bridge",
        )
        .await
        .unwrap();

        // The bridge sink for the managed member must have received the delivery
        // (federated block on a bridged channel reaches Bridge::outbound).
        let got = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("bridge sink should receive the federated block")
            .expect("delivery present");
        assert_eq!(
            got.0.channel_id.as_deref(),
            Some(jig_pipeline::ingest_record::label_cid("chan x").as_str())
        );
        assert_eq!(got.0.sender_did, sender_did.to_did_jig_string());
    }

    /// v0.2 federates only open, unencrypted channels. A peer block naming a
    /// local restricted or encrypted channel is dropped before the write
    /// gate: an encrypted channel's group lives on one server until the
    /// federation contract says how it spans two.
    #[tokio::test]
    async fn peer_blocks_for_channels_that_do_not_federate_are_dropped() {
        use ed25519_dalek::SigningKey;
        use jig_core::{Author, BlockKind, BlockManifest, Did, HlcTimestamp};
        use jig_pipeline::persist::StoredChannel;

        let state = Arc::new(AppState::for_test().unwrap());
        let peer = jig_config::v0_0_2_server::FederationPeer {
            url: "wss://test-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        };
        for (slug, visibility, suite) in [
            ("#private", "restricted", "none"),
            ("#sealed", "open", "mls"),
        ] {
            state
                .ingest_ctx
                .store
                .upsert_channel(&StoredChannel {
                    id: jig_pipeline::ingest_record::label_cid(slug),
                    slug: slug.into(),
                    visibility: visibility.into(),
                    created_at: 0,
                    owner_did: "did:jig:zOwner".into(),
                    suite: suite.into(),
                    sequencer_did: String::new(),
                    co_owners: Vec::new(),
                    tiering: jig_pipeline::persist::ChannelTiering::current(&visibility, &suite),
                })
                .unwrap();
            let secret: [u8; 32] = rand::random();
            let key = SigningKey::from_bytes(&secret);
            let did = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
            let manifest = BlockManifest::builder()
                .version(semver::Version::new(0, 1, 0))
                .author(Author {
                    did: did.clone(),
                    public_key: None,
                    roles: vec![],
                })
                .metadata_entry("channel", serde_json::json!(slug))
                .metadata_entry("body", serde_json::json!("from a peer"))
                .build()
                .unwrap()
                .with_kind(BlockKind::TextRender)
                .with_hlc(HlcTimestamp {
                    wall_ms: 1_747_680_000_000,
                    logical: 0,
                    server_did: did,
                });
            let bundle_bytes =
                serde_json::to_vec(&(manifest.to_canonical_bytes().unwrap(), Vec::<u8>::new()))
                    .unwrap();
            let sig = key.sign(&bundle_bytes).to_bytes().to_vec();
            ingest_peer_block(
                &state,
                &peer,
                &base64::engine::general_purpose::STANDARD.encode(&bundle_bytes),
                Some(&base64::engine::general_purpose::STANDARD.encode(&sig)),
                "delivery:refused",
            )
            .await
            .unwrap();
            let cid = peer_block_cid(&bundle_bytes).unwrap();
            assert!(
                state.ingest_ctx.store.get_block(&cid).unwrap().is_none(),
                "a peer block for {slug} ({visibility}, {suite}) must not be stored"
            );
        }
    }

    #[tokio::test]
    async fn ingest_peer_block_rejects_forged_sender_did() {
        use ed25519_dalek::SigningKey;
        use jig_core::{Author, BlockKind, BlockManifest, Did, HlcTimestamp};

        let state = Arc::new(AppState::for_test().unwrap());
        let peer = jig_config::v0_0_2_server::FederationPeer {
            url: "wss://test-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        };

        // Alice signs; manifest claims bob as author. Sig verifies against
        // alice's pubkey but NOT against bob's.
        let alice_secret: [u8; 32] = rand::random();
        let alice_key = SigningKey::from_bytes(&alice_secret);
        let bob_secret: [u8; 32] = rand::random();
        let bob_key = SigningKey::from_bytes(&bob_secret);
        let bob_did = Did::from_ed25519_pubkey(bob_key.verifying_key().as_bytes());

        let manifest = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: bob_did.clone(),
                public_key: None,
                roles: vec![],
            })
            .metadata_entry("body", serde_json::json!("i am bob"))
            .build()
            .unwrap()
            .with_kind(BlockKind::TextRender)
            .with_hlc(HlcTimestamp {
                wall_ms: 1_747_680_000_000,
                logical: 0,
                server_did: bob_did.clone(),
            });
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle_bytes = serde_json::to_vec(&(manifest_bytes, Vec::<u8>::new())).unwrap();
        // Forged: signed by ALICE, manifest claims BOB.
        let sig = alice_key.sign(&bundle_bytes).to_bytes().to_vec();
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

        ingest_peer_block(&state, &peer, &bundle_b64, Some(&sig_b64), "d:forged")
            .await
            .unwrap();

        let block_cid = peer_block_cid(&bundle_bytes).unwrap();
        assert!(
            state
                .ingest_ctx
                .store
                .get_block(&block_cid)
                .unwrap()
                .is_none(),
            "forged-author peer block must be rejected (not persisted)"
        );
    }

    #[tokio::test]
    async fn ingest_peer_block_rejects_missing_sig() {
        use ed25519_dalek::SigningKey;
        use jig_core::{Author, BlockKind, BlockManifest, Did};

        let state = Arc::new(AppState::for_test().unwrap());
        let peer = jig_config::v0_0_2_server::FederationPeer {
            url: "wss://test-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        };

        let secret: [u8; 32] = rand::random();
        let key = SigningKey::from_bytes(&secret);
        let did = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
        let manifest = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did,
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap()
            .with_kind(BlockKind::TextRender);
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle_bytes = serde_json::to_vec(&(manifest_bytes, Vec::<u8>::new())).unwrap();
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle_bytes);

        // No sig_b64 at all (legacy v0.0.2 emitter shape). Default policy must reject.
        ingest_peer_block(&state, &peer, &bundle_b64, None, "d:nosig")
            .await
            .unwrap();

        let block_cid = peer_block_cid(&bundle_bytes).unwrap();
        assert!(
            state
                .ingest_ctx
                .store
                .get_block(&block_cid)
                .unwrap()
                .is_none(),
            "peer block without sig must be rejected under default policy"
        );
    }

    #[tokio::test]
    async fn ingest_peer_block_refuses_manifests_failing_the_gates() {
        use ed25519_dalek::SigningKey;
        use jig_core::{Author, BlockKind, BlockManifest, Did};

        let state = Arc::new(AppState::for_test().unwrap());
        let peer = jig_config::v0_0_2_server::FederationPeer {
            url: "wss://test-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        };
        let secret: [u8; 32] = rand::random();
        let key = SigningKey::from_bytes(&secret);
        let did = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
        let manifest = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did,
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap()
            .with_kind(BlockKind::TextRender);
        let base = serde_json::to_value(&manifest).unwrap();

        let mut future_schema = base.clone();
        future_schema["schema"] = "https://jig.dev/schema/block-manifest/v0.2".into();
        let mut mls = base;
        mls["privacy"] = serde_json::json!({ "encryption": "mls" });

        for manifest in [future_schema, mls] {
            let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
            let bundle_bytes = serde_json::to_vec(&(manifest_bytes, Vec::<u8>::new())).unwrap();
            let sig = key.sign(&bundle_bytes).to_bytes().to_vec();
            let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle_bytes);
            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

            ingest_peer_block(&state, &peer, &bundle_b64, Some(&sig_b64), "d:gate")
                .await
                .unwrap();

            let block_cid = peer_block_cid(&bundle_bytes).unwrap();
            assert!(
                state
                    .ingest_ctx
                    .store
                    .get_block(&block_cid)
                    .unwrap()
                    .is_none(),
                "a correctly signed peer block failing the gates must not be persisted: {manifest}"
            );
        }
    }

    /// A text-render `key` signed, the way a peer relays it: the base64
    /// bundle and signature, and the bundle bytes for its CID.
    fn relayed(
        key: &ed25519_dalek::SigningKey,
        kind: BlockKind,
        metadata: serde_json::Value,
    ) -> (Vec<u8>, String, String) {
        let did = jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
        let mut builder = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: did.clone(),
                public_key: None,
                roles: vec![],
            });
        if let serde_json::Value::Object(map) = metadata {
            for (k, v) in map {
                builder = builder.metadata_entry(&k, v);
            }
        }
        let manifest = builder
            .build()
            .unwrap()
            .with_kind(kind)
            .with_hlc(jig_core::HlcTimestamp {
                wall_ms: 1_747_680_000_000,
                logical: 0,
                server_did: did,
            });
        let bundle_bytes =
            serde_json::to_vec(&(manifest.to_canonical_bytes().unwrap(), Vec::<u8>::new()))
                .unwrap();
        let sig = key.sign(&bundle_bytes).to_bytes().to_vec();
        let b64 = &base64::engine::general_purpose::STANDARD;
        let (bundle_b64, sig_b64) = (b64.encode(&bundle_bytes), b64.encode(&sig));
        (bundle_bytes, bundle_b64, sig_b64)
    }

    fn test_peer() -> jig_config::v0_0_2_server::FederationPeer {
        jig_config::v0_0_2_server::FederationPeer {
            url: "wss://test-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        }
    }

    /// The write gate runs on relayed blocks: a member-add on an open channel
    /// from someone who does not own it is refused, and nobody is added. The
    /// relay used to persist it (unapplied) on the peer's word.
    #[tokio::test]
    async fn a_peer_cannot_change_a_channel_its_author_does_not_own() {
        use jig_pipeline::persist::StoredChannel;

        let state = Arc::new(AppState::for_test().unwrap());
        state
            .ingest_ctx
            .store
            .upsert_channel(&StoredChannel {
                id: jig_pipeline::ingest_record::label_cid("#open"),
                slug: "#open".into(),
                visibility: "open".into(),
                created_at: 0,
                owner_did: "did:jig:zOwner".into(),
                suite: "none".into(),
                sequencer_did: String::new(),
                co_owners: Vec::new(),
                tiering: jig_pipeline::persist::ChannelTiering::current("open", "none"),
            })
            .unwrap();
        let stranger = ed25519_dalek::SigningKey::from_bytes(&rand::random());
        let (bundle_bytes, bundle_b64, sig_b64) = relayed(
            &stranger,
            BlockKind::MemberAdd,
            serde_json::json!({"channel": "#open", "member_did": "did:jig:zSomeoneElse"}),
        );

        ingest_peer_block(&state, &test_peer(), &bundle_b64, Some(&sig_b64), "d:add")
            .await
            .unwrap();

        let cid = peer_block_cid(&bundle_bytes).unwrap();
        assert!(state.ingest_ctx.store.get_block(&cid).unwrap().is_none());
        assert!(
            state
                .ingest_ctx
                .store
                .list_members(&jig_pipeline::ingest_record::label_cid("#open"))
                .unwrap()
                .is_empty(),
            "a refused member-add must add nobody"
        );
    }

    /// Admission runs on relayed blocks: an author this server bans is
    /// refused whichever server it posted through.
    #[tokio::test]
    async fn a_banned_author_is_refused_from_a_peer_too() {
        let banned = ed25519_dalek::SigningKey::from_bytes(&rand::random());
        let banned_did = jig_core::Did::from_ed25519_pubkey(banned.verifying_key().as_bytes())
            .to_did_jig_string();
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.auth.admission.banned_dids = vec![banned_did];
        let state = Arc::new(AppState::for_test_with_config(config).unwrap());
        // A relayed post needs a channel this server holds.
        state
            .ingest_ctx
            .store
            .upsert_channel(&jig_pipeline::persist::StoredChannel {
                id: jig_pipeline::ingest_record::label_cid("#remote"),
                slug: "#remote".into(),
                visibility: "open".into(),
                created_at: 0,
                owner_did: "did:jig:zOwner".into(),
                suite: "none".into(),
                sequencer_did: String::new(),
                co_owners: Vec::new(),
                tiering: jig_pipeline::persist::ChannelTiering::current("open", "none"),
            })
            .unwrap();

        let (bundle_bytes, bundle_b64, sig_b64) = relayed(
            &banned,
            BlockKind::TextRender,
            serde_json::json!({"channel": "#remote", "body": "hi"}),
        );
        ingest_peer_block(
            &state,
            &test_peer(),
            &bundle_b64,
            Some(&sig_b64),
            "d:banned",
        )
        .await
        .unwrap();

        let cid = peer_block_cid(&bundle_bytes).unwrap();
        assert!(state.ingest_ctx.store.get_block(&cid).unwrap().is_none());

        // Control: the same relay from an admitted author lands.
        let admitted = ed25519_dalek::SigningKey::from_bytes(&rand::random());
        let (bundle_bytes, bundle_b64, sig_b64) = relayed(
            &admitted,
            BlockKind::TextRender,
            serde_json::json!({"channel": "#remote", "body": "hi"}),
        );
        ingest_peer_block(&state, &test_peer(), &bundle_b64, Some(&sig_b64), "d:ok")
            .await
            .unwrap();
        let cid = peer_block_cid(&bundle_bytes).unwrap();
        assert!(state.ingest_ctx.store.get_block(&cid).unwrap().is_some());
    }

    #[test]
    fn only_a_not_a_peer_error_ends_the_connection() {
        let frame = |code: &str| {
            serde_json::to_string(&Envelope::new(Frame::Error {
                status: Some(403),
                code: code.to_string(),
                ref_cid: None,
                message: "no".to_string(),
            }))
            .unwrap()
        };
        assert_eq!(
            subscription_refusal(&frame("NOT_A_PEER")).as_deref(),
            Some("no")
        );
        assert_eq!(subscription_refusal(&frame("NOT_ADMITTED")), None);
        assert_eq!(subscription_refusal("not json"), None);
    }
}
