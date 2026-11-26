//! Federation peer manager: dials each configured peer and keeps the link up.
//!
//! The link carries peer frames only ([`crate::v0_0_2_peer`]): the federation
//! contract's offers, answers and ends, and the streams of the channels a
//! share carries. A channel reaches another server only by a share
//! (JEP-0005). The legacy relay, which pushed every post of a server's open
//! channels to its peers, is gone: this server neither sends nor takes its
//! blocks. A follower's users' writes still reach the owner, relayed under
//! the share's grant (`relay-submit`, [`crate::v0_0_2_relay`]).
//!
//! Trust model: listing a peer in `[federation] peers` is what trusts it.
//! This server dials the peer's `url` and refuses a welcome signed by any
//! key but its `expected_did`.
//!
//! A `ws://` (plaintext) peer is refused — at boot and at every dial — unless
//! `[federation] dangerously_allow_plaintext_federation` is set
//! ([`check_peer_transport`]). The welcome pins the peer's DID either way, but
//! on a plaintext link nothing after the welcome is protected.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use jig_pipeline::{Envelope, Frame};
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

/// The configured peer whose DID is `did`, a DID this server verified and so
/// spells canonically. An operator typed each `expected_did`, so it may be in
/// any letter case: it is read the way boot and the dialer read it (#460).
pub(crate) fn configured_peer<'a>(
    federation: &'a jig_config::v0_0_2_server::FederationSection,
    did: &str,
) -> Option<&'a jig_config::v0_0_2_server::FederationPeer> {
    federation.peers.iter().find(|p| {
        jig_core::Did::canonicalize(&p.expected_did).is_ok_and(|d| d.to_did_jig_string() == did)
    })
}

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
    handshake_as(ws, pinned_server_did, &[], None, false).await
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
    handshake_as(ws, Some(pinned_server_did), tls_exporter, Some(key), false).await
}

/// [`complete_peer_handshake`] as a v0.2.0 node sends it: its hello lists
/// no block kinds, so a server gates it at any kind added since.
#[cfg(test)]
pub(crate) async fn complete_v0_2_0_peer_handshake<S>(
    ws: &mut S,
    pinned_server_did: &str,
    key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<jig_pipeline::handshake::VerifiedWelcome>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    handshake_as(ws, Some(pinned_server_did), &[], Some(key), true).await
}

async fn handshake_as<S>(
    ws: &mut S,
    pinned_server_did: Option<&str>,
    tls_exporter: &[u8],
    key: Option<&ed25519_dalek::SigningKey>,
    lists_no_kinds: bool,
) -> anyhow::Result<jig_pipeline::handshake::VerifiedWelcome>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    let mut offer = jig_pipeline::handshake::ClientOffer {
        pinned_server_did: pinned_server_did.map(str::to_string),
        peer_did: key.map(|k| {
            jig_core::Did::from_ed25519_pubkey(k.verifying_key().as_bytes()).to_did_jig_string()
        }),
        ..Default::default()
    };
    if lists_no_kinds {
        offer.capabilities.block_kinds.clear();
    }
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
    let (peer_sender, mut peer_out) = crate::v0_0_2_peer::PeerSender::with_tiers(
        jig_core::did::Did::from_did_jig_string(&welcome.server_did)
            .map_err(|e| anyhow::anyhow!("the peer's welcome DID: {e}"))?,
        welcome.capabilities.tiers,
    );
    let registration = state.peers.register(peer_sender.clone());
    info!(peer_url = %peer.url, "federation peer connected");

    // This server subscribes to nothing on the link and pushes the peer no
    // blocks outside a share: a share's record stream and the writes a
    // follower relays under it go out and come in as peer frames.
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
                        match handle_inbound_frame(state, peer, &peer_sender, &text) {
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

        }
    };

    // On loop exit (peer disconnect, error, or task cancellation), drop the
    //    peer's registration so no dead sender stays behind.
    state.peers.unregister(registration);

    result
}

/// Handle one frame from a peer this server dialed. `Ok(Some(_))` means the
/// federation contract closed the connection.
///
/// Anything but a peer frame is logged and dropped: a peer on a release
/// before this one may still push relayed blocks down the link, and the link
/// goes on, since it carries that peer's shares too.
fn handle_inbound_frame(
    state: &Arc<AppState>,
    peer: &jig_config::v0_0_2_server::FederationPeer,
    sender: &crate::v0_0_2_peer::PeerSender,
    text: &str,
) -> anyhow::Result<Option<crate::v0_0_2_peer::CloseReason>> {
    let env: Envelope = serde_json::from_str(text)?;
    match env.frame {
        Frame::Peer { kind, body } => {
            Ok(
                crate::v0_0_2_peer::dispatch(state.peer_frame_handler(), sender, &kind, &body)
                    .err(),
            )
        }
        Frame::Error { code, message, .. } => {
            warn!(peer_url = %peer.url, %code, %message, "peer returned error frame");
            Ok(None)
        }
        other => {
            debug!(peer_url = %peer.url, frame = ?std::mem::discriminant(&other), "ignoring a frame that is not a peer frame");
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer listed with its DID in another letter case is the same peer:
    /// the contract and the stream quota find it by the DID its welcome
    /// proved, as boot and the dialer already did (#460).
    #[test]
    fn a_peer_listed_in_another_letter_case_is_found_by_its_did() {
        use jig_config::v0_0_2_server::{FederationPeer, FederationSection, OfferPolicy};
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let did =
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();
        let body = did.strip_prefix("did:jig:z").unwrap();
        let federation = FederationSection {
            peers: vec![FederationPeer {
                url: "wss://peer.example".into(),
                expected_did: format!("did:jig:z{}", body.to_uppercase()),
                alias: None,
                publish: false,
                quota: None,
                offers: OfferPolicy::Hold,
            }],
            ..Default::default()
        };
        assert!(configured_peer(&federation, &did).is_some());
        let other = jig_core::Did::from_ed25519_pubkey(
            ed25519_dalek::SigningKey::from_bytes(&[8; 32])
                .verifying_key()
                .as_bytes(),
        )
        .to_did_jig_string();
        assert!(configured_peer(&federation, &other).is_none());
    }

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
}
