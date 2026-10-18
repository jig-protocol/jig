//! WSS connection management for jig-client.
//!
//! Wraps tokio-tungstenite with the v0.0.2 envelope codec (from
//! jig-pipeline). One [`Client`] per server connection; reuse across
//! subscriptions. Per-origin HLC cursors are tracked so that a resumed
//! connection can eventually send `CatchUp { since_hlc }` to backfill missed
//! blocks — NOT YET WIRED: the cursors are placeholders and nothing sends
//! `CatchUp` today.
//!
//! There is also NO automatic reconnect: when the connection drops, every
//! [`BlockStream`] ends and further `submit` calls fail, so callers can
//! detect the loss and decide what to do (a supervising shell loop, for now).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use jig_pipeline::envelope::{
    Envelope, EnvelopeParseError, Frame, HlcCursor, ReceiptRef, Scope, SubscribeAuth,
};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use url::Url;

use crate::blocks::BuiltBlock;
use crate::identity::Identity;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("failed to connect: {0}")]
    Connect(String),
    #[error("URL parse failed: {0}")]
    BadUrl(String),
    #[error("server returned error: code={code}, message={message}")]
    ServerError { code: String, message: String },
    #[error("connection closed before ack received")]
    ConnectionClosed,
    #[error("submit ack timed out after {0}s")]
    AckTimeout(u64),
    /// The welcome was missing, malformed, or contradicted itself. The socket
    /// is closed (4001) and nothing further was sent.
    #[error("handshake failed closed: {reason}")]
    HandshakeFailed {
        reason: String,
        /// The frame that failed, when one arrived.
        evidence: Option<String>,
    },
    /// The server signed that it speaks none of the versions or suites this
    /// client offered, and closed the connection (4002).
    #[error(
        "the server speaks none of what this client offered ({}): {}; it speaks versions {:?} and suites {:?}",
        .0.code, .0.message, .0.versions, .0.suites
    )]
    Incompatible(Box<jig_pipeline::handshake::VerifiedRefusal>),
    /// The server contradicted its signed welcome, or a signed refusal
    /// contradicted what this device pinned. The socket is closed (4003).
    #[error("the server contradicted what it signed: {}", .0.reason)]
    Contradiction(Contradiction),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::Error),
}

/// WSS client for a single server connection.
///
/// Construct via [`Client::connect`]; reuse the same client across
/// channel subscriptions and submissions. Internally drives reader +
/// writer tasks; the public API is fully `async` and message-based.
pub struct Client {
    identity: Arc<Identity>,
    write_tx: mpsc::UnboundedSender<Message>,
    inbound_rx: Mutex<mpsc::UnboundedReceiver<Frame>>,
    pending_subscriptions: SubscriptionMap,
    last_cursors: Arc<Mutex<HashMap<String, HlcCursor>>>,
    /// Set by [`ReaderCleanup`] when the reader task exits. Lets `submit`
    /// and `subscribe_channel` fail fast instead of waiting on a socket
    /// nobody is reading.
    closed: Arc<AtomicBool>,
    server_url: String,
    submit_ack_timeout_seconds: u64,
    welcome: Option<jig_pipeline::handshake::VerifiedWelcome>,
    /// Set once the server contradicts its welcome. The connection is then
    /// closed, and every later call returns it.
    contradiction: Arc<StdMutex<Option<Contradiction>>>,
}

/// The server contradicted something it signed (JEP-0002 rule 8).
///
/// `evidence` holds the frames as received: the signed welcome or refusal
/// first, then what contradicts it. Every item that proves the contradiction
/// is signed by the server, so it can be checked without trusting this
/// client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contradiction {
    pub reason: String,
    pub evidence: Vec<String>,
}

/// Per-channel delivery senders, keyed by channel slug.
///
/// A `std` mutex, not a `tokio` one, so [`ReaderCleanup::drop`] can clear the
/// map — `Drop` cannot await. Nothing holds this guard across an await point.
type SubscriptionMap = Arc<StdMutex<HashMap<String, mpsc::UnboundedSender<DeliveredBlock>>>>;

/// Lock the subscription map, recovering from poisoning: a panicking holder
/// must not wedge every live [`BlockStream`] for the rest of the process.
fn lock_subscriptions(
    map: &SubscriptionMap,
) -> MutexGuard<'_, HashMap<String, mpsc::UnboundedSender<DeliveredBlock>>> {
    map.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Owned by the reader task; clearing the subscription map on drop is what
/// stops `jig tail` / `jig chat` from becoming silent zombies when the server
/// restarts or the link dies.
///
/// WHY a `Drop` guard rather than a cleanup block after the read loop: the
/// reader task can be cancelled mid-`await` (runtime shutdown, task abort),
/// and `Drop` is the only path that runs in every case. Dropping each
/// subscriber's sender is what makes `BlockStream::next` return `None`.
struct ReaderCleanup {
    pending_subscriptions: SubscriptionMap,
    closed: Arc<AtomicBool>,
}

impl Drop for ReaderCleanup {
    fn drop(&mut self) {
        // Flag first, then clear: `subscribe_channel` re-checks the flag while
        // holding the map lock, so this ordering means a subscription can never
        // be registered after the clear and left dangling forever.
        self.closed.store(true, Ordering::SeqCst);
        lock_subscriptions(&self.pending_subscriptions).clear();
    }
}

/// A block delivered via [`BlockStream`].
///
/// Serde derives are part of a cross-crate wire contract, not a convenience:
/// the REST history endpoint (`GET /api/v1/channels/:slug/blocks`) serves a
/// JSON array that deserializes into `Vec<DeliveredBlock>`. Renaming or
/// reordering these fields is a breaking wire change for both sides.
///
/// `sig_b64` is the author's signature over the bundle. Clients verify it
/// before showing anything ([`crate::open::open`]): a server relays blocks,
/// and without the check it could rewrite one in transit undetected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeliveredBlock {
    pub bundle_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_b64: Option<String>,
    pub receipts: Vec<ReceiptRef>,
    pub delivery_cid: String,
}

/// Stream of [`DeliveredBlock`] items for a subscribed channel. Returned
/// by [`Client::subscribe_channel`].
pub struct BlockStream {
    rx: mpsc::UnboundedReceiver<DeliveredBlock>,
}

impl BlockStream {
    /// Wait for the next delivery. Returns `None` once the underlying
    /// connection closes — the reader task drops every subscription sender on
    /// exit, so a server restart or dead link ends the stream instead of
    /// blocking here forever. Callers should treat `None` as "disconnected".
    pub async fn next(&mut self) -> Option<DeliveredBlock> {
        self.rx.recv().await
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("server_url", &self.server_url)
            .field("identity_did", &self.identity.did_string())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Connect to a jig-server at `server_url` (e.g., `ws://127.0.0.1:7117`
    /// or `wss://dj.jig.onl`). Identity is used to sign outbound `Submit`
    /// frames.
    pub async fn connect(server_url: &str, identity: Identity) -> Result<Self, ClientError> {
        Self::connect_with(
            server_url,
            identity,
            jig_pipeline::handshake::ClientOffer::default(),
        )
        .await
    }

    /// [`Client::connect`] with an explicit offer. A pinned server DID that
    /// does not match the welcome fails closed. A server that speaks none of
    /// the offer answers with a signed refusal and closes
    /// ([`ClientError::Incompatible`]).
    pub async fn connect_with(
        server_url: &str,
        identity: Identity,
        offer: jig_pipeline::handshake::ClientOffer,
    ) -> Result<Self, ClientError> {
        Self::connect_with_tls(server_url, identity, offer, None).await
    }

    /// [`Client::connect_with`] over `tls`, typically the config
    /// [`crate::tls::probe`] built for this server. `None` uses the system's
    /// CA roots alone, which refuse a server's own certificate.
    pub async fn connect_with_tls(
        server_url: &str,
        identity: Identity,
        offer: jig_pipeline::handshake::ClientOffer,
        tls: Option<std::sync::Arc<rustls::ClientConfig>>,
    ) -> Result<Self, ClientError> {
        let url = Url::parse(server_url).map_err(|e| ClientError::BadUrl(e.to_string()))?;
        // Map http(s) → ws(s) if user gave HTTP scheme; otherwise leave alone.
        let scheme = match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            other => other,
        };
        let host = url
            .host_str()
            .ok_or_else(|| ClientError::BadUrl("no host".into()))?;
        let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
        let ws_url = format!("{scheme}://{host}{port}/api/v1/ws");

        let (ws, _resp) = match tls {
            Some(config) => {
                tokio_tungstenite::connect_async_tls_with_config(
                    &ws_url,
                    None,
                    false,
                    Some(tokio_tungstenite::Connector::Rustls(config)),
                )
                .await
            }
            None => connect_async(&ws_url).await,
        }
        .map_err(|e| ClientError::Connect(e.to_string()))?;
        let (mut sink, mut stream) = ws.split();

        let welcome = match drive_handshake(&mut sink, &mut stream, &offer).await {
            Ok(welcome) => welcome,
            Err(err) => {
                use jig_pipeline::handshake::close;
                let code = match &err {
                    ClientError::Contradiction(_) => Some(close::CONTRADICTION),
                    // The server closes after its refusal.
                    ClientError::Incompatible(_) => None,
                    _ => Some(close::HANDSHAKE_FAILED),
                };
                if let Some(code) = code {
                    let _ = sink.send(close_frame(code, "handshake failed")).await;
                }
                let _ = sink.close().await;
                return Err(err);
            }
        };
        let welcome_did = welcome.server_did.clone();
        let welcome_text = welcome.evidence.clone();
        let contradiction: Arc<StdMutex<Option<Contradiction>>> = Arc::new(StdMutex::new(None));

        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Message>();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Frame>();
        let pending_subscriptions: SubscriptionMap = Arc::new(StdMutex::new(HashMap::new()));
        let last_cursors: Arc<Mutex<HashMap<String, HlcCursor>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));

        // Writer task
        tokio::spawn(async move {
            while let Some(msg) = write_rx.recv().await {
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Reader task — dispatches incoming Block frames to per-channel
        // subscriber channels; forwards Ack / Error frames via inbound_tx
        // so callers awaiting a reply can pick them up. On every exit path
        // `ReaderCleanup` drops the subscription senders so each BlockStream
        // terminates instead of blocking forever.
        let pending_subs_for_reader = pending_subscriptions.clone();
        let cursors_for_reader = last_cursors.clone();
        let closed_for_reader = closed.clone();
        let contradiction_for_reader = contradiction.clone();
        let write_tx_for_reader = write_tx.clone();
        tokio::spawn(async move {
            let _cleanup = ReaderCleanup {
                pending_subscriptions: pending_subs_for_reader.clone(),
                closed: closed_for_reader,
            };
            let contradict = |reason: String, frame: &str| {
                contradicted(
                    &contradiction_for_reader,
                    &write_tx_for_reader,
                    reason,
                    vec![welcome_text.clone(), frame.to_string()],
                );
            };
            while let Some(Ok(msg)) = stream.next().await {
                if let Message::Text(text) = msg {
                    // Every frame is checked against the signed welcome
                    // (JEP-0002 rule 8): one at a version or suite it did not
                    // advertise ends the connection. One that does not parse
                    // at all is noise, not evidence.
                    let env = match Envelope::parse(&text) {
                        Ok(env) => env,
                        Err(EnvelopeParseError::Gate(gate)) => {
                            contradict(
                                format!("a frame outside the signed welcome: {gate}"),
                                &text,
                            );
                            break;
                        }
                        Err(EnvelopeParseError::Malformed(e)) => {
                            tracing::debug!("ignoring a frame that does not parse: {e}");
                            continue;
                        }
                    };
                    match env.frame {
                        Frame::Welcome { .. } | Frame::Refusal { .. } => {
                            contradict(
                                "a second handshake answer on one connection".to_string(),
                                &text,
                            );
                            break;
                        }
                        Frame::Block {
                            bundle_b64,
                            sig_b64,
                            receipts,
                            delivery_cid,
                            ..
                        } => {
                            // This server's receipts name the key that signed
                            // its welcome; a relayed block arrives with the
                            // receipt this server produced for it.
                            if let Some(other) = receipts.iter().find(|r| {
                                !jig_pipeline::handshake::same_did(&r.server_did, &welcome_did)
                            }) {
                                contradict(
                                    format!(
                                        "a receipt names {}, not the server that signed the welcome",
                                        other.server_did
                                    ),
                                    &text,
                                );
                                break;
                            }
                            // Track HLC cursor from receipts (best-effort —
                            // receipts may carry render_hash but not HLC; the
                            // bundle_b64 contains the manifest with hlc_ts).
                            // For v0.0.2 we just stash by delivery_cid origin;
                            // Phase D wires the real cursor logic when server
                            // emits explicit cursor advances.
                            let delivered = DeliveredBlock {
                                bundle_b64,
                                sig_b64,
                                receipts,
                                delivery_cid: delivery_cid.clone(),
                            };
                            // Dispatch to ALL pending channel subs (server-side
                            // filtering means we only get blocks for our subs;
                            // we'd add scope-side multiplexing here if subs
                            // could come from different channels — for v0.0.2
                            // one sub per channel slug suffices, and the
                            // server already filtered).
                            {
                                let subs = lock_subscriptions(&pending_subs_for_reader);
                                for tx in subs.values() {
                                    let _ = tx.send(delivered.clone());
                                }
                            }
                            // Update cursor for delivery_cid (placeholder —
                            // Phase D will swap in HLC cursor parsed from the
                            // delivered block's manifest).
                            cursors_for_reader.lock().await.insert(
                                delivery_cid.clone(),
                                HlcCursor {
                                    wall_ms: 0,
                                    logical: 0,
                                    origin: delivery_cid,
                                },
                            );
                        }
                        other => {
                            let _ = inbound_tx.send(other);
                        }
                    }
                }
            }
        });

        Ok(Self {
            identity: Arc::new(identity),
            write_tx,
            inbound_rx: Mutex::new(inbound_rx),
            pending_subscriptions,
            last_cursors,
            closed,
            server_url: server_url.to_string(),
            submit_ack_timeout_seconds: 5,
            welcome: Some(welcome),
            contradiction,
        })
    }

    /// The signed welcome, once the handshake has succeeded.
    pub fn welcome(&self) -> Option<&jig_pipeline::handshake::VerifiedWelcome> {
        self.welcome.as_ref()
    }

    /// Set once the server has contradicted its signed welcome. The
    /// connection is closed from then on.
    pub fn contradiction(&self) -> Option<Contradiction> {
        lock_contradiction(&self.contradiction).clone()
    }

    fn require_welcome(&self) -> Result<(), ClientError> {
        if let Some(contradiction) = self.contradiction() {
            return Err(ClientError::Contradiction(contradiction));
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(ClientError::ConnectionClosed);
        }
        if self.welcome.is_none() {
            return Err(ClientError::HandshakeFailed {
                reason: "no welcome".to_string(),
                evidence: None,
            });
        }
        Ok(())
    }

    /// Sign a subscription request with this client's identity.
    ///
    /// Servers requiring authentication refuse an unsigned `Subscribe`. The
    /// signature covers the scope's canonical string, so a proof minted for one
    /// channel cannot subscribe to another.
    ///
    /// The nonce is random per call rather than derived from anything: a server
    /// refuses a nonce it has already seen inside its acceptance window, so two
    /// subscriptions to the same channel must not collide.
    fn sign_subscribe(&self, scope: &Scope) -> SubscribeAuth {
        use base64::Engine as _;

        let hlc_wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Shared with the REST read proofs: one nonce sequence per process,
        // so a backfill and a subscribe in the same millisecond never carry
        // the same nonce. See `read_auth::fresh_nonce` for why a counter and
        // not randomness.
        let nonce = crate::read_auth::fresh_nonce(hlc_wall_ms);

        let hash = jig_core::request_auth::canonical_request_hash(
            "SUBSCRIBE",
            &scope.canonical_string(),
            b"",
            hlc_wall_ms,
            0,
            &nonce,
        );

        SubscribeAuth {
            did: self.identity.did_string(),
            hlc_wall_ms,
            hlc_logical: 0,
            nonce,
            sig_b64: base64::engine::general_purpose::STANDARD
                .encode(self.identity.sign(hash.as_bytes()).to_bytes()),
        }
    }

    /// Subscribe to a channel by slug. Returns a [`BlockStream`] that
    /// yields each delivered block.
    ///
    /// Returns [`ClientError::ConnectionClosed`] if the connection is already
    /// dead — better a loud error than a stream that can never yield or end.
    pub async fn subscribe_channel(&self, slug: &str) -> Result<BlockStream, ClientError> {
        self.require_welcome()?;
        let scope = Scope::Channel {
            slug: slug.to_string(),
        };
        let env = Envelope::new(Frame::Subscribe {
            auth: Some(self.sign_subscribe(&scope)),
            scope,
        });
        // Serialize before registering so a serde failure can't leave a
        // half-registered subscription behind.
        let json = serde_json::to_string(&env)?;

        let (delivery_tx, delivery_rx) = mpsc::unbounded_channel();
        {
            let mut subs = lock_subscriptions(&self.pending_subscriptions);
            if self.closed.load(Ordering::SeqCst) {
                return Err(ClientError::ConnectionClosed);
            }
            subs.insert(slug.to_string(), delivery_tx);
        }

        if self.write_tx.send(Message::Text(json.into())).is_err() {
            lock_subscriptions(&self.pending_subscriptions).remove(slug);
            return Err(ClientError::ConnectionClosed);
        }

        Ok(BlockStream { rx: delivery_rx })
    }

    /// Submit a built block and await its `Ack` (or `Error`). Returns the
    /// block CID assigned by the server.
    ///
    /// Fails immediately with [`ClientError::ConnectionClosed`] once the
    /// reader task has exited, rather than waiting out the ack timeout for
    /// an answer that can never arrive.
    pub async fn submit(&self, block: BuiltBlock) -> Result<String, ClientError> {
        use base64::Engine;
        self.require_welcome()?;
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&block.sender_sig);
        let env = Envelope::new(Frame::Submit {
            bundle_b64,
            sig_b64,
        });
        let json = serde_json::to_string(&env)?;
        self.write_tx
            .send(Message::Text(json.into()))
            .map_err(|_| ClientError::ConnectionClosed)?;

        // Await the first non-Block frame (Ack/Error).
        let timeout = Duration::from_secs(self.submit_ack_timeout_seconds);
        let mut rx = self.inbound_rx.lock().await;
        loop {
            let received = tokio::time::timeout(timeout, rx.recv())
                .await
                .map_err(|_| ClientError::AckTimeout(self.submit_ack_timeout_seconds))?;
            let Some(frame) = received else {
                return Err(self
                    .contradiction()
                    .map_or(ClientError::ConnectionClosed, ClientError::Contradiction));
            };
            match frame {
                Frame::Ack { block_cid } => return Ok(block_cid),
                Frame::Error { code, message, .. } => {
                    // Refusing a kind the welcome advertised contradicts it.
                    if code == DISALLOWED_BLOCK_KIND
                        && let Some(kind) = block_kind(&block)
                        && self
                            .welcome
                            .as_ref()
                            .is_some_and(|w| w.capabilities.block_kinds.contains(&kind))
                    {
                        let error = Envelope::new(Frame::Error {
                            status: None,
                            code: code.clone(),
                            ref_cid: None,
                            message: message.clone(),
                        });
                        contradicted(
                            &self.contradiction,
                            &self.write_tx,
                            format!(
                                "the server refused `{kind}`, a block kind its welcome advertises"
                            ),
                            vec![
                                self.welcome
                                    .as_ref()
                                    .map(|w| w.evidence.clone())
                                    .unwrap_or_default(),
                                serde_json::to_string(&error)?,
                            ],
                        );
                        return Err(ClientError::Contradiction(
                            self.contradiction().expect("just recorded"),
                        ));
                    }
                    return Err(ClientError::ServerError { code, message });
                }
                // Ignore other non-Block frames while waiting for ack;
                // Block frames go directly to the per-channel subscriber.
                _ => continue,
            }
        }
    }

    /// Returns the server URL this client was constructed with.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Returns the DID of the identity this client is signing with.
    pub fn identity_did(&self) -> String {
        self.identity.did_string()
    }

    /// Returns the last cursor seen for an origin (best-effort; populated
    /// by the reader task as blocks arrive). v0.0.2 uses placeholder
    /// cursors; Phase D wires in real HLC parsing.
    pub async fn last_cursor(&self, origin: &str) -> Option<HlcCursor> {
        self.last_cursors.lock().await.get(origin).cloned()
    }
}

/// The code a server refuses a disallowed block kind with.
const DISALLOWED_BLOCK_KIND: &str = "DISALLOWED_BLOCK_KIND";

/// The kind `block` declares, as the welcome names kinds.
fn block_kind(block: &BuiltBlock) -> Option<String> {
    let manifest: jig_core::BlockManifest = serde_json::from_slice(&block.manifest_bytes).ok()?;
    manifest.kind.map(|kind| kind.as_str().to_string())
}

fn lock_contradiction(
    slot: &StdMutex<Option<Contradiction>>,
) -> MutexGuard<'_, Option<Contradiction>> {
    slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Record the first contradiction and close the connection with
/// [`jig_pipeline::handshake::close::CONTRADICTION`]. A later one is dropped:
/// the connection is already ending.
fn contradicted(
    slot: &StdMutex<Option<Contradiction>>,
    write_tx: &mpsc::UnboundedSender<Message>,
    reason: String,
    evidence: Vec<String>,
) {
    let mut guard = lock_contradiction(slot);
    if guard.is_some() {
        return;
    }
    tracing::warn!("closing: the server contradicted what it signed: {reason}");
    *guard = Some(Contradiction { reason, evidence });
    let _ = write_tx.send(close_frame(
        jig_pipeline::handshake::close::CONTRADICTION,
        "contradiction",
    ));
}

fn close_frame(code: u16, reason: &str) -> Message {
    use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
    Message::Close(Some(CloseFrame {
        code: CloseCode::from(code),
        reason: reason.into(),
    }))
}

/// Send hello and read the first frame. `Err` means the handshake did not
/// establish: the caller closes with the code the error's class names.
async fn drive_handshake(
    sink: &mut (impl futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    stream: &mut (
             impl futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
             + Unpin
         ),
    offer: &jig_pipeline::handshake::ClientOffer,
) -> Result<jig_pipeline::handshake::VerifiedWelcome, ClientError> {
    use futures_util::SinkExt;

    let (hello, pending) = jig_pipeline::handshake::begin(offer);
    let json = serde_json::to_string(&hello)?;
    sink.send(Message::Text(json.into()))
        .await
        .map_err(|err| ClientError::Connect(err.to_string()))?;

    // One deadline for the whole wait. A Ping or Pong must not start it over,
    // or a peer can hold the connection open past WELCOME_WAIT.
    let deadline = tokio::time::Instant::now() + jig_pipeline::handshake::WELCOME_WAIT;
    loop {
        let next = tokio::time::timeout_at(deadline, stream.next()).await;
        let message = match next {
            Err(_) => {
                return Err(ClientError::HandshakeFailed {
                    reason: "timed out waiting for a welcome".to_string(),
                    evidence: None,
                });
            }
            Ok(None) => {
                return Err(ClientError::HandshakeFailed {
                    reason: "connection closed before a welcome".to_string(),
                    evidence: None,
                });
            }
            Ok(Some(Err(err))) => {
                return Err(ClientError::Connect(err.to_string()));
            }
            Ok(Some(Ok(message))) => message,
        };
        match message {
            Message::Text(text) => {
                use jig_pipeline::handshake::HandshakeResult;
                return match pending.interpret(&text) {
                    HandshakeResult::Established(welcome) => Ok(welcome),
                    HandshakeResult::Incompatible(refusal) => {
                        Err(ClientError::Incompatible(Box::new(refusal)))
                    }
                    HandshakeResult::FailClosed { reason, evidence } => {
                        Err(ClientError::HandshakeFailed { reason, evidence })
                    }
                    HandshakeResult::Contradiction { reason, evidence } => {
                        Err(ClientError::Contradiction(Contradiction {
                            reason,
                            evidence: vec![evidence],
                        }))
                    }
                };
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => {
                return Err(ClientError::HandshakeFailed {
                    reason: "connection closed before a welcome".to_string(),
                    evidence: None,
                });
            }
            _ => {
                return Err(ClientError::HandshakeFailed {
                    reason: "first frame is not a welcome".to_string(),
                    evidence: None,
                });
            }
        }
    }
}

// Re-export the envelope types through jig_client::envelope for callers
// that don't want to depend on jig-pipeline directly.
pub mod envelope {
    pub use jig_pipeline::envelope::{
        Envelope, Frame, HlcCursor, ReceiptRef, Scope, SubscribeAuth,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio_tungstenite::accept_async;

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        jig_core::crypto::ed25519::generate_signing_key()
    }

    /// A correct welcome for a hello frame, or `None` when `text` is not a hello.
    fn welcome_reply(text: &str, key: &ed25519_dalek::SigningKey) -> Option<String> {
        let env: Envelope = serde_json::from_str(text).ok()?;
        let Frame::Hello {
            versions,
            suites,
            capabilities,
            nonce,
        } = env.frame
        else {
            return None;
        };
        let reply = match jig_pipeline::handshake::negotiate(
            &jig_pipeline::handshake::HelloView {
                versions,
                suites,
                capabilities,
                nonce,
            },
            &jig_pipeline::handshake::ServerOffer {
                capabilities: jig_pipeline::handshake::Capabilities {
                    block_kinds: vec!["text-render".to_string()],
                    execution: true,
                    federation: false,
                },
            },
        ) {
            Ok(statement) => jig_pipeline::handshake::seal(key, statement),
            Err(refusal) => jig_pipeline::handshake::seal_refusal(key, &refusal, &nonce_of(text)),
        };
        Some(serde_json::to_string(&reply).unwrap())
    }

    fn nonce_of(hello: &str) -> String {
        match serde_json::from_str::<Envelope>(hello).map(|env| env.frame) {
            Ok(Frame::Hello { nonce, .. }) => nonce,
            _ => panic!("not a hello: {hello}"),
        }
    }

    /// One connection: answers hello with a signed welcome, then sends each
    /// of `after_welcome` as raw text, then reports the close code the client
    /// sends, if any.
    async fn start_scripted_server(
        after_welcome: Vec<String>,
    ) -> (String, Arc<StdMutex<Option<u16>>>) {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let close_code = Arc::new(StdMutex::new(None));
        let close_for_server = close_code.clone();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut ws) = accept_async(stream).await else {
                return;
            };
            let key = test_signing_key();
            while let Some(Ok(msg)) = ws.next().await {
                if let Message::Text(text) = msg
                    && let Some(reply) = welcome_reply(&text, &key)
                {
                    let _ = ws.send(Message::Text(reply.into())).await;
                    break;
                }
            }
            for text in after_welcome {
                let _ = ws.send(Message::Text(text.into())).await;
            }
            while let Some(Ok(msg)) = ws.next().await {
                if let Message::Close(frame) = msg {
                    *close_for_server.lock().unwrap() = frame.map(|f| u16::from(f.code));
                    break;
                }
            }
        });
        (url, close_code)
    }

    /// Wait until the client records a contradiction, or fail.
    async fn await_contradiction(client: &Client) -> Contradiction {
        for _ in 0..50 {
            if let Some(c) = client.contradiction() {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no contradiction recorded");
    }

    fn test_identity() -> Identity {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep();
        Identity::generate_and_save(&path).unwrap()
    }

    /// Spin up a tiny WS server on an ephemeral port. The handler closure
    /// receives one frame and may send any number of replies; it's
    /// configurable via the `on_recv` argument so each test can script
    /// the expected dialogue.
    async fn start_test_server<F, Fut>(on_recv: F) -> (String, Arc<AtomicUsize>)
    where
        F: Fn(Envelope) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Vec<Envelope>> + Send + 'static,
    {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://{addr}");
        let frame_counter = Arc::new(AtomicUsize::new(0));
        let counter_for_server = frame_counter.clone();
        let on_recv = Arc::new(on_recv);

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let on_recv = on_recv.clone();
                let counter = counter_for_server.clone();
                tokio::spawn(async move {
                    let Ok(ws) = accept_async(stream).await else {
                        return;
                    };
                    let key = test_signing_key();
                    let (mut sink, mut stream) = ws.split();
                    while let Some(Ok(msg)) = stream.next().await {
                        if let Message::Text(text) = msg {
                            counter.fetch_add(1, Ordering::SeqCst);
                            if let Some(reply) = welcome_reply(&text, &key) {
                                let _ = sink.send(Message::Text(reply.into())).await;
                                continue;
                            }
                            let Ok(env) = serde_json::from_str::<Envelope>(&text) else {
                                continue;
                            };
                            let replies = on_recv(env).await;
                            for r in replies {
                                let json = serde_json::to_string(&r).unwrap();
                                let _ = sink.send(Message::Text(json.into())).await;
                            }
                        }
                    }
                });
            }
        });

        (url, frame_counter)
    }

    /// Accepts one WS connection, answers hello with a signed welcome, then
    /// consumes `frames_before_close` further text frames and closes.
    ///
    /// `0` is "the link dies as soon as the handshake finishes", which is what
    /// the submit-after-close tests need: `connect` itself has to succeed.
    async fn start_closing_test_server(frames_before_close: usize) -> String {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://{addr}");

        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut ws) = accept_async(stream).await else {
                return;
            };
            let key = test_signing_key();
            loop {
                match ws.next().await {
                    Some(Ok(Message::Text(text))) => {
                        if let Some(reply) = welcome_reply(&text, &key) {
                            let _ = ws.send(Message::Text(reply.into())).await;
                            break;
                        }
                    }
                    Some(Ok(_)) => continue,
                    _ => return,
                }
            }
            let mut seen = 0;
            while seen < frames_before_close {
                match ws.next().await {
                    Some(Ok(Message::Text(_))) => seen += 1,
                    Some(Ok(_)) => continue,
                    _ => break,
                }
            }
            let _ = ws.close(None).await;
            drop(ws);
        });

        url
    }

    /// One connection. The closure builds the reply to the first text frame.
    /// `texts` counts text frames received; `closed` flips when the socket ends.
    async fn start_probe_server<F>(reply: F) -> (String, Arc<AtomicUsize>, Arc<AtomicBool>)
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://{addr}");
        let texts = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let texts_for_server = texts.clone();
        let closed_for_server = closed.clone();
        let reply = Arc::new(reply);

        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                closed_for_server.store(true, Ordering::SeqCst);
                return;
            };
            let Ok(mut ws) = accept_async(stream).await else {
                closed_for_server.store(true, Ordering::SeqCst);
                return;
            };
            let mut answered = false;
            loop {
                match ws.next().await {
                    Some(Ok(Message::Text(text))) => {
                        texts_for_server.fetch_add(1, Ordering::SeqCst);
                        if !answered {
                            answered = true;
                            let body = reply(&text);
                            if ws.send(Message::Text(body.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break,
                }
            }
            closed_for_server.store(true, Ordering::SeqCst);
        });

        (url, texts, closed)
    }

    /// Regression guard for the "silent zombie" bug: when the server goes
    /// away, every [`BlockStream`] must terminate so callers can notice.
    /// Before the reader-task cleanup existed, the subscription's sender was
    /// never dropped and `next()` blocked forever.
    #[tokio::test]
    async fn block_stream_ends_when_server_closes() {
        let url = start_closing_test_server(1).await;
        let id = test_identity();
        let client = Client::connect(&url, id).await.unwrap();
        let mut stream = client.subscribe_channel("#hello").await.unwrap();

        let ended = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;
        match ended {
            Ok(None) => {}
            Ok(Some(block)) => panic!("expected stream end, got block {block:?}"),
            Err(_) => panic!("stream never ended after server closed (silent zombie)"),
        }
    }

    /// A submit on a dead connection must fail fast rather than waiting out
    /// the 5s ack timeout.
    #[tokio::test]
    async fn submit_after_close_returns_error() {
        use crate::blocks::build_text_render;
        use jig_core::HlcTimestamp;

        let url = start_closing_test_server(0).await;
        let id = test_identity();
        let client = Client::connect(&url, id).await.unwrap();
        // Let the reader task observe the closed socket before we submit.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let hlc = HlcTimestamp {
            wall_ms: 0,
            logical: 0,
            server_did: client.identity.did().clone(),
        };
        let block = build_text_render(&client.identity, "#hello", "hi", hlc);

        let started = std::time::Instant::now();
        let err = client.submit(block).await.unwrap_err();
        let elapsed = started.elapsed();

        assert!(
            matches!(err, ClientError::ConnectionClosed),
            "expected ConnectionClosed, got {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "submit took {elapsed:?}; it waited out the ack timeout instead of failing fast"
        );
    }

    /// Subscribing after the connection is already dead must fail loudly
    /// rather than handing back a stream that can never yield or end.
    #[tokio::test]
    async fn subscribe_after_close_returns_error() {
        let url = start_closing_test_server(0).await;
        let id = test_identity();
        let client = Client::connect(&url, id).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // `BlockStream` has no Debug impl, so match instead of unwrap_err.
        match client.subscribe_channel("#hello").await {
            Err(ClientError::ConnectionClosed) => {}
            Err(other) => panic!("expected ConnectionClosed, got {other:?}"),
            Ok(_) => panic!("expected ConnectionClosed, got a stream that can never yield"),
        }
    }

    #[tokio::test]
    async fn connect_succeeds_against_test_server() {
        let (url, _) = start_test_server(|_env| async move { vec![] }).await;
        let id = test_identity();
        let client = Client::connect(&url, id).await.unwrap();
        assert_eq!(client.server_url(), &url);
    }

    #[tokio::test]
    async fn connect_fails_on_bad_url() {
        let id = test_identity();
        let err = Client::connect("not a url", id).await.unwrap_err();
        assert!(matches!(err, ClientError::BadUrl(_)));
    }

    #[tokio::test]
    async fn submit_returns_block_cid_on_ack() {
        let (url, frame_counter) = start_test_server(|env| async move {
            // Echo back an Ack for any Submit frame
            match env.frame {
                Frame::Submit { .. } => vec![Envelope::new(Frame::Ack {
                    block_cid: "bafy_test_ack".to_string(),
                })],
                _ => vec![],
            }
        })
        .await;

        let id = test_identity();
        let client = Client::connect(&url, id).await.unwrap();
        // Build a trivial block
        use crate::blocks::build_text_render;
        use jig_core::HlcTimestamp;
        let hlc = HlcTimestamp {
            wall_ms: 0,
            logical: 0,
            server_did: client.identity.did().clone(),
        };
        let block = build_text_render(&client.identity, "#hello", "hi", hlc);
        let cid = client.submit(block).await.unwrap();
        assert_eq!(cid, "bafy_test_ack");
        assert!(frame_counter.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn submit_returns_server_error_on_error_frame() {
        let (url, _) = start_test_server(|env| async move {
            match env.frame {
                Frame::Submit { .. } => vec![Envelope::new(Frame::Error {
                    status: None,
                    code: "INVALID_SIG".to_string(),
                    ref_cid: None,
                    message: "signature verification failed".to_string(),
                })],
                _ => vec![],
            }
        })
        .await;

        let id = test_identity();
        let client = Client::connect(&url, id).await.unwrap();
        use crate::blocks::build_text_render;
        use jig_core::HlcTimestamp;
        let hlc = HlcTimestamp {
            wall_ms: 0,
            logical: 0,
            server_did: client.identity.did().clone(),
        };
        let block = build_text_render(&client.identity, "#hello", "hi", hlc);
        let err = client.submit(block).await.unwrap_err();
        match err {
            ClientError::ServerError { code, .. } => assert_eq!(code, "INVALID_SIG"),
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribe_channel_streams_delivered_blocks() {
        let (url, _) = start_test_server(|env| async move {
            match env.frame {
                Frame::Subscribe { .. } => vec![Envelope::new(Frame::Block {
                    bundle_b64: "dGVzdC1ibG9jaw==".to_string(),
                    sig_b64: None,
                    receipts: vec![],
                    delivery_cid: "bafy_delivery_1".to_string(),
                    ingest: None,
                })],
                _ => vec![],
            }
        })
        .await;

        let id = test_identity();
        let client = Client::connect(&url, id).await.unwrap();
        let mut stream = client.subscribe_channel("#hello").await.unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("timeout waiting for block")
            .expect("stream closed");
        assert_eq!(delivered.bundle_b64, "dGVzdC1ibG9jaw==");
        assert_eq!(delivered.delivery_cid, "bafy_delivery_1");
    }

    /// Guards the cross-lane contract: `GET /api/v1/channels/:slug/blocks`
    /// returns a JSON array that must deserialize into `Vec<DeliveredBlock>`.
    #[test]
    fn delivered_block_round_trips_through_json() {
        let original = DeliveredBlock {
            sig_b64: None,
            bundle_b64: "dGVzdC1ibG9jaw==".to_string(),
            receipts: vec![ReceiptRef {
                server_did: "did:jig:zServer".to_string(),
                render_hash: Some("blake3:abc123".to_string()),
                receipt_bytes_b64: "cmVjZWlwdA==".to_string(),
            }],
            delivery_cid: "bafy_delivery_1".to_string(),
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: DeliveredBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.bundle_b64, original.bundle_b64);
        assert_eq!(decoded.delivery_cid, original.delivery_cid);
        assert_eq!(decoded.receipts.len(), 1);
        assert_eq!(decoded.receipts[0].server_did, "did:jig:zServer");
        assert_eq!(
            decoded.receipts[0].render_hash.as_deref(),
            Some("blake3:abc123")
        );
        assert_eq!(decoded.receipts[0].receipt_bytes_b64, "cmVjZWlwdA==");
    }

    #[test]
    fn delivered_block_vec_round_trips_as_json_array() {
        let blocks = vec![
            DeliveredBlock {
                sig_b64: None,
                bundle_b64: "YQ==".to_string(),
                receipts: vec![],
                delivery_cid: "bafy_a".to_string(),
            },
            DeliveredBlock {
                sig_b64: None,
                bundle_b64: "Yg==".to_string(),
                receipts: vec![],
                delivery_cid: "bafy_b".to_string(),
            },
        ];
        let json = serde_json::to_string(&blocks).unwrap();
        assert!(json.starts_with('['));
        let decoded: Vec<DeliveredBlock> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[1].delivery_cid, "bafy_b");
    }

    #[tokio::test]
    async fn identity_did_returns_canonical_form() {
        let (url, _) = start_test_server(|_| async { vec![] }).await;
        let id = test_identity();
        let expected_did = id.did_string();
        let client = Client::connect(&url, id).await.unwrap();
        assert_eq!(client.identity_did(), expected_did);
        assert!(client.identity_did().starts_with("did:jig:z"));
    }

    #[tokio::test]
    async fn connect_keeps_a_signed_welcome() {
        let (url, _) = start_test_server(|_| async { vec![] }).await;
        let client = Client::connect(&url, test_identity()).await.unwrap();
        let welcome = client.welcome().expect("a verified welcome");
        assert_eq!(welcome.version, 1);
        assert_eq!(welcome.suites, vec!["none".to_string(), "mls".to_string()]);
        assert!(welcome.reputation.is_null());
        assert_eq!(
            welcome.capabilities.block_kinds,
            vec!["text-render".to_string()]
        );
        assert!(welcome.capabilities.execution);
        assert!(!welcome.capabilities.federation);
        assert!(welcome.server_did.starts_with("did:jig:z"));
        assert!(client.contradiction().is_none());
    }

    #[tokio::test]
    async fn connect_fails_closed_when_the_welcome_is_missing() {
        let (url, texts, closed) = start_probe_server(|_hello| {
            serde_json::to_string(&Envelope::new(Frame::Ack {
                block_cid: "bafy".to_string(),
            }))
            .unwrap()
        })
        .await;
        let err = Client::connect(&url, test_identity()).await.unwrap_err();
        match err {
            ClientError::HandshakeFailed { reason, evidence } => {
                assert!(reason.contains("not a welcome"), "{reason}");
                assert!(evidence.is_some());
            }
            other => panic!("expected fail closed, got {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            texts.load(Ordering::SeqCst),
            1,
            "a failed handshake must not send another frame"
        );
        assert!(
            closed.load(Ordering::SeqCst),
            "a missing welcome must close the connection"
        );
    }

    #[tokio::test]
    async fn connect_fails_closed_when_the_welcome_contradicts_itself() {
        let (url, texts, closed) = start_probe_server(|hello| {
            let key = test_signing_key();
            let env: Envelope = serde_json::from_str(hello).unwrap();
            let Frame::Hello { nonce, .. } = env.frame else {
                panic!("client's first frame must be hello");
            };
            let mut statement = jig_pipeline::handshake::negotiate(
                &jig_pipeline::handshake::HelloView {
                    versions: vec![1],
                    suites: vec!["none".to_string()],
                    capabilities: jig_pipeline::handshake::Capabilities::default(),
                    nonce,
                },
                &jig_pipeline::handshake::ServerOffer {
                    capabilities: jig_pipeline::handshake::Capabilities::default(),
                },
            )
            .unwrap();
            // Signed, but the frame is carried as `none` while the advertisement
            // says the server only implements `mls`.
            statement.suites = vec!["mls".to_string()];
            serde_json::to_string(&jig_pipeline::handshake::seal(&key, statement)).unwrap()
        })
        .await;
        let err = Client::connect(&url, test_identity()).await.unwrap_err();
        match err {
            ClientError::HandshakeFailed { reason, evidence } => {
                assert!(reason.contains("contradicts itself"), "{reason}");
                assert!(evidence.is_some());
            }
            other => panic!("expected fail closed, got {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(texts.load(Ordering::SeqCst), 1);
        assert!(closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_signed_refusal_is_an_incompatibility() {
        let (url, texts, _closed) = start_probe_server(|hello| {
            serde_json::to_string(&jig_pipeline::handshake::seal_refusal(
                &test_signing_key(),
                &jig_pipeline::handshake::HelloRefusal::UnsupportedVersion(
                    "server speaks envelope v1".to_string(),
                ),
                &nonce_of(hello),
            ))
            .unwrap()
        })
        .await;
        match Client::connect(&url, test_identity()).await {
            Err(ClientError::Incompatible(refusal)) => {
                assert_eq!(refusal.code, "UNSUPPORTED_VERSION");
            }
            other => panic!("expected an incompatibility, got {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(texts.load(Ordering::SeqCst), 1, "nothing follows a refusal");
    }

    #[tokio::test]
    async fn an_unsigned_refusal_fails_closed() {
        let (url, _texts, closed) = start_probe_server(|_| {
            serde_json::to_string(&Envelope::new(Frame::Error {
                status: Some(400),
                code: "UNSUPPORTED_VERSION".to_string(),
                ref_cid: None,
                message: "server speaks envelope v1".to_string(),
            }))
            .unwrap()
        })
        .await;
        assert!(matches!(
            Client::connect(&url, test_identity()).await,
            Err(ClientError::HandshakeFailed { .. })
        ));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(closed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_frame_outside_the_welcome_is_a_contradiction() {
        let v2 = r##"{"v":2,"op":"ack","block_cid":"bafy"}"##.to_string();
        let (url, close_code) = start_scripted_server(vec![v2.clone()]).await;
        let client = Client::connect(&url, test_identity()).await.unwrap();
        let contradiction = await_contradiction(&client).await;
        assert!(contradiction.reason.contains("outside the signed welcome"));
        assert_eq!(contradiction.evidence[1], v2);
        assert_eq!(
            contradiction.evidence[0],
            client.welcome().unwrap().evidence,
            "the evidence starts with the signed welcome"
        );
        assert!(matches!(
            client.subscribe_channel("#hello").await,
            Err(ClientError::Contradiction(_))
        ));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            *close_code.lock().unwrap(),
            Some(jig_pipeline::handshake::close::CONTRADICTION)
        );
    }

    #[tokio::test]
    async fn a_second_welcome_is_a_contradiction() {
        let again = serde_json::to_string(&Envelope::new(Frame::Welcome {
            server_did: "did:jig:zElsewhere".to_string(),
            suites: vec!["none".to_string()],
            capabilities: Default::default(),
            reputation: jig_pipeline::handshake::Reputation::none(),
            nonce: "n".to_string(),
            sig: String::new(),
        }))
        .unwrap();
        let (url, _) = start_scripted_server(vec![again]).await;
        let client = Client::connect(&url, test_identity()).await.unwrap();
        assert!(
            await_contradiction(&client)
                .await
                .reason
                .contains("second handshake")
        );
    }

    #[tokio::test]
    async fn a_receipt_from_another_key_is_a_contradiction() {
        let stranger =
            jig_core::Did::from_ed25519_pubkey(test_signing_key().verifying_key().as_bytes())
                .to_did_jig_string();
        let block = serde_json::to_string(&Envelope::new(Frame::Block {
            bundle_b64: "YQ==".to_string(),
            sig_b64: None,
            receipts: vec![ReceiptRef {
                server_did: stranger.clone(),
                render_hash: None,
                receipt_bytes_b64: String::new(),
            }],
            delivery_cid: "delivery:bafy".to_string(),
            ingest: None,
        }))
        .unwrap();
        let (url, _) = start_scripted_server(vec![block]).await;
        let client = Client::connect(&url, test_identity()).await.unwrap();
        assert!(
            await_contradiction(&client)
                .await
                .reason
                .contains(&stranger)
        );
    }

    #[tokio::test]
    async fn a_frame_that_does_not_parse_is_not_a_contradiction() {
        let (url, close_code) = start_scripted_server(vec!["{not json".to_string()]).await;
        let client = Client::connect(&url, test_identity()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(client.contradiction().is_none());
        assert_eq!(*close_code.lock().unwrap(), None);
    }

    #[tokio::test]
    async fn refusing_an_advertised_kind_is_a_contradiction() {
        let (url, _) = start_test_server(|env| async move {
            match env.frame {
                Frame::Submit { .. } => vec![Envelope::new(Frame::Error {
                    status: Some(403),
                    code: "DISALLOWED_BLOCK_KIND".to_string(),
                    ref_cid: None,
                    message: "kind not in allow list: text-render".to_string(),
                })],
                _ => vec![],
            }
        })
        .await;
        let id = test_identity();
        let hlc = jig_core::HlcTimestamp::now_wall(id.did().clone());
        let block = crate::blocks::build_text_render(&id, "#hello", "hi", hlc);
        let client = Client::connect(&url, id).await.unwrap();
        match client.submit(block).await {
            Err(ClientError::Contradiction(c)) => assert!(c.reason.contains("text-render")),
            other => panic!("expected a contradiction, got {other:?}"),
        }
        assert!(client.contradiction().is_some());
    }
}
