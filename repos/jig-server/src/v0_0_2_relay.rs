//! Writes through a follower (JEP-0005 rules 7a and 15), over the peer
//! connection both servers proved their DIDs on ([`crate::v0_0_2_peer`]).
//!
//! A client posts to the server it is authenticated to. When that server
//! carries the channel for its owner, the block cannot land there
//! (`CARRIED_CHANNEL`, rule 12). If this server's share of the channel has a
//! grant that relays the block's kind, the block goes on to the owner instead:
//! - the follower has already run its own admission, proof of work and rate
//!   limits on the client, and checked the author's signature (ingest's steps
//!   1 and 1b run before it finds the channel carried);
//! - it checks the grant itself, so the owner never sees a write it would
//!   refuse for that, and it holds at most [`MAX_IN_FLIGHT`] relays per
//!   client connection (each REST request is its own, and its address is
//!   the client), [`MAX_CLIENT_IN_FLIGHT`] per client and
//!   [`MAX_SERVER_IN_FLIGHT`] in all, refusing past any of them with
//!   `RELAY_BUSY` and when to try again. Nothing waits in a queue: a write
//!   the owner cannot take now is refused with a code, never dropped (this
//!   replaces F2's caps on writes queued while a sequencer is down, DJ
//!   2026-11-26);
//! - it sends the block in a [`RELAY_SUBMIT_FRAME`] and answers the client
//!   with the owner's [`RELAY_RESULT_FRAME`]: the block's CID, or the owner's
//!   refusal code. The block lands here only through the owner's stream,
//!   with the owner's record, like every other block of the channel.
//!
//! If the owner is not connected, the client is told `OWNER_UNREACHABLE` with
//! when to try again. If the owner does not answer within [`RELAY_TIMEOUT`],
//! the client is told `RELAY_PENDING`: the outcome is unknown, and submitting
//! the same signed block again is safe, because the owner takes a block it
//! already holds as accepted, before any effect.
//!
//! The owner counts each relayed write against the follower's quota
//! ([`PeerQuotas`], shared with the stream) and holds at most
//! [`MAX_PEER_IN_FLIGHT`] of a follower's writes at once, both before any
//! task or lookup. It takes a relayed block only from a peer holding an
//! accepted share of the channel it names, at most
//! `[federation.relayed_writes]` per peer and channel, and runs its full write gate on it with
//! [`IngestSource::Relayed`]: the author's signature, its write and role
//! checks, the grant, and the relayed admission. Admission is the follower's
//! to do (delegated admission): the owner does not ask a relayed author for
//! proof of work, which the author could only have done for the follower. It
//! still refuses a banned author and one below its floors. The follower
//! answers for what it relays through its share: the owner records its DID
//! with every block, limits it per channel, and can end the share.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use jig_config::v0_0_2_server::FederationSection;
use jig_core::BlockBundle;
use jig_core::block_kind::BlockKind;
use jig_core::dcbor::{self, Value};
use jig_core::did::Did;
use jig_pipeline::contracts::{OfferState, Side};
use jig_pipeline::ingest::{IngestContext, IngestError, IngestSource, ingest};
use tokio::sync::oneshot;

use crate::v0_0_2_peer::{CloseReason, PeerRegistry, PeerSender};
use crate::v0_0_2_stream::{PeerQuotas, RequestLimit};

/// A follower's relay of one client block to the channel's owner.
pub const RELAY_SUBMIT_FRAME: &str = "relay-submit";
/// The owner's answer to one [`RELAY_SUBMIT_FRAME`].
pub const RELAY_RESULT_FRAME: &str = "relay-result";

/// How long a follower holds a client's write for the owner's answer.
pub const RELAY_TIMEOUT: Duration = Duration::from_secs(10);

/// The most relays one client connection may have waiting on the owner.
pub const MAX_IN_FLIGHT: usize = 4;
/// The most relays one client may have waiting, over all its connections:
/// its DID on WSS, its address on REST (DJ 2026-11-26).
pub const MAX_CLIENT_IN_FLIGHT: usize = 16;
/// The most relays this server holds waiting on owners, from every client
/// together. Nothing is queued past this: a write is refused, never dropped.
pub const MAX_SERVER_IN_FLIGHT: usize = 1024;
/// The most relayed writes one follower may have this server working on at
/// once, on the owner's side.
pub const MAX_PEER_IN_FLIGHT: usize = 64;
/// What a client is told to wait when this server's relay slots are full,
/// before [`crate::v0_0_2_ingest_error::jitter`]. A slot frees within
/// [`RELAY_TIMEOUT`] at the latest.
pub const BUSY_RETRY: Duration = Duration::from_secs(1);

/// What a client is told to wait when the owner is not connected, before
/// [`crate::v0_0_2_ingest_error::jitter`].
pub const UNREACHABLE_RETRY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Submit {
    pub(crate) request_id: u64,
    pub(crate) channel_id: String,
    /// The block's canonical bundle bytes.
    pub(crate) bundle: Vec<u8>,
    /// The author's signature over them.
    pub(crate) sig: Vec<u8>,
}

/// The owner's answer. Accepted when `code` is empty, with the block's CID;
/// otherwise refused, with the status, code and message the owner's own
/// clients would get, and `retry_after_ms` when a retry may succeed (0
/// otherwise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    pub(crate) request_id: u64,
    pub(crate) block_cid: String,
    pub(crate) status: u16,
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) retry_after_ms: u64,
}

/// A map with exactly `keys`, or `None`.
fn fields<'a>(value: &'a Value, keys: &[&str]) -> Option<Vec<&'a Value>> {
    let Value::Map(entries) = value else {
        return None;
    };
    if entries.len() != keys.len() {
        return None;
    }
    keys.iter().map(|k| value.get(k)).collect()
}

impl Submit {
    pub(crate) fn encode(&self) -> Vec<u8> {
        dcbor::encode(&Value::text_map([
            ("request_id", Value::Unsigned(self.request_id)),
            ("channel_id", Value::text(&self.channel_id)),
            ("bundle", Value::Bytes(self.bundle.clone())),
            ("sig", Value::Bytes(self.sig.clone())),
        ]))
        .expect("text keys never repeat")
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let value = dcbor::decode(bytes).ok()?;
        let [request_id, channel_id, bundle, sig] =
            fields(&value, &["request_id", "channel_id", "bundle", "sig"])?[..]
        else {
            return None;
        };
        Some(Submit {
            request_id: request_id.as_u64()?,
            channel_id: channel_id.as_text()?.to_string(),
            bundle: bundle.as_bytes()?.to_vec(),
            sig: sig.as_bytes()?.to_vec(),
        })
    }
}

impl Answer {
    fn accepted(request_id: u64, block_cid: String) -> Self {
        Answer {
            request_id,
            block_cid,
            status: StatusCode::OK.as_u16(),
            code: String::new(),
            message: String::new(),
            retry_after_ms: 0,
        }
    }

    fn refused(request_id: u64, status: StatusCode, code: &str, message: String) -> Self {
        Answer {
            request_id,
            block_cid: String::new(),
            status: status.as_u16(),
            code: code.to_string(),
            message,
            retry_after_ms: 0,
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        dcbor::encode(&Value::text_map([
            ("request_id", Value::Unsigned(self.request_id)),
            ("block_cid", Value::text(&self.block_cid)),
            ("status", Value::Unsigned(u64::from(self.status))),
            ("code", Value::text(&self.code)),
            ("message", Value::text(&self.message)),
            ("retry_after_ms", Value::Unsigned(self.retry_after_ms)),
        ]))
        .expect("text keys never repeat")
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let value = dcbor::decode(bytes).ok()?;
        let [request_id, block_cid, status, code, message, retry_after_ms] = fields(
            &value,
            &[
                "request_id",
                "block_cid",
                "status",
                "code",
                "message",
                "retry_after_ms",
            ],
        )?[..] else {
            return None;
        };
        Some(Answer {
            request_id: request_id.as_u64()?,
            block_cid: block_cid.as_text()?.to_string(),
            status: u16::try_from(status.as_u64()?).ok()?,
            code: code.as_text()?.to_string(),
            message: message.as_text()?.to_string(),
            retry_after_ms: retry_after_ms.as_u64()?,
        })
    }
}

/// Why a client's write did not land: what the client is told, on whichever
/// surface it posted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    /// How long to wait before posting again, for a refusal waiting changes:
    /// the client's `Error` frame carries it as `retry_after_ms`.
    pub retry_after_ms: Option<u64>,
}

impl Refusal {
    fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        Refusal {
            status,
            code: code.to_string(),
            message: message.into(),
            retry_after_ms: None,
        }
    }

    /// The refusal for an ingest error, as every surface classifies it.
    pub fn of(e: &IngestError) -> Self {
        use crate::v0_0_2_ingest_error::{classify_with_wait, jitter, millis, retry_after};
        // One draw, said in the message and carried in the field.
        let wait = retry_after(e).map(jitter);
        let (status, code, message) = classify_with_wait(e, wait);
        Refusal {
            retry_after_ms: wait.map(millis),
            ..Refusal::new(status, code, message)
        }
    }

    /// A refusal with when to post again: in `retry_after_ms`, and in the
    /// message for whoever reads it.
    fn retry(status: StatusCode, code: &str, message: &str, wait: Duration) -> Self {
        let ms = crate::v0_0_2_ingest_error::millis(wait);
        Refusal {
            retry_after_ms: Some(ms),
            ..Refusal::new(
                status,
                code,
                format!("{message}; try again in {ms} ms (retry_after_ms={ms})"),
            )
        }
    }
}

/// Requests waiting on an owner's answer, by request id: the owner each was
/// sent to, and where its answer goes.
type Pending = HashMap<u64, (String, oneshot::Sender<Answer>)>;

/// One server's side of every write it relays or takes relayed.
pub struct Relay {
    ctx: Arc<IngestContext>,
    federation: Arc<FederationSection>,
    peers: Arc<PeerRegistry>,
    /// The owner's limit on each follower's relayed writes.
    writes: RequestLimit,
    pending: Mutex<Pending>,
    next_id: AtomicU64,
    /// Relays waiting on an owner: per client connection, per client, and
    /// in all.
    in_flight: Arc<Mutex<InFlightCounts>>,
    /// Each peer's quota, shared with this server's stream.
    quotas: Arc<PeerQuotas>,
    /// Relayed writes the owner is working on, per follower.
    taking: Arc<Mutex<HashMap<String, usize>>>,
}

/// What [`Relay::hold`] counts.
#[derive(Default)]
struct InFlightCounts {
    conns: HashMap<String, usize>,
    clients: HashMap<String, usize>,
    total: usize,
}

/// Take one from `key`'s count, dropping the entry at zero.
fn release(counts: &mut HashMap<String, usize>, key: &str) {
    if let Some(n) = counts.get_mut(key) {
        *n -= 1;
        if *n == 0 {
            counts.remove(key);
        }
    }
}

/// One request waiting on its owner's answer, forgotten when its waiter goes,
/// however it goes.
struct Waiting<'a> {
    relay: &'a Relay,
    request_id: u64,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.relay.forget(self.request_id);
    }
}

/// One relay counted against its connection, its client and this server
/// while it waits.
struct InFlight {
    conn: String,
    client: String,
    counts: Arc<Mutex<InFlightCounts>>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        release(&mut counts.conns, &self.conn);
        release(&mut counts.clients, &self.client);
        counts.total -= 1;
    }
}

/// One relayed write the owner works on, counted against its follower.
struct Taking {
    peer: String,
    counts: Arc<Mutex<HashMap<String, usize>>>,
}

impl Drop for Taking {
    fn drop(&mut self) {
        release(
            &mut self.counts.lock().unwrap_or_else(|p| p.into_inner()),
            &self.peer,
        );
    }
}

impl Relay {
    pub fn new(
        ctx: Arc<IngestContext>,
        federation: Arc<FederationSection>,
        peers: Arc<PeerRegistry>,
    ) -> Self {
        Relay {
            ctx,
            peers,
            writes: RequestLimit::new(federation.relayed_writes),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            in_flight: Arc::new(Mutex::new(InFlightCounts::default())),
            quotas: Arc::new(PeerQuotas::new(federation.clone())),
            federation,
            taking: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Each peer's quota, for this server's stream to count against too.
    pub fn quotas(&self) -> Arc<PeerQuotas> {
        self.quotas.clone()
    }

    /// Handle a relay frame from `peer`, or `None` for a frame of another
    /// kind. A frame that does not parse closes the connection.
    pub fn on_peer_frame(
        self: &Arc<Self>,
        peer: &Did,
        kind: &str,
        body: &[u8],
        out: &PeerSender,
    ) -> Option<Result<(), CloseReason>> {
        match kind {
            RELAY_SUBMIT_FRAME => Some(self.on_submit(peer, body, out)),
            RELAY_RESULT_FRAME => Some(self.on_result(peer, body)),
            _ => None,
        }
    }

    // ---- The follower's side -----------------------------------------------

    /// Post a client's block on this server, relaying it to the channel's
    /// owner if this server carries the channel under a share whose grant
    /// relays it. `caller` names the client and its connection, for the
    /// in-flight caps.
    pub async fn submit(
        &self,
        manifest_bytes: &[u8],
        code_bytes: &[u8],
        sig: Vec<u8>,
        conn_id: u64,
        caller: &Caller,
        tiers: bool,
    ) -> Result<String, Refusal> {
        self.submit_as(
            IngestSource::LocalClient { conn_id, tiers },
            manifest_bytes,
            code_bytes,
            sig,
            caller,
        )
        .await
    }

    /// [`Relay::submit`] for a block that reaches this server as `source`:
    /// ingested here as that, and relayed to the owner, as any client write
    /// is, if it lands on a channel this server carries.
    pub async fn submit_as(
        &self,
        source: IngestSource,
        manifest_bytes: &[u8],
        code_bytes: &[u8],
        sig: Vec<u8>,
        caller: &Caller,
    ) -> Result<String, Refusal> {
        let bundle = BlockBundle {
            manifest_bytes,
            code_bytes,
            resources: vec![],
        };
        let refused = match ingest(&self.ctx, bundle, sig.clone(), source).await {
            Ok(cid) => return Ok(cid),
            Err(e) => e,
        };
        let IngestError::CarriedChannel {
            kind,
            channel_id,
            sequencer,
        } = &refused
        else {
            return Err(refusal_of(&self.ctx, &refused));
        };
        self.check_self_join(manifest_bytes, channel_id)?;
        let canonical = serde_json::to_vec(&(manifest_bytes, code_bytes))
            .map_err(|e| Refusal::of(&IngestError::BundleMalformed(e.to_string())))?;
        self.relay(
            &refused, kind, channel_id, sequencer, canonical, sig, caller,
        )
        .await
    }

    /// A self-join to a carried `shared` channel is relayed only if this
    /// server's roles count for it (`join_servers = granted`) and the
    /// joiner's role here meets its `join` (JEP-0014 rule 13). The owner
    /// cannot check that role: it is this server's judgement, and the
    /// owner's `member` grant is its trust in it. Any other block is the
    /// relay's to judge as before.
    fn check_self_join(&self, manifest_bytes: &[u8], channel_id: &str) -> Result<(), Refusal> {
        use jig_core::tier::{JoinServers, StoredTier, Tier};
        let Ok(manifest) = serde_json::from_slice::<jig_core::BlockManifest>(manifest_bytes) else {
            return Ok(());
        };
        let canonical = jig_pipeline::effect::canonical_did_string;
        let sender = manifest
            .authors
            .first()
            .map(|a| canonical(&a.did.to_string()));
        let adds_self = manifest.kind == Some(BlockKind::MemberAdd)
            && manifest
                .metadata
                .get("member_did")
                .and_then(|v| v.as_str())
                .map(canonical)
                .is_some_and(|member| Some(&member) == sender.as_ref());
        let Some(sender) = sender.filter(|_| adds_self) else {
            return Ok(());
        };
        let Some(channel) = self
            .ctx
            .store
            .get_channel_by_id(channel_id)
            .map_err(|e| Refusal::of(&IngestError::Persist(e)))?
        else {
            return Ok(());
        };
        let tiering = &channel.tiering;
        if !tiering.takes_self_join() {
            return Ok(());
        }
        let refused =
            |message: String| Err(Refusal::new(StatusCode::FORBIDDEN, "JOIN_REFUSED", message));
        if tiering.tier != StoredTier::Tier(Tier::Shared)
            || tiering.join_servers != Some(JoinServers::Granted)
        {
            return refused(format!(
                "channel {channel_id} takes self-joins only on the server that orders it, \
                 `{}`: join there",
                channel.sequencer_did
            ));
        }
        let role = self.ctx.admission.server_role(&sender);
        match tiering.join {
            Some(join) if role.may_join(join) => Ok(()),
            join => refused(format!(
                "your role on this server ({}) is below the one channel {channel_id} \
                 needs to join ({})",
                role.as_str(),
                join.map_or("none", |j| j.as_str())
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn relay(
        &self,
        refused: &IngestError,
        kind: &str,
        channel_id: &str,
        sequencer: &str,
        bundle: Vec<u8>,
        sig: Vec<u8>,
        caller: &Caller,
    ) -> Result<String, Refusal> {
        let owner = jig_pipeline::effect::canonical_did_string(sequencer);
        let share = self
            .ctx
            .store
            .contract_offers_for(channel_id, &owner, Side::Follower, OfferState::Accepted)
            .map_err(|e| Refusal::of(&IngestError::Persist(e)))?
            .pop();
        // No live share, or an owner no longer configured (DJ 2026-11-26):
        // the channel is carried, nothing more, and nothing is sent to it.
        let Some(share) = share.filter(|_| {
            crate::v0_0_2_federation::configured_peer(&self.federation, &owner).is_some()
        }) else {
            return Err(refusal_of(&self.ctx, refused));
        };
        let relays = kind
            .parse::<BlockKind>()
            .is_ok_and(|k| jig_core::contract::grant_allows(share.grant, k));
        if !relays {
            return Err(Refusal::new(
                StatusCode::FORBIDDEN,
                "GRANT_REFUSED",
                format!(
                    "`{kind}` refused: this server holds a `{}` share of channel {channel_id}, \
                     which does not relay it; post it to `{owner}` directly",
                    share.grant.as_str()
                ),
            ));
        }
        let _slot = self.hold(caller)?;
        let Ok(owner_did) = Did::from_did_jig_string(&owner) else {
            return Err(Refusal::of(refused));
        };
        let unreachable = || {
            Refusal::retry(
                StatusCode::SERVICE_UNAVAILABLE,
                "OWNER_UNREACHABLE",
                &format!("channel {channel_id}'s owner `{owner}` is not connected"),
                crate::v0_0_2_ingest_error::jitter(UNREACHABLE_RETRY),
            )
        };
        let Some(sender) = self.peers.sender_for(&owner_did) else {
            return Err(unreachable());
        };
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(request_id, (owner.clone(), tx));
        // Forgotten however this waiter ends: answered, timed out, or dropped
        // with the client's request.
        let _pending = Waiting {
            relay: self,
            request_id,
        };
        let body = Submit {
            request_id,
            channel_id: channel_id.to_string(),
            bundle,
            sig,
        }
        .encode();
        if sender.send(RELAY_SUBMIT_FRAME, body).is_err() {
            return Err(unreachable());
        }
        let answer = match tokio::time::timeout(RELAY_TIMEOUT, rx).await {
            Ok(Ok(answer)) => answer,
            // Timed out, or the connection went with the answer.
            _ => {
                return Err(Refusal::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    "RELAY_PENDING",
                    format!(
                        "channel {channel_id}'s owner `{owner}` has not answered; whether the \
                         block landed is unknown. Submitting the same signed block again is \
                         safe: the owner takes it once"
                    ),
                ));
            }
        };
        if answer.code.is_empty() {
            return Ok(answer.block_cid);
        }
        let status = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::BAD_GATEWAY);
        if answer.retry_after_ms > 0 {
            return Err(Refusal::retry(
                status,
                &answer.code,
                &answer.message,
                Duration::from_millis(answer.retry_after_ms),
            ));
        }
        Err(Refusal::new(status, &answer.code, answer.message))
    }

    /// Count one relay against `caller`'s connection, `caller` and this
    /// server, or refuse it past [`MAX_IN_FLIGHT`], [`MAX_CLIENT_IN_FLIGHT`]
    /// or [`MAX_SERVER_IN_FLIGHT`]: `RELAY_BUSY` each time, with when to try
    /// again.
    fn hold(&self, caller: &Caller) -> Result<InFlight, Refusal> {
        let mut counts = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
        let busy = |whose: &str, max: usize| {
            Err(Refusal::retry(
                StatusCode::TOO_MANY_REQUESTS,
                "RELAY_BUSY",
                &format!("{max} writes from {whose} are already waiting on their channels' owners"),
                crate::v0_0_2_ingest_error::jitter(BUSY_RETRY),
            ))
        };
        if counts.conns.get(&caller.conn).copied().unwrap_or(0) >= MAX_IN_FLIGHT {
            return busy("this connection", MAX_IN_FLIGHT);
        }
        if counts.clients.get(&caller.client).copied().unwrap_or(0) >= MAX_CLIENT_IN_FLIGHT {
            return busy("this client", MAX_CLIENT_IN_FLIGHT);
        }
        if counts.total >= MAX_SERVER_IN_FLIGHT {
            return busy("this server's clients", MAX_SERVER_IN_FLIGHT);
        }
        *counts.conns.entry(caller.conn.clone()).or_insert(0) += 1;
        *counts.clients.entry(caller.client.clone()).or_insert(0) += 1;
        counts.total += 1;
        Ok(InFlight {
            conn: caller.conn.clone(),
            client: caller.client.clone(),
            counts: self.in_flight.clone(),
        })
    }

    /// Count one relayed write against follower `peer`, or `None` past
    /// [`MAX_PEER_IN_FLIGHT`].
    fn take_slot(&self, peer: &str) -> Option<Taking> {
        let mut counts = self.taking.lock().unwrap_or_else(|p| p.into_inner());
        let n = counts.entry(peer.to_string()).or_insert(0);
        if *n >= MAX_PEER_IN_FLIGHT {
            return None;
        }
        *n += 1;
        Some(Taking {
            peer: peer.to_string(),
            counts: self.taking.clone(),
        })
    }

    /// How many requests wait on an owner's answer.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.pending.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    fn forget(&self, request_id: u64) {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&request_id);
    }

    /// The owner's answer to a relay: handed to the client waiting on it, if
    /// it came from the owner it was sent to.
    fn on_result(&self, peer: &Did, body: &[u8]) -> Result<(), CloseReason> {
        let answer = Answer::decode(body).ok_or_else(|| violation("malformed relay-result"))?;
        let peer = peer.to_did_jig_string();
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        match pending.get(&answer.request_id) {
            Some((owner, _)) if *owner == peer => {
                let (_, tx) = pending
                    .remove(&answer.request_id)
                    .expect("the entry just read");
                let _ = tx.send(answer);
            }
            // Another server's request, or one already given up on.
            _ => tracing::debug!(
                peer,
                request_id = answer.request_id,
                "relay-result for no request of this peer's"
            ),
        }
        Ok(())
    }

    // ---- The owner's side --------------------------------------------------

    fn on_submit(
        self: &Arc<Self>,
        peer: &Did,
        body: &[u8],
        out: &PeerSender,
    ) -> Result<(), CloseReason> {
        let submit = Submit::decode(body).ok_or_else(|| violation("malformed relay-submit"))?;
        // The peer's quota and its slots, before any task or lookup: a flood
        // is answered from here.
        let via = peer.to_did_jig_string();
        let refuse = |answer: Answer| {
            if let Err(e) = out.send(RELAY_RESULT_FRAME, answer.encode()) {
                tracing::info!(peer = via, "relay-result not sent: {e}");
            }
            Ok(())
        };
        if let Err(wait) = self.quotas.take_or_wait(&via, submit.bundle.len()) {
            let mut answer = Answer::refused(
                submit.request_id,
                StatusCode::TOO_MANY_REQUESTS,
                "RELAY_RATE_LIMITED",
                format!("`{via}` is past its quota on this server for this minute"),
            );
            answer.retry_after_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX).max(1);
            return refuse(answer);
        }
        let Some(slot) = self.take_slot(&via) else {
            let mut answer = Answer::refused(
                submit.request_id,
                StatusCode::TOO_MANY_REQUESTS,
                "RELAY_BUSY",
                format!(
                    "{MAX_PEER_IN_FLIGHT} writes relayed by `{via}` are already being taken here"
                ),
            );
            answer.retry_after_ms =
                crate::v0_0_2_ingest_error::millis(crate::v0_0_2_ingest_error::jitter(BUSY_RETRY));
            return refuse(answer);
        };
        let relay = self.clone();
        let peer = peer.clone();
        let out = out.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let answer = relay.accept(&peer, submit).await;
            if let Err(e) = out.send(RELAY_RESULT_FRAME, answer.encode()) {
                tracing::info!(
                    peer = peer.to_did_jig_string(),
                    "relay-result not sent: {e}"
                );
            }
        });
        Ok(())
    }

    /// Take a block `peer` relayed, or say why not.
    pub(crate) async fn accept(&self, peer: &Did, submit: Submit) -> Answer {
        let id = submit.request_id;
        let via = peer.to_did_jig_string();
        let channel_id = submit.channel_id.as_str();
        let store = &self.ctx.store;
        let grant =
            match store.contract_offers_for(channel_id, &via, Side::Owner, OfferState::Accepted) {
                Ok(mut shares) => match shares.pop() {
                    Some(share) => share.grant,
                    None => {
                        return Answer::refused(
                            id,
                            StatusCode::FORBIDDEN,
                            "NOT_SHARED",
                            format!("`{via}` holds no accepted share of channel {channel_id}"),
                        );
                    }
                },
                Err(e) => return refused_by(id, &IngestError::Persist(e)),
            };
        if let Err(wait) = self
            .writes
            .take(&via, channel_id, tokio::time::Instant::now())
        {
            let mut answer = Answer::refused(
                id,
                StatusCode::TOO_MANY_REQUESTS,
                "RELAY_RATE_LIMITED",
                format!(
                    "`{via}` is relaying into channel {channel_id} faster than this server takes"
                ),
            );
            answer.retry_after_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX).max(1);
            return answer;
        }
        let Ok((manifest_bytes, code_bytes)) =
            serde_json::from_slice::<(Vec<u8>, Vec<u8>)>(&submit.bundle)
        else {
            return refused_by(
                id,
                &IngestError::BundleMalformed("not a canonical bundle".to_string()),
            );
        };
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &code_bytes,
            resources: vec![],
        };
        // The same block again is the block already taken, before any
        // effect: a client told RELAY_PENDING may safely submit it again.
        if let Ok(cid) = bundle.block_cid() {
            let cid = cid.to_string();
            if let Ok(Some(held)) = store.get_block(&cid)
                && held.channel_id.as_deref() == Some(channel_id)
            {
                return Answer::accepted(id, cid);
            }
        }
        let source = IngestSource::Relayed {
            via: peer.clone(),
            channel_id: channel_id.to_string(),
            grant,
        };
        match ingest(&self.ctx, bundle, submit.sig, source).await {
            Ok(cid) => Answer::accepted(id, cid),
            // Taken by a concurrent copy of the same request.
            Err(IngestError::DuplicateBlock { cid }) => Answer::accepted(id, cid),
            // An author refused for its rate here is told this server's wait,
            // not the follower's.
            Err(e) => answer_of(id, refusal_of(&self.ctx, &e)),
        }
    }
}

/// Who a write comes from, for the in-flight caps: its connection, and the
/// client behind it, whose connections share [`MAX_CLIENT_IN_FLIGHT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub conn: String,
    pub client: String,
}

/// The [`Caller`] for a WSS connection: the client is the DID it
/// authenticated as, else its address, else the connection alone.
pub fn ws_caller(conn_id: u64, did: Option<&str>, ip: Option<std::net::IpAddr>) -> Caller {
    let conn = format!("ws:{conn_id}");
    let client = match (did, ip) {
        (Some(did), _) => format!("did:{did}"),
        (None, Some(ip)) => format!("ip:{ip}"),
        (None, None) => conn.clone(),
    };
    Caller { conn, client }
}

/// The [`Caller`] for a REST write from `ip`. The client is the caller's
/// address, so a caller resubmitting someone else's signed block holds its
/// own relay slots, not the author's. A request with no address (a router
/// driven without connection info) falls back to the block's `author`.
///
/// Each REST request is its own connection, with a key no other request
/// shares. A REST client is bounded by [`MAX_CLIENT_IN_FLIGHT`] across its
/// requests, not by [`MAX_IN_FLIGHT`] at its address.
pub fn rest_caller(ip: Option<std::net::IpAddr>, author: &str) -> Caller {
    use std::sync::atomic::{AtomicU64, Ordering};
    static REQUEST: AtomicU64 = AtomicU64::new(0);

    let client = match ip {
        Some(ip) => format!("rest:ip:{ip}"),
        None => format!("rest:{author}"),
    };
    Caller {
        conn: format!("rest:req:{}", REQUEST.fetch_add(1, Ordering::Relaxed)),
        client,
    }
}

/// [`Refusal::of`] for a refusal on this server, saying when an author
/// refused for its rate or its pool may post again.
fn refusal_of(ctx: &IngestContext, e: &IngestError) -> Refusal {
    let mut refusal = Refusal::of(e);
    if let IngestError::NotAdmitted {
        sender,
        refusal: jig_pipeline::ingest::AdmissionRefusal::RateLimited,
    } = e
    {
        refusal.retry_after_ms = ctx.admission.retry_after_ms(sender);
    }
    refusal
}

/// Post a client's block on `state`'s server: through its [`Relay`], once
/// the contract runs ([`crate::v0_0_2_contract`]), or straight to ingest.
/// `caller` names the client and its connection for the in-flight caps.
pub async fn post(
    state: &crate::v0_0_2::AppState,
    manifest_bytes: &[u8],
    code_bytes: &[u8],
    sig: Vec<u8>,
    conn_id: u64,
    caller: &Caller,
    tiers: bool,
) -> Result<String, Refusal> {
    let posted = match state.relay.get() {
        Some(relay) => {
            relay
                .submit(manifest_bytes, code_bytes, sig, conn_id, caller, tiers)
                .await
        }
        None => {
            let bundle = BlockBundle {
                manifest_bytes,
                code_bytes,
                resources: vec![],
            };
            ingest(
                &state.ingest_ctx,
                bundle,
                sig,
                IngestSource::LocalClient { conn_id, tiers },
            )
            .await
            .map_err(|e| refusal_of(&state.ingest_ctx, &e))
        }
    };
    // An author an owner refused for its rate, with no time given, gets a
    // token back within one refill of this server's rate.
    posted.map_err(|mut refusal| {
        if refusal.code == "RATE_LIMITED" && refusal.retry_after_ms.is_none() {
            refusal.retry_after_ms = state.auth.did_retry_after_ms();
        }
        refusal
    })
}

/// [`post`] for a block that reaches this server as `source` rather than
/// from a client connection: the channel-op routes' `IngestSource::AdminEndpoint`.
/// On a channel this server carries, it is relayed to the owner like any
/// client write, under the share's grant. `caller` names the caller for the
/// in-flight caps.
pub async fn post_as(
    state: &crate::v0_0_2::AppState,
    source: IngestSource,
    manifest_bytes: &[u8],
    code_bytes: &[u8],
    sig: Vec<u8>,
    caller: &Caller,
) -> Result<String, Refusal> {
    if let Some(relay) = state.relay.get() {
        return relay
            .submit_as(source, manifest_bytes, code_bytes, sig, caller)
            .await;
    }
    let bundle = BlockBundle {
        manifest_bytes,
        code_bytes,
        resources: vec![],
    };
    ingest(&state.ingest_ctx, bundle, sig, source)
        .await
        .map_err(|e| refusal_of(&state.ingest_ctx, &e))
}

fn refused_by(request_id: u64, e: &IngestError) -> Answer {
    answer_of(request_id, Refusal::of(e))
}

/// The answer that carries `refusal` back to the follower: one refusal, so
/// its message and its `retry_after_ms` name the same wait, however that
/// wait was drawn.
fn answer_of(request_id: u64, refusal: Refusal) -> Answer {
    Answer {
        retry_after_ms: refusal.retry_after_ms.unwrap_or(0),
        ..Answer::refused(request_id, refusal.status, &refusal.code, refusal.message)
    }
}

fn violation(why: &str) -> CloseReason {
    CloseReason {
        code: jig_pipeline::handshake::close::PROTOCOL_VIOLATION,
        reason: format!("relay: {why}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let submit = Submit {
            request_id: 9,
            channel_id: "bafkchannel".to_string(),
            bundle: vec![1, 2, 3],
            sig: vec![4],
        };
        assert_eq!(Submit::decode(&submit.encode()), Some(submit));
        let mut answer = Answer::refused(
            9,
            StatusCode::TOO_MANY_REQUESTS,
            "RELAY_RATE_LIMITED",
            "slow down".to_string(),
        );
        answer.retry_after_ms = 3_000;
        assert_eq!(Answer::decode(&answer.encode()), Some(answer));
        let accepted = Answer::accepted(9, "bafkblock".to_string());
        assert_eq!(Answer::decode(&accepted.encode()), Some(accepted));
    }

    #[test]
    fn a_frame_with_anything_more_or_less_is_malformed() {
        let extra = dcbor::encode(&Value::text_map([
            ("request_id", Value::Unsigned(1)),
            ("channel_id", Value::text("bafkchannel")),
            ("bundle", Value::Bytes(vec![])),
            ("sig", Value::Bytes(vec![])),
            ("author_did", Value::text("did:jig:zSomeoneElse")),
        ]))
        .unwrap();
        assert_eq!(Submit::decode(&extra), None, "no frame names who sent it");
        let short = dcbor::encode(&Value::text_map([("request_id", Value::Unsigned(1))])).unwrap();
        assert_eq!(Answer::decode(&short), None);
        let mut bytes = Answer::accepted(1, "bafk".to_string()).encode();
        bytes.push(0);
        assert_eq!(Answer::decode(&bytes), None, "trailing bytes");
    }

    /// A render that missed its deadline tells the client when to post again,
    /// in the field as well as the message; a block too expensive to render
    /// is given no wait, because waiting does not change the answer.
    #[test]
    fn a_missed_render_deadline_carries_its_wait() {
        use jig_pipeline::ingest::RenderCause;
        let render_failed = |cause| IngestError::RenderFailed {
            kind: "text-render".to_string(),
            cause,
            detail: "the render is incomplete".to_string(),
        };
        let refusal = Refusal::of(&render_failed(RenderCause::DeadlineExceeded));
        assert_eq!(refusal.status, StatusCode::SERVICE_UNAVAILABLE);
        let wait = refusal.retry_after_ms.expect("a wait");
        assert!((500..=1500).contains(&wait), "{wait}");
        assert!(
            refusal
                .message
                .ends_with(&format!("(retry_after_ms={wait})")),
            "{}",
            refusal.message
        );
        // The owner's answer to a follower says the same wait in both, on
        // every draw.
        for _ in 0..50 {
            let answer = refused_by(7, &render_failed(RenderCause::DeadlineExceeded));
            assert!((500..=1500).contains(&answer.retry_after_ms), "{answer:?}");
            assert!(
                answer
                    .message
                    .ends_with(&format!("(retry_after_ms={})", answer.retry_after_ms)),
                "{answer:?}"
            );
        }
        let refusal = Refusal::of(&render_failed(RenderCause::FuelExhausted));
        assert_eq!(refusal.code, "BLOCK_TOO_EXPENSIVE");
        assert_eq!(refusal.retry_after_ms, None);
    }

    #[test]
    fn a_wait_rides_in_its_field_and_the_message() {
        let refusal = Refusal::retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "OWNER_UNREACHABLE",
            "not connected",
            Duration::from_millis(1_500),
        );
        assert_eq!(refusal.code, "OWNER_UNREACHABLE");
        assert_eq!(refusal.retry_after_ms, Some(1_500));
        assert!(
            refusal.message.ends_with("(retry_after_ms=1500)"),
            "{}",
            refusal.message
        );
    }

    /// An author refused for its rate is told when it may post again: one
    /// token's refill of this server's rate.
    #[tokio::test]
    async fn an_author_over_its_rate_is_told_when_to_post_again() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.auth.rate_limit.per_did_burst = 1;
        config.auth.rate_limit.per_did_per_second = 4;
        let state = crate::v0_0_2::AppState::for_test_with_config(config).unwrap();
        let author = jig_client::Identity::generate_for_tests(&tempfile::tempdir().unwrap().keep());
        let mut refusals = Vec::new();
        for body in ["first", "second"] {
            let hlc = jig_core::HlcTimestamp::now_wall(author.did().clone());
            let block = jig_client::blocks::build_text_render(&author, "#nowhere", body, hlc);
            let posted = post(
                &state,
                &block.manifest_bytes,
                &block.code_bytes,
                block.sender_sig.clone(),
                1,
                &ws_caller(1, None, None),
                true,
            )
            .await;
            refusals.push(posted.unwrap_err());
        }
        assert_ne!(refusals[0].code, "RATE_LIMITED", "{:?}", refusals[0]);
        assert_eq!(refusals[0].retry_after_ms, None);
        assert_eq!(refusals[1].code, "RATE_LIMITED", "{:?}", refusals[1]);
        assert_eq!(refusals[1].retry_after_ms, Some(250));
    }

    fn relay_for(state: &crate::v0_0_2::AppState) -> Arc<Relay> {
        Arc::new(Relay::new(
            state.ingest_ctx.clone(),
            Arc::new(state.config.federation.clone()),
            state.peers.clone(),
        ))
    }

    fn caller(n: usize) -> Caller {
        Caller {
            conn: format!("conn:{n}"),
            client: format!("client:{n}"),
        }
    }

    fn busy(refusal: Refusal, whose: &str) {
        assert_eq!(refusal.code, "RELAY_BUSY", "{refusal:?}");
        assert_eq!(refusal.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            refusal.retry_after_ms.is_some_and(|ms| ms > 0),
            "{refusal:?}"
        );
        assert!(refusal.message.contains(whose), "{refusal:?}");
    }

    /// Relays waiting on owners are bounded per connection, per client over
    /// its connections, and over the whole server, each refused with
    /// `RELAY_BUSY` and when to try again (DJ 2026-11-26). A slot frees when
    /// its relay ends.
    #[tokio::test]
    async fn relays_waiting_are_bounded_per_connection_client_and_server() {
        let state = crate::v0_0_2::AppState::for_test().unwrap();
        let relay = relay_for(&state);
        let alice = |conn| ws_caller(conn, Some("did:jig:zAlice"), None);

        let mut held = Vec::new();
        for _ in 0..MAX_IN_FLIGHT {
            held.push(relay.hold(&alice(1)).unwrap());
        }
        busy(relay.hold(&alice(1)).err().unwrap(), "this connection");

        // More connections of the same client, up to its own bound.
        let mut conn = 2;
        while held.len() < MAX_CLIENT_IN_FLIGHT {
            for _ in 0..MAX_IN_FLIGHT {
                held.push(relay.hold(&alice(conn)).unwrap());
            }
            conn += 1;
        }
        busy(relay.hold(&alice(conn)).err().unwrap(), "this client");
        // Its address does not make it another client, and another client is
        // not held up by it.
        let ip = Some(std::net::IpAddr::from([192, 0, 2, 1]));
        busy(
            relay
                .hold(&ws_caller(conn, Some("did:jig:zAlice"), ip))
                .err()
                .unwrap(),
            "this client",
        );
        let bob = relay
            .hold(&ws_caller(conn, Some("did:jig:zBob"), None))
            .unwrap();

        // The whole server.
        let mut n = 0;
        while held.len() + 1 < MAX_SERVER_IN_FLIGHT {
            held.push(relay.hold(&caller(n)).unwrap());
            n += 1;
        }
        busy(relay.hold(&caller(n)).err().unwrap(), "this server");

        // Every slot frees with its relay.
        drop(bob);
        relay.hold(&caller(n)).unwrap();
        drop(held);
        for _ in 0..MAX_IN_FLIGHT {
            std::mem::forget(relay.hold(&alice(1)).unwrap());
        }
        let counts = relay.in_flight.lock().unwrap();
        assert_eq!(counts.total, MAX_IN_FLIGHT);
        assert_eq!(counts.clients.len(), 1);
    }

    /// A REST client's writes are separate requests: one address holds up
    /// to [`MAX_CLIENT_IN_FLIGHT`] relays, not [`MAX_IN_FLIGHT`], and a
    /// WSS connection keeps its own bound of [`MAX_IN_FLIGHT`].
    #[tokio::test]
    async fn rest_writes_from_one_address_are_bounded_as_one_client() {
        let state = crate::v0_0_2::AppState::for_test().unwrap();
        let relay = relay_for(&state);
        let ip = Some(std::net::IpAddr::from([192, 0, 2, 7]));

        let mut held = Vec::new();
        for _ in 0..MAX_CLIENT_IN_FLIGHT {
            held.push(relay.hold(&rest_caller(ip, "did:jig:zAuthor")).unwrap());
        }
        busy(
            relay
                .hold(&rest_caller(ip, "did:jig:zAuthor"))
                .err()
                .unwrap(),
            "this client",
        );
        // Another address is another client.
        let other = Some(std::net::IpAddr::from([192, 0, 2, 8]));
        held.push(relay.hold(&rest_caller(other, "did:jig:zAuthor")).unwrap());

        // A WSS connection is still bounded on its own.
        let carol = ws_caller(1, Some("did:jig:zCarol"), None);
        for _ in 0..MAX_IN_FLIGHT {
            held.push(relay.hold(&carol).unwrap());
        }
        busy(relay.hold(&carol).err().unwrap(), "this connection");
    }

    /// A REST request's connection key is its own, so it must not outlive
    /// the request: after many REST relays from one address have ended,
    /// nothing is left counted for their connections or their client.
    #[tokio::test]
    async fn rest_relays_leave_no_slots_behind() {
        let state = crate::v0_0_2::AppState::for_test().unwrap();
        let relay = relay_for(&state);
        let ip = Some(std::net::IpAddr::from([192, 0, 2, 9]));
        for _ in 0..4 * MAX_CLIENT_IN_FLIGHT {
            drop(relay.hold(&rest_caller(ip, "did:jig:zAuthor")).unwrap());
        }
        let counts = relay.in_flight.lock().unwrap();
        assert!(counts.conns.is_empty(), "{:?}", counts.conns);
        assert!(counts.clients.is_empty(), "{:?}", counts.clients);
        assert_eq!(counts.total, 0);
    }

    /// The answer `rx` carries next, as the follower would read it.
    async fn next_answer(rx: &mut tokio::sync::mpsc::Receiver<jig_pipeline::Envelope>) -> Answer {
        let envelope = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("an answer")
            .expect("the connection");
        let jig_pipeline::Frame::Peer { kind, body } = envelope.frame else {
            panic!("not a peer frame");
        };
        assert_eq!(kind, RELAY_RESULT_FRAME);
        Answer::decode(&body).unwrap()
    }

    fn submit(request_id: u64) -> Vec<u8> {
        Submit {
            request_id,
            channel_id: "bafkchannel".to_string(),
            bundle: vec![0; 100],
            sig: vec![0; 64],
        }
        .encode()
    }

    /// On the owner's side, a follower's relayed writes count against its
    /// quota, and at most [`MAX_PEER_IN_FLIGHT`] are taken at once; past
    /// either, the follower is answered at once, with when to try again.
    #[tokio::test]
    async fn an_owner_bounds_a_followers_relays_before_taking_them() {
        let mut config = jig_config::v0_0_2_server::JigServerConfig::default();
        config.federation.default_peer_quota.blocks_per_min = 2;
        let state = crate::v0_0_2::AppState::for_test_with_config(config).unwrap();
        let relay = relay_for(&state);
        let follower = Did::from_ed25519_pubkey(&[7; 32]);
        let (out, mut rx) = PeerSender::new(follower.clone());

        // Within the quota: taken, and refused for the share it lacks.
        for id in [1, 2] {
            relay.on_submit(&follower, &submit(id), &out).unwrap();
            assert_eq!(next_answer(&mut rx).await.code, "NOT_SHARED");
        }
        // Past it.
        relay.on_submit(&follower, &submit(3), &out).unwrap();
        let answer = next_answer(&mut rx).await;
        assert_eq!(answer.request_id, 3);
        assert_eq!(answer.code, "RELAY_RATE_LIMITED");
        assert!(answer.retry_after_ms > 0, "{answer:?}");
        // Another follower has its own quota.
        let other = Did::from_ed25519_pubkey(&[8; 32]);
        let (other_out, mut other_rx) = PeerSender::new(other.clone());
        relay.on_submit(&other, &submit(4), &other_out).unwrap();
        assert_eq!(next_answer(&mut other_rx).await.code, "NOT_SHARED");

        // Every slot of `other` taken: refused busy, before any lookup.
        let slots: Vec<_> = (0..MAX_PEER_IN_FLIGHT)
            .map(|_| relay.take_slot(&other.to_did_jig_string()).unwrap())
            .collect();
        relay.on_submit(&other, &submit(5), &other_out).unwrap();
        let answer = next_answer(&mut other_rx).await;
        assert_eq!((answer.request_id, answer.code.as_str()), (5, "RELAY_BUSY"));
        assert!(answer.retry_after_ms > 0, "{answer:?}");
        drop(slots);
        assert!(relay.take_slot(&other.to_did_jig_string()).is_some());
    }
}
