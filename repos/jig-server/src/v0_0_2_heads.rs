//! Head gossip between servers (JEP-0002 rule 10; design D11 item 6): the
//! `channel-head` peer frame.
//!
//! A server forwards the latest `ingest` record it verified for a channel to
//! the other servers that hold the channel, so that two records one sequencer
//! signed for the same `seq` can meet. The frame carries the record's signed
//! envelope and nothing about who first sent it.
//!
//! The frame is sent only on a peer connection whose welcome granted
//! [`jig_pipeline::handshake::Capabilities::heads`]; a server that predates
//! it ignores the kind. Its body is deterministic CBOR, like the stream's
//! frames ([`crate::v0_0_2_stream`]).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use jig_config::v0_0_2_server::RateLimit;
use jig_core::dcbor::{self, Value};
use jig_core::did::Did;
use jig_pipeline::contracts::{OfferState, Side};
use jig_pipeline::heads::HeadCheck;
use jig_pipeline::ingest::IngestContext;
use jig_pipeline::ingest_record::{IngestRecord, MAX_COSE_BYTES};

use crate::v0_0_2_peer::PeerRegistry;
use crate::v0_0_2_stream::{RequestLimit, Stream};

/// How many heads one client connection may hand in: one a second, with a
/// burst of 32. A client sends one per channel it follows on subscribe, and
/// then at most one every [`CLIENT_SEND_EVERY`] per channel.
pub const CLIENT_HEADS: RateLimit = RateLimit {
    per_min: 60,
    burst: 32,
};

/// How many heads one peer may hand in: 20 a second, with a burst of 200.
pub const PEER_HEADS: RateLimit = RateLimit {
    per_min: 1200,
    burst: 200,
};

/// The most often this server forwards one channel's head to one peer.
pub const FORWARD_EVERY: Duration = Duration::from_secs(5);

/// The most first-fork frames held for a peer that could not take them,
/// across peers and channels. A fork is kept once per channel, so this is
/// reached only with that many forked channels at once.
pub const MAX_PENDING_FORKS: usize = 1024;

/// The most often a client sends one channel's head.
pub const CLIENT_SEND_EVERY: Duration = Duration::from_secs(30);

/// One client connection's allowance of heads ([`CLIENT_HEADS`]), kept
/// with the connection so that it goes when the connection does.
#[derive(Debug, Clone)]
pub struct ClientAllowance {
    tokens: f64,
    at: tokio::time::Instant,
}

impl Default for ClientAllowance {
    fn default() -> Self {
        ClientAllowance {
            tokens: f64::from(CLIENT_HEADS.burst),
            at: tokio::time::Instant::now(),
        }
    }
}

impl ClientAllowance {
    /// Take one head, or say how long until one is free.
    fn take(&mut self, now: tokio::time::Instant) -> Result<(), Duration> {
        let per_sec = f64::from(CLIENT_HEADS.per_min) / 60.0;
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * per_sec).min(f64::from(CLIENT_HEADS.burst));
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - self.tokens) / per_sec))
        }
    }
}

/// What became of a head handed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// Over its sender's limit: refused, with when to send again. Charged
    /// before anything else is looked at, so the answer is the same whether
    /// or not this server holds the channel.
    RateLimited(Duration),
    /// Looked at. Nothing is said back, whatever it showed.
    Checked(HeadCheck),
}

/// One server's head gossip: what clients and peers hand it, and what it
/// forwards.
pub struct Heads {
    ctx: Arc<IngestContext>,
    /// Who this server federates with: heads go only to configured peers.
    federation: Arc<jig_config::v0_0_2_server::FederationSection>,
    peers: Arc<PeerRegistry>,
    /// The follower's stream, to fetch up to a head past its chain.
    stream: OnceLock<Stream>,
    from_peers: RequestLimit,
    /// When each channel's head was last forwarded to each peer, and the
    /// first-fork frames a peer has not yet taken, by peer and channel. One
    /// lock, held from the choice of a link to the frame's admission.
    forwarded: Mutex<Forwarded>,
    /// Signatures checked: what a flood of heads cost.
    verifications: AtomicU64,
}

impl Heads {
    pub fn new(
        ctx: Arc<IngestContext>,
        federation: Arc<jig_config::v0_0_2_server::FederationSection>,
        peers: Arc<PeerRegistry>,
    ) -> Self {
        Heads {
            ctx,
            federation,
            peers,
            stream: OnceLock::new(),
            from_peers: RequestLimit::new(PEER_HEADS),
            forwarded: Mutex::new(Forwarded::default()),
            verifications: AtomicU64::new(0),
        }
    }

    /// The stream a follower fetches with. Once.
    pub fn set_stream(&self, stream: Stream) {
        let _ = self.stream.set(stream);
    }

    /// How many signatures heads have cost this server.
    pub fn verifications(&self) -> u64 {
        self.verifications.load(Ordering::Relaxed)
    }

    /// Take `envelope`, a head for `channel_id`, from a client whose
    /// connection holds `allowance`.
    pub fn take_from_client(
        &self,
        allowance: &mut ClientAllowance,
        channel_id: &str,
        envelope: &[u8],
    ) -> Taken {
        if envelope.len() > MAX_COSE_BYTES {
            return Taken::Checked(HeadCheck::Malformed("past the record size".into()));
        }
        if let Err(wait) = allowance.take(tokio::time::Instant::now()) {
            return Taken::RateLimited(wait);
        }
        Taken::Checked(self.check(None, channel_id, envelope))
    }

    /// Take `envelope`, a head for `channel_id`, from `peer`.
    pub fn take_from_peer(&self, peer: &Did, channel_id: &str, envelope: &[u8]) -> Taken {
        if envelope.len() > MAX_COSE_BYTES {
            return Taken::Checked(HeadCheck::Malformed("past the record size".into()));
        }
        let peer = peer.to_did_jig_string();
        if let Err(wait) = self.from_peers.take(&peer, "", tokio::time::Instant::now()) {
            return Taken::RateLimited(wait);
        }
        Taken::Checked(self.check(Some(&peer), channel_id, envelope))
    }

    /// The store's check ([`jig_pipeline::heads`]), which looks at bytes
    /// before signatures, and what follows from it. The sender is charged
    /// already, before the channel is looked up, so that a refusal does not
    /// depend on whether this server holds it.
    fn check(&self, from: Option<&str>, channel_id: &str, envelope: &[u8]) -> HeadCheck {
        let check = match self.ctx.store.check_head(channel_id, envelope) {
            Ok(check) => check,
            Err(e) => {
                tracing::warn!(channel_id, "checking a head: {e}");
                return HeadCheck::Malformed("not checked".into());
            }
        };
        if check.verified() {
            self.verifications.fetch_add(1, Ordering::Relaxed);
        }
        match &check {
            HeadCheck::Ahead { advanced: true, .. } => {
                self.fetch_up_to(channel_id);
                self.forward(channel_id, envelope, from, false);
            }
            HeadCheck::Fork {
                first: true, seq, ..
            } => {
                tracing::warn!(
                    channel_id,
                    seq,
                    "a head shows the channel's sequencer forked"
                );
                self.forward(channel_id, envelope, from, true);
            }
            _ => {}
        }
        check
    }

    /// The server that sequences `channel_id`, when it is not this one.
    fn owner_of(&self, channel_id: &str) -> Option<String> {
        let channel = self.ctx.store.get_channel_by_id(channel_id).ok()??;
        let local = self.ctx.store.local_sequencer();
        (!channel.sequencer_did.is_empty()
            && !jig_pipeline::handshake::same_did(&channel.sequencer_did, local))
        .then_some(channel.sequencer_did)
    }

    /// A follower handed a head past its chain asks the owner for what it is
    /// missing, as its periodic pull would.
    fn fetch_up_to(&self, channel_id: &str) {
        if let (Some(owner), Some(stream)) = (self.owner_of(channel_id), self.stream.get()) {
            stream.pull_from_head(&owner, channel_id);
        }
    }

    /// The servers `channel_id`'s heads go to: its owner, when this server
    /// follows it, and every server holding an accepted share of it, when
    /// this server owns it.
    fn targets(&self, channel_id: &str) -> Vec<String> {
        let mut targets: Vec<String> = self.owner_of(channel_id).into_iter().collect();
        match self
            .ctx
            .store
            .contract_offers_in(Side::Owner, OfferState::Accepted)
        {
            Ok(shares) => targets.extend(
                shares
                    .into_iter()
                    .filter(|s| s.channel_id == channel_id)
                    .map(|s| s.peer_did),
            ),
            Err(e) => tracing::warn!(channel_id, "listing a channel's shares: {e}"),
        }
        targets
    }

    /// Send `envelope` on to every target but `from` that is a configured
    /// peer, on links that take heads. An ordinary head goes at most once
    /// every [`FORWARD_EVERY`] per peer and channel. A `fork`, the first kept
    /// for the channel, goes whatever the interval, and is held for a peer
    /// that cannot take it now, to be sent again ([`Self::retry_pending`]).
    /// A share-holder the operator has since delisted is told nothing,
    /// whatever its share's state.
    fn forward(&self, channel_id: &str, envelope: &[u8], from: Option<&str>, fork: bool) {
        let body = ChannelHead {
            channel_id: channel_id.to_string(),
            record: envelope.to_vec(),
        }
        .encode();
        let now = tokio::time::Instant::now();
        for target in self.targets(channel_id) {
            if from.is_some_and(|f| jig_pipeline::handshake::same_did(f, &target))
                || crate::v0_0_2_federation::configured_peer(&self.federation, &target).is_none()
            {
                continue;
            }
            let key = (target.clone(), channel_id.to_string());
            let mut forwarded = self.forwarded.lock().unwrap_or_else(|p| p.into_inner());
            if !fork
                && forwarded
                    .at
                    .get(&key)
                    .is_some_and(|at| now.saturating_duration_since(*at) < FORWARD_EVERY)
            {
                continue;
            }
            if self.send_to(&target, &body) {
                forwarded.at.insert(key.clone(), now);
                forwarded.forks.remove(&key);
            } else if fork {
                forwarded.hold(key, body.clone());
            }
        }
    }

    /// Queue `body` on `target`'s newest live link that granted heads.
    /// Whether it was queued.
    fn send_to(&self, target: &str, body: &[u8]) -> bool {
        let Some(sender) = Did::from_did_jig_string(target)
            .ok()
            .and_then(|did| self.peers.heads_sender_for(&did))
        else {
            return false;
        };
        match sender.send(HEAD_FRAME, body.to_vec()) {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!(peer = target, "head not forwarded: {e}");
                false
            }
        }
    }

    /// Send again the first-fork frames a peer could not take: no link that
    /// takes heads, or a full queue. A peer the operator has since delisted
    /// is dropped from them.
    pub fn retry_pending(&self) {
        let now = tokio::time::Instant::now();
        let mut forwarded = self.forwarded.lock().unwrap_or_else(|p| p.into_inner());
        let pending: Vec<_> = forwarded
            .forks
            .iter()
            .map(|(k, b)| (k.clone(), b.clone()))
            .collect();
        for (key, body) in pending {
            if crate::v0_0_2_federation::configured_peer(&self.federation, &key.0).is_none() {
                forwarded.forks.remove(&key);
            } else if self.send_to(&key.0, &body) {
                forwarded.forks.remove(&key);
                forwarded.at.insert(key, now);
            }
        }
    }

    /// How many first-fork frames wait for a peer.
    pub fn pending_forks(&self) -> usize {
        self.forwarded
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .forks
            .len()
    }

    /// A [`HEAD_FRAME`] from `peer`. A body that does not decode is
    /// dropped; a peer over its limit has its heads dropped until it is
    /// under it again. Neither closes the connection, which carries every
    /// contract between the two servers.
    pub fn on_peer_frame(&self, peer: &Did, body: &[u8]) {
        // Only from a configured peer: a DID the operator never listed, or
        // has since delisted, costs nothing and is told nothing.
        if crate::v0_0_2_federation::configured_peer(&self.federation, &peer.to_did_jig_string())
            .is_none()
        {
            tracing::debug!(peer = %peer.to_did_jig_string(), "a channel-head from a peer not configured");
            return;
        }
        let Some(head) = ChannelHead::decode(body) else {
            tracing::debug!(peer = %peer.to_did_jig_string(), "a channel-head that does not decode");
            return;
        };
        if let Taken::RateLimited(wait) = self.take_from_peer(peer, &head.channel_id, &head.record)
        {
            tracing::debug!(
                peer = %peer.to_did_jig_string(),
                "heads past the limit, dropped for {wait:?}"
            );
        }
    }
}

/// What [`Heads::forward`] keeps between calls.
#[derive(Default)]
struct Forwarded {
    /// When each channel's head was last queued for each peer.
    at: HashMap<(String, String), tokio::time::Instant>,
    /// First-fork frames a peer has not taken, by peer and channel.
    forks: HashMap<(String, String), Vec<u8>>,
}

impl Forwarded {
    fn hold(&mut self, key: (String, String), body: Vec<u8>) {
        if self.forks.len() >= MAX_PENDING_FORKS && !self.forks.contains_key(&key) {
            tracing::warn!(
                peer = key.0,
                channel_id = key.1,
                "a fork not forwarded: {MAX_PENDING_FORKS} already wait"
            );
            return;
        }
        self.forks.insert(key, body);
    }
}

/// What a server tells a client that subscribes to `channel_id` on a
/// connection that takes heads, as base64 record envelopes: both records of
/// the fork its chain evidence holds, when it holds one, and the highest
/// head it was handed, when that is past what it serves. Either is signed
/// by the channel's sequencer, so the client checks them against its own
/// chain as it checks any record; what the server says is not taken on its
/// word.
pub fn for_subscriber(store: &jig_pipeline::persist::SqliteStore, channel_id: &str) -> Vec<String> {
    use base64::Engine as _;
    let b64 = |r: &IngestRecord| {
        r.cose_bytes()
            .ok()
            .map(|e| base64::engine::general_purpose::STANDARD.encode(e))
    };
    let mut out = Vec::new();
    if let Ok(evidence) = store.chain_evidence(channel_id) {
        for e in evidence {
            for bytes in [&e.held, &e.offered] {
                if let Some(record) = IngestRecord::decode(bytes).ok().as_ref().and_then(b64) {
                    out.push(record);
                }
            }
        }
    }
    let served = store
        .latest_ingest_record(channel_id)
        .ok()
        .flatten()
        .map(|r| r.seq);
    if let Ok(Some(kept)) = store.kept_head_record(channel_id)
        && served.is_none_or(|s| kept.seq > s)
        && let Some(record) = b64(&kept)
    {
        out.push(record);
    }
    out
}

/// The peer frame kind for one channel's head.
pub const HEAD_FRAME: &str = "channel-head";

/// One channel's head, as a [`HEAD_FRAME`] carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelHead {
    /// The CID of the channel's `channel-create` block.
    pub channel_id: String,
    /// The record's COSE_Sign1 envelope
    /// ([`jig_pipeline::ingest_record::IngestRecord::cose_bytes`]).
    pub record: Vec<u8>,
}

/// The most a [`HEAD_FRAME`] body may hold: the record's envelope, a CID and
/// the keys. Anything larger is refused before it is parsed.
pub const MAX_HEAD_BODY: usize = MAX_COSE_BYTES + 256;

impl ChannelHead {
    pub fn encode(&self) -> Vec<u8> {
        dcbor::encode(&Value::text_map([
            ("channel_id", Value::text(&self.channel_id)),
            ("record", Value::Bytes(self.record.clone())),
        ]))
        .expect("text keys never repeat")
    }

    /// `None` for a body past [`MAX_HEAD_BODY`], one that is not
    /// deterministic CBOR, or a map with any key but the two above.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_HEAD_BODY {
            return None;
        }
        let value = dcbor::decode(bytes).ok()?;
        let Value::Map(entries) = &value else {
            return None;
        };
        if entries.len() != 2 {
            return None;
        }
        let record = value.get("record")?.as_bytes()?;
        if record.len() > MAX_COSE_BYTES {
            return None;
        }
        Some(Self {
            channel_id: value.get("channel_id")?.as_text()?.to_string(),
            record: record.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_head_round_trips() {
        let head = ChannelHead {
            channel_id: jig_pipeline::ingest_record::label_cid("Create"),
            record: vec![1, 2, 3],
        };
        assert_eq!(ChannelHead::decode(&head.encode()), Some(head));
    }

    #[test]
    fn a_body_that_is_not_a_head_is_refused() {
        let extra = dcbor::encode(&Value::text_map([
            ("channel_id", Value::text("c")),
            ("record", Value::Bytes(vec![1])),
            ("from", Value::text("someone")),
        ]))
        .unwrap();
        let oversize = ChannelHead {
            channel_id: "c".into(),
            record: vec![0; MAX_COSE_BYTES + 1],
        }
        .encode();
        for bad in [
            b"not cbor".to_vec(),
            extra,
            oversize,
            vec![0; MAX_HEAD_BODY + 1],
        ] {
            assert_eq!(ChannelHead::decode(&bad), None);
        }
    }

    /// A server and a channel it sequences, with its record 0.
    async fn sequencing() -> (crate::v0_0_2::AppState, String, IngestRecord) {
        let state = crate::v0_0_2::AppState::for_test().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let owner = jig_client::Identity::generate_for_tests(dir.path());
        let block = jig_client::blocks::build_channel_create(
            &owner,
            "#c",
            "open",
            &state.server_did.to_did_jig_string(),
            jig_core::HlcTimestamp::now_wall(owner.did().clone()),
        );
        let cid = jig_pipeline::ingest::ingest(
            &state.ingest_ctx,
            jig_core::BlockBundle {
                manifest_bytes: &block.manifest_bytes,
                code_bytes: &block.code_bytes,
                resources: vec![],
            },
            block.sender_sig.clone(),
            jig_pipeline::ingest::IngestSource::LocalClient {
                conn_id: 1,
                tiers: true,
            },
        )
        .await
        .unwrap();
        let held = state
            .ingest_ctx
            .store
            .list_ingest_records_by_id(&cid, 0, 1)
            .unwrap()
            .remove(0);
        (state, cid, held)
    }

    /// F2 Task 10: a flood of heads costs no signature checks past what the
    /// sender's allowance lets through. Duplicates, oversize heads and
    /// heads over the limit cost none; distinct stale heads, which could be
    /// a fork, cost one each, and only up to the allowance. Over the limit,
    /// the refusal is the same whether or not the channel is held here.
    #[tokio::test(start_paused = true)]
    async fn a_flood_of_heads_costs_no_more_signatures_than_its_allowance() {
        let (state, channel, held) = sequencing().await;
        let heads = Heads::new(
            state.ingest_ctx.clone(),
            Arc::new(state.config.federation.clone()),
            state.peers.clone(),
        );
        let duplicate = held.cose_bytes().unwrap();
        let burst = CLIENT_HEADS.burst as usize;

        // Duplicates, up to the allowance and past it: no signature.
        let mut allowance = ClientAllowance::default();
        let taken: Vec<Taken> = (0..burst * 3)
            .map(|_| heads.take_from_client(&mut allowance, &channel, &duplicate))
            .collect();
        assert!(
            taken[..burst]
                .iter()
                .all(|t| *t == Taken::Checked(HeadCheck::Duplicate))
        );
        assert!(
            taken[burst..]
                .iter()
                .all(|t| matches!(t, Taken::RateLimited(_)))
        );
        assert_eq!(heads.verifications(), 0);

        // Oversize: refused before anything is charged or checked.
        let mut allowance = ClientAllowance::default();
        for _ in 0..burst * 3 {
            assert!(matches!(
                heads.take_from_client(&mut allowance, &channel, &vec![0; MAX_COSE_BYTES + 1]),
                Taken::Checked(HeadCheck::Malformed(_))
            ));
        }
        assert_eq!(heads.verifications(), 0);

        // Over the limit, a held and an unheld channel are refused alike.
        let unheld = jig_pipeline::ingest_record::label_cid("not here");
        let mut allowance = ClientAllowance::default();
        for _ in 0..burst {
            heads.take_from_client(&mut allowance, &unheld, &duplicate);
        }
        for channel in [&channel, &unheld] {
            assert!(matches!(
                heads.take_from_client(&mut allowance, channel, &duplicate),
                Taken::RateLimited(_)
            ));
        }
        assert_eq!(heads.verifications(), 0);

        // Distinct heads at a held seq, by keys that are not the sequencer's:
        // each could be a fork, so each within the allowance is checked, and
        // none past it.
        let mut allowance = ClientAllowance::default();
        for _ in 0..burst * 3 {
            let forged = RecordSigner {
                channel_id: channel.clone(),
                key: &jig_core::crypto::ed25519::generate_signing_key(),
                ingest_wall_ms: 1,
                ingest_logical: 0,
            }
            .sign(0, &channel, GENESIS_PREV)
            .unwrap();
            heads.take_from_client(&mut allowance, &channel, &forged.cose_bytes().unwrap());
        }
        assert_eq!(heads.verifications(), burst as u64);

        // A peer's allowance is larger, and the same holds for it.
        let peer = Did::from_ed25519_pubkey(&[9; 32]);
        let before = heads.verifications();
        let refused = (0..PEER_HEADS.burst as usize + 50)
            .filter(|_| {
                matches!(
                    heads.take_from_peer(&peer, &channel, &duplicate),
                    Taken::RateLimited(_)
                )
            })
            .count();
        assert_eq!(refused, 50);
        assert_eq!(heads.verifications(), before);
    }

    /// A head past the chain goes on to the servers holding a share of the
    /// channel that are configured peers, on links that take heads, never
    /// back to whoever sent it, and at most once every [`FORWARD_EVERY`] per
    /// peer and channel. A share-holder the operator delisted gets nothing.
    #[tokio::test(start_paused = true)]
    async fn a_head_past_the_chain_goes_on_to_the_channels_other_servers() {
        use crate::v0_0_2_peer::PeerSender;
        let (state, channel, held) = sequencing().await;
        let peer = |n: u8| Did::from_ed25519_pubkey(&[n; 32]);
        let (takes, others, source, delisted) = (peer(1), peer(2), peer(3), peer(4));
        let mut federation = state.config.federation.clone();
        federation.peers = [&takes, &others, &source]
            .into_iter()
            .map(|did| jig_config::v0_0_2_server::FederationPeer {
                url: "wss://peer.invalid".into(),
                expected_did: did.to_did_jig_string(),
                alias: None,
                publish: false,
                quota: None,
                offers: Default::default(),
            })
            .collect();
        let heads = Heads::new(
            state.ingest_ctx.clone(),
            Arc::new(federation),
            state.peers.clone(),
        );
        let mut inboxes = Vec::new();
        for (did, takes_heads) in [
            (&takes, true),
            (&others, false),
            (&source, true),
            (&delisted, true),
        ] {
            let (sender, rx) = PeerSender::with_features(did.clone(), true, takes_heads);
            state.peers.register(sender);
            inboxes.push(rx);
            state
                .ingest_ctx
                .store
                .put_contract_offer(&jig_pipeline::contracts::StoredOffer {
                    offer_id: [did.as_bytes().unwrap()[0]; 32],
                    channel_id: channel.clone(),
                    side: Side::Owner,
                    peer_did: did.to_did_jig_string(),
                    grant: jig_core::contract::Grant::Write,
                    state: OfferState::Accepted,
                    offer: Vec::new(),
                    answer: None,
                    share_cid: None,
                })
                .unwrap();
        }
        let ahead = |seq: u64| {
            RecordSigner {
                channel_id: channel.clone(),
                key: &state.ingest_ctx.server_key,
                ingest_wall_ms: 99,
                ingest_logical: 0,
            }
            .sign(seq, &channel, held.hash())
            .unwrap()
            .cose_bytes()
            .unwrap()
        };
        let sent = |inbox: &mut tokio::sync::mpsc::Receiver<jig_pipeline::Envelope>| {
            std::iter::from_fn(|| inbox.try_recv().ok())
                .filter_map(|e| match e.frame {
                    jig_pipeline::Frame::Peer { kind, body } if kind == HEAD_FRAME => {
                        ChannelHead::decode(&body)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        let first = ahead(5);
        assert_eq!(
            heads.take_from_peer(&source, &channel, &first),
            Taken::Checked(HeadCheck::Ahead {
                seq: 5,
                advanced: true
            })
        );
        assert_eq!(sent(&mut inboxes[0]).len(), 1, "a link that takes heads");
        assert!(sent(&mut inboxes[1]).is_empty(), "a link that does not");
        assert!(sent(&mut inboxes[2]).is_empty(), "never back to the sender");
        assert!(
            sent(&mut inboxes[3]).is_empty(),
            "an accepted share-holder that is no longer a configured peer"
        );
        // And a head from a peer that is not configured costs nothing and
        // goes nowhere.
        let before = heads.verifications();
        heads.on_peer_frame(
            &delisted,
            &ChannelHead {
                channel_id: channel.clone(),
                record: ahead(9),
            }
            .encode(),
        );
        assert_eq!(heads.verifications(), before);
        assert!(inboxes.iter_mut().all(|i| sent(i).is_empty()));

        // Coalesced: a higher head within the interval is not sent again.
        heads.take_from_peer(&source, &channel, &ahead(6));
        assert!(sent(&mut inboxes[0]).is_empty());
        tokio::time::advance(FORWARD_EVERY).await;
        heads.take_from_peer(&source, &channel, &ahead(7));
        let got = sent(&mut inboxes[0]);
        assert_eq!(got.len(), 1);
        assert_eq!(IngestRecord::from_cose(&got[0].record).unwrap().seq, 7);
    }

    /// A first fork goes on whatever the interval, and one a peer cannot
    /// take now (its queue full, or no link that takes heads) is held and
    /// sent again. The link is the newest of those that granted heads.
    #[tokio::test(start_paused = true)]
    async fn a_fork_is_forwarded_inside_the_interval_and_retried_until_taken() {
        use crate::v0_0_2_peer::{PEER_QUEUE, PeerSender};
        let (state, channel, held) = sequencing().await;
        let target = Did::from_ed25519_pubkey(&[1; 32]);
        let mut federation = state.config.federation.clone();
        federation.peers = vec![jig_config::v0_0_2_server::FederationPeer {
            url: "wss://peer.invalid".into(),
            expected_did: target.to_did_jig_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        }];
        state
            .ingest_ctx
            .store
            .put_contract_offer(&jig_pipeline::contracts::StoredOffer {
                offer_id: [1; 32],
                channel_id: channel.clone(),
                side: Side::Owner,
                peer_did: target.to_did_jig_string(),
                grant: jig_core::contract::Grant::Write,
                state: OfferState::Accepted,
                offer: Vec::new(),
                answer: None,
                share_cid: None,
            })
            .unwrap();
        let heads = Heads::new(
            state.ingest_ctx.clone(),
            Arc::new(federation),
            state.peers.clone(),
        );
        // An older link that takes heads, and a newer one that does not.
        let (takes, mut inbox) = PeerSender::with_features(target.clone(), true, true);
        state.peers.register(takes.clone());
        let (newer, mut newer_inbox) = PeerSender::with_features(target.clone(), true, false);
        state.peers.register(newer);
        let heads_in = |inbox: &mut tokio::sync::mpsc::Receiver<jig_pipeline::Envelope>| {
            std::iter::from_fn(|| inbox.try_recv().ok())
                .filter(|e| matches!(&e.frame, jig_pipeline::Frame::Peer { kind, .. } if kind == HEAD_FRAME))
                .count()
        };
        let record = held.cose_bytes().unwrap();

        heads.forward(&channel, &record, None, false);
        assert_eq!(heads_in(&mut inbox), 1, "on the link that granted heads");
        assert_eq!(heads_in(&mut newer_inbox), 0);
        // A fork inside the interval still goes.
        heads.forward(&channel, &record, None, true);
        assert_eq!(heads_in(&mut inbox), 1);

        // A full queue: the fork is held, and sent once there is room.
        for _ in 0..PEER_QUEUE {
            takes.send("filler", Vec::new()).unwrap();
        }
        heads.forward(&channel, &record, None, true);
        assert_eq!(heads.pending_forks(), 1);
        heads.retry_pending();
        assert_eq!(heads.pending_forks(), 1, "still no room");
        assert_eq!(heads_in(&mut inbox), 0, "only the filler was queued");
        heads.retry_pending();
        assert_eq!(heads.pending_forks(), 0);
        assert_eq!(heads_in(&mut inbox), 1);
    }

    /// A connection's allowance takes its burst, then refuses with the wait
    /// for one head, and takes one again after it.
    #[test]
    fn a_client_allowance_takes_its_burst_then_refills_at_its_rate() {
        let start = tokio::time::Instant::now();
        let mut allowance = ClientAllowance {
            tokens: f64::from(CLIENT_HEADS.burst),
            at: start,
        };
        for _ in 0..CLIENT_HEADS.burst {
            assert_eq!(allowance.take(start), Ok(()));
        }
        let per_head = Duration::from_secs(60) / CLIENT_HEADS.per_min;
        assert_eq!(allowance.take(start), Err(per_head));
        assert!(allowance.take(start + per_head / 2).is_err());
        assert_eq!(allowance.take(start + per_head), Ok(()));
        assert!(allowance.take(start + per_head).is_err());
    }

    /// A subscriber is told the highest head this server was handed, when
    /// it is past what the server serves; and nothing when there is none.
    #[tokio::test]
    async fn a_subscriber_is_told_of_a_head_past_what_is_served() {
        let (state, channel, held) = sequencing().await;
        let store = &state.ingest_ctx.store;
        assert!(for_subscriber(store, &channel).is_empty());
        let ahead = RecordSigner {
            channel_id: channel.clone(),
            key: &state.ingest_ctx.server_key,
            ingest_wall_ms: 99,
            ingest_logical: 0,
        }
        .sign(3, &channel, held.hash())
        .unwrap();
        let heads = Heads::new(
            state.ingest_ctx.clone(),
            Arc::new(state.config.federation.clone()),
            state.peers.clone(),
        );
        heads.take_from_peer(
            &Did::from_ed25519_pubkey(&[4; 32]),
            &channel,
            &ahead.cose_bytes().unwrap(),
        );
        use base64::Engine as _;
        assert_eq!(
            for_subscriber(store, &channel),
            vec![base64::engine::general_purpose::STANDARD.encode(ahead.cose_bytes().unwrap())]
        );
    }

    /// `jig-spec/jep/vectors/0002/heads.json` (JEP-0002 rule 10): one record,
    /// signed by a fixed key, as a block's `seen`, as a client's `head` frame
    /// and as a `channel-head` peer frame body. Regenerate after an intended
    /// change with `JIG_BLESS_HEADS_VECTORS=1`, and review the diff.
    #[test]
    fn heads_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../jig-spec/jep/vectors/0002/heads.json");
        let blessed = bless_heads_vectors();
        if std::env::var_os("JIG_BLESS_HEADS_VECTORS").is_some() {
            std::fs::write(&path, &blessed).unwrap();
        }
        let committed = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            committed, blessed,
            "regenerate with JIG_BLESS_HEADS_VECTORS=1"
        );

        // What an independent reader does with the committed bytes.
        let v: serde_json::Value = serde_json::from_str(&committed).unwrap();
        let envelope = hex::decode(v["record_cose_hex"].as_str().unwrap()).unwrap();
        let record = IngestRecord::from_cose(&envelope).unwrap();
        record.verify(v["sequencer"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(record.hash()), v["record_hash_hex"]);
        let body = hex::decode(v["channel_head_body_hex"].as_str().unwrap()).unwrap();
        assert_eq!(ChannelHead::decode(&body).unwrap().record, envelope);
        let frame = jig_pipeline::Envelope::parse(&v["head_frame"].to_string()).unwrap();
        assert!(matches!(frame.frame, jig_pipeline::Frame::Head { .. }));
    }

    use base64::Engine as _;
    use jig_pipeline::ingest_record::{
        GENESIS_PREV, IngestRecord, RecordSigner, SEEN_KEY, label_cid, seen_value,
    };

    fn bless_heads_vectors() -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let channel_id = label_cid("vector channel-create");
        let record = RecordSigner {
            channel_id: channel_id.clone(),
            key: &key,
            ingest_wall_ms: 1_700_000_000_000,
            ingest_logical: 3,
        }
        .sign(5, &label_cid("vector block"), GENESIS_PREV)
        .unwrap();
        let envelope = record.cose_bytes().unwrap();
        let frame = jig_pipeline::Envelope::new(jig_pipeline::Frame::Head {
            channel_id: channel_id.clone(),
            record_b64: base64::engine::general_purpose::STANDARD.encode(&envelope),
        });
        let vectors = serde_json::json!({
            "description": "One ingest record, signed by the ed25519 key whose seed is 32 bytes of \
                0x07, in the three places JEP-0002 rule 10 carries it: as a block's `seen` \
                (manifest metadata, base64 of the COSE_Sign1 envelope), in a client's `head` \
                frame, and as the deterministic-CBOR body of a `channel-head` peer frame. \
                `record` is the envelope's payload as fields; `record_hash_hex` is BLAKE3 of the \
                envelope, what the next record's `prev` names.",
            "sequencer": record.sequencer,
            "record": {
                "channel_id": record.channel_id,
                "seq": record.seq,
                "ingest_wall_ms": record.ingest_wall_ms,
                "ingest_logical": record.ingest_logical,
                "block_cid": record.block_cid,
                "prev": record.prev,
            },
            "record_cose_hex": hex::encode(&envelope),
            "record_hash_hex": hex::encode(record.hash()),
            "seen": { SEEN_KEY: seen_value(&record).unwrap() },
            "head_frame": serde_json::to_value(&frame).unwrap(),
            "channel_head_body_hex": hex::encode(ChannelHead {
                channel_id,
                record: envelope,
            }.encode()),
        });
        serde_json::to_string_pretty(&vectors).unwrap() + "\n"
    }
}
