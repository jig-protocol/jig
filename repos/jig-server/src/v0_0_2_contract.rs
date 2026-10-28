//! The channel contract between two servers (JEP-0005 rules 7-11 and 17):
//! offers, answers and ends, over the peer connection both servers proved
//! their DIDs on ([`crate::v0_0_2_peer`]).
//!
//! On the owner's side, the channel's blocks drive it:
//! - a `channel-share` this server sequences becomes a signed offer to the
//!   server it names, if that server is a configured peer. If it is not, the
//!   share is refused in the channel's log (`NOT_A_PEER`), and nothing is sent;
//! - the answer is recorded in the log as a `contract-accept` or a
//!   `contract-refuse`, carrying the signed messages;
//! - a `channel-unshare` ends the live share with the server it names, and
//!   withdraws an offer not yet answered.
//!
//! On the offered side, an offer this server cannot honour is refused:
//! - `NOT_A_PEER`: the owner is not a configured peer;
//! - `UNSUPPORTED_SUITE`: the channel's suite is not one this server carries.
//!   There is no fallback (rule 9);
//! - `SUFFIX_CONFLICT`: the owner attests a suffix this server attests too,
//!   under a different authority (JEP-0004 rule 7). Each side lists the
//!   suffixes it attests, each with its authority, so one suffix under one
//!   authority is no conflict;
//! - `POLICY_REFUSED`: the offer's creation block is not the channel's, or
//!   names another sequencer.
//!
//! Any other offer is accepted, or held for the operator
//! (`jig-server contracts accept` or `refuse`, [`operate`]), as the peer's
//! `offers` setting says. Either side may end a live share: the owner on a
//! `channel-unshare`, and the operator of either side with
//! `jig-server contracts end`. An end is sent once the other side is
//! connected, so it is not lost to a connection that is down.
//!
//! Each frame carries one signed message from [`jig_core::contract`]. A frame
//! that does not parse, or that is signed by a server other than the
//! connection's proven peer, closes the connection: that peer is not speaking
//! the contract.
//!
//! A live share carries the owner's stream to the follower
//! ([`crate::v0_0_2_stream`], rules 12-14), on the same connection. The
//! follower's relayed writes (rule 15) come in a later slice.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use cid::Cid;
use jig_config::v0_0_2_server::{FederationPeer, FederationSection, OfferPolicy};
use jig_core::block_kind::BlockKind;
use jig_core::contract::{
    AttestedSuffix, ContractAccept, ContractEnd, ContractOffer, ContractRefuse, Grant, ManifestRef,
    RefuseCode,
};
use jig_core::did::Did;
use jig_core::{Author, BlockBundle, BlockManifest};
use jig_pipeline::contracts::{self, OfferState, Side, StoredOffer};
use jig_pipeline::ingest::{IngestContext, IngestSource, ingest};
use jig_pipeline::persist::{SqliteStore, StoredBlock, StoredChannel};

use crate::v0_0_2::AppState;
use crate::v0_0_2_peer::{CloseReason, PeerFrames, PeerRegistry, PeerSender};
use crate::v0_0_2_relay::Relay;
use crate::v0_0_2_stream::Stream;

/// The owner's offer: one signed `contract-offer`.
pub const OFFER_FRAME: &str = "contract-offer";
/// The offered server's answer: one signed `contract-accept` or
/// `contract-refuse`.
pub const ANSWER_FRAME: &str = "contract-answer";
/// Either side's end of a share, or the owner's withdrawal of an offer not
/// yet answered: one signed `contract-end`.
pub const END_FRAME: &str = "contract-end";

/// How often the owner sends its unanswered offers again. A send fails while
/// there is no connection to the peer, so an offer made then goes out
/// within this long of the connection coming up. Answering is idempotent: an
/// offer sent twice is answered with the same message.
pub const RESEND_EVERY: Duration = Duration::from_secs(30);

/// How often the running server acts on its operator's decisions
/// ([`operate`]) and sends the ends still waiting for a connection.
pub const DECIDE_EVERY: Duration = Duration::from_secs(5);

/// One server's side of every contract it takes part in.
#[derive(Clone)]
pub struct Contracts {
    ctx: Arc<IngestContext>,
    federation: Arc<FederationSection>,
    manifest: Arc<RwLock<Option<jig_pipeline::handshake::ManifestRef>>>,
    peers: Arc<PeerRegistry>,
    stream: Stream,
    /// The same [`Relay`] as `AppState::relay`, once [`handle`] has set it:
    /// one table of requests waiting on owners.
    relay: Arc<Relay>,
    /// Serves `federation-catch-up` to the peers that dial this server.
    replay: crate::v0_0_2_catch_up::Replay,
}

/// Run the contract on `state`'s server:
/// - register its peer-frame handler;
/// - watch for share blocks;
/// - resend unanswered offers every [`RESEND_EVERY`];
/// - act on the operator's decisions every [`DECIDE_EVERY`];
/// - ask each followed channel's owner for its new records every
///   [`crate::v0_0_2_stream::PULL_EVERY`].
///
/// Call once, at boot.
pub fn start(state: &AppState) -> Contracts {
    let contracts = handle(state);
    let resender = contracts.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RESEND_EVERY);
        loop {
            tick.tick().await;
            resender.resend_offers();
        }
    });
    let decider = contracts.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(DECIDE_EVERY);
        loop {
            tick.tick().await;
            decider.act_on_decisions().await;
        }
    });
    let puller = contracts.stream.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(crate::v0_0_2_stream::PULL_EVERY);
        loop {
            tick.tick().await;
            puller.pull_all();
        }
    });
    contracts
}

/// Register the peer-frame handler, watch for share blocks and stream the
/// blocks of shared channels, with no timers: what [`start`] runs, less the
/// resending, the decisions and the pulls.
fn handle(state: &AppState) -> Contracts {
    let contracts = Contracts::new(state);
    repair_relayed_copies(&state.ingest_ctx.store);
    if !state.set_peer_frames(Arc::new(contracts.clone())) {
        tracing::warn!("a peer-frame handler was already registered; contract frames go to it");
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    state
        .ingest_ctx
        .fanout
        .watch_kinds(&[BlockKind::ChannelShare, BlockKind::ChannelUnshare], tx);
    let watcher = contracts.clone();
    tokio::spawn(async move {
        while let Some((block, _receipt)) = rx.recv().await {
            if let Err(e) = watcher.on_share_block(&block).await {
                tracing::warn!(block = %block.cid, "share not acted on: {e:#}");
            }
        }
    });
    contracts.stream.run();
    if state.relay.set(contracts.relay.clone()).is_err() {
        tracing::warn!("a relay was already set; relayed writes go through it");
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    state.ingest_ctx.fanout.watch_all(tx);
    let streamer = contracts.stream.clone();
    tokio::spawn(async move {
        while let Some((block, _receipt)) = rx.recv().await {
            if let Err(e) = streamer.on_block(&block) {
                tracing::warn!(block = %block.cid, "block not streamed: {e:#}");
            }
        }
    });
    contracts
}

/// Set aside this server's relayed copy of `channel_id`, if it holds one,
/// now that it follows the channel's owner for it: the owner's stream lands
/// the channel under its own id, from its first block, in the owner's order.
/// The copy is kept, whole ([`SqliteStore::quarantine_relayed_copy`]).
fn quarantine_relayed_copy(store: &SqliteStore, channel_id: &str) {
    match store.quarantine_relayed_copy(channel_id) {
        Ok(Some(copy)) => tracing::warn!(
            channel_id,
            copy_id = copy.copy_id,
            slug = copy.slug,
            own_blocks = copy.own_blocks,
            "set aside the federation relay's copy of a channel this server now follows; \
             blocks this server's users posted in it stay in the copy"
        ),
        Ok(None) => {}
        Err(e) => tracing::warn!(
            channel_id,
            "the relayed copy of a followed channel was not set aside: {e:#}"
        ),
    }
}

/// At boot: a server that accepted a share while it held the relay's copy of
/// the channel (before this was handled) sequences a copy of a channel it
/// follows, and its stream refuses the owner's every record. Set each such
/// copy aside, so the stream lands the channel. Report the copies left: the
/// relay keeps one of each open channel of a peer, until it is shared.
fn repair_relayed_copies(store: &SqliteStore) {
    let copies = match store.relayed_copies() {
        Ok(copies) => copies,
        Err(e) => {
            tracing::warn!("listing the federation relay's copies: {e:#}");
            return;
        }
    };
    let mut followed = 0;
    for channel_id in &copies {
        if store.is_followed(channel_id).unwrap_or(false) {
            followed += 1;
            quarantine_relayed_copy(store, channel_id);
        }
    }
    if followed > 0 {
        tracing::warn!(
            followed,
            "set aside relayed copies of channels this server follows"
        );
    }
    if copies.len() > followed {
        tracing::info!(
            copies = copies.len() - followed,
            "channels held as federation relay copies; sharing one sets its copy aside"
        );
    }
}

impl Contracts {
    pub fn new(state: &AppState) -> Self {
        let federation = Arc::new(state.config.federation.clone());
        Self {
            ctx: state.ingest_ctx.clone(),
            federation: federation.clone(),
            manifest: state.manifest.clone(),
            peers: state.peers.clone(),
            stream: Stream::new(
                state.ingest_ctx.clone(),
                federation.clone(),
                state.peers.clone(),
            ),
            relay: state.relay.get().cloned().unwrap_or_else(|| {
                Arc::new(Relay::new(
                    state.ingest_ctx.clone(),
                    &federation,
                    state.peers.clone(),
                ))
            }),
            replay: crate::v0_0_2_catch_up::Replay::new(state.ingest_ctx.clone(), federation),
        }
    }

    fn me(&self) -> String {
        self.ctx.server_did.to_did_jig_string()
    }

    fn store(&self) -> &SqliteStore {
        &self.ctx.store
    }

    /// The configured peer whose DID is `did`.
    fn peer(&self, did: &str) -> Option<&FederationPeer> {
        self.federation
            .peers
            .iter()
            .find(|p| jig_pipeline::effect::canonical_did_string(&p.expected_did) == did)
    }

    /// This server's current `server-manifest`, as contract messages cite it.
    fn manifest_ref(&self) -> anyhow::Result<ManifestRef> {
        let current = self
            .manifest
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .context("this server has published no server-manifest yet")?;
        Ok(ManifestRef {
            cid: current.cid.parse().context("the server-manifest's CID")?,
            seq: current.seq,
        })
    }

    /// The suffixes this server attests, as its contract messages list them:
    /// its `[[federation.attested_suffixes]]`, each `dns`-rooted under its own
    /// name. It attests no `config`-rooted suffix yet.
    fn attested(&self) -> Vec<AttestedSuffix> {
        let mut ours: Vec<AttestedSuffix> = self
            .federation
            .attested_suffixes
            .iter()
            .map(|a| {
                let suffix = a.suffix.to_lowercase();
                AttestedSuffix::dns(suffix.clone(), suffix)
            })
            .collect();
        // `validate` refuses a repeated suffix; a message names each once.
        ours.dedup_by(|a, b| a.suffix == b.suffix);
        ours
    }

    /// A suffix in `theirs` that this server attests under another authority.
    fn suffix_conflict(&self, theirs: &[AttestedSuffix]) -> Option<String> {
        let ours = self.attested();
        theirs
            .iter()
            .find(|t| ours.iter().any(|o| o.conflicts_with(t)))
            .map(|t| t.suffix.clone())
    }

    /// Send `body` to `peer` on its live connection. A peer with none gets
    /// it on a later try: the owner resends its unanswered offers, and an
    /// answer goes out again when the offer comes again.
    fn send(&self, peer: &str, kind: &str, body: Vec<u8>) {
        let Ok(did) = Did::from_did_jig_string(peer) else {
            return;
        };
        match self.peers.sender_for(&did) {
            Some(sender) => {
                if let Err(e) = sender.send(kind, body) {
                    tracing::info!(peer, kind, "contract frame not sent: {e}");
                }
            }
            None => tracing::debug!(peer, kind, "no live connection to the peer"),
        }
    }

    /// Send every unanswered offer again.
    pub fn resend_offers(&self) {
        match self
            .store()
            .contract_offers_in(Side::Owner, OfferState::Offered)
        {
            Ok(offers) => {
                for offer in offers {
                    if self.may_offer(&offer.channel_id, &offer.peer_did) {
                        self.send(&offer.peer_did, OFFER_FRAME, offer.offer);
                    }
                }
            }
            Err(e) => tracing::warn!("listing unanswered offers: {e}"),
        }
    }

    // ---- The owner's side --------------------------------------------------

    /// Act on a `channel-share` or `channel-unshare` that has landed, if this
    /// server sequences its channel.
    async fn on_share_block(&self, block: &StoredBlock) -> anyhow::Result<()> {
        let Some(channel_id) = block.channel_id.as_deref() else {
            return Ok(());
        };
        let Some(channel) = self.store().get_channel_by_id(channel_id)? else {
            return Ok(());
        };
        if jig_pipeline::effect::canonical_did_string(&channel.sequencer_did) != self.me() {
            return Ok(());
        }
        let kind: BlockKind = block.block_kind.parse()?;
        let request = contracts::share_request(kind, &manifest_of(&block.bundle_bytes)?)?;
        match request.grant {
            Some(grant) => self.offer(&channel, &block.cid, &request.to, grant).await,
            None => self.unshare(&channel, &request.to).await,
        }
    }

    async fn offer(
        &self,
        channel: &StoredChannel,
        share_cid: &str,
        to: &str,
        grant: Grant,
    ) -> anyhow::Result<()> {
        // Design 5.7: a share naming a server that is not a configured peer
        // fails visibly in the channel's log. The owner's signature never
        // adds a peer; an operator does.
        if self.peer(to).is_none() {
            self.record(
                channel,
                BlockKind::ContractRefuse,
                serde_json::json!({
                    contracts::TO_KEY: to,
                    contracts::CODE_KEY: RefuseCode::NotAPeer.as_str(),
                }),
            )
            .await?;
            return Ok(());
        }
        let creation = self
            .store()
            .get_block(&channel.id)?
            .context("the channel has no creation block")?;
        let head = self
            .store()
            .latest_ingest_record(&channel.id)?
            .context("the channel has no ingest record")?;
        let offer = ContractOffer::sign(
            &self.ctx.server_key,
            to,
            channel.id.parse()?,
            grant,
            creation.bundle_bytes,
            head.encode(),
            self.manifest_ref()?,
            self.attested(),
        );
        self.store().put_contract_offer(&StoredOffer {
            offer_id: offer.offer_id,
            channel_id: channel.id.clone(),
            side: Side::Owner,
            peer_did: to.to_string(),
            grant,
            state: OfferState::Offered,
            offer: offer.envelope.clone(),
            answer: None,
            share_cid: Some(share_cid.to_string()),
        })?;
        if self.may_offer(&channel.id, to) {
            self.send(to, OFFER_FRAME, offer.envelope);
        }
        Ok(())
    }

    /// Whether `channel`'s offer may go to `peer` now. A `shared` channel's
    /// offer waits for a connection whose handshake says the peer implements
    /// tiers (JEP-0014): a server without them would carry it as an untiered
    /// channel. It stays unanswered, and goes out on a later resend once the
    /// peer has upgraded.
    fn may_offer(&self, channel_id: &str, peer: &str) -> bool {
        use jig_core::tier::{StoredTier, Tier};
        let shared = self
            .store()
            .get_channel_by_id(channel_id)
            .ok()
            .flatten()
            .is_some_and(|c| c.tiering.tier == StoredTier::Tier(Tier::Shared));
        if !shared {
            return true;
        }
        let Ok(did) = Did::from_did_jig_string(peer) else {
            return false;
        };
        match self.peers.sender_for(&did) {
            Some(sender) if !sender.tiers() => {
                tracing::info!(
                    peer,
                    channel_id,
                    "a shared channel's offer waits: the peer does not implement tiers"
                );
                false
            }
            _ => true,
        }
    }

    /// End the live share with `to`, and withdraw any offer to it not yet
    /// answered.
    async fn unshare(&self, channel: &StoredChannel, to: &str) -> anyhow::Result<()> {
        let channel_id: Cid = channel.id.parse()?;
        let store = self.store();
        for live in store.contract_offers_for(&channel.id, to, Side::Owner, OfferState::Accepted)? {
            store.move_contract_offer(
                &live.offer_id,
                OfferState::Accepted,
                OfferState::Ending,
                None,
            )?;
        }
        self.deliver_ends().await;
        for pending in
            store.contract_offers_for(&channel.id, to, Side::Owner, OfferState::Offered)?
        {
            if store.move_contract_offer(
                &pending.offer_id,
                OfferState::Offered,
                OfferState::Withdrawn,
                None,
            )? {
                let end = ContractEnd::sign(&self.ctx.server_key, channel_id, pending.offer_id);
                self.send(to, END_FRAME, end.envelope);
            }
        }
        Ok(())
    }

    /// Record what an answer says, once: an answer that arrives twice, or
    /// after the offer was withdrawn, changes nothing.
    async fn on_answer(&self, kept: StoredOffer, answer: Answer) -> anyhow::Result<()> {
        let Some(channel) = self.store().get_channel_by_id(&kept.channel_id)? else {
            return Ok(());
        };
        let to = kept.peer_did.as_str();
        match answer {
            Answer::Accept(accept) => {
                // The contract is refused when the two servers claim one
                // suffix under different authorities, whichever side found
                // it (JEP-0004 rule 7).
                if self.suffix_conflict(&accept.attested_suffixes).is_some() {
                    if self.store().move_contract_offer(
                        &kept.offer_id,
                        OfferState::Offered,
                        OfferState::Refused,
                        None,
                    )? {
                        let end = ContractEnd::sign(
                            &self.ctx.server_key,
                            accept.channel_id,
                            kept.offer_id,
                        );
                        self.send(to, END_FRAME, end.envelope);
                        self.record(
                            &channel,
                            BlockKind::ContractRefuse,
                            serde_json::json!({
                                contracts::TO_KEY: to,
                                contracts::CODE_KEY: RefuseCode::SuffixConflict.as_str(),
                            }),
                        )
                        .await?;
                    }
                    return Ok(());
                }
                if self.store().move_contract_offer(
                    &kept.offer_id,
                    OfferState::Offered,
                    OfferState::Accepted,
                    Some(&accept.envelope),
                )? {
                    self.record(
                        &channel,
                        BlockKind::ContractAccept,
                        serde_json::json!({
                            contracts::TO_KEY: to,
                            contracts::OFFER_KEY: b64(&kept.offer),
                            contracts::ACCEPT_KEY: b64(&accept.envelope),
                        }),
                    )
                    .await?;
                } else if matches!(
                    kept.state,
                    OfferState::Withdrawn | OfferState::Ending | OfferState::Ended
                ) {
                    // Accepted after this side let it go: tell the follower,
                    // so it does not carry a share the owner does not.
                    let end =
                        ContractEnd::sign(&self.ctx.server_key, accept.channel_id, kept.offer_id);
                    self.send(to, END_FRAME, end.envelope);
                }
            }
            Answer::Refuse(refuse) => {
                if self.store().move_contract_offer(
                    &kept.offer_id,
                    OfferState::Offered,
                    OfferState::Refused,
                    Some(&refuse.envelope),
                )? {
                    self.record(
                        &channel,
                        BlockKind::ContractRefuse,
                        serde_json::json!({
                            contracts::TO_KEY: to,
                            contracts::CODE_KEY: refuse.code.as_str(),
                            contracts::OFFER_KEY: b64(&kept.offer),
                            contracts::REFUSE_KEY: b64(&refuse.envelope),
                        }),
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn record_end(
        &self,
        channel: &StoredChannel,
        to: &str,
        end: &ContractEnd,
    ) -> anyhow::Result<()> {
        self.record(
            channel,
            BlockKind::ContractEnd,
            serde_json::json!({
                contracts::TO_KEY: to,
                contracts::END_KEY: b64(&end.envelope),
            }),
        )
        .await
    }

    /// Append a contract record to `channel`'s log, signed by this server,
    /// its sequencer (rule 10).
    async fn record(
        &self,
        channel: &StoredChannel,
        kind: BlockKind,
        fields: serde_json::Value,
    ) -> anyhow::Result<()> {
        use ed25519_dalek::Signer as _;
        let mut builder = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: self.me().into(),
                public_key: None,
                roles: vec!["jig-server".to_string()],
            })
            .metadata_entry("channel_id", serde_json::json!(channel.id));
        if let serde_json::Value::Object(fields) = fields {
            for (key, value) in fields {
                builder = builder.metadata_entry(&key, value);
            }
        }
        let manifest_bytes = builder.build()?.with_kind(kind).to_canonical_bytes()?;
        let code_bytes: Vec<u8> = Vec::new();
        let sig = self
            .ctx
            .server_key
            .sign(&serde_json::to_vec(&(&manifest_bytes, &code_bytes))?)
            .to_bytes()
            .to_vec();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &code_bytes,
            resources: vec![],
        };
        ingest(&self.ctx, bundle, sig, IngestSource::AdminEndpoint)
            .await
            .with_context(|| format!("recording a {kind:?} in {}", channel.id))?;
        Ok(())
    }

    // ---- The offered side --------------------------------------------------

    /// Answer `offer` from `owner`, or hold it. An offer already kept is
    /// answered as it was before, if it has been.
    fn on_offer(&self, offer: ContractOffer, out: &PeerSender) -> anyhow::Result<()> {
        if let Some(kept) = self.store().get_contract_offer(&offer.offer_id)? {
            if let Some(answer) = kept.answer {
                send_on(out, ANSWER_FRAME, answer);
            }
            return Ok(());
        }
        self.store().put_contract_offer(&StoredOffer {
            offer_id: offer.offer_id,
            channel_id: offer.channel_id.to_string(),
            side: Side::Follower,
            peer_did: offer.owner.clone(),
            grant: offer.grant,
            state: OfferState::Held,
            offer: offer.envelope.clone(),
            answer: None,
            share_cid: None,
        })?;
        let answer = match self.judge(&offer) {
            Err(code) => self.refuse(&offer, code, OfferState::Held)?,
            Ok(OfferPolicy::Accept) => self.accept(&offer, OfferState::Held)?,
            Ok(OfferPolicy::Hold) => {
                tracing::info!(
                    owner = %offer.owner,
                    channel = %offer.channel_id,
                    grant = offer.grant.as_str(),
                    "holding a contract offer for the operator"
                );
                return Ok(());
            }
        };
        send_on(out, ANSWER_FRAME, answer);
        Ok(())
    }

    /// Whether this server can honour `offer`, and if so, what its owner's
    /// peer entry says to do with it.
    fn judge(&self, offer: &ContractOffer) -> Result<OfferPolicy, RefuseCode> {
        // Rule 17: only a configured peer.
        let policy = self.peer(&offer.owner).ok_or(RefuseCode::NotAPeer)?.offers;
        // The creation block is the channel's, and names its owner as the
        // sequencer.
        let (manifest, cid) =
            creation_of(&offer.creation_block).ok_or(RefuseCode::PolicyRefused)?;
        if cid != offer.channel_id || manifest.kind != Some(BlockKind::ChannelCreate) {
            return Err(RefuseCode::PolicyRefused);
        }
        let terms = jig_pipeline::ingest::channel_terms(&manifest, &offer.owner)
            .map_err(|_| RefuseCode::PolicyRefused)?;
        if terms.sequencer != offer.owner {
            return Err(RefuseCode::PolicyRefused);
        }
        // A tier that stays on its owner's server is not carried here,
        // whatever its owner offers.
        if let Some(tiering) = &terms.tiering
            && !contracts::crosses_servers(tiering.tier)
        {
            return Err(RefuseCode::PolicyRefused);
        }
        // Rule 9: a suite this server carries, and no fallback.
        let suite = jig_pipeline::mls_gate::requested_suite(&manifest)
            .map_err(|_| RefuseCode::UnsupportedSuite)?;
        if !suite.is_implemented() {
            return Err(RefuseCode::UnsupportedSuite);
        }
        if self.suffix_conflict(&offer.attested_suffixes).is_some() {
            return Err(RefuseCode::SuffixConflict);
        }
        // A channel of this server's own under the offered id: it cannot
        // follow another sequencer for it. A copy the federation relay made
        // is not one; accepting sets it aside.
        let local = self.store().local_sequencer().to_string();
        let owned_here = self
            .store()
            .get_channel_by_id_including_archived(&offer.channel_id.to_string())
            .ok()
            .flatten()
            .is_some_and(|c| c.sequencer_did.is_empty() || c.sequencer_did == local);
        if owned_here
            && !self
                .store()
                .relayed_copies()
                .unwrap_or_default()
                .contains(&offer.channel_id.to_string())
        {
            return Err(RefuseCode::PolicyRefused);
        }
        Ok(policy)
    }

    /// Accept an offer in `from`: sign, record, and return the accept.
    fn accept(&self, offer: &ContractOffer, from: OfferState) -> anyhow::Result<Vec<u8>> {
        let accept = ContractAccept::sign(
            &self.ctx.server_key,
            offer,
            self.manifest_ref()?,
            self.attested(),
            Vec::new(),
        );
        self.store().move_contract_offer(
            &offer.offer_id,
            from,
            OfferState::Accepted,
            Some(&accept.envelope),
        )?;
        quarantine_relayed_copy(self.store(), &offer.channel_id.to_string());
        Ok(accept.envelope)
    }

    /// Refuse an offer in `from` with `code`: sign, record, and return the
    /// refusal.
    fn refuse(
        &self,
        offer: &ContractOffer,
        code: RefuseCode,
        from: OfferState,
    ) -> anyhow::Result<Vec<u8>> {
        tracing::info!(owner = %offer.owner, channel = %offer.channel_id, code = code.as_str(), "refusing a contract offer");
        let refuse = ContractRefuse::sign(&self.ctx.server_key, offer, code);
        self.store().move_contract_offer(
            &offer.offer_id,
            from,
            OfferState::Refused,
            Some(&refuse.envelope),
        )?;
        Ok(refuse.envelope)
    }

    /// Act on what the operator decided ([`operate`]):
    /// - an offer to accept is accepted if this server can still honour it,
    ///   and refused with the reason otherwise. What made it acceptable may
    ///   have changed while it waited;
    /// - an offer to refuse is refused (`POLICY_REFUSED`);
    /// - a share to end is ended once the other side is connected.
    ///
    /// An answer goes to the owner now if it is connected, and otherwise when
    /// the owner sends the offer again.
    pub async fn act_on_decisions(&self) {
        let store = self.store();
        let decided = |state| {
            store
                .contract_offers_in(Side::Follower, state)
                .unwrap_or_else(|e| {
                    tracing::warn!("listing decided offers: {e}");
                    Vec::new()
                })
        };
        for (state, accepting) in [(OfferState::Accepting, true), (OfferState::Refusing, false)] {
            for kept in decided(state) {
                let answer = ContractOffer::from_envelope(&kept.offer)
                    .map_err(anyhow::Error::from)
                    .and_then(|offer| match self.judge(&offer) {
                        Ok(_) if accepting => self.accept(&offer, state),
                        Ok(_) => self.refuse(&offer, RefuseCode::PolicyRefused, state),
                        Err(code) => self.refuse(&offer, code, state),
                    });
                match answer {
                    Ok(answer) => self.send(&kept.peer_did, ANSWER_FRAME, answer),
                    Err(e) => tracing::warn!("contract offer not answered: {e:#}"),
                }
            }
        }
        self.deliver_ends().await;
    }

    /// Send each end this server decided on to the other side, and once it
    /// is on a live connection, count the share ended. The owner records the
    /// end in the channel's log.
    async fn deliver_ends(&self) {
        let store = self.store();
        for side in [Side::Owner, Side::Follower] {
            let ending = store
                .contract_offers_in(side, OfferState::Ending)
                .unwrap_or_default();
            for kept in ending {
                if let Err(e) = self.deliver_end(&kept).await {
                    tracing::warn!(peer = %kept.peer_did, "contract end not delivered: {e:#}");
                }
            }
        }
    }

    async fn deliver_end(&self, kept: &StoredOffer) -> anyhow::Result<()> {
        let peer = Did::from_did_jig_string(&kept.peer_did)?;
        let Some(sender) = self.peers.sender_for(&peer) else {
            return Ok(());
        };
        let end = ContractEnd::sign(
            &self.ctx.server_key,
            kept.channel_id.parse()?,
            kept.offer_id,
        );
        sender.send(END_FRAME, end.envelope.clone())?;
        if self.store().move_contract_offer(
            &kept.offer_id,
            OfferState::Ending,
            OfferState::Ended,
            None,
        )? && kept.side == Side::Owner
            && let Some(channel) = self.store().get_channel_by_id(&kept.channel_id)?
        {
            self.record_end(&channel, &kept.peer_did, &end).await?;
        }
        Ok(())
    }

    /// The other side's end of a share, or the owner's withdrawal of an offer
    /// this server holds. The owner records an end in the channel's log.
    async fn on_end(&self, kept: StoredOffer, end: ContractEnd) -> anyhow::Result<()> {
        let store = self.store();
        // A live share, or one this side was ending too.
        for live in [OfferState::Accepted, OfferState::Ending] {
            if store.move_contract_offer(&kept.offer_id, live, OfferState::Ended, None)? {
                if kept.side == Side::Owner
                    && let Some(channel) = store.get_channel_by_id(&kept.channel_id)?
                {
                    self.record_end(&channel, &kept.peer_did, &end).await?;
                }
                return Ok(());
            }
        }
        // An offer withdrawn before this side answered it.
        if kept.side == Side::Follower {
            for waiting in [
                OfferState::Held,
                OfferState::Accepting,
                OfferState::Refusing,
            ] {
                store.move_contract_offer(&kept.offer_id, waiting, OfferState::Withdrawn, None)?;
            }
        }
        Ok(())
    }
}

/// A `contract-answer`'s message.
enum Answer {
    Accept(ContractAccept),
    Refuse(ContractRefuse),
}

impl PeerFrames for Contracts {
    fn on_peer_frame(
        &self,
        peer: &Did,
        kind: &str,
        body: &[u8],
        out: &PeerSender,
    ) -> Result<(), CloseReason> {
        if let Some(handled) = self.stream.on_peer_frame(peer, kind, body, out) {
            return handled;
        }
        if let Some(handled) = self.relay.on_peer_frame(peer, kind, body, out) {
            return handled;
        }
        if let Some(handled) = self.replay.on_peer_frame(peer, kind, body, out) {
            return handled;
        }
        let peer = peer.to_did_jig_string();
        match kind {
            OFFER_FRAME => {
                let offer = ContractOffer::from_envelope(body).map_err(violation)?;
                if offer.owner != peer {
                    return Err(violation("an offer signed by a server other than the peer"));
                }
                if offer.to != self.me() {
                    return Err(violation("an offer made to another server"));
                }
                if let Err(e) = self.on_offer(offer, out) {
                    tracing::warn!(peer, "contract offer not answered: {e:#}");
                }
            }
            ANSWER_FRAME => {
                let answer = match ContractAccept::from_envelope(body) {
                    Ok(accept) => Answer::Accept(accept),
                    Err(_) => {
                        Answer::Refuse(ContractRefuse::from_envelope(body).map_err(violation)?)
                    }
                };
                let (offer_id, server) = match &answer {
                    Answer::Accept(a) => (a.offer_id, a.server.clone()),
                    Answer::Refuse(r) => (r.offer_id, r.server.clone()),
                };
                if server != peer {
                    return Err(violation(
                        "an answer signed by a server other than the peer",
                    ));
                }
                let Some(kept) = self.kept(&offer_id, Side::Owner, &peer) else {
                    return Ok(());
                };
                let offer = ContractOffer::from_envelope(&kept.offer).map_err(violation)?;
                match &answer {
                    Answer::Accept(a) => a.answers(&offer),
                    Answer::Refuse(r) => r.answers(&offer),
                }
                .map_err(violation)?;
                let contracts = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = contracts.on_answer(kept, answer).await {
                        tracing::warn!("contract answer not recorded: {e:#}");
                    }
                });
            }
            END_FRAME => {
                let end = ContractEnd::from_envelope(body).map_err(violation)?;
                if end.server != peer {
                    return Err(violation("an end signed by a server other than the peer"));
                }
                let kept = [Side::Owner, Side::Follower]
                    .into_iter()
                    .find_map(|side| self.kept(&end.offer_id, side, &peer));
                let Some(kept) = kept else {
                    return Ok(());
                };
                if kept.channel_id != end.channel_id.to_string() {
                    return Err(violation("an end for another channel"));
                }
                let contracts = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = contracts.on_end(kept, end).await {
                        tracing::warn!("contract end not recorded: {e:#}");
                    }
                });
            }
            // A frame for a later slice of the contract, or another
            // extension: not this handler's to judge.
            other => tracing::debug!(peer, kind = other, "peer frame this server does not speak"),
        }
        Ok(())
    }
}

impl Contracts {
    /// The offer `offer_id` on `side`, if it was made with `peer`.
    fn kept(&self, offer_id: &[u8; 32], side: Side, peer: &str) -> Option<StoredOffer> {
        match self.store().get_contract_offer(offer_id) {
            Ok(kept) => kept.filter(|o| o.side == side && o.peer_did == peer),
            Err(e) => {
                tracing::warn!("reading a contract offer: {e}");
                None
            }
        }
    }
}

/// What the operator asks of this server's contracts, as
/// `jig-server contracts ...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Every offer this server made or received.
    List,
    /// Accept a held offer.
    Accept(String),
    /// Refuse a held offer.
    Refuse(String),
    /// End a live share, on either side.
    End(String),
}

/// Record the operator's decision in `store`, and say what was done. The
/// running server acts on it within [`DECIDE_EVERY`]: it holds the key that
/// signs, and the connection to the other side, so this needs neither.
///
/// An offer is named by its id in hex, or by a prefix of it that names one
/// offer.
pub fn operate(store: &SqliteStore, operation: Operation) -> anyhow::Result<String> {
    let (id, side, from, to, verb) = match operation {
        Operation::List => return list(store),
        Operation::Accept(id) => (
            id,
            Some(Side::Follower),
            OfferState::Held,
            OfferState::Accepting,
            "accepted",
        ),
        Operation::Refuse(id) => (
            id,
            Some(Side::Follower),
            OfferState::Held,
            OfferState::Refusing,
            "refused",
        ),
        Operation::End(id) => (id, None, OfferState::Accepted, OfferState::Ending, "ended"),
    };
    let offer = find(store, &id)?;
    if side.is_some_and(|side| side != offer.side) || offer.state != from {
        anyhow::bail!(
            "offer {} is {} on the {} side; only {} offers{} can be {verb}",
            hex(&offer.offer_id),
            offer.state.as_str(),
            offer.side.as_str(),
            from.as_str(),
            if side.is_some() {
                " this server received"
            } else {
                ""
            },
        );
    }
    if !store.move_contract_offer(&offer.offer_id, from, to, None)? {
        anyhow::bail!(
            "offer {} changed while this ran; list it again",
            hex(&offer.offer_id)
        );
    }
    Ok(format!(
        "offer {} will be {verb} by the running server within {} seconds",
        hex(&offer.offer_id),
        DECIDE_EVERY.as_secs()
    ))
}

fn list(store: &SqliteStore) -> anyhow::Result<String> {
    let offers = store.list_contract_offers()?;
    if offers.is_empty() {
        return Ok("no contract offers".to_string());
    }
    let mut lines = offers
        .iter()
        .map(|o| {
            format!(
                "{}  {:<8} {:<10} {:<6} peer {}  channel {}",
                hex(&o.offer_id),
                o.side.as_str(),
                o.state.as_str(),
                o.grant.as_str(),
                o.peer_did,
                o.channel_id
            )
        })
        .collect::<Vec<_>>();
    // A carried channel that cannot take its owner's next record, and why
    // (deploy/README.md, "A stalled carried channel").
    lines.extend(
        store
            .carried_stalls()?
            .iter()
            .map(|stall| format!("stalled: {stall}")),
    );
    Ok(lines.join("\n"))
}

/// The one offer whose hex id starts with `prefix`.
fn find(store: &SqliteStore, prefix: &str) -> anyhow::Result<StoredOffer> {
    let prefix = prefix.trim().to_ascii_lowercase();
    if prefix.len() < 8 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("`{prefix}` is not an offer id: give at least 8 of its hex digits");
    }
    let mut found = store
        .list_contract_offers()?
        .into_iter()
        .filter(|o| hex(&o.offer_id).starts_with(&prefix));
    match (found.next(), found.next()) {
        (Some(offer), None) => Ok(offer),
        (None, _) => anyhow::bail!("no offer id starts with {prefix}"),
        (Some(_), Some(_)) => anyhow::bail!("more than one offer id starts with {prefix}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn violation(why: impl std::fmt::Display) -> CloseReason {
    CloseReason {
        code: jig_pipeline::handshake::close::PROTOCOL_VIOLATION,
        reason: format!("contract: {why}"),
    }
}

fn send_on(out: &PeerSender, kind: &str, body: Vec<u8>) {
    if let Err(e) = out.send(kind, body) {
        tracing::info!(kind, "contract frame not sent: {e}");
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The manifest of a stored block's bundle.
fn manifest_of(bundle_bytes: &[u8]) -> anyhow::Result<BlockManifest> {
    let (manifest_bytes, _code): (Vec<u8>, Vec<u8>) = serde_json::from_slice(bundle_bytes)?;
    Ok(serde_json::from_slice(&manifest_bytes)?)
}

/// A creation block as an offer carries it, and the CID it hashes to.
fn creation_of(bundle_bytes: &[u8]) -> Option<(BlockManifest, Cid)> {
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(bundle_bytes).ok()?;
    let cid = BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    }
    .block_cid()
    .ok()?;
    Some((serde_json::from_slice(&manifest_bytes).ok()?, cid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jig_config::v0_0_2_server::{AttestedSuffixConfig, JigServerConfig};
    use jig_pipeline::ingest::IngestError;

    fn did_of(key: &SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    fn peer(url: &str, expected_did: String, offers: OfferPolicy) -> FederationPeer {
        FederationPeer {
            url: url.trim_end_matches("/api/v1/ws").to_string(),
            expected_did,
            alias: None,
            publish: false,
            quota: None,
            offers,
        }
    }

    fn state_with(peers: Vec<FederationPeer>, attested: &[&str]) -> AppState {
        state_tuned(peers, attested, |_| {})
    }

    /// [`state_with`], with `tune` applied to the configuration first.
    fn state_tuned(
        peers: Vec<FederationPeer>,
        attested: &[&str],
        tune: impl FnOnce(&mut JigServerConfig),
    ) -> AppState {
        let mut config = JigServerConfig::default();
        config.federation.dangerously_allow_plaintext_federation = true;
        config.federation.peers = peers;
        config.federation.attested_suffixes = attested
            .iter()
            .map(|s| AttestedSuffixConfig {
                suffix: s.to_string(),
                root: "dns".to_string(),
            })
            .collect();
        tune(&mut config);
        AppState::for_test_with_config(config).unwrap()
    }

    async fn serve(state: AppState) -> (Arc<AppState>, String) {
        let state = Arc::new(state);
        let app = axum::Router::new()
            .route(
                "/api/v1/ws",
                axum::routing::get(crate::v0_0_2_ws::ws_handler),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/api/v1/ws", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (state, url)
    }

    async fn eventually<T>(what: &str, f: impl Fn() -> Option<T>) -> T {
        for _ in 0..500 {
            if let Some(t) = f() {
                return t;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    /// An owning server and a follower, connected, each running its side of
    /// the contract. The follower takes the owner's offers as `offers` says.
    struct Pair {
        owner: Arc<AppState>,
        follower: Arc<AppState>,
        follows: Contracts,
        user: SigningKey,
        /// The owner's dial to the follower.
        dial: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    async fn pair(offers: OfferPolicy) -> Pair {
        pair_with(offers, None).await
    }

    /// [`pair`], with the follower holding the owner to `quota`.
    async fn pair_with(
        offers: OfferPolicy,
        quota: Option<jig_config::v0_0_2_server::PeerQuotaConfig>,
    ) -> Pair {
        pair_tuned(offers, quota, |_| {}).await
    }

    /// [`pair_with`], with `tune` applied to the owner's configuration.
    async fn pair_tuned(
        offers: OfferPolicy,
        quota: Option<jig_config::v0_0_2_server::PeerQuotaConfig>,
        tune: impl FnOnce(&mut JigServerConfig),
    ) -> Pair {
        let mut owner = state_tuned(vec![], &[], tune);
        let follower = state_with(
            vec![FederationPeer {
                quota,
                ..peer(
                    "ws://127.0.0.1:1",
                    owner.server_did.to_did_jig_string(),
                    offers,
                )
            }],
            &[],
        );
        let (follower, url) = serve(follower).await;
        let to_follower = peer(
            &url,
            follower.server_did.to_did_jig_string(),
            OfferPolicy::Hold,
        );
        owner.config.federation.peers = vec![to_follower.clone()];
        let owner = Arc::new(owner);
        crate::v0_0_2_manifest_log::publish(&owner).await.unwrap();
        crate::v0_0_2_manifest_log::publish(&follower)
            .await
            .unwrap();
        // No timers: each test acts on decisions when it means to.
        handle(&owner);
        let follows = handle(&follower);
        let dial = tokio::spawn({
            let owner = owner.clone();
            async move { crate::v0_0_2_federation::connect_and_relay(&owner, &to_follower).await }
        });
        eventually("the connection", || {
            (owner.peers.sender_for(&follower.server_did).is_some()
                && follower.peers.sender_for(&owner.server_did).is_some())
            .then_some(())
        })
        .await;
        Pair {
            owner,
            follower,
            follows,
            user: SigningKey::from_bytes(&rand::random()),
            dial,
        }
    }

    /// Sign a block as `key` and ingest it on `state`, as a client would.
    async fn post(
        state: &AppState,
        key: &SigningKey,
        kind: BlockKind,
        meta: serde_json::Value,
    ) -> Result<String, IngestError> {
        post_at(state, key, kind, meta, None).await
    }

    /// [`post`], with the author's clock at `hlc`.
    async fn post_at(
        state: &AppState,
        key: &SigningKey,
        kind: BlockKind,
        meta: serde_json::Value,
        hlc: Option<jig_core::HlcTimestamp>,
    ) -> Result<String, IngestError> {
        use ed25519_dalek::Signer as _;
        let mut builder = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: did_of(key).into(),
                public_key: None,
                roles: vec![],
            });
        if let serde_json::Value::Object(map) = meta {
            for (k, v) in map {
                builder = builder.metadata_entry(&k, v);
            }
        }
        let mut manifest = builder.build().unwrap().with_kind(kind);
        if let Some(hlc) = hlc {
            manifest = manifest.with_hlc(hlc);
        }
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let code_bytes: Vec<u8> = Vec::new();
        let sig = key
            .sign(&serde_json::to_vec(&(&manifest_bytes, &code_bytes)).unwrap())
            .to_bytes()
            .to_vec();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &code_bytes,
            resources: vec![],
        };
        ingest(
            &state.ingest_ctx,
            bundle,
            sig,
            IngestSource::LocalClient {
                conn_id: 1,
                tiers: true,
            },
        )
        .await
    }

    impl Pair {
        async fn channel(&self) -> String {
            post(
                &self.owner,
                &self.user,
                BlockKind::ChannelCreate,
                serde_json::json!({"slug": "#shared", "tier": "public"}),
            )
            .await
            .unwrap()
        }

        async fn share(&self, channel: &str, grant: &str) {
            post(
                &self.owner,
                &self.user,
                BlockKind::ChannelShare,
                serde_json::json!({
                    "channel_id": channel,
                    "to": self.follower.server_did.to_did_jig_string(),
                    "grant": grant,
                }),
            )
            .await
            .unwrap();
        }

        /// The follower's operator decides.
        fn decide(&self, operation: Operation) -> Result<String, String> {
            operate(&self.follower.ingest_ctx.store, operation).map_err(|e| e.to_string())
        }

        /// The offers on `side` of `channel` in `state`.
        fn offers(&self, side: Side, channel: &str, state: OfferState) -> Vec<StoredOffer> {
            let (store, peer) = match side {
                Side::Owner => (&self.owner.ingest_ctx.store, &self.follower.server_did),
                Side::Follower => (&self.follower.ingest_ctx.store, &self.owner.server_did),
            };
            store
                .contract_offers_for(channel, &peer.to_did_jig_string(), side, state)
                .unwrap()
        }

        /// Wait for one offer on each side of `channel` in `state`.
        async fn both(&self, channel: &str, state: OfferState) -> (StoredOffer, StoredOffer) {
            eventually(&format!("an offer {state:?} on both sides"), || {
                let ours = self.offers(Side::Owner, channel, state);
                let theirs = self.offers(Side::Follower, channel, state);
                match (ours.as_slice(), theirs.as_slice()) {
                    ([o], [t]) => Some((o.clone(), t.clone())),
                    _ => None,
                }
            })
            .await
        }
    }

    /// The kinds of `channel`'s blocks on `state`, in chain order.
    fn kinds_in(state: &AppState, channel: &str) -> Vec<(String, BlockManifest)> {
        let store = &state.ingest_ctx.store;
        store
            .list_ingest_records_by_id(channel, 0, 100)
            .unwrap()
            .iter()
            .map(|r| {
                let block = store.get_block(&r.block_cid).unwrap().unwrap();
                (block.block_kind, manifest_of(&block.bundle_bytes).unwrap())
            })
            .collect()
    }

    async fn record_of(state: &AppState, channel: &str, kind: BlockKind) -> BlockManifest {
        eventually(&format!("a {kind:?} record"), || {
            kinds_in(state, channel)
                .into_iter()
                .rev()
                .find(|(k, _)| k == kind.as_str())
                .map(|(_, m)| m)
        })
        .await
    }

    #[tokio::test]
    async fn a_share_with_a_peer_is_offered_accepted_and_recorded() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.channel().await;
        p.share(&channel, "write").await;

        let (ours, theirs) = p.both(&channel, OfferState::Accepted).await;
        assert_eq!(ours.offer_id, theirs.offer_id);
        assert_eq!((ours.grant, theirs.grant), (Grant::Write, Grant::Write));
        assert_eq!(
            ours.answer, theirs.answer,
            "both hold the follower's signed accept"
        );

        // The owner's log shows which server carries the channel, with the
        // signed messages a member can check (rule 10).
        let record = record_of(&p.owner, &channel, BlockKind::ContractAccept).await;
        assert_eq!(
            contracts::check_record(
                BlockKind::ContractAccept,
                &record,
                &channel.parse().unwrap(),
                &p.owner.server_did.to_did_jig_string(),
            ),
            Ok(())
        );
        let accept = ContractAccept::from_envelope(
            &contracts::envelope(&record, contracts::ACCEPT_KEY).unwrap(),
        )
        .unwrap();
        assert_eq!(accept.server, p.follower.server_did.to_did_jig_string());
        // The offer carried the channel's creation block and its head.
        let offer = ContractOffer::from_envelope(&ours.offer).unwrap();
        assert_eq!(
            creation_of(&offer.creation_block).unwrap().1.to_string(),
            channel
        );
        let cited = p.follower.manifest.read().unwrap().clone().unwrap();
        assert_eq!(
            (accept.manifest.cid.to_string(), accept.manifest.seq),
            (cited.cid, cited.seq),
            "the follower cites its own manifest"
        );
    }

    /// A share goes to the server it names and to no one else: another peer
    /// connected to the owner receives nothing of it.
    #[tokio::test]
    async fn a_share_reaches_only_the_server_it_names() {
        let p = pair(OfferPolicy::Accept).await;
        let bystander = Did::from_ed25519_pubkey(&[11; 32]);
        let (to_bystander, mut bystander_rx) = PeerSender::new(bystander);
        p.owner.peers.register(to_bystander);
        let channel = p.channel().await;
        p.share(&channel, "write").await;
        p.both(&channel, OfferState::Accepted).await;
        record_of(&p.owner, &channel, BlockKind::ContractAccept).await;
        assert!(
            bystander_rx.try_recv().is_err(),
            "the other peer was sent nothing"
        );
    }

    /// Design 5.7: a share naming a server that is not a configured peer
    /// fails visibly in the channel's log, and nothing is sent.
    #[tokio::test]
    async fn a_share_naming_an_unlisted_server_is_refused_in_the_log() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.channel().await;
        let stranger = did_of(&SigningKey::from_bytes(&[7; 32]));
        post(
            &p.owner,
            &p.user,
            BlockKind::ChannelShare,
            serde_json::json!({"channel_id": channel, "to": stranger, "grant": "read"}),
        )
        .await
        .unwrap();
        let record = record_of(&p.owner, &channel, BlockKind::ContractRefuse).await;
        assert_eq!(record.metadata["code"], "NOT_A_PEER");
        assert_eq!(record.metadata["to"], stranger.as_str());
        assert!(!record.metadata.contains_key("offer"), "no offer was made");
        assert!(
            p.owner
                .ingest_ctx
                .store
                .contract_offers_in(Side::Owner, OfferState::Offered)
                .unwrap()
                .is_empty()
        );
    }

    /// JEP-0014 rules 12 and 13: a `private` channel never leaves its
    /// owner's server. Its share is refused when posted, and nothing is sent.
    #[tokio::test]
    async fn a_private_channel_is_not_offered() {
        let p = pair(OfferPolicy::Accept).await;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let did = jig_core::did::Did::from_ed25519_pubkey(p.user.verifying_key().as_bytes());
        let creator = jig_mls::member::Member::new(&p.user.to_bytes(), &did).unwrap();
        let created = creator.create_group().unwrap();
        let channel = post(
            &p.owner,
            &p.user,
            BlockKind::ChannelCreate,
            serde_json::json!({
                "slug": "#private",
                "tier": "private",
                "suite": "mls",
                "mls_group_info": b64(&created.group_info),
                "mls_ratchet_tree": b64(&created.ratchet_tree),
            }),
        )
        .await
        .unwrap();
        let shared = post(
            &p.owner,
            &p.user,
            BlockKind::ChannelShare,
            serde_json::json!({
                "channel_id": channel,
                "to": p.follower.server_did.to_did_jig_string(),
                "grant": "read",
            }),
        )
        .await;
        match shared {
            Err(e) => assert!(e.to_string().contains("stays on the server"), "{e}"),
            Ok(cid) => panic!("the share landed: {cid}"),
        }
        assert!(
            p.owner
                .ingest_ctx
                .store
                .contract_offers_in(Side::Owner, OfferState::Offered)
                .unwrap()
                .is_empty(),
            "no offer was made"
        );
    }

    /// The default: an offer waits for the operator, who may accept it.
    #[tokio::test]
    async fn an_offer_is_held_until_the_operator_answers() {
        let p = pair(OfferPolicy::Hold).await;
        let channel = p.channel().await;
        p.share(&channel, "read").await;
        let held = eventually("a held offer", || {
            p.offers(Side::Follower, &channel, OfferState::Held).pop()
        })
        .await;
        assert_eq!(
            p.offers(Side::Owner, &channel, OfferState::Offered).len(),
            1
        );
        let id = hex(&held.offer_id);
        let error = p.decide(Operation::End(id.clone())).unwrap_err();
        assert!(
            error.contains("only accepted offers can be ended"),
            "{error}"
        );

        // The operator's decision, by a prefix of the id; the running server
        // acts on it.
        p.decide(Operation::Accept(id[..12].to_string())).unwrap();
        assert_eq!(
            p.offers(Side::Follower, &channel, OfferState::Accepting)
                .len(),
            1
        );
        p.follows.act_on_decisions().await;
        p.both(&channel, OfferState::Accepted).await;
        record_of(&p.owner, &channel, BlockKind::ContractAccept).await;
        let error = p.decide(Operation::Refuse(id)).unwrap_err();
        assert!(error.contains("is accepted"), "answered once: {error}");
    }

    #[tokio::test]
    async fn an_operator_refusal_is_recorded_by_the_owner() {
        let p = pair(OfferPolicy::Hold).await;
        let channel = p.channel().await;
        p.share(&channel, "member").await;
        let held = eventually("a held offer", || {
            p.offers(Side::Follower, &channel, OfferState::Held).pop()
        })
        .await;
        p.decide(Operation::Refuse(hex(&held.offer_id))).unwrap();
        p.follows.act_on_decisions().await;
        p.both(&channel, OfferState::Refused).await;
        let record = record_of(&p.owner, &channel, BlockKind::ContractRefuse).await;
        assert_eq!(record.metadata["code"], "POLICY_REFUSED");
        let refuse = ContractRefuse::from_envelope(
            &contracts::envelope(&record, contracts::REFUSE_KEY).unwrap(),
        )
        .unwrap();
        assert_eq!(refuse.server, p.follower.server_did.to_did_jig_string());
    }

    /// Rule 11: either side ends a live share, and the owner records it.
    #[tokio::test]
    async fn either_side_ends_a_share() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.channel().await;

        // The follower ends it.
        p.share(&channel, "write").await;
        let (_, theirs) = p.both(&channel, OfferState::Accepted).await;
        p.decide(Operation::End(hex(&theirs.offer_id))).unwrap();
        p.follows.act_on_decisions().await;
        p.both(&channel, OfferState::Ended).await;
        let record = record_of(&p.owner, &channel, BlockKind::ContractEnd).await;
        let end =
            ContractEnd::from_envelope(&contracts::envelope(&record, contracts::END_KEY).unwrap())
                .unwrap();
        assert_eq!(end.server, p.follower.server_did.to_did_jig_string());

        // The owner ends the next one, on a `channel-unshare`.
        p.share(&channel, "read").await;
        eventually("the second share", || {
            (p.offers(Side::Owner, &channel, OfferState::Accepted).len() == 1
                && p.offers(Side::Follower, &channel, OfferState::Accepted)
                    .len()
                    == 1)
                .then_some(())
        })
        .await;
        post(
            &p.owner,
            &p.user,
            BlockKind::ChannelUnshare,
            serde_json::json!({
                "channel_id": channel,
                "to": p.follower.server_did.to_did_jig_string(),
            }),
        )
        .await
        .unwrap();
        eventually("both shares ended on both sides", || {
            (p.offers(Side::Owner, &channel, OfferState::Ended).len() == 2
                && p.offers(Side::Follower, &channel, OfferState::Ended).len() == 2)
                .then_some(())
        })
        .await;
        let ends = eventually("two end records", || {
            let ends: Vec<_> = kinds_in(&p.owner, &channel)
                .into_iter()
                .filter(|(k, _)| k == "contract-end")
                .collect();
            (ends.len() == 2).then_some(ends)
        })
        .await;
        let last = ContractEnd::from_envelope(
            &contracts::envelope(&ends[1].1, contracts::END_KEY).unwrap(),
        )
        .unwrap();
        assert_eq!(last.server, p.owner.server_did.to_did_jig_string());
    }

    /// Rule 11: a grant changes by a new offer and accept, which replaces
    /// the old grant on both sides.
    #[tokio::test]
    async fn a_new_offer_with_another_grant_replaces_the_old() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.channel().await;
        p.share(&channel, "read").await;
        let (first, _) = p.both(&channel, OfferState::Accepted).await;
        p.share(&channel, "member").await;
        let (ours, theirs) = eventually("the second share accepted", || {
            let ours = p.offers(Side::Owner, &channel, OfferState::Accepted);
            let theirs = p.offers(Side::Follower, &channel, OfferState::Accepted);
            match (ours.as_slice(), theirs.as_slice()) {
                ([o], [t]) if o.offer_id != first.offer_id && t.offer_id == o.offer_id => {
                    Some((o.clone(), t.clone()))
                }
                _ => None,
            }
        })
        .await;
        assert_eq!((ours.grant, theirs.grant), (Grant::Member, Grant::Member));
        assert_eq!(
            p.offers(Side::Owner, &channel, OfferState::Superseded)
                .iter()
                .map(|o| o.offer_id)
                .collect::<Vec<_>>(),
            [first.offer_id]
        );
        assert_eq!(
            p.offers(Side::Follower, &channel, OfferState::Superseded)
                .len(),
            1
        );
    }

    // ---- Offers a follower cannot honour ------------------------------------

    /// A follower that lists `owner` as a peer (accepting its offers) and
    /// attests `Names.Example.org`.
    fn follower_of(owner: &SigningKey) -> (AppState, Contracts) {
        let state = state_with(
            vec![peer("ws://127.0.0.1:1", did_of(owner), OfferPolicy::Accept)],
            &["Names.Example.org"],
        );
        let contracts = Contracts::new(&state);
        (state, contracts)
    }

    /// A creation block, as an offer carries it, and its CID.
    fn creation(owner: &SigningKey, meta: serde_json::Value) -> (Vec<u8>, Cid) {
        let mut builder = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:zCreator".into(),
                public_key: None,
                roles: vec![],
            })
            .metadata_entry("slug", serde_json::json!("#theirs"))
            .metadata_entry("sequencer", serde_json::json!(did_of(owner)));
        if let serde_json::Value::Object(map) = meta {
            for (k, v) in map {
                builder = builder.metadata_entry(&k, v);
            }
        }
        let manifest_bytes = builder
            .build()
            .unwrap()
            .with_kind(BlockKind::ChannelCreate)
            .to_canonical_bytes()
            .unwrap();
        let bytes = serde_json::to_vec(&(&manifest_bytes, Vec::<u8>::new())).unwrap();
        let cid = creation_of(&bytes).unwrap().1;
        (bytes, cid)
    }

    fn offer_to(
        follower: &AppState,
        owner: &SigningKey,
        (creation_block, channel_id): (Vec<u8>, Cid),
        attested_suffixes: &[AttestedSuffix],
    ) -> ContractOffer {
        ContractOffer::sign(
            owner,
            &follower.server_did.to_did_jig_string(),
            channel_id,
            Grant::Write,
            creation_block,
            b"head".to_vec(),
            ManifestRef {
                cid: channel_id,
                seq: 0,
            },
            attested_suffixes.to_vec(),
        )
    }

    /// Offer `offer` from `owner` to `contracts` on a connection, and return
    /// the code of the refusal it answers with, if it refuses.
    fn answer_to(
        contracts: &Contracts,
        owner: &SigningKey,
        offer: &ContractOffer,
    ) -> Option<String> {
        let (out, mut rx) =
            PeerSender::new(Did::from_ed25519_pubkey(owner.verifying_key().as_bytes()));
        contracts
            .on_peer_frame(out.peer(), OFFER_FRAME, &offer.envelope, &out)
            .unwrap();
        let jig_pipeline::Frame::Peer { kind, body } = rx.try_recv().ok()?.frame else {
            panic!("a peer frame");
        };
        assert_eq!(kind, ANSWER_FRAME);
        ContractRefuse::from_envelope(&body)
            .ok()
            .map(|r| r.code.as_str().to_string())
    }

    #[tokio::test]
    async fn offers_a_follower_cannot_honour_are_refused() {
        let owner = SigningKey::from_bytes(&[3; 32]);
        let (follower, contracts) = follower_of(&owner);
        crate::v0_0_2_manifest_log::publish(&Arc::new(follower.clone()))
            .await
            .unwrap();
        let none = serde_json::json!({});

        // Honourable: accepted (no refusal), and answered again the same way.
        let good = offer_to(&follower, &owner, creation(&owner, none.clone()), &[]);
        assert_eq!(answer_to(&contracts, &owner, &good), None);
        assert_eq!(answer_to(&contracts, &owner, &good), None, "answered again");

        // Rule 9: a suite this server does not carry, with no fallback.
        let suite = creation(&owner, serde_json::json!({"suite": "pq-mls-2"}));
        assert_eq!(
            answer_to(&contracts, &owner, &offer_to(&follower, &owner, suite, &[])).as_deref(),
            Some("UNSUPPORTED_SUITE")
        );
        // JEP-0014 rules 12 and 13: `private` and `server` stay on their
        // owner's server; `shared` crosses.
        for (tier, refused) in [("private", true), ("server", true), ("shared", false)] {
            let offered = creation(&owner, serde_json::json!({"tier": tier, "suite": "mls"}));
            assert_eq!(
                answer_to(
                    &contracts,
                    &owner,
                    &offer_to(&follower, &owner, offered, &[])
                )
                .as_deref(),
                refused.then_some("POLICY_REFUSED"),
                "{tier}"
            );
        }
        // A suffix this server attests (`dns`, as `Names.Example.org`): the
        // same claim from the owner is no conflict, and the same suffix under
        // another authority is.
        let same = offer_to(
            &follower,
            &owner,
            creation(&owner, serde_json::json!({"v": 3})),
            &[AttestedSuffix::dns(
                "names.example.org",
                "names.example.org",
            )],
        );
        assert_eq!(
            answer_to(&contracts, &owner, &same),
            None,
            "one claim, accepted"
        );
        let other = offer_to(
            &follower,
            &owner,
            creation(&owner, serde_json::json!({"v": 1})),
            &[AttestedSuffix::config(
                "names.example.org",
                [did_of(&owner)],
            )],
        );
        assert_eq!(
            answer_to(&contracts, &owner, &other).as_deref(),
            Some("SUFFIX_CONFLICT")
        );
        // A creation block that is not the channel's, and one naming another
        // sequencer.
        let (bytes, _) = creation(&owner, serde_json::json!({"v": 2}));
        let wrong_id = offer_to(&follower, &owner, (bytes, good.channel_id), &[]);
        assert_eq!(
            answer_to(&contracts, &owner, &wrong_id).as_deref(),
            Some("POLICY_REFUSED")
        );
        let elsewhere = creation(
            &owner,
            serde_json::json!({"sequencer": did_of(&SigningKey::from_bytes(&[8; 32]))}),
        );
        assert_eq!(
            answer_to(
                &contracts,
                &owner,
                &offer_to(&follower, &owner, elsewhere, &[])
            )
            .as_deref(),
            Some("POLICY_REFUSED")
        );

        // Rule 17: an owner that is not a configured peer.
        let stranger = SigningKey::from_bytes(&[4; 32]);
        let unlisted = offer_to(&follower, &stranger, creation(&stranger, none), &[]);
        assert_eq!(
            answer_to(&contracts, &stranger, &unlisted).as_deref(),
            Some("NOT_A_PEER")
        );
    }

    /// A frame that is not the contract, or not the proven peer's, closes the
    /// connection.
    #[test]
    fn a_frame_not_signed_by_the_peer_closes_the_connection() {
        let owner = SigningKey::from_bytes(&[3; 32]);
        let (follower, contracts) = follower_of(&owner);
        let offer = offer_to(
            &follower,
            &owner,
            creation(&owner, serde_json::json!({})),
            &[],
        );
        let someone = Did::from_ed25519_pubkey(&[5; 32]);
        let (out, _rx) = PeerSender::new(someone.clone());
        for (kind, body) in [
            (OFFER_FRAME, offer.envelope.as_slice()),
            (OFFER_FRAME, b"not a contract".as_slice()),
            (ANSWER_FRAME, b"not a contract".as_slice()),
            (END_FRAME, offer.envelope.as_slice()),
        ] {
            let closed = contracts
                .on_peer_frame(&someone, kind, body, &out)
                .unwrap_err();
            assert_eq!(
                closed.code,
                jig_pipeline::handshake::close::PROTOCOL_VIOLATION,
                "{kind}"
            );
        }
        // An offer made to another server.
        let elsewhere = ContractOffer::sign(
            &owner,
            &did_of(&SigningKey::from_bytes(&[6; 32])),
            offer.channel_id,
            Grant::Read,
            offer.creation_block.clone(),
            vec![],
            offer.manifest.clone(),
            vec![],
        );
        let (out, _rx) =
            PeerSender::new(Did::from_ed25519_pubkey(owner.verifying_key().as_bytes()));
        assert!(
            contracts
                .on_peer_frame(out.peer(), OFFER_FRAME, &elsewhere.envelope, &out)
                .is_err()
        );
        // A kind this server does not speak is left alone.
        assert!(
            contracts
                .on_peer_frame(out.peer(), "a-later-slice", b"", &out)
                .is_ok()
        );
    }

    /// The owner refuses an accept claiming a suffix it attests under another authority: the
    /// contract is refused whichever side finds the conflict.
    #[tokio::test]
    async fn an_accept_claiming_the_owners_suffix_is_refused_only_under_another_authority() {
        let follower = SigningKey::from_bytes(&[9; 32]);
        let owner = state_with(
            vec![peer(
                "ws://127.0.0.1:1",
                did_of(&follower),
                OfferPolicy::Hold,
            )],
            &["names.example.org"],
        );
        let owner = Arc::new(owner);
        crate::v0_0_2_manifest_log::publish(&owner).await.unwrap();
        let contracts = Contracts::new(&owner);
        let user = SigningKey::from_bytes(&[10; 32]);
        let channel = post(
            &owner,
            &user,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#c", "tier": "public"}),
        )
        .await
        .unwrap();
        let cid: Cid = channel.parse().unwrap();
        // The follower claims the owner's suffix under another authority,
        // then, on a second offer, under the same one.
        for (grant, claim, state) in [
            (
                Grant::Read,
                AttestedSuffix::config("names.example.org", [did_of(&follower)]),
                OfferState::Refused,
            ),
            (
                Grant::Write,
                AttestedSuffix::dns("names.example.org", "names.example.org"),
                OfferState::Accepted,
            ),
        ] {
            let offer = ContractOffer::sign(
                &owner.ingest_ctx.server_key,
                &did_of(&follower),
                cid,
                grant,
                vec![],
                vec![],
                ManifestRef { cid, seq: 1 },
                vec![],
            );
            owner
                .ingest_ctx
                .store
                .put_contract_offer(&StoredOffer {
                    offer_id: offer.offer_id,
                    channel_id: channel.clone(),
                    side: Side::Owner,
                    peer_did: did_of(&follower),
                    grant,
                    state: OfferState::Offered,
                    offer: offer.envelope.clone(),
                    answer: None,
                    share_cid: None,
                })
                .unwrap();
            let accept = ContractAccept::sign(
                &follower,
                &offer,
                ManifestRef { cid, seq: 1 },
                vec![claim],
                vec![],
            );
            let (out, _rx) = PeerSender::new(Did::from_ed25519_pubkey(
                follower.verifying_key().as_bytes(),
            ));
            contracts
                .on_peer_frame(out.peer(), ANSWER_FRAME, &accept.envelope, &out)
                .unwrap();
            let store = &owner.ingest_ctx.store;
            eventually(&format!("the {grant:?} offer {state:?}"), || {
                (store
                    .get_contract_offer(&offer.offer_id)
                    .unwrap()
                    .unwrap()
                    .state
                    == state)
                    .then_some(())
            })
            .await;
        }
        let record = record_of(&owner, &channel, BlockKind::ContractRefuse).await;
        assert_eq!(record.metadata["code"], "SUFFIX_CONFLICT");
        record_of(&owner, &channel, BlockKind::ContractAccept).await;
    }

    /// An end waits for the other side to be connected: it is not counted
    /// done, or recorded, until it is on a live connection.
    #[tokio::test]
    async fn an_end_waits_for_a_connection() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.channel().await;
        p.share(&channel, "read").await;
        let (ours, _) = p.both(&channel, OfferState::Accepted).await;

        // The owner's operator ends it while the follower is not connected.
        let unconnected = Contracts {
            peers: Arc::new(PeerRegistry::default()),
            ..Contracts::new(&p.owner)
        };
        operate(
            &p.owner.ingest_ctx.store,
            Operation::End(hex(&ours.offer_id)),
        )
        .unwrap();
        unconnected.act_on_decisions().await;
        assert_eq!(p.offers(Side::Owner, &channel, OfferState::Ending).len(), 1);
        assert!(
            !kinds_in(&p.owner, &channel)
                .iter()
                .any(|(k, _)| k == "contract-end"),
            "not recorded before it is sent"
        );

        // Connected again: sent, counted, recorded, on both sides.
        Contracts::new(&p.owner).act_on_decisions().await;
        p.both(&channel, OfferState::Ended).await;
        record_of(&p.owner, &channel, BlockKind::ContractEnd).await;
    }

    #[test]
    fn the_operator_lists_offers_and_names_one_by_a_prefix() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(
            operate(&store, Operation::List).unwrap(),
            "no contract offers"
        );
        let owner = SigningKey::from_bytes(&[3; 32]);
        let (follower, _) = follower_of(&owner);
        let offer = offer_to(
            &follower,
            &owner,
            creation(&owner, serde_json::json!({})),
            &[],
        );
        let row = StoredOffer {
            offer_id: offer.offer_id,
            channel_id: offer.channel_id.to_string(),
            side: Side::Follower,
            peer_did: offer.owner.clone(),
            grant: Grant::Write,
            state: OfferState::Held,
            offer: offer.envelope.clone(),
            answer: None,
            share_cid: None,
        };
        store.put_contract_offer(&row).unwrap();
        let id = hex(&offer.offer_id);
        let listed = operate(&store, Operation::List).unwrap();
        assert!(
            listed.starts_with(&id) && listed.contains("follower") && listed.contains("held"),
            "{listed}"
        );
        for bad in ["abc", "zzzzzzzzzz", "00000000"] {
            assert!(
                operate(&store, Operation::Accept(bad.into())).is_err(),
                "{bad}"
            );
        }
        operate(&store, Operation::Accept(id[..8].to_uppercase())).unwrap();
        assert_eq!(
            store
                .get_contract_offer(&offer.offer_id)
                .unwrap()
                .unwrap()
                .state,
            OfferState::Accepting
        );
    }

    // ---- The owner's stream (JEP-0005 rules 12-14, 22a) --------------------

    impl Pair {
        async fn text(&self, channel: &str, body: &str) -> String {
            post(
                &self.owner,
                &self.user,
                BlockKind::TextRender,
                serde_json::json!({"channel_id": channel, "body": body}),
            )
            .await
            .unwrap()
        }

        /// A shared channel, accepted on both sides, with `texts` posts
        /// before the share.
        async fn shared(&self, texts: usize) -> String {
            let channel = self.channel().await;
            for i in 0..texts {
                self.text(&channel, &format!("before {i}")).await;
            }
            self.share(&channel, "read").await;
            self.both(&channel, OfferState::Accepted).await;
            channel
        }

        /// The head of `channel`'s chain on `state`.
        fn head(state: &AppState, channel: &str) -> Option<u64> {
            state
                .ingest_ctx
                .store
                .latest_ingest_record(channel)
                .unwrap()
                .map(|r| r.seq)
        }

        /// Wait for the follower's chain to reach the owner's head.
        async fn caught_up(&self, channel: &str) -> u64 {
            let want = Self::head(&self.owner, channel).unwrap();
            eventually("the follower at the owner's head", || {
                (Self::head(&self.follower, channel) == Some(want)).then_some(want)
            })
            .await
        }
    }

    /// A follower lists a channel it carries as ordered by its owner, with
    /// the owner's offer: what lets a client hold the channel's records to
    /// the owner without taking the follower's word for it.
    #[tokio::test]
    async fn a_follower_lists_a_carried_channel_with_its_owners_offer() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.shared(1).await;
        p.follows.stream.pull_all();
        p.caught_up(&channel).await;
        let owner = p.owner.server_did.to_did_jig_string();
        let follower = p.follower.server_did.to_did_jig_string();

        let row = p
            .follower
            .ingest_ctx
            .store
            .get_channel_by_id(&channel)
            .unwrap()
            .unwrap();
        let view = crate::v0_0_2_blocks::view_of(&p.follower, row).unwrap();
        assert_eq!(view.sequencer, owner);
        let proven = jig_client::pins::prove_carried(
            "wss://follower",
            &view.slug,
            &view.id,
            &view.sequencer,
            std::slice::from_ref(&follower),
            view.share.as_deref(),
        )
        .unwrap();
        assert_eq!(proven, owner);

        // The owner lists its own channel as its own, with nothing to prove.
        let row = p
            .owner
            .ingest_ctx
            .store
            .get_channel_by_id(&channel)
            .unwrap()
            .unwrap();
        let view = crate::v0_0_2_blocks::view_of(&p.owner, row).unwrap();
        assert_eq!(view.sequencer, owner);
        assert!(view.share.is_none());
    }

    #[tokio::test]
    async fn a_follower_carries_the_owners_chain_as_signed() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.shared(3).await;
        // Catch-up from nothing, then each new block as it lands.
        p.follows.stream.pull_all();
        let head = p.caught_up(&channel).await;
        p.text(&channel, "live").await;
        assert_eq!(p.caught_up(&channel).await, head + 1, "pushed, not pulled");

        let follower = &p.follower.ingest_ctx.store;
        let owner = &p.owner.ingest_ctx.store;
        let row = follower.get_channel_by_id(&channel).unwrap().unwrap();
        assert_eq!(row.sequencer_did, p.owner.server_did.to_did_jig_string());
        for seq in 0..=head + 1 {
            assert_eq!(
                follower.ingest_record_bytes(&channel, seq).unwrap(),
                owner.ingest_record_bytes(&channel, seq).unwrap(),
                "seq {seq}, byte for byte"
            );
        }
        // The follower signed nothing of its own into it.
        let records = follower
            .list_ingest_records_by_id(&channel, 0, 100)
            .unwrap();
        assert!(
            records
                .iter()
                .all(|r| r.sequencer == p.owner.server_did.to_did_jig_string())
        );
    }

    #[tokio::test]
    async fn a_follower_catches_up_across_frames() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.shared(crate::v0_0_2_stream::MAX_ENTRIES + 6).await;
        // One pull: the rest follows on the owner's `more`.
        p.follows.stream.pull_all();
        let head = p.caught_up(&channel).await;
        assert!(head as usize > crate::v0_0_2_stream::MAX_ENTRIES);
    }

    #[tokio::test]
    async fn only_the_connections_peer_sequences_what_it_streams() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.shared(1).await;
        let records = Contracts::new(&p.owner)
            .stream
            .records_from(&channel, 0)
            .unwrap()
            .unwrap();
        // The owner's own blocks and records, landed as if another server
        // sent them: the sequencer is the connection's peer, and this one
        // holds no share and sequences nothing.
        let stranger = Did::from_ed25519_pubkey(
            SigningKey::from_bytes(&rand::random())
                .verifying_key()
                .as_bytes(),
        );
        p.follows.stream.land(&stranger, records.clone()).await;
        let follower = &p.follower.ingest_ctx.store;
        assert!(
            follower
                .get_channel_by_id_including_archived(&channel)
                .unwrap()
                .is_none(),
            "no row for a stream from a server that does not own the channel"
        );
        // From the owner, the same frame lands.
        p.follows.stream.land(&p.owner.server_did, records).await;
        assert!(follower.get_channel_by_id(&channel).unwrap().is_some());
    }

    #[tokio::test]
    async fn a_channel_pushed_without_an_accepted_share_makes_no_row() {
        let p = pair(OfferPolicy::Hold).await;
        let channel = p.channel().await;
        p.share(&channel, "read").await;
        eventually("the offer held", || {
            (p.offers(Side::Follower, &channel, OfferState::Held).len() == 1).then_some(())
        })
        .await;
        let ours = p
            .offers(Side::Owner, &channel, OfferState::Offered)
            .remove(0);
        // The owner takes the offer as accepted, though the follower holds it
        // still, and streams the channel.
        let owner = &p.owner.ingest_ctx.store;
        assert!(
            owner
                .move_contract_offer(
                    &ours.offer_id,
                    OfferState::Offered,
                    OfferState::Accepted,
                    None
                )
                .unwrap()
        );
        p.text(&channel, "pushed").await;
        p.follows.stream.pull_all();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            p.follower
                .ingest_ctx
                .store
                .get_channel_by_id_including_archived(&channel)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn what_a_peer_streams_counts_against_its_quota() {
        let quota = jig_config::v0_0_2_server::PeerQuotaConfig {
            blocks_per_min: 3,
            bytes_per_min: 8 * 1024 * 1024,
        };
        let p = pair_with(OfferPolicy::Accept, Some(quota)).await;
        let channel = p.shared(5).await;
        // Three entries a minute, whichever frames carry them: the owner's
        // push of its accept counts too, so two or three land.
        p.follows.stream.pull_all();
        let head = eventually("the blocks the quota allows", || {
            Pair::head(&p.follower, &channel).filter(|h| *h >= 1)
        })
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        p.follows.stream.pull_all();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let now = Pair::head(&p.follower, &channel).unwrap();
        assert!(now <= 2, "at most three blocks: seq {now}");
        assert!(now >= head);
        assert!(
            now < Pair::head(&p.owner, &channel).unwrap(),
            "nothing past the quota this minute"
        );
    }

    // ---- The owner's limit on records-from ---------------------------------

    /// What a peer connection carried: each frame's kind and body.
    fn sent(
        rx: &mut tokio::sync::mpsc::Receiver<jig_pipeline::envelope::Envelope>,
    ) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        while let Ok(envelope) = rx.try_recv() {
            if let jig_pipeline::envelope::Frame::Peer { kind, body } = envelope.frame {
                out.push((kind, body));
            }
        }
        out
    }

    fn ask(channel: &str) -> Vec<u8> {
        let body = jig_core::dcbor::Value::text_map([
            ("channel_id", jig_core::dcbor::Value::text(channel)),
            ("from_seq", jig_core::dcbor::Value::Unsigned(0)),
        ]);
        jig_core::dcbor::encode(&body).unwrap()
    }

    /// An owner with one channel, shared with every DID in `followers`.
    async fn owner_sharing(followers: &[&Did]) -> (AppState, String) {
        let owner = state_with(vec![], &[]);
        let user = SigningKey::from_bytes(&rand::random());
        let channel = post(
            &owner,
            &user,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#limited", "tier": "public"}),
        )
        .await
        .unwrap();
        for follower in followers {
            owner
                .ingest_ctx
                .store
                .put_contract_offer(&StoredOffer {
                    offer_id: rand::random(),
                    channel_id: channel.clone(),
                    side: Side::Owner,
                    peer_did: follower.to_did_jig_string(),
                    grant: Grant::Read,
                    state: OfferState::Accepted,
                    offer: vec![],
                    answer: None,
                    share_cid: None,
                })
                .unwrap();
        }
        (owner, channel)
    }

    fn a_did() -> Did {
        Did::from_ed25519_pubkey(
            SigningKey::from_bytes(&rand::random())
                .verifying_key()
                .as_bytes(),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_follower_looping_on_records_from_is_cut_off_at_the_limit() {
        let (looping, polite) = (a_did(), a_did());
        let (owner, channel) = owner_sharing(&[&looping, &polite]).await;
        let stream = Contracts::new(&owner).stream;
        let limit = owner.config.federation.records_from;

        // One follower asks in a loop: its burst is answered, the rest are
        // refused with when to ask again, none dropped.
        let (out, mut rx) = PeerSender::new(looping.clone());
        for _ in 0..50 {
            stream
                .on_peer_frame(
                    &looping,
                    crate::v0_0_2_stream::RECORDS_FROM_FRAME,
                    &ask(&channel),
                    &out,
                )
                .unwrap()
                .unwrap();
        }
        let frames = sent(&mut rx);
        assert_eq!(frames.len(), 50, "every request answered");
        let records = frames
            .iter()
            .filter(|(k, _)| k == crate::v0_0_2_stream::RECORDS_FRAME)
            .count();
        assert_eq!(records, limit.burst as usize);
        let refusals: Vec<_> = frames
            .iter()
            .filter(|(k, _)| k == crate::v0_0_2_stream::RECORDS_LATER_FRAME)
            .collect();
        assert_eq!(refusals.len(), 50 - limit.burst as usize);
        let retry_after = jig_core::dcbor::decode(&refusals[0].1)
            .unwrap()
            .get("retry_after_ms")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(retry_after, 60_000 / u64::from(limit.per_min));

        // Meanwhile a follower polling every 10 s is answered every time.
        let (out, mut polite_rx) = PeerSender::new(polite.clone());
        for _ in 0..30 {
            stream
                .on_peer_frame(
                    &polite,
                    crate::v0_0_2_stream::RECORDS_FROM_FRAME,
                    &ask(&channel),
                    &out,
                )
                .unwrap()
                .unwrap();
            tokio::time::advance(crate::v0_0_2_stream::PULL_EVERY).await;
        }
        assert!(
            sent(&mut polite_rx)
                .iter()
                .all(|(k, _)| k == crate::v0_0_2_stream::RECORDS_FRAME),
            "a polling follower is never refused"
        );

        // And the looping one, once it waits, is answered again.
        let (out, mut rx) = PeerSender::new(looping.clone());
        stream
            .on_peer_frame(
                &looping,
                crate::v0_0_2_stream::RECORDS_FROM_FRAME,
                &ask(&channel),
                &out,
            )
            .unwrap()
            .unwrap();
        assert_eq!(sent(&mut rx)[0].0, crate::v0_0_2_stream::RECORDS_FRAME);
    }

    #[tokio::test(start_paused = true)]
    async fn a_follower_waits_as_long_as_the_owner_says() {
        let follower = state_with(vec![], &[]);
        let stream = Contracts::new(&follower).stream;
        let owner = a_did();
        let channel = jig_pipeline::ingest_record::label_cid("a channel");
        let later = jig_core::dcbor::encode(&jig_core::dcbor::Value::text_map([
            ("channel_id", jig_core::dcbor::Value::text(&channel)),
            ("retry_after_ms", jig_core::dcbor::Value::Unsigned(3_000)),
        ]))
        .unwrap();
        let (out, _rx) = PeerSender::new(owner.clone());
        stream
            .on_peer_frame(
                &owner,
                crate::v0_0_2_stream::RECORDS_LATER_FRAME,
                &later,
                &out,
            )
            .unwrap()
            .unwrap();
        let owner = owner.to_did_jig_string();
        let at = stream.retry_at(&owner, &channel).expect("held back");
        assert_eq!(at - tokio::time::Instant::now(), Duration::from_secs(3));
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(stream.retry_at(&owner, &channel), None, "free to ask again");

        // A wait past the cap is held to it.
        let long = jig_core::dcbor::encode(&jig_core::dcbor::Value::text_map([
            ("channel_id", jig_core::dcbor::Value::text(&channel)),
            ("retry_after_ms", jig_core::dcbor::Value::Unsigned(u64::MAX)),
        ]))
        .unwrap();
        let owner_did = Did::from_did_jig_string(&owner).unwrap();
        stream
            .on_peer_frame(
                &owner_did,
                crate::v0_0_2_stream::RECORDS_LATER_FRAME,
                &long,
                &out,
            )
            .unwrap()
            .unwrap();
        let at = stream.retry_at(&owner, &channel).unwrap();
        assert_eq!(
            at - tokio::time::Instant::now(),
            crate::v0_0_2_stream::MAX_RETRY_AFTER
        );
    }

    // ---- Federation catch-up, the legacy path (v0_0_2_catch_up) ------------

    /// Two servers on the legacy federation path, not yet connected: `a`
    /// dials `b` and subscribes to its federation stream.
    struct Legacy {
        a: Arc<AppState>,
        b: Arc<AppState>,
        /// `b`, as `a` lists it.
        to_b: FederationPeer,
        user: SigningKey,
    }

    async fn legacy() -> Legacy {
        let mut a = state_with(vec![], &[]);
        let b = state_with(
            vec![peer(
                "ws://127.0.0.1:1",
                a.server_did.to_did_jig_string(),
                OfferPolicy::Hold,
            )],
            &[],
        );
        let (b, url) = serve(b).await;
        let to_b = peer(&url, b.server_did.to_did_jig_string(), OfferPolicy::Hold);
        a.config.federation.peers = vec![to_b.clone()];
        let a = Arc::new(a);
        crate::v0_0_2_manifest_log::publish(&a).await.unwrap();
        crate::v0_0_2_manifest_log::publish(&b).await.unwrap();
        handle(&a);
        handle(&b);
        Legacy {
            a,
            b,
            to_b,
            user: SigningKey::from_bytes(&rand::random()),
        }
    }

    impl Legacy {
        /// `a` holds `b` to `quota` from its next dial.
        fn held_to(&mut self, quota: Option<jig_config::v0_0_2_server::PeerQuotaConfig>) {
            self.to_b.quota = quota;
        }

        /// `a` dials `b`, as `spawn_federation_peers` does.
        fn dial(&self, a: &Arc<AppState>) -> tokio::task::JoinHandle<anyhow::Result<()>> {
            let (a, to_b) = (a.clone(), self.to_b.clone());
            tokio::spawn(
                async move { crate::v0_0_2_federation::connect_and_relay(&a, &to_b).await },
            )
        }

        /// An open channel on `b`.
        async fn channel(&self, slug: &str) -> String {
            post(
                &self.b,
                &self.user,
                BlockKind::ChannelCreate,
                serde_json::json!({"slug": slug, "tier": "public"}),
            )
            .await
            .unwrap()
        }

        /// A restricted channel on `b` the user owns, unencrypted (as the
        /// federation tests make one: creating it takes an MLS group).
        fn restricted(&self, slug: &str) -> String {
            let id = jig_pipeline::ingest_record::label_cid(slug);
            self.b
                .ingest_ctx
                .store
                .upsert_channel(&jig_pipeline::persist::StoredChannel {
                    id: id.clone(),
                    slug: slug.into(),
                    visibility: "restricted".into(),
                    created_at: 0,
                    owner_did: did_of(&self.user),
                    suite: "none".into(),
                    sequencer_did: String::new(),
                    co_owners: Vec::new(),
                    tiering: jig_pipeline::persist::ChannelTiering::current("restricted", "none"),
                })
                .unwrap();
            id
        }

        /// `n` posts to the restricted `channel` on `b`, put in its store as
        /// a frozen channel holds them: ingest takes no new ones.
        fn stored_texts(&self, channel: &str, n: usize) -> Vec<String> {
            use ed25519_dalek::Signer as _;
            (0..n)
                .map(|i| {
                    let manifest_bytes = BlockManifest::builder()
                        .version(semver::Version::new(0, 1, 0))
                        .author(Author {
                            did: did_of(&self.user).into(),
                            public_key: None,
                            roles: vec![],
                        })
                        .metadata_entry("channel_id", serde_json::json!(channel))
                        .metadata_entry("body", serde_json::json!(format!("closed {i}")))
                        .build()
                        .unwrap()
                        .with_kind(BlockKind::TextRender)
                        .to_canonical_bytes()
                        .unwrap();
                    let bundle_bytes =
                        serde_json::to_vec(&(&manifest_bytes, &Vec::<u8>::new())).unwrap();
                    let cid = crate::v0_0_2_federation::peer_block_cid(&bundle_bytes).unwrap();
                    self.b
                        .ingest_ctx
                        .store
                        .insert_block(&jig_pipeline::persist::StoredBlock {
                            cid: cid.clone(),
                            channel_id: Some(channel.to_string()),
                            block_kind: "text-render".into(),
                            sender_did: did_of(&self.user),
                            sender_sig: self.user.sign(&bundle_bytes).to_bytes().to_vec(),
                            bundle_bytes,
                            is_synthetic: false,
                            hlc_wall_ms: 0,
                            hlc_logical: 0,
                            hlc_origin: String::new(),
                            posted_at: 0,
                            origin_server: self.b.server_did.to_did_jig_string(),
                            federated_from: None,
                        })
                        .unwrap();
                    cid
                })
                .collect()
        }

        /// How many of `b`'s blocks federate so far: its own manifest log's,
        /// before a test posts anything.
        fn federating(&self) -> usize {
            self.page("", 0).entries.len()
        }

        /// `n` posts to `channel` on `b`.
        async fn texts(&self, channel: &str, n: usize) -> Vec<String> {
            let mut cids = Vec::new();
            for i in 0..n {
                cids.push(
                    post(
                        &self.b,
                        &self.user,
                        BlockKind::TextRender,
                        serde_json::json!({
                            "channel_id": channel,
                            "body": format!("text {i} {}", rand::random::<u64>()),
                        }),
                    )
                    .await
                    .unwrap(),
                );
            }
            cids
        }

        fn cursor(&self, state: &AppState) -> Option<String> {
            state
                .ingest_ctx
                .store
                .catch_up_cursor(&self.to_b.url)
                .unwrap()
        }

        /// `b`'s answer to a catch-up after `after`.
        fn page(&self, after: &str, overlap: u64) -> crate::v0_0_2_catch_up::Page {
            Contracts::new(&self.b)
                .replay
                .page(&crate::v0_0_2_catch_up::Ask {
                    after: after.to_string(),
                    overlap,
                })
                .unwrap()
        }

        /// Wait for `state` to hold every block of `cids`.
        async fn holds(state: &AppState, cids: &[String]) {
            eventually("the blocks caught up", || {
                cids.iter().all(|cid| held(state, cid)).then_some(())
            })
            .await
        }
    }

    fn held(state: &AppState, cid: &str) -> bool {
        state.ingest_ctx.store.get_block(cid).unwrap().is_some()
    }

    /// This server again, on the same store and key: a restart.
    async fn restarted(state: &AppState) -> Arc<AppState> {
        let state = Arc::new(
            AppState::for_test_from(
                state.config.clone(),
                state.ingest_ctx.store.clone(),
                state.ingest_ctx.server_key.clone(),
            )
            .unwrap(),
        );
        crate::v0_0_2_manifest_log::publish(&state).await.unwrap();
        handle(&state);
        state
    }

    #[tokio::test]
    async fn a_dialer_gets_what_the_peer_took_before_its_first_dial() {
        let l = legacy().await;
        let channel = l.channel("#open").await;
        let mut before = vec![channel.clone()];
        before.extend(l.texts(&channel, 3).await);

        // No block from `b` yet: the first catch-up starts from `b`'s start.
        l.dial(&l.a);
        Legacy::holds(&l.a, &before).await;
        eventually("the catch-up done", || {
            l.cursor(&l.a).is_none().then_some(())
        })
        .await;

        // From then on, the live push.
        let live = l.texts(&channel, 1).await;
        Legacy::holds(&l.a, &live).await;
    }

    #[tokio::test]
    async fn catch_up_replays_only_the_channels_that_federate() {
        let l = legacy().await;
        let own = l.federating();
        let open = l.channel("#open").await;
        let first = l.texts(&open, 1).await;
        let restricted = l.restricted("#closed");
        let closed = l.stored_texts(&restricted, 2);
        let last = l.texts(&open, 1).await;

        let page = l.page("", 0);
        let replayed: Vec<String> = page.entries[own..]
            .iter()
            .map(|e| crate::v0_0_2_federation::peer_block_cid(&e.bundle).unwrap())
            .collect();
        assert_eq!(replayed, [open.clone(), first[0].clone(), last[0].clone()]);
        assert!(!page.more);

        l.dial(&l.a);
        Legacy::holds(&l.a, &last).await;
        assert!(closed.iter().all(|cid| !held(&l.a, cid)));
    }

    #[tokio::test]
    async fn the_cursor_is_a_block_in_the_peers_own_order() {
        let l = legacy().await;
        let channel = l.channel("#open").await;
        let early = l.texts(&channel, 2).await;
        // Taken last, with an author's clock older than every block before
        // it: still after them in `b`'s order.
        let backdated = post_at(
            &l.b,
            &l.user,
            BlockKind::TextRender,
            serde_json::json!({"channel_id": channel, "body": "backdated"}),
            Some(jig_core::HlcTimestamp {
                wall_ms: 1,
                logical: 0,
                server_did: l.b.server_did.clone(),
            }),
        )
        .await
        .unwrap();

        let after = |cid: &str| -> Vec<String> {
            l.page(cid, 0)
                .entries
                .iter()
                .map(|e| crate::v0_0_2_federation::peer_block_cid(&e.bundle).unwrap())
                .collect()
        };
        assert_eq!(after(&early[0]), [early[1].clone(), backdated.clone()]);
        assert_eq!(after(&backdated), Vec::<String>::new());

        l.dial(&l.a);
        Legacy::holds(&l.a, std::slice::from_ref(&backdated)).await;
        // `a` keeps each block under `b`'s CID, byte for byte: the cursor it
        // sends next is a block `b` finds in its own store.
        for cid in [&channel, &early[0], &early[1], &backdated] {
            let ours = l.a.ingest_ctx.store.get_block(cid).unwrap().unwrap();
            let theirs = l.b.ingest_ctx.store.get_block(cid).unwrap().unwrap();
            assert_eq!(ours.bundle_bytes, theirs.bundle_bytes);
            assert_eq!(ours.federated_from.as_deref(), Some(l.to_b.url.as_str()));
        }
        let next = l.a.ingest_ctx.store.newest_block_from(&l.to_b.url).unwrap();
        assert_eq!(next.as_deref(), Some(backdated.as_str()));
        assert!(
            l.b.ingest_ctx
                .store
                .block_position(&backdated)
                .unwrap()
                .is_some()
        );
    }

    /// The live push need not reach `a` in `b`'s order: two ingests racing
    /// on `b` can fan out the later one first. Here `a` took `b`'s second
    /// post live, not its first, when the link dropped: the reconnect's
    /// overlap still brings the first.
    #[tokio::test]
    async fn a_block_pushed_out_of_order_is_caught_up_after_a_reconnect() {
        let l = legacy().await;
        let channel = l.channel("#open").await;
        let texts = l.texts(&channel, 2).await;
        let b64 = base64::engine::general_purpose::STANDARD;
        for cid in [&channel, &texts[1]] {
            let block = l.b.ingest_ctx.store.get_block(cid).unwrap().unwrap();
            crate::v0_0_2_federation::ingest_peer_block(
                &l.a,
                &l.to_b,
                &base64::Engine::encode(&b64, &block.bundle_bytes),
                Some(&base64::Engine::encode(&b64, &block.sender_sig)),
                "live",
            )
            .await
            .unwrap();
        }
        assert!(!held(&l.a, &texts[0]));
        let newest = l.a.ingest_ctx.store.newest_block_from(&l.to_b.url).unwrap();
        assert_eq!(newest.as_deref(), Some(texts[1].as_str()));

        l.dial(&l.a);
        Legacy::holds(&l.a, &texts[..1]).await;
    }

    #[tokio::test]
    async fn catch_up_pages_past_one_frame() {
        let l = legacy().await;
        let channel = l.channel("#open").await;
        let texts = l
            .texts(&channel, crate::v0_0_2_catch_up::MAX_ENTRIES * 2 + 5)
            .await;

        let first = l.page("", 0);
        assert_eq!(first.entries.len(), crate::v0_0_2_catch_up::MAX_ENTRIES);
        assert!(first.more);

        l.dial(&l.a);
        Legacy::holds(&l.a, &texts).await;
    }

    #[tokio::test]
    async fn catch_up_stops_at_the_quota_and_keeps_its_place() {
        let mut l = legacy().await;
        // `b`'s own blocks, then its channel and two posts, this minute.
        let quota = jig_config::v0_0_2_server::PeerQuotaConfig {
            blocks_per_min: l.federating() as u64 + 3,
            bytes_per_min: 8 * 1024 * 1024,
        };
        l.held_to(Some(quota));
        let channel = l.channel("#open").await;
        let texts = l.texts(&channel, 6).await;

        l.dial(&l.a);
        Legacy::holds(&l.a, &texts[..2]).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            texts[2..].iter().all(|cid| !held(&l.a, cid)),
            "nothing past the quota this minute"
        );
        assert_eq!(l.cursor(&l.a).as_deref(), Some(texts[1].as_str()));
    }

    /// The legacy path across a restart of the dialer part way through a
    /// catch-up, with the live push landing blocks past the gap first: the
    /// restarted server resumes where the catch-up got to, not after the
    /// newest block it holds.
    #[tokio::test]
    async fn a_dialer_restarted_mid_catch_up_misses_nothing() {
        let mut l = legacy().await;
        let quota = jig_config::v0_0_2_server::PeerQuotaConfig {
            blocks_per_min: l.federating() as u64 + 5,
            bytes_per_min: 8 * 1024 * 1024,
        };
        l.held_to(Some(quota));
        let channel = l.channel("#open").await;
        // More than the reconnect's overlap past where the quota stops it.
        let gap = l
            .texts(&channel, crate::v0_0_2_catch_up::OVERLAP as usize + 30)
            .await;

        let dial = l.dial(&l.a);
        Legacy::holds(&l.a, &gap[..4]).await;
        let live = l.texts(&channel, 1).await;
        Legacy::holds(&l.a, &live).await;
        assert!(!held(&l.a, gap.last().unwrap()), "stopped at the quota");
        dial.abort();
        let _ = dial.await;

        // Down: `b` takes more.
        let while_down = l.texts(&channel, 3).await;

        l.held_to(None);
        let a = restarted(&l.a).await;
        l.dial(&a);
        Legacy::holds(&a, &gap).await;
        Legacy::holds(&a, &while_down).await;
        eventually("the catch-up done", || l.cursor(&a).is_none().then_some(())).await;
    }

    /// The contract path across a restart of the follower while the owner
    /// streams to it: the owner's records past the follower's head arrive
    /// once it is back.
    #[tokio::test]
    async fn a_follower_restarted_mid_stream_catches_up() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.shared(0).await;
        p.follows.stream.pull_all();
        p.caught_up(&channel).await;
        for i in 0..5 {
            p.text(&channel, &format!("live {i}")).await;
        }
        p.dial.abort();
        // Down: the owner takes more, past one frame.
        for i in 0..crate::v0_0_2_stream::MAX_ENTRIES + 6 {
            p.text(&channel, &format!("while down {i}")).await;
        }

        // Back, on the same store and key, at a new address.
        let (follower, url) = serve(
            AppState::for_test_from(
                p.follower.config.clone(),
                p.follower.ingest_ctx.store.clone(),
                p.follower.ingest_ctx.server_key.clone(),
            )
            .unwrap(),
        )
        .await;
        crate::v0_0_2_manifest_log::publish(&follower)
            .await
            .unwrap();
        let follows = handle(&follower);
        let to_follower = peer(
            &url,
            follower.server_did.to_did_jig_string(),
            OfferPolicy::Hold,
        );
        tokio::spawn({
            let owner = p.owner.clone();
            async move { crate::v0_0_2_federation::connect_and_relay(&owner, &to_follower).await }
        });
        eventually("the connection", || {
            (p.owner.peers.sender_for(&follower.server_did).is_some()
                && follower.peers.sender_for(&p.owner.server_did).is_some())
            .then_some(())
        })
        .await;

        // What a follower does every `PULL_EVERY`.
        follows.stream.pull_all();
        let want = Pair::head(&p.owner, &channel).unwrap();
        eventually("the restarted follower at the owner's head", || {
            (Pair::head(&follower, &channel) == Some(want)).then_some(())
        })
        .await;
        for seq in 0..=want {
            assert_eq!(
                follower
                    .ingest_ctx
                    .store
                    .ingest_record_bytes(&channel, seq)
                    .unwrap(),
                p.owner
                    .ingest_ctx
                    .store
                    .ingest_record_bytes(&channel, seq)
                    .unwrap(),
                "seq {seq}"
            );
        }
    }

    // ---- The federation relay and the contract on one channel ---------------

    /// Two servers peered both ways, each dialing the other and running its
    /// side of the contract, as every pair that shares a channel is. `b`
    /// accepts `a`'s offers.
    struct Mutual {
        a: Arc<AppState>,
        b: Arc<AppState>,
        b_follows: Contracts,
        user: SigningKey,
    }

    async fn mutual() -> Mutual {
        // Each lists the other, which takes both keys first.
        let (a_key, b_key) = (
            SigningKey::from_bytes(&rand::random()),
            SigningKey::from_bytes(&rand::random()),
        );
        let state = |key: &SigningKey, other: &SigningKey, offers| {
            let mut config = JigServerConfig::default();
            config.federation.dangerously_allow_plaintext_federation = true;
            config.federation.peers = vec![peer("ws://127.0.0.1:1", did_of(other), offers)];
            AppState::for_test_from(
                config,
                Arc::new(jig_pipeline::persist::SqliteStore::open_in_memory().unwrap()),
                key.clone(),
            )
            .unwrap()
        };
        let a = state(&a_key, &b_key, OfferPolicy::Hold);
        let b = state(&b_key, &a_key, OfferPolicy::Accept);
        let (a, a_url) = serve(a).await;
        let (b, b_url) = serve(b).await;
        for state in [&a, &b] {
            crate::v0_0_2_manifest_log::publish(state).await.unwrap();
        }
        handle(&a);
        let b_follows = handle(&b);
        for (from, to, url) in [(&a, &b, &b_url), (&b, &a, &a_url)] {
            let (from, to_peer) = (
                from.clone(),
                peer(url, to.server_did.to_did_jig_string(), OfferPolicy::Hold),
            );
            tokio::spawn(async move {
                crate::v0_0_2_federation::connect_and_relay(&from, &to_peer).await
            });
        }
        // Each subscribed to the other's federation stream: the relay carries
        // only what lands after that.
        for _ in 0..500 {
            if a.ingest_ctx.fanout.local_subscription_count().await == 1
                && b.ingest_ctx.fanout.local_subscription_count().await == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        eventually("both links", || {
            (a.peers.sender_for(&b.server_did).is_some()
                && b.peers.sender_for(&a.server_did).is_some())
            .then_some(())
        })
        .await;
        Mutual {
            a,
            b,
            b_follows,
            user: SigningKey::from_bytes(&rand::random()),
        }
    }

    impl Mutual {
        async fn text(
            &self,
            state: &AppState,
            channel: &str,
            body: &str,
        ) -> Result<String, IngestError> {
            post(
                state,
                &self.user,
                BlockKind::TextRender,
                serde_json::json!({"channel_id": channel, "body": body}),
            )
            .await
        }

        fn held(state: &AppState, cid: &str) -> bool {
            state.ingest_ctx.store.get_block(cid).unwrap().is_some()
        }

        /// A post in `channel` that only `b` holds, as its own user's.
        fn own_post(&self, channel: &str) -> String {
            use ed25519_dalek::Signer as _;
            let manifest_bytes = BlockManifest::builder()
                .version(semver::Version::new(0, 1, 0))
                .author(Author {
                    did: did_of(&self.user).into(),
                    public_key: None,
                    roles: vec![],
                })
                .metadata_entry("channel_id", serde_json::json!(channel))
                .metadata_entry("body", serde_json::json!("only on b"))
                .build()
                .unwrap()
                .with_kind(BlockKind::TextRender)
                .to_canonical_bytes()
                .unwrap();
            let bundle_bytes = serde_json::to_vec(&(&manifest_bytes, &Vec::<u8>::new())).unwrap();
            let cid = crate::v0_0_2_federation::peer_block_cid(&bundle_bytes).unwrap();
            self.b
                .ingest_ctx
                .store
                .insert_block(&StoredBlock {
                    cid: cid.clone(),
                    channel_id: Some(channel.to_string()),
                    block_kind: BlockKind::TextRender.as_str().to_string(),
                    sender_did: did_of(&self.user),
                    sender_sig: self.user.sign(&bundle_bytes).to_bytes().to_vec(),
                    bundle_bytes,
                    is_synthetic: false,
                    hlc_wall_ms: 0,
                    hlc_logical: 0,
                    hlc_origin: String::new(),
                    posted_at: 0,
                    origin_server: self.b.server_url.clone(),
                    federated_from: None,
                })
                .unwrap();
            cid
        }
    }

    /// The collision this guards against: the relay landed `a`'s channel on
    /// `b` as `b`'s own, so a share made `b` act as its owner (offering it to
    /// itself, and writing a refusal into its copy), and `b`'s stream then
    /// refused every record of `a`'s, its row saying `b` sequenced it.
    #[tokio::test]
    async fn a_shared_channel_is_carried_by_the_contract_not_the_relay() {
        let m = mutual().await;
        // Made once both links are up, so the relay copies it at once.
        let channel = post(
            &m.a,
            &m.user,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#k", "tier": "public"}),
        )
        .await
        .unwrap();
        let first = m.text(&m.a, &channel, "before the share").await.unwrap();
        // A post only `b` holds: its user posted it in `b`'s copy, and `a`
        // never took it (stored as such, as a lost relay leaves it).
        let own = m.own_post(&channel);
        eventually("the relay's copy on b", || {
            Mutual::held(&m.b, &first).then_some(())
        })
        .await;
        assert_eq!(
            m.b.ingest_ctx.store.relayed_copies().unwrap(),
            std::slice::from_ref(&channel)
        );

        post(
            &m.a,
            &m.user,
            BlockKind::ChannelShare,
            serde_json::json!({
                "channel_id": channel,
                "to": m.b.server_did.to_did_jig_string(),
                "grant": "write",
            }),
        )
        .await
        .unwrap();
        let b_did = m.b.server_did.to_did_jig_string();
        let a_did = m.a.server_did.to_did_jig_string();
        eventually("the share accepted", || {
            (m.b.ingest_ctx
                .store
                .has_accepted_share(&channel, &a_did)
                .unwrap()
                && m.a
                    .ingest_ctx
                    .store
                    .contract_offers_for(&channel, &b_did, Side::Owner, OfferState::Accepted)
                    .unwrap()
                    .len()
                    == 1)
                .then_some(())
        })
        .await;

        // `b` never acted as the owner, and its copy is set aside, whole,
        // under its own id: `a`'s chain lands under the channel's.
        let b_store = &m.b.ingest_ctx.store;
        assert!(b_store.relayed_copies().unwrap().is_empty());
        let copy_id = jig_pipeline::ingest_record::label_cid(&format!("relayed-copy:{channel}"));
        let copy = b_store.get_channel_by_id(&copy_id).unwrap().unwrap();
        assert!(copy.slug.starts_with("#jig/relayed-"), "{}", copy.slug);
        let kept = b_store.quarantined_records(&copy_id).unwrap();
        assert_eq!(
            kept.len(),
            2,
            "b's records of its copy, kept: the create and the first post"
        );
        for state in [OfferState::Held, OfferState::Accepted, OfferState::Refused] {
            assert!(
                b_store
                    .contract_offers_for(&channel, &b_did, Side::Owner, state)
                    .unwrap()
                    .is_empty()
            );
        }

        // What `b` carries, it does not relay: a peer of `b`'s would take it
        // as its own copy.
        let (relayed, mut relayed_rx) = tokio::sync::mpsc::unbounded_channel();
        m.b.ingest_ctx
            .fanout
            .subscribe_local(
                jig_pipeline::fanout::SubscriptionScope::Federation {
                    block_kinds: vec![],
                },
                jig_pipeline::fanout::SubscriberIdentity::Did(did_of(&SigningKey::from_bytes(
                    &rand::random(),
                ))),
                relayed,
            )
            .await;

        m.b_follows.stream.pull_all();
        for i in 0..3 {
            m.text(&m.a, &channel, &format!("after the share {i}"))
                .await
                .unwrap();
        }
        let head = |state: &AppState| Pair::head(state, &channel);
        let want = eventually("a's records past the share", || {
            Pair::head(&m.a, &channel).filter(|h| *h >= 5)
        })
        .await;
        m.b_follows.stream.pull_all();
        eventually("b at a's head", || (head(&m.b) == Some(want)).then_some(())).await;

        // One chain, a's, byte for byte, holding nothing signed by b.
        let row = b_store.get_channel_by_id(&channel).unwrap().unwrap();
        assert_eq!(row.sequencer_did, a_did);
        for seq in 0..=want {
            assert_eq!(
                b_store.ingest_record_bytes(&channel, seq).unwrap(),
                m.a.ingest_ctx
                    .store
                    .ingest_record_bytes(&channel, seq)
                    .unwrap(),
                "seq {seq}"
            );
        }
        let kinds: Vec<String> = kinds_in(&m.a, &channel)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(
            !kinds
                .iter()
                .any(|k| k == BlockKind::ContractRefuse.as_str()),
            "no refusal of b's in a's log: {kinds:?}"
        );
        assert_eq!(kinds_in(&m.b, &channel).len(), kinds.len());
        // What `a` never took stays in the copy; what `a`'s chain landed
        // came back into the channel.
        let own_block = b_store.get_block(&own).unwrap().unwrap();
        assert_eq!(own_block.channel_id.as_deref(), Some(copy_id.as_str()));
        let back = b_store.get_block(&first).unwrap().unwrap();
        assert_eq!(back.channel_id.as_deref(), Some(channel.as_str()));

        let mut relayed_any = Vec::new();
        while let Ok((block, _)) = relayed_rx.try_recv() {
            relayed_any.push(block.block_kind);
        }
        assert!(relayed_any.is_empty(), "b relayed {relayed_any:?}");

        // Posts both ways: a post on `b` goes to `a` under the share's grant
        // (JEP-0005 rule 15), lands in `a`'s chain, and comes back through the
        // contract, never the relay. One chain still, `a`'s, byte for byte.
        let parts = signed(&m.user, BlockKind::TextRender, text_in(&channel, "on b"));
        let on_b = client_post(&m.b, &parts).await.unwrap();
        assert!(Mutual::held(&m.a, &on_b));
        m.b_follows.stream.pull_all();
        let want = Pair::head(&m.a, &channel).unwrap();
        eventually("b at a's head, with its own post", || {
            (head(&m.b) == Some(want)).then_some(())
        })
        .await;
        for seq in 0..=want {
            assert_eq!(
                b_store.ingest_record_bytes(&channel, seq).unwrap(),
                m.a.ingest_ctx
                    .store
                    .ingest_record_bytes(&channel, seq)
                    .unwrap(),
                "seq {seq}, after the relayed post"
            );
        }
        let landed = b_store.get_block(&on_b).unwrap().unwrap();
        assert_eq!(landed.channel_id.as_deref(), Some(channel.as_str()));
        // A post that skips the grant path is still refused here.
        assert!(matches!(
            m.text(&m.b, &channel, "around the relay").await,
            Err(IngestError::CarriedChannel { .. })
        ));

        // The relay still carries what is not shared, both ways.
        let elsewhere = post(
            &m.b,
            &m.user,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#elsewhere", "tier": "public"}),
        )
        .await
        .unwrap();
        let on_b = m.text(&m.b, &elsewhere, "from b").await.unwrap();
        eventually("b's open channel on a", || {
            Mutual::held(&m.a, &on_b).then_some(())
        })
        .await;
        let on_a = m.text(&m.a, &elsewhere, "from a").await.unwrap();
        eventually("a's post on b", || Mutual::held(&m.b, &on_a).then_some(())).await;
    }

    /// Two peers that each have their own `#general`: the relay lands `a`'s
    /// posts, which name the channel by slug as clients post them, in `b`'s
    /// own `#general`. Once `b` follows `a`'s, `a`'s chain names a block `b`
    /// holds in its own channel. `b` leaves it there, stalls, and says so.
    #[tokio::test]
    async fn a_same_slug_channel_stalls_the_carried_one_visibly() {
        let m = mutual().await;
        // Made by another user: the same author's create of the same slug is
        // the same block, so the same channel.
        let ours = post(
            &m.b,
            &SigningKey::from_bytes(&rand::random()),
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#general", "tier": "public"}),
        )
        .await
        .unwrap();
        let channel = post(
            &m.a,
            &m.user,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#general", "tier": "public"}),
        )
        .await
        .unwrap();
        let text = post(
            &m.a,
            &m.user,
            BlockKind::TextRender,
            serde_json::json!({"channel": "#general", "body": "by slug"}),
        )
        .await
        .unwrap();
        eventually("a's post in b's own #general", || {
            Mutual::held(&m.b, &text).then_some(())
        })
        .await;
        let b_store = &m.b.ingest_ctx.store;
        assert_eq!(
            b_store
                .get_block(&text)
                .unwrap()
                .unwrap()
                .channel_id
                .as_deref(),
            Some(ours.as_str())
        );

        post(
            &m.a,
            &m.user,
            BlockKind::ChannelShare,
            serde_json::json!({
                "channel_id": channel,
                "to": m.b.server_did.to_did_jig_string(),
                "grant": "read",
            }),
        )
        .await
        .unwrap();
        let a_did = m.a.server_did.to_did_jig_string();
        eventually("the share accepted", || {
            b_store
                .has_accepted_share(&channel, &a_did)
                .unwrap()
                .then_some(())
        })
        .await;
        m.b_follows.stream.pull_all();
        let stall = eventually("the stall", || b_store.carried_stalls().unwrap().pop()).await;
        assert_eq!(
            (
                stall.channel_id.as_str(),
                stall.seq,
                stall.block_cid.as_str()
            ),
            (channel.as_str(), 1, text.as_str())
        );
        assert_eq!(stall.holder, ours);
        // `b`'s own channel keeps its block, and its chain still names it.
        assert_eq!(
            b_store
                .get_block(&text)
                .unwrap()
                .unwrap()
                .channel_id
                .as_deref(),
            Some(ours.as_str())
        );
        assert_eq!(b_store.get_ingest_record(&text).unwrap().unwrap().seq, 1);
        // An operator sees it without reading logs.
        let listed = operate(b_store, Operation::List).unwrap();
        assert!(
            listed.contains(&format!(
                "stalled: channel {channel} stalled at seq 1: block {text} is held in channel {ours}"
            )),
            "{listed}"
        );
    }

    /// A share the relay brings is refused: it is a request to the channel's
    /// sequencer, and this server would act on it as owner of its copy.
    #[tokio::test]
    async fn a_share_from_a_peer_is_refused() {
        let m = mutual().await;
        let channel = post(
            &m.a,
            &m.user,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#k", "tier": "public"}),
        )
        .await
        .unwrap();
        eventually("the relay's copy on b", || {
            Mutual::held(&m.b, &channel).then_some(())
        })
        .await;
        // Shared with a third server: `a` refuses it (NOT_A_PEER), and `b`
        // must not take it at all.
        let share = post(
            &m.a,
            &m.user,
            BlockKind::ChannelShare,
            serde_json::json!({
                "channel_id": channel,
                "to": did_of(&SigningKey::from_bytes(&rand::random())),
                "grant": "read",
            }),
        )
        .await
        .unwrap();
        let sentinel = m.text(&m.a, &channel, "after").await.unwrap();
        eventually("the relay past the share", || {
            Mutual::held(&m.b, &sentinel).then_some(())
        })
        .await;
        assert!(!Mutual::held(&m.b, &share));
        let refusals: Vec<String> = kinds_in(&m.b, &channel)
            .into_iter()
            .map(|(k, _)| k)
            .filter(|k| k.starts_with("contract-"))
            .collect();
        assert!(refusals.is_empty(), "{refusals:?}");
    }

    /// A server that accepted a share while it held the relay's copy (as one
    /// running the release before this fix did) sets the copy aside at boot,
    /// keeping all of it.
    #[tokio::test]
    async fn a_forked_copy_is_set_aside_at_boot() {
        let m = mutual().await;
        let followed = post(
            &m.a,
            &m.user,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#k", "tier": "public"}),
        )
        .await
        .unwrap();
        let other = post(
            &m.a,
            &m.user,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#other", "tier": "public"}),
        )
        .await
        .unwrap();
        eventually("the relay's copies on b", || {
            (Mutual::held(&m.b, &followed) && Mutual::held(&m.b, &other)).then_some(())
        })
        .await;
        let store = &m.b.ingest_ctx.store;
        // The accept, as the release before this fix kept it: the copy stays.
        store
            .put_contract_offer(&StoredOffer {
                offer_id: rand::random(),
                channel_id: followed.clone(),
                side: Side::Follower,
                peer_did: m.a.server_did.to_did_jig_string(),
                grant: Grant::Read,
                state: OfferState::Accepted,
                offer: vec![],
                answer: None,
                share_cid: None,
            })
            .unwrap();

        let from_a_store = m.a.ingest_ctx.store.get_block(&followed).unwrap().unwrap();
        let records = store
            .list_ingest_records_by_id(&followed, 0, 100)
            .unwrap()
            .len();
        repair_relayed_copies(store);
        assert!(store.get_channel_by_id(&followed).unwrap().is_none());
        let copy_id = jig_pipeline::ingest_record::label_cid(&format!("relayed-copy:{followed}"));
        assert!(store.get_channel_by_id(&copy_id).unwrap().is_some());
        assert_eq!(store.quarantined_records(&copy_id).unwrap().len(), records);
        let create = store.get_block(&followed).unwrap().unwrap();
        assert_eq!(
            create.channel_id.as_deref(),
            Some(copy_id.as_str()),
            "kept, aside"
        );

        // Until the owner's stream lands it again, the relay cannot bring the
        // copy back (a catch-up replays a peer's channels from their start).
        let b64 = base64::engine::general_purpose::STANDARD;
        let from_a = peer(
            "ws://127.0.0.1:1",
            m.a.server_did.to_did_jig_string(),
            OfferPolicy::Hold,
        );
        crate::v0_0_2_federation::ingest_peer_block(
            &m.b,
            &from_a,
            &base64::Engine::encode(&b64, &from_a_store.bundle_bytes),
            Some(&base64::Engine::encode(&b64, &from_a_store.sender_sig)),
            "replayed",
        )
        .await
        .unwrap();
        assert!(store.get_channel_by_id(&followed).unwrap().is_none());
        assert_eq!(
            store.relayed_copies().unwrap(),
            [other],
            "a copy not shared stays"
        );
    }

    // ---- Writes through a follower (JEP-0005 rules 7a, 15) -----------------

    use crate::v0_0_2_relay::{Refusal, Submit};

    /// A block signed by `key`: its manifest, code and signature.
    fn signed(
        key: &SigningKey,
        kind: BlockKind,
        meta: serde_json::Value,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use ed25519_dalek::Signer as _;
        let mut builder = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: did_of(key).into(),
                public_key: None,
                roles: vec![],
            });
        if let serde_json::Value::Object(map) = meta {
            for (k, v) in map {
                builder = builder.metadata_entry(&k, v);
            }
        }
        let manifest = builder
            .build()
            .unwrap()
            .with_kind(kind)
            .to_canonical_bytes()
            .unwrap();
        let code: Vec<u8> = Vec::new();
        let sig = key
            .sign(&serde_json::to_vec(&(&manifest, &code)).unwrap())
            .to_bytes()
            .to_vec();
        (manifest, code, sig)
    }

    /// Post `parts` as a client of `state` would.
    async fn client_post(
        state: &AppState,
        parts: &(Vec<u8>, Vec<u8>, Vec<u8>),
    ) -> Result<String, Refusal> {
        crate::v0_0_2_relay::post(state, &parts.0, &parts.1, parts.2.clone(), 7, "ws:7", true).await
    }

    /// The submit a follower would send for `parts`, into `channel`.
    fn submit_of(channel: &str, parts: &(Vec<u8>, Vec<u8>, Vec<u8>)) -> Submit {
        Submit {
            request_id: 1,
            channel_id: channel.to_string(),
            bundle: serde_json::to_vec(&(&parts.0, &parts.1)).unwrap(),
            sig: parts.2.clone(),
        }
    }

    fn text_in(channel: &str, body: &str) -> serde_json::Value {
        serde_json::json!({"channel_id": channel, "body": body})
    }

    impl Pair {
        /// A channel shared with `grant`, accepted, and carried by the
        /// follower.
        async fn carried(&self, grant: &str) -> String {
            let channel = self.channel().await;
            self.share(&channel, grant).await;
            self.both(&channel, OfferState::Accepted).await;
            self.follows.stream.pull_all();
            self.caught_up(&channel).await;
            channel
        }

        fn owner_relay(&self) -> Arc<Relay> {
            self.owner.relay.get().unwrap().clone()
        }
    }

    /// A `shared` MLS channel on `p`'s owner, created by its user: the
    /// channel, the user's MLS member and the group's id.
    async fn shared_mls_channel(p: &Pair) -> (String, jig_mls::member::Member, Vec<u8>) {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let did = jig_core::did::Did::from_ed25519_pubkey(p.user.verifying_key().as_bytes());
        let creator = jig_mls::member::Member::new(&p.user.to_bytes(), &did).unwrap();
        let created = creator.create_group().unwrap();
        let channel = post(
            &p.owner,
            &p.user,
            BlockKind::ChannelCreate,
            serde_json::json!({
                "slug": "#across",
                "tier": "shared",
                "suite": "mls",
                "mls_group_info": b64(&created.group_info),
                "mls_ratchet_tree": b64(&created.ratchet_tree),
            }),
        )
        .await
        .unwrap();
        (channel, creator, created.group_id)
    }

    /// A `shared` channel's offer goes only to a peer whose handshake says
    /// it implements tiers: one without them would carry it untiered. The
    /// offer waits, unanswered.
    #[tokio::test]
    async fn a_shared_channel_is_not_offered_to_a_peer_without_tiers() {
        let p = pair(OfferPolicy::Accept).await;
        let (channel, _, _) = shared_mls_channel(&p).await;
        // The follower's newest connection is one that did not ask for tiers.
        let (old, mut old_rx) = PeerSender::new(p.follower.server_did.clone());
        let _registration = p.owner.peers.register(old);
        p.share(&channel, "write").await;
        let offered = eventually("the owner's offer", || {
            p.offers(Side::Owner, &channel, OfferState::Offered).pop()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(old_rx.try_recv().is_err(), "nothing sent to the old peer");
        assert!(
            p.offers(Side::Follower, &channel, OfferState::Accepted)
                .is_empty(),
            "the follower never saw it"
        );
        assert_eq!(
            p.offers(Side::Owner, &channel, OfferState::Offered),
            vec![offered],
            "the offer waits"
        );
    }

    /// JEP-0014 rule 13 across servers: a `shared` MLS channel on its owner,
    /// shared with a follower. A member whose client is on the follower joins
    /// by Welcome and posts through it; the owner's member reads the post.
    /// Neither server ever holds the plaintext.
    #[tokio::test]
    async fn a_shared_mls_channel_is_written_through_its_follower_and_read_at_its_owner() {
        use jig_mls::member::Member;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let did = |key: &SigningKey| {
            jig_core::did::Did::from_ed25519_pubkey(key.verifying_key().as_bytes())
        };
        let p = pair(OfferPolicy::Accept).await;
        let (channel, creator, gid) = shared_mls_channel(&p).await;
        p.share(&channel, "write").await;
        p.both(&channel, OfferState::Accepted).await;

        // A member whose client is on the follower, added on the owner. Its
        // key package reaches the creator directly (custodians: Task 8).
        let remote_key = SigningKey::from_bytes(&rand::random());
        let remote = Member::new(&remote_key.to_bytes(), &did(&remote_key)).unwrap();
        let kp = remote.key_packages(1, false).unwrap().remove(0);
        let remote_did = did(&remote_key).to_did_jig_string();
        let commit = creator.add(&gid, &kp, &remote_did).unwrap();
        post(
            &p.owner,
            &p.user,
            BlockKind::MemberAdd,
            serde_json::json!({
                "channel_id": channel,
                "member_did": remote_did,
                "mls_commit": b64(&commit.commit),
                "mls_welcome": b64(commit.welcome.as_ref().unwrap()),
            }),
        )
        .await
        .unwrap();
        creator.confirm(&gid).unwrap();
        assert_eq!(
            remote
                .join_welcome(commit.welcome.as_ref().unwrap())
                .unwrap(),
            gid
        );
        p.follows.stream.pull_all();
        p.caught_up(&channel).await;
        assert_eq!(
            p.follower
                .ingest_ctx
                .store
                .get_mls_group_by_id(&channel)
                .unwrap()
                .unwrap()
                .epoch,
            1,
            "the follower's mirror moved with the commit"
        );

        // The remote member posts through the follower.
        let secret = "the meeting moved to thursday";
        let (ct, epoch) = remote.encrypt(&gid, secret.as_bytes()).unwrap();
        let parts = {
            use ed25519_dalek::Signer as _;
            let manifest = BlockManifest::builder()
                .version(semver::Version::new(0, 1, 0))
                .author(Author {
                    did: did(&remote_key),
                    public_key: None,
                    roles: vec![],
                })
                .privacy(jig_core::Privacy {
                    encryption: jig_core::EncryptionSuite::Mls,
                    recipients: vec![],
                    metadata_visibility: Default::default(),
                })
                .metadata_entry("channel_id", serde_json::json!(channel))
                .metadata_entry("mls_message", serde_json::json!(b64(&ct)))
                .metadata_entry("mls_epoch", serde_json::json!(epoch))
                .build()
                .unwrap()
                .with_kind(BlockKind::TextRender)
                .to_canonical_bytes()
                .unwrap();
            let code: Vec<u8> = Vec::new();
            let sig = remote_key
                .sign(&serde_json::to_vec(&(&manifest, &code)).unwrap())
                .to_bytes()
                .to_vec();
            (manifest, code, sig)
        };
        let cid = client_post(&p.follower, &parts).await.unwrap();
        let at_owner = p
            .owner
            .ingest_ctx
            .store
            .get_block(&cid)
            .unwrap()
            .expect("landed at the owner");
        assert_eq!(at_owner.channel_id.as_deref(), Some(channel.as_str()));
        p.caught_up(&channel).await;
        // The owner knows which server relayed the member's latest write:
        // the hint `jig channel members --via` lists after a contract ends.
        let via = p
            .owner
            .ingest_ctx
            .store
            .last_relay_by_sender(&channel)
            .unwrap();
        assert_eq!(
            via.get(&remote_did).cloned().flatten(),
            Some(p.follower.server_did.to_did_jig_string())
        );
        assert_eq!(via.get(&did(&p.user).to_did_jig_string()), Some(&None));

        // The owner's member reads it from what the owner stored.
        let (stored, _): (Vec<u8>, Vec<u8>) =
            serde_json::from_slice(&at_owner.bundle_bytes).unwrap();
        let stored: BlockManifest = serde_json::from_slice(&stored).unwrap();
        let ct = base64::engine::general_purpose::STANDARD
            .decode(stored.metadata["mls_message"].as_str().unwrap())
            .unwrap();
        let read = creator.decrypt(&gid, &ct).unwrap();
        assert_eq!(read.plaintext, secret.as_bytes());

        // Neither server holds the plaintext, in any block of the channel.
        for state in [&p.owner, &p.follower] {
            for (_, manifest) in kinds_in(state, &channel) {
                assert!(
                    !serde_json::to_string(&manifest).unwrap().contains(secret),
                    "a server holds the plaintext"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_write_through_a_write_follower_lands_at_the_owner_and_comes_back() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.carried("write").await;
        let author = SigningKey::from_bytes(&rand::random());
        let parts = signed(&author, BlockKind::TextRender, text_in(&channel, "hello"));

        let cid = client_post(&p.follower, &parts).await.unwrap();
        let owner = &p.owner.ingest_ctx.store;
        let block = owner.get_block(&cid).unwrap().expect("landed at the owner");
        assert_eq!(block.channel_id.as_deref(), Some(channel.as_str()));
        assert_eq!(
            block.federated_from.as_deref(),
            Some(p.follower.server_did.to_did_jig_string().as_str()),
            "the owner records the relaying server"
        );
        // Back through the owner's stream, with the owner's record.
        let head = p.caught_up(&channel).await;
        let record = p
            .follower
            .ingest_ctx
            .store
            .get_ingest_record(&cid)
            .unwrap()
            .unwrap();
        assert_eq!(record.seq, head);
        assert_eq!(record.sequencer, p.owner.server_did.to_did_jig_string());

        // The same signed block again is the block already taken.
        assert_eq!(client_post(&p.follower, &parts).await.unwrap(), cid);
        assert_eq!(Pair::head(&p.owner, &channel), Some(head), "it landed once");
    }

    #[tokio::test]
    async fn a_read_follower_relays_no_content_and_the_owner_refuses_it_too() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.carried("read").await;
        let author = SigningKey::from_bytes(&rand::random());
        let parts = signed(&author, BlockKind::TextRender, text_in(&channel, "hi"));
        let refused = client_post(&p.follower, &parts).await.unwrap_err();
        assert_eq!(refused.code, "GRANT_REFUSED", "{refused:?}");

        // A follower that relays it anyway meets the owner's own check.
        let answer = p
            .owner_relay()
            .accept(&p.follower.server_did, submit_of(&channel, &parts))
            .await;
        assert_eq!(answer.code, "GRANT_REFUSED", "{answer:?}");
        assert!(
            p.owner
                .ingest_ctx
                .store
                .get_block(&answer.block_cid)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn membership_goes_only_through_a_member_follower() {
        let member = did_of(&SigningKey::from_bytes(&rand::random()));
        let add = |channel: &str| serde_json::json!({"channel_id": channel, "member_did": member});

        let p = pair(OfferPolicy::Accept).await;
        let channel = p.carried("write").await;
        let parts = signed(&p.user, BlockKind::MemberAdd, add(&channel));
        let refused = client_post(&p.follower, &parts).await.unwrap_err();
        assert_eq!(refused.code, "GRANT_REFUSED", "{refused:?}");

        let p = pair(OfferPolicy::Accept).await;
        let channel = p.carried("member").await;
        let parts = signed(&p.user, BlockKind::MemberAdd, add(&channel));
        client_post(&p.follower, &parts).await.unwrap();
        assert!(
            p.owner
                .ingest_ctx
                .store
                .is_member_by_id(&channel, &member)
                .unwrap()
        );
        // As the channel's rule allows: a stranger may not add members.
        let stranger = SigningKey::from_bytes(&rand::random());
        let parts = signed(&stranger, BlockKind::MemberAdd, add(&channel));
        let refused = client_post(&p.follower, &parts).await.unwrap_err();
        assert_ne!(
            refused.code, "GRANT_REFUSED",
            "the owner's gate, not the grant"
        );
    }

    #[tokio::test]
    async fn a_relayed_block_needs_its_authors_signature_whatever_the_grant() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.carried("member").await;
        let author = SigningKey::from_bytes(&rand::random());
        let mut parts = signed(&author, BlockKind::TextRender, text_in(&channel, "forged"));
        parts.2[0] ^= 1;
        let refused = client_post(&p.follower, &parts).await.unwrap_err();
        assert_eq!(refused.code, "INVALID_SIG", "{refused:?}");
        let answer = p
            .owner_relay()
            .accept(&p.follower.server_did, submit_of(&channel, &parts))
            .await;
        assert_eq!(answer.code, "INVALID_SIG", "{answer:?}");
    }

    #[tokio::test]
    async fn a_follower_relays_only_into_the_channel_it_shares_and_never_a_banned_author() {
        let banned = SigningKey::from_bytes(&rand::random());
        let banned_did = did_of(&banned);
        let p = pair_tuned(OfferPolicy::Accept, None, |c| {
            c.auth.admission.banned_dids = vec![banned_did.clone()];
        })
        .await;
        let channel = p.carried("write").await;
        let unshared = post(
            &p.owner,
            &p.user,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#unshared", "tier": "public"}),
        )
        .await
        .unwrap();
        let author = SigningKey::from_bytes(&rand::random());
        let relay = p.owner_relay();
        let follower = &p.follower.server_did;

        // A block for another channel, sent under this share.
        let elsewhere = signed(&author, BlockKind::TextRender, text_in(&unshared, "in"));
        let answer = relay
            .accept(follower, submit_of(&channel, &elsewhere))
            .await;
        assert_eq!(answer.code, "RELAY_OUTSIDE_SHARE", "{answer:?}");
        // A channel the share does not cover.
        let answer = relay
            .accept(follower, submit_of(&unshared, &elsewhere))
            .await;
        assert_eq!(answer.code, "NOT_SHARED", "{answer:?}");
        // A channel-create is outside every share.
        let create = signed(
            &author,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#new", "tier": "public"}),
        );
        let answer = relay.accept(follower, submit_of(&channel, &create)).await;
        assert_eq!(answer.code, "RELAY_OUTSIDE_SHARE", "{answer:?}");
        assert!(
            p.owner
                .ingest_ctx
                .store
                .get_block(&unshared)
                .unwrap()
                .is_some()
        );

        // An author the owner bans, admitted by the follower.
        let parts = signed(&banned, BlockKind::TextRender, text_in(&channel, "banned"));
        let refused = client_post(&p.follower, &parts).await.unwrap_err();
        assert_eq!(refused.code, "NOT_ADMITTED", "{refused:?}");
    }

    #[tokio::test]
    async fn a_follower_relaying_too_fast_is_told_to_wait() {
        let p = pair_tuned(OfferPolicy::Accept, None, |c| {
            c.federation.relayed_writes = jig_config::v0_0_2_server::RateLimit {
                burst: 2,
                per_min: 6,
            };
        })
        .await;
        let channel = p.carried("write").await;
        let author = SigningKey::from_bytes(&rand::random());
        for i in 0..2 {
            let parts = signed(
                &author,
                BlockKind::TextRender,
                text_in(&channel, &format!("{i}")),
            );
            client_post(&p.follower, &parts).await.unwrap();
        }
        let parts = signed(&author, BlockKind::TextRender, text_in(&channel, "third"));
        let refused = client_post(&p.follower, &parts).await.unwrap_err();
        assert_eq!(refused.code, "RELAY_RATE_LIMITED", "{refused:?}");
        assert!(
            refused.message.contains("retry_after_ms="),
            "{}",
            refused.message
        );
    }

    #[tokio::test]
    async fn a_relay_the_owner_does_not_answer_is_pending_and_held_to_a_cap() {
        let p = pair(OfferPolicy::Accept).await;
        let channel = p.carried("write").await;
        // The follower's newest connection to the owner swallows every frame.
        let (silent, mut swallowed) = PeerSender::new(p.owner.server_did.clone());
        let _registration = p.follower.peers.register(silent);
        let follower = p.follower.clone();
        let author = SigningKey::from_bytes(&rand::random());
        let mut waiting = Vec::new();
        for i in 0..crate::v0_0_2_relay::MAX_IN_FLIGHT {
            let parts = signed(
                &author,
                BlockKind::TextRender,
                text_in(&channel, &format!("{i}")),
            );
            let follower = follower.clone();
            waiting.push(tokio::spawn(
                async move { client_post(&follower, &parts).await },
            ));
        }
        for _ in 0..crate::v0_0_2_relay::MAX_IN_FLIGHT {
            swallowed.recv().await.expect("a relay sent");
        }
        let parts = signed(
            &author,
            BlockKind::TextRender,
            text_in(&channel, "one more"),
        );
        let refused = client_post(&p.follower, &parts).await.unwrap_err();
        assert_eq!(refused.code, "RELAY_BUSY", "{refused:?}");

        // A client that goes away while it waits leaves nothing waiting.
        let relay = p.follower.relay.get().unwrap().clone();
        let parts = signed(&author, BlockKind::TextRender, text_in(&channel, "gone"));
        let gone = {
            let follower = follower.clone();
            tokio::spawn(async move {
                crate::v0_0_2_relay::post(&follower, &parts.0, &parts.1, parts.2, 8, "ws:8", true)
                    .await
            })
        };
        swallowed.recv().await.expect("its relay sent");
        assert_eq!(relay.waiting(), crate::v0_0_2_relay::MAX_IN_FLIGHT + 1);
        gone.abort();
        let _ = gone.await;
        assert_eq!(relay.waiting(), crate::v0_0_2_relay::MAX_IN_FLIGHT);

        // Unanswered, each is pending: the outcome is unknown, and resending
        // is safe.
        tokio::time::pause();
        for task in waiting {
            let refused = task.await.unwrap().unwrap_err();
            assert_eq!(refused.code, "RELAY_PENDING", "{refused:?}");
            assert!(
                refused.message.contains("again is safe"),
                "{}",
                refused.message
            );
        }
        assert_eq!(relay.waiting(), 0, "nothing left waiting");
    }

    #[tokio::test]
    async fn a_write_for_an_owner_not_connected_is_refused_with_when_to_retry() {
        let follower = state_with(vec![], &[]);
        handle(&follower);
        let owner = did_of(&SigningKey::from_bytes(&rand::random()));
        let channel = jig_pipeline::ingest_record::label_cid("carried");
        let store = &follower.ingest_ctx.store;
        store
            .upsert_channel(&StoredChannel {
                id: channel.clone(),
                slug: "#carried".to_string(),
                visibility: "open".to_string(),
                created_at: 0,
                owner_did: owner.clone(),
                suite: jig_core::EncryptionSuite::Unencrypted.as_str().to_string(),
                sequencer_did: owner.clone(),
                co_owners: vec![],
                tiering: jig_pipeline::persist::ChannelTiering::current(
                    "open",
                    jig_core::EncryptionSuite::Unencrypted.as_str(),
                ),
            })
            .unwrap();
        store
            .put_contract_offer(&StoredOffer {
                offer_id: rand::random(),
                channel_id: channel.clone(),
                side: Side::Follower,
                peer_did: owner.clone(),
                grant: Grant::Write,
                state: OfferState::Accepted,
                offer: vec![],
                answer: None,
                share_cid: None,
            })
            .unwrap();
        let author = SigningKey::from_bytes(&rand::random());
        let parts = signed(&author, BlockKind::TextRender, text_in(&channel, "hello"));
        let refused = client_post(&follower, &parts).await.unwrap_err();
        assert_eq!(refused.code, "OWNER_UNREACHABLE", "{refused:?}");
        assert!(
            refused.message.contains("retry_after_ms=5000"),
            "{}",
            refused.message
        );
    }
}
