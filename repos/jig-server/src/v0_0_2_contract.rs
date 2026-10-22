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
//! - `SUFFIX_CONFLICT`: the owner privately attests a suffix this server
//!   attests too. Its private suffixes are `config`-rooted and this server's
//!   attested suffixes are `dns`-rooted, so the two claims are under
//!   different authorities;
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
//! What a live share carries (the owner's stream to the follower, and the
//! follower's relayed writes) is JEP-0005 rules 12-15, in later slices.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use cid::Cid;
use jig_config::v0_0_2_server::{FederationPeer, FederationSection, OfferPolicy};
use jig_core::block_kind::BlockKind;
use jig_core::contract::{
    ContractAccept, ContractEnd, ContractOffer, ContractRefuse, Grant, ManifestRef, RefuseCode,
};
use jig_core::did::Did;
use jig_core::{Author, BlockBundle, BlockManifest};
use jig_pipeline::contracts::{self, OfferState, Side, StoredOffer};
use jig_pipeline::ingest::{IngestContext, IngestSource, ingest};
use jig_pipeline::persist::{SqliteStore, StoredBlock, StoredChannel};

use crate::v0_0_2::AppState;
use crate::v0_0_2_peer::{CloseReason, PeerFrames, PeerRegistry, PeerSender};

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
}

/// Run the contract on `state`'s server:
/// - register its peer-frame handler;
/// - watch for share blocks;
/// - resend unanswered offers every [`RESEND_EVERY`];
/// - act on the operator's decisions every [`DECIDE_EVERY`].
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
    contracts
}

/// Register the peer-frame handler and watch for share blocks, with no
/// timers: what [`start`] runs, less the resending and the decisions.
fn handle(state: &AppState) -> Contracts {
    let contracts = Contracts::new(state);
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
    contracts
}

impl Contracts {
    pub fn new(state: &AppState) -> Self {
        Self {
            ctx: state.ingest_ctx.clone(),
            federation: Arc::new(state.config.federation.clone()),
            manifest: state.manifest.clone(),
            peers: state.peers.clone(),
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

    /// A suffix in `theirs` that this server attests too. Theirs are the
    /// other side's private, `config`-rooted suffixes, and this server's are
    /// `dns`-rooted, so a shared one is claimed under two authorities.
    fn suffix_conflict(&self, theirs: &[String]) -> Option<String> {
        theirs.iter().map(|s| s.to_lowercase()).find(|s| {
            self.federation
                .attested_suffixes
                .iter()
                .any(|a| a.suffix.to_lowercase() == *s)
        })
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
                    self.send(&offer.peer_did, OFFER_FRAME, offer.offer);
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
            Vec::new(),
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
        self.send(to, OFFER_FRAME, offer.envelope);
        Ok(())
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
                if self.suffix_conflict(&accept.private_suffixes).is_some() {
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
        // Rule 9: a suite this server carries, and no fallback.
        let suite = jig_pipeline::mls_gate::requested_suite(&manifest)
            .map_err(|_| RefuseCode::UnsupportedSuite)?;
        if !suite.is_implemented() {
            return Err(RefuseCode::UnsupportedSuite);
        }
        if self.suffix_conflict(&offer.private_suffixes).is_some() {
            return Err(RefuseCode::SuffixConflict);
        }
        Ok(policy)
    }

    /// Accept an offer in `from`: sign, record, and return the accept.
    fn accept(&self, offer: &ContractOffer, from: OfferState) -> anyhow::Result<Vec<u8>> {
        let accept = ContractAccept::sign(
            &self.ctx.server_key,
            offer,
            self.manifest_ref()?,
            Vec::new(),
            Vec::new(),
        );
        self.store().move_contract_offer(
            &offer.offer_id,
            from,
            OfferState::Accepted,
            Some(&accept.envelope),
        )?;
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
    Ok(offers
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
        .collect::<Vec<_>>()
        .join("\n"))
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
    }

    async fn pair(offers: OfferPolicy) -> Pair {
        let mut owner = state_with(vec![], &[]);
        let follower = state_with(
            vec![peer(
                "ws://127.0.0.1:1",
                owner.server_did.to_did_jig_string(),
                offers,
            )],
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
        tokio::spawn({
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
        }
    }

    /// Sign a block as `key` and ingest it on `state`, as a client would.
    async fn post(
        state: &AppState,
        key: &SigningKey,
        kind: BlockKind,
        meta: serde_json::Value,
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
        let manifest_bytes = builder
            .build()
            .unwrap()
            .with_kind(kind)
            .to_canonical_bytes()
            .unwrap();
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
            IngestSource::LocalClient { conn_id: 1 },
        )
        .await
    }

    impl Pair {
        async fn channel(&self) -> String {
            post(
                &self.owner,
                &self.user,
                BlockKind::ChannelCreate,
                serde_json::json!({"slug": "#shared"}),
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
        private_suffixes: &[&str],
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
            private_suffixes.iter().map(|s| s.to_string()).collect(),
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
        // A suffix the owner attests privately that this server attests too.
        let suffix = offer_to(
            &follower,
            &owner,
            creation(&owner, serde_json::json!({"v": 1})),
            &["names.example.org"],
        );
        assert_eq!(
            answer_to(&contracts, &owner, &suffix).as_deref(),
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
                .on_peer_frame(out.peer(), "relay-submit", b"", &out)
                .is_ok()
        );
    }

    /// The owner refuses an accept whose private suffixes it attests too: the
    /// contract is refused whichever side finds the conflict.
    #[tokio::test]
    async fn an_accept_claiming_a_suffix_the_owner_attests_is_refused() {
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
            serde_json::json!({"slug": "#c"}),
        )
        .await
        .unwrap();
        let cid: Cid = channel.parse().unwrap();
        let offer = ContractOffer::sign(
            &owner.ingest_ctx.server_key,
            &did_of(&follower),
            cid,
            Grant::Read,
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
                grant: Grant::Read,
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
            vec!["names.example.org".to_string()],
            vec![],
        );
        let (out, _rx) = PeerSender::new(Did::from_ed25519_pubkey(
            follower.verifying_key().as_bytes(),
        ));
        contracts
            .on_peer_frame(out.peer(), ANSWER_FRAME, &accept.envelope, &out)
            .unwrap();
        let record = record_of(&owner, &channel, BlockKind::ContractRefuse).await;
        assert_eq!(record.metadata["code"], "SUFFIX_CONFLICT");
        assert_eq!(
            owner
                .ingest_ctx
                .store
                .get_contract_offer(&offer.offer_id)
                .unwrap()
                .unwrap()
                .state,
            OfferState::Refused
        );
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
}
