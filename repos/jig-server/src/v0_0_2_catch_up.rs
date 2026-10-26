//! Catch-up for the federation subscription (`Scope::Federation`): what a
//! peer missed while it was not connected.
//!
//! A server receives a peer's open channels only over its own dial
//! ([`crate::v0_0_2_federation`]), and only live: a block the peer took while
//! the connection was down, or before this server first dialed, never
//! arrived. So after it subscribes, the dialer asks for what it missed: a
//! [`CATCH_UP_FRAME`] naming a block of the peer's to start after, or none
//! at all. The peer answers with [`BLOCKS_FRAME`] pages of its own blocks
//! after that one, and the dialer asks for the next page until there are no
//! more.
//!
//! - **The cursor is the peer's.** It is a block CID, the one identity a block
//!   has on every server, and the peer finds where it is in its own store's
//!   order ([`SqliteStore::block_position`]): the order the peer took its
//!   blocks in. No clock is involved, the block's `hlc_ts` included: that is
//!   the author's to set. Ingest on the dialer keeps the CID as it is.
//! - **Where the dialer starts.** The subscription goes first, so the live
//!   push carries everything the peer takes from then on. A catch-up that
//!   reached the end leaves nothing missing before the newest block the
//!   dialer holds from the peer, and the next one starts after it. One that
//!   did not (a restart part way) is resumed from its saved cursor
//!   (`catch_up_cursors`), since the live push has landed newer blocks past
//!   the gap it was still filling.
//! - **The scope is the live path's.** A page holds only blocks of channels
//!   that federate, as the live subscription delivers them
//!   (`DeliveryPolicy::federates`, judged on the channel as it stands): a
//!   restricted or encrypted channel's blocks are never replayed.
//! - **Paged and bounded.** A page holds at most [`MAX_ENTRIES`] blocks, at
//!   most [`jig_core::bundle::MAX_BUNDLE_BYTES`] of them past a first block
//!   that fills it alone, and reads at most [`SCAN`] rows. The peer takes requests at its
//!   `[federation.records_from]` rate, answering one past it with
//!   [`LATER_FRAME`] and when to ask again. The dialer takes replayed blocks
//!   within its quota for the peer (its `quota`, or `default_peer_quota`):
//!   past it, it stops part way through the page and asks again from there
//!   when the minute turns.
//! - **Nothing is missed at a page edge.** A reconnect steps back [`OVERLAP`]
//!   rows, for blocks the peer fanned out in another order than it stored
//!   them. Blocks the dialer already holds are skipped before ingest.
//! - **At boot,** with no block from the peer yet, the dialer asks from the
//!   start: everything of the peer's that federates, a page at a time. A
//!   cursor the peer does not hold (its store was reset) also starts there.
//!
//! The frames are peer frames ([`crate::v0_0_2_peer`]) on the dialer's
//! connection, deterministic CBOR like the stream's.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use jig_config::v0_0_2_server::{FederationPeer, FederationSection, PeerQuotaConfig};
use jig_core::dcbor::{self, Value};
use jig_core::did::Did;
use jig_pipeline::fanout::DeliveryPolicy;
use jig_pipeline::ingest::IngestContext;
use jig_pipeline::persist::SqliteStore;
use tokio::time::Instant;

use crate::v0_0_2::AppState;
use crate::v0_0_2_peer::{CloseReason, PeerSender};
use crate::v0_0_2_stream::RequestLimit;

/// The dialer's request for the blocks after a cursor.
pub const CATCH_UP_FRAME: &str = "federation-catch-up";
/// One page of the peer's federating blocks.
pub const BLOCKS_FRAME: &str = "federation-blocks";
/// The peer's refusal of a request past its rate, with when to ask again.
pub const LATER_FRAME: &str = "federation-later";

/// The most blocks one page carries.
pub const MAX_ENTRIES: usize = 64;
/// The most rows one page reads, federating or not.
pub const SCAN: usize = 512;
/// How many rows a reconnect steps back from its cursor.
pub const OVERLAP: u64 = 32;
/// The longest the dialer waits on one [`LATER_FRAME`].
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

/// The most block and signature bytes a page packs, unless its first block
/// fills it alone: one largest bundle. Base64 on the wire, a page then fits
/// `jig_core::bundle::MAX_ENVELOPE_BYTES`.
const PAGE_BUDGET: usize = jig_core::bundle::MAX_BUNDLE_BYTES;

/// The dialer's request: the blocks after `after` (empty: from the start),
/// stepping back `overlap` rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ask {
    pub(crate) after: String,
    pub(crate) overlap: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) bundle: Vec<u8>,
    pub(crate) sig: Vec<u8>,
}

/// A page: its blocks, the cursor to ask from next (the last row it read,
/// federating or not), and whether there are more rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Page {
    pub(crate) entries: Vec<Entry>,
    pub(crate) last: String,
    pub(crate) more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Later {
    ask: Ask,
    retry_after_ms: u64,
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

impl Ask {
    pub(crate) fn encode(&self) -> Vec<u8> {
        dcbor::encode(&Value::text_map([
            ("after", Value::text(&self.after)),
            ("overlap", Value::Unsigned(self.overlap)),
        ]))
        .expect("text keys never repeat")
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let value = dcbor::decode(bytes).ok()?;
        let [after, overlap] = fields(&value, &["after", "overlap"])?[..] else {
            return None;
        };
        Some(Ask {
            after: after.as_text()?.to_string(),
            overlap: overlap.as_u64()?,
        })
    }
}

impl Page {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let entries = self
            .entries
            .iter()
            .map(|e| {
                Value::text_map([
                    ("bundle", Value::Bytes(e.bundle.clone())),
                    ("sig", Value::Bytes(e.sig.clone())),
                ])
            })
            .collect();
        dcbor::encode(&Value::text_map([
            ("entries", Value::Array(entries)),
            ("last", Value::text(&self.last)),
            ("more", Value::Bool(self.more)),
        ]))
        .expect("text keys never repeat")
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let value = dcbor::decode(bytes).ok()?;
        let [entries, last, more] = fields(&value, &["entries", "last", "more"])?[..] else {
            return None;
        };
        let entries = entries
            .as_array()?
            .iter()
            .map(|e| {
                let [bundle, sig] = fields(e, &["bundle", "sig"])?[..] else {
                    return None;
                };
                Some(Entry {
                    bundle: bundle.as_bytes()?.to_vec(),
                    sig: sig.as_bytes()?.to_vec(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let Value::Bool(more) = more else {
            return None;
        };
        Some(Page {
            entries,
            last: last.as_text()?.to_string(),
            more: *more,
        })
    }
}

impl Later {
    fn encode(&self) -> Vec<u8> {
        dcbor::encode(&Value::text_map([
            ("after", Value::text(&self.ask.after)),
            ("overlap", Value::Unsigned(self.ask.overlap)),
            ("retry_after_ms", Value::Unsigned(self.retry_after_ms)),
        ]))
        .expect("text keys never repeat")
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let value = dcbor::decode(bytes).ok()?;
        let [after, overlap, retry_after_ms] =
            fields(&value, &["after", "overlap", "retry_after_ms"])?[..]
        else {
            return None;
        };
        Some(Later {
            ask: Ask {
                after: after.as_text()?.to_string(),
                overlap: overlap.as_u64()?,
            },
            retry_after_ms: retry_after_ms.as_u64()?,
        })
    }
}

fn violation(why: &str) -> CloseReason {
    CloseReason {
        code: jig_pipeline::handshake::close::PROTOCOL_VIOLATION,
        reason: format!("catch-up: {why}"),
    }
}

// ---- The dialed side: answering ---------------------------------------------

/// The dialed side of catch-up: pages of this server's federating blocks for
/// the configured peers that ask. Clones share one limit.
#[derive(Clone)]
pub struct Replay {
    ctx: Arc<IngestContext>,
    federation: Arc<FederationSection>,
    requests: Arc<RequestLimit>,
}

impl Replay {
    pub fn new(ctx: Arc<IngestContext>, federation: Arc<FederationSection>) -> Self {
        let requests = Arc::new(RequestLimit::new(federation.records_from));
        Replay {
            ctx,
            federation,
            requests,
        }
    }

    /// Handle a [`CATCH_UP_FRAME`] from `peer`, or `None` for a frame of
    /// another kind. A frame that does not parse closes the connection.
    pub fn on_peer_frame(
        &self,
        peer: &Did,
        kind: &str,
        body: &[u8],
        out: &PeerSender,
    ) -> Option<Result<(), CloseReason>> {
        (kind == CATCH_UP_FRAME).then(|| self.on_ask(peer, body, out))
    }

    fn on_ask(&self, peer: &Did, body: &[u8], out: &PeerSender) -> Result<(), CloseReason> {
        let ask = Ask::decode(body).ok_or_else(|| violation("a malformed federation-catch-up"))?;
        let peer = peer.to_did_jig_string();
        // The federation subscription's own gate: configured peers only.
        let configured = self
            .federation
            .peers
            .iter()
            .any(|p| jig_pipeline::effect::canonical_did_string(&p.expected_did) == peer);
        if !configured {
            tracing::debug!(peer, "catch-up from a server that is not a configured peer");
            return Ok(());
        }
        if let Err(wait) = self
            .requests
            .take(&peer, "federation", tokio::time::Instant::now())
        {
            let later = Later {
                ask,
                retry_after_ms: u64::try_from(wait.as_millis()).unwrap_or(u64::MAX).max(1),
            };
            if let Err(e) = out.send(LATER_FRAME, later.encode()) {
                tracing::info!(peer, "federation-later not sent: {e}");
            }
            return Ok(());
        }
        match self.page(&ask) {
            Ok(page) => {
                if let Err(e) = out.send(BLOCKS_FRAME, page.encode()) {
                    tracing::info!(peer, "federation-blocks not sent: {e}");
                }
            }
            Err(e) => tracing::warn!(peer, "catch-up not answered: {e:#}"),
        }
        Ok(())
    }

    /// The page after `ask`'s cursor.
    pub(crate) fn page(&self, ask: &Ask) -> anyhow::Result<Page> {
        let store = &self.ctx.store;
        let start = match ask.after.as_str() {
            "" => 0,
            after => match store.block_position(after)? {
                Some(at) => at.saturating_sub(ask.overlap.min(OVERLAP) as i64).max(0),
                // Not a block this server holds: from the start.
                None => 0,
            },
        };
        // Positions and channels only: a block's bytes are read once it is
        // known to federate, so a page holds at most its budget and one
        // block more in memory.
        let rows = store.block_ids_after(start, SCAN)?;
        let scanned_all = rows.len() < SCAN;
        let mut federates = Federates::new(store);
        let mut page = Page {
            entries: Vec::new(),
            last: ask.after.clone(),
            more: false,
        };
        let mut size = 0;
        for (_, cid, channel_id) in rows {
            if federates.check(channel_id.as_deref())?
                && let Some(block) = store.get_block(&cid)?
            {
                let len = block.bundle_bytes.len() + block.sender_sig.len();
                let full = page.entries.len() == MAX_ENTRIES
                    || (!page.entries.is_empty() && size + len > PAGE_BUDGET);
                if full {
                    page.more = true;
                    return Ok(page);
                }
                size += len;
                page.entries.push(Entry {
                    bundle: block.bundle_bytes,
                    sig: block.sender_sig,
                });
            }
            page.last = cid;
        }
        page.more = !scanned_all;
        Ok(page)
    }
}

/// Whether blocks federate, as the live subscription decides it, with each
/// channel looked up once per page.
struct Federates<'a> {
    store: &'a SqliteStore,
    channels: HashMap<String, bool>,
}

impl<'a> Federates<'a> {
    fn new(store: &'a SqliteStore) -> Self {
        Federates {
            store,
            channels: HashMap::new(),
        }
    }

    /// A block federates only in a channel whose policy federates: the live
    /// path sends nothing with no channel policy.
    fn check(&mut self, channel_id: Option<&str>) -> anyhow::Result<bool> {
        let Some(id) = channel_id else {
            return Ok(false);
        };
        if let Some(known) = self.channels.get(id) {
            return Ok(*known);
        }
        let federates = self
            .store
            .get_channel_by_id_including_archived(id)?
            .is_some_and(|chan| DeliveryPolicy::for_channel(&chan, vec![]).federates);
        self.channels.insert(id.to_string(), federates);
        Ok(federates)
    }
}

// ---- The dialing side: asking -----------------------------------------------

/// One connection's catch-up from the peer it dialed: the request it last
/// made, and what it took in the current minute against its quota for the
/// peer.
pub(crate) struct CatchingUp {
    asked: Ask,
    start: Instant,
    blocks: u64,
    bytes: u64,
}

impl CatchingUp {
    /// Ask `peer` for what this server missed, once subscribed: after an
    /// unfinished catch-up's cursor if there is one, else after the newest
    /// block it holds from `peer`, stepping back [`OVERLAP`]. With neither,
    /// from the start.
    ///
    /// The subscription is made first, so the live push carries everything
    /// the peer takes from then on: once a catch-up reaches the end, nothing
    /// before the newest block is missing, and the cursor is dropped. Until
    /// then it is kept, since the live push lands blocks past the gap the
    /// catch-up is still filling.
    pub(crate) fn start(
        state: &AppState,
        peer: &FederationPeer,
        out: &PeerSender,
    ) -> anyhow::Result<Self> {
        let store = &state.ingest_ctx.store;
        let after = match store.catch_up_cursor(&peer.url)? {
            Some(after) => after,
            None => store.newest_block_from(&peer.url)?.unwrap_or_default(),
        };
        store.set_catch_up_cursor(&peer.url, &after)?;
        let asked = Ask {
            after,
            overlap: OVERLAP,
        };
        out.send(CATCH_UP_FRAME, asked.encode())
            .map_err(|e| anyhow::anyhow!("federation-catch-up not sent: {e}"))?;
        Ok(CatchingUp {
            asked,
            start: Instant::now(),
            blocks: 0,
            bytes: 0,
        })
    }

    /// Count one block of `bytes` if this minute's quota has room for it,
    /// or say how long until it does. The first block of a minute is always
    /// taken, so one block past `bytes_per_min` cannot stop a catch-up.
    fn take(&mut self, quota: PeerQuotaConfig, bytes: u64) -> Result<(), Duration> {
        if self.start.elapsed() >= Duration::from_secs(60) {
            (self.start, self.blocks, self.bytes) = (Instant::now(), 0, 0);
        }
        let past = self.blocks + 1 > quota.blocks_per_min
            || self.bytes.saturating_add(bytes) > quota.bytes_per_min;
        if past && self.blocks > 0 {
            return Err(Duration::from_secs(60).saturating_sub(self.start.elapsed()));
        }
        self.blocks += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        Ok(())
    }

    /// Send `ask` to the peer after `wait`.
    fn ask(&mut self, out: &PeerSender, ask: Ask, wait: Duration) {
        self.asked = ask.clone();
        let out = out.clone();
        tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            if let Err(e) = out.send(CATCH_UP_FRAME, ask.encode()) {
                tracing::info!("federation-catch-up not sent: {e}");
            }
        });
    }
}

/// The dialer's quota for `peer`: its own `quota`, or the default.
fn quota_for(federation: &FederationSection, peer: &FederationPeer) -> PeerQuotaConfig {
    peer.quota.unwrap_or(federation.default_peer_quota)
}

/// Handle a catch-up frame on a connection this server dialed, or `None` for a
/// frame of another kind: land a page's blocks as the live path lands them,
/// then ask for the next page, within the quota.
pub(crate) async fn on_dialer_frame(
    state: &Arc<AppState>,
    peer: &FederationPeer,
    out: &PeerSender,
    catching: &mut CatchingUp,
    kind: &str,
    body: &[u8],
) -> Option<Result<(), CloseReason>> {
    match kind {
        BLOCKS_FRAME => Some(land(state, peer, out, catching, body).await),
        LATER_FRAME => Some(match Later::decode(body) {
            Some(later) => {
                let wait = Duration::from_millis(later.retry_after_ms).min(MAX_RETRY_AFTER);
                tracing::info!(peer_url = %peer.url, "the peer limits catch-up; asking again in {wait:?}");
                catching.ask(out, later.ask, wait);
                Ok(())
            }
            None => Err(violation("a malformed federation-later")),
        }),
        _ => None,
    }
}

async fn land(
    state: &Arc<AppState>,
    peer: &FederationPeer,
    out: &PeerSender,
    catching: &mut CatchingUp,
    body: &[u8],
) -> Result<(), CloseReason> {
    let page = Page::decode(body).ok_or_else(|| violation("malformed federation-blocks"))?;
    if page.entries.len() > MAX_ENTRIES {
        return Err(violation("federation-blocks past the most a page carries"));
    }
    let store = &state.ingest_ctx.store;
    let quota = quota_for(&state.config.federation, peer);
    let b64 = base64::engine::general_purpose::STANDARD;
    // Where to resume if the quota stops this page part way.
    let mut resume = catching.asked.clone();
    for entry in &page.entries {
        let cid = crate::v0_0_2_federation::peer_block_cid(&entry.bundle).ok();
        // Held already (the overlap, or the live push): skipped before any
        // check runs on it, and not counted.
        let held = cid
            .as_deref()
            .is_some_and(|cid| matches!(store.get_block(cid), Ok(Some(_))));
        if !held {
            if let Err(wait) = catching.take(quota, entry.bundle.len() as u64) {
                tracing::info!(peer_url = %peer.url, "catch-up past this minute's quota; resuming in {wait:?}");
                save(store, peer, Some(&resume.after));
                catching.ask(out, resume, wait);
                return Ok(());
            }
            if let Err(e) = crate::v0_0_2_federation::ingest_peer_block(
                state,
                peer,
                &b64.encode(&entry.bundle),
                Some(&b64.encode(&entry.sig)),
                "catch-up",
            )
            .await
            {
                tracing::warn!(peer_url = %peer.url, "a caught-up block did not land: {e:#}");
            }
        }
        if let Some(cid) = cid {
            resume = Ask {
                after: cid,
                overlap: 0,
            };
        }
    }
    if page.more {
        save(store, peer, Some(&page.last));
        let next = Ask {
            after: page.last,
            overlap: 0,
        };
        catching.ask(out, next, Duration::ZERO);
    } else {
        save(store, peer, None);
        tracing::debug!(peer_url = %peer.url, "caught up");
    }
    Ok(())
}

/// Keep how far the catch-up from `peer` got, or drop it at the end.
fn save(store: &SqliteStore, peer: &FederationPeer, after: Option<&str>) {
    let saved = match after {
        Some(after) => store.set_catch_up_cursor(&peer.url, after),
        None => store.clear_catch_up_cursor(&peer.url),
    };
    if let Err(e) = saved {
        tracing::warn!(peer_url = %peer.url, "catch-up cursor not saved: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_config::v0_0_2_server::RateLimit;

    fn page_of(entries: Vec<Entry>) -> Page {
        Page {
            entries,
            last: "a block".to_string(),
            more: true,
        }
    }

    #[test]
    fn frames_round_trip_and_hold_their_shape() {
        let ask = Ask {
            after: "a block".to_string(),
            overlap: 7,
        };
        assert_eq!(Ask::decode(&ask.encode()), Some(ask.clone()));
        let page = page_of(vec![Entry {
            bundle: vec![1, 2],
            sig: vec![3],
        }]);
        assert_eq!(Page::decode(&page.encode()), Some(page));
        let later = Later {
            ask,
            retry_after_ms: 1500,
        };
        assert_eq!(Later::decode(&later.encode()), Some(later));

        // A field more, or one missing, or of another type, is no frame.
        let extra = dcbor::encode(&Value::text_map([
            ("after", Value::text("")),
            ("overlap", Value::Unsigned(0)),
            ("since_hlc", Value::Unsigned(0)),
        ]))
        .unwrap();
        assert_eq!(Ask::decode(&extra), None);
        let missing = dcbor::encode(&Value::text_map([("after", Value::text(""))])).unwrap();
        assert_eq!(Ask::decode(&missing), None);
        let typed = dcbor::encode(&Value::text_map([
            ("after", Value::Unsigned(1)),
            ("overlap", Value::Unsigned(0)),
        ]))
        .unwrap();
        assert_eq!(Ask::decode(&typed), None);
    }

    fn envelope_len(page: Page) -> usize {
        let envelope = jig_pipeline::envelope::Envelope::new(jig_pipeline::envelope::Frame::Peer {
            kind: BLOCKS_FRAME.to_string(),
            body: page.encode(),
        });
        serde_json::to_vec(&envelope).unwrap().len()
    }

    #[test]
    fn the_largest_pages_fit_the_peer_connection() {
        let max_envelope = jig_core::bundle::MAX_ENVELOPE_BYTES;
        let entry = |bundle: usize| Entry {
            bundle: vec![0xff; bundle],
            sig: vec![0xff; 64],
        };
        let one = envelope_len(page_of(vec![entry(jig_core::bundle::MAX_BUNDLE_BYTES)]));
        assert!(
            one <= max_envelope,
            "one largest block: {one} > {max_envelope}"
        );
        let per = PAGE_BUDGET / MAX_ENTRIES - 64;
        let many = envelope_len(page_of((0..MAX_ENTRIES).map(|_| entry(per)).collect()));
        assert!(many <= max_envelope, "a full page: {many} > {max_envelope}");
    }

    fn catching() -> CatchingUp {
        CatchingUp {
            asked: Ask {
                after: String::new(),
                overlap: OVERLAP,
            },
            start: Instant::now(),
            blocks: 0,
            bytes: 0,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_quota_is_a_minute_window() {
        let quota = PeerQuotaConfig {
            blocks_per_min: 2,
            bytes_per_min: 100,
        };
        let mut c = catching();
        assert_eq!(c.take(quota, 10), Ok(()));
        assert_eq!(c.take(quota, 10), Ok(()));
        tokio::time::advance(Duration::from_secs(20)).await;
        assert_eq!(c.take(quota, 10), Err(Duration::from_secs(40)));
        tokio::time::advance(Duration::from_secs(40)).await;
        assert_eq!(c.take(quota, 10), Ok(()), "a new minute");

        // Bytes count as well; the first block of a minute is always taken,
        // whatever its size, so no one block stops a catch-up for good.
        let mut c = catching();
        assert_eq!(c.take(quota, 500), Ok(()));
        assert!(c.take(quota, 1).is_err());
    }

    fn replay_for(peer: &Did, limit: RateLimit) -> Replay {
        let state = AppState::for_test().unwrap();
        let mut federation = state.config.federation.clone();
        federation.records_from = limit;
        federation.peers = vec![FederationPeer {
            url: "ws://127.0.0.1:1".to_string(),
            expected_did: peer.to_did_jig_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        }];
        Replay::new(state.ingest_ctx.clone(), Arc::new(federation))
    }

    fn a_did() -> Did {
        let key = ed25519_dalek::SigningKey::from_bytes(&rand::random());
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes())
    }

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

    #[tokio::test(start_paused = true)]
    async fn a_peer_asking_past_the_limit_is_told_when_to_ask_again() {
        let peer = a_did();
        let replay = replay_for(
            &peer,
            RateLimit {
                burst: 2,
                per_min: 6,
            },
        );
        let (out, mut rx) = PeerSender::new(peer.clone());
        let ask = Ask {
            after: String::new(),
            overlap: 0,
        };
        for _ in 0..3 {
            replay
                .on_peer_frame(&peer, CATCH_UP_FRAME, &ask.encode(), &out)
                .unwrap()
                .unwrap();
        }
        let frames = sent(&mut rx);
        let kinds: Vec<&str> = frames.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kinds, [BLOCKS_FRAME, BLOCKS_FRAME, LATER_FRAME]);
        let later = Later::decode(&frames[2].1).unwrap();
        assert_eq!(later.ask, ask, "the request it refused, to make again");
        assert_eq!(later.retry_after_ms, 10_000);
    }

    #[tokio::test]
    async fn only_a_configured_peer_is_answered_and_a_bad_frame_closes() {
        let peer = a_did();
        let replay = replay_for(
            &peer,
            RateLimit {
                burst: 10,
                per_min: 60,
            },
        );
        let stranger = a_did();
        let (out, mut rx) = PeerSender::new(stranger.clone());
        let ask = Ask {
            after: String::new(),
            overlap: 0,
        }
        .encode();
        replay
            .on_peer_frame(&stranger, CATCH_UP_FRAME, &ask, &out)
            .unwrap()
            .unwrap();
        assert!(sent(&mut rx).is_empty());

        let (out, _rx) = PeerSender::new(peer.clone());
        assert!(
            replay
                .on_peer_frame(&peer, CATCH_UP_FRAME, b"not cbor", &out)
                .unwrap()
                .is_err()
        );
        assert!(
            replay
                .on_peer_frame(&peer, "another-frame", &ask, &out)
                .is_none()
        );
    }
}
