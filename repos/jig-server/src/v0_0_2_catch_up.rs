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

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use jig_config::v0_0_2_server::{FederationPeer, FederationSection, PeerQuotaConfig};
use jig_core::dcbor::{self, Value};
use jig_pipeline::persist::SqliteStore;
use tokio::time::Instant;

use crate::v0_0_2::AppState;
use crate::v0_0_2_peer::{CloseReason, PeerSender};

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
/// How long the dialer waits to ask again after its own store failed to
/// land a block.
pub const STORE_RETRY: Duration = Duration::from_secs(5);

/// The most block and signature bytes a page packs, unless its first block
/// fills it alone: one largest bundle. Base64 on the wire, a page then fits
/// `jig_core::bundle::MAX_ENVELOPE_BYTES`.
#[cfg(test)]
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

    #[cfg(test)]
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
    #[cfg(test)]
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
    #[cfg(test)]
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

/// One connection's catch-up from the peer it dialed: the request it last
/// made, and what it took in the current minute against its quota for the
/// peer.
pub(crate) struct CatchingUp {
    asked: Ask,
    start: Instant,
    blocks: u64,
    bytes: u64,
    /// Whether the live push has brought a block on this connection. Those
    /// come after everything a catch-up replays, in the peer's order, so a
    /// page no longer moves the last-seen block once one has.
    live: bool,
    /// Whether a live block failed here (the store, or the author's rate):
    /// the last-seen block then stays before it until this connection ends,
    /// so the reconnect's catch-up asks for it again.
    held: bool,
}

impl CatchingUp {
    /// Ask `peer` for what this server missed, once subscribed: after an
    /// unfinished catch-up's cursor if there is one, else after the last
    /// block from `peer` it dealt with (landed or refused), else after the
    /// newest block it holds from `peer`, stepping back [`OVERLAP`]. With
    /// none, from the start. A refused block is never held, so starting from
    /// the newest held one would ask for every refusal again (#357).
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
        let after = resume_after(store, peer)?;
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
            live: false,
            held: false,
        })
    }

    /// A catch-up asked from the start, with nothing counted or seen yet.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        CatchingUp {
            asked: Ask {
                after: String::new(),
                overlap: OVERLAP,
            },
            start: Instant::now(),
            blocks: 0,
            bytes: 0,
            live: false,
            held: false,
        }
    }

    /// The live push brought a block, which `ingest_peer_block` dealt with:
    /// remember it as the last seen from `peer`, past anything a catch-up
    /// page could still bring.
    pub(crate) fn saw_live(&mut self, store: &SqliteStore, peer: &FederationPeer, cid: &str) {
        self.live = true;
        if !self.held {
            seen(store, peer, cid);
        }
    }

    /// A live block failed here: keep the last-seen block where it is for
    /// the rest of this connection (see [`Self::held`]). With none recorded
    /// yet (a server upgrading, whose first catch-up dealt with nothing),
    /// record where a reconnect would ask from now: otherwise the blocks
    /// landing after this one would move the newest held block past it,
    /// and a reconnect would ask from there. An error if that could not be
    /// recorded: the caller ends the connection, so nothing lands after the
    /// failed block before the reconnect asks for it again.
    pub(crate) fn hold_seen(
        &mut self,
        store: &SqliteStore,
        peer: &FederationPeer,
    ) -> anyhow::Result<()> {
        let first = !self.held;
        self.live = true;
        self.held = true;
        if first && store.catch_up_seen(&peer.url)?.is_none() {
            store.set_catch_up_seen(&peer.url, &resume_after(store, peer)?)?;
        }
        Ok(())
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
    // The last entry this page dealt with: landed, held, or refused. Not one
    // this server's store failed on, which is asked for again.
    let mut dealt: Option<String> = None;
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
                page_seen(store, peer, catching, dealt.as_deref());
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
                // This server's store failed (a busy database, say), not the
                // block: keep the place before it and ask again, or the block
                // is skipped for good. A block the peer got wrong is skipped,
                // or it would stall the catch-up.
                if failed_here(&e) {
                    tracing::warn!(peer_url = %peer.url, "a caught-up block did not land; asking again in {STORE_RETRY:?}: {e:#}");
                    page_seen(store, peer, catching, dealt.as_deref());
                    save(store, peer, Some(&resume.after));
                    catching.ask(out, resume, STORE_RETRY);
                    return Ok(());
                }
                tracing::warn!(peer_url = %peer.url, "a caught-up block did not land: {e:#}");
            }
        }
        if let Some(cid) = cid {
            dealt = Some(cid.clone());
            resume = Ask {
                after: cid,
                overlap: 0,
            };
        }
    }
    page_seen(store, peer, catching, dealt.as_deref());
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

/// Whether `ingest_peer_block` failed here rather than on the block, so that
/// asking again can land it: a store failure (every one it returns is a
/// [`PersistError`]), or an author over this server's rate
/// ([`RetryLater`](crate::v0_0_2_federation::RetryLater)).
///
/// [`PersistError`]: jig_pipeline::persist::PersistError
pub(crate) fn failed_here(e: &anyhow::Error) -> bool {
    e.downcast_ref::<jig_pipeline::persist::PersistError>()
        .is_some()
        || e.downcast_ref::<crate::v0_0_2_federation::RetryLater>()
            .is_some()
}

/// Where the next catch-up from `peer` asks from (before [`OVERLAP`]): an
/// unfinished catch-up's cursor, else the last block from `peer` this server
/// dealt with, else the newest it holds from `peer`, else the start.
pub(crate) fn resume_after(store: &SqliteStore, peer: &FederationPeer) -> anyhow::Result<String> {
    Ok(match store.catch_up_cursor(&peer.url)? {
        Some(after) => after,
        None => match store.catch_up_seen(&peer.url)? {
            Some(seen) => seen,
            None => store.newest_block_from(&peer.url)?.unwrap_or_default(),
        },
    })
}

/// Record the last entry a page dealt with as the last block seen from
/// `peer`, unless the live push has brought one since this connection began:
/// it comes after the page in the peer's order.
fn page_seen(
    store: &SqliteStore,
    peer: &FederationPeer,
    catching: &CatchingUp,
    dealt: Option<&str>,
) {
    if let Some(cid) = dealt
        && !catching.live
    {
        seen(store, peer, cid);
    }
}

fn seen(store: &SqliteStore, peer: &FederationPeer, cid: &str) {
    if let Err(e) = store.set_catch_up_seen(&peer.url, cid) {
        tracing::warn!(peer_url = %peer.url, "last block seen from the peer not saved: {e:#}");
    }
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
        CatchingUp::for_test()
    }

    /// A store failure while landing a caught-up block is asked again; a
    /// block the peer got wrong is not.
    #[test]
    fn only_a_store_failure_is_asked_again() {
        use jig_pipeline::persist::PersistError;
        let corrupt = || PersistError::Corrupt("x".into());
        // As `ingest_peer_block` returns them: by `?`, and from ingest.
        let by_question_mark = || -> anyhow::Result<()> { Err(corrupt())? };
        assert!(failed_here(&by_question_mark().unwrap_err()));
        assert!(failed_here(&anyhow::Error::from(corrupt())));

        let base64 = || -> anyhow::Result<Vec<u8>> {
            Ok(base64::engine::general_purpose::STANDARD.decode("!")?)
        };
        assert!(!failed_here(&base64().unwrap_err()));
        let json = || -> anyhow::Result<Vec<u8>> { Ok(serde_json::from_slice(b"{")?) };
        assert!(!failed_here(&json().unwrap_err()));

        // An author over this server's rate: waiting changes the answer.
        let later = anyhow::Error::from(crate::v0_0_2_federation::RetryLater("rate".into()));
        assert!(failed_here(&later));
    }

    /// A live block that failed here holds the last block seen where it was,
    /// for the rest of the connection: later live blocks do not move it past
    /// the failure, so a reconnect asks for it again.
    #[test]
    fn a_live_failure_holds_the_last_block_seen() {
        let store = SqliteStore::open_in_memory().unwrap();
        let peer = FederationPeer {
            url: "wss://held-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        };
        let mut c = catching();
        c.saw_live(&store, &peer, "bafy-before");
        c.hold_seen(&store, &peer).unwrap();
        c.saw_live(&store, &peer, "bafy-after");
        assert_eq!(
            store.catch_up_seen(&peer.url).unwrap().as_deref(),
            Some("bafy-before")
        );
        assert_eq!(resume_after(&store, &peer).unwrap(), "bafy-before");
    }

    /// With no last-seen block yet (an upgraded server whose first catch-up
    /// dealt with nothing), a live failure records where a reconnect asks
    /// from: the blocks landing after it do not move that past it.
    #[test]
    fn a_live_failure_with_nothing_seen_yet_keeps_the_resume_point() {
        let store = SqliteStore::open_in_memory().unwrap();
        let peer = FederationPeer {
            url: "wss://unseen-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        };
        let mut c = catching();
        c.hold_seen(&store, &peer).unwrap();
        assert_eq!(store.catch_up_seen(&peer.url).unwrap().as_deref(), Some(""));
        c.saw_live(&store, &peer, "bafy-after");
        assert_eq!(resume_after(&store, &peer).unwrap(), "", "from the start");
    }

    /// A hold whose resume point cannot be recorded is an error, which ends
    /// the connection before anything lands after the failed block.
    #[test]
    fn a_hold_that_cannot_be_recorded_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = SqliteStore::open(&path).unwrap();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TABLE catch_up_seen;")
            .unwrap();
        let peer = FederationPeer {
            url: "wss://broken-peer".to_string(),
            expected_did: "did:jig:zPeer".to_string(),
            alias: None,
            publish: false,
            quota: None,
            offers: Default::default(),
        };
        let mut c = catching();
        assert!(c.hold_seen(&store, &peer).is_err());
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
}
