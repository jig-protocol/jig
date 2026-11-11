//! Following a channel live, and catching up when this reader falls behind.
//!
//! The client ends a subscription whose reader is more than
//! [`jig_client::connection::SUBSCRIPTION_QUEUE`] deliveries behind
//! ([`jig_client::BlockStream::lagged`]). A burst on a busy channel, or a slow
//! device, does that. [`Follower`] then subscribes again and fills the gap from
//! history, so `jig tail` and `jig chat` carry on with nothing missed and
//! nothing shown twice. On an encrypted channel the missed blocks replay
//! through the MLS session in epoch order ([`Reader::read_missed`]), so no
//! commit is skipped.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::sync::Arc;

use anyhow::{Context, Result};
use jig_client::open::open;
use jig_client::{Client, DeliveredBlock};

use crate::cmd::blocks_decode::{DecodedBlock, SYSTEM};
use crate::cmd::display::{connection_lost, fell_behind};
use crate::cmd::history;
use crate::cmd::reader::Reader;
use crate::cmd::secure::{MAX_CATCH_UP_PAGES, MAX_HISTORY_PAGE};

/// How many delivery CIDs a follower remembers. A catch-up stops at the first
/// history page holding a block already read, and only that page's blocks are
/// checked against what was read, so a few pages' worth is ample.
const SEEN_WINDOW: usize = 4096;

/// Anything that yields delivered blocks until it ends.
///
/// Exists so the "stream ended" branch — the one that used to return
/// `Ok(())` and exit 0 on a dead connection — is unit-testable without a
/// live socket. `jig_client::BlockStream` is the only production impl.
pub trait BlockSource {
    fn next_block(&mut self) -> impl Future<Output = Option<DeliveredBlock>> + Send;

    /// Whether it ended because its reader fell behind, not on a disconnect.
    fn lagged(&self) -> bool {
        false
    }
}

impl BlockSource for jig_client::BlockStream {
    fn next_block(&mut self) -> impl Future<Output = Option<DeliveredBlock>> + Send {
        self.next()
    }

    fn lagged(&self) -> bool {
        jig_client::BlockStream::lagged(self)
    }
}

/// Where a follower subscribes and reads history from.
pub trait Feed {
    type Source: BlockSource;

    /// A fresh subscription to the channel.
    fn subscribe(&self) -> impl Future<Output = Result<Self::Source>> + Send;

    /// One page of history, oldest first: the newest `limit` blocks, or those
    /// just older than the block whose CID is `before`.
    fn page(
        &self,
        limit: usize,
        before: Option<&str>,
    ) -> impl Future<Output = Result<Vec<DeliveredBlock>>> + Send;

    /// Hold blocks fetched from history to what this device pinned, before
    /// any of them is shown.
    fn check(&self, _blocks: &[DeliveredBlock]) -> impl Future<Output = Result<()>> + Send {
        async { Ok(()) }
    }
}

/// The live connection, and the server's history routes as its identity.
pub struct Live {
    pub client: Arc<Client>,
    pub server_url: String,
    pub slug: String,
}

impl Feed for Live {
    type Source = jig_client::BlockStream;

    async fn subscribe(&self) -> Result<Self::Source> {
        self.client
            .subscribe_channel(&self.slug)
            .await
            .with_context(|| format!("subscribing to {}", self.slug))
    }

    fn page(
        &self,
        limit: usize,
        before: Option<&str>,
    ) -> impl Future<Output = Result<Vec<DeliveredBlock>>> + Send {
        history::fetch_history_page(
            self.client.identity(),
            &self.server_url,
            &self.slug,
            limit,
            before,
        )
    }

    fn check(&self, blocks: &[DeliveredBlock]) -> impl Future<Output = Result<()>> + Send {
        crate::cmd::trust::check_history(
            self.client.identity(),
            &self.server_url,
            &self.slug,
            blocks,
        )
    }
}

/// Delivery CIDs already read, the newest [`SEEN_WINDOW`] of them.
#[derive(Default)]
struct Seen {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl Seen {
    /// Whether `cid` is new.
    fn insert(&mut self, cid: &str) -> bool {
        if !self.set.insert(cid.to_string()) {
            return false;
        }
        self.order.push_back(cid.to_string());
        if self.order.len() > SEEN_WINDOW
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        true
    }

    fn contains(&self, cid: &str) -> bool {
        self.set.contains(cid)
    }

    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// Something to show.
pub enum Event {
    Line(DecodedBlock),
    /// A delivered block that could not be read.
    Unreadable(String),
    /// This reader fell behind and caught up: `blocks` came from history.
    CaughtUp {
        blocks: usize,
    },
}

/// One channel, followed: its live stream, refilled from history whenever
/// this reader falls behind.
pub struct Follower<F: Feed> {
    feed: F,
    source: F::Source,
    reader: Arc<Reader>,
    channel: String,
    seen: Seen,
    ready: VecDeque<Event>,
}

impl<F: Feed> Follower<F> {
    /// Follow `source`, skipping the blocks in `read` (the backlog already
    /// shown, by delivery CID).
    pub fn new(
        feed: F,
        source: F::Source,
        reader: Arc<Reader>,
        channel: &str,
        read: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut seen = Seen::default();
        for cid in read {
            seen.insert(&cid);
        }
        Self {
            feed,
            source,
            reader,
            channel: channel.to_string(),
            seen,
            ready: VecDeque::new(),
        }
    }

    /// The next thing to show. Only ever ends in an error: the connection
    /// closed, or this reader fell behind and could not catch up.
    pub async fn next(&mut self) -> Result<Event> {
        loop {
            if let Some(event) = self.ready.pop_front() {
                return Ok(event);
            }
            let Some(d) = self.source.next_block().await else {
                if !self.source.lagged() {
                    return Err(connection_lost(&self.channel));
                }
                let channel = self.channel.clone();
                self.catch_up().await.context(fell_behind(&channel))?;
                continue;
            };
            if !self.seen.insert(&d.delivery_cid) {
                continue;
            }
            match self.reader.read(&d) {
                Ok(read) => {
                    if let Some(did) = read.tidy {
                        self.reader.tidy(vec![did]);
                    }
                    if let Some(line) = read.line {
                        return Ok(Event::Line(line));
                    }
                }
                Err(e) => return Ok(Event::Unreadable(format!("{e:#}"))),
            }
        }
    }

    /// Subscribe again, then queue what the old stream dropped.
    async fn catch_up(&mut self) -> Result<()> {
        // Subscribe first: whatever lands from here on queues on the new
        // stream, and history holds everything before it. Blocks in both are
        // read once.
        self.source = self.feed.subscribe().await?;
        let (fetched, complete) = self.history().await?;
        // Checked as fetched: the pinned chain runs through the blocks
        // already read too, and a page with those cut out would look like
        // one with records missing.
        self.feed.check(&fetched).await?;
        let missed = self.missed(fetched);
        for d in &missed {
            self.seen.insert(&d.delivery_cid);
        }
        self.ready.push_back(Event::CaughtUp {
            blocks: missed.len(),
        });
        if !complete {
            self.ready.push_back(Event::Line(gap_notice(&self.channel)));
        }
        for read in self.reader.read_missed(&missed) {
            self.ready.push_back(match read {
                Ok(line) => Event::Line(line),
                Err(e) => Event::Unreadable(format!("{e:#}")),
            });
        }
        Ok(())
    }

    /// History back to what this reader has read, oldest first, and whether
    /// it reached that far.
    ///
    /// Pages back from the newest until a page holds a block already read.
    async fn history(&self) -> Result<(Vec<DeliveredBlock>, bool)> {
        let mut blocks = self.feed.page(MAX_HISTORY_PAGE, None).await?;
        if self.seen.is_empty() {
            // Nothing read yet to stop at: the newest page is the catch-up.
            return Ok((blocks, true));
        }
        let mut pages = 1;
        loop {
            if blocks.iter().any(|d| self.seen.contains(&d.delivery_cid)) {
                return Ok((blocks, true));
            }
            if pages == MAX_CATCH_UP_PAGES {
                return Ok((blocks, false));
            }
            let Some(oldest) = blocks.first().and_then(|d| open(d).ok()) else {
                // Nothing older, or nothing to page back from.
                return Ok((blocks, true));
            };
            let mut older = self.feed.page(MAX_HISTORY_PAGE, Some(&oldest.cid)).await?;
            if older.is_empty() {
                return Ok((blocks, true));
            }
            older.append(&mut blocks);
            blocks = older;
            pages += 1;
        }
    }

    /// What the stream dropped, out of history fetched by [`Self::history`].
    ///
    /// Blocks older than the oldest one already read predate what this
    /// reader was shown, and are left out. Unread blocks among and after
    /// those read are the ones the stream dropped: history is in
    /// author-clock order, so a dropped block can sit between two that were
    /// read.
    fn missed(&self, mut fetched: Vec<DeliveredBlock>) -> Vec<DeliveredBlock> {
        if let Some(first) = fetched
            .iter()
            .position(|d| self.seen.contains(&d.delivery_cid))
        {
            fetched.drain(..first);
        }
        fetched.retain(|d| !self.seen.contains(&d.delivery_cid));
        fetched
    }
}

/// Shown where a catch-up could not reach back to what was last read.
fn gap_notice(channel: &str) -> DecodedBlock {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    DecodedBlock {
        sender: SYSTEM.to_string(),
        body: format!(
            "fell more than {} blocks behind {channel}; older messages were skipped",
            MAX_CATCH_UP_PAGES * MAX_HISTORY_PAGE
        ),
        ts,
        parity_warning: false,
        parity_hash_count: 0,
        kind: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use base64::Engine as _;
    use jig_client::blocks::build_text_render;
    use jig_core::HlcTimestamp;

    use super::*;

    fn test_identity() -> jig_client::Identity {
        jig_client::Identity::generate_for_tests(&tempfile::tempdir().unwrap().keep())
    }

    /// A text block as a server delivers it.
    fn text(id: &jig_client::Identity, body: &str, wall_ms: u64) -> DeliveredBlock {
        let hlc = HlcTimestamp {
            wall_ms,
            logical: 0,
            server_did: id.did().clone(),
        };
        let block = build_text_render(id, "#busy", body, hlc);
        let cid = block.cid().to_string();
        DeliveredBlock {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: None,
            receipts: vec![],
            delivery_cid: format!("delivery:{cid}"),
            ingest: None,
        }
    }

    /// A channel's whole history, numbered from `m0`.
    fn channel(n: usize) -> Vec<DeliveredBlock> {
        let id = test_identity();
        (0..n)
            .map(|i| text(&id, &format!("m{i}"), 1_747_680_000_000 + i as u64))
            .collect()
    }

    /// A stream that yields its blocks, then ends, lagged or not.
    struct Stream {
        items: VecDeque<DeliveredBlock>,
        lagged: bool,
    }

    impl BlockSource for Stream {
        fn next_block(&mut self) -> impl Future<Output = Option<DeliveredBlock>> + Send {
            let next = self.items.pop_front();
            async move { next }
        }

        fn lagged(&self) -> bool {
            self.lagged
        }
    }

    /// A server: its history, and the streams each new subscription gets.
    struct Server {
        history: Vec<DeliveredBlock>,
        subscriptions: Mutex<VecDeque<Stream>>,
        pages: Mutex<usize>,
    }

    impl Server {
        fn new(history: Vec<DeliveredBlock>, subscriptions: Vec<Stream>) -> Self {
            Self {
                history,
                subscriptions: Mutex::new(subscriptions.into()),
                pages: Mutex::new(0),
            }
        }
    }

    impl Feed for &Server {
        type Source = Stream;

        fn subscribe(&self) -> impl Future<Output = Result<Stream>> + Send {
            let next = self.subscriptions.lock().unwrap().pop_front();
            async move { next.context("no more subscriptions") }
        }

        fn page(
            &self,
            limit: usize,
            before: Option<&str>,
        ) -> impl Future<Output = Result<Vec<DeliveredBlock>>> + Send {
            *self.pages.lock().unwrap() += 1;
            let end = match before {
                None => self.history.len(),
                Some(cid) => self
                    .history
                    .iter()
                    .position(|d| open(d).unwrap().cid == cid)
                    .expect("paged from a block in history"),
            };
            let page = self.history[end.saturating_sub(limit)..end].to_vec();
            async move { Ok(page) }
        }
    }

    fn live(blocks: &[DeliveredBlock], lagged: bool) -> Stream {
        Stream {
            items: blocks.iter().cloned().collect(),
            lagged,
        }
    }

    fn cids(blocks: &[DeliveredBlock]) -> Vec<String> {
        blocks.iter().map(|d| d.delivery_cid.clone()).collect()
    }

    /// Everything the follower shows until it ends, how it ended, and how
    /// many blocks each catch-up took from history.
    async fn shown(mut f: Follower<&Server>) -> (Vec<String>, String, Vec<usize>) {
        let mut bodies = Vec::new();
        let mut caught_up = Vec::new();
        loop {
            match f.next().await {
                // Unsigned test blocks carry markers after the text.
                Ok(Event::Line(d)) => {
                    bodies.push(d.body.split(' ').next().unwrap_or("").to_string())
                }
                Ok(Event::Unreadable(e)) => bodies.push(format!("<unreadable: {e}>")),
                Ok(Event::CaughtUp { blocks }) => caught_up.push(blocks),
                Err(e) => return (bodies, format!("{e:#}"), caught_up),
            }
        }
    }

    fn bodies(range: std::ops::Range<usize>) -> Vec<String> {
        range.map(|i| format!("m{i}")).collect()
    }

    #[tokio::test]
    async fn a_stream_that_ends_without_lagging_is_a_lost_connection() {
        let history = channel(3);
        let server = Server::new(history.clone(), vec![]);
        let f = Follower::new(
            &server,
            live(&history[1..], false),
            Arc::new(Reader::plain("#busy")),
            "#busy",
            cids(&history[..1]),
        );
        let (shown, ended, caught_up) = shown(f).await;
        assert_eq!(shown, bodies(1..3));
        assert!(ended.contains("connection lost"), "{ended}");
        assert!(ended.contains("#busy"), "it names the channel: {ended}");
        assert_eq!(
            *server.pages.lock().unwrap(),
            0,
            "no catch-up without a lag"
        );
        assert!(caught_up.is_empty());
    }

    /// The backlog holds m0..m9; the stream overlaps it, delivers m10..m19,
    /// drops m20..m149 and ends lagged. The follower subscribes again (the
    /// new stream starts at m140, overlapping history) and shows m20..m159
    /// once each, in order.
    #[tokio::test]
    async fn a_lagged_stream_is_refilled_from_history_with_no_gap_and_no_repeat() {
        let history = channel(160);
        let server = Server::new(history.clone(), vec![live(&history[140..], false)]);
        let f = Follower::new(
            &server,
            live(&history[5..20], true),
            Arc::new(Reader::plain("#busy")),
            "#busy",
            cids(&history[..10]),
        );
        let (shown, ended, caught_up) = shown(f).await;
        assert_eq!(shown, bodies(10..160));
        // m20..m159: the new stream's copies of m140.. are then skipped.
        assert_eq!(caught_up, [140], "the dropped blocks came from history");
        assert!(ended.contains("connection lost"), "{ended}");
    }

    /// Lagging again while catching up is caught up the same way.
    #[tokio::test]
    async fn a_follower_that_lags_twice_catches_up_twice() {
        let history = channel(50);
        let server = Server::new(
            history.clone(),
            vec![live(&history[30..32], true), live(&history[45..], false)],
        );
        let f = Follower::new(
            &server,
            live(&history[..5], true),
            Arc::new(Reader::plain("#busy")),
            "#busy",
            [],
        );
        let (shown, _, caught_up) = shown(f).await;
        assert_eq!(shown, bodies(0..50));
        assert_eq!(caught_up, [45, 0]);
    }

    /// More than a page behind: the follower pages back until it reaches
    /// what it had read, and shows none of the history before that.
    #[tokio::test]
    async fn a_follower_far_behind_pages_back_to_what_it_read() {
        let n = 3 * MAX_HISTORY_PAGE;
        let history = channel(n);
        let server = Server::new(history.clone(), vec![live(&[], false)]);
        let f = Follower::new(
            &server,
            live(&history[90..100], true),
            Arc::new(Reader::plain("#busy")),
            "#busy",
            cids(&history[50..90]),
        );
        let (shown, _, caught_up) = shown(f).await;
        assert_eq!(shown, bodies(90..n));
        assert_eq!(caught_up, [n - 100]);
        assert_eq!(*server.pages.lock().unwrap(), 3);
    }

    /// A block the stream dropped can sit between two it delivered, since
    /// history is in author-clock order. It is still caught up.
    #[tokio::test]
    async fn a_dropped_block_between_two_read_ones_is_caught_up() {
        let history = channel(10);
        let mut delivered: Vec<_> = history[..6].to_vec();
        delivered.remove(3);
        let server = Server::new(history.clone(), vec![live(&[], false)]);
        let f = Follower::new(
            &server,
            live(&delivered, true),
            Arc::new(Reader::plain("#busy")),
            "#busy",
            [],
        );
        let (shown, _, caught_up) = shown(f).await;
        let mut expect = bodies(0..6);
        expect.remove(3);
        expect.extend(["m3".to_string()]);
        expect.extend(bodies(6..10));
        assert_eq!(shown, expect);
        assert_eq!(caught_up, [5]);
    }

    /// When the follower cannot subscribe again, it ends saying it fell
    /// behind, with the reason.
    #[tokio::test]
    async fn a_follower_that_cannot_resubscribe_says_it_fell_behind() {
        let history = channel(3);
        let server = Server::new(history.clone(), vec![]);
        let f = Follower::new(
            &server,
            live(&history, true),
            Arc::new(Reader::plain("#busy")),
            "#busy",
            [],
        );
        let (shown, ended, caught_up) = shown(f).await;
        assert_eq!(shown, bodies(0..3));
        assert!(caught_up.is_empty());
        assert!(ended.contains("fell behind #busy"), "{ended}");
        assert!(ended.contains("no more subscriptions"), "{ended}");
    }

    #[tokio::test]
    async fn an_undecodable_block_is_reported_and_following_goes_on() {
        let history = channel(2);
        let mut bad = history[0].clone();
        bad.bundle_b64 = "not_base64_!!!".into();
        let server = Server::new(history.clone(), vec![]);
        let f = Follower::new(
            &server,
            live(&[bad, history[1].clone()], false),
            Arc::new(Reader::plain("#busy")),
            "#busy",
            [],
        );
        let (shown, _, caught_up) = shown(f).await;
        assert_eq!(shown.len(), 2);
        assert!(caught_up.is_empty());
        assert!(shown[0].starts_with("<unreadable: "), "{shown:?}");
        assert_eq!(shown[1], "m1");
    }
}
