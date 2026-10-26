//! The owner's stream to the servers that follow its channels, and the
//! follower's side of it (JEP-0005 rules 12-14, 22a), over the peer
//! connection both servers proved their DIDs on ([`crate::v0_0_2_peer`]).
//!
//! The owner sends each block of a channel it shares, with its signed
//! `ingest` record, to every server holding an accepted share of the
//! channel, as the block lands: a [`RECORDS_FRAME`]. A follower asks for the
//! records from its head with a [`RECORDS_FROM_FRAME`]:
//! - after a gap;
//! - when a frame says more follow;
//! - every [`PULL_EVERY`], which is also how it catches up after a
//!   reconnect, and how it starts once it accepts a share.
//!
//! The owner answers only a peer holding an accepted share of the channel,
//! and only as often as `[federation.records_from]` allows: a token bucket
//! per peer and channel. A request past it is answered with a
//! [`RECORDS_LATER_FRAME`] naming when to ask again, never dropped, and the
//! follower asks nothing more for that channel until then.
//!
//! The follower lands each entry with [`ingest_sequenced`], one frame at a
//! time in the order frames came, with the connection's proven peer as the
//! sequencer: no frame names its own. A channel lands only under an accepted
//! share with that peer, and only if that peer sequences it, so a peer
//! cannot write into a channel another server owns.
//!
//! What a peer streams counts against its quota (its `quota`, or
//! `default_peer_quota`: what this server's manifest publishes, rule 16).
//! Entries past it are not landed; a later pull fetches them once the minute
//! turns.
//!
//! The frames are deterministic CBOR (`jig_core::dcbor`), with the block,
//! its signature and its record as byte strings, so a frame's base64 on the
//! wire is the only expansion.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jig_config::v0_0_2_server::{FederationSection, PeerQuotaConfig, RateLimit};
use jig_core::BlockBundle;
use jig_core::dcbor::{self, Value};
use jig_core::did::Did;
use jig_pipeline::contracts::{OfferState, Side};
use jig_pipeline::follow::{FollowError, Followed, ingest_sequenced};
use jig_pipeline::ingest::IngestContext;
use jig_pipeline::persist::{SqliteStore, StoredBlock};
use tokio::sync::mpsc;

use crate::v0_0_2_peer::{CloseReason, PeerRegistry, PeerSender};

/// The owner's blocks of one channel, each with its record, in `seq` order.
pub const RECORDS_FRAME: &str = "channel-records";
/// A follower's request for one channel's records from a `seq`.
pub const RECORDS_FROM_FRAME: &str = "records-from";

/// The owner's refusal of a `records-from` past its limit, with when to ask
/// again.
pub const RECORDS_LATER_FRAME: &str = "records-later";

/// The longest a follower waits on one [`RECORDS_LATER_FRAME`]: a longer
/// `retry_after_ms` is taken as this, so an owner cannot silence a follower
/// for good with one frame.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

/// The most entries one [`RECORDS_FRAME`] carries.
pub const MAX_ENTRIES: usize = 64;

/// How often a follower asks each channel it follows for the records past its
/// head.
pub const PULL_EVERY: Duration = Duration::from_secs(10);

/// The most block, signature and record bytes the owner packs into one
/// frame, beyond its first entry: one largest block. Base64 on the wire, a
/// frame then fits `jig_core::bundle::MAX_ENVELOPE_BYTES`.
const FRAME_BUDGET: usize = jig_core::bundle::MAX_BUNDLE_BYTES;

/// Frames waiting to be landed. A frame that finds the queue full is dropped,
/// and a later pull fetches what it carried.
const QUEUE: usize = 64;

/// One block of a [`RECORDS_FRAME`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The block's canonical bundle bytes, as the owner stores them.
    bundle: Vec<u8>,
    /// The author's signature over them.
    sig: Vec<u8>,
    /// The owner's `ingest` record for the block, in its stored form.
    record: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Records {
    pub(crate) channel_id: String,
    pub(crate) entries: Vec<Entry>,
    /// The owner holds records past the last entry: ask again.
    pub(crate) more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordsFrom {
    channel_id: String,
    from_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordsLater {
    channel_id: String,
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

impl Records {
    fn encode(&self) -> Vec<u8> {
        let entries = self
            .entries
            .iter()
            .map(|e| {
                Value::text_map([
                    ("bundle", Value::Bytes(e.bundle.clone())),
                    ("sig", Value::Bytes(e.sig.clone())),
                    ("record", Value::Bytes(e.record.clone())),
                ])
            })
            .collect();
        dcbor::encode(&Value::text_map([
            ("channel_id", Value::text(&self.channel_id)),
            ("entries", Value::Array(entries)),
            ("more", Value::Bool(self.more)),
        ]))
        .expect("text keys never repeat")
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let value = dcbor::decode(bytes).ok()?;
        let [channel_id, entries, more] = fields(&value, &["channel_id", "entries", "more"])?[..]
        else {
            return None;
        };
        let entries = entries
            .as_array()?
            .iter()
            .map(|e| {
                let [bundle, sig, record] = fields(e, &["bundle", "sig", "record"])?[..] else {
                    return None;
                };
                Some(Entry {
                    bundle: bundle.as_bytes()?.to_vec(),
                    sig: sig.as_bytes()?.to_vec(),
                    record: record.as_bytes()?.to_vec(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let Value::Bool(more) = more else {
            return None;
        };
        Some(Records {
            channel_id: channel_id.as_text()?.to_string(),
            entries,
            more: *more,
        })
    }
}

impl RecordsFrom {
    fn encode(&self) -> Vec<u8> {
        dcbor::encode(&Value::text_map([
            ("channel_id", Value::text(&self.channel_id)),
            ("from_seq", Value::Unsigned(self.from_seq)),
        ]))
        .expect("text keys never repeat")
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let value = dcbor::decode(bytes).ok()?;
        let [channel_id, from_seq] = fields(&value, &["channel_id", "from_seq"])?[..] else {
            return None;
        };
        Some(RecordsFrom {
            channel_id: channel_id.as_text()?.to_string(),
            from_seq: from_seq.as_u64()?,
        })
    }
}

impl RecordsLater {
    fn encode(&self) -> Vec<u8> {
        dcbor::encode(&Value::text_map([
            ("channel_id", Value::text(&self.channel_id)),
            ("retry_after_ms", Value::Unsigned(self.retry_after_ms)),
        ]))
        .expect("text keys never repeat")
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let value = dcbor::decode(bytes).ok()?;
        let [channel_id, retry_after_ms] = fields(&value, &["channel_id", "retry_after_ms"])?[..]
        else {
            return None;
        };
        Some(RecordsLater {
            channel_id: channel_id.as_text()?.to_string(),
            retry_after_ms: retry_after_ms.as_u64()?,
        })
    }
}

/// How often each peer may send `records-from` for each channel: a token
/// bucket per (peer, channel), holding `burst` and refilled at `per_min` a
/// minute. Keyed only for peers holding a share of the channel, so it holds
/// at most one bucket per live share.
pub(crate) struct RequestLimit {
    burst: f64,
    per_sec: f64,
    buckets: Mutex<HashMap<(String, String), Bucket>>,
}

struct Bucket {
    tokens: f64,
    at: tokio::time::Instant,
}

impl RequestLimit {
    pub(crate) fn new(limit: RateLimit) -> Self {
        RequestLimit {
            burst: f64::from(limit.burst),
            per_sec: f64::from(limit.per_min) / 60.0,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one request for `peer` and `channel_id` at `now`, or say how long
    /// until one is free.
    pub(crate) fn take(
        &self,
        peer: &str,
        channel_id: &str,
        now: tokio::time::Instant,
    ) -> Result<(), Duration> {
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let bucket = buckets
            .entry((peer.to_string(), channel_id.to_string()))
            .or_insert(Bucket {
                tokens: self.burst,
                at: now,
            });
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.per_sec).min(self.burst);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }
        Err(Duration::from_secs_f64(
            (1.0 - bucket.tokens) / self.per_sec,
        ))
    }
}

/// The entries of one [`RECORDS_FRAME`]: at most [`MAX_ENTRIES`], and past
/// the first, at most [`FRAME_BUDGET`] bytes of them.
#[derive(Default)]
struct Packer {
    entries: Vec<Entry>,
    size: usize,
}

impl Packer {
    /// Add `entry` if the frame has room for it. The check comes before each
    /// entry after the first, so nothing follows a largest first entry.
    fn add(&mut self, entry: Entry) -> bool {
        let len = entry.bundle.len() + entry.sig.len() + entry.record.len();
        let full = self.entries.len() == MAX_ENTRIES
            || (!self.entries.is_empty() && self.size + len > FRAME_BUDGET);
        if full {
            return false;
        }
        self.size += len;
        self.entries.push(entry);
        true
    }
}

/// What one peer streamed in the current minute.
struct Window {
    start: Instant,
    blocks: u64,
    bytes: u64,
}

/// A frame waiting to be landed, with the peer it came from.
type Queued = (Did, Records);

/// One server's side of every stream it sends or follows.
#[derive(Clone)]
pub struct Stream {
    ctx: Arc<IngestContext>,
    federation: Arc<FederationSection>,
    peers: Arc<PeerRegistry>,
    queue: mpsc::Sender<Queued>,
    /// The queue's other end, until [`Stream::run`] takes it.
    frames: Arc<Mutex<Option<mpsc::Receiver<Queued>>>>,
    used: Arc<Mutex<HashMap<String, Window>>>,
    /// The owner's limit on each follower's `records-from`.
    requests: Arc<RequestLimit>,
    /// The follower's side of it: per (owner, channel), when the owner said
    /// to ask again.
    retry_at: Arc<Mutex<HashMap<(String, String), tokio::time::Instant>>>,
}

impl Stream {
    /// A stream for this server. It lands nothing until [`Self::run`].
    pub fn new(
        ctx: Arc<IngestContext>,
        federation: Arc<FederationSection>,
        peers: Arc<PeerRegistry>,
    ) -> Self {
        let (queue, frames) = mpsc::channel(QUEUE);
        let requests = Arc::new(RequestLimit::new(federation.records_from));
        Stream {
            ctx,
            federation,
            peers,
            queue,
            frames: Arc::new(Mutex::new(Some(frames))),
            used: Arc::new(Mutex::new(HashMap::new())),
            requests,
            retry_at: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start the worker that lands the frames followers receive, in the
    /// order they came. Once; a second call does nothing.
    pub fn run(&self) {
        let Some(mut frames) = self.frames.lock().unwrap_or_else(|p| p.into_inner()).take() else {
            return;
        };
        let worker = self.clone();
        tokio::spawn(async move {
            while let Some((peer, records)) = frames.recv().await {
                worker.land(&peer, records).await;
            }
        });
    }

    fn store(&self) -> &SqliteStore {
        &self.ctx.store
    }

    /// Send `body` to `peer`, if it is connected. A frame not sent is not
    /// lost: the follower's next pull asks for what it lacks.
    fn send(&self, peer: &str, kind: &str, body: Vec<u8>) {
        let Ok(did) = Did::from_did_jig_string(peer) else {
            return;
        };
        match self.peers.sender_for(&did) {
            Some(sender) => {
                if let Err(e) = sender.send(kind, body) {
                    tracing::info!(peer, kind, "stream frame not sent: {e}");
                }
            }
            None => tracing::debug!(peer, kind, "no live connection to the peer"),
        }
    }

    /// Handle a stream frame from `peer`, or `None` for a frame of another
    /// kind. A frame that does not parse closes the connection.
    pub fn on_peer_frame(
        &self,
        peer: &Did,
        kind: &str,
        body: &[u8],
        out: &PeerSender,
    ) -> Option<Result<(), CloseReason>> {
        match kind {
            RECORDS_FRAME => Some(self.on_records(peer, body)),
            RECORDS_FROM_FRAME => Some(self.on_records_from(peer, body, out)),
            RECORDS_LATER_FRAME => Some(self.on_records_later(peer, body)),
            _ => None,
        }
    }

    // ---- The owner's side --------------------------------------------------

    /// The entry the owner sends for `block`: its bundle, signature and
    /// record. `None` for a block with no record (one outside any channel).
    fn entry(&self, block: &StoredBlock) -> anyhow::Result<Option<(String, u64, Entry)>> {
        let Some(record) = self.store().get_ingest_record(&block.cid)? else {
            return Ok(None);
        };
        let Some(bytes) = self
            .store()
            .ingest_record_bytes(&record.channel_id, record.seq)?
        else {
            return Ok(None);
        };
        Ok(Some((
            record.channel_id,
            record.seq,
            Entry {
                bundle: block.bundle_bytes.clone(),
                sig: block.sender_sig.clone(),
                record: bytes,
            },
        )))
    }

    /// The peers holding an accepted share of `channel_id`, on the owner's
    /// side.
    fn followers(&self, channel_id: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .store()
            .contract_offers_in(Side::Owner, OfferState::Accepted)?
            .into_iter()
            .filter(|o| o.channel_id == channel_id)
            .map(|o| o.peer_did)
            .collect())
    }

    /// Send a block this server just sequenced to every server following its
    /// channel.
    pub fn on_block(&self, block: &StoredBlock) -> anyhow::Result<()> {
        if block.channel_id.is_none() {
            return Ok(());
        }
        let Some((channel_id, _, entry)) = self.entry(block)? else {
            return Ok(());
        };
        let followers = self.followers(&channel_id)?;
        if followers.is_empty() {
            return Ok(());
        }
        let body = Records {
            channel_id,
            entries: vec![entry],
            more: false,
        }
        .encode();
        for peer in followers {
            self.send(&peer, RECORDS_FRAME, body.clone());
        }
        Ok(())
    }

    /// Answer a follower's request with the records from its `from_seq`, if
    /// it holds an accepted share of the channel.
    fn on_records_from(
        &self,
        peer: &Did,
        body: &[u8],
        out: &PeerSender,
    ) -> Result<(), CloseReason> {
        let ask = RecordsFrom::decode(body).ok_or_else(|| violation("a malformed records-from"))?;
        let peer = peer.to_did_jig_string();
        if let Err(e) = self.answer(&peer, &ask, out) {
            tracing::warn!(
                peer,
                channel_id = ask.channel_id,
                "records-from not answered: {e:#}"
            );
        }
        Ok(())
    }

    fn answer(&self, peer: &str, ask: &RecordsFrom, out: &PeerSender) -> anyhow::Result<()> {
        let shared = !self
            .store()
            .contract_offers_for(&ask.channel_id, peer, Side::Owner, OfferState::Accepted)?
            .is_empty();
        if !shared {
            tracing::debug!(
                peer,
                channel_id = ask.channel_id,
                "records-from without a share"
            );
            return Ok(());
        }
        if let Err(wait) = self
            .requests
            .take(peer, &ask.channel_id, tokio::time::Instant::now())
        {
            let retry_after_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX).max(1);
            tracing::info!(
                peer,
                channel_id = ask.channel_id,
                retry_after_ms,
                "records-from past the limit"
            );
            let later = RecordsLater {
                channel_id: ask.channel_id.clone(),
                retry_after_ms,
            };
            if let Err(e) = out.send(RECORDS_LATER_FRAME, later.encode()) {
                tracing::info!(peer, "records-later not sent: {e}");
            }
            return Ok(());
        }
        let Some(records) = self.records_from(&ask.channel_id, ask.from_seq)? else {
            return Ok(());
        };
        if let Err(e) = out.send(RECORDS_FRAME, records.encode()) {
            tracing::info!(peer, "records not sent: {e}");
        }
        Ok(())
    }

    /// `channel_id`'s blocks from `from_seq`, as many as one frame holds, or
    /// `None` when there are none.
    pub(crate) fn records_from(
        &self,
        channel_id: &str,
        from_seq: u64,
    ) -> anyhow::Result<Option<Records>> {
        // One more than a frame holds, to know whether more follow.
        let records =
            self.store()
                .list_ingest_records_by_id(channel_id, from_seq, MAX_ENTRIES + 1)?;
        let mut frame = Packer::default();
        let mut more = false;
        for record in records {
            let Some(block) = self.store().get_block(&record.block_cid)? else {
                break;
            };
            let Some((_, _, entry)) = self.entry(&block)? else {
                break;
            };
            if !frame.add(entry) {
                more = true;
                break;
            }
        }
        Ok((!frame.entries.is_empty()).then(|| Records {
            channel_id: channel_id.to_string(),
            entries: frame.entries,
            more,
        }))
    }

    // ---- The follower's side -----------------------------------------------

    fn on_records(&self, peer: &Did, body: &[u8]) -> Result<(), CloseReason> {
        let records =
            Records::decode(body).ok_or_else(|| violation("malformed channel-records"))?;
        if records.entries.len() > MAX_ENTRIES {
            return Err(violation("channel-records past the most a frame carries"));
        }
        if let Err(e) = self.queue.try_send((peer.clone(), records)) {
            tracing::info!(
                peer = peer.to_did_jig_string(),
                "channel-records dropped, to be fetched again: {e}"
            );
        }
        Ok(())
    }

    /// The owner `peer` said to ask again for `channel_id` later: ask nothing
    /// more for it until then, and then ask from the head.
    fn on_records_later(&self, peer: &Did, body: &[u8]) -> Result<(), CloseReason> {
        let later =
            RecordsLater::decode(body).ok_or_else(|| violation("malformed records-later"))?;
        let peer = peer.to_did_jig_string();
        let wait = Duration::from_millis(later.retry_after_ms).min(MAX_RETRY_AFTER);
        self.retry_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                (peer.clone(), later.channel_id.clone()),
                tokio::time::Instant::now() + wait,
            );
        tracing::info!(
            peer,
            channel_id = later.channel_id,
            "the owner limits records-from; asking again in {wait:?}"
        );
        let stream = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            stream.pull_from_head(&peer, &later.channel_id);
        });
        Ok(())
    }

    /// When the owner `peer` said this server may ask for `channel_id` again,
    /// if that is still to come.
    pub(crate) fn retry_at(&self, peer: &str, channel_id: &str) -> Option<tokio::time::Instant> {
        let mut retry_at = self.retry_at.lock().unwrap_or_else(|p| p.into_inner());
        let key = (peer.to_string(), channel_id.to_string());
        match retry_at.get(&key) {
            Some(at) if *at > tokio::time::Instant::now() => Some(*at),
            Some(_) => {
                retry_at.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Ask `peer` for `channel_id`'s records from `from_seq`, unless the
    /// owner said to wait.
    fn pull(&self, peer: &str, channel_id: &str, from_seq: u64) {
        if self.retry_at(peer, channel_id).is_some() {
            tracing::debug!(
                peer,
                channel_id,
                "records-from held back: the owner said to wait"
            );
            return;
        }
        let body = RecordsFrom {
            channel_id: channel_id.to_string(),
            from_seq,
        }
        .encode();
        self.send(peer, RECORDS_FROM_FRAME, body);
    }

    /// Ask every owner this server follows for the records past its head. A
    /// channel stopped at a fork is not asked: it takes nothing more.
    pub fn pull_all(&self) {
        let shares = match self
            .store()
            .contract_offers_in(Side::Follower, OfferState::Accepted)
        {
            Ok(shares) => shares,
            Err(e) => {
                tracing::warn!("listing followed channels: {e}");
                return;
            }
        };
        for share in shares {
            let stopped = self
                .store()
                .chain_evidence(&share.channel_id)
                .map(|e| !e.is_empty())
                .unwrap_or(true);
            if stopped {
                continue;
            }
            self.pull_from_head(&share.peer_did, &share.channel_id);
        }
    }

    /// Ask `peer` for `channel_id`'s records past this server's head.
    fn pull_from_head(&self, peer: &str, channel_id: &str) {
        match self.store().latest_ingest_record(channel_id) {
            Ok(head) => self.pull(peer, channel_id, head.map_or(0, |h| h.seq + 1)),
            Err(e) => tracing::warn!(channel_id, "reading the head: {e}"),
        }
    }

    /// Count `bytes` of one block against `peer`'s quota for this minute.
    /// Whether it is within it.
    fn within_quota(&self, peer: &str, bytes: usize) -> bool {
        let quota: PeerQuotaConfig = self
            .federation
            .peers
            .iter()
            .find(|p| jig_pipeline::effect::canonical_did_string(&p.expected_did) == peer)
            .and_then(|p| p.quota)
            .unwrap_or(self.federation.default_peer_quota);
        let mut used = self.used.lock().unwrap_or_else(|p| p.into_inner());
        let window = used.entry(peer.to_string()).or_insert(Window {
            start: Instant::now(),
            blocks: 0,
            bytes: 0,
        });
        if window.start.elapsed() >= Duration::from_secs(60) {
            *window = Window {
                start: Instant::now(),
                blocks: 0,
                bytes: 0,
            };
        }
        if window.blocks + 1 > quota.blocks_per_min
            || window.bytes + bytes as u64 > quota.bytes_per_min
        {
            return false;
        }
        window.blocks += 1;
        window.bytes += bytes as u64;
        true
    }

    /// Land one frame from `peer`, entry by entry, with `peer` as the
    /// sequencer. The first entry that does not land ends the frame: a gap
    /// asks for what is missing, and anything else is logged (a fork's
    /// evidence is kept by the pipeline).
    pub(crate) async fn land(&self, peer: &Did, records: Records) {
        let sequencer = peer.to_did_jig_string();
        let mut last = None;
        for entry in records.entries {
            let Ok((manifest_bytes, code_bytes)) =
                serde_json::from_slice::<(Vec<u8>, Vec<u8>)>(&entry.bundle)
            else {
                tracing::warn!(peer = sequencer, "a streamed block that is not a bundle");
                return;
            };
            if !self.within_quota(&sequencer, entry.bundle.len()) {
                tracing::info!(
                    peer = sequencer,
                    "past the peer's quota; fetched again later"
                );
                return;
            }
            let bundle = BlockBundle {
                manifest_bytes: &manifest_bytes,
                code_bytes: &code_bytes,
                resources: vec![],
            };
            match ingest_sequenced(&self.ctx, bundle, entry.sig, &entry.record, &sequencer).await {
                Ok(Followed::Landed { seq, .. } | Followed::Duplicate { seq, .. }) => {
                    last = Some(seq);
                }
                Err(FollowError::Gap {
                    channel_id, head, ..
                }) => {
                    self.pull(&sequencer, &channel_id, head.map_or(0, |h| h + 1));
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        peer = sequencer,
                        channel_id = records.channel_id,
                        "a streamed block did not land: {e}"
                    );
                    return;
                }
            }
        }
        if records.more
            && let Some(seq) = last
        {
            self.pull(&sequencer, &records.channel_id, seq + 1);
        }
    }
}

fn violation(why: &str) -> CloseReason {
    CloseReason {
        code: jig_pipeline::handshake::close::PROTOCOL_VIOLATION,
        reason: format!("stream: {why}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records() -> Records {
        Records {
            channel_id: "bafkchannel".to_string(),
            entries: vec![Entry {
                bundle: vec![1, 2],
                sig: vec![3],
                record: b"{}".to_vec(),
            }],
            more: true,
        }
    }

    /// The largest frame the owner sends, wrapped as the peer connection
    /// sends it, in bytes.
    fn envelope_len(entries: Vec<Entry>) -> usize {
        let body = Records {
            channel_id: jig_pipeline::ingest_record::label_cid("a channel"),
            entries,
            more: true,
        }
        .encode();
        let envelope = jig_pipeline::envelope::Envelope::new(jig_pipeline::envelope::Frame::Peer {
            kind: RECORDS_FRAME.to_string(),
            body,
        });
        serde_json::to_vec(&envelope).unwrap().len()
    }

    fn entry_of(bundle: usize) -> Entry {
        Entry {
            bundle: vec![0xff; bundle],
            sig: vec![0xff; 64],
            record: vec![b'x'; jig_pipeline::follow::MAX_RECORD_BYTES],
        }
    }

    #[test]
    fn the_largest_frames_fit_the_peer_connection() {
        let max_envelope = jig_core::bundle::MAX_ENVELOPE_BYTES;
        let max = jig_core::bundle::MAX_BUNDLE_BYTES;

        // A largest block first: nothing follows it.
        let mut one = Packer::default();
        assert!(one.add(entry_of(max)));
        assert!(!one.add(entry_of(1)), "nothing after a largest first entry");
        let len = envelope_len(one.entries);
        assert!(
            len <= max_envelope,
            "one largest entry: {len} > {max_envelope}"
        );

        // As many entries as a frame holds, filling the budget.
        let per = FRAME_BUDGET / MAX_ENTRIES - 64 - jig_pipeline::follow::MAX_RECORD_BYTES;
        let mut many = Packer::default();
        for _ in 0..MAX_ENTRIES {
            assert!(many.add(entry_of(per)));
        }
        assert!(!many.add(entry_of(1)), "no more than MAX_ENTRIES");
        let len = envelope_len(many.entries);
        assert!(
            len <= max_envelope,
            "{MAX_ENTRIES} entries: {len} > {max_envelope}"
        );
    }

    #[test]
    fn the_limit_is_a_bucket_per_peer_and_channel() {
        // Two at once, then one every 10 s.
        let limit = RequestLimit::new(RateLimit {
            burst: 2,
            per_min: 6,
        });
        let t0 = tokio::time::Instant::now();
        let take = |peer: &str, channel: &str, at: Duration| limit.take(peer, channel, t0 + at);
        assert_eq!(take("a", "c", Duration::ZERO), Ok(()));
        assert_eq!(take("a", "c", Duration::ZERO), Ok(()));
        assert_eq!(take("a", "c", Duration::ZERO), Err(Duration::from_secs(10)));
        // Each peer and each channel has its own.
        assert_eq!(take("a", "other", Duration::ZERO), Ok(()));
        assert_eq!(take("b", "c", Duration::ZERO), Ok(()));
        // The wait it named is the wait it means.
        let at = Duration::from_secs(4);
        assert_eq!(take("a", "c", at), Err(Duration::from_secs(6)));
        assert_eq!(take("a", "c", Duration::from_secs(10)), Ok(()));
        assert!(take("a", "c", Duration::from_secs(10)).is_err());
        // Idle time refills no more than the burst.
        let later = Duration::from_secs(3600);
        assert_eq!(take("a", "c", later), Ok(()));
        assert_eq!(take("a", "c", later), Ok(()));
        assert!(take("a", "c", later).is_err());
    }

    #[test]
    fn frames_round_trip() {
        let r = records();
        assert_eq!(Records::decode(&r.encode()), Some(r));
        let later = RecordsLater {
            channel_id: "bafkchannel".to_string(),
            retry_after_ms: 3000,
        };
        assert_eq!(RecordsLater::decode(&later.encode()), Some(later));
        let ask = RecordsFrom {
            channel_id: "bafkchannel".to_string(),
            from_seq: 7,
        };
        assert_eq!(RecordsFrom::decode(&ask.encode()), Some(ask));
    }

    #[test]
    fn a_frame_with_anything_more_or_less_is_malformed() {
        let extra = dcbor::encode(&Value::text_map([
            ("channel_id", Value::text("bafkchannel")),
            ("from_seq", Value::Unsigned(0)),
            ("sequencer", Value::text("did:jig:zOther")),
        ]))
        .unwrap();
        assert_eq!(
            RecordsFrom::decode(&extra),
            None,
            "no frame names a sequencer"
        );
        let short = dcbor::encode(&Value::text_map([("channel_id", Value::text("x"))])).unwrap();
        assert_eq!(RecordsFrom::decode(&short), None);
        let mut bytes = records().encode();
        bytes.push(0);
        assert_eq!(Records::decode(&bytes), None, "trailing bytes");
    }
}
