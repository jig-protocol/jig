//! Encrypted channels in the CLI: the network half of
//! `jig_client::secure::Session`.
//!
//! The session holds MLS state and does the cryptography; this module talks to
//! the server — key packages, group info, history, and submitting the blocks
//! that carry commits — and keeps the two in step: a commit is merged only
//! after the server accepts the block carrying it, and dropped if it refuses.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jig_client::blocks::BuiltBlock;
use jig_client::chain::{ChannelChain, Step};
use jig_client::limits;
use jig_client::open::open;
use jig_client::pins::{
    ChannelPin, Pins, names_another_server, prove_carried, prove_carried_after_move,
    prove_channel_ordered_by,
};
use jig_client::secure::{CommitLock, ReadIn, Seen, Session, history_reaches, replay_order};
use jig_client::servers::{LocalAdds, Reach, ServerState, ServerStates};
use jig_client::{Client, ClientError, DeliveredBlock, Identity};
use jig_core::naming::ReachabilityRecord;
use jig_mls::member::Commit;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::cmd::blocks_decode::{DecodedBlock, present};
use crate::cmd::channel::{base_http_url, escape_slug_for_url};
use crate::cmd::common::CliContext;
use crate::cmd::history::{DEFAULT_HISTORY_LIMIT, history_url, parse_history};

/// The most a server returns per history request.
pub(crate) const MAX_HISTORY_PAGE: usize = 200;
/// Pages of older history to fetch before giving up on catching up.
pub(crate) const MAX_CATCH_UP_PAGES: usize = 50;
/// The first page a catch-up from a known head asks for: a device that
/// synced recently is usually a few blocks behind, if any. Pages after it
/// are [`MAX_HISTORY_PAGE`], so [`MAX_CATCH_UP_PAGES`] reach 16 + 49 × 200 =
/// 9,816 blocks back.
const SINCE_HEAD_FIRST_PAGE: usize = 16;

/// Packages a DID keeps published, so it can be added while offline.
const KEY_PACKAGE_TARGET: u64 = 10;
/// Top up when fewer than this many remain.
const KEY_PACKAGE_LOW_WATER: u64 = 3;

/// A refusal from the server, with its error code.
#[derive(Debug)]
pub struct Refused {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.message)
    }
}

impl std::error::Error for Refused {}

impl Refused {
    /// The server looked at the request and turned it down. A 5xx — perhaps
    /// from a proxy that gave up waiting — says nothing about whether the
    /// server acted on it.
    pub fn is_definite(&self) -> bool {
        (400..500).contains(&self.status)
    }
}

/// Whether `e` is a server saying the member it was asked to add ended local
/// adds there (JEP-0017 R2): `LOCAL_ADDS_ENDED` for a key package,
/// `MEMBER_DECLINED` for the `member-add`. Both are final for that channel
/// (rule 18).
pub fn local_adds_ended(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<Refused>()
            .is_some_and(|r| r.code == "LOCAL_ADDS_ENDED" || r.code == "MEMBER_DECLINED")
    })
}

/// Drop the references in `refs` from `state`, keeping any recorded since.
fn forget_stock_refs(state: &mut ServerState, refs: &std::collections::BTreeSet<String>) {
    state.packages.retain(|r| !refs.contains(r));
    state.retiring.retain(|r| !refs.contains(r));
    if state.last_resort.as_ref().is_some_and(|r| refs.contains(r)) {
        state.last_resort = None;
    }
}

/// How [`first_release`] ended without a package.
enum Asked {
    /// A refusal no other custodian can get around (JEP-0017 rule 18).
    Final(anyhow::Error),
    /// Each custodian asked, and why it gave nothing.
    Tried(Vec<String>),
}

/// Ask each of `servers` in turn with `ask` until one releases a package.
/// A custodian that sequences the channel, where the member ended local
/// adds, would refuse the member-add too: the next is not asked.
async fn first_release<'a, F, Fut>(
    servers: &'a [(String, String)],
    mut ask: F,
) -> std::result::Result<Vec<u8>, Asked>
where
    F: FnMut(&'a str, &'a str) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let mut tried = Vec::new();
    for (server_did, url) in servers {
        match ask(server_did, url).await {
            Ok(package) => return Ok(package),
            Err(e) if local_adds_ended(&e) => {
                return Err(Asked::Final(e.context(format!("{url} ({server_did})"))));
            }
            Err(e) => tried.push(format!("  {url} ({server_did}): {e:#}")),
        }
    }
    Err(Asked::Tried(tried))
}

/// Send a local-adds marker at `seq` with `put`, which answers the marker
/// the server keeps. If that is a later one from another device saying the
/// opposite, say ours once more, above it, and take what is kept then: one
/// retry, so two devices disagreeing do not race without end.
async fn settle_local_adds<F, Fut>(allow: bool, seq: u64, mut put: F) -> Result<LocalAdds>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Result<LocalAdds>>,
{
    let kept = put(seq).await?;
    if kept.allow == allow {
        return Ok(kept);
    }
    put(kept.seq.saturating_add(1)).await
}

/// Whether `e` is the server definitely turning a request down.
pub fn refused(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Refused>()
        .is_some_and(Refused::is_definite)
}

/// A channel as the server lists it. [`Secure::channel`] replaces `suite`
/// with the one its owner signed into the creation block `id`.
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelInfo {
    /// The CID of the block that created the channel.
    #[serde(default)]
    pub id: String,
    pub slug: String,
    #[serde(default = "none_suite")]
    pub suite: String,
    /// The server that orders the channel, as the listing says. Taken from
    /// another server only with `share` ([`Secure::channel`]).
    #[serde(default)]
    pub sequencer: String,
    /// The owner's signed offer, for a channel the server carries.
    #[serde(default)]
    pub share: Option<String>,
    /// The owner's key links beside `share`, when the owner changed its key
    /// after it created the channel (base64, oldest first). Checked, never
    /// trusted ([`prove_carried`]).
    #[serde(default)]
    pub share_key_links: Vec<String>,
    /// The channel's tier (JEP-0014), or `frozen`, as the listing says.
    /// Absent from servers before tiers. Unsigned: shown, never trusted.
    #[serde(default)]
    pub tier: Option<String>,
}

fn none_suite() -> String {
    "none".to_string()
}

impl ChannelInfo {
    /// Anything but `none` is encrypted, including a suite this CLI does not
    /// speak; [`Secure::channel`] refuses those before anything is sent.
    pub fn encrypted(&self) -> bool {
        self.suite != "none"
    }
}

/// Whether a channel must be encrypted, given whether this device holds its
/// MLS group (`held`) and what the server's unsigned listing says (`listed`;
/// `None` when the channel is not listed to us).
///
/// A device that holds the group knows the channel is encrypted, whatever the
/// listing says: a server relabelling a channel `none` is asking for
/// plaintext (OP-03), and a channel hidden from a removed member is still
/// encrypted. Only a channel this device holds no group for is taken on the
/// listing's word: there is nothing local to check it against.
pub fn must_encrypt(held: bool, listed: Option<bool>) -> bool {
    held || listed.unwrap_or(false)
}

/// Connect over WSS to `server`, holding it to what this device pinned:
/// its welcome must be signed by the pinned DID and still advertise every
/// pinned suite. The first welcome from a server is pinned.
pub async fn connect_pinned(server: &str, identity: Identity) -> Result<Client> {
    let mut pins = Pins::load(&Pins::default_path())?;
    let pinned = pins.offer(server).pinned_server_did;
    let tls = crate::cmd::trust::server_tls(server).await?;
    let options = jig_client::connection::ConnectOptions {
        offer: pins.offer(server),
        tls,
        on_contradiction: Some(crate::cmd::trust::evidence_hook(server)),
        key_links: pins
            .server(server)
            .map(|p| p.links.clone())
            .unwrap_or_default(),
        carried: pins.carried_signers(server),
        owners: pins.owners(server),
    };
    let client = Client::connect_with_options(server, identity, options)
        .await
        .map_err(|e| match (e, pinned) {
            (ClientError::HandshakeFailed { reason, .. }, Some(did)) => anyhow::anyhow!(
                "{server} did not prove it is the server this device pinned ({did}): {reason}. \
                 If its key really changed, `jig server forget` drops the pin."
            ),
            (e, _) => e.into(),
        })?;
    if let Some(welcome) = client.welcome() {
        pins.check_welcome(server, welcome)?;
        crate::cmd::trust::check_manifest(client.identity(), server, welcome).await?;
    }
    Ok(client)
}

/// A reachability record as a server serves it.
#[derive(Debug, Deserialize)]
struct RecordBody {
    record_b64: String,
}

/// Hold the server at `url` to `server_did` with its signed welcome, without
/// pinning it: a custodian is trusted with nothing but answering.
async fn prove_server(url: &str, server_did: &str, identity: Identity) -> Result<()> {
    let tls = crate::cmd::trust::server_tls(url).await?;
    let mut options = jig_client::connection::ConnectOptions {
        tls,
        ..Default::default()
    };
    options.offer.pinned_server_did = Some(server_did.to_string());
    Client::connect_with_options(url, identity, options)
        .await
        .map(drop)
        .with_context(|| format!("{url} did not prove it is {server_did}"))
}

/// A connection to the server at `url`, its welcome verified and held to
/// nothing this device pinned, and pinning nothing.
pub async fn connect_unpinned(url: &str, identity: Identity) -> Result<Client> {
    let tls = crate::cmd::trust::server_tls(url).await?;
    let options = jig_client::connection::ConnectOptions {
        tls,
        ..Default::default()
    };
    Client::connect_with_options(url, identity, options)
        .await
        .with_context(|| format!("connecting to {url}"))
}

/// The server at `url`'s DID, as its signed welcome says.
async fn server_did_at(url: &str, identity: Identity) -> Result<String> {
    connect_unpinned(url, identity)
        .await?
        .welcome()
        .map(|w| w.server_did.clone())
        .with_context(|| format!("{url} sent no welcome"))
}

/// Where to ask for `did`'s key packages, from the server at `via`: the
/// reachability record it keeps for `did`, if `did` signed one, or else that
/// server alone, under the DID its welcome proves. Asking a server `did` did
/// not list gets `NO_CUSTODY`; a record a server makes up gets nothing, since
/// only `did` can sign one.
pub async fn custodians_via(
    via: &str,
    did: &str,
    identity: &Identity,
) -> Result<ReachabilityRecord> {
    let url = format!("{}/api/v1/reach/{did}", base_http_url(via));
    let http = crate::cmd::trust::http(via, std::time::Duration::from_secs(15)).await?;
    // `via` is asked, not trusted: its welcome proves the audience, and
    // nothing is pinned.
    let resp = crate::cmd::request_proof::send_as(
        via,
        crate::cmd::request_proof::Trust::Unpinned,
        identity,
        "GET",
        &url,
        b"",
        || http.get(&url),
    )
    .await?;
    if resp.status().is_success() {
        let body: RecordBody = limits::json_capped(resp, limits::MAX_DOCUMENT_BYTES)
            .await
            .with_context(|| format!("reading {url}"))?;
        let record = STANDARD
            .decode(body.record_b64)
            .ok()
            .and_then(|e| ReachabilityRecord::from_envelope(&e).ok())
            .filter(|r| r.did == did);
        if let Some(record) = record {
            return Ok(record);
        }
        eprintln!("warning: {via} served a reachability record {did} did not sign; ignoring it");
    }
    let server_did = server_did_at(via, identity.duplicate()).await?;
    Ok(ReachabilityRecord {
        did: did.to_string(),
        servers: vec![(server_did, via.to_string())],
        seq: 0,
        envelope: Vec::new(),
    })
}

/// History replayed through the session.
pub struct Synced {
    /// What to show, oldest first.
    pub lines: Vec<DecodedBlock>,
    /// Departed members still in this member's copy of the tree.
    pub tidy: Vec<String>,
    /// Every block the history held, by CID.
    pub cids: std::collections::HashSet<String>,
    /// The same blocks by delivery CID, the key a live delivery carries.
    pub deliveries: Vec<String>,
    /// The critical block of an unknown kind the replay stopped at, if any
    /// (JEP-0005 rule 14c): nothing at or after it was read, and the head
    /// stays before it.
    pub stopped: Option<jig_client::open::OpenError>,
}

/// Which page of a channel's history to fetch.
#[derive(Clone, Copy)]
enum Page<'a> {
    /// The newest blocks.
    Newest,
    /// The blocks just older than this one.
    Before(&'a str),
    /// The blocks just newer than this one.
    After(&'a str),
}

/// What a replay has found so far, over one page of history or several.
#[derive(Default)]
struct Replayed {
    lines: Vec<DecodedBlock>,
    /// Members who left and may need tidying, until one is seen back.
    left: Vec<String>,
    cids: std::collections::HashSet<String>,
    deliveries: Vec<String>,
    stopped: Option<jig_client::open::OpenError>,
}

/// The blocks of `delivered` (oldest first) before the first critical block
/// of a kind this build does not implement, and that block's error: a reader
/// reads nothing at or past it (JEP-0005 rule 14c).
fn before_stop(
    delivered: &[DeliveredBlock],
) -> (&[DeliveredBlock], Option<jig_client::open::OpenError>) {
    for (at, d) in delivered.iter().enumerate() {
        if let Err(e) = open(d)
            && e.needs_upgrade()
        {
            return (&delivered[..at], Some(e));
        }
    }
    (delivered, None)
}

/// How a forward walk through history ended.
enum Forwarded {
    /// At the newest block.
    Done(Replayed),
    /// At a page that does not continue from `head`, the last block read,
    /// for `why`. Everything up to `head` is in `replayed`.
    Broken {
        replayed: Replayed,
        head: String,
        why: String,
    },
    /// At history with no sequencer records, from `head` on: it is ordered
    /// by its authors' clocks, so a message can come after the commits that
    /// left its epoch, and only replaying it with them puts it back in MLS
    /// order ([`replay_order`]). A page at a time could seal it for good.
    Unsequenced { replayed: Replayed, head: String },
}

/// Hold `page` to `chain`: each block's record must be the next one after
/// the chain's head. Moves the head along as it goes.
fn continues(chain: &mut ChannelChain, page: &[DeliveredBlock]) -> Result<(), String> {
    for d in page {
        let Some(record) = &d.ingest else {
            return Err(format!("block {} has no sequencer record", d.delivery_cid));
        };
        let cid = placed_cid(d);
        match chain.accept_block(record, cid.as_deref(), &d.bundle_b64, d.sig_b64.as_deref()) {
            Ok(Step::Next) => {}
            Ok(Step::Gap { from, to }) => {
                return Err(format!("records {from} to {} are missing", to - 1));
            }
            Ok(Step::Behind) => {
                return Err(format!("record {} is not after this device's", record.seq));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

/// Who may sign `channel_id`'s records on `server`, for [`ChannelChain`]: a
/// channel the server carries for its owner is held to the owner, the DID
/// its pin proved (`Pins::anchor_channel`), as `jig read` holds it, never
/// to the server. Any other channel is held to the server's DIDs along the
/// key links pinned for it, or to the record's own signer when nothing is
/// pinned.
fn sequencers_for(
    pins: Option<&Pins>,
    server: &str,
    channel_id: &str,
    record_sequencer: &str,
) -> Vec<String> {
    if let Some(owner) = pins.and_then(|p| p.carried(server).remove(channel_id)) {
        return vec![owner];
    }
    let pinned = pins
        .and_then(|p| p.server(server).map(|s| s.sequencers()))
        .unwrap_or_default();
    if pinned.is_empty() {
        vec![record_sequencer.to_string()]
    } else {
        pinned
    }
}

/// Where the block `cid` is in `page`, if it is.
fn position_of(page: &[DeliveredBlock], cid: &str) -> Option<usize> {
    page.iter()
        .position(|d| placed_cid(d).is_some_and(|c| c == cid))
}

/// Keep of `window` (oldest first) only what a sync read up to `head`, the
/// block it left its head at: a block past it landed since, and is the next
/// sync's to read in order, through the stop rule. A window with no head in
/// it lies wholly past it (more blocks landed since than it holds), and no
/// head means the sync placed nothing; either way nothing is shown.
fn bound_to_head(window: &mut Vec<DeliveredBlock>, head: Option<&str>) {
    match head.and_then(|head| position_of(window, head)) {
        Some(at) => window.truncate(at + 1),
        None => window.clear(),
    }
}

/// The CID of a delivered block this reader can place in its channel: one it
/// opens, or a non-critical block of a kind this build does not implement
/// (JEP-0005 rule 14c), which is in the chain all the same though nothing in
/// it is read. A head, a cursor or a page bound may be either.
pub(crate) fn placed_cid(d: &DeliveredBlock) -> Option<String> {
    match open(d) {
        Ok(opened) => Some(opened.cid),
        Err(jig_client::open::OpenError::UnknownKind {
            cid,
            critical: false,
            ..
        }) => Some(cid),
        Err(_) => None,
    }
}

/// The reachability record a server keeps for us ([`Secure::kept_record`]).
enum Kept {
    /// The server has no route for records.
    Unsupported,
    None,
    Record(ReachabilityRecord),
}

/// Whether the record a server keeps for `did`, as it answered, leaves
/// `server_did` out (a withdrawal there). `None` when the answer is not a
/// record `did` signed: nothing can be concluded from it.
fn kept_leaves_out(body: &RecordBody, did: &str, server_did: &str) -> Option<bool> {
    let envelope = STANDARD.decode(&body.record_b64).ok()?;
    let record = ReachabilityRecord::from_envelope(&envelope).ok()?;
    (record.did == did).then(|| !record.servers.iter().any(|(s, _)| s == server_did))
}

/// What one server's answer to our signed read of its kept record says.
#[derive(Debug, PartialEq, Eq)]
enum KeptAnswer {
    /// Its record leaves it out: withdrawn there, so it is dropped.
    Withdrawn,
    /// It still lists itself, or keeps no record: the new one may go there.
    Listed,
    /// Nothing can be concluded: it stays listed, but is not sent the record.
    Unchecked,
}

/// Judge an answer: `None` when the request failed; otherwise its status and
/// its body, `None` when the body could not be read in full.
fn judge_kept_answer(
    answer: Option<(reqwest::StatusCode, Option<&[u8]>)>,
    did: &str,
    server_did: &str,
) -> KeptAnswer {
    match answer {
        Some((status, body)) if status.is_success() => {
            let record = body.and_then(|b| serde_json::from_slice::<RecordBody>(b).ok());
            match record.and_then(|r| kept_leaves_out(&r, did, server_did)) {
                Some(true) => KeptAnswer::Withdrawn,
                Some(false) => KeptAnswer::Listed,
                // An answer that is not our record: not checked.
                None => KeptAnswer::Unchecked,
            }
        }
        // No record there: nothing to restore, so sending is safe.
        Some((reqwest::StatusCode::NOT_FOUND, _)) => KeptAnswer::Listed,
        _ => KeptAnswer::Unchecked,
    }
}

/// Servers as (DID, URL) pairs.
type ServerList = Vec<(String, String)>;

/// Split the servers a new record lists into those it is sent to and those
/// it is not, because their own record could not be read.
fn split_unchecked(
    servers: &[(String, String)],
    unchecked: &std::collections::HashSet<String>,
) -> (ServerList, ServerList) {
    servers
        .iter()
        .cloned()
        .partition(|(s, _)| !unchecked.contains(s))
}

/// Guards a walk of the release log's pages against a server that ignores
/// `offset`: a page the same as the one before, or more pages than any log
/// can hold, ends the walk with an error that names the server.
#[derive(Default)]
struct LogWalk {
    previous: Option<Vec<String>>,
    pages: usize,
}

impl LogWalk {
    /// More pages than a member's log can hold: the per-member limit
    /// releases at most a few hundred a day, within a package's lifetime.
    const MAX_PAGES: usize = 1000;

    /// One page, as the identities of its entries, or `None` when the server
    /// gives entries no identity (then only the cap applies).
    fn page(&mut self, server: &str, ids: Option<Vec<String>>) -> Result<()> {
        self.pages += 1;
        if self.pages > Self::MAX_PAGES {
            anyhow::bail!(
                "{server}'s release log does not end; stopped after {} pages",
                Self::MAX_PAGES
            );
        }
        if let Some(page) = &ids
            && !page.is_empty()
            && self.previous.as_ref() == Some(page)
        {
            anyhow::bail!(
                "{server} answers every page of the release log the same; it ignores `offset`"
            );
        }
        self.previous = ids;
        Ok(())
    }
}

/// One entry of a server's release log, as this device reads it.
#[derive(Deserialize)]
struct ReleaseEntry {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    reference_hex: Option<String>,
    #[serde(default)]
    channel_id: String,
    #[serde(default)]
    request_b64: String,
    #[serde(default)]
    id_hex: Option<String>,
}

#[derive(Deserialize)]
struct ReleaseLog {
    releases: Vec<ReleaseEntry>,
}

/// Entries per page of the release log, as the server pages it.
const RELEASE_PAGE: usize = 200;

/// Walk a release log page by page, `fetch(offset)` giving each page (`None`
/// when the server keeps no log), and collect the references of the custody
/// releases in it. A short page ends the walk; [`LogWalk`] ends one that
/// does not.
async fn walk_release_log<F, Fut>(server: &str, mut fetch: F) -> Result<Vec<Vec<u8>>>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Result<Option<Vec<ReleaseEntry>>>>,
{
    let mut refs = Vec::new();
    let mut offset = 0;
    let mut walk = LogWalk::default();
    loop {
        let Some(releases) = fetch(offset).await? else {
            return Ok(refs);
        };
        let n = releases.len();
        // Each entry is told apart by its own id; a server that sends
        // none leaves only the page cap.
        let ids: Option<Vec<String>> = releases.iter().map(|e| e.id_hex.clone()).collect();
        walk.page(server, ids)?;
        for e in releases {
            let custody = match e.kind.as_deref() {
                Some(kind) => kind == "custody",
                None => !e.channel_id.is_empty() || !e.request_b64.is_empty(),
            };
            if !custody {
                continue;
            }
            match e.reference_hex.as_deref().map(hex::decode) {
                Some(Ok(r)) => refs.push(r),
                _ => anyhow::bail!(
                    "{server} logs releases without the package they released; it cannot \
                     tell this device which keys to delete"
                ),
            }
        }
        if n < RELEASE_PAGE {
            return Ok(refs);
        }
        offset += n;
    }
}

/// What [`Secure::set_custody`] did.
#[derive(Debug, Default)]
pub struct CustodyChange {
    /// The new record's seq.
    pub seq: u64,
    /// Each other server the record went to, and how it answered.
    pub elsewhere: Vec<(String, Result<(), String>)>,
    /// Private init keys this device deleted (rule 32).
    pub deleted: usize,
}

/// One identity's encrypted-channel state, bound to one server.
pub struct Secure {
    pub session: Arc<Session>,
    identity: Identity,
    /// The server, as configured (any scheme).
    server: String,
    /// The same server as an `http(s)://` base for REST.
    base: String,
    /// `[server] publish_reachability` ([`Self::ensure_reachable`]).
    publish_reachability: bool,
    /// Set once this process has held the server to its pin
    /// ([`Self::ensure_pinned`]).
    pinned: tokio::sync::OnceCell<()>,
    /// Whether the server advertises paging history forward (`after=`),
    /// once asked ([`Self::pages_forward`]).
    forward: tokio::sync::OnceCell<bool>,
    /// Set when a forward page broke the chain: not again this process.
    forward_broken: std::sync::atomic::AtomicBool,
}

impl Secure {
    pub fn open(ctx: &CliContext) -> Result<Self> {
        let server = ctx.server_url()?;
        let session = Session::open(&jig_client::secure::default_dir(), ctx.identity()?)
            .context("opening local MLS state (~/.jig/mls)")?;
        // State an older build filed under a server's own channel's slug is
        // filed under its channel id, once (#432). Pins that do not open now
        // are tried again next time.
        if let Ok(pins) = Pins::load(&Pins::default_path()) {
            for note in session
                .key_by_channel_id(&pins)
                .context("filing local MLS state by channel id")?
            {
                eprintln!("warning: {note}");
            }
        }
        Ok(Self {
            session: Arc::new(session),
            identity: ctx.identity()?,
            base: base_http_url(&server),
            server,
            publish_reachability: ctx.effective().server.publishes_reachability(),
            pinned: tokio::sync::OnceCell::new(),
            forward: tokio::sync::OnceCell::new(),
            forward_broken: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Hold the server to its pin before this process's first request. REST
    /// carries no handshake, so without this an encrypted send, a key-package
    /// fetch or a channel proof would go to whatever answers at the URL. One
    /// signed welcome per process ties them to the server this device pinned,
    /// and pins it on first use. (Binding each REST response to that server
    /// is TLS's job.)
    async fn ensure_pinned(&self) -> Result<()> {
        self.pinned
            .get_or_try_init(|| async {
                let client = connect_pinned(&self.server, self.identity.duplicate()).await?;
                // The welcome just held to the pin proves the audience for
                // this server's request proofs; a server that does not list
                // v2 is refused here, before anything is signed.
                if let Some(welcome) = client.welcome() {
                    let did = jig_client::read_auth::audience_of(welcome)?;
                    crate::cmd::request_proof::remember(
                        &self.server,
                        crate::cmd::request_proof::Trust::Pinned,
                        &did,
                    );
                }
                anyhow::Ok(())
            })
            .await
            .map(|_| ())
            .with_context(|| format!("connecting to {}", self.server))
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    /// The name this device files `reference`'s MLS state under: the
    /// channel's id, for a server's own channels as for carried ones (#432),
    /// so that a slug a server gives to a new channel never finds the old
    /// one's group. `reference` itself while it names no pinned channel.
    pub fn key(&self, reference: &str) -> String {
        let pins = Pins::load(&Pins::default_path()).ok();
        group_name(pins.as_ref(), &self.server, reference)
    }

    /// [`Self::key`] for the channel this server itself orders under `slug`:
    /// `None` when none is pinned, though a channel it carries for another
    /// server may go by the same slug.
    pub fn own_key(&self, slug: &str) -> Option<String> {
        let pins = Pins::load(&Pins::default_path()).ok();
        own_group_name(pins.as_ref(), &self.server, slug)
    }

    /// [`Self::key`], once the channel `reference` names is pinned: proven
    /// from the server's listing if it is not yet. Before a channel's MLS
    /// state is first written, so it is filed under its id from the start.
    pub async fn pin(&self, reference: &str) -> Result<String> {
        let key = self.key(reference);
        if key == reference && !jig_core::canonical_cid::is_canonical_text(reference) {
            self.channel(reference).await?;
            return Ok(self.key(reference));
        }
        Ok(key)
    }

    /// Wait for the channel's commit lock, in this process or any other for
    /// this DID ([`Session::commit_lock`]). Hold it from before a commit,
    /// create or join is prepared until its outcome is settled.
    pub async fn hold(&self, slug: &str) -> Result<CommitLock> {
        let session = Arc::clone(&self.session);
        let (server, slug) = (self.server.clone(), self.pin(slug).await?);
        tokio::task::spawn_blocking(move || session.commit_lock(&server, &slug))
            .await
            .context("waiting for the channel's commit lock")?
            .context("taking the channel's commit lock")
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    async fn http(&self) -> Result<reqwest::Client> {
        crate::cmd::trust::http(&self.server, std::time::Duration::from_secs(15)).await
    }

    async fn refusal(resp: reqwest::Response) -> Refused {
        let status = resp.status().as_u16();
        let body = limits::error_text(resp).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        Refused {
            status,
            code: v["code"].as_str().unwrap_or("HTTP_ERROR").to_string(),
            message: v["message"].as_str().map(str::to_string).unwrap_or(body),
        }
    }

    /// A signed GET returning a JSON document of at most
    /// [`limits::MAX_DOCUMENT_BYTES`].
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.get_json_capped(path, limits::MAX_DOCUMENT_BYTES).await
    }

    /// A signed GET returning JSON of at most `max` bytes.
    pub async fn get_json_capped<T: DeserializeOwned>(&self, path: &str, max: usize) -> Result<T> {
        self.ensure_pinned().await?;
        let url = format!("{}{path}", self.base);
        let http = self.http().await?;
        let resp =
            crate::cmd::request_proof::send(&self.server, &self.identity, "GET", &url, b"", || {
                // History this client reads is held to its chain, moves
                // included: it is served past a `sequencer-set`.
                http.get(&url)
                    .header("jig-capabilities", jig_client::chain::REQUEST_FEATURES)
            })
            .await?;
        if !resp.status().is_success() {
            return Err(Self::refusal(resp).await.into());
        }
        limits::json_capped(resp, max)
            .await
            .with_context(|| format!("reading {url}"))
    }

    /// Submit a signed block through `POST /api/v1/blocks`. A refusal comes
    /// back as a [`Refused`] the caller can branch on.
    pub async fn submit(&self, block: &BuiltBlock) -> Result<String> {
        self.ensure_pinned().await?;
        let url = format!("{}/api/v1/blocks", self.base);
        let body = serde_json::json!({
            "bundle_b64": STANDARD.encode(block.canonical_bytes()),
            "sig_b64": STANDARD.encode(&block.sender_sig),
        });
        let resp = self
            .http()
            .await?
            .post(&url)
            // Outside a connection, the features a hello would ask for
            // (JEP-0014 rule 5): this client labels `public` channels.
            .header("jig-capabilities", jig_core::tier::TIERS_FEATURE)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        if !resp.status().is_success() {
            return Err(Self::refusal(resp).await.into());
        }
        let v: serde_json::Value = limits::json_capped(resp, limits::MAX_DOCUMENT_BYTES)
            .await
            .context("reading the submit result")?;
        Ok(v["block_cid"].as_str().unwrap_or_default().to_string())
    }

    /// The channel as this identity may see it, or `None` if it is not listed
    /// to us (unknown, or restricted and we are not in it).
    ///
    /// Its `suite` is the one the owner signed into the creation block, not
    /// the listing's: a server relabelling a channel would otherwise be taken
    /// at its word by any device that holds no group for it (OP-03). The
    /// creation block is pinned on first sight, so a channel re-created
    /// under the same name is refused rather than silently trusted.
    pub async fn channel(&self, slug: &str) -> Result<Option<ChannelInfo>> {
        self.listed(slug, false).await
    }

    /// [`Self::channel`], for the channel this server itself orders under
    /// `slug`: `None` when it orders none, though it may carry a channel for
    /// another server under the same slug.
    pub async fn own_channel(&self, slug: &str) -> Result<Option<ChannelInfo>> {
        self.listed(slug, true).await
    }

    async fn listed(&self, slug: &str, own_only: bool) -> Result<Option<ChannelInfo>> {
        #[derive(Deserialize)]
        struct Listing {
            channels: Vec<ChannelInfo>,
        }
        let listing: Listing = self.get_json("/api/v1/channels").await?;
        let ours = Pins::load(&Pins::default_path())?
            .server(&self.server)
            .map(|p| p.sequencers())
            .unwrap_or_default();
        let channels = if own_only {
            ordered_here(listing.channels, &ours)
        } else {
            listing.channels
        };
        let Some(mut info) = pick(channels, slug, &ours)? else {
            return Ok(None);
        };
        let pin = self.proven(&info).await?;
        self.anchor(&info)?;
        if pin.suite != info.suite {
            eprintln!(
                "warning: the server lists {slug} as `{}`, but its owner created it `{}`; \
                 going by the owner",
                info.suite, pin.suite
            );
        }
        info.suite = pin.suite;
        // The CLI speaks `none` and `mls`. Another suite's channel can be
        // neither posted to nor managed from here, and is never treated as
        // plaintext.
        if !matches!(info.suite.as_str(), "none" | "mls") {
            anyhow::bail!(
                "{slug} uses encryption suite `{}`, which this client does not support",
                info.suite
            );
        }
        Ok(Some(info))
    }

    /// Pin which server orders `info`'s channel. One the listing says
    /// another server orders is carried for that owner only if the owner's
    /// signed offer to this server proves it ([`prove_carried`]); then its
    /// records are held to the owner. A server cannot name another
    /// sequencer, or take a carried channel back as its own
    /// ([`Pins::anchor_channel`]).
    fn anchor(&self, info: &ChannelInfo) -> Result<()> {
        let mut pins = Pins::load(&Pins::default_path())?;
        let ours = pins
            .server(&self.server)
            .map(|p| p.sequencers())
            .unwrap_or_default();
        let other = names_another_server(&ours, &info.sequencer).then_some(info.sequencer.as_str());
        // A channel whose chain this device verified moving to the server
        // listed (JEP-0005 rule 11a) is held to that server by the chain's
        // moves; its pin stays as it was pinned.
        if let Some(moved_to) = pins.moved_to(&self.server, &info.id) {
            let listed = match other {
                Some(sequencer) => !names_another_server(&[moved_to.to_string()], sequencer),
                None => !names_another_server(&ours, moved_to),
            };
            if listed {
                if let Some(sequencer) = other {
                    prove_carried_after_move(
                        &self.server,
                        &info.slug,
                        &info.id,
                        sequencer,
                        &ours,
                        info.share.as_deref(),
                        moved_to,
                    )?;
                }
                return Ok(());
            }
        }
        let owner = match other {
            Some(sequencer) => Some(prove_carried(
                &self.server,
                &info.slug,
                &info.id,
                sequencer,
                &ours,
                info.share.as_deref(),
                &info.share_key_links,
            )?),
            None => None,
        };
        if pins.anchor_carried(&self.server, &info.slug, &info.id, owner.as_ref())? {
            eprintln!(
                "note: {} is now carried here for {}, which orders it; its history is checked \
                 against that server's records from now on",
                info.slug,
                owner.as_ref().map(|o| o.did.as_str()).unwrap_or_default()
            );
        }
        Ok(())
    }

    /// What `info`'s creation block proves, from the pin when it names the
    /// same block, else fetched, verified and pinned.
    async fn proven(&self, info: &ChannelInfo) -> Result<ChannelPin> {
        let mut pins = Pins::load(&Pins::default_path())?;
        // Pinned by id, and listed under the slug it was pinned as.
        if let Some(pin) = pins.channel_listed_as(&self.server, &info.id, &info.slug)? {
            return Ok(pin.clone());
        }
        if info.id.is_empty() {
            anyhow::bail!(
                "the server does not say which block created {}, so whether it is encrypted \
                 cannot be checked",
                info.slug
            );
        }
        #[derive(Deserialize)]
        struct Served {
            bundle_b64: String,
            sig_b64: Option<String>,
        }
        let served: Served = self
            .get_json_capped(
                &format!("/api/v1/blocks/{}", info.id),
                limits::history_page_bytes(1),
            )
            .await
            .with_context(|| format!("fetching the block that created {}", info.slug))?;
        let sig = served.sig_b64.with_context(|| {
            format!("the server serves {}'s creation block unsigned", info.slug)
        })?;
        // Who may order it: this server, under any DID its key links lead
        // from, or the owner the listing names for a carried channel, which
        // `anchor` then proves.
        let ours = pins
            .server(&self.server)
            .map(|p| p.sequencers())
            .unwrap_or_default();
        // Which server orders it is part of what is pinned: a carried channel
        // may share its slug with one of this server's own (#388), and only
        // a channel of the same orderer can replace it. The owner is taken
        // only as its signed offer proves ([`Self::anchor`] does the same),
        // and the creation block may name it under a DID its key links lead
        // from (#375).
        let owner = if names_another_server(&ours, &info.sequencer) {
            Some(prove_carried(
                &self.server,
                &info.slug,
                &info.id,
                &info.sequencer,
                &ours,
                info.share.as_deref(),
                &info.share_key_links,
            )?)
        } else {
            None
        };
        let orders = match &owner {
            Some(owner) => jig_client::pins::dids_along(&owner.links, &owner.did),
            None => ours.clone(),
        };
        let mut proven =
            prove_channel_ordered_by(&info.slug, &info.id, &served.bundle_b64, &sig, &orders)?;
        proven.sequencer = owner.as_ref().map(|o| o.did.clone());
        let pinned = pins.check_channel(&self.server, &info.slug, proven)?;
        if let Some(owner) = &owner
            && pinned.sequencer.as_deref() == Some(owner.did.as_str())
        {
            pins.keep_carried_links(&self.server, &info.id, &owner.links)?;
        }
        if let Some(owner) = &pinned.sequencer {
            eprintln!(
                "note: {} is now carried here for {owner}, which orders it; its history is \
                 checked against that server's records from now on",
                info.slug
            );
        }
        Ok(pinned)
    }

    /// The id of the MLS group `info`'s creation block starts (#455): the
    /// block is fetched and held to the channel's id, which it must hash to.
    pub async fn created_group_id(&self, info: &ChannelInfo) -> Result<Option<Vec<u8>>> {
        #[derive(Deserialize)]
        struct Served {
            bundle_b64: String,
        }
        let served: Served = self
            .get_json_capped(
                &format!("/api/v1/blocks/{}", info.id),
                limits::history_page_bytes(1),
            )
            .await
            .with_context(|| format!("fetching the block that created {}", info.slug))?;
        creation_group_id(&info.id, &served.bundle_b64)
            .with_context(|| format!("reading the block that created {}", info.slug))
    }

    /// Whether what is sent to `slug` must be encrypted. This device's own
    /// MLS state outranks the server's listing ([`must_encrypt`]), and the
    /// listing's suite is the owner's signed one ([`Self::channel`]). A
    /// channel no longer listed to us is still what this device pinned.
    /// Failing to find out is an error, never a reason to send in the clear.
    /// Also returns the tier the server lists, for a label (JEP-0014 rule 5).
    pub async fn encrypted_with_tier(&self, slug: &str) -> Result<(bool, Option<String>)> {
        let held = self.session.has_group(&self.server, &self.key(slug))?;
        let pinned = Pins::load(&Pins::default_path())?
            .channel(&self.server, slug)
            .map(ChannelPin::encrypted);
        let info = self.channel(slug).await?;
        let tier = info.as_ref().and_then(|c| c.tier.clone());
        let listed = info.map(|c| c.encrypted()).or(pinned);
        if held && listed == Some(false) {
            eprintln!(
                "warning: the server lists {slug} as unencrypted, but this device holds its \
                 MLS group; treating it as encrypted"
            );
        }
        Ok((must_encrypt(held, listed), tier))
    }

    /// Keep enough key packages published that others can add us while we
    /// are offline, plus one last-resort package so we are never unreachable.
    /// `false` where this server keeps no stock for us: custody and local
    /// adds are both ended there (JEP-0017 rule 19).
    pub async fn ensure_key_packages(&self) -> Result<bool> {
        #[derive(Deserialize)]
        struct Stock {
            available: u64,
            last_resort: bool,
        }
        let did = self.session.did().to_string();
        let server_did = self.server_did().await?;
        // Custody withdrawn and local adds ended: the server keeps no stock
        // for this identity and refuses uploads (JEP-0017 rule 19). The
        // reachability check still runs: it is how this device learns that
        // another restored custody (`ensure_reachable` keeps a withdrawal as
        // it is).
        let ended = |s: &Self| -> Result<bool> {
            Ok(s.server_state(&server_did)?
                .is_some_and(|s| s.stock_ended()))
        };
        if ended(self)? {
            self.ensure_reachable().await?;
            if ended(self)? {
                // Finishes a deletion an earlier run left undone.
                self.end_stock_if_purged(&server_did).await?;
                return Ok(false);
            }
        }
        let stock: Stock = self
            .get_json(&format!("/api/v1/mls/key-packages/{did}/stock"))
            .await?;
        let mut packages = Vec::new();
        if stock.available < KEY_PACKAGE_LOW_WATER {
            packages.extend(
                self.session
                    .key_packages((KEY_PACKAGE_TARGET - stock.available) as usize, false)?,
            );
        }
        if !stock.last_resort {
            packages.extend(self.session.key_packages(1, true)?);
        }
        if packages.is_empty() {
            self.ensure_reachable().await?;
            return Ok(true);
        }
        let stocked_before = self.stock_refs(&server_did)?;
        if !self.publish_packages(&packages).await? {
            // Another of this identity's devices ended both custody and local
            // adds here, and the server deleted the stock (rule 19): this
            // device's keys for it are of no further use (rule 32).
            eprintln!(
                "note: {} keeps no key packages for you any more (custody and local adds \
                 were both ended, from another device); deleting this device's keys for them",
                self.server
            );
            self.delete_stock_keys(&server_did, &stocked_before)?;
            return Ok(false);
        }
        self.ensure_reachable().await?;
        Ok(true)
    }

    /// The DID this device pinned for its server.
    async fn server_did(&self) -> Result<String> {
        self.ensure_pinned().await?;
        Pins::load(&Pins::default_path())?
            .offer(&self.server)
            .pinned_server_did
            .with_context(|| format!("no DID is pinned for {}", self.server))
    }

    /// This device's per-server state file ([`ServerStates`]).
    fn server_states_path(&self) -> std::path::PathBuf {
        ServerStates::default_path(self.session.did())
    }

    /// The reachability record this server keeps for us, as we see it: a
    /// withdrawal included, which the server serves to its DID alone.
    async fn kept_record(&self) -> Result<Kept> {
        let did = self.session.did().to_string();
        match self
            .get_json::<RecordBody>(&format!("/api/v1/reach/{did}"))
            .await
        {
            Ok(body) => Ok(STANDARD
                .decode(body.record_b64)
                .ok()
                .and_then(|e| ReachabilityRecord::from_envelope(&e).ok())
                .filter(|r| r.did == did)
                .map_or(Kept::None, Kept::Record)),
            Err(e) => match e.downcast_ref::<Refused>() {
                Some(r) if r.code == "NO_RECORD" => Ok(Kept::None),
                // A server from before reachability records has no route for
                // them: nothing kept there, and nothing wrong.
                Some(r) if r.status == 404 || r.status == 405 => Ok(Kept::Unsupported),
                _ => Err(e),
            },
        }
    }

    /// Keep a reachability record on this server that lists it (JEP-0004
    /// rule 21), so members of other servers can ask it for our key packages
    /// ([`Self::key_package_from_custodians`]). Servers the record kept here
    /// already listed stay listed; this server is put first.
    ///
    /// Never after custody here was withdrawn (JEP-0017 R1): only
    /// [`Self::set_custody`] lists this server again. A withdrawal made on
    /// another device is learned here, from the record the server keeps, and
    /// this device then rotates its own keys (rule 32), since only it holds
    /// them. Nothing, with `[server] publish_reachability = false`.
    pub async fn ensure_reachable(&self) -> Result<()> {
        if !self.publish_reachability {
            return Ok(());
        }
        let kept = match self.kept_record().await? {
            Kept::Unsupported => return Ok(()),
            Kept::None => None,
            Kept::Record(r) => Some(r),
        };
        // After the read, not before: a WRONG_AUDIENCE retry moves the pin
        // along the server's key link, and the record is held to the DID that
        // answered it. Against the DID before the move, a record listing the
        // server would read as a withdrawal.
        let server_did = self.server_did().await?;
        let here = (server_did.clone(), self.base.clone());
        let path = self.server_states_path();
        let mine = ServerStates::load(&path)?
            .get(&server_did)
            .and_then(|s| s.reach);
        match (&kept, mine) {
            // The server keeps a record without itself only as a withdrawal.
            (Some(k), _) if !k.servers.iter().any(|(s, _)| *s == server_did) => {
                if !mine.is_some_and(|m| m.withdrawn && m.seq >= k.seq) {
                    eprintln!(
                        "note: custody of your key packages at {} was withdrawn, from another device; deleting this device's keys for packages it released",
                        self.server
                    );
                    self.rotate_after_withdrawal(&server_did).await?;
                    self.note_reach(&server_did, k.seq, true)?;
                    self.end_stock_if_purged(&server_did).await?;
                }
                return Ok(());
            }
            (Some(k), _) if k.servers.contains(&here) => {
                // Listed here; a higher seq than ours is another device's
                // record, an undo included.
                if mine.is_none_or(|m| m.seq < k.seq || m.withdrawn) {
                    self.note_reach(&server_did, k.seq, false)?;
                }
                return Ok(());
            }
            // Withdrawn by this device, and the server keeps no record:
            // still withdrawn.
            (None, Some(m)) if m.withdrawn => return Ok(()),
            _ => {}
        }
        let mut servers = vec![here];
        let mut floor = mine.map_or(0, |m| m.seq);
        if let Some(kept) = kept {
            floor = floor.max(kept.seq);
            // Never list again a server this device withdrew from.
            let states = ServerStates::load(&path)?;
            servers.extend(kept.servers.into_iter().filter(|(s, _)| {
                *s != server_did && !states.get(s).is_some_and(|st| st.custody_withdrawn())
            }));
        }
        let record = self.sign_record(servers, floor);
        self.put_record(&self.base, &record).await?;
        self.note_reach(&server_did, record.seq, false)
    }

    /// A record of `servers` above `floor` and above any this device signed
    /// before: a record kept on another server may have reached a higher
    /// seq, and the clock keeps each new one above it.
    fn sign_record(&self, servers: Vec<(String, String)>, floor: u64) -> ReachabilityRecord {
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        self.identity
            .sign_reachability(servers, floor.saturating_add(1).max(now))
    }

    /// Put `record` on the server at `base`. The record is signed by us; the
    /// route needs no request signature. A server that keeps a record at the
    /// same or a higher seq answers `stored: false`, which is an error here:
    /// the record did not take effect there.
    async fn put_record(&self, base: &str, record: &ReachabilityRecord) -> Result<()> {
        #[derive(Deserialize)]
        struct Stored {
            stored: bool,
            seq: u64,
        }
        let url = format!("{base}/api/v1/reach/{}", record.did);
        let resp = crate::cmd::trust::http(base, std::time::Duration::from_secs(15))
            .await?
            .put(&url)
            .json(&serde_json::json!({"record_b64": STANDARD.encode(&record.envelope)}))
            .send()
            .await
            .with_context(|| format!("PUT {url}"))?;
        if !resp.status().is_success() {
            return Err(Self::refusal(resp).await.into());
        }
        let answer: Stored = limits::json_capped(resp, limits::MAX_DOCUMENT_BYTES)
            .await
            .with_context(|| format!("reading {url}"))?;
        if !answer.stored {
            anyhow::bail!(
                "{base} kept its record at seq {}, not this one (seq {})",
                answer.seq,
                record.seq
            );
        }
        Ok(())
    }

    /// The servers in `servers` that still list themselves for us: those
    /// this device withdrew from, or whose own kept record leaves them out
    /// (a withdrawal from another device), are dropped. Copying an older
    /// record's list would otherwise list them again, and sending it to them
    /// would restore custody there unasked. A server that cannot be asked
    /// stays listed, but comes back among the unchecked: the new record is
    /// not sent to it, since it may keep a withdrawal this device has not seen.
    async fn still_custodians(
        &self,
        servers: Vec<(String, String)>,
    ) -> (Vec<(String, String)>, std::collections::HashSet<String>) {
        let states = ServerStates::load(&self.server_states_path()).unwrap_or_default();
        let did = self.session.did().to_string();
        let mut out = Vec::new();
        let mut unchecked = std::collections::HashSet::new();
        for (server_did, url) in servers {
            if states
                .get(&server_did)
                .is_some_and(|s| s.custody_withdrawn())
            {
                continue;
            }
            let reach = format!("{}/api/v1/reach/{did}", base_http_url(&url));
            let http = match crate::cmd::trust::http(&url, std::time::Duration::from_secs(15)).await
            {
                Ok(client) => client,
                Err(_) => {
                    unchecked.insert(server_did.clone());
                    out.push((server_did, url));
                    continue;
                }
            };
            // Addressed to the DID the custodian's own welcome proves, which
            // must list jig-request-auth-v2 (JEP-0015 rule 24), and pinned
            // nowhere: a custodian is asked, and trusted with nothing more. A
            // custodian that cannot be handshaken with, or refuses, is left
            // unchecked like one that cannot be reached.
            let answer = match crate::cmd::request_proof::send_as(
                &url,
                crate::cmd::request_proof::Trust::Unpinned,
                &self.identity,
                "GET",
                &reach,
                b"",
                || http.get(&reach),
            )
            .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    let body = if status.is_success() {
                        limits::read_capped(resp, limits::MAX_DOCUMENT_BYTES)
                            .await
                            .ok()
                    } else {
                        None
                    };
                    judge_kept_answer(Some((status, body.as_deref())), &did, &server_did)
                }
                Err(_) => judge_kept_answer(None, &did, &server_did),
            };
            match answer {
                KeptAnswer::Withdrawn => {}
                KeptAnswer::Listed => out.push((server_did, url)),
                KeptAnswer::Unchecked => {
                    unchecked.insert(server_did.clone());
                    out.push((server_did, url));
                }
            }
        }
        (out, unchecked)
    }

    fn note_reach(&self, server_did: &str, seq: u64, withdrawn: bool) -> Result<()> {
        let base = self.base.clone();
        ServerStates::update(&self.server_states_path(), |s| {
            s.entry(server_did, &base).reach = Some(Reach { seq, withdrawn });
        })?;
        Ok(())
    }

    /// JEP-0017 rules 19 and 32: where this device's state says custody and
    /// local adds are both ended at `server_did`, and the server confirms its
    /// stock for us is ended, delete this device's keys for that stock.
    /// The state alone is not enough: another device may have undone either
    /// since, and the server then still hands out packages whose keys this
    /// would delete. Nor is an empty stock: a released package is handed
    /// again to a repeated request. A server that does not say (`stocked`
    /// absent) predates R2 and never ends a stock. Repeatable, so a
    /// deletion cut short runs again.
    async fn end_stock_if_purged(&self, server_did: &str) -> Result<()> {
        #[derive(Deserialize)]
        struct Stock {
            #[serde(default = "stocked_by_default")]
            stocked: bool,
        }
        fn stocked_by_default() -> bool {
            true
        }
        if !self
            .server_state(server_did)?
            .is_some_and(|s| s.stock_ended())
        {
            return Ok(());
        }
        // Taken before the server is asked: what it says is ended is the
        // stock as of then, not packages stocked after (see
        // `delete_stock_keys`).
        let refs = self.stock_refs(server_did)?;
        let did = self.session.did().to_string();
        let stock: Stock = self
            .get_json(&format!("/api/v1/mls/key-packages/{did}/stock"))
            .await?;
        if !stock.stocked {
            self.delete_stock_keys(server_did, &refs)?;
        }
        Ok(())
    }

    /// End (`on = false`) or restore custody of our key packages at this
    /// server: JEP-0017 R1 and its undo (rules 12–15). The new record goes
    /// here, then, best effort, to every other server it lists, which should
    /// drop or list this one too. Ending custody also rotates this device's
    /// keys (rule 32).
    pub async fn set_custody(&self, on: bool) -> Result<CustodyChange> {
        let server_did = self.server_did().await?;
        let here = (server_did.clone(), self.base.clone());
        let kept = match self.kept_record().await? {
            Kept::Unsupported => anyhow::bail!(
                "{} keeps no reachability records, so it is no custodian of your key packages",
                self.server
            ),
            Kept::None => None,
            Kept::Record(r) => Some(r),
        };
        let mine = ServerStates::load(&self.server_states_path())?
            .get(&server_did)
            .and_then(|s| s.reach);
        let floor = mine
            .map_or(0, |m| m.seq)
            .max(kept.as_ref().map_or(0, |k| k.seq));
        let others: Vec<_> = kept
            .map(|k| k.servers)
            .unwrap_or_default()
            .into_iter()
            .filter(|(s, _)| *s != server_did)
            .collect();
        let (others, unchecked) = self.still_custodians(others).await;
        // Sent only to servers whose own state was read.
        let (send_to, skipped) = split_unchecked(&others, &unchecked);
        let mut change = CustodyChange {
            elsewhere: skipped
                .into_iter()
                .map(|(_, url)| {
                    (
                        url,
                        Err("its record could not be read, so the new one was not sent".into()),
                    )
                })
                .collect(),
            ..CustodyChange::default()
        };
        if on {
            let mut servers = vec![here];
            servers.extend(others.iter().cloned());
            let record = self.sign_record(servers, floor);
            self.put_record(&self.base, &record).await?;
            self.note_reach(&server_did, record.seq, false)?;
            change.seq = record.seq;
            change
                .elsewhere
                .extend(self.put_elsewhere(&send_to, &record).await);
            return Ok(change);
        }
        let record = self.sign_record(others.clone(), floor);
        if floor > 0 {
            self.put_record(&self.base, &record).await?;
        }
        // With no record here ever, custody was never in force: noting the
        // withdrawal keeps this device from listing the server later.
        change.seq = record.seq;
        change
            .elsewhere
            .extend(self.put_elsewhere(&send_to, &record).await);
        // This device rotated for the withdrawal in force already (the state
        // is noted only once a rotation finished): rotating again would delete
        // the key of the last-resort package stocked then, which local adds
        // may have used since. Only retirements left pending are finished.
        change.deleted = if mine.is_some_and(|m| m.withdrawn) {
            self.finish_retirements(&server_did)?
        } else {
            self.rotate_after_withdrawal(&server_did).await?
        };
        self.note_reach(&server_did, record.seq, true)?;
        self.end_stock_if_purged(&server_did).await?;
        Ok(change)
    }

    /// Put `record` on each of `servers`, best effort: what each answered.
    async fn put_elsewhere(
        &self,
        servers: &[(String, String)],
        record: &ReachabilityRecord,
    ) -> Vec<(String, Result<(), String>)> {
        let mut out = Vec::new();
        for (_, url) in servers {
            let base = base_http_url(url);
            let result = self
                .put_record(&base, record)
                .await
                .map_err(|e| format!("{e:#}"));
            out.push((url.clone(), result));
        }
        out
    }

    /// JEP-0017 rule 32, on R1: publish a fresh last-resort package here,
    /// then delete the private init keys of the old one and of each ordinary
    /// package the release log shows went to another server's requester.
    /// Packages taken by this server's own route stay, for local adds.
    /// Returns how many keys this device deleted.
    ///
    /// The old last-resort reference is first moved to the entry's
    /// `retiring` list, so a run cut short after the fresh one is published
    /// still deletes the old key when it runs again.
    async fn rotate_after_withdrawal(&self, server_did: &str) -> Result<usize> {
        let mut dead = self.custody_releases().await?;
        let path = self.server_states_path();
        let base = self.base.clone();
        ServerStates::update(&path, |s| {
            let entry = s.entry(server_did, &base);
            if let Some(old) = entry.last_resort.take()
                && !entry.retiring.contains(&old)
            {
                entry.retiring.push(old);
            }
        })?;
        let fresh = self.session.key_packages(1, true)?;
        let fresh_ref = jig_mls::delivery::validate_key_package(&fresh[0])?.reference;
        // Refused only with local adds ended too: its key is deleted then and
        // nothing is recorded as stocked, and `note_reach` deletes every other
        // key stocked here.
        self.publish_packages(&fresh).await?;
        dead.retain(|r| *r != fresh_ref);
        let deleted = self.session.forget_key_packages(&dead)?;
        ServerStates::update(&path, |s| {
            let entry = s.entry(server_did, &base);
            let gone: std::collections::HashSet<String> = dead.iter().map(hex::encode).collect();
            entry.packages.retain(|p| !gone.contains(p));
        })?;
        Ok(deleted + self.finish_retirements(server_did)?)
    }

    /// Delete the keys of the packages `server_did`'s entry lists as
    /// `retiring`, then clear the list. Repeatable.
    fn finish_retirements(&self, server_did: &str) -> Result<usize> {
        let path = self.server_states_path();
        let pending: Vec<String> = ServerStates::load(&path)?
            .get(server_did)
            .map(|s| s.retiring.clone())
            .unwrap_or_default();
        if pending.is_empty() {
            return Ok(0);
        }
        let refs: Vec<Vec<u8>> = pending.iter().filter_map(|h| hex::decode(h).ok()).collect();
        let deleted = self.session.forget_key_packages(&refs)?;
        ServerStates::update(&path, |s| {
            if let Some(entry) = s.servers.get_mut(server_did) {
                entry.retiring.retain(|r| !pending.contains(r));
            }
        })?;
        Ok(deleted)
    }

    /// The references this device has recorded as stocked at `server_did`
    /// (packages, last resort, retiring), as lowercase hex.
    fn stock_refs(&self, server_did: &str) -> Result<std::collections::BTreeSet<String>> {
        Ok(ServerStates::load(&self.server_states_path())?
            .get(server_did)
            .map(|s| {
                s.packages
                    .iter()
                    .chain(&s.last_resort)
                    .chain(&s.retiring)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    /// JEP-0017 rule 32, under R1 and R2 together and on R3: delete the
    /// private init keys of the packages `refs` names, the stock this device
    /// had at `server_did` when the server said it was ended
    /// ([`Self::stock_refs`], taken before asking), and forget those
    /// references. Packages another `jig` process on this device stocked
    /// since (after undoing R1 or R2) are not in `refs`, and keep their keys.
    /// Local only, and repeatable. Returns how many keys were deleted.
    fn delete_stock_keys(
        &self,
        server_did: &str,
        refs: &std::collections::BTreeSet<String>,
    ) -> Result<usize> {
        let bytes: Vec<Vec<u8>> = refs.iter().filter_map(|h| hex::decode(h).ok()).collect();
        let deleted = self.session.forget_key_packages(&bytes)?;
        ServerStates::update(&self.server_states_path(), |s| {
            if let Some(state) = s.servers.get_mut(server_did) {
                forget_stock_refs(state, refs);
            }
        })?;
        Ok(deleted)
    }

    /// The references of every package this server released to a custody
    /// request, from our release log, every page. An entry from a server
    /// before rule 32 carries no `kind`: it is `local` when it names no
    /// channel and no request, as #440 logged a local take.
    async fn custody_releases(&self) -> Result<Vec<Vec<u8>>> {
        let did = self.session.did().to_string();
        walk_release_log(&self.server, |offset| {
            let path = format!("/api/v1/custody/{did}/releases?offset={offset}");
            async move {
                match self.get_json::<ReleaseLog>(&path).await {
                    Ok(log) => Ok(Some(log.releases)),
                    Err(e) => match e.downcast_ref::<Refused>() {
                        Some(r) if r.status == 404 || r.status == 405 => Ok(None),
                        _ => Err(e),
                    },
                }
            }
        })
        .await
    }

    /// Upload `packages` here, and remember their references
    /// ([`ServerStates`]), so their keys can be deleted later (rule 32).
    /// `false`, with their keys deleted, when the server keeps no stock for
    /// this identity (`NOT_STOCKED_HERE`, JEP-0017 rule 19).
    async fn publish_packages(&self, packages: &[Vec<u8>]) -> Result<bool> {
        self.ensure_pinned().await?;
        let url = format!("{}/api/v1/mls/key-packages", self.base);
        let body = serde_json::to_vec(&serde_json::json!({
            "key_packages_b64": packages.iter().map(|p| STANDARD.encode(p)).collect::<Vec<_>>(),
        }))
        .expect("the upload serializes");
        // Signed over the exact body, so the server lets a new last-resort
        // package replace the one it holds (rule 32) and the proof cannot be
        // replayed with other packages; stocking alone would not need it.
        let http = self.http().await?;
        let resp = crate::cmd::request_proof::send(
            &self.server,
            &self.identity,
            "POST",
            &url,
            &body,
            || {
                http.post(&url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body.clone())
            },
        )
        .await?;
        if !resp.status().is_success() {
            let refused = Self::refusal(resp).await;
            if refused.code == "NOT_STOCKED_HERE" {
                let refs = packages
                    .iter()
                    .map(|p| Ok(jig_mls::delivery::validate_key_package(p)?.reference))
                    .collect::<Result<Vec<_>>>()?;
                self.session.forget_key_packages(&refs)?;
                return Ok(false);
            }
            return Err(refused.into());
        }
        let server_did = self.server_did().await?;
        let base = self.base.clone();
        let infos = packages
            .iter()
            .map(|p| jig_mls::delivery::validate_key_package(p))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ServerStates::update(&self.server_states_path(), |s| {
            let entry = s.entry(&server_did, &base);
            for info in infos {
                let reference = hex::encode(&info.reference);
                if info.last_resort {
                    entry.last_resort = Some(reference);
                } else if !entry.packages.contains(&reference) {
                    entry.packages.push(reference);
                }
            }
        })?;
        Ok(true)
    }

    /// End (`allow = false`) or allow again (`allow = true`) local adds at
    /// this server (JEP-0017 R2): while ended, nobody else can add this
    /// identity to a channel the server sequences. Answers the marker the
    /// server keeps afterwards, and records it for this device.
    pub async fn set_local_adds(&self, allow: bool) -> Result<LocalAdds> {
        let did = self.session.did().to_string();
        let server_did = self.server_did().await?;
        let path = self.server_states_path();
        let sent = ServerStates::load(&path)?
            .get(&server_did)
            .and_then(|s| s.local_adds)
            .map_or(0, |l| l.seq);
        // Like reachability records, the clock keeps each marker above any
        // another device of this identity sent.
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        let kept = settle_local_adds(allow, sent.saturating_add(1).max(now), |seq| {
            self.put_local_adds(&did, &server_did, allow, seq)
        })
        .await?;
        ServerStates::update(&path, |s| {
            s.entry(&server_did, &self.base).local_adds = Some(kept);
        })?;
        self.end_stock_if_purged(&server_did).await?;
        Ok(kept)
    }

    async fn put_local_adds(
        &self,
        did: &str,
        server_did: &str,
        allow: bool,
        seq: u64,
    ) -> Result<LocalAdds> {
        #[derive(Deserialize)]
        struct Kept {
            allow: bool,
            seq: u64,
        }
        let marker = self.identity.sign_local_adds(server_did, allow, seq);
        let url = format!("{}/api/v1/local-adds/{did}", self.base);
        let resp = self
            .http()
            .await?
            .put(&url)
            .json(&serde_json::json!({"request_b64": STANDARD.encode(&marker.envelope)}))
            .send()
            .await
            .with_context(|| format!("PUT {url}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND
            || resp.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
        {
            anyhow::bail!(
                "{} does not support ending local adds (JEP-0017)",
                self.server
            );
        }
        if !resp.status().is_success() {
            return Err(Self::refusal(resp).await.into());
        }
        let kept: Kept = limits::json_capped(resp, limits::MAX_DOCUMENT_BYTES)
            .await
            .with_context(|| format!("PUT {url} answered something other than a marker"))?;
        Ok(LocalAdds {
            allow: kept.allow,
            seq: kept.seq,
        })
    }

    /// This device's state at its server ([`ServerStates`]), if it has any.
    fn server_state(&self, server_did: &str) -> Result<Option<ServerState>> {
        Ok(ServerStates::load(&self.server_states_path())?
            .get(server_did)
            .cloned())
    }

    /// One of `did`'s key packages for the channel `channel_id`, asked of
    /// each custodian `record` lists in turn (JEP-0005 rule 21). Each is held
    /// to the server DID the record names by its signed welcome before it is
    /// asked. What comes back is checked here only for being `did`'s package;
    /// the commit that adds it checks its signature again
    /// (`jig_mls::member::Member::add`), so a custodian can withhold a package
    /// but not substitute one.
    pub async fn key_package_from_custodians(
        &self,
        did: &str,
        channel_id: &str,
        record: &ReachabilityRecord,
    ) -> Result<Vec<u8>> {
        let channel_id = cid::Cid::try_from(channel_id)
            .ok()
            .filter(|_| jig_core::canonical_cid::is_canonical_text(channel_id))
            .with_context(|| format!("the channel's id `{channel_id}` is not a canonical CID"))?;
        let tried = match first_release(&record.servers, |server_did, url| {
            self.ask_custodian(did, channel_id, server_did, url)
        })
        .await
        {
            Ok(package) => return Ok(package),
            Err(Asked::Final(e)) => return Err(e),
            Err(Asked::Tried(tried)) => tried,
        };
        if tried.is_empty() {
            anyhow::bail!("{did}'s reachability record lists no servers");
        }
        anyhow::bail!(
            "no server {did} lists released a key package; nothing was changed. Tried:\n{}",
            tried.join("\n")
        )
    }

    async fn ask_custodian(
        &self,
        did: &str,
        channel_id: cid::Cid,
        server_did: &str,
        url: &str,
    ) -> Result<Vec<u8>> {
        prove_server(url, server_did, self.identity.duplicate()).await?;
        // A custodian that asks unknown DIDs for proof of work asks the
        // requester too.
        crate::cmd::admission::ensure_for(url, &self.identity).await?;
        let request = self.identity.sign_kp_request(
            did,
            channel_id,
            server_did,
            rand::random(),
            chrono::Utc::now().timestamp(),
        );
        let endpoint = format!("{}/api/v1/custody/{did}/requests", base_http_url(url));
        let resp = crate::cmd::trust::http(url, std::time::Duration::from_secs(15))
            .await?
            .post(&endpoint)
            .json(&serde_json::json!({"request_b64": STANDARD.encode(&request.envelope)}))
            .send()
            .await
            .with_context(|| format!("POST {endpoint}"))?;
        if !resp.status().is_success() {
            return Err(Self::refusal(resp).await.into());
        }
        #[derive(Deserialize)]
        struct Released {
            key_package_b64: String,
        }
        let released: Released = limits::json_capped(resp, limits::MAX_DOCUMENT_BYTES)
            .await
            .with_context(|| format!("reading {endpoint}"))?;
        let package = STANDARD
            .decode(released.key_package_b64)
            .context("key package is not base64")?;
        let info = jig_mls::delivery::validate_key_package(&package)
            .context("the custodian sent a key package that does not verify")?;
        if info.did != did {
            anyhow::bail!("the custodian sent {}'s key package, not {did}'s", info.did);
        }
        Ok(package)
    }

    pub async fn take_key_package(&self, did: &str) -> Result<Vec<u8>> {
        #[derive(Deserialize)]
        struct Package {
            key_package_b64: String,
        }
        let p: Package = self
            .get_json(&format!("/api/v1/mls/key-packages/{did}"))
            .await?;
        STANDARD
            .decode(p.key_package_b64)
            .context("key package is not base64")
    }

    pub async fn group_info(&self, slug: &str) -> Result<Vec<u8>> {
        #[derive(Deserialize)]
        struct Info {
            group_info_b64: String,
        }
        let i: Info = self
            .get_json(&format!(
                "/api/v1/channels/{}/mls/group-info",
                escape_slug_for_url(slug)
            ))
            .await?;
        STANDARD
            .decode(i.group_info_b64)
            .context("group info is not base64")
    }

    /// Bring the session up to date with the channel: join from a welcome,
    /// follow commits, read messages. Run before building a commit so it is
    /// built on the channel's current epoch. Returns what the blocks it
    /// processed meant.
    ///
    /// Every block is processed once, in history order, from the session's
    /// head ([`Session::head`]) on. That matters for more than cost: MLS lets a
    /// sender's messages be read only a few generations out of order (openmls
    /// keeps 5 behind the newest it has read), so a block skipped now could
    /// never be decrypted later.
    ///
    /// The first sync, with no head yet, reads the newest page, and older
    /// pages until history reaches back to this device's epoch
    /// ([`history_reaches`]) or to the start of the channel.
    pub async fn sync(&self, slug: &str) -> Result<Synced> {
        let key = self.pin(slug).await?;
        let Some(head) = self.session.head(&self.server, &key)? else {
            let delivered = self.newest_to_epoch(slug).await?;
            return self.process(slug, &delivered);
        };
        // Usually the device is a few blocks behind, if any.
        let newest = self
            .history_page(slug, SINCE_HEAD_FIRST_PAGE, Page::Newest)
            .await?;
        if let Some(at) = position_of(&newest, &head) {
            let delivered = &newest[at + 1..];
            self.hold_to_head(slug, delivered)?;
            return self.process(slug, delivered);
        }
        if !self.pages_forward().await? {
            let (delivered, reached) = self.back_to(slug, &head, newest).await?;
            if reached {
                self.hold_to_head(slug, &delivered)?;
            }
            return self.process(slug, &delivered);
        }
        match self.forward_from(slug, &head).await? {
            Forwarded::Done(replayed) => Ok(self.finish(slug, replayed)),
            Forwarded::Broken {
                mut replayed,
                head,
                why,
            } => {
                eprintln!(
                    "warning: {}'s history of {slug} does not continue from this device's \
                     last block ({why}); reading it back instead",
                    self.server
                );
                // Not again in this process: a server that advertises `after`
                // and breaks it costs a little time, never a message.
                self.forward_broken.store(true, Ordering::Relaxed);
                self.read_back(slug, &mut replayed, &head).await?;
                Ok(self.finish(slug, replayed))
            }
            Forwarded::Unsequenced { mut replayed, head } => {
                self.read_back(slug, &mut replayed, &head).await?;
                Ok(self.finish(slug, replayed))
            }
        }
    }

    /// Read what came after `head` the way a server without `after` is read
    /// (#348), all at once, into `replayed`, and move the head past it.
    async fn read_back(&self, slug: &str, replayed: &mut Replayed, head: &str) -> Result<()> {
        let newest = self
            .history_page(slug, SINCE_HEAD_FIRST_PAGE, Page::Newest)
            .await?;
        let (delivered, reached) = match position_of(&newest, head) {
            Some(at) => (newest[at + 1..].to_vec(), true),
            None => self.back_to(slug, head, newest).await?,
        };
        if reached {
            self.hold_to_head(slug, &delivered)?;
        }
        self.replay_into(slug, replayed, &delivered);
        self.move_head(slug, &delivered)
    }

    /// Replay `delivered` and move the head to its newest block.
    fn process(&self, slug: &str, delivered: &[DeliveredBlock]) -> Result<Synced> {
        let synced = self.replay(slug, delivered);
        self.move_head(slug, delivered)?;
        Ok(synced)
    }

    /// The error for `slug` stopped at the critical block `stop`, kept as
    /// [`crate::cmd::upgrade::stop_at`] keeps a reader's.
    fn stopped_at(&self, slug: &str, stop: &jig_client::open::OpenError) -> anyhow::Error {
        crate::cmd::upgrade::stop_at(
            &jig_client::upgrade_stops::UpgradeStops::default_path(),
            &self.server,
            slug,
            stop,
        )
    }

    /// Move the head to the newest block of `delivered`, with its record.
    fn move_head(&self, slug: &str, delivered: &[DeliveredBlock]) -> Result<()> {
        // Never past a block this reader stopped at.
        let (delivered, _) = before_stop(delivered);
        if let Some((d, newest)) = delivered
            .iter()
            .rev()
            .find_map(|d| placed_cid(d).map(|cid| (d, cid)))
        {
            self.session
                .set_head(&self.server, &self.key(slug), &newest, d.ingest.as_ref())?;
        }
        Ok(())
    }

    /// Read forward from `head` a page at a time, oldest first, until a page
    /// comes back empty. Each page is processed and the head moved past it
    /// before the next is fetched, so one page is held at a time and a sync
    /// cut short resumes where it stopped. No cap on how far: nothing is
    /// skipped however long the device was away.
    ///
    /// The server's word that it pages forward is unsigned, so every page is
    /// held to the chain from the head before any of it is read: on a
    /// sequenced channel each record must be the next one
    /// ([`ChannelChain::accept`]). Where the head has no record (history from
    /// before records, or a head an older build saved), the block a page
    /// starts after must be the cursor, asked for with `before=` ([`Self::
    /// follows`]); once a page's newest block has a record, the chain holds
    /// the rest. A page that fails either ends the walk as
    /// [`Forwarded::Broken`], from the last block read.
    ///
    /// Each page is put in MLS order on its own ([`replay_order`]). A message
    /// whose epoch's commit ended the page before is still read: openmls
    /// keeps past epochs (`max_past_epochs`).
    async fn forward_from(&self, slug: &str, head: &str) -> Result<Forwarded> {
        let mut replayed = Replayed::default();
        let mut cursor = head.to_string();
        let mut chain = self.chain_from_head(slug)?;
        loop {
            let broken = |replayed, why: String| Forwarded::Broken {
                replayed,
                head: cursor.clone(),
                why,
            };
            let page = match self
                .history_page(slug, MAX_HISTORY_PAGE, Page::After(&cursor))
                .await
            {
                Ok(page) => page,
                Err(e)
                    if e.downcast_ref::<Refused>()
                        .is_some_and(|r| r.code == "BAD_CURSOR") =>
                {
                    return Ok(broken(replayed, "it does not know that block".into()));
                }
                Err(e) => return Err(e),
            };
            if page.is_empty() {
                return Ok(Forwarded::Done(replayed));
            }
            let continued = match chain.as_mut() {
                Some(chain) => continues(chain, &page),
                None if position_of(&page, &cursor).is_some() => {
                    Err("a page after a block holds that block".to_string())
                }
                None => match self.follows(slug, &cursor, &page).await? {
                    // The cursor's own record, from the server: the chain
                    // starts there and holds this page as it would have.
                    Ok(Some(mut anchored)) => {
                        let held = continues(&mut anchored, &page);
                        chain = Some(anchored);
                        held
                    }
                    // No records to page by: read it back, as one replay.
                    Ok(None) => {
                        return Ok(Forwarded::Unsequenced {
                            replayed,
                            head: cursor,
                        });
                    }
                    Err(why) => Err(why),
                },
            };
            if let Err(why) = continued {
                return Ok(broken(replayed, why));
            }
            // Whatever the chain says, a walk forward never meets a block
            // twice: one that does would never end.
            if page
                .iter()
                .any(|d| open(d).is_ok_and(|o| replayed.cids.contains(&o.cid)))
            {
                return Ok(broken(
                    replayed,
                    "a page repeats blocks already read".into(),
                ));
            }
            self.replay_into(slug, &mut replayed, &page);
            if replayed.stopped.is_some() {
                self.move_head(slug, &page)?;
                return Ok(Forwarded::Done(replayed));
            }
            // A page of only non-critical blocks of unknown kinds moves the
            // cursor past them too, or the blocks after them are never reached.
            let Some(last) = page.iter().rev().find_map(placed_cid) else {
                return Ok(Forwarded::Done(replayed));
            };
            self.move_head(slug, &page)?;
            cursor = last;
            if chain.is_none() {
                chain = self.chain_from_head(slug)?;
            }
        }
    }

    /// The channel's chain as this device last read it, from its head's
    /// record: `None` where the head has none.
    fn chain_from_head(&self, slug: &str) -> Result<Option<ChannelChain>> {
        Ok(self
            .session
            .head_record(&self.server, &self.key(slug))?
            .and_then(|h| h.record.clone().map(|r| (h, r)))
            .map(|(h, r)| {
                ChannelChain::across(&r.channel_id, self.sequencers(&r), Some(h))
                    .with_owners(self.owners(&r.channel_id))
            }))
    }

    /// Who may move `channel_id`'s sequencer, for [`ChannelChain`]: the
    /// channel's owner as this device pinned it from the creation block
    /// (JEP-0005 rule 11a).
    fn owners(&self, channel_id: &str) -> Vec<String> {
        Pins::load(&Pins::default_path())
            .ok()
            .and_then(|pins| pins.owners(&self.server).remove(channel_id))
            .unwrap_or_default()
    }

    /// Whether `page` starts right after `cursor`, with no chain on this
    /// device to say so: the block just before the page's first must be
    /// `cursor`. A server that ignored `after` and sent a later page fails
    /// this.
    ///
    /// That alone shows only that the server answers consistently: one that
    /// skips a block can name the cursor as the block before. So when the
    /// cursor comes back with its record, the record must be the cursor's
    /// and signed by the channel's sequencer ([`sequencers_for`]), and the
    /// chain anchored on it is returned for the page to be held to. With no
    /// record, `None`: the history has none to page by, and is read back.
    async fn follows(
        &self,
        slug: &str,
        cursor: &str,
        page: &[DeliveredBlock],
    ) -> Result<Result<Option<ChannelChain>, String>> {
        let Some(first) = page.first().and_then(placed_cid) else {
            return Ok(Err("a page's first block does not open".into()));
        };
        let before = match self.history_page(slug, 1, Page::Before(&first)).await {
            Ok(before) => before,
            Err(e)
                if e.downcast_ref::<Refused>()
                    .is_some_and(|r| r.code == "BAD_CURSOR") =>
            {
                return Ok(Err("it does not know a block it sent".into()));
            }
            Err(e) => return Err(e),
        };
        let Some(at) = position_of(&before, cursor) else {
            return Ok(Err("a page after a block does not start after it".into()));
        };
        let Some(record) = &before[at].ingest else {
            return Ok(Ok(None));
        };
        let mut chain = ChannelChain::across(&record.channel_id, self.sequencers(record), None);
        match chain.accept_live(record, Some(cursor)) {
            Ok(_) => Ok(Ok(Some(chain))),
            Err(e) => Ok(Err(format!(
                "the record it sent for this device's last block: {e}"
            ))),
        }
    }

    /// Hold `delivered`, the blocks after the head however they were read,
    /// to the chain from the head, and warn when it breaks. Nothing is
    /// left to read it from instead: the blocks are still processed, and a
    /// message the server left out may never be readable on this device.
    fn hold_to_head(&self, slug: &str, delivered: &[DeliveredBlock]) -> Result<()> {
        if let Some(mut chain) = self.chain_from_head(slug)?
            && let Err(why) = continues(&mut chain, delivered)
        {
            eprintln!(
                "warning: {}'s history of {slug} after this device's last block is not \
                 whole ({why}); a message in it may never be readable on this device",
                self.server
            );
        }
        Ok(())
    }

    /// The DIDs the sequencer that signed `record` has signed as, along the
    /// key links this device follows; at least `record`'s own.
    fn sequencers(&self, record: &jig_client::chain::IngestRecord) -> Vec<String> {
        let pins = Pins::load(&Pins::default_path()).ok();
        sequencers_for(
            pins.as_ref(),
            &self.server,
            &record.channel_id,
            &record.sequencer,
        )
    }

    /// The blocks after `head`, oldest first, for a server that cannot page
    /// forward: pages back from `newest` until a page holds `head`. Never
    /// stops on a page's length, which a server's byte budget can cut short.
    /// Also says whether a page held `head`: when none did, what is returned
    /// does not start after it.
    async fn back_to(
        &self,
        slug: &str,
        head: &str,
        mut delivered: Vec<DeliveredBlock>,
    ) -> Result<(Vec<DeliveredBlock>, bool)> {
        let mut pages = 1;
        loop {
            if pages == MAX_CATCH_UP_PAGES {
                // About ten thousand blocks: past that, the blocks before
                // this window are skipped, and MLS will refuse them later.
                eprintln!(
                    "warning: more than {} blocks reached {slug} since this device last \
                     read it. The newest {} are read; every older one is skipped, and \
                     may never be readable on this device.",
                    delivered.len(),
                    delivered.len()
                );
                return Ok((delivered, false));
            }
            let Some(oldest) = delivered.first().and_then(placed_cid) else {
                return Ok((delivered, false));
            };
            let mut older = self
                .history_page(slug, MAX_HISTORY_PAGE, Page::Before(&oldest))
                .await?;
            if older.is_empty() {
                // The head is not in this history: the server dropped it, or
                // the channel was replaced. Read what there is.
                eprintln!(
                    "warning: {slug}'s history no longer holds the last block this \
                     device read; reading it from the start"
                );
                return Ok((delivered, false));
            }
            // Only the new page is searched; it goes in front, so an index
            // into it is an index into the whole.
            let found = position_of(&older, head);
            older.append(&mut delivered);
            delivered = older;
            pages += 1;
            if let Some(at) = found {
                return Ok((delivered.split_off(at + 1), true));
            }
        }
    }

    /// Whether to page history forward on this server: it advertises
    /// `history_after` in `/.well-known/jig` (#349), and no page it sent
    /// in this process broke the chain. Read once per process.
    async fn pages_forward(&self) -> Result<bool> {
        if self.forward_broken.load(Ordering::Relaxed) {
            return Ok(false);
        }
        self.forward
            .get_or_try_init(|| async {
                let info: serde_json::Value = self.get_json("/.well-known/jig").await?;
                Ok::<_, anyhow::Error>(info["history_after"].as_bool() == Some(true))
            })
            .await
            .copied()
    }

    /// A first catch-up: the newest page, and older pages until history
    /// reaches back to this device's epoch.
    async fn newest_to_epoch(&self, slug: &str) -> Result<Vec<DeliveredBlock>> {
        let mut delivered = self
            .history_page(slug, DEFAULT_HISTORY_LIMIT, Page::Newest)
            .await?;
        // Only an empty page ends the history. A server may send fewer
        // blocks than asked, to keep a page within a byte budget, so a short
        // page is not the start of the channel.
        let mut more = !delivered.is_empty();
        let epoch = self.session.epoch(&self.server, &self.key(slug))?;
        let me = self.session.did().to_string();
        let mut pages = 1;
        while more && !history_reaches(&opened(&delivered), epoch, &me) {
            if pages == MAX_CATCH_UP_PAGES {
                eprintln!(
                    "warning: {slug} has moved on more than {} blocks since this device \
                     last followed it; ask its owner to re-add you",
                    delivered.len()
                );
                break;
            }
            let Some(oldest) = delivered.first().and_then(placed_cid) else {
                break;
            };
            let mut older = self
                .history_page(slug, MAX_HISTORY_PAGE, Page::Before(&oldest))
                .await?;
            more = !older.is_empty();
            older.append(&mut delivered);
            delivered = older;
            pages += 1;
        }
        Ok(delivered)
    }

    /// The channel's newest `limit` blocks, read, for showing: what `jig read`
    /// prints and a pane opens with. Syncs first, so every block shown has
    /// been processed in order, and replaying it only recalls what it meant.
    /// Departed members to tidy come from the sync.
    pub async fn recent(&self, slug: &str, limit: usize) -> Result<Synced> {
        let synced = self.sync(slug).await?;
        // Stopped at a critical block of an unknown kind: nothing past it is
        // shown, and the newest window may well be past it.
        if synced.stopped.is_some() {
            return Ok(synced);
        }
        // The head the sync read to: blocks past it landed since, and are the
        // next sync's to read in order, through the stop rule.
        let head = self.session.head(&self.server, &self.key(slug))?;
        let mut delivered = self
            .history_page(slug, limit.min(MAX_HISTORY_PAGE), Page::Newest)
            .await?;
        while delivered.len() < limit {
            let Some(oldest) = delivered.first().and_then(placed_cid) else {
                break;
            };
            let mut older = self
                .history_page(
                    slug,
                    (limit - delivered.len()).min(MAX_HISTORY_PAGE),
                    Page::Before(&oldest),
                )
                .await?;
            if older.is_empty() {
                break;
            }
            older.append(&mut delivered);
            delivered = older;
        }
        bound_to_head(&mut delivered, head.as_deref());
        let shown = self.replay(slug, &delivered);
        Ok(Synced {
            tidy: synced.tidy,
            ..shown
        })
    }

    /// One page of the channel's history, oldest first: the newest `limit`
    /// blocks, or those just older or just newer than a block.
    async fn history_page(
        &self,
        slug: &str,
        limit: usize,
        page: Page<'_>,
    ) -> Result<Vec<DeliveredBlock>> {
        // This is the one path that pages on until an empty page, so the one
        // that may ask the server to cut a page at its byte budget. A server
        // that predates the budget ignores it.
        let mut url = history_url(&self.server, slug, limit) + "&budget=1";
        match page {
            Page::Newest => {}
            Page::Before(cid) => url.push_str(&format!("&before={cid}")),
            Page::After(cid) => url.push_str(&format!("&after={cid}")),
        }
        let path = url.strip_prefix(&self.base).unwrap_or(&url).to_string();
        let body: serde_json::Value = self
            .get_json_capped(&path, limits::history_page_bytes(limit))
            .await?;
        parse_history(&body.to_string())
    }

    /// The id and slug of the channel this device names `reference`, from
    /// what it pinned ([`Self::channel`] pins a channel before it is read);
    /// else `reference` itself, as an id or a slug. Blocks of the channel
    /// name it by one of the two ([`Session::observe_in`]).
    fn names(&self, reference: &str) -> (String, String) {
        let pinned = Pins::load(&Pins::default_path()).ok().and_then(|pins| {
            pins.channel_by_ref(&self.server, reference)
                .map(|(slug, pin)| (pin.create_cid.clone(), slug.to_string()))
        });
        pinned.unwrap_or_else(|| {
            if jig_core::canonical_cid::is_canonical_text(reference) {
                (reference.to_string(), String::new())
            } else {
                (String::new(), reference.to_string())
            }
        })
    }

    /// What one block of `reference`'s live stream means, read through the
    /// group state filed under `reference`, as [`Self::replay`] reads its
    /// history.
    pub fn observe(&self, reference: &str, block: &jig_client::open::OpenedBlock) -> Seen {
        let (id, slug) = self.names(reference);
        let key = self.key(reference);
        let channel = ReadIn {
            key: &key,
            id: &id,
            slug: &slug,
        };
        self.session.observe_in(&self.server, Some(&channel), block)
    }

    /// [`Secure::sync`] over blocks already fetched.
    pub fn replay(&self, reference: &str, delivered: &[DeliveredBlock]) -> Synced {
        let mut replayed = Replayed::default();
        self.replay_into(reference, &mut replayed, delivered);
        self.finish(reference, replayed)
    }

    /// Process `delivered`, in MLS order, into what a replay has found.
    fn replay_into(&self, reference: &str, r: &mut Replayed, delivered: &[DeliveredBlock]) {
        // Nothing past a critical block of an unknown kind is read.
        if r.stopped.is_some() {
            return;
        }
        let (delivered, stopped) = before_stop(delivered);
        r.stopped = stopped;
        let mut opened = Vec::with_capacity(delivered.len());
        let mut receipts = std::collections::HashMap::new();
        for d in delivered {
            match open(d) {
                Ok(o) => {
                    receipts.insert(o.cid.clone(), d.receipts.clone());
                    opened.push(o);
                }
                // In the chain, and nothing in it for this reader.
                Err(e) if e.skippable() => {}
                Err(e) => eprintln!("[dropped history block {}: {e}]", d.delivery_cid),
            }
        }
        r.cids.extend(opened.iter().map(|o| o.cid.clone()));
        r.deliveries
            .extend(delivered.iter().map(|d| d.delivery_cid.clone()));
        let (id, slug) = self.names(reference);
        let key = self.key(reference);
        let channel = ReadIn {
            key: &key,
            id: &id,
            slug: &slug,
        };
        for o in replay_order(opened) {
            let seen = self.session.observe_in(&self.server, Some(&channel), &o);
            match &seen {
                Seen::Left { member, tidy: true }
                | Seen::Linked {
                    old: member,
                    tidy: true,
                    ..
                } => r.left.push(member.clone()),
                // Back again since they left: nothing to tidy.
                Seen::Added { member } => r.left.retain(|d| d != member),
                _ => {}
            }
            let receipts = receipts.get(&o.cid).cloned().unwrap_or_default();
            if let Some(line) = present(&o, &receipts, &seen) {
                r.lines.push(line);
            }
        }
    }

    /// What a replay found, once every page has been processed.
    fn finish(&self, reference: &str, r: Replayed) -> Synced {
        // Only those still in the tree once everything has been replayed: a
        // later block in the same history may already have removed them.
        let still = self
            .session
            .group_members(&self.server, &self.key(reference))
            .unwrap_or_default();
        // A device a key link moved a place to holds no group yet: the old
        // leaf it has to take out after rejoining is kept for it.
        let linked = self
            .session
            .linked_from(&self.server, &self.key(reference))
            .ok()
            .flatten();
        let tidy = r
            .left
            .into_iter()
            .filter(|d| still.contains(d) || linked.as_ref() == Some(d))
            .collect();
        Synced {
            lines: r.lines,
            tidy,
            cids: r.cids,
            deliveries: r.deliveries,
            stopped: r.stopped,
        }
    }

    /// Build a commit, submit the block carrying it, and merge it once the
    /// server accepts. On `STALE_EPOCH` — someone committed first — catch up
    /// and try once more.
    ///
    /// A commit is dropped only when the server refuses it. When no answer
    /// comes, the server may have taken it, and dropping it would leave this
    /// member an epoch behind with no way back; history settles it instead.
    pub async fn commit(
        &self,
        slug: &str,
        prepare: impl Fn(&Session, &str) -> Result<Commit>,
        block_for: impl Fn(&Commit) -> BuiltBlock,
    ) -> Result<String> {
        let _held = self.hold(slug).await?;
        for attempt in 0..2 {
            // A group this device could not read to its head must not be
            // committed from: the block it stopped at may change it.
            if let Some(stop) = self.sync(slug).await?.stopped {
                return Err(self.stopped_at(slug, &stop));
            }
            // Still pending after a sync: an earlier commit whose answer never
            // came, and which did not land (had it, its echo would have
            // merged it). It would block this one.
            let key = self.key(slug);
            if self.session.has_pending_commit(&self.server, &key)? {
                self.session.abandon(&self.server, &key)?;
            }
            let commit = prepare(&self.session, &key)?;
            let block = block_for(&commit);
            match self.submit(&block).await {
                Ok(cid) => {
                    self.session.confirm(&self.server, &key)?;
                    return Ok(cid);
                }
                Err(e) if refused(&e) => {
                    // Best effort: the refusal is the error worth reporting.
                    self.session.abandon(&self.server, &key).ok();
                    let stale = e
                        .downcast_ref::<Refused>()
                        .is_some_and(|r| r.code == "STALE_EPOCH");
                    if !(stale && attempt == 0) {
                        return Err(e);
                    }
                }
                Err(e) => return self.settle(slug, &block, e).await,
            }
        }
        unreachable!("the loop returns on its second attempt")
    }

    /// A commit was sent and no answer came. Its echo in history means it
    /// landed (the sync merges it); none means it did not.
    async fn settle(&self, slug: &str, block: &BuiltBlock, sent: anyhow::Error) -> Result<String> {
        let Ok(synced) = self.sync(slug).await else {
            return Err(sent.context(
                "no answer from the server; the commit is kept until the next sync shows whether it landed",
            ));
        };
        let key = self.key(slug);
        if synced.cids.contains(&block.cid()) {
            self.session.confirm(&self.server, &key)?;
            return Ok(block.cid());
        }
        // A sync that stopped short says nothing of whether the commit landed
        // past where it stopped: keep it until one that reads that far.
        if let Some(stop) = &synced.stopped {
            return Err(self.stopped_at(slug, stop).context(format!(
                "{sent:#}; the commit is kept until a sync past the stop shows whether it landed"
            )));
        }
        // Best effort: a commit still pending is dropped by the next one.
        self.session.abandon(&self.server, &key).ok();
        Err(sent)
    }

    /// Commit the removal of a member who left. Losing the race to another
    /// member doing the same is success.
    ///
    /// A device whose key a key link moved `did`'s place to (JEP-0005 rule
    /// 7b) holds no group yet: it first rejoins by its own external commit,
    /// then commits `did`'s old leaf out, before it sends anything else.
    pub async fn tidy(&self, slug: &str, did: &str) -> Result<()> {
        let key = self.key(slug);
        let linked = self.session.linked_from(&self.server, &key)?;
        if linked.as_deref() == Some(did) && !self.session.has_group(&self.server, &key)? {
            self.rejoin(slug).await?;
        }
        let tidied = self.tidy_out(slug, did).await;
        if tidied.is_ok() && linked.as_deref() == Some(did) {
            self.session.link_settled(&self.server, &key)?;
        }
        tidied
    }

    /// Join `slug`'s group by this device's own external commit: what the
    /// new DID of a key link does, already on the roster (JEP-0005 rule 7b).
    /// One retry on a stale epoch.
    async fn rejoin(&self, slug: &str) -> Result<()> {
        let _held = self.hold(slug).await?;
        let key = self.key(slug);
        let me = self.identity.did_string();
        for attempt in 0..2 {
            let info = self.group_info(slug).await?;
            let commit = self.session.prepare_join(&self.server, &key, &info)?;
            let mut meta = serde_json::json!({"channel": slug, "member_did": me});
            if let (Some(meta), serde_json::Value::Object(fields)) =
                (meta.as_object_mut(), mls_fields(&commit))
            {
                meta.extend(fields);
            }
            let block = jig_client::blocks::build_with_metadata(
                &self.identity,
                jig_core::BlockKind::MemberAdd,
                jig_core::HlcTimestamp::now_wall(self.identity.did().clone()),
                meta,
            );
            match self.submit(&block).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let stale = e
                        .downcast_ref::<Refused>()
                        .is_some_and(|r| r.code == "STALE_EPOCH");
                    if e.downcast_ref::<Refused>().is_some() {
                        self.session.discard_join(&self.server, &key)?;
                    }
                    if !(stale && attempt == 0) {
                        return Err(e.context(format!("rejoining {slug} under the new key")));
                    }
                }
            }
        }
        unreachable!("the loop returns on its second attempt")
    }

    async fn tidy_out(&self, slug: &str, did: &str) -> Result<()> {
        let prepare = |s: &Session, key: &str| Ok(s.prepare_remove(&self.server, key, did)?);
        let block_for = |c: &Commit| {
            jig_client::blocks::build_member_remove(
                &self.identity,
                slug,
                did,
                mls_fields(c),
                jig_core::HlcTimestamp::now_wall(self.identity.did().clone()),
            )
        };
        match self.commit(slug, prepare, block_for).await {
            Ok(_) => Ok(()),
            Err(e) if e.downcast_ref::<Refused>().is_some() => Ok(()),
            Err(e) if format!("{e:#}").contains("is not in the group") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Encrypt and send `text`. Returns the block CID.
    pub async fn send(&self, slug: &str, text: &str) -> Result<String> {
        // A key link moved this device's place here, or moved another
        // member's (JEP-0005 rule 7b): the old leaf is out before anything is
        // sent. A tidy-up that does not take it out leaves the send refused
        // by the session, never encrypted for the old key.
        let key = self.key(slug);
        if let Some(old) = self.session.linked_from(&self.server, &key)? {
            self.tidy(slug, &old)
                .await
                .with_context(|| format!("taking the old key's leaf out of {slug}"))?;
        }
        for old in self.session.linked_leaves(&self.server, &key)? {
            self.tidy(slug, &old)
                .await
                .with_context(|| format!("taking {old}'s old leaf out of {slug}"))?;
        }
        let (message, epoch) = self
            .session
            .encrypt(&self.server, &self.key(slug), text)
            .with_context(|| format!("encrypting for {slug}"))?;
        let block = jig_client::blocks::build_sealed_text(
            &self.identity,
            slug,
            &message,
            epoch,
            jig_core::HlcTimestamp::now_wall(self.identity.did().clone()),
        );
        // Filed before submitting: MLS will never decrypt our own message
        // for us, and the echo may arrive before the submit returns.
        self.session
            .remember(&block.cid(), self.session.did(), text)?;
        self.submit(&block).await
    }
}

/// [`Secure::key`] against `pins`: the id of the channel `reference` names on
/// `server`, by id or as its pin's slug reads it, else `reference`.
fn group_name(pins: Option<&Pins>, server: &str, reference: &str) -> String {
    if jig_core::canonical_cid::is_canonical_text(reference) {
        return reference.to_string();
    }
    pins.and_then(|p| p.channel(server, reference))
        .map(|pin| pin.create_cid.clone())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| reference.to_string())
}

/// [`Secure::own_key`] against `pins`: the id of the channel `server` itself
/// orders under `slug`, never one it carries.
fn own_group_name(pins: Option<&Pins>, server: &str, slug: &str) -> Option<String> {
    pins.and_then(|p| p.channel(server, slug))
        .filter(|pin| pin.sequencer.is_none())
        .map(|pin| pin.create_cid.clone())
        .filter(|id| !id.is_empty())
}

/// The blocks that open; the rest are dropped (and reported) by `replay`.
fn opened(delivered: &[DeliveredBlock]) -> Vec<jig_client::open::OpenedBlock> {
    delivered.iter().filter_map(|d| open(d).ok()).collect()
}

/// The MLS fields a commit-carrying block adds to its metadata.
pub fn mls_fields(c: &Commit) -> serde_json::Value {
    let mut v = serde_json::json!({
        "mls_commit": STANDARD.encode(&c.commit),
        "mls_epoch": c.epoch,
    });
    if let Some(w) = &c.welcome {
        v["mls_welcome"] = STANDARD.encode(w).into();
    }
    if let Some(i) = &c.group_info {
        v["mls_group_info"] = STANDARD.encode(i).into();
    }
    v
}

/// The listed channel `reference` names: the one whose id it is, else the
/// one this server orders under that slug (`ours`, the server's DIDs). A
/// slug names a channel only where it is ordered, so a channel this server
/// carries for its owner is named by its id here, whatever order the listing
/// is in: a carried channel and this server's own may share a slug.
fn pick(
    channels: Vec<ChannelInfo>,
    reference: &str,
    ours: &[String],
) -> Result<Option<ChannelInfo>> {
    let mut carried = None;
    let mut by_slug = None;
    for channel in channels {
        if !channel.id.is_empty() && channel.id == reference {
            return Ok(Some(channel));
        }
        if channel.slug == reference {
            if names_another_server(ours, &channel.sequencer) {
                carried.get_or_insert(channel);
            } else {
                by_slug.get_or_insert(channel);
            }
        }
    }
    match (by_slug, carried) {
        // Both: the slug names this server's own (JEP-0005 rule 1), but
        // never silently (#388).
        (Some(own), Some(c)) => {
            eprintln!("note: {}", shadow_note(reference, &own, &c));
            Ok(Some(own))
        }
        (Some(own), None) => Ok(Some(own)),
        (None, Some(c)) => anyhow::bail!(
            "{reference} here is a channel this server carries for {}; name it by its id, {}",
            c.sequencer,
            c.id
        ),
        (None, None) => Ok(None),
    }
}

/// The MLS group the channel-create in `bundle_b64` starts, once the bundle
/// is shown to be the block `channel_id` names: the server serving it is not
/// taken at its word.
fn creation_group_id(channel_id: &str, bundle_b64: &str) -> Result<Option<Vec<u8>>> {
    let bytes = STANDARD
        .decode(bundle_b64)
        .context("the bundle is not base64")?;
    let (manifest_bytes, code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&bytes).context("the bundle is malformed")?;
    let bundle = jig_core::BlockBundle {
        manifest_bytes: &manifest_bytes,
        code_bytes: &code_bytes,
        resources: vec![],
    };
    let cid = bundle.block_cid().context("its CID cannot be derived")?;
    anyhow::ensure!(
        cid.to_string() == channel_id,
        "the block served is not the one the channel names"
    );
    let manifest: jig_core::BlockManifest =
        serde_json::from_slice(&manifest_bytes).context("the manifest is malformed")?;
    // The block is the channel's own, by its hash: without a group info it
    // was created unencrypted, and no group is anyone's to adopt.
    let Some(info) = manifest.metadata.get("mls_group_info") else {
        return Ok(None);
    };
    let info = info
        .as_str()
        .context("its `mls_group_info` is not a string")?;
    Ok(Some(jig_client::secure::created_group_id(info)?))
}

/// The channels in a listing that this server orders itself, leaving out
/// those it carries for another server.
fn ordered_here(channels: Vec<ChannelInfo>, ours: &[String]) -> Vec<ChannelInfo> {
    channels
        .into_iter()
        .filter(|c| !names_another_server(ours, &c.sequencer))
        .collect()
}

/// What `jig` says when `reference` names both this server's own channel
/// `own` and a channel it carries for another server, `carried` (#388): the
/// slug reads the server's own, and the other is named by its id.
fn shadow_note(reference: &str, own: &ChannelInfo, carried: &ChannelInfo) -> String {
    format!(
        "{reference} here is this server's channel {}; {} is also {reference}, carried for {}. \
         Name it by its id to read it.",
        own.id, carried.id, carried.sequencer
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Asked, ChannelInfo, KeptAnswer, LocalAdds, LogWalk, RELEASE_PAGE, RecordBody, Refused,
        ReleaseEntry, ServerState, creation_group_id, first_release, forget_stock_refs, group_name,
        judge_kept_answer, kept_leaves_out, must_encrypt, ordered_here, own_group_name, pick,
        sequencers_for, settle_local_adds, shadow_note, split_unchecked, walk_release_log,
    };
    use std::cell::RefCell;

    /// Signed text blocks, as a history window delivers them, oldest first.
    fn window(n: usize) -> (Vec<jig_client::DeliveredBlock>, Vec<String>) {
        use base64::Engine as _;
        let dir = tempfile::tempdir().unwrap();
        let id = jig_client::Identity::generate_for_tests(&dir.keep());
        let blocks: Vec<_> = (0..n)
            .map(|i| {
                let hlc = jig_core::HlcTimestamp::now_wall(id.did().clone());
                let block = jig_client::blocks::build_text_render(&id, "#c", &format!("m{i}"), hlc);
                jig_client::DeliveredBlock {
                    bundle_b64: base64::engine::general_purpose::STANDARD
                        .encode(block.canonical_bytes()),
                    sig_b64: Some(
                        base64::engine::general_purpose::STANDARD.encode(&block.sender_sig),
                    ),
                    receipts: vec![],
                    delivery_cid: format!("delivery:{i}"),
                    ingest: None,
                }
            })
            .collect();
        let cids = blocks
            .iter()
            .map(|d| super::placed_cid(d).unwrap())
            .collect();
        (blocks, cids)
    }

    /// `recent` shows only what the sync read: up to its head, and nothing
    /// when the sync placed nothing (no head) or the window lies past it.
    #[test]
    fn the_shown_window_ends_at_the_synced_head() {
        let (blocks, cids) = window(4);
        let mut w = blocks.clone();
        super::bound_to_head(&mut w, Some(&cids[1]));
        assert_eq!(w.len(), 2, "cut after the head");

        // The sync placed nothing, then blocks landed: none of them is shown.
        let mut w = blocks.clone();
        super::bound_to_head(&mut w, None);
        assert!(w.is_empty(), "no head: nothing the sync read");

        // A window wholly past the head.
        let mut w = blocks[2..].to_vec();
        super::bound_to_head(&mut w, Some(&cids[0]));
        assert!(w.is_empty(), "head not in the window");
    }

    fn refusal(status: u16, code: &str) -> anyhow::Error {
        Refused {
            status,
            code: code.into(),
            message: String::new(),
        }
        .into()
    }

    fn custodians() -> Vec<(String, String)> {
        ["one", "two", "three"]
            .iter()
            .map(|n| (format!("did:jig:z{n}"), format!("https://{n}")))
            .collect()
    }

    /// JEP-0017 rule 18: the custodian sequences the channel and refuses
    /// it; a second custodian's package would be refused at the member-add
    /// anyway, so none is asked.
    #[tokio::test]
    async fn ended_local_adds_at_a_custodian_stop_the_search() {
        for code in ["LOCAL_ADDS_ENDED", "MEMBER_DECLINED"] {
            let servers = custodians();
            let asked = RefCell::new(Vec::new());
            let got = first_release(&servers, |_, url| {
                asked.borrow_mut().push(url.to_string());
                let e = refusal(403, code).context("asking");
                async move { Err(e) }
            })
            .await;
            match got {
                Err(Asked::Final(e)) => {
                    assert!(format!("{e:#}").contains(code), "{e:#}");
                    assert!(format!("{e:#}").contains("https://one"), "{e:#}");
                }
                _ => panic!("{code}: not final"),
            }
            assert_eq!(*asked.borrow(), ["https://one"], "{code}");
        }
    }

    /// Any other refusal moves on to the next custodian.
    #[tokio::test]
    async fn other_refusals_ask_the_next_custodian() {
        let servers = custodians();
        let asked = RefCell::new(0);
        let got = first_release(&servers, |_, url| {
            *asked.borrow_mut() += 1;
            let answer = match url {
                "https://one" => Err(refusal(404, "NO_CUSTODY")),
                "https://two" => Err(refusal(429, "RATE_LIMITED")),
                _ => Ok(b"kp".to_vec()),
            };
            async move { answer }
        })
        .await;
        assert!(matches!(got, Ok(ref p) if p == b"kp"));
        assert_eq!(*asked.borrow(), 3);
        let got = first_release(&servers, |_, _| async { Err(refusal(404, "NO_CUSTODY")) }).await;
        assert!(matches!(got, Err(Asked::Tried(ref t)) if t.len() == 3));
    }

    /// A marker the server keeps is answered back. Ours kept: no retry. A
    /// later, opposite one from another device: exactly one retry, above
    /// its seq, and what is kept then is the answer even if it still
    /// disagrees.
    #[tokio::test]
    async fn a_stale_local_adds_marker_is_sent_once_more_above_the_kept_one() {
        let sent = RefCell::new(Vec::new());
        let kept = settle_local_adds(false, 10, |seq| {
            sent.borrow_mut().push(seq);
            async move { Ok(LocalAdds { seq, allow: false }) }
        })
        .await
        .unwrap();
        assert_eq!(
            kept,
            LocalAdds {
                seq: 10,
                allow: false
            }
        );
        assert_eq!(*sent.borrow(), [10]);

        // A kept marker that agrees, at a higher seq, is taken as it is.
        sent.borrow_mut().clear();
        let kept = settle_local_adds(false, 10, |seq| {
            sent.borrow_mut().push(seq);
            async move {
                Ok(LocalAdds {
                    seq: 50,
                    allow: false,
                })
            }
        })
        .await
        .unwrap();
        assert_eq!(
            kept,
            LocalAdds {
                seq: 50,
                allow: false
            }
        );
        assert_eq!(*sent.borrow(), [10]);

        sent.borrow_mut().clear();
        let kept = settle_local_adds(false, 10, |seq| {
            sent.borrow_mut().push(seq);
            async move {
                Ok(if seq == 51 {
                    LocalAdds { seq, allow: false }
                } else {
                    LocalAdds {
                        seq: 50,
                        allow: true,
                    }
                })
            }
        })
        .await
        .unwrap();
        assert_eq!(
            kept,
            LocalAdds {
                seq: 51,
                allow: false
            }
        );
        assert_eq!(*sent.borrow(), [10, 51]);

        // Still outrun: one retry only, and the kept marker is the answer.
        sent.borrow_mut().clear();
        let kept = settle_local_adds(false, 10, |seq| {
            sent.borrow_mut().push(seq);
            async move {
                Ok(LocalAdds {
                    seq: seq + 100,
                    allow: true,
                })
            }
        })
        .await
        .unwrap();
        assert_eq!(
            kept,
            LocalAdds {
                seq: 211,
                allow: true
            }
        );
        assert_eq!(*sent.borrow(), [10, 111]);
    }

    #[test]
    fn an_answer_that_is_not_our_record_concludes_nothing() {
        use base64::Engine as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let did =
            jig_core::Did::from_ed25519_pubkey(&key.verifying_key().to_bytes()).to_did_jig_string();
        let other = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let b64 = |e: &[u8]| base64::engine::general_purpose::STANDARD.encode(e);
        let rec = |k: &ed25519_dalek::SigningKey, servers: Vec<(String, String)>| {
            jig_core::naming::ReachabilityRecord::sign(k, servers, 3).envelope
        };
        let did_from = |seed: u8| {
            let k = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
            jig_core::Did::from_ed25519_pubkey(&k.verifying_key().to_bytes()).to_did_jig_string()
        };
        let s = did_from(10);
        let t = did_from(11);
        let body = |record_b64: String| RecordBody { record_b64 };
        // Ours, leaving S out: a withdrawal. Ours, listing S: not.
        let out = rec(&key, vec![(t.clone(), "u".into())]);
        assert_eq!(kept_leaves_out(&body(b64(&out)), &did, &s), Some(true));
        let listed = rec(&key, vec![(s.clone(), "u".into())]);
        assert_eq!(kept_leaves_out(&body(b64(&listed)), &did, &s), Some(false));
        // Not base64, not a record, or someone else's: nothing concluded.
        assert_eq!(kept_leaves_out(&body("not base64!".into()), &did, &s), None);
        assert_eq!(kept_leaves_out(&body(b64(b"garbage")), &did, &s), None);
        let theirs = rec(&other, vec![(t.clone(), "u".into())]);
        assert_eq!(kept_leaves_out(&body(b64(&theirs)), &did, &s), None);
    }

    #[test]
    fn an_unreadable_or_malformed_answer_is_unchecked() {
        use base64::Engine as _;
        use reqwest::StatusCode;
        let key = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let did =
            jig_core::Did::from_ed25519_pubkey(&key.verifying_key().to_bytes()).to_did_jig_string();
        let s = {
            let k = ed25519_dalek::SigningKey::from_bytes(&[10; 32]);
            jig_core::Did::from_ed25519_pubkey(&k.verifying_key().to_bytes()).to_did_jig_string()
        };
        let kept = |servers: Vec<(String, String)>| {
            let env = jig_core::naming::ReachabilityRecord::sign(&key, servers, 3).envelope;
            serde_json::json!({
                "record_b64": base64::engine::general_purpose::STANDARD.encode(env)
            })
            .to_string()
            .into_bytes()
        };
        let judge = |a: Option<(StatusCode, Option<&[u8]>)>| judge_kept_answer(a, &did, &s);
        let ok = StatusCode::OK;
        // Our record, listing S or leaving it out; or no record at all.
        let listed = kept(vec![(s.clone(), "u".into())]);
        assert_eq!(judge(Some((ok, Some(&listed)))), KeptAnswer::Listed);
        assert_eq!(
            judge(Some((ok, Some(&kept(vec![]))))),
            KeptAnswer::Withdrawn
        );
        assert_eq!(
            judge(Some((StatusCode::NOT_FOUND, None))),
            KeptAnswer::Listed
        );
        // A 200 whose body is malformed JSON, the wrong shape, or unread.
        for body in [&b"{ not json"[..], b"[]", b"{\"other\": 1}"] {
            assert_eq!(judge(Some((ok, Some(body)))), KeptAnswer::Unchecked);
        }
        assert_eq!(judge(Some((ok, None))), KeptAnswer::Unchecked);
        // Any other status, or no answer.
        for status in [StatusCode::UNAUTHORIZED, StatusCode::INTERNAL_SERVER_ERROR] {
            assert_eq!(judge(Some((status, Some(&listed)))), KeptAnswer::Unchecked);
        }
        assert_eq!(judge(None), KeptAnswer::Unchecked);
    }

    #[test]
    fn the_new_record_is_not_sent_to_an_unchecked_server() {
        let servers = vec![
            ("did:a".to_string(), "https://a".to_string()),
            ("did:b".to_string(), "https://b".to_string()),
            ("did:c".to_string(), "https://c".to_string()),
        ];
        let unchecked = std::collections::HashSet::from(["did:b".to_string()]);
        let (send_to, skipped) = split_unchecked(&servers, &unchecked);
        assert_eq!(send_to, [servers[0].clone(), servers[2].clone()]);
        assert_eq!(skipped, [servers[1].clone()]);
    }

    /// A page of `n` custody releases, numbered from `from`, each with its id.
    fn release_page(from: usize, n: usize, with_ids: bool) -> Vec<ReleaseEntry> {
        (from..from + n)
            .map(|i| ReleaseEntry {
                kind: Some("custody".into()),
                reference_hex: Some(hex::encode((i as u32).to_be_bytes())),
                channel_id: String::new(),
                request_b64: String::new(),
                id_hex: with_ids.then(|| format!("{i:08x}")),
            })
            .collect()
    }

    #[tokio::test]
    async fn full_distinct_pages_are_walked_to_the_short_one() {
        let mut asked = Vec::new();
        let refs = walk_release_log("S", |offset| {
            asked.push(offset);
            let n = if offset < 2 * RELEASE_PAGE {
                RELEASE_PAGE
            } else {
                3
            };
            async move { Ok(Some(release_page(offset, n, true))) }
        })
        .await
        .unwrap();
        assert_eq!(asked, [0, RELEASE_PAGE, 2 * RELEASE_PAGE]);
        assert_eq!(refs.len(), 2 * RELEASE_PAGE + 3);
        assert_eq!(
            refs.last().unwrap(),
            &((2 * RELEASE_PAGE + 2) as u32).to_be_bytes()
        );
    }

    #[tokio::test]
    async fn a_full_page_served_again_stops_the_walk() {
        let mut calls = 0;
        let err = walk_release_log("S", |_offset| {
            calls += 1;
            async { Ok(Some(release_page(0, RELEASE_PAGE, true))) }
        })
        .await
        .unwrap_err();
        assert_eq!(calls, 2);
        assert!(err.to_string().contains("ignores `offset`"), "{err}");
    }

    #[tokio::test]
    async fn full_pages_without_ids_stop_at_the_cap() {
        let mut calls = 0;
        let err = walk_release_log("S", |_offset| {
            calls += 1;
            async { Ok(Some(release_page(0, RELEASE_PAGE, false))) }
        })
        .await
        .unwrap_err();
        assert_eq!(calls, LogWalk::MAX_PAGES + 1);
        assert!(err.to_string().contains("does not end"), "{err}");
    }

    #[tokio::test]
    async fn a_server_with_no_log_releases_nothing() {
        let refs = walk_release_log("S", |_| async { Ok(None) }).await.unwrap();
        assert!(refs.is_empty());
    }

    fn ids(xs: &[&str]) -> Option<Vec<String>> {
        Some(xs.iter().map(|x| x.to_string()).collect())
    }

    /// The stock references taken when the server said the stock was ended
    /// are the ones forgotten; references another process recorded since,
    /// a fresh last-resort package included, stay with their keys.
    #[test]
    fn only_the_stock_seen_ended_is_forgotten() {
        let mut state = ServerState {
            packages: vec!["a".into(), "b".into()],
            last_resort: Some("l0".into()),
            retiring: vec!["old".into()],
            ..ServerState::default()
        };
        let seen: std::collections::BTreeSet<String> =
            ["a", "b", "l0", "old"].map(String::from).into();
        // Another process undid R2 and stocked anew in between.
        state.packages.push("c".into());
        state.last_resort = Some("l1".into());
        forget_stock_refs(&mut state, &seen);
        assert_eq!(state.packages, ["c"]);
        assert_eq!(state.last_resort.as_deref(), Some("l1"));
        assert!(state.retiring.is_empty());

        let mut same = ServerState {
            last_resort: Some("l0".into()),
            ..ServerState::default()
        };
        forget_stock_refs(&mut same, &seen);
        assert_eq!(same.last_resort, None);
    }

    #[test]
    fn a_log_that_ignores_offset_stops_the_walk() {
        let mut walk = LogWalk::default();
        walk.page("S", ids(&["a@1", "b@2"])).unwrap();
        walk.page("S", ids(&["c@3", "d@4"])).unwrap();
        let err = walk
            .page("S", ids(&["c@3", "d@4"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("S answers every page"), "{err}");
    }

    #[test]
    fn distinct_pages_of_local_takes_are_not_a_repeat() {
        // Local takes of one package in one second differ only by their ids.
        let mut walk = LogWalk::default();
        walk.page("S", ids(&["a@1", "b@1"])).unwrap();
        walk.page("S", ids(&["c@1", "d@1"])).unwrap();
        // Entries with no identity at all are never called a repeat.
        walk.page("S", None).unwrap();
        walk.page("S", None).unwrap();
    }

    #[test]
    fn a_log_that_never_ends_stops_the_walk() {
        let mut walk = LogWalk::default();
        let mut result = Ok(());
        for n in 0..=LogWalk::MAX_PAGES {
            result = walk.page("S", Some(vec![n.to_string()]));
            if result.is_err() {
                break;
            }
        }
        assert!(result.unwrap_err().to_string().contains("does not end"));
    }
    use jig_client::pins::{ChannelPin, Pins};

    /// A carried channel's records are held to its owner; the server's own
    /// channels to the server; and with nothing pinned, to the record's
    /// signer.
    #[test]
    fn a_carried_channel_is_held_to_its_owner_and_others_to_the_server() {
        let dir = tempfile::tempdir().unwrap();
        let mut pins = Pins::load(&dir.path().join("pins.json")).unwrap();
        let server = "wss://follower";
        pins.check_server_did(server, "did:jig:zserver").unwrap();
        for (slug, cid) in [("#carried", "bafycarried"), ("#own", "bafyown")] {
            pins.check_channel(
                server,
                slug,
                ChannelPin {
                    create_cid: cid.to_string(),
                    slug: String::new(),
                    suite: "mls".to_string(),
                    owner_did: "did:jig:zuser".to_string(),
                    co_owners: Vec::new(),
                    chain_head: None,
                    sequencer: None,
                },
            )
            .unwrap();
        }
        pins.anchor_channel(server, "#carried", "bafycarried", Some("did:jig:zowner"))
            .unwrap();

        assert_eq!(
            sequencers_for(Some(&pins), server, "bafycarried", "did:jig:zowner"),
            vec!["did:jig:zowner".to_string()]
        );
        assert_eq!(
            sequencers_for(Some(&pins), server, "bafyown", "did:jig:zserver"),
            vec!["did:jig:zserver".to_string()]
        );
        assert_eq!(
            sequencers_for(None, server, "bafyown", "did:jig:zsigner"),
            vec!["did:jig:zsigner".to_string()]
        );
    }

    fn listed(id: &str, slug: &str, sequencer: &str) -> ChannelInfo {
        ChannelInfo {
            id: id.to_string(),
            slug: slug.to_string(),
            suite: "none".to_string(),
            sequencer: sequencer.to_string(),
            share: None,
            share_key_links: Vec::new(),
            tier: None,
        }
    }

    /// A slug names the channel this server orders, never one it carries,
    /// whatever order the listing is in; a carried channel is named by id.
    #[test]
    fn a_slug_names_the_servers_own_channel_not_a_carried_one() {
        let ours = vec!["did:jig:zfollower".to_string()];
        let carried = listed("bafycarried", "#shared", "did:jig:zowner");
        let own = listed("bafyown", "#shared", "did:jig:zfollower");
        for listing in [
            vec![carried.clone(), own.clone()],
            vec![own.clone(), carried.clone()],
        ] {
            let got = pick(listing.clone(), "#shared", &ours).unwrap().unwrap();
            assert_eq!(got.id, "bafyown");
            let got = pick(listing, "bafycarried", &ours).unwrap().unwrap();
            assert_eq!(got.id, "bafycarried");
        }
        // Both: what `jig` says names the one read and the one shadowed.
        let note = shadow_note("#shared", &own, &carried);
        assert!(note.contains("bafyown"), "{note}");
        assert!(note.contains("bafycarried"), "{note}");
        assert!(note.contains("did:jig:zowner"), "{note}");
        // Only a carried channel under the slug: refused, naming its id.
        let error = pick(vec![carried], "#shared", &ours)
            .unwrap_err()
            .to_string();
        assert!(error.contains("bafycarried"), "{error}");
        // A listing that names no sequencer is the server's own.
        let legacy = listed("bafylegacy", "#old", "");
        assert_eq!(
            pick(vec![legacy], "#old", &ours).unwrap().unwrap().id,
            "bafylegacy"
        );
        assert!(pick(vec![], "#none", &ours).unwrap().is_none());
    }

    /// A `channel create` retry reads the group the listed channel was
    /// created with from its creation block, held to the channel's id (#455).
    #[test]
    fn a_creation_block_names_the_group_it_started() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let keys = tempfile::tempdir().unwrap();
        let id = jig_client::Identity::generate_for_tests(keys.path());
        let state = tempfile::tempdir().unwrap();
        let session = jig_client::secure::Session::open(
            state.path(),
            jig_client::Identity::generate_for_tests(keys.path()),
        )
        .unwrap();
        let created = session.create_group("wss://host", "creating:#x").unwrap();
        let create = |meta| {
            jig_client::blocks::build_with_metadata(
                &id,
                jig_core::BlockKind::ChannelCreate,
                jig_core::HlcTimestamp::now_wall(id.did().clone()),
                meta,
            )
        };
        let block = create(serde_json::json!({
            "slug": "#x",
            "suite": "mls",
            "mls_group_info": STANDARD.encode(&created.group_info),
        }));
        let bundle = STANDARD.encode(block.canonical_bytes());
        assert_eq!(
            creation_group_id(&block.cid(), &bundle).unwrap(),
            Some(created.group_id)
        );

        // Served under another channel's id: not taken.
        let other = create(serde_json::json!({ "slug": "#y" }));
        assert!(creation_group_id(&other.cid(), &bundle).is_err());
        // A channel created with no group: none to adopt.
        let plain = STANDARD.encode(other.canonical_bytes());
        assert_eq!(creation_group_id(&other.cid(), &plain).unwrap(), None);
        // A group info that is no string is an error, not "no group".
        let odd = create(serde_json::json!({ "slug": "#z", "mls_group_info": 7 }));
        let odd_bundle = STANDARD.encode(odd.canonical_bytes());
        assert!(creation_group_id(&odd.cid(), &odd_bundle).is_err());
    }

    /// A `channel create` retry asks whether this server took the create it
    /// left pending: a channel the server carries for another under the slug
    /// is not that create, and is no error.
    #[test]
    fn a_retry_reads_past_a_carried_channel_with_the_slug() {
        let ours = vec!["did:jig:zfollower".to_string()];
        let carried = listed("bafycarried", "#shared", "did:jig:zowner");
        let own = listed("bafyown", "#shared", "did:jig:zfollower");
        assert!(
            pick(ordered_here(vec![carried.clone()], &ours), "#shared", &ours)
                .unwrap()
                .is_none()
        );
        let got = pick(ordered_here(vec![carried, own], &ours), "#shared", &ours)
            .unwrap()
            .unwrap();
        assert_eq!(got.id, "bafyown");
    }

    /// #432: a server's own channel's MLS state is filed under the id its
    /// slug is pinned to, as a carried channel's is under the id it is named
    /// by; a slug nothing is pinned to stays itself.
    #[test]
    fn mls_state_is_filed_under_the_pinned_channel_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut pins = Pins::load(&dir.path().join("pins.json")).unwrap();
        let server = "wss://host";
        let id = jig_core::canonical_cid::of(b"team").to_string();
        pins.check_channel(
            server,
            "#team",
            ChannelPin {
                create_cid: id.clone(),
                slug: String::new(),
                suite: "mls".to_string(),
                owner_did: "did:jig:zuser".to_string(),
                co_owners: Vec::new(),
                chain_head: None,
                sequencer: None,
            },
        )
        .unwrap();
        assert_eq!(group_name(Some(&pins), server, "#team"), id);
        assert_eq!(group_name(Some(&pins), server, &id), id);
        let carried = jig_core::canonical_cid::of(b"carried").to_string();
        assert_eq!(group_name(Some(&pins), server, &carried), carried);
        assert_eq!(group_name(Some(&pins), server, "#new"), "#new");
        assert_eq!(group_name(None, server, "#team"), "#team");
        // Another server's `#team` is not this one's.
        assert_eq!(group_name(Some(&pins), "wss://elsewhere", "#team"), "#team");
    }

    /// `channel create` asks whether this server's own channel is already
    /// here: a channel the server carries for another under the same slug is
    /// not it, though [`group_name`] resolves the slug to the carried one
    /// while the server orders none by that slug.
    #[test]
    fn a_carried_channel_is_not_the_servers_own() {
        let dir = tempfile::tempdir().unwrap();
        let mut pins = Pins::load(&dir.path().join("pins.json")).unwrap();
        let server = "wss://host";
        let pin = |id: &str, sequencer: Option<&str>| ChannelPin {
            create_cid: id.to_string(),
            slug: String::new(),
            suite: "mls".to_string(),
            owner_did: "did:jig:zuser".to_string(),
            co_owners: Vec::new(),
            chain_head: None,
            sequencer: sequencer.map(str::to_string),
        };
        let carried = jig_core::canonical_cid::of(b"shared, carried").to_string();
        pins.check_channel(server, "#shared", pin(&carried, Some("did:jig:zother")))
            .unwrap();
        assert_eq!(group_name(Some(&pins), server, "#shared"), carried);
        assert_eq!(own_group_name(Some(&pins), server, "#shared"), None);

        let own = jig_core::canonical_cid::of(b"shared, own").to_string();
        pins.check_channel(server, "#shared", pin(&own, None))
            .unwrap();
        assert_eq!(own_group_name(Some(&pins), server, "#shared"), Some(own));
        assert_eq!(own_group_name(None, server, "#shared"), None);
    }

    /// A server can say anything about a channel's suite. A device that
    /// holds the group never takes its word for "unencrypted" (OP-03).
    #[test]
    fn local_mls_state_outranks_the_servers_listing() {
        assert!(must_encrypt(true, Some(true)));
        assert!(must_encrypt(true, Some(false)), "relabelled");
        assert!(must_encrypt(true, None), "hidden, or we were removed");
        // Nothing local to check against: the listing decides.
        assert!(must_encrypt(false, Some(true)));
        assert!(!must_encrypt(false, Some(false)));
        assert!(!must_encrypt(false, None));
    }
}
