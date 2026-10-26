//! Encrypted channels in the CLI: the network half of
//! `jig_client::secure::Session`.
//!
//! The session holds MLS state and does the cryptography; this module talks to
//! the server — key packages, group info, history, and submitting the blocks
//! that carry commits — and keeps the two in step: a commit is merged only
//! after the server accepts the block carrying it, and dropped if it refuses.

use std::sync::Arc;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jig_client::blocks::BuiltBlock;
use jig_client::limits;
use jig_client::open::open;
use jig_client::pins::{ChannelPin, Pins, names_another_server, prove_carried, prove_channel};
use jig_client::read_auth::{ReadProof, signable_path};
use jig_client::secure::{CommitLock, Seen, Session, history_reaches, replay_order};
use jig_client::{Client, ClientError, DeliveredBlock, Identity};
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
        carried: pins.carried(server),
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
}

/// One identity's encrypted-channel state, bound to one server.
pub struct Secure {
    pub session: Arc<Session>,
    identity: Identity,
    /// The server, as configured (any scheme).
    server: String,
    /// The same server as an `http(s)://` base for REST.
    base: String,
    /// Set once this process has held the server to its pin
    /// ([`Self::ensure_pinned`]).
    pinned: tokio::sync::OnceCell<()>,
}

impl Secure {
    pub fn open(ctx: &CliContext) -> Result<Self> {
        let server = ctx.server_url()?;
        let session = Session::open(&jig_client::secure::default_dir(), ctx.identity()?)
            .context("opening local MLS state (~/.jig/mls)")?;
        Ok(Self {
            session: Arc::new(session),
            identity: ctx.identity()?,
            base: base_http_url(&server),
            server,
            pinned: tokio::sync::OnceCell::new(),
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
                connect_pinned(&self.server, self.identity.duplicate())
                    .await
                    .map(drop)
            })
            .await
            .map(|_| ())
            .with_context(|| format!("connecting to {}", self.server))
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    /// Wait for the channel's commit lock, in this process or any other for
    /// this DID ([`Session::commit_lock`]). Hold it from before a commit,
    /// create or join is prepared until its outcome is settled.
    pub async fn hold(&self, slug: &str) -> Result<CommitLock> {
        let session = Arc::clone(&self.session);
        let (server, slug) = (self.server.clone(), slug.to_string());
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
        let proof = ReadProof::sign(&self.identity, "GET", signable_path(&url));
        let mut req = self.http().await?.get(&url);
        for (name, value) in proof.headers() {
            req = req.header(name, value);
        }
        let resp = req.send().await.with_context(|| format!("GET {url}"))?;
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
        #[derive(Deserialize)]
        struct Listing {
            channels: Vec<ChannelInfo>,
        }
        let listing: Listing = self.get_json("/api/v1/channels").await?;
        // By its slug, or by its id: a channel this server carries for its
        // owner is named by id here (a slug names a channel only where it
        // is ordered).
        let Some(mut info) = listing
            .channels
            .into_iter()
            .find(|c| c.slug == slug || (!c.id.is_empty() && c.id == slug))
        else {
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
        let owner = match other {
            Some(sequencer) => Some(prove_carried(
                &self.server,
                &info.slug,
                &info.id,
                sequencer,
                &ours,
                info.share.as_deref(),
            )?),
            None => None,
        };
        if pins.anchor_channel(&self.server, &info.slug, &info.id, owner.as_deref())? {
            eprintln!(
                "note: {} is now carried here for {}, which orders it; its history is checked \
                 against that server's records from now on",
                info.slug,
                owner.as_deref().unwrap_or_default()
            );
        }
        Ok(())
    }

    /// What `info`'s creation block proves, from the pin when it names the
    /// same block, else fetched, verified and pinned.
    async fn proven(&self, info: &ChannelInfo) -> Result<ChannelPin> {
        let mut pins = Pins::load(&Pins::default_path())?;
        if let Some(pin) = pins.channel(&self.server, &info.slug)
            && pin.create_cid == info.id
        {
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
        let proven = prove_channel(&info.slug, &info.id, &served.bundle_b64, &sig)?;
        Ok(pins.check_channel(&self.server, &info.slug, proven)?)
    }

    /// Whether what is sent to `slug` must be encrypted. This device's own
    /// MLS state outranks the server's listing ([`must_encrypt`]), and the
    /// listing's suite is the owner's signed one ([`Self::channel`]). A
    /// channel no longer listed to us is still what this device pinned.
    /// Failing to find out is an error, never a reason to send in the clear.
    pub async fn encrypted(&self, slug: &str) -> Result<bool> {
        let held = self.session.has_group(&self.server, slug)?;
        let pinned = Pins::load(&Pins::default_path())?
            .channel(&self.server, slug)
            .map(ChannelPin::encrypted);
        let listed = self.channel(slug).await?.map(|c| c.encrypted()).or(pinned);
        if held && listed == Some(false) {
            eprintln!(
                "warning: the server lists {slug} as unencrypted, but this device holds its \
                 MLS group; treating it as encrypted"
            );
        }
        Ok(must_encrypt(held, listed))
    }

    /// Keep enough key packages published that others can add us while we
    /// are offline, plus one last-resort package so we are never unreachable.
    pub async fn ensure_key_packages(&self) -> Result<()> {
        #[derive(Deserialize)]
        struct Stock {
            available: u64,
            last_resort: bool,
        }
        let did = self.session.did().to_string();
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
            return Ok(());
        }
        self.ensure_pinned().await?;
        let url = format!("{}/api/v1/mls/key-packages", self.base);
        let body = serde_json::json!({
            "key_packages_b64": packages.iter().map(|p| STANDARD.encode(p)).collect::<Vec<_>>(),
        });
        let resp = self
            .http()
            .await?
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        if !resp.status().is_success() {
            return Err(Self::refusal(resp).await.into());
        }
        Ok(())
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

    /// Replay the channel's history through the session: join from a
    /// welcome, follow commits, read messages. Run before building a commit
    /// so it is built on the channel's current epoch.
    ///
    /// The newest page usually holds everything this device is missing. When
    /// it has been away for longer — more than a page of blocks, commits among
    /// them — older pages are fetched until history reaches back to this
    /// device's epoch ([`history_reaches`]), or to the start of the channel.
    pub async fn sync(&self, slug: &str) -> Result<Synced> {
        let mut delivered = self.history_page(slug, DEFAULT_HISTORY_LIMIT, None).await?;
        // Only an empty page ends the history. A server may send fewer
        // blocks than asked, to keep a page within a byte budget, so a short
        // page is not the start of the channel.
        let mut more = !delivered.is_empty();
        let epoch = self.session.epoch(&self.server, slug)?;
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
            let Some(oldest) = delivered.first().and_then(|d| open(d).ok()) else {
                break;
            };
            let mut older = self
                .history_page(slug, MAX_HISTORY_PAGE, Some(&oldest.cid))
                .await?;
            more = !older.is_empty();
            older.append(&mut delivered);
            delivered = older;
            pages += 1;
        }
        Ok(self.replay(&delivered))
    }

    /// One page of the channel's history, oldest first: the newest `limit`
    /// blocks, or those just older than the block `before`.
    async fn history_page(
        &self,
        slug: &str,
        limit: usize,
        before: Option<&str>,
    ) -> Result<Vec<DeliveredBlock>> {
        // This is the one path that pages on until an empty page, so the one
        // that may ask the server to cut a page at its byte budget. A server
        // that predates the budget ignores it.
        let mut url = history_url(&self.server, slug, limit) + "&budget=1";
        if let Some(cid) = before {
            url.push_str(&format!("&before={cid}"));
        }
        let path = url.strip_prefix(&self.base).unwrap_or(&url).to_string();
        let body: serde_json::Value = self
            .get_json_capped(&path, limits::history_page_bytes(limit))
            .await?;
        parse_history(&body.to_string())
    }

    /// [`Secure::sync`] over blocks already fetched.
    pub fn replay(&self, delivered: &[DeliveredBlock]) -> Synced {
        let mut opened = Vec::with_capacity(delivered.len());
        let mut receipts = std::collections::HashMap::new();
        for d in delivered {
            match open(d) {
                Ok(o) => {
                    receipts.insert(o.cid.clone(), d.receipts.clone());
                    opened.push(o);
                }
                Err(e) => eprintln!("[dropped history block {}: {e}]", d.delivery_cid),
            }
        }
        let cids = opened.iter().map(|o| o.cid.clone()).collect();
        let mut lines = Vec::new();
        let mut left = Vec::new();
        let mut slug = None;
        for o in replay_order(opened) {
            if slug.is_none() {
                slug = o
                    .manifest
                    .kind
                    .and_then(|k| jig_pipeline_slug(k, &o.manifest));
            }
            let seen = self.session.observe(&self.server, &o);
            match &seen {
                Seen::Left { member, tidy: true } => left.push(member.clone()),
                // Back again since they left: nothing to tidy.
                Seen::Added { member } => left.retain(|d| d != member),
                _ => {}
            }
            let r = receipts.get(&o.cid).cloned().unwrap_or_default();
            if let Some(line) = present(&o, &r, &seen) {
                lines.push(line);
            }
        }
        // Only those still in the tree once everything has been replayed: a
        // later block in the same history may already have removed them.
        let tidy = match slug {
            Some(slug) => {
                let still = self
                    .session
                    .group_members(&self.server, &slug)
                    .unwrap_or_default();
                left.into_iter().filter(|d| still.contains(d)).collect()
            }
            None => Vec::new(),
        };
        let deliveries = delivered.iter().map(|d| d.delivery_cid.clone()).collect();
        Synced {
            lines,
            tidy,
            cids,
            deliveries,
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
        prepare: impl Fn(&Session) -> Result<Commit>,
        block_for: impl Fn(&Commit) -> BuiltBlock,
    ) -> Result<String> {
        let _held = self.hold(slug).await?;
        for attempt in 0..2 {
            self.sync(slug).await?;
            // Still pending after a sync: an earlier commit whose answer never
            // came, and which did not land (had it, its echo would have
            // merged it). It would block this one.
            if self.session.has_pending_commit(&self.server, slug)? {
                self.session.abandon(&self.server, slug)?;
            }
            let commit = prepare(&self.session)?;
            let block = block_for(&commit);
            match self.submit(&block).await {
                Ok(cid) => {
                    self.session.confirm(&self.server, slug)?;
                    return Ok(cid);
                }
                Err(e) if refused(&e) => {
                    // Best effort: the refusal is the error worth reporting.
                    self.session.abandon(&self.server, slug).ok();
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
        if synced.cids.contains(&block.cid()) {
            self.session.confirm(&self.server, slug)?;
            return Ok(block.cid());
        }
        // Best effort: a commit still pending is dropped by the next one.
        self.session.abandon(&self.server, slug).ok();
        Err(sent)
    }

    /// Commit the removal of a member who left. Losing the race to another
    /// member doing the same is success.
    pub async fn tidy(&self, slug: &str, did: &str) -> Result<()> {
        let prepare = |s: &Session| Ok(s.prepare_remove(&self.server, slug, did)?);
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
        let (message, epoch) = self
            .session
            .encrypt(&self.server, slug, text)
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

fn jig_pipeline_slug(kind: jig_core::BlockKind, m: &jig_core::BlockManifest) -> Option<String> {
    let key = if kind == jig_core::BlockKind::ChannelCreate {
        "slug"
    } else {
        "channel"
    };
    m.metadata
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::must_encrypt;

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
