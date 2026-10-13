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
use jig_client::open::open;
use jig_client::read_auth::{ReadProof, signable_path};
use jig_client::secure::{CommitLock, Seen, Session, replay_order};
use jig_client::{DeliveredBlock, Identity};
use jig_mls::member::Commit;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::cmd::blocks_decode::{DecodedBlock, present};
use crate::cmd::channel::{base_http_url, escape_slug_for_url};
use crate::cmd::common::CliContext;
use crate::cmd::history::{DEFAULT_HISTORY_LIMIT, history_url, parse_history};

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

/// A channel as the server lists it.
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelInfo {
    pub slug: String,
    #[serde(default = "none_suite")]
    pub suite: String,
}

fn none_suite() -> String {
    "none".to_string()
}

impl ChannelInfo {
    pub fn encrypted(&self) -> bool {
        self.suite == "mls"
    }
}

/// History replayed through the session.
pub struct Synced {
    /// What to show, oldest first.
    pub lines: Vec<DecodedBlock>,
    /// Departed members still in this member's copy of the tree.
    pub tidy: Vec<String>,
    /// Every block the history held, by CID.
    pub cids: std::collections::HashSet<String>,
}

/// One identity's encrypted-channel state, bound to one server.
pub struct Secure {
    pub session: Arc<Session>,
    identity: Identity,
    /// The server, as configured (any scheme).
    server: String,
    /// The same server as an `http(s)://` base for REST.
    base: String,
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
        })
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

    fn http() -> Result<reqwest::Client> {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("building HTTP client")
    }

    async fn refusal(resp: reqwest::Response) -> Refused {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        Refused {
            status,
            code: v["code"].as_str().unwrap_or("HTTP_ERROR").to_string(),
            message: v["message"].as_str().map(str::to_string).unwrap_or(body),
        }
    }

    /// A signed GET returning JSON.
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{path}", self.base);
        let proof = ReadProof::sign(&self.identity, "GET", signable_path(&url));
        let mut req = Self::http()?.get(&url);
        for (name, value) in proof.headers() {
            req = req.header(name, value);
        }
        let resp = req.send().await.with_context(|| format!("GET {url}"))?;
        if !resp.status().is_success() {
            return Err(Self::refusal(resp).await.into());
        }
        resp.json().await.with_context(|| format!("decoding {url}"))
    }

    /// Submit a signed block through `POST /api/v1/blocks`. A refusal comes
    /// back as a [`Refused`] the caller can branch on.
    pub async fn submit(&self, block: &BuiltBlock) -> Result<String> {
        let url = format!("{}/api/v1/blocks", self.base);
        let body = serde_json::json!({
            "bundle_b64": STANDARD.encode(block.canonical_bytes()),
            "sig_b64": STANDARD.encode(&block.sender_sig),
        });
        let resp = Self::http()?
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        if !resp.status().is_success() {
            return Err(Self::refusal(resp).await.into());
        }
        let v: serde_json::Value = resp.json().await.context("decoding submit result")?;
        Ok(v["block_cid"].as_str().unwrap_or_default().to_string())
    }

    /// The channel as this identity may see it, or `None` if it is not listed
    /// to us (unknown, or restricted and we are not in it).
    pub async fn channel(&self, slug: &str) -> Result<Option<ChannelInfo>> {
        #[derive(Deserialize)]
        struct Listing {
            channels: Vec<ChannelInfo>,
        }
        let listing: Listing = self.get_json("/api/v1/channels").await?;
        Ok(listing.channels.into_iter().find(|c| c.slug == slug))
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
        let url = format!("{}/api/v1/mls/key-packages", self.base);
        let body = serde_json::json!({
            "key_packages_b64": packages.iter().map(|p| STANDARD.encode(p)).collect::<Vec<_>>(),
        });
        let resp = Self::http()?
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
    pub async fn sync(&self, slug: &str) -> Result<Synced> {
        let url = history_url(&self.server, slug, DEFAULT_HISTORY_LIMIT);
        let path = url.strip_prefix(&self.base).unwrap_or(&url).to_string();
        let body: serde_json::Value = self.get_json(&path).await?;
        let delivered = parse_history(&body.to_string())?;
        Ok(self.replay(&delivered))
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
        Synced { lines, tidy, cids }
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
