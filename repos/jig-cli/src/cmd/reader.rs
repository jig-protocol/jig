//! One reader for `jig chat` and `jig tail`: turns delivered blocks into
//! lines, through the MLS session when the channel is encrypted.
//!
//! An encrypted channel is detected from the server's channel listing (its
//! `suite`), falling back to whether this device holds a group for it. Plain
//! channels take the same path they always did, plus signature verification.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use jig_client::open::open;
use jig_client::{DeliveredBlock, Identity};

use crate::cmd::blocks_decode::{DecodedBlock, decode, present};
use crate::cmd::common::CliContext;
use crate::cmd::history;
use crate::cmd::secure::Secure;
use crate::cmd::upgrade;

pub struct Reader {
    slug: String,
    /// The server read through, as the channel's stops are kept under it.
    server: String,
    /// Where the channels this device stopped at an unknown critical kind
    /// are kept ([`jig_client::upgrade_stops`]).
    stops: PathBuf,
    secure: Option<Arc<Secure>>,
    /// Who can read the channel, for an unencrypted one (JEP-0014 rule 5).
    notice: Option<String>,
}

/// A channel's recent history, as a pane opens with it.
#[derive(Default)]
pub struct Backlog {
    /// What to show, oldest first.
    pub lines: Vec<DecodedBlock>,
    /// Departed members still in this member's copy of the tree.
    pub tidy: Vec<String>,
    /// The delivery CID of every block the history held.
    pub deliveries: Vec<String>,
}

/// One delivered block, read.
pub struct Read {
    pub line: Option<DecodedBlock>,
    /// A departed member this device should commit out of the group.
    pub tidy: Option<String>,
}

impl Reader {
    /// A reader that never decrypts.
    #[cfg(test)]
    pub fn plain(slug: &str) -> Self {
        Self::plain_with_stops(
            slug,
            std::env::temp_dir().join("jig-test-unused-stops.json"),
        )
    }

    /// [`Self::plain`], keeping its stops at `stops`.
    #[cfg(test)]
    pub fn plain_with_stops(slug: &str, stops: PathBuf) -> Self {
        Self {
            slug: slug.to_string(),
            server: "ws://test".to_string(),
            stops,
            secure: None,
            notice: None,
        }
    }

    pub async fn open(ctx: &CliContext, slug: &str) -> Result<Self> {
        // A channel this device stopped at a block kind it does not
        // implement stays stopped until a build that does.
        let server = ctx.server_url()?;
        let stops = jig_client::upgrade_stops::UpgradeStops::default_path();
        upgrade::check_open(&stops, &server, slug)?;
        // Without local MLS state there is no telling an encrypted channel
        // from one the server relabelled, and a plain reader sends in the
        // clear; so it is an error, not a fallback.
        let secure = Secure::open(ctx)?;
        // Keep this identity reachable for DMs and adds. Best effort: a server
        // that predates v0.2 has no key-package endpoint (404), which is not
        // worth a warning; anything else is. Printed before any TUI starts.
        if let Err(e) = secure.ensure_key_packages().await
            && !e
                .downcast_ref::<crate::cmd::secure::Refused>()
                .is_some_and(|r| r.status == 404)
        {
            eprintln!("warning: MLS key packages not published: {e:#}");
        }
        let (encrypted, tier) = secure.encrypted_with_tier(slug).await?;
        Ok(Self {
            slug: slug.to_string(),
            server,
            stops,
            notice: readability_notice(encrypted, tier.as_deref()),
            secure: encrypted.then(|| Arc::new(secure)),
        })
    }

    /// Who can read the channel, when it is unencrypted.
    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    pub fn secure(&self) -> Option<&Arc<Secure>> {
        self.secure.as_ref()
    }

    /// The channel's recent history, read. Departed members still in the
    /// tree come back for tidying. Fails only when the server contradicts
    /// the history this device pinned.
    pub async fn backlog(&self, who: &Identity, server_url: &str) -> Result<Backlog> {
        let Some(secure) = &self.secure else {
            let (lines, deliveries) =
                history::backfill(who, server_url, &self.slug, history::DEFAULT_HISTORY_LIMIT)
                    .await
                    .map_err(|e| self.stopped(e))?;
            return Ok(Backlog {
                lines,
                tidy: Vec::new(),
                deliveries,
            });
        };
        match secure
            .recent(&self.slug, history::DEFAULT_HISTORY_LIMIT)
            .await
        {
            Ok(synced) => {
                if let Some(stop) = &synced.stopped {
                    return Err(self.stop_at(stop));
                }
                // A catch-up can replay many pages; the pane shows the tail.
                let mut lines: Vec<DecodedBlock> = synced
                    .lines
                    .into_iter()
                    .filter(|d| d.is_message())
                    .collect();
                lines.drain(..lines.len().saturating_sub(history::DEFAULT_HISTORY_LIMIT));
                Ok(Backlog {
                    lines,
                    tidy: synced.tidy,
                    deliveries: synced.deliveries,
                })
            }
            Err(e) => {
                let e = self.stopped(e);
                if upgrade::is_needs_upgrade(&e) {
                    return Err(e);
                }
                eprintln!("warning: could not load history for {}: {e:#}", self.slug);
                Ok(Backlog::default())
            }
        }
    }

    /// Blocks a live stream missed, read in one go, oldest first. On an
    /// encrypted channel they replay through the session in epoch order, the
    /// way [`Secure::sync`] does, so a commit among them is applied before the
    /// messages that need it.
    pub fn read_missed(&self, blocks: &[DeliveredBlock]) -> Vec<Result<DecodedBlock>> {
        let Some(secure) = &self.secure else {
            let mut read = Vec::new();
            for d in blocks {
                match self.read(d) {
                    Ok(r) => read.extend(r.line.map(Ok)),
                    // Nothing past the block the channel stopped at.
                    Err(e) if upgrade::is_needs_upgrade(&e) => {
                        read.push(Err(e));
                        break;
                    }
                    Err(e) => read.push(Err(e)),
                }
            }
            return read;
        };
        let synced = secure.replay(&self.slug, blocks);
        self.tidy(synced.tidy);
        let mut read: Vec<Result<DecodedBlock>> = synced.lines.into_iter().map(Ok).collect();
        if let Some(stop) = &synced.stopped {
            read.push(Err(self.stop_at(stop)));
        }
        read
    }

    /// `e`, as the stop it is when it is one: a critical block of a kind this
    /// build does not implement (kept, so the next session stops too), or the
    /// server's word that it stopped the channel. Anything else is `e`.
    fn stopped(&self, e: anyhow::Error) -> anyhow::Error {
        if let Some(open) = upgrade::unknown_kind(&e)
            && open.needs_upgrade()
        {
            return self.stop_at(open);
        }
        upgrade::server_stop(&self.slug, e)
    }

    /// Stop this channel at the critical block `e` names, keeping the stop
    /// for the next session, and say so.
    pub fn stop_at(&self, e: &jig_client::open::OpenError) -> anyhow::Error {
        upgrade::stop_at(&self.stops, &self.server, &self.slug, e)
    }

    /// What reading `d` came to: a line, nothing (a non-critical block of a
    /// kind this build does not implement), or the stop.
    fn unread(&self, e: anyhow::Error) -> Result<Read> {
        if upgrade::unknown_kind(&e).is_some_and(|open| open.skippable()) {
            return Ok(Read {
                line: None,
                tidy: None,
            });
        }
        Err(self.stopped(e))
    }

    pub fn read(&self, d: &DeliveredBlock) -> Result<Read> {
        let Some(secure) = &self.secure else {
            return match decode(d) {
                Ok(line) => Ok(Read {
                    line: Some(line),
                    tidy: None,
                }),
                Err(e) => self.unread(e),
            };
        };
        let opened = match open(d) {
            Ok(opened) => opened,
            Err(e) => return self.unread(e.into()),
        };
        let seen = secure.observe(&self.slug, &opened);
        let tidy = match &seen {
            jig_client::secure::Seen::Left { member, tidy: true }
            | jig_client::secure::Seen::Linked {
                old: member,
                tidy: true,
                ..
            } => Some(member.clone()),
            _ => None,
        };
        Ok(Read {
            line: present(&opened, &d.receipts, &seen),
            tidy,
        })
    }

    /// Commit departed members out of the group, in the background. Best
    /// effort and silent — it runs under a TUI, and any other member who comes
    /// online does the same job.
    pub fn tidy(&self, dids: Vec<String>) {
        let Some(secure) = self.secure.clone() else {
            return;
        };
        if dids.is_empty() {
            return;
        }
        let slug = self.slug.clone();
        tokio::spawn(async move {
            for did in dids {
                let _ = secure.tidy(&slug, &did).await;
            }
        });
    }
}

/// What a client says about who can read a channel (JEP-0014 rule 5), or
/// `None` for an encrypted one. Keyed on `encrypted`, which the CLI proves
/// against the creation block; the server's unsigned `tier` only names it.
pub fn readability_notice(encrypted: bool, tier: Option<&str>) -> Option<String> {
    if encrypted {
        return None;
    }
    Some(match tier {
        Some("frozen") => "frozen: read-only, created unencrypted before channel tiers; \
                           anyone, including the server operator, can read its history"
            .to_string(),
        Some("public") => "public: anyone, including the server operator, can read it".to_string(),
        _ => "unencrypted: anyone, including the server operator, can read it".to_string(),
    })
}
