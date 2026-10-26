//! One reader for `jig chat` and `jig tail`: turns delivered blocks into
//! lines, through the MLS session when the channel is encrypted.
//!
//! An encrypted channel is detected from the server's channel listing (its
//! `suite`), falling back to whether this device holds a group for it. Plain
//! channels take the same path they always did, plus signature verification.

use std::sync::Arc;

use anyhow::Result;
use jig_client::open::open;
use jig_client::{DeliveredBlock, Identity};

use crate::cmd::blocks_decode::{DecodedBlock, decode, present};
use crate::cmd::common::CliContext;
use crate::cmd::history;
use crate::cmd::secure::Secure;

pub struct Reader {
    slug: String,
    secure: Option<Arc<Secure>>,
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
        Self {
            slug: slug.to_string(),
            secure: None,
        }
    }

    pub async fn open(ctx: &CliContext, slug: &str) -> Result<Self> {
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
        let encrypted = secure.encrypted(slug).await?;
        Ok(Self {
            slug: slug.to_string(),
            secure: encrypted.then(|| Arc::new(secure)),
        })
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
                    .await?;
            return Ok(Backlog {
                lines,
                tidy: Vec::new(),
                deliveries,
            });
        };
        match secure.sync(&self.slug).await {
            Ok(synced) => {
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
            return blocks
                .iter()
                .filter_map(|d| self.read(d).map(|r| r.line).transpose())
                .collect();
        };
        let synced = secure.replay(blocks);
        self.tidy(synced.tidy);
        synced.lines.into_iter().map(Ok).collect()
    }

    pub fn read(&self, d: &DeliveredBlock) -> Result<Read> {
        let Some(secure) = &self.secure else {
            return Ok(Read {
                line: Some(decode(d)?),
                tidy: None,
            });
        };
        let opened = open(d)?;
        let seen = secure.session.observe(secure.server(), &opened);
        let tidy = match &seen {
            jig_client::secure::Seen::Left { member, tidy: true } => Some(member.clone()),
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
