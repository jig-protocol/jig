//! Carrying a channel another server sequences (JEP-0005 rules 12-14, 22a).
//!
//! A follower takes the owner's blocks with the owner's signed `ingest`
//! records, and keeps the owner's chain as the owner signed it:
//! - each record is checked against the channel's sequencer and stored as the
//!   bytes that arrived. Nothing here signs a record (rule 12);
//! - a record lands only as the next link of the chain: `seq` one past the
//!   head and `prev` naming it (rule 13). A record past the next is a gap,
//!   which the caller fills from the owner before going on;
//! - a second record at a `seq` already held, with other content, or a
//!   record no link can follow, is a fork. Both records are kept as
//!   evidence, and the channel takes nothing more until an operator looks
//!   (rule 14);
//! - the evidence is one fork per channel: the first stops it, and nothing
//!   sent afterwards is kept, so an owner cannot grow it;
//! - a block or record past [`jig_core::bundle::MAX_BUNDLE_BYTES`] or
//!   [`MAX_RECORD_BYTES`], or a record not in its stored form, is refused
//!   before anything is parsed or kept;
//! - every block needs an accepted share of its channel with its sequencer
//!   (`contract_offers`, follower side): a create from a server this one
//!   never agreed to follow makes no row, and an ended share takes nothing
//!   more;
//! - the author's signature is checked, but no write gate runs: the owner
//!   gated the block before it sequenced it, and its order is what a
//!   follower follows (rule 22a).
//!
//! A `shared` MLS channel is followed too (JEP-0005 rule 19): each block the
//! owner sequenced is judged against this server's mirror of the group's
//! public state, and a commit or sealed message the mirror refuses stops the
//! channel, as a fork does. A block of any other suite is refused here, so the
//! stream stops rather than carry what it cannot validate.

use jig_core::{BlockBundle, BlockKind};
use rusqlite::{OptionalExtension, params};

use crate::fanout::DeliveryPolicy;
use crate::ingest::{IngestContext, IngestError};
use crate::ingest_record::{IngestRecord, RecordError};
use crate::persist::{SqliteStore, StoredBlock, StoredReceipt};

/// Why a carried block did not land.
#[derive(Debug, thiserror::Error)]
pub enum FollowError {
    /// The block itself is refused: its author's signature, its manifest.
    #[error(transparent)]
    Block(#[from] IngestError),
    /// The record is not the owner's, or not a record.
    #[error("the record is refused: {0}")]
    Record(#[from] RecordError),
    /// The record does not place this block, in this channel.
    #[error("the record does not fit the block: {0}")]
    Mismatch(&'static str),
    /// The channel is not one this server carries for that sequencer.
    #[error("this server does not carry channel {channel_id} for {sequencer}")]
    NotCarried {
        channel_id: String,
        sequencer: String,
    },
    /// Records are missing between the head and this one: fetch them first.
    #[error("channel {channel_id} is at seq {head:?}; this record is seq {got}")]
    Gap {
        channel_id: String,
        head: Option<u64>,
        got: u64,
    },
    /// The owner's chain forked. The evidence is kept; the channel takes
    /// nothing more.
    #[error("channel {channel_id} forked at seq {seq}: the evidence is kept")]
    Fork { channel_id: String, seq: u64 },
    /// The channel stopped at an earlier fork.
    #[error("channel {channel_id} is stopped at a fork")]
    Stopped { channel_id: String },
    /// No accepted share with this sequencer names the channel: this server
    /// never agreed to carry it.
    #[error("no accepted share of channel {channel_id} with {sequencer}")]
    NoShare {
        channel_id: String,
        sequencer: String,
    },
    /// The record is larger than any record is.
    #[error("the record is {len} bytes; a follower takes at most {max}")]
    RecordTooLarge { len: usize, max: usize },
    /// The owner sequenced an MLS block that does not apply to the group as
    /// this server mirrors it (JEP-0005 rule 19). It is not delivered; the
    /// evidence is kept and the channel takes nothing more, as at a fork.
    #[error(
        "channel {channel_id} stopped at seq {seq}: the owner's block does not apply to its group: {reason}"
    )]
    Unapplied {
        channel_id: String,
        seq: u64,
        reason: String,
    },
    /// The owner sequenced a critical block of a kind this build does not
    /// implement (JEP-0005 rule 14c). Nothing of it is kept but the stop: the
    /// channel takes nothing more, and asks for nothing more, until this
    /// server is upgraded. Other channels go on.
    #[error(
        "channel {channel_id} needs an upgrade at seq {seq}: block kind `{kind}` is unknown to this version"
    )]
    NeedsUpgrade {
        channel_id: String,
        seq: u64,
        kind: String,
    },
    /// A record past a `sequencer-set`, signed by a sequencer the channel
    /// moved away from (JEP-0005 rule 11a): refused, as two keys' words,
    /// not as a signed proof against either.
    #[error(
        "channel {channel_id} moved to {sequencer} before seq {seq}; a record there by {signer} is refused"
    )]
    Superseded {
        channel_id: String,
        seq: u64,
        sequencer: String,
        signer: String,
    },
    /// A `sequencer-set` to a sequencer that already orders another channel
    /// of this slug, an archived one included (JEP-0005 rule 11a). Two
    /// channels of one slug under one sequencer would make the slug name
    /// either, so the channel stops here, with the evidence kept, as at a
    /// block its group refuses.
    #[error(
        "channel {channel_id} stopped at seq {seq}: it moved to {sequencer}, which already orders a channel `{slug}`"
    )]
    SlugTaken {
        channel_id: String,
        seq: u64,
        sequencer: String,
        slug: String,
    },
    /// A `sequencer-set` that is not a move this server can follow.
    #[error("the sequencer move is refused: {0}")]
    Move(#[from] jig_core::sequencer_move::MoveError),
    /// Not followed in this slice.
    #[error("{0}")]
    Unsupported(&'static str),
    #[error(transparent)]
    Persist(#[from] crate::persist::PersistError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// What became of a carried block that was no error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Followed {
    /// Stored, as the chain's new head.
    Landed { block_cid: String, seq: u64 },
    /// Already held, with this same record.
    Duplicate { block_cid: String, seq: u64 },
}

/// The most a carried record's stored form may hold. A real one is under
/// 1.5 KiB: two CIDs, a DID, a hash and a COSE_Sign1 of them.
pub const MAX_RECORD_BYTES: usize = 4 * 1024;

/// Two records that cannot both be the owner's chain, kept as they arrived.
/// A channel keeps one: the first fork stops it, and nothing it is sent
/// afterwards is kept, so a hostile owner cannot grow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEvidence {
    pub channel_id: String,
    pub seq: u64,
    /// The record this server held at `seq`, or its head when the new one
    /// does not follow it.
    pub held: Vec<u8>,
    /// The record that contradicts it.
    pub offered: Vec<u8>,
    pub found_at: i64,
}

/// A carried channel that waited at `seq`, under a release before the
/// stall was repaired (#427): the owner's record there named `block_cid`,
/// which this server holds in its own channel `holder`. Kept until a record of
/// the channel lands, which takes the stalled one again first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarriedStall {
    pub channel_id: String,
    pub seq: u64,
    pub block_cid: String,
    pub holder: String,
    pub found_at: i64,
}

impl std::fmt::Display for CarriedStall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "channel {} stalled at seq {}: block {} is held in channel {}",
            self.channel_id, self.seq, self.block_cid, self.holder
        )
    }
}

/// A carried channel stopped at a critical block of a kind this build does
/// not implement (JEP-0005 rule 14c): the owner's record at `seq` names
/// `block_cid`, of kind `kind`. Nothing of the block is kept. A build that
/// implements the kind drops the stop when it opens the store
/// (`clear_known_upgrades`, run by the store's migration), and the channel then takes the
/// block again from the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeStop {
    pub channel_id: String,
    pub seq: u64,
    pub block_cid: String,
    pub kind: String,
    pub found_at: i64,
}

impl std::fmt::Display for UpgradeStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "channel {} at seq {} uses block kind `{}`, unknown to this version",
            self.channel_id, self.seq, self.kind
        )
    }
}

impl UpgradeStop {
    /// What a client of this server is told about the channel: on a refused
    /// subscribe or history read, and once to a live subscription when the
    /// channel stops.
    pub fn notice(&self) -> crate::fanout::ChannelNotice {
        crate::fanout::ChannelNotice {
            status: 409,
            code: crate::fanout::CHANNEL_NEEDS_UPGRADE,
            channel_id: self.channel_id.clone(),
            message: format!(
                "this channel needs this server to upgrade: block kind `{}` at seq {} is unknown \
                 to it, so it carries nothing of the channel past seq {}",
                self.kind,
                self.seq,
                self.seq.saturating_sub(1)
            ),
        }
    }
}

/// One `sequencer-set` in a channel's chain, as this server keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMove {
    /// The `seq` of the set's record: the first the new sequencer signs.
    pub seq: u64,
    /// The new sequencer's DID.
    pub sequencer: String,
    /// The sequencer before it.
    pub previous: String,
    pub block_cid: String,
}

/// A `sequencer-set` that arrived before this server held the head it cites
/// (JEP-0005 rule 11a), kept as it arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMove {
    /// The `seq` of the set's record: the cited head's + 1.
    pub seq: u64,
    /// The new sequencer, which sent it.
    pub sequencer: String,
    manifest: Vec<u8>,
    code: Vec<u8>,
    sig: Vec<u8>,
    record: Vec<u8>,
}

/// Where a client stops reading a channel (JEP-0005 rules 11a and 14c): the
/// first block of a critical kind added after `v0.2.0` that the client does
/// not implement. It is served the channel's records before `seq`, and told
/// at `seq` that the channel needs it to upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderGate {
    pub channel_id: String,
    pub seq: u64,
    pub kind: String,
}

impl ReaderGate {
    pub fn notice(&self) -> crate::fanout::ChannelNotice {
        crate::fanout::ChannelNotice {
            status: 409,
            code: crate::fanout::CHANNEL_NEEDS_UPGRADE,
            channel_id: self.channel_id.clone(),
            message: format!(
                "this channel needs your client to upgrade: block kind `{}` at seq {} is one it \
                 does not implement, so it is served nothing of the channel from there on",
                self.kind, self.seq
            ),
        }
    }
}

/// The kind of a carried block: one this build implements, or one it does
/// not (JEP-0005 rule 14c).
enum CarriedKind {
    Known(BlockKind),
    Unknown { name: String, critical: bool },
}

impl CarriedKind {
    fn known(&self) -> Option<BlockKind> {
        match self {
            Self::Known(kind) => Some(*kind),
            Self::Unknown { .. } => None,
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Known(kind) => kind.as_str(),
            Self::Unknown { name, .. } => name,
        }
    }
}

/// The `chain_evidence`, `carried_stalls`, `carried_upgrades` and
/// `carried_records` tables and
/// the `chain_records` view, created by [`SqliteStore`]'s migration.
///
/// `ingest_records` holds one record per block, under the block's own
/// channel. A carried channel's record for a block this server already holds
/// in another channel of its own (one an older relay landed there, whose
/// chain still names it) is kept in `carried_records` instead, and the block
/// stays where it is. `chain_records` is both, and is what a channel's chain
/// is read from.
pub(crate) fn migrate(conn: &rusqlite::Connection) -> crate::persist::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS chain_evidence (
            channel_id TEXT NOT NULL,
            seq        INTEGER NOT NULL,
            held       BLOB NOT NULL,
            offered    BLOB NOT NULL,
            found_at   INTEGER NOT NULL,
            PRIMARY KEY (channel_id)
        );
        CREATE TABLE IF NOT EXISTS carried_stalls (
            channel_id TEXT PRIMARY KEY,
            seq        INTEGER NOT NULL,
            block_cid  TEXT NOT NULL,
            holder     TEXT NOT NULL,
            found_at   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS carried_upgrades (
            channel_id TEXT PRIMARY KEY,
            seq        INTEGER NOT NULL,
            block_cid  TEXT NOT NULL,
            kind       TEXT NOT NULL,
            found_at   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS carried_records (
            channel_id TEXT NOT NULL,
            seq        INTEGER NOT NULL,
            block_cid  TEXT NOT NULL REFERENCES blocks(cid),
            record     BLOB NOT NULL,
            PRIMARY KEY (channel_id, seq)
        );
        -- Each `sequencer-set` in a channel's chain (JEP-0005 rule 11a):
        -- from `seq` on, `sequencer` signs the channel's records, where
        -- `previous` did before.
        CREATE TABLE IF NOT EXISTS channel_moves (
            channel_id TEXT NOT NULL,
            seq        INTEGER NOT NULL,
            sequencer  TEXT NOT NULL,
            previous   TEXT NOT NULL,
            block_cid  TEXT NOT NULL,
            PRIMARY KEY (channel_id, seq)
        );
        -- A `sequencer-set` that cites a head this server does not hold yet
        -- (JEP-0005 rule 11a): kept, as it arrived, until the records up to
        -- that head have landed, then landed itself.
        CREATE TABLE IF NOT EXISTS pending_moves (
            channel_id TEXT PRIMARY KEY,
            seq        INTEGER NOT NULL,
            sequencer  TEXT NOT NULL,
            manifest   BLOB NOT NULL,
            code       BLOB NOT NULL,
            sig        BLOB NOT NULL,
            record     BLOB NOT NULL
        );
        CREATE VIEW IF NOT EXISTS chain_records AS
            SELECT block_cid, channel_id, seq, record FROM ingest_records
            UNION ALL
            SELECT block_cid, channel_id, seq, record FROM carried_records;
        "#,
    )?;
    clear_known_upgrades(conn)
}

/// Drop the stops at kinds this build implements, each time the store opens:
/// an upgraded server takes those channels again from the block they stopped
/// at, since their head never moved past it.
fn clear_known_upgrades(conn: &rusqlite::Connection) -> crate::persist::Result<()> {
    let kinds: Vec<(String, String)> = conn
        .prepare("SELECT channel_id, kind FROM carried_upgrades")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (channel_id, kind) in kinds {
        if kind.parse::<BlockKind>().is_ok() {
            tracing::info!(
                channel_id,
                kind,
                "this version implements the block kind a carried channel stopped at; taking it again"
            );
            conn.execute(
                "DELETE FROM carried_upgrades WHERE channel_id = ?1",
                [&channel_id],
            )?;
        }
    }
    Ok(())
}

fn upgrade_stop(r: &rusqlite::Row<'_>) -> rusqlite::Result<UpgradeStop> {
    Ok(UpgradeStop {
        channel_id: r.get(0)?,
        seq: r.get::<_, i64>(1)? as u64,
        block_cid: r.get(2)?,
        kind: r.get(3)?,
        found_at: r.get(4)?,
    })
}

/// How a landing attempt ended, inside its transaction.
enum Landing {
    Landed,
    Duplicate,
    Gap(Option<u64>),
    Fork,
    Stopped,
    /// The block is the next link, but critical and of a kind this build does
    /// not implement: the stop is kept, the block is not.
    NeedsUpgrade,
    /// The block's effect failed; nothing was kept.
    EffectFailed(anyhow::Error),
}

impl SqliteStore {
    /// The chain evidence kept for `channel_id`: none, or the one fork that
    /// stopped it.
    pub fn chain_evidence(&self, channel_id: &str) -> crate::persist::Result<Vec<ChainEvidence>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT channel_id, seq, held, offered, found_at FROM chain_evidence
             WHERE channel_id = ?1 ORDER BY rowid",
        )?;
        let rows = stmt
            .query_map([channel_id], |r| {
                Ok(ChainEvidence {
                    channel_id: r.get(0)?,
                    seq: r.get::<_, i64>(1)? as u64,
                    held: r.get(2)?,
                    offered: r.get(3)?,
                    found_at: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Stop `channel_id` at `seq`, where the owner's record `offered` names a
    /// block its group refuses; `held` is this server's head before it.
    fn keep_unapplied(
        &self,
        channel_id: &str,
        seq: u64,
        held: &[u8],
        offered: &[u8],
    ) -> crate::persist::Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT OR IGNORE INTO chain_evidence (channel_id, seq, held, offered, found_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                channel_id,
                seq as i64,
                held,
                offered,
                chrono::Utc::now().timestamp()
            ],
        )?;
        Ok(())
    }

    /// The carried channels waiting on a block held in another channel.
    pub fn carried_stalls(&self) -> crate::persist::Result<Vec<CarriedStall>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT channel_id, seq, block_cid, holder, found_at FROM carried_stalls
             ORDER BY found_at, channel_id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(CarriedStall {
                    channel_id: r.get(0)?,
                    seq: r.get::<_, i64>(1)? as u64,
                    block_cid: r.get(2)?,
                    holder: r.get(3)?,
                    found_at: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The moves of `channel_id`'s sequencer, oldest first (JEP-0005 rule
    /// 11a): none for a channel that never moved.
    pub fn channel_moves(&self, channel_id: &str) -> crate::persist::Result<Vec<ChannelMove>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT seq, sequencer, previous, block_cid FROM channel_moves
             WHERE channel_id = ?1 ORDER BY seq",
        )?;
        let rows = stmt
            .query_map([channel_id], |r| {
                Ok(ChannelMove {
                    seq: r.get::<_, i64>(0)? as u64,
                    sequencer: r.get(1)?,
                    previous: r.get(2)?,
                    block_cid: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The `sequencer-set` kept for `channel_id` until this server holds the
    /// head it cites, if any.
    pub fn pending_move(&self, channel_id: &str) -> crate::persist::Result<Option<PendingMove>> {
        let conn = self.conn.lock().expect("poisoned");
        Ok(conn
            .query_row(
                "SELECT seq, sequencer, manifest, code, sig, record FROM pending_moves
                 WHERE channel_id = ?1",
                [channel_id],
                |r| {
                    Ok(PendingMove {
                        seq: r.get::<_, i64>(0)? as u64,
                        sequencer: r.get(1)?,
                        manifest: r.get(2)?,
                        code: r.get(3)?,
                        sig: r.get(4)?,
                        record: r.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// Every kept move, by channel: the channels to ask its new sequencer
    /// for the records up to the head it cites.
    pub fn pending_moves(&self) -> crate::persist::Result<Vec<(String, PendingMove)>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT channel_id, seq, sequencer, manifest, code, sig, record FROM pending_moves",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    PendingMove {
                        seq: r.get::<_, i64>(1)? as u64,
                        sequencer: r.get(2)?,
                        manifest: r.get(3)?,
                        code: r.get(4)?,
                        sig: r.get(5)?,
                        record: r.get(6)?,
                    },
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn keep_pending_move(
        &self,
        channel_id: &str,
        moved: &PendingMove,
    ) -> crate::persist::Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT OR REPLACE INTO pending_moves
                 (channel_id, seq, sequencer, manifest, code, sig, record)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                channel_id,
                moved.seq as i64,
                moved.sequencer,
                moved.manifest,
                moved.code,
                moved.sig,
                moved.record
            ],
        )?;
        Ok(())
    }

    /// Whether `sequencer` orders a channel of `slug` here other than
    /// `except`, archived or not: the rows `UNIQUE (sequencer_did, slug)`
    /// would hold against a move of `except` to `sequencer`.
    pub fn slug_held_by(
        &self,
        sequencer: &str,
        slug: &str,
        except: &str,
    ) -> crate::persist::Result<bool> {
        Ok(self.conn.lock().expect("poisoned").query_row(
            "SELECT EXISTS(SELECT 1 FROM channels
             WHERE sequencer_did = ?1 AND slug = ?2 AND id != ?3)",
            params![sequencer, slug, except],
            |r| r.get(0),
        )?)
    }

    /// The highest `seq` of `channel_id`'s chain this server holds.
    pub fn chain_head_seq(&self, channel_id: &str) -> crate::persist::Result<Option<u64>> {
        let conn = self.conn.lock().expect("poisoned");
        let head: Option<i64> = conn.query_row(
            "SELECT MAX(seq) FROM chain_records WHERE channel_id = ?1",
            [channel_id],
            |r| r.get(0),
        )?;
        Ok(head.map(|s| s as u64))
    }

    /// Where a client implementing `client_kinds` stops reading `channel_id`
    /// ([`ReaderGate`]): the first block in its chain of a kind this build
    /// implements, that gates older readers
    /// ([`jig_core::block_kind::gates_older_readers`]), and that the client
    /// does not list. `None` when it can read the whole chain.
    pub fn reader_gate(
        &self,
        channel_id: &str,
        client_kinds: &[String],
    ) -> crate::persist::Result<Option<ReaderGate>> {
        let gated: Vec<&str> = BlockKind::ALL
            .iter()
            .map(BlockKind::as_str)
            .filter(|k| jig_core::block_kind::gates_older_readers(k))
            .filter(|k| !client_kinds.iter().any(|c| c == k))
            .collect();
        if gated.is_empty() {
            return Ok(None);
        }
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT c.seq, b.block_kind FROM chain_records c JOIN blocks b ON b.cid = c.block_cid
             WHERE c.channel_id = ?1 AND b.block_kind IN (SELECT value FROM json_each(?2))
             ORDER BY c.seq LIMIT 1",
        )?;
        Ok(stmt
            .query_row(
                params![channel_id, serde_json::to_string(&gated).expect("strings")],
                |r| {
                    Ok(ReaderGate {
                        channel_id: channel_id.to_string(),
                        seq: r.get::<_, i64>(0)? as u64,
                        kind: r.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    /// The DID expected to sign `channel_id`'s record at `seq` (JEP-0005
    /// rule 11a): the sequencer of the latest move at or below `seq`, else
    /// the one the channel's row names, the sequencer it was created under
    /// (or, along its key links, the DID that signs for it now). `None` for
    /// a channel this server holds no row for.
    ///
    /// The one lookup for who signs a channel's records here; within the
    /// first range, the DIDs the sequencer signed as before its key changed
    /// are [`SqliteStore::owner_predecessors`].
    pub fn expected_sequencer(
        &self,
        channel_id: &str,
        seq: u64,
    ) -> crate::persist::Result<Option<String>> {
        if let Some(moved) = self
            .channel_moves(channel_id)?
            .into_iter()
            .rev()
            .find(|m| m.seq <= seq)
        {
            return Ok(Some(moved.sequencer));
        }
        let first = self.channel_moves(channel_id)?.into_iter().next();
        Ok(match first {
            // Before the first move: the DID that move took over from.
            Some(first) => Some(first.previous),
            None => self
                .get_channel_by_id_including_archived(channel_id)?
                .map(|c| crate::effect::canonical_did_string(&c.sequencer_did)),
        })
    }

    /// The stop kept for `channel_id` at a block it needs an upgrade for, if
    /// any.
    pub fn carried_upgrade(&self, channel_id: &str) -> crate::persist::Result<Option<UpgradeStop>> {
        let conn = self.conn.lock().expect("poisoned");
        Ok(conn
            .query_row(
                "SELECT channel_id, seq, block_cid, kind, found_at FROM carried_upgrades
                 WHERE channel_id = ?1",
                [channel_id],
                upgrade_stop,
            )
            .optional()?)
    }

    /// Keep `moved` as though a `sequencer-set` had landed in `channel_id`,
    /// for other crates' tests of what follows a move.
    #[cfg(any(test, feature = "test-support"))]
    pub fn record_move_for_tests(
        &self,
        channel_id: &str,
        moved: &ChannelMove,
    ) -> crate::persist::Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT OR REPLACE INTO channel_moves (channel_id, seq, sequencer, previous, block_cid)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                channel_id,
                moved.seq as i64,
                moved.sequencer,
                moved.previous,
                moved.block_cid
            ],
        )?;
        Ok(())
    }

    /// Keep a block of kind `kind` at `seq` of `channel_id`'s chain, with a
    /// record signed by a fixed test key, as though the owner's stream had landed
    /// it: for other crates' tests of what a channel answers a client that
    /// cannot read the kind ([`Self::reader_gate`]). Returns its CID.
    #[cfg(any(test, feature = "test-support"))]
    pub fn gate_for_tests(
        &self,
        channel_id: &str,
        seq: u64,
        kind: &str,
    ) -> crate::persist::Result<String> {
        let block_cid = crate::ingest_record::label_cid(&format!("{channel_id} {seq} {kind}"));
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let record = crate::ingest_record::RecordSigner {
            channel_id: channel_id.to_string(),
            key: &key,
            ingest_wall_ms: 1,
            ingest_logical: 0,
        }
        .sign(seq, &block_cid, [0; 32])
        .map_err(|e| crate::persist::PersistError::Corrupt(e.to_string()))?;
        let conn = self.conn.lock().expect("poisoned");
        conn.execute(
            "INSERT INTO blocks (cid, channel_id, block_kind, sender_did, sender_sig, bundle_bytes,
                 is_synthetic, hlc_wall_ms, hlc_logical, hlc_origin, posted_at, origin_server)
             VALUES (?1, ?2, ?3, 'did:jig:zauthor', x'', x'', 1, 1, 0, '', 0, '')",
            params![block_cid, channel_id, kind],
        )?;
        conn.execute(
            "INSERT INTO carried_records (channel_id, seq, block_cid, record) VALUES (?1, ?2, ?3, ?4)",
            params![channel_id, seq as i64, block_cid, record.encode()],
        )?;
        Ok(block_cid)
    }

    /// Keep `stop` as though a critical block of an unknown kind had stopped
    /// its channel, for other crates' tests of what a stopped channel answers.
    #[cfg(any(test, feature = "test-support"))]
    pub fn stop_for_upgrade_for_tests(&self, stop: &UpgradeStop) -> crate::persist::Result<()> {
        self.conn.lock().expect("poisoned").execute(
            "INSERT OR REPLACE INTO carried_upgrades (channel_id, seq, block_cid, kind, found_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                stop.channel_id,
                stop.seq as i64,
                stop.block_cid,
                stop.kind,
                stop.found_at
            ],
        )?;
        Ok(())
    }

    /// Every carried channel stopped at a block it needs an upgrade for.
    pub fn carried_upgrades(&self) -> crate::persist::Result<Vec<UpgradeStop>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT channel_id, seq, block_cid, kind, found_at FROM carried_upgrades
             ORDER BY found_at, channel_id",
        )?;
        let rows = stmt
            .query_map([], upgrade_stop)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The stored bytes of `channel_id`'s record at `seq`, as they arrived.
    pub fn ingest_record_bytes(
        &self,
        channel_id: &str,
        seq: u64,
    ) -> crate::persist::Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().expect("poisoned");
        Ok(conn
            .query_row(
                "SELECT record FROM chain_records WHERE channel_id = ?1 AND seq = ?2",
                params![channel_id, seq as i64],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Store `block` with the owner's `record`, verified already, as the next
    /// link of its chain, in one transaction: or keep the evidence that it
    /// cannot be one.
    ///
    /// With `needs_upgrade`, the block is critical and of that kind, which
    /// this build does not implement: where it would land, the channel is
    /// stopped there instead, and the block is not stored.
    fn land_carried(
        &self,
        block: &StoredBlock,
        record: &IngestRecord,
        record_bytes: &[u8],
        needs_upgrade: Option<&str>,
        effect: impl FnOnce(&rusqlite::Connection) -> anyhow::Result<()>,
    ) -> crate::persist::Result<Landing> {
        let mut conn = self.conn.lock().expect("poisoned");
        let tx = conn.transaction()?;
        let channel_id = record.channel_id.as_str();
        let stopped: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM chain_evidence WHERE channel_id = ?1)",
            [channel_id],
            |r| r.get(0),
        )?;
        if stopped {
            return Ok(Landing::Stopped);
        }
        let upgrading: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM carried_upgrades WHERE channel_id = ?1)",
            [channel_id],
            |r| r.get(0),
        )?;
        if upgrading {
            return Ok(Landing::NeedsUpgrade);
        }
        let held_at = |seq: u64| -> crate::persist::Result<Option<Vec<u8>>> {
            Ok(tx
                .query_row(
                    "SELECT record FROM chain_records WHERE channel_id = ?1 AND seq = ?2",
                    params![channel_id, seq as i64],
                    |r| r.get(0),
                )
                .optional()?)
        };
        let keep = |held: &[u8]| -> crate::persist::Result<()> {
            tx.execute(
                "INSERT OR IGNORE INTO chain_evidence (channel_id, seq, held, offered, found_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    channel_id,
                    record.seq as i64,
                    held,
                    record_bytes,
                    chrono::Utc::now().timestamp()
                ],
            )?;
            Ok(())
        };
        // A record at a seq already held: the same one again, or a fork.
        if let Some(held) = held_at(record.seq)? {
            let same = IngestRecord::decode(&held)
                .map(|h| h.cose == record.cose && h.block_cid == record.block_cid)
                .unwrap_or(false);
            if same {
                return Ok(Landing::Duplicate);
            }
            keep(&held)?;
            tx.commit()?;
            return Ok(Landing::Fork);
        }
        let head: Option<(u64, Vec<u8>)> = tx
            .query_row(
                "SELECT seq, record FROM chain_records WHERE channel_id = ?1
                 ORDER BY seq DESC LIMIT 1",
                [channel_id],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)),
            )
            .optional()?;
        match &head {
            None if !record.is_genesis() => return Ok(Landing::Gap(None)),
            Some((seq, _)) if record.seq > seq + 1 => return Ok(Landing::Gap(Some(*seq))),
            Some((_, held)) => {
                let follows = IngestRecord::decode(held)
                    .map(|h| record.follows(&h))
                    .unwrap_or(false);
                if !follows {
                    // The next seq, but not the next link: the owner signed
                    // two chains.
                    keep(held)?;
                    tx.commit()?;
                    return Ok(Landing::Fork);
                }
            }
            None => {}
        }
        if let Some(kind) = needs_upgrade {
            tx.execute(
                "INSERT OR IGNORE INTO carried_upgrades (channel_id, seq, block_cid, kind, found_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    channel_id,
                    record.seq as i64,
                    record.block_cid,
                    kind,
                    chrono::Utc::now().timestamp()
                ],
            )?;
            tx.commit()?;
            return Ok(Landing::NeedsUpgrade);
        }
        // A block held already in a relayed copy of this channel, set aside
        // ([`SqliteStore::quarantine_relayed_copy`]): one CID is one block, so
        // the owner's chain takes it back into the channel. A block held in
        // any other channel stays where it is, and the owner's record goes to
        // `carried_records`: a block named by slug can sit in this server's
        // own channel of the same name, whose chain still names it, from an
        // older relay (#357, #427). Both chains then hold it, each under its
        // own record.
        let in_copy: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blocks b JOIN quarantined_copies q
                 ON b.channel_id = q.copy_id
             WHERE b.cid = ?1 AND q.channel_id = ?2)",
            params![block.cid, channel_id],
            |r| r.get(0),
        )?;
        let held: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blocks WHERE cid = ?1)",
            [&block.cid],
            |r| r.get(0),
        )?;
        let records = match (held, in_copy) {
            (true, true) => {
                tx.execute(
                    "UPDATE blocks SET channel_id = ?2 WHERE cid = ?1",
                    params![block.cid, channel_id],
                )?;
                "ingest_records"
            }
            (true, false) => "carried_records",
            (false, _) => {
                crate::persist::insert_block_on(&tx, block)?;
                "ingest_records"
            }
        };
        tx.execute(
            &format!(
                "INSERT INTO {records} (block_cid, channel_id, seq, record) VALUES (?1, ?2, ?3, ?4)"
            ),
            params![
                record.block_cid,
                channel_id,
                record.seq as i64,
                record_bytes
            ],
        )?;
        // The effect lands with the block, or neither does: a record whose
        // effect failed can come again.
        if let Err(e) = effect(&tx) {
            return Ok(Landing::EffectFailed(e));
        }
        tx.execute(
            "DELETE FROM carried_stalls WHERE channel_id = ?1",
            [channel_id],
        )?;
        tx.commit()?;
        Ok(Landing::Landed)
    }
}

/// This server, `me`, sequenced `channel_id` and its owner moved it away
/// (JEP-0005 rule 11a): `bundle` is the owner's `sequencer-set`, and
/// `record_bytes` its record, as the new sequencer `link` sent them. Checked
/// as every reader checks a move, against the head this server signed; then
/// kept as the channel's move, so this server refuses writes to it
/// (`IngestError::SequencerMoved`) and never sequences it again. The block
/// itself is not stored: its `seq` may hold a record of this server's own.
///
/// Returns how many records this server signed past the cited head: the
/// writes the move left behind, for the operator.
pub fn record_moved_away(
    store: &SqliteStore,
    bundle: BlockBundle<'_>,
    sig: &[u8],
    record_bytes: &[u8],
    link: &str,
    me: &str,
) -> Result<u64, FollowError> {
    let (manifest, kind) = carried_manifest(bundle.manifest_bytes)?;
    if kind.known() != Some(BlockKind::SequencerSet) {
        return Err(FollowError::Mismatch("not a sequencer move"));
    }
    let sender =
        crate::ingest::verify_sig(bundle.manifest_bytes, bundle.code_bytes, &manifest, sig)?;
    let record = IngestRecord::decode(record_bytes)?;
    let set = jig_core::sequencer_move::SequencerSet::from_metadata(&manifest.metadata)?;
    let chan = store
        .get_channel_by_id_including_archived(&record.channel_id)?
        .filter(|c| crate::handshake::same_did(&c.sequencer_did, me))
        .ok_or(FollowError::Mismatch(
            "a move of a channel this server does not sequence",
        ))?;
    if set.channel_id != chan.id || !crate::handshake::same_did(&set.sequencer, link) {
        return Err(FollowError::Mismatch(
            "the move names another channel or server",
        ));
    }
    let block_cid = bundle
        .block_cid()
        .map_err(|e| IngestError::BundleMalformed(e.to_string()))?
        .to_string();
    if record.block_cid != block_cid {
        return Err(FollowError::Mismatch("the record is for another block"));
    }
    if !crate::roles::rights_at_channel(
        store,
        &chan,
        &crate::effect::canonical_did_string(&sender.to_did_jig_string()),
        record.seq,
    )?
    .owner
    {
        return Err(FollowError::Mismatch(
            "a sequencer move signed by a DID that is not the channel's owner",
        ));
    }
    record.verify(&set.sequencer)?;
    set.check_record(record.seq, &record.prev, &record.sequencer)?;
    let cited = store
        .ingest_record_bytes(&chan.id, set.head.seq)?
        .and_then(|b| IngestRecord::decode(&b).ok())
        .filter(|h| h.hash() == set.head.hash && crate::handshake::same_did(&h.sequencer, me))
        .ok_or(FollowError::Mismatch(
            "the move cites a head this server did not sign",
        ))?;
    let past = store.chain_head_seq(&chan.id)?.unwrap_or(cited.seq) - cited.seq;
    {
        let conn = store.conn.lock().expect("poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO channel_moves (channel_id, seq, sequencer, previous, block_cid)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![chan.id, record.seq as i64, set.sequencer, me, block_cid],
        )
        .map_err(crate::persist::PersistError::from)?;
        conn.execute(
            "UPDATE channels SET sequencer_did = ?1 WHERE id = ?2",
            params![set.sequencer, chan.id],
        )
        .map_err(crate::persist::PersistError::from)?;
    }
    Ok(past)
}

/// Check that this server, `me`, can take `chan` over by the `sequencer-set`
/// `manifest` (JEP-0005 rule 11a), submitted to it by the channel's owner:
/// - the block names this channel and this server;
/// - its move accept is this server's own (verified under `me`);
/// - this server carries the channel under an accepted share with its
///   sequencer, and does not sequence it already;
/// - the head the block cites is the newest record this server holds, so the
///   record it signs is right after it.
///
/// The write gate checks the author is an owner.
pub fn check_takeover(
    store: &SqliteStore,
    chan: &crate::persist::StoredChannel,
    manifest: &jig_core::BlockManifest,
    me: &str,
) -> Result<jig_core::sequencer_move::SequencerSet, IngestError> {
    let refused = |detail: &str| IngestError::MoveRefused {
        detail: detail.to_string(),
    };
    let set = jig_core::sequencer_move::SequencerSet::from_metadata(&manifest.metadata)
        .map_err(|e| refused(&e.to_string()))?;
    if set.channel_id != chan.id {
        return Err(refused("it names another channel"));
    }
    if !crate::handshake::same_did(&set.sequencer, me) {
        return Err(refused(
            "it moves the channel to another server, which must sign its record",
        ));
    }
    let current = crate::effect::canonical_did_string(&chan.sequencer_did);
    if chan.sequencer_did.is_empty() || crate::handshake::same_did(&current, me) {
        return Err(refused("this server sequences the channel already"));
    }
    if !store.has_accepted_share(&chan.id, &current)? {
        return Err(refused(
            "this server holds no accepted share of the channel",
        ));
    }
    // Rule 11a: a slug names one channel per sequencer. A channel of this
    // slug here, archived or not, taken since this server's move accept,
    // refuses the move.
    if store.slug_held_by(store.local_sequencer(), &chan.slug, &chan.id)?
        || store.slug_held_by(me, &chan.slug, &chan.id)?
    {
        return Err(refused(&format!(
            "this server already orders a channel `{}`",
            chan.slug
        )));
    }
    let head = store
        .chain_head_seq(&chan.id)?
        .ok_or_else(|| refused("this server holds none of the channel's chain"))?;
    let held = store
        .ingest_record_bytes(&chan.id, head)?
        .and_then(|b| IngestRecord::decode(&b).ok())
        .ok_or_else(|| refused("this server's head record does not read"))?;
    if set.head.seq != head || set.head.hash != held.hash() {
        return Err(refused(&format!(
            "it cites seq {}, and this server's newest record is seq {head}; \
             cite that one once this server holds it",
            set.head.seq
        )));
    }
    Ok(set)
}

/// Take one block of a channel `sequencer` owns, with its record as the owner
/// sent it (`record_bytes`, the stored form, kept byte for byte).
///
/// The first block of a channel is its `channel-create` at seq 0, which makes
/// the carried row: owned by `sequencer`, whatever this server's own DID.
/// Every later block must be the next link of that channel's chain.
///
/// Precondition: the caller MUST have authenticated the connection the block
/// came on as `sequencer`'s DID. This function cannot see the connection; it
/// checks only that an accepted share of the channel with `sequencer` exists
/// (`NoShare` otherwise), so a caller that passes a DID the peer merely
/// claims lets that peer speak for any owner this server follows.
///
/// A sequencer move (JEP-0005 rule 11a) is taken from a DID with no share of
/// the channel: the new sequencer sends its own `sequencer-set`, and then the
/// records up to the head it cites to a follower behind it, before its
/// re-offer is accepted. The owner's signature is the move's authority, but
/// only for a source the operator chose: the caller MUST pass only a DID that
/// is a configured peer, and SHOULD charge the peer's quota before calling.
pub async fn ingest_sequenced(
    ctx: &IngestContext,
    bundle: BlockBundle<'_>,
    sig: Vec<u8>,
    record_bytes: &[u8],
    sequencer: &str,
) -> Result<Followed, FollowError> {
    crate::ingest::check_bundle_size(bundle.manifest_bytes, bundle.code_bytes)?;
    if record_bytes.len() > MAX_RECORD_BYTES {
        return Err(FollowError::RecordTooLarge {
            len: record_bytes.len(),
            max: MAX_RECORD_BYTES,
        });
    }
    let (manifest, kind) = carried_manifest(bundle.manifest_bytes)?;
    crate::ingest::check_manifest_dids(&manifest)?;
    let sender =
        crate::ingest::verify_sig(bundle.manifest_bytes, bundle.code_bytes, &manifest, &sig)?;

    let record = IngestRecord::decode(record_bytes)?;
    // The stored form exactly, as the owner stores it: nothing rides along
    // outside the signed fields, and what a client is sent is what was signed.
    if record.encode() != record_bytes {
        return Err(FollowError::Mismatch(
            "the record is not in its stored form",
        ));
    }
    let block_cid = bundle
        .block_cid()
        .map_err(|e| IngestError::BundleMalformed(e.to_string()))?
        .to_string();
    if record.block_cid != block_cid {
        return Err(FollowError::Mismatch("the record is for another block"));
    }
    let channel_id = record.channel_id.clone();
    let not_carried = || FollowError::NotCarried {
        channel_id: channel_id.clone(),
        sequencer: sequencer.to_string(),
    };

    // JEP-0005 rule 11a: the channel's moves so far, and whether this block
    // is the next one. A record past a move is the new sequencer's; one by a
    // DID the channel moved away from is refused, before anything else is
    // asked of it.
    let moves = ctx.store.channel_moves(&channel_id)?;
    let moving = match kind.known() {
        Some(BlockKind::SequencerSet) => Some(
            jig_core::sequencer_move::SequencerSet::from_metadata(&manifest.metadata)?,
        ),
        _ => None,
    };
    let range = moves.iter().rev().find(|m| m.seq <= record.seq);
    if let Some(range) = range
        && moving.is_none()
        && !crate::handshake::same_did(&record.sequencer, &range.sequencer)
    {
        let moved_from = |did: &str| {
            moves.iter().any(|m| {
                crate::handshake::same_did(&m.previous, did)
                    || (m.seq < range.seq && crate::handshake::same_did(&m.sequencer, did))
            })
        };
        if moved_from(&record.sequencer) {
            return Err(FollowError::Superseded {
                channel_id,
                seq: record.seq,
                sequencer: range.sequencer.clone(),
                signer: record.sequencer.clone(),
            });
        }
    }

    // A follower behind the head a move cites takes the records up to it
    // from the new sequencer, which serves them: each is held to the range of
    // the schedule it falls in, the old sequencer's, whoever serves it
    // (JEP-0005 rule 11a). Below, `sequencer` is the DID the record is held
    // to; `link` is the one that sent it.
    let link = sequencer;
    let pending = ctx.store.pending_move(&channel_id)?;
    let backfill_for = match &pending {
        Some(p)
            if moving.is_none()
                && crate::handshake::same_did(&p.sequencer, link)
                && record.seq < p.seq =>
        {
            ctx.store.expected_sequencer(&channel_id, record.seq)?
        }
        _ => None,
    };
    let sequencer: &str = backfill_for.as_deref().unwrap_or(link);

    // The DIDs the owner signed as before `sequencer`, along the key links
    // its offer came with (JEP-0005 rule 7, D37): the channel's creation
    // block may name one of them, and the records signed before the owner's
    // key changed are theirs.
    let predecessors = ctx.store.owner_predecessors(&channel_id, sequencer)?;

    // The channel the record puts the block in, and the block's own word for
    // it, must agree.
    let channel = if kind.known() == Some(BlockKind::ChannelCreate) {
        if channel_id != block_cid {
            return Err(FollowError::Mismatch(
                "a channel-create's record names another channel",
            ));
        }
        let terms = crate::ingest::channel_terms_from(&manifest, sequencer, &predecessors)?;
        if terms.sequencer != crate::effect::canonical_did_string(sequencer) {
            return Err(not_carried());
        }
        if !followed_suite(crate::mls_gate::requested_suite(&manifest).ok()) {
            return Err(FollowError::Unsupported(UNFOLLOWED_SUITE));
        }
        None
    } else {
        // Carried for `sequencer`, or for the server it is moving from: the
        // new sequencer delivers its own `sequencer-set`.
        let chan = ctx
            .store
            .get_channel_by_id_including_archived(&channel_id)?
            .filter(|c| {
                crate::effect::canonical_did_string(&c.sequencer_did)
                    == crate::effect::canonical_did_string(sequencer)
                    || moving
                        .as_ref()
                        .is_some_and(|m| crate::handshake::same_did(&m.sequencer, sequencer))
            })
            .ok_or_else(not_carried)?;
        let names_it = match manifest
            .metadata
            .get(crate::ingest::CHANNEL_ID_KEY)
            .and_then(|v| v.as_str())
        {
            Some(id) => id == channel_id,
            // A kind this build does not implement names its channel by id,
            // or names none it can tell.
            None => kind.known().is_some_and(|kind| {
                crate::ingest::channel_slug_of(kind, &manifest) == Some(chan.slug.as_str())
            }),
        };
        if !names_it {
            return Err(FollowError::Mismatch("the block names another channel"));
        }
        if !followed_suite(chan.suite.parse().ok()) {
            return Err(FollowError::Unsupported(UNFOLLOWED_SUITE));
        }
        Some(chan)
    };
    // This server carries only what it agreed to: an accepted share of the
    // channel, with this sequencer. A move is taken under the share with the
    // sequencer it moves from: its authority is the owner's signature, and
    // the new sequencer's share comes after it, by a re-offer.
    let share_with = match (&moving, record.seq.checked_sub(1)) {
        (Some(_), Some(cited)) => ctx
            .store
            .expected_sequencer(&channel_id, cited)?
            .ok_or_else(not_carried)?,
        _ => sequencer.to_string(),
    };
    if !ctx.store.has_accepted_share(&channel_id, &share_with)? {
        return Err(FollowError::NoShare {
            channel_id,
            sequencer: share_with,
        });
    }
    // Rule 11a: only the owner moves the sequencer, and the set's record is
    // the new sequencer's, right after the head it cites.
    if let (Some(set), Some(chan)) = (&moving, &channel) {
        if set.channel_id != channel_id {
            return Err(FollowError::Mismatch("the move names another channel"));
        }
        // An owner as of the move's place in the chain, the creator rule
        // carried across its key links (rule 7b).
        if !crate::roles::rights_at_channel(
            &ctx.store,
            chan,
            &crate::effect::canonical_did_string(&sender.to_did_jig_string()),
            record.seq,
        )?
        .owner
        {
            return Err(FollowError::Mismatch(
                "a sequencer move signed by a DID that is not the channel's owner",
            ));
        }
        set.check_record(record.seq, &record.prev, &record.sequencer)?;
        // Behind the head it cites: keep it until the records up to that
        // head have landed. Ahead of it is the partition case: the record at
        // the set's seq is held already, and the landing below stops the
        // channel as at a fork.
        let held = ctx.store.chain_head_seq(&channel_id)?;
        if held.is_none_or(|h| h + 1 < record.seq) {
            record.verify(&set.sequencer)?;
            ctx.store.keep_pending_move(
                &channel_id,
                &PendingMove {
                    seq: record.seq,
                    sequencer: set.sequencer.clone(),
                    manifest: bundle.manifest_bytes.to_vec(),
                    code: bundle.code_bytes.to_vec(),
                    sig: sig.clone(),
                    record: record_bytes.to_vec(),
                },
            )?;
            return Err(FollowError::Gap {
                channel_id,
                head: held,
                got: record.seq,
            });
        }
    }
    // Rule 12: the owner's signature, exactly, and nothing of this server's:
    // under `sequencer`, or under a DID it signed as before (JEP-0012). Each
    // signs only in link order: once a record by a later DID is in the
    // chain, an earlier one signs nothing after it. Records land in `seq`
    // order, so the record before this one is the one to compare with.
    let signers: Vec<&str> = match (&moving, range) {
        (Some(set), _) => vec![set.sequencer.as_str()],
        (None, Some(range)) => vec![range.sequencer.as_str()],
        (None, None) => predecessors
            .iter()
            .map(String::as_str)
            .chain([sequencer])
            .collect(),
    };
    let rank = signers
        .iter()
        .rposition(|did| crate::handshake::same_did(did, &record.sequencer));
    record.verify(rank.map_or(signers[signers.len() - 1], |i| signers[i]))?;
    if let Some(rank) = rank
        && rank + 1 < signers.len()
        && let Some(before) = record.seq.checked_sub(1)
        && let Some(held) = ctx.store.ingest_record_bytes(&channel_id, before)?
        && let Ok(held) = IngestRecord::decode(&held)
        && signers[rank + 1..]
            .iter()
            .any(|did| crate::handshake::same_did(did, &held.sequencer))
    {
        return Err(FollowError::Mismatch(
            "a record signed by a key its owner has since moved on from",
        ));
    }
    // A channel stopped for an upgrade takes nothing more: not a gap to fill.
    if let Some(stop) = ctx.store.carried_upgrade(&channel_id)? {
        return Err(FollowError::NeedsUpgrade {
            channel_id,
            seq: stop.seq,
            kind: stop.kind,
        });
    }
    // Rule 11a: a move to a sequencer that orders another channel of this
    // slug, archived or not, would give the slug two channels. It stops
    // here, with the evidence kept, rather than fail its landing on every
    // retry. Only a move whose record verified gets this far, so no one
    // but the owner can stop a channel this way.
    if let (Some(set), Some(chan)) = (&moving, &channel)
        && ctx.store.chain_evidence(&channel_id)?.is_empty()
        && ctx
            .store
            .slug_held_by(&set.sequencer, &chan.slug, &channel_id)?
    {
        let held = match record.seq.checked_sub(1) {
            Some(before) => ctx
                .store
                .ingest_record_bytes(&channel_id, before)?
                .unwrap_or_default(),
            None => Vec::new(),
        };
        ctx.store
            .keep_unapplied(&channel_id, record.seq, &held, record_bytes)?;
        tracing::warn!(
            channel_id,
            seq = record.seq,
            sequencer = set.sequencer,
            slug = chan.slug,
            "the owner moved the channel to a sequencer that already orders a channel of \
             this slug; the channel is stopped"
        );
        return Err(FollowError::SlugTaken {
            channel_id,
            seq: record.seq,
            sequencer: set.sequencer.clone(),
            slug: chan.slug.clone(),
        });
    }
    let (mls, needs_upgrade) = match &kind {
        CarriedKind::Known(known) => (
            mirror_plan(
                ctx,
                *known,
                &sender,
                &manifest,
                channel.as_ref(),
                &record,
                record_bytes,
            )?,
            None,
        ),
        // Rule 14c: a non-critical block changes no group (a group key makes
        // it critical), and a critical one never lands.
        CarriedKind::Unknown { name, critical } => (
            crate::mls_gate::MlsPlan::Nothing,
            critical.then_some(name.as_str()),
        ),
    };

    let canonical = crate::ingest::bundle_canonical_bytes(bundle.manifest_bytes, bundle.code_bytes)
        .map_err(IngestError::BundleMalformed)?;
    let hlc = manifest.hlc_ts.as_ref();
    let stored = StoredBlock {
        cid: block_cid.clone(),
        channel_id: Some(channel_id.clone()),
        block_kind: kind.name().to_string(),
        sender_did: sender.to_did_jig_string(),
        sender_sig: sig,
        bundle_bytes: canonical,
        // Ciphertext is never executed, here or at the owner.
        is_synthetic: !kind.known().is_some_and(|k| k.is_wasm_executable())
            || matches!(mls, crate::mls_gate::MlsPlan::Sealed),
        hlc_wall_ms: hlc.map(|h| h.wall_ms).unwrap_or(0),
        hlc_logical: hlc.map(|h| h.logical).unwrap_or(0),
        hlc_origin: hlc.map(|h| h.server_did.to_string()).unwrap_or_default(),
        posted_at: chrono::Utc::now().timestamp(),
        origin_server: sequencer.to_string(),
        federated_from: Some(sequencer.to_string()),
    };
    let seq = record.seq;
    let effect = |conn: &rusqlite::Connection| {
        // A kind this build does not implement has no effect it could apply.
        if kind.known().is_some() {
            crate::effect::apply_carried_effect(
                conn,
                &manifest,
                &block_cid,
                channel.as_ref(),
                sequencer,
                &predecessors,
            )?;
        }
        // The move lands with its record: from here on the new sequencer
        // signs the channel's records, and the row names it.
        if let Some(set) = &moving {
            conn.execute(
                "INSERT INTO channel_moves (channel_id, seq, sequencer, previous, block_cid)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![channel_id, seq as i64, set.sequencer, share_with, block_cid],
            )?;
            conn.execute(
                "UPDATE channels SET sequencer_did = ?1 WHERE id = ?2",
                params![set.sequencer, channel_id],
            )?;
            // The move kept for its head, if this is it, lands with it: in
            // this transaction, and only that move's row.
            conn.execute(
                "DELETE FROM pending_moves WHERE channel_id = ?1 AND seq = ?2",
                params![channel_id, seq as i64],
            )?;
        }
        advance_mirror(conn, &channel_id, mls)
    };
    match ctx
        .store
        .land_carried(&stored, &record, record_bytes, needs_upgrade, effect)?
    {
        Landing::Duplicate => return Ok(Followed::Duplicate { block_cid, seq }),
        Landing::Gap(head) => {
            return Err(FollowError::Gap {
                channel_id,
                head,
                got: seq,
            });
        }
        Landing::Fork => {
            tracing::warn!(
                channel_id,
                seq,
                sequencer,
                "the owner's chain forked; the channel is stopped"
            );
            return Err(FollowError::Fork { channel_id, seq });
        }
        Landing::Stopped => return Err(FollowError::Stopped { channel_id }),
        Landing::NeedsUpgrade => {
            let stop = ctx
                .store
                .carried_upgrade(&channel_id)?
                .unwrap_or(UpgradeStop {
                    channel_id: channel_id.clone(),
                    seq,
                    block_cid: block_cid.clone(),
                    kind: kind.name().to_string(),
                    found_at: 0,
                });
            tracing::warn!(
                channel_id,
                seq = stop.seq,
                kind = stop.kind,
                "the owner sequenced a critical block of a kind this version does not \
                 implement; the channel is stopped until this server is upgraded"
            );
            ctx.fanout.notify_channel(&channel_id, stop.notice()).await;
            return Err(FollowError::NeedsUpgrade {
                channel_id,
                seq: stop.seq,
                kind: stop.kind,
            });
        }
        Landing::EffectFailed(e) => return Err(FollowError::Other(e)),
        Landing::Landed => {}
    }
    // A removed member still receives its own removal, as from the owner
    // (`ingest`): on an MLS channel it carries the commit that tells its
    // client the group is gone.
    let removed = (kind.known() == Some(BlockKind::MemberRemove))
        .then(|| manifest.metadata.get("member_did").and_then(|v| v.as_str()))
        .flatten()
        .map(crate::effect::canonical_did_string);
    deliver(ctx, &stored, &channel_id, removed).await;
    if moving.is_none()
        && let Some(p) = pending.filter(|p| p.seq == seq + 1)
    {
        // The head the kept move cites has landed: land the move now.
        let parts = BlockBundle {
            manifest_bytes: &p.manifest,
            code_bytes: &p.code,
            resources: vec![],
        };
        if let Err(e) = Box::pin(ingest_sequenced(
            ctx,
            parts,
            p.sig.clone(),
            &p.record,
            &p.sequencer,
        ))
        .await
        {
            tracing::warn!(
                channel_id,
                seq = p.seq,
                "a kept sequencer move did not land: {e}"
            );
        }
    }
    Ok(Followed::Landed { block_cid, seq })
}

/// Read a carried block's manifest: of a kind this build implements, or, as
/// JEP-0005 rule 14c reads it, of one it does not. A manifest that is neither
/// is refused as it always was.
fn carried_manifest(bytes: &[u8]) -> Result<(jig_core::BlockManifest, CarriedKind), IngestError> {
    match crate::ingest::parse_manifest(bytes) {
        Ok(manifest) => {
            let kind = manifest.kind.ok_or(IngestError::KindRequired)?;
            Ok((manifest, CarriedKind::Known(kind)))
        }
        Err(refused) => {
            let Some(unknown) = jig_core::UnknownKindManifest::parse(bytes) else {
                return Err(refused);
            };
            unknown.manifest.check_gates()?;
            Ok((
                unknown.manifest,
                CarriedKind::Unknown {
                    name: unknown.kind,
                    critical: unknown.critical,
                },
            ))
        }
    }
}

const UNFOLLOWED_SUITE: &str = "only plaintext and MLS channels are followed";

/// The suites a follower carries: plaintext, and MLS through its mirror of
/// the group's public state.
fn followed_suite(suite: Option<jig_core::EncryptionSuite>) -> bool {
    matches!(
        suite,
        Some(jig_core::EncryptionSuite::Unencrypted | jig_core::EncryptionSuite::Mls)
    )
}

/// What the block does to an MLS channel's group, judged against this
/// server's mirror of its public state exactly as the owner's gate judged it
/// (JEP-0005 rule 19). Only the chain's next record is judged: a duplicate,
/// a gap or a fork is the landing's to tell, and a mirror that moved past or
/// not yet reached the block would refuse a block that is fine.
///
/// A next record that does not apply is the owner sequencing what its own
/// group refuses: the evidence is kept and the channel stops.
fn mirror_plan(
    ctx: &IngestContext,
    kind: BlockKind,
    sender: &jig_core::Did,
    manifest: &jig_core::BlockManifest,
    channel: Option<&crate::persist::StoredChannel>,
    record: &IngestRecord,
    record_bytes: &[u8],
) -> Result<crate::mls_gate::MlsPlan, FollowError> {
    let mls = jig_core::EncryptionSuite::Mls;
    let is_mls = match channel {
        None => crate::mls_gate::requested_suite(manifest).ok() == Some(mls),
        Some(chan) => chan.suite == mls.as_str(),
    };
    if !is_mls {
        return Ok(crate::mls_gate::MlsPlan::Nothing);
    }
    let head = ctx.store.latest_ingest_record(&record.channel_id)?;
    let stopped = !ctx.store.chain_evidence(&record.channel_id)?.is_empty();
    if stopped || record.seq != head.as_ref().map_or(0, |h| h.seq + 1) {
        return Ok(crate::mls_gate::MlsPlan::Nothing);
    }
    let group = match channel {
        Some(chan) => ctx.store.get_mls_group_by_id(&chan.id)?,
        None => None,
    };
    crate::mls_gate::plan(
        kind,
        &sender.to_did_jig_string(),
        manifest,
        channel,
        group.as_ref(),
    )
    .or_else(|refusal| {
        let label = channel.map_or("", |c| c.slug.as_str());
        let reason = crate::ingest::suite_refusal(refusal, label).to_string();
        let held = head.map(|h| h.encode()).unwrap_or_default();
        ctx.store
            .keep_unapplied(&record.channel_id, record.seq, &held, record_bytes)?;
        tracing::warn!(
            channel_id = record.channel_id,
            seq = record.seq,
            reason,
            "the owner sequenced an MLS block its group refuses; the channel is stopped"
        );
        Err(FollowError::Unapplied {
            channel_id: record.channel_id.clone(),
            seq: record.seq,
            reason,
        })
    })
}

/// Move the mirror with the block, in its landing's transaction: the group
/// a new channel starts, or the epoch a commit makes. A commit whose epoch
/// another landing took first lands nothing, and comes again.
fn advance_mirror(
    conn: &rusqlite::Connection,
    channel_id: &str,
    plan: crate::mls_gate::MlsPlan,
) -> anyhow::Result<()> {
    match plan {
        crate::mls_gate::MlsPlan::Genesis(group) => {
            conn.execute(
                "INSERT OR REPLACE INTO mls_groups (channel_id, group_id, state, epoch, group_info)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    channel_id,
                    group.group_id,
                    group.state,
                    group.epoch as i64,
                    group.group_info
                ],
            )?;
        }
        crate::mls_gate::MlsPlan::Advance {
            from_epoch,
            state,
            to_epoch,
            group_info,
            ..
        } => {
            let advanced = conn.execute(
                "UPDATE mls_groups SET state = ?3, epoch = ?4, group_info = ?5
                  WHERE channel_id = ?1 AND epoch = ?2",
                params![
                    channel_id,
                    from_epoch as i64,
                    state,
                    to_epoch as i64,
                    group_info
                ],
            )?;
            if advanced == 0 {
                anyhow::bail!(
                    "the group of channel {channel_id} is no longer at epoch {from_epoch}"
                );
            }
        }
        crate::mls_gate::MlsPlan::Nothing | crate::mls_gate::MlsPlan::Sealed => {}
    }
    Ok(())
}

/// Hand a carried block to this server's own subscribers and to the bridge
/// sinks of its members, under the channel's policy as it now stands. Never
/// to peers: the owner sends its blocks to each follower itself.
async fn deliver(
    ctx: &IngestContext,
    block: &StoredBlock,
    channel_id: &str,
    removed: Option<String>,
) {
    let policy = match ctx.store.get_channel_by_id_including_archived(channel_id) {
        Ok(Some(chan)) => {
            let mut members: Vec<String> = ctx
                .store
                .list_members(&chan.id)
                .map(|ms| ms.into_iter().map(|m| m.member_did).collect())
                .unwrap_or_default();
            members.extend(removed);
            DeliveryPolicy::for_channel(&chan, members)
        }
        // Narrow delivery on any doubt, never widen it.
        _ => DeliveryPolicy::default(),
    };
    // A carried block has no receipt of this server's: it executed nothing.
    let receipt = StoredReceipt {
        cid: String::new(),
        block_cid: block.cid.clone(),
        server_id: ctx.server_did.to_did_jig_string(),
        receipt_bytes: Vec::new(),
        render_hash: None,
        produced_at: block.posted_at,
    };
    if let Err(e) = ctx
        .fanout
        .broadcast_carried(block, &receipt, Some(&policy))
        .await
    {
        tracing::warn!(block = %block.cid, "carried block not delivered: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fanout::Fanout;
    use crate::hlc::HlcClock;
    use crate::ingest::{AdmitEveryone, IngestSource, ingest};
    use crate::ingest_record::RecordSigner;
    use ed25519_dalek::{Signer, SigningKey};
    use jig_core::did::Did;
    use jig_core::{Author, BlockManifest};
    use semver::Version;
    use std::sync::Arc;

    fn ctx() -> IngestContext {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let server_key = SigningKey::from_bytes(&rand::random());
        let server_did = Did::from_ed25519_pubkey(server_key.verifying_key().as_bytes());
        IngestContext {
            store: store.clone(),
            admission: Arc::new(AdmitEveryone),
            identity: Arc::new(crate::identity::TofuResolver::new(store)),
            hlc_clock: Arc::new(HlcClock::new(server_did.clone())),
            allowed_block_kinds: [
                "text-render",
                "channel-create",
                "member-add",
                "member-remove",
                "sequencer-set",
            ]
            .map(String::from)
            .to_vec(),
            server_did,
            server_key,
            fanout: Arc::new(Fanout::new()),
            server_url: "ws://127.0.0.1:7117".to_string(),
            naively_allow_unknown_handles_fallback: false,
            executor: Some(crate::executor::BlockExecutor::shared()),
        }
    }

    fn did(key: &SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    /// A block signed by `key`: its manifest, code and signature.
    fn signed(
        key: &SigningKey,
        kind: BlockKind,
        meta: serde_json::Value,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        signed_as(key, kind, meta, jig_core::EncryptionSuite::Unencrypted)
    }

    /// [`signed`], its content in `suite`.
    fn signed_as(
        key: &SigningKey,
        kind: BlockKind,
        meta: serde_json::Value,
        suite: jig_core::EncryptionSuite,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut manifest = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: Did::from_ed25519_pubkey(key.verifying_key().as_bytes()),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap()
            .with_kind(kind);
        if let serde_json::Value::Object(map) = meta {
            manifest.metadata.extend(map);
        }
        crate::ingest::tier_as_a_current_client_would(kind, &mut manifest.metadata);
        if suite != jig_core::EncryptionSuite::Unencrypted {
            manifest.privacy = Some(jig_core::Privacy {
                encryption: suite,
                recipients: vec![],
                metadata_visibility: Default::default(),
            });
        }
        manifest.hlc_ts = Some(jig_core::HlcTimestamp {
            wall_ms: rand::random::<u32>() as u64,
            logical: 0,
            server_did: Did::from_str_unchecked("did:jig:client"),
        });
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let code_bytes = Vec::new();
        let sig = key
            .sign(&serde_json::to_vec(&(&manifest_bytes, &code_bytes)).unwrap())
            .to_bytes()
            .to_vec();
        (manifest_bytes, code_bytes, sig)
    }

    fn bundle<'a>((m, c, _): &'a (Vec<u8>, Vec<u8>, Vec<u8>)) -> BlockBundle<'a> {
        BlockBundle {
            manifest_bytes: m,
            code_bytes: c,
            resources: vec![],
        }
    }

    /// A block as the owner sends it: its parts and its stored record.
    struct Sent {
        parts: (Vec<u8>, Vec<u8>, Vec<u8>),
        record: Vec<u8>,
    }

    /// The owner, with one open channel and the blocks it sequenced.
    struct Owner {
        ctx: IngestContext,
        user: SigningKey,
        channel: String,
        sent: Vec<Sent>,
    }

    impl Owner {
        async fn new() -> Self {
            let ctx = ctx();
            let user = SigningKey::from_bytes(&rand::random());
            let mut owner = Owner {
                ctx,
                user,
                channel: String::new(),
                sent: Vec::new(),
            };
            owner.channel = owner
                .post(
                    BlockKind::ChannelCreate,
                    serde_json::json!({"slug": "#shared"}),
                )
                .await;
            owner
        }

        fn did(&self) -> String {
            self.ctx.server_did.to_did_jig_string()
        }

        /// A server that accepted this owner's share of its channel.
        fn follower(&self) -> IngestContext {
            let follower = ctx();
            share(&follower, &self.channel, &self.did());
            follower
        }

        /// Post through the owner's own gate, and keep what it would send.
        async fn post(&mut self, kind: BlockKind, mut meta: serde_json::Value) -> String {
            if kind == BlockKind::ChannelCreate {
                meta[crate::ingest::SEQUENCER_KEY] = serde_json::json!(self.did());
            }
            let parts = signed(&self.user, kind, meta);
            self.post_parts(kind, parts).await
        }

        /// [`Self::post`] for a block signed already.
        async fn post_parts(
            &mut self,
            kind: BlockKind,
            parts: (Vec<u8>, Vec<u8>, Vec<u8>),
        ) -> String {
            let cid = ingest(
                &self.ctx,
                bundle(&parts),
                parts.2.clone(),
                IngestSource::LocalClient {
                    conn_id: 1,
                    tiers: true,
                },
            )
            .await
            .unwrap();
            let channel = if kind == BlockKind::ChannelCreate {
                cid.clone()
            } else {
                self.channel.clone()
            };
            let seq = self.ctx.store.get_ingest_record(&cid).unwrap().unwrap().seq;
            let record = self
                .ctx
                .store
                .ingest_record_bytes(&channel, seq)
                .unwrap()
                .unwrap();
            self.sent.push(Sent { parts, record });
            cid
        }

        async fn text(&mut self, body: &str) -> String {
            let meta = serde_json::json!({"channel_id": self.channel, "body": body});
            self.post(BlockKind::TextRender, meta).await
        }

        /// A record the owner's key signs at `seq`, for `parts`, outside its
        /// own chain: what a forking or careless owner would send.
        fn sign_at(
            &self,
            parts: &(Vec<u8>, Vec<u8>, Vec<u8>),
            seq: u64,
            prev: [u8; 32],
        ) -> Vec<u8> {
            let cid = bundle(parts).block_cid().unwrap().to_string();
            RecordSigner {
                channel_id: self.channel.clone(),
                key: &self.ctx.server_key,
                ingest_wall_ms: 1,
                ingest_logical: 0,
            }
            .sign(seq, &cid, prev)
            .unwrap()
            .encode()
        }
    }

    /// Keep an accepted share of `channel` from `owner`, on the follower's
    /// side. Its id, for ending it.
    fn share(follower: &IngestContext, channel: &str, owner: &str) -> [u8; 32] {
        let offer_id: [u8; 32] = rand::random();
        follower
            .store
            .put_contract_offer(&crate::contracts::StoredOffer {
                offer_id,
                channel_id: channel.to_string(),
                side: crate::contracts::Side::Follower,
                peer_did: owner.to_string(),
                grant: jig_core::contract::Grant::Read,
                state: crate::contracts::OfferState::Accepted,
                offer: vec![],
                answer: None,
                share_cid: None,
            })
            .unwrap();
        offer_id
    }

    async fn take(
        follower: &IngestContext,
        owner: &Owner,
        sent: &Sent,
    ) -> Result<Followed, FollowError> {
        ingest_sequenced(
            follower,
            bundle(&sent.parts),
            sent.parts.2.clone(),
            &sent.record,
            &owner.did(),
        )
        .await
    }

    /// A bridge sink on `follower` for `managed`.
    fn bridge_sink(
        follower: &IngestContext,
        managed: &str,
    ) -> tokio::sync::mpsc::UnboundedReceiver<crate::fanout::BridgeDelivery> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        follower.fanout.register_bridge_did(managed.to_string(), tx);
        rx
    }

    /// #454: a carried post reaches the bridge sink of a member the follower
    /// mirrors, as a post the server sequenced does. It is marked as not
    /// sequenced here and has no receipt, since the follower executed
    /// nothing. A managed DID that is not a member gets nothing.
    #[tokio::test]
    async fn a_carried_post_reaches_a_bridged_members_sink() {
        let mut owner = Owner::new().await;
        let member = did(&SigningKey::from_bytes(&[6; 32]));
        owner
            .post(
                BlockKind::MemberAdd,
                serde_json::json!({"channel_id": owner.channel, "member_did": member}),
            )
            .await;
        let follower = owner.follower();
        for sent in &owner.sent {
            take(&follower, &owner, sent).await.unwrap();
        }
        let mut members_sink = bridge_sink(&follower, &member);
        let mut strangers_sink = bridge_sink(&follower, &did(&SigningKey::from_bytes(&[7; 32])));

        let post = owner.text("for the member").await;
        take(&follower, &owner, owner.sent.last().unwrap())
            .await
            .unwrap();

        let got = members_sink
            .try_recv()
            .expect("the member's sink gets the post");
        assert_eq!(got.block.cid, post);
        assert!(!got.sequenced_here, "the owner sequenced it");
        assert!(got.receipt.is_none(), "the follower executed nothing");
        assert!(
            strangers_sink.try_recv().is_err(),
            "not to a non-member's sink"
        );
    }

    /// A carried post is not echoed to its author's own sink, though the
    /// author is a member.
    #[tokio::test]
    async fn a_carried_post_is_not_echoed_to_its_authors_sink() {
        let mut owner = Owner::new().await;
        let author = did(&owner.user);
        owner
            .post(
                BlockKind::MemberAdd,
                serde_json::json!({"channel_id": owner.channel, "member_did": author}),
            )
            .await;
        let follower = owner.follower();
        for sent in &owner.sent {
            take(&follower, &owner, sent).await.unwrap();
        }
        let mut authors_sink = bridge_sink(&follower, &author);
        owner.text("mine").await;
        take(&follower, &owner, owner.sent.last().unwrap())
            .await
            .unwrap();
        assert!(
            authors_sink.try_recv().is_err(),
            "the author's sink gets nothing"
        );
    }

    /// A removed bridged member's sink gets its own removal, as a removed
    /// member's client does, and nothing posted after it.
    #[tokio::test]
    async fn a_removed_bridged_member_gets_its_removal_and_nothing_after() {
        let mut owner = Owner::new().await;
        let member = did(&SigningKey::from_bytes(&[8; 32]));
        owner
            .post(
                BlockKind::MemberAdd,
                serde_json::json!({"channel_id": owner.channel, "member_did": member}),
            )
            .await;
        let follower = owner.follower();
        for sent in &owner.sent {
            take(&follower, &owner, sent).await.unwrap();
        }
        let mut sink = bridge_sink(&follower, &member);

        let removal = owner
            .post(
                BlockKind::MemberRemove,
                serde_json::json!({"channel_id": owner.channel, "member_did": member}),
            )
            .await;
        take(&follower, &owner, owner.sent.last().unwrap())
            .await
            .unwrap();
        assert_eq!(
            sink.try_recv().expect("its removal").block.cid,
            removal,
            "the removed member's sink gets its removal"
        );

        owner.text("after").await;
        take(&follower, &owner, owner.sent.last().unwrap())
            .await
            .unwrap();
        assert!(sink.try_recv().is_err(), "nothing after the removal");
    }

    #[tokio::test]
    async fn a_follower_keeps_the_owners_chain_as_it_was_signed() {
        let mut owner = Owner::new().await;
        owner.text("one").await;
        let member = did(&SigningKey::from_bytes(&[5; 32]));
        owner
            .post(
                BlockKind::MemberAdd,
                serde_json::json!({"channel_id": owner.channel, "member_did": member}),
            )
            .await;
        owner.text("two").await;

        let follower = owner.follower();
        for (seq, sent) in owner.sent.iter().enumerate() {
            match take(&follower, &owner, sent).await.unwrap() {
                Followed::Landed { seq: got, .. } => assert_eq!(got, seq as u64),
                other => panic!("{other:?}"),
            }
        }
        // The carried row is the owner's, under its terms.
        let row = follower
            .store
            .get_channel_by_id(&owner.channel)
            .unwrap()
            .unwrap();
        assert_eq!(row.sequencer_did, owner.did());
        assert_eq!(row.slug, "#shared");
        assert!(
            follower
                .store
                .is_member_by_id(&owner.channel, &member)
                .unwrap()
        );
        // Every record as the owner stored it, byte for byte, and none signed
        // by the follower.
        for seq in 0..owner.sent.len() as u64 {
            assert_eq!(
                follower
                    .store
                    .ingest_record_bytes(&owner.channel, seq)
                    .unwrap(),
                owner
                    .ctx
                    .store
                    .ingest_record_bytes(&owner.channel, seq)
                    .unwrap(),
                "seq {seq}"
            );
        }
        let records = follower
            .store
            .list_ingest_records_by_id(&owner.channel, 0, 50)
            .unwrap();
        assert!(records.iter().all(|r| r.sequencer == owner.did()));

        // Carried, not executed: the boot backfill renders none of it.
        assert!(
            follower
                .store
                .blocks_missing_receipt(
                    BlockKind::TextRender.as_str(),
                    &follower.server_did.to_string()
                )
                .unwrap()
                .is_empty()
        );

        // The same block again is one block.
        assert!(matches!(
            take(&follower, &owner, &owner.sent[1]).await.unwrap(),
            Followed::Duplicate { seq: 1, .. }
        ));
    }

    /// #375: an owner that changed its key after it created the channel is
    /// followed under its new DID, with the key links its offer came with.
    /// The creation block names the old DID, and the records from before the
    /// change are the old key's: they land under the links. After the first
    /// record by the new key, the old one signs nothing more (JEP-0012).
    /// Without the links, the block names another server.
    #[tokio::test]
    async fn an_owner_that_changed_its_key_is_followed_along_its_links() {
        let mut owner = Owner::new().await;
        owner.text("before the change").await;
        let new_key = SigningKey::from_bytes(&[42; 32]);
        let new_did = did(&new_key);
        let link = jig_core::key_link::SignedKeyLink::sign(
            &owner.ctx.server_key,
            &new_key,
            jig_core::key_link::Audience::Public,
            1_700_000_000,
        )
        .unwrap()
        .envelope()
        .to_vec();

        // Without the links: the creation block names another server.
        let unlinked = ctx();
        share(&unlinked, &owner.channel, &new_did);
        assert!(
            ingest_sequenced(
                &unlinked,
                bundle(&owner.sent[0].parts),
                owner.sent[0].parts.2.clone(),
                &owner.sent[0].record,
                &new_did,
            )
            .await
            .is_err()
        );

        let follower = ctx();
        let offer_id = share(&follower, &owner.channel, &new_did);
        follower
            .store
            .put_offer_key_links(&jig_core::contract::OwnerKeyLinks {
                offer_id,
                links: vec![link],
            })
            .unwrap();
        async fn take_as(
            follower: &IngestContext,
            sent: &Sent,
            sequencer: &str,
        ) -> Result<Followed, FollowError> {
            ingest_sequenced(
                follower,
                bundle(&sent.parts),
                sent.parts.2.clone(),
                &sent.record,
                sequencer,
            )
            .await
        }
        for (seq, sent) in owner.sent.iter().enumerate() {
            match take_as(&follower, sent, &new_did).await.unwrap() {
                Followed::Landed { seq: got, .. } => assert_eq!(got, seq as u64),
                other => panic!("{other:?}"),
            }
        }
        // The carried row is under the DID that signs for it now.
        let row = follower
            .store
            .get_channel_by_id(&owner.channel)
            .unwrap()
            .unwrap();
        assert_eq!(row.sequencer_did, new_did);

        // The new key goes on from the old key's last record.
        let sign = |key: &SigningKey, parts: &(Vec<u8>, Vec<u8>, Vec<u8>), after: &[u8]| {
            let last = IngestRecord::decode(after).unwrap();
            RecordSigner {
                channel_id: owner.channel.clone(),
                key,
                ingest_wall_ms: last.ingest_wall_ms + 1,
                ingest_logical: 0,
            }
            .sign(
                last.seq + 1,
                &bundle(parts).block_cid().unwrap().to_string(),
                last.hash(),
            )
            .unwrap()
            .encode()
        };
        let parts = owner.text_parts("after the change");
        let after = Sent {
            record: sign(&new_key, &parts, &owner.sent.last().unwrap().record),
            parts,
        };
        assert!(matches!(
            take_as(&follower, &after, &new_did).await.unwrap(),
            Followed::Landed { seq: 2, .. }
        ));

        // The old key, after the new one has signed: refused.
        let parts = owner.text_parts("the old key again");
        let stale = Sent {
            record: sign(&owner.ctx.server_key, &parts, &after.record),
            parts,
        };
        assert!(matches!(
            take_as(&follower, &stale, &new_did).await,
            Err(FollowError::Mismatch(_))
        ));
        // A key on no link: refused, as before.
        let parts = owner.text_parts("a stranger");
        let stranger = Sent {
            record: sign(&SigningKey::from_bytes(&[43; 32]), &parts, &after.record),
            parts,
        };
        assert!(matches!(
            take_as(&follower, &stranger, &new_did).await,
            Err(FollowError::Record(_))
        ));
    }

    // ---- A sequencer move (JEP-0005 rule 11a) --------------------------------

    /// `owner`'s channel moving to `new`: the owner's `sequencer-set`, citing
    /// the record sent last, with its record signed by `new` right after it.
    fn move_to(owner: &Owner, new: &SigningKey, signer: &SigningKey) -> Sent {
        move_after(owner, new, signer, &owner.sent.last().unwrap().record)
    }

    /// [`move_to`], citing `cited` as the head.
    fn move_after(owner: &Owner, new: &SigningKey, signer: &SigningKey, cited: &[u8]) -> Sent {
        use jig_core::contract::{ContractAccept, ContractOffer, Grant, ManifestRef};
        use jig_core::sequencer_move::{CitedHead, SequencerSet};
        let last = IngestRecord::decode(cited).unwrap();
        let channel: cid::Cid = owner.channel.parse().unwrap();
        let held = ContractOffer::sign(
            &owner.ctx.server_key,
            &did(new),
            channel,
            Grant::Member,
            owner.sent[0].parts.0.clone(),
            owner.sent[0].record.clone(),
            ManifestRef {
                cid: channel,
                seq: 0,
            },
            vec![],
        );
        let accept = ContractAccept::sign_move(
            new,
            &held,
            ManifestRef {
                cid: channel,
                seq: 1,
            },
            vec![],
            vec![],
            vec![],
        );
        let set = SequencerSet {
            channel_id: owner.channel.clone(),
            sequencer: did(new),
            head: CitedHead {
                seq: last.seq,
                hash: last.hash(),
            },
            accept,
            reinstalls: vec![],
        };
        let mut meta = serde_json::Map::new();
        meta.extend(set.to_metadata());
        let parts = signed(
            signer,
            BlockKind::SequencerSet,
            serde_json::Value::Object(meta),
        );
        let record = RecordSigner {
            channel_id: owner.channel.clone(),
            key: new,
            ingest_wall_ms: last.ingest_wall_ms + 1,
            ingest_logical: 0,
        }
        .sign(
            last.seq + 1,
            &bundle(&parts).block_cid().unwrap().to_string(),
            last.hash(),
        )
        .unwrap()
        .encode();
        Sent { parts, record }
    }

    /// `parts` as the next record after `after`, signed by `key`.
    fn after(
        key: &SigningKey,
        channel: &str,
        after: &[u8],
        parts: (Vec<u8>, Vec<u8>, Vec<u8>),
    ) -> Sent {
        let last = IngestRecord::decode(after).unwrap();
        let record = RecordSigner {
            channel_id: channel.to_string(),
            key,
            ingest_wall_ms: last.ingest_wall_ms + 1,
            ingest_logical: 0,
        }
        .sign(
            last.seq + 1,
            &bundle(&parts).block_cid().unwrap().to_string(),
            last.hash(),
        )
        .unwrap()
        .encode();
        Sent { parts, record }
    }

    async fn take_from(
        follower: &IngestContext,
        sent: &Sent,
        sequencer: &str,
    ) -> Result<Followed, FollowError> {
        ingest_sequenced(
            follower,
            bundle(&sent.parts),
            sent.parts.2.clone(),
            &sent.record,
            sequencer,
        )
        .await
    }

    /// Rule 11a: a move to a sequencer that already orders a channel of this
    /// slug, an archived one included, stops the channel with the evidence
    /// kept. It does not fail its landing on the constraint and come again.
    #[tokio::test]
    async fn a_move_onto_a_slug_the_new_sequencer_holds_stops_the_channel() {
        let mut owner = Owner::new().await;
        owner.text("before the move").await;
        let follower = owner.follower();
        for sent in &owner.sent {
            take(&follower, &owner, sent).await.unwrap();
        }
        let new = SigningKey::from_bytes(&[50; 32]);
        // The new sequencer already orders an archived channel of this slug.
        {
            let conn = follower.store.conn.lock().unwrap();
            conn.execute_batch(&format!(
                "CREATE TEMP TABLE other AS SELECT * FROM channels WHERE id = '{channel}';
                 UPDATE other SET id = 'bafyother', sequencer_did = '{new}', archived_at = 1;
                 INSERT INTO channels SELECT * FROM other;
                 DROP TABLE other;",
                channel = owner.channel,
                new = did(&new),
            ))
            .unwrap();
        }
        let moved = move_to(&owner, &new, &owner.user);
        let got = take_from(&follower, &moved, &did(&new)).await;
        assert!(
            matches!(got, Err(FollowError::SlugTaken { seq: 2, .. })),
            "{got:?}"
        );
        // Stopped, not refused again on every retry.
        assert!(matches!(
            take_from(&follower, &moved, &did(&new)).await,
            Err(FollowError::Stopped { .. })
        ));
        assert_eq!(
            follower.store.chain_evidence(&owner.channel).unwrap().len(),
            1
        );
        assert!(
            follower
                .store
                .channel_moves(&owner.channel)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            follower
                .store
                .get_channel_by_id(&owner.channel)
                .unwrap()
                .unwrap()
                .sequencer_did,
            owner.did()
        );
    }

    /// The owner moves its channel to a new sequencer. The follower takes
    /// the move from the new sequencer under its share with the old one, and
    /// from the set's `seq` on expects the new one: the old sequencer's
    /// records past it are refused, and the new one's need a share with it.
    #[tokio::test]
    async fn a_follower_takes_a_move_and_then_holds_the_channel_to_the_new_sequencer() {
        let mut owner = Owner::new().await;
        owner.text("before the move").await;
        let follower = owner.follower();
        for sent in &owner.sent {
            take(&follower, &owner, sent).await.unwrap();
        }
        let new = SigningKey::from_bytes(&[50; 32]);
        let moved = move_to(&owner, &new, &owner.user);
        assert_eq!(
            follower
                .store
                .expected_sequencer(&owner.channel, 2)
                .unwrap(),
            Some(owner.did())
        );
        match take_from(&follower, &moved, &did(&new)).await.unwrap() {
            Followed::Landed { seq, .. } => assert_eq!(seq, 2),
            other => panic!("{other:?}"),
        }
        // The schedule: the old sequencer up to the cited head, the new one
        // from the set's seq on. The row names the new one.
        let store = &follower.store;
        assert_eq!(
            store.expected_sequencer(&owner.channel, 1).unwrap(),
            Some(owner.did())
        );
        assert_eq!(
            store.expected_sequencer(&owner.channel, 2).unwrap(),
            Some(did(&new))
        );
        assert_eq!(
            store.expected_sequencer(&owner.channel, 9).unwrap(),
            Some(did(&new))
        );
        assert_eq!(
            store
                .get_channel_by_id(&owner.channel)
                .unwrap()
                .unwrap()
                .sequencer_did,
            did(&new)
        );
        // The same move again is one move.
        assert!(matches!(
            take_from(&follower, &moved, &did(&new)).await.unwrap(),
            Followed::Duplicate { seq: 2, .. }
        ));

        // The old sequencer past the move, at the set's seq or after it.
        for at in [&owner.sent.last().unwrap().record, &moved.record] {
            let stale = after(
                &owner.ctx.server_key,
                &owner.channel,
                at,
                owner.text_parts("late"),
            );
            assert!(matches!(
                take_from(&follower, &stale, &owner.did()).await,
                Err(FollowError::Superseded { .. })
            ));
        }

        // The new sequencer's next record waits for its own share (its
        // re-offer), then lands.
        let next = after(
            &new,
            &owner.channel,
            &moved.record,
            owner.text_parts("after"),
        );
        assert!(matches!(
            take_from(&follower, &next, &did(&new)).await,
            Err(FollowError::NoShare { .. })
        ));
        share(&follower, &owner.channel, &did(&new));
        assert!(matches!(
            take_from(&follower, &next, &did(&new)).await.unwrap(),
            Followed::Landed { seq: 3, .. }
        ));
    }

    /// A follower behind the head a move cites keeps the move, takes the
    /// records up to that head from the new sequencer (each held to the old
    /// sequencer's signature, whoever serves it), and lands the move once it
    /// holds the head: an old sequencer that is gone cannot strand it.
    #[tokio::test]
    async fn a_follower_behind_the_cited_head_catches_up_from_the_new_sequencer() {
        let mut owner = Owner::new().await;
        owner.text("one").await;
        owner.text("two").await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        let new = SigningKey::from_bytes(&[50; 32]);
        let new_did = did(&new);

        // Before any move, the new sequencer is no source for this channel.
        assert!(
            take_from(&follower, &owner.sent[1], &new_did)
                .await
                .is_err()
        );

        let moved = move_to(&owner, &new, &owner.user);
        assert!(matches!(
            take_from(&follower, &moved, &new_did).await,
            Err(FollowError::Gap {
                head: Some(0),
                got: 3,
                ..
            })
        ));
        assert_eq!(
            follower
                .store
                .pending_move(&owner.channel)
                .unwrap()
                .map(|p| p.seq),
            Some(3)
        );
        assert!(
            follower
                .store
                .channel_moves(&owner.channel)
                .unwrap()
                .is_empty()
        );

        // A record up to the cited head signed by the new sequencer is not
        // the old sequencer's: refused.
        let forged = after(
            &new,
            &owner.channel,
            &owner.sent[0].record,
            owner.sent[1].parts.clone(),
        );
        assert!(take_from(&follower, &forged, &new_did).await.is_err());

        // The old sequencer's records, served by the new one.
        for sent in &owner.sent[1..] {
            assert!(matches!(
                take_from(&follower, sent, &new_did).await.unwrap(),
                Followed::Landed { .. }
            ));
        }
        // Holding the cited head, the move has landed.
        let store = &follower.store;
        assert_eq!(store.pending_move(&owner.channel).unwrap(), None);
        assert_eq!(
            store.expected_sequencer(&owner.channel, 3).unwrap(),
            Some(new_did.clone())
        );
        assert_eq!(
            store.expected_sequencer(&owner.channel, 2).unwrap(),
            Some(owner.did())
        );
    }

    /// The owner moves its channel to a server that carries it. That server
    /// signs the move's record right after the head it holds, and from then
    /// on sequences the channel: a post to it lands under its own record.
    #[tokio::test]
    async fn a_carrying_server_takes_the_channel_over_by_the_owners_move() {
        let mut owner = Owner::new().await;
        owner.text("before the move").await;
        let new = owner.follower();
        for sent in &owner.sent {
            take(&new, &owner, sent).await.unwrap();
        }
        let new_did = new.server_did.to_did_jig_string();
        let submit = |parts: (Vec<u8>, Vec<u8>, Vec<u8>)| {
            let new = &new;
            async move {
                ingest(
                    new,
                    bundle(&parts),
                    parts.2.clone(),
                    IngestSource::LocalClient {
                        conn_id: 1,
                        tiers: true,
                    },
                )
                .await
            }
        };

        // Refused: citing a head it does not hold as its newest, naming
        // another server, and signed by someone who is not the owner.
        let first = owner.sent[0].record.clone();
        let stale = move_after(&owner, &new.server_key, &owner.user, &first).parts;
        assert!(matches!(
            submit(stale).await,
            Err(IngestError::MoveRefused { .. })
        ));
        let elsewhere = move_to(&owner, &SigningKey::from_bytes(&[50; 32]), &owner.user).parts;
        assert!(matches!(
            submit(elsewhere).await,
            Err(IngestError::MoveRefused { .. })
        ));
        let stranger = SigningKey::from_bytes(&[51; 32]);
        assert!(
            submit(move_to(&owner, &new.server_key, &stranger).parts)
                .await
                .is_err()
        );
        assert!(new.store.channel_moves(&owner.channel).unwrap().is_empty());

        // The owner's move: sequenced at the cited head + 1, by this server.
        let moved = move_to(&owner, &new.server_key, &owner.user);
        let cid = submit(moved.parts).await.unwrap();
        let record = new.store.get_ingest_record(&cid).unwrap().unwrap();
        let cited = IngestRecord::decode(&owner.sent.last().unwrap().record).unwrap();
        assert_eq!(record.seq, cited.seq + 1);
        assert!(record.follows(&cited));
        assert_eq!(record.sequencer, new_did);
        assert_eq!(
            new.store
                .expected_sequencer(&owner.channel, record.seq)
                .unwrap(),
            Some(new_did.clone())
        );
        let row = new
            .store
            .get_channel_by_id(&owner.channel)
            .unwrap()
            .unwrap();
        assert_eq!(row.sequencer_did, new_did);

        // It sequences the channel now.
        let meta = serde_json::json!({"channel_id": owner.channel, "body": "after"});
        let after = submit(signed(&owner.user, BlockKind::TextRender, meta))
            .await
            .unwrap();
        let next = new.store.get_ingest_record(&after).unwrap().unwrap();
        assert_eq!(next.seq, record.seq + 1);
        assert!(next.follows(&record));
        assert_eq!(next.sequencer, new_did);
    }

    /// The move's write checks again what `check_takeover` checked: a record
    /// that lands on the channel between the check and the write leaves the
    /// move refused, with nothing of it written.
    #[tokio::test]
    async fn a_takeover_whose_head_moves_before_its_write_is_refused_whole() {
        let mut owner = Owner::new().await;
        owner.text("before the move").await;
        let new = owner.follower();
        for sent in &owner.sent {
            take(&new, &owner, sent).await.unwrap();
        }
        let store = new.store.clone();
        let key = new.server_key.clone();
        let channel_id = owner.channel.clone();
        let owner_did = owner.ctx.server_did.to_did_jig_string();
        crate::ingest::BEFORE_LANDING.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let block = StoredBlock {
                    cid: crate::ingest_record::label_cid("lands in the window"),
                    channel_id: Some(channel_id.clone()),
                    block_kind: "text-render".to_string(),
                    sender_did: owner_did,
                    sender_sig: vec![],
                    bundle_bytes: vec![],
                    is_synthetic: true,
                    hlc_wall_ms: 0,
                    hlc_logical: 0,
                    hlc_origin: String::new(),
                    posted_at: 0,
                    origin_server: String::new(),
                    federated_from: None,
                };
                store
                    .insert_block_sequenced(
                        &block,
                        &crate::ingest_record::RecordSigner {
                            channel_id,
                            key: &key,
                            ingest_wall_ms: 0,
                            ingest_logical: 0,
                        },
                    )
                    .unwrap();
            }));
        });
        let moved = move_to(&owner, &new.server_key, &owner.user);
        let parts = moved.parts;
        let got = ingest(
            &new,
            bundle(&parts),
            parts.2.clone(),
            IngestSource::LocalClient {
                conn_id: 1,
                tiers: true,
            },
        )
        .await;
        assert!(
            matches!(got, Err(IngestError::MoveRefused { .. })),
            "{got:?}"
        );
        assert!(new.store.channel_moves(&owner.channel).unwrap().is_empty());
        let row = new
            .store
            .get_channel_by_id(&owner.channel)
            .unwrap()
            .unwrap();
        assert_ne!(row.sequencer_did, new.server_did.to_did_jig_string());
        assert_eq!(
            new.store.chain_head_seq(&owner.channel).unwrap(),
            Some(
                IngestRecord::decode(&owner.sent.last().unwrap().record)
                    .unwrap()
                    .seq
                    + 1
            )
        );
    }

    /// Only the owner moves the sequencer, and only with a record signed by
    /// the server it names, right after the head it cites. A follower that
    /// already holds the old sequencer's record at that seq stops the
    /// channel, keeping both, as at a fork.
    #[tokio::test]
    async fn a_move_the_owner_did_not_make_or_that_does_not_fit_the_chain_is_refused() {
        let mut owner = Owner::new().await;
        owner.text("before the move").await;
        let new = SigningKey::from_bytes(&[50; 32]);
        // Signed by a member who is not the owner.
        let follower = owner.follower();
        for sent in &owner.sent {
            take(&follower, &owner, sent).await.unwrap();
        }
        let stranger = SigningKey::from_bytes(&[51; 32]);
        let by_stranger = move_to(&owner, &new, &stranger);
        assert!(matches!(
            take_from(&follower, &by_stranger, &did(&new)).await,
            Err(FollowError::Mismatch(_))
        ));

        // Its record signed by another server than the one it names.
        let mut forged = move_to(&owner, &new, &owner.user);
        let last = owner.sent.last().unwrap();
        forged.record = after(
            &SigningKey::from_bytes(&[52; 32]),
            &owner.channel,
            &last.record,
            forged.parts.clone(),
        )
        .record;
        assert!(take_from(&follower, &forged, &did(&new)).await.is_err());
        assert_eq!(
            follower.store.channel_moves(&owner.channel).unwrap(),
            vec![]
        );

        // Offered on a link from a third server, with no share at all.
        let third = SigningKey::from_bytes(&[53; 32]);
        let to_third = move_to(&owner, &new, &owner.user);
        assert!(take_from(&follower, &to_third, &did(&third)).await.is_err());

        // A follower that holds the old sequencer's record at the set's seq.
        owner.text("past the cited head").await;
        let partitioned = owner.follower();
        for sent in &owner.sent {
            take(&partitioned, &owner, sent).await.unwrap();
        }
        let before_last = &owner.sent[owner.sent.len() - 2].record;
        let cut = move_after(&owner, &new, &owner.user, before_last);
        assert!(matches!(
            take_from(&partitioned, &cut, &did(&new)).await,
            Err(FollowError::Fork { .. })
        ));
    }

    /// The JEP-0005 chain across a move, under fixed keys: three records by
    /// the old sequencer (seed 60), the `sequencer-set`'s record by the new
    /// one (seed 61) right after the cited head, one more by the new one, and
    /// one by the old sequencer past the cited head, which a reader refuses.
    /// Block CIDs are labels; the records are as they are stored and served.
    fn chain_across_a_move() -> serde_json::Value {
        let (old, new) = (
            SigningKey::from_bytes(&[60; 32]),
            SigningKey::from_bytes(&[61; 32]),
        );
        let channel = crate::ingest_record::label_cid("channel-create");
        let sign = |key: &SigningKey, seq: u64, label: &str, prev: [u8; 32]| {
            RecordSigner {
                channel_id: channel.clone(),
                key,
                ingest_wall_ms: 1_700_000_000_000 + seq,
                ingest_logical: 0,
            }
            .sign(seq, &crate::ingest_record::label_cid(label), prev)
            .unwrap()
        };
        let mut chain = vec![sign(
            &old,
            0,
            "channel-create",
            crate::ingest_record::GENESIS_PREV,
        )];
        for (seq, label) in [(1, "text 1"), (2, "text 2")] {
            let prev = chain.last().unwrap().hash();
            chain.push(sign(&old, seq, label, prev));
        }
        let cited = chain.last().unwrap().clone();
        chain.push(sign(&new, 3, "sequencer-set", cited.hash()));
        let set = chain.last().unwrap().clone();
        chain.push(sign(&new, 4, "text 4", set.hash()));
        let refused = sign(&old, 4, "text 4 by the old sequencer", set.hash());
        let entry = |r: &IngestRecord| {
            serde_json::json!({
                "seq": r.seq,
                "signed_by": r.sequencer,
                "hash_hex": hex::encode(r.hash()),
                "record": String::from_utf8(r.encode()).unwrap(),
            })
        };
        serde_json::json!({
            "comment": "JEP-0005 rule 11a: a chain across a sequencer-set. `record` is the ingest record as stored and served (JSON). seq 3 is the sequencer-set's record: signed by the new sequencer, its prev the cited head's hash (seq 2). `refused` is a record by the old sequencer past the cited head: a reader that holds the set refuses it.",
            "keys": {
                "comment": "Ed25519 seeds: every byte set to the given value",
                "old_sequencer": {"seed_byte": 60, "did": did(&old)},
                "new_sequencer": {"seed_byte": 61, "did": did(&new)},
            },
            "channel_id": channel,
            "cited_head": {"seq": cited.seq, "hash": hex::encode(cited.hash())},
            "chain": chain.iter().map(entry).collect::<Vec<_>>(),
            "refused": entry(&refused),
        })
    }

    #[test]
    fn the_chain_across_a_move_matches_the_committed_vectors() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../jig-spec/jep/vectors/0005/sequence-chain-move.json"
        ))
        .unwrap();
        assert_eq!(chain_across_a_move(), v);
        // Each record follows the one before it, under the key its range
        // expects.
        let chain: Vec<IngestRecord> = v["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| IngestRecord::decode(e["record"].as_str().unwrap().as_bytes()).unwrap())
            .collect();
        let (old, new) = (
            &v["keys"]["old_sequencer"]["did"],
            &v["keys"]["new_sequencer"]["did"],
        );
        for (i, r) in chain.iter().enumerate() {
            let expected = if r.seq < 3 { old } else { new };
            r.verify(expected.as_str().unwrap()).unwrap();
            if i > 0 {
                assert!(r.follows(&chain[i - 1]), "seq {}", r.seq);
            }
        }
    }

    /// `cargo test -p jig-pipeline follow::tests::print_chain_across_a_move -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_chain_across_a_move() {
        println!(
            "{}",
            serde_json::to_string_pretty(&chain_across_a_move()).unwrap()
        );
    }

    /// The owner's chain takes back a block only from this channel's relayed
    /// copy. The same CID held in another of the follower's channels stays
    /// there, and the record for it does not land.
    /// The owner's record for a block this server holds in another channel
    /// of its own (as an older relay left one there) lands beside it: the
    /// block stays where it is, its own channel's record stays, and the
    /// carried chain names it under the owner's record, in `carried_records`.
    /// A stall an earlier release recorded for it is cleared, and the chain
    /// goes on past it.
    #[tokio::test]
    async fn a_block_held_in_another_channel_lands_in_both_chains() {
        let mut owner = Owner::new().await;
        let text = owner.text("one").await;
        let next = owner.text("two").await;
        let follower = owner.follower();
        let mut held = owner.ctx.store.get_block(&text).unwrap().unwrap();
        held.channel_id = Some("bafyours".to_string());
        follower.store.insert_block(&held).unwrap();
        follower
            .store
            .conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO carried_stalls (channel_id, seq, block_cid, holder, found_at)
                 VALUES (?1, 1, ?2, 'bafyours', 0)",
                params![owner.channel, text],
            )
            .unwrap();

        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        take(&follower, &owner, &owner.sent[1]).await.unwrap();
        let block = follower.store.get_block(&text).unwrap().unwrap();
        assert_eq!(
            block.channel_id.as_deref(),
            Some("bafyours"),
            "kept where it is"
        );
        assert_eq!(
            follower
                .store
                .ingest_record_bytes(&owner.channel, 1)
                .unwrap(),
            owner
                .ctx
                .store
                .ingest_record_bytes(&owner.channel, 1)
                .unwrap(),
            "the owner's record, byte for byte"
        );
        let in_carried: i64 = follower
            .store
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM carried_records WHERE channel_id = ?1 AND block_cid = ?2",
                params![owner.channel, text],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(in_carried, 1);
        assert!(follower.store.carried_stalls().unwrap().is_empty());

        // The chain goes on from it, and reads hold the block in order.
        take(&follower, &owner, &owner.sent[2]).await.unwrap();
        let history: Vec<String> = follower
            .store
            .list_blocks_by_channel_id(&owner.channel, 10, None)
            .unwrap()
            .into_iter()
            .map(|b| b.cid)
            .collect();
        assert_eq!(history, [owner.channel.clone(), text.clone(), next.clone()]);

        // Every read of the carried chain places the block by the carried
        // record: a live frame or a timeline entry, and a cursor at it either
        // way.
        let record = follower
            .store
            .get_chain_record(&owner.channel, &text)
            .unwrap()
            .expect("the carried record");
        assert_eq!(
            record.encode(),
            owner
                .ctx
                .store
                .get_ingest_record(&text)
                .unwrap()
                .unwrap()
                .encode()
        );
        assert!(
            follower
                .store
                .get_chain_record("bafyours", &text)
                .unwrap()
                .is_none()
        );
        let cids = |blocks: Option<Vec<StoredBlock>>| -> Vec<String> {
            blocks
                .expect("a cursor in the chain")
                .into_iter()
                .map(|b| b.cid)
                .collect()
        };
        assert_eq!(
            cids(
                follower
                    .store
                    .list_blocks_after_by_channel_id(&owner.channel, 10, &text)
                    .unwrap()
            ),
            vec![next.clone()]
        );
        assert_eq!(
            cids(
                follower
                    .store
                    .list_blocks_before_by_channel_id(&owner.channel, 10, &text)
                    .unwrap()
            ),
            vec![owner.channel.clone()]
        );
        assert!(
            follower
                .store
                .list_blocks_after_by_channel_id("bafynone", 10, &text)
                .unwrap()
                .is_none(),
            "a cursor tells nothing of a chain that does not hold it"
        );
        let sizes = |w: Option<Vec<(String, u64)>>| -> Vec<String> {
            w.expect("a cursor in the chain")
                .into_iter()
                .map(|(cid, _)| cid)
                .collect()
        };
        assert_eq!(
            sizes(
                follower
                    .store
                    .history_after_window_sizes(&owner.channel, 10, &text)
                    .unwrap()
            ),
            vec![next.clone()]
        );
        assert_eq!(
            sizes(
                follower
                    .store
                    .history_window_sizes(&owner.channel, 10, Some(&text))
                    .unwrap()
            ),
            [owner.channel.clone()]
        );
    }

    #[tokio::test]
    async fn a_gap_waits_for_the_missing_records() {
        let mut owner = Owner::new().await;
        owner.text("one").await;
        owner.text("two").await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        match take(&follower, &owner, &owner.sent[2]).await {
            Err(FollowError::Gap {
                head: Some(0),
                got: 2,
                ..
            }) => {}
            other => panic!("a gap: {other:?}"),
        }
        // Nothing of it was kept, and once the missing record comes, both land.
        assert!(
            follower
                .store
                .ingest_record_bytes(&owner.channel, 2)
                .unwrap()
                .is_none()
        );
        take(&follower, &owner, &owner.sent[1]).await.unwrap();
        take(&follower, &owner, &owner.sent[2]).await.unwrap();
        assert!(
            follower
                .store
                .chain_evidence(&owner.channel)
                .unwrap()
                .is_empty()
        );
        // A channel's first record must be its genesis.
        let fresh = owner.follower();
        assert!(matches!(
            take(&fresh, &owner, &owner.sent[1]).await,
            Err(FollowError::NotCarried { .. })
        ));
    }

    #[tokio::test]
    async fn a_fork_is_kept_as_evidence_and_stops_the_channel() {
        let mut owner = Owner::new().await;
        owner.text("one").await;
        owner.text("two").await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        take(&follower, &owner, &owner.sent[1]).await.unwrap();

        // The owner signs another block at seq 1.
        let other = signed(
            &owner.user,
            BlockKind::TextRender,
            serde_json::json!({"channel_id": owner.channel, "body": "other"}),
        );
        let genesis = IngestRecord::decode(&owner.sent[0].record).unwrap();
        let forged = Sent {
            record: owner.sign_at(&other, 1, genesis.hash()),
            parts: other,
        };
        match take(&follower, &owner, &forged).await {
            Err(FollowError::Fork { seq: 1, .. }) => {}
            other => panic!("a fork: {other:?}"),
        }
        let evidence = follower.store.chain_evidence(&owner.channel).unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].held, owner.sent[1].record, "the record held");
        assert_eq!(
            evidence[0].offered, forged.record,
            "and the one contradicting it"
        );

        // The channel takes nothing more, not even the owner's next record.
        assert!(matches!(
            take(&follower, &owner, &owner.sent[2]).await,
            Err(FollowError::Stopped { .. })
        ));

        // The next seq, but a `prev` naming something else, forks too.
        let mut owner = Owner::new().await;
        owner.text("one").await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        let next = signed(
            &owner.user,
            BlockKind::TextRender,
            serde_json::json!({"channel_id": owner.channel, "body": "x"}),
        );
        let forged = Sent {
            record: owner.sign_at(&next, 1, [7; 32]),
            parts: next,
        };
        assert!(matches!(
            take(&follower, &owner, &forged).await,
            Err(FollowError::Fork { seq: 1, .. })
        ));
    }

    #[tokio::test]
    async fn a_block_whose_effect_fails_lands_nothing() {
        let mut owner = Owner::new().await;
        let member = did(&SigningKey::from_bytes(&[6; 32]));
        owner
            .post(
                BlockKind::MemberAdd,
                serde_json::json!({"channel_id": owner.channel, "member_did": member}),
            )
            .await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        // The membership the effect writes is made to fail.
        follower
            .store
            .conn
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_members BEFORE INSERT ON memberships
                 BEGIN SELECT RAISE(ABORT, 'refused'); END;",
            )
            .unwrap();
        assert!(matches!(
            take(&follower, &owner, &owner.sent[1]).await,
            Err(FollowError::Other(_))
        ));
        assert!(
            follower
                .store
                .ingest_record_bytes(&owner.channel, 1)
                .unwrap()
                .is_none(),
            "no record without its effect"
        );
        // Once the effect can land, the same record lands with it.
        follower
            .store
            .conn
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER no_members;")
            .unwrap();
        assert!(matches!(
            take(&follower, &owner, &owner.sent[1]).await,
            Ok(Followed::Landed { seq: 1, .. })
        ));
        assert!(
            follower
                .store
                .is_member_by_id(&owner.channel, &member)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_hostile_owner_cannot_grow_the_evidence() {
        let mut owner = Owner::new().await;
        owner.text("one").await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        take(&follower, &owner, &owner.sent[1]).await.unwrap();
        let genesis = IngestRecord::decode(&owner.sent[0].record).unwrap();
        for i in 0..20u64 {
            let other = signed(
                &owner.user,
                BlockKind::TextRender,
                serde_json::json!({"channel_id": owner.channel, "body": format!("fork {i}")}),
            );
            // Contradictions at the same seq, and at seqs no link follows.
            let (seq, prev) = if i % 2 == 0 {
                (1, genesis.hash())
            } else {
                (2, [i as u8; 32])
            };
            let forged = Sent {
                record: owner.sign_at(&other, seq, prev),
                parts: other,
            };
            let got = take(&follower, &owner, &forged).await;
            match (i, got) {
                (0, Err(FollowError::Fork { .. })) => {}
                (_, Err(FollowError::Stopped { .. })) if i > 0 => {}
                (_, other) => panic!("forgery {i}: {other:?}"),
            }
        }
        assert_eq!(
            follower.store.chain_evidence(&owner.channel).unwrap().len(),
            1,
            "only the fork that stopped the channel"
        );
    }

    #[tokio::test]
    async fn a_carried_block_or_record_has_limits() {
        let mut owner = Owner::new().await;
        owner.text("one").await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        let sent = &owner.sent[1];

        // A record carrying more than its signed fields: refused whatever
        // its size, so a client is sent only what was signed.
        let mut padded: serde_json::Value = serde_json::from_slice(&sent.record).unwrap();
        padded["note"] = serde_json::json!("x");
        let padded_record = serde_json::to_vec(&padded).unwrap();
        assert!(matches!(
            ingest_sequenced(
                &follower,
                bundle(&sent.parts),
                sent.parts.2.clone(),
                &padded_record,
                &owner.did()
            )
            .await,
            Err(FollowError::Mismatch(_))
        ));
        padded["note"] = serde_json::json!("x".repeat(MAX_RECORD_BYTES));
        let padded_record = serde_json::to_vec(&padded).unwrap();
        assert!(matches!(
            ingest_sequenced(
                &follower,
                bundle(&sent.parts),
                sent.parts.2.clone(),
                &padded_record,
                &owner.did()
            )
            .await,
            Err(FollowError::RecordTooLarge { .. })
        ));

        // One canonical byte past the limit is refused before it is parsed;
        // the limit itself is not.
        let max = jig_core::bundle::MAX_BUNDLE_BYTES;
        for (len, refused) in [(max, false), (max + 1, true)] {
            let code = code_for(&sent.parts.0, len);
            let got = ingest_sequenced(
                &follower,
                BlockBundle {
                    manifest_bytes: &sent.parts.0,
                    code_bytes: &code,
                    resources: vec![],
                },
                sent.parts.2.clone(),
                &sent.record,
                &owner.did(),
            )
            .await;
            let too_large = matches!(
                got,
                Err(FollowError::Block(IngestError::BundleTooLarge { .. }))
            );
            assert_eq!(too_large, refused, "{len} bytes: {got:?}");
            // The same number bounds a local post.
            let got = ingest(
                &owner.ctx,
                BlockBundle {
                    manifest_bytes: &sent.parts.0,
                    code_bytes: &code,
                    resources: vec![],
                },
                sent.parts.2.clone(),
                IngestSource::LocalClient {
                    conn_id: 1,
                    tiers: true,
                },
            )
            .await;
            let too_large = matches!(got, Err(IngestError::BundleTooLarge { .. }));
            assert_eq!(too_large, refused, "a local post of {len} bytes: {got:?}");
        }
        // A kind this build does not know is read as JEP-0005 rule 14c reads
        // it, and checked like any block: renamed after signing, it fails the
        // author's signature.
        let mut manifest: serde_json::Value = serde_json::from_slice(&sent.parts.0).unwrap();
        manifest["kind"] = serde_json::json!("not-a-kind");
        let manifest = serde_json::to_vec(&manifest).unwrap();
        let unknown = BlockBundle {
            manifest_bytes: &manifest,
            code_bytes: &sent.parts.1,
            resources: vec![],
        };
        assert!(matches!(
            ingest_sequenced(
                &follower,
                unknown,
                sent.parts.2.clone(),
                &sent.record,
                &owner.did()
            )
            .await,
            Err(FollowError::Block(IngestError::InvalidSignature))
        ));
        // None of it was kept, and the real block still lands.
        assert!(
            follower
                .store
                .chain_evidence(&owner.channel)
                .unwrap()
                .is_empty()
        );
        take(&follower, &owner, sent).await.unwrap();
    }

    /// Code that makes `manifest`'s canonical bundle exactly `len` bytes.
    fn code_for(manifest: &[u8], len: usize) -> Vec<u8> {
        let canonical = |code: &[u8]| serde_json::to_vec(&(manifest, code)).unwrap().len();
        // Each byte is `0,` in the JSON; a `10` makes up an odd length.
        let base = canonical(&[]);
        let mut code = vec![0u8; (len - base).div_ceil(2)];
        if canonical(&code) < len {
            code[0] = 10;
        }
        assert_eq!(canonical(&code), len);
        code
    }

    #[tokio::test]
    async fn only_an_accepted_share_is_followed() {
        let mut owner = Owner::new().await;
        owner.text("one").await;
        owner.text("two").await;

        // A create from a server this one never agreed to follow: no row.
        let stranger = ctx();
        assert!(matches!(
            take(&stranger, &owner, &owner.sent[0]).await,
            Err(FollowError::NoShare { .. })
        ));
        assert!(
            stranger
                .store
                .get_channel_by_id_including_archived(&owner.channel)
                .unwrap()
                .is_none()
        );
        // A share of the channel with another server is not one with this
        // owner.
        let other = Owner::new().await;
        share(&stranger, &owner.channel, &other.did());
        assert!(matches!(
            take(&stranger, &owner, &owner.sent[0]).await,
            Err(FollowError::NoShare { .. })
        ));

        // Once the share ends, the channel takes nothing more.
        let follower = ctx();
        let offer_id = share(&follower, &owner.channel, &owner.did());
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        take(&follower, &owner, &owner.sent[1]).await.unwrap();
        use crate::contracts::OfferState;
        assert!(
            follower
                .store
                .move_contract_offer(&offer_id, OfferState::Accepted, OfferState::Ended, None)
                .unwrap()
        );
        assert!(matches!(
            take(&follower, &owner, &owner.sent[2]).await,
            Err(FollowError::NoShare { .. })
        ));
    }

    #[tokio::test]
    async fn a_followers_client_gets_the_owners_cose_bytes() {
        let mut owner = Owner::new().await;
        let cids = [
            owner.channel.clone(),
            owner.text("one").await,
            owner.text("two").await,
        ];
        let follower = owner.follower();
        for sent in &owner.sent {
            take(&follower, &owner, sent).await.unwrap();
        }
        for cid in &cids {
            // What a client's `block` frame carries, on either server.
            let at_owner = owner.ctx.store.get_ingest_record(cid).unwrap().unwrap();
            let at_follower = follower.store.get_ingest_record(cid).unwrap().unwrap();
            assert_eq!(
                serde_json::to_vec(&at_follower).unwrap(),
                serde_json::to_vec(&at_owner).unwrap(),
                "{cid}"
            );
            let envelope = |r: &IngestRecord| {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &r.cose).unwrap()
            };
            assert_eq!(envelope(&at_follower), envelope(&at_owner), "{cid}");
            at_follower.verify(&owner.did()).unwrap();
        }
    }

    /// A block whose manifest names an author its signature is not by is
    /// refused, even under a record the owner signed: the owner's word places
    /// a block, it does not author one. (What `integration-tests` H3 held a
    /// relayed block to, on the path a block now crosses by.)
    #[tokio::test]
    async fn a_block_signed_by_another_than_its_author_is_refused() {
        use ed25519_dalek::Signer as _;
        let owner = Owner::new().await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();

        let alice = SigningKey::from_bytes(&rand::random());
        let bob = SigningKey::from_bytes(&rand::random());
        let meta = serde_json::json!({"channel_id": owner.channel, "body": "as bob"});
        let mut parts = signed(&bob, BlockKind::TextRender, meta);
        parts.2 = alice
            .sign(&serde_json::to_vec(&(&parts.0, &parts.1)).unwrap())
            .to_bytes()
            .to_vec();
        let prev = IngestRecord::decode(&owner.sent[0].record).unwrap().hash();
        let forged = Sent {
            record: owner.sign_at(&parts, 1, prev),
            parts,
        };
        assert!(matches!(
            take(&follower, &owner, &forged).await,
            Err(FollowError::Block(IngestError::InvalidSignature))
        ));
        let cid = bundle(&forged.parts).block_cid().unwrap().to_string();
        assert!(follower.store.get_block(&cid).unwrap().is_none());
    }

    #[tokio::test]
    async fn only_the_owners_signature_places_a_block() {
        let mut owner = Owner::new().await;
        owner.text("one").await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();

        // Signed by another server: refused, and nothing kept.
        let intruder = Owner::new().await;
        let sent = &owner.sent[1];
        let mut record = IngestRecord::decode(&intruder.sign_at(
            &sent.parts,
            1,
            IngestRecord::decode(&owner.sent[0].record).unwrap().hash(),
        ))
        .unwrap();
        record.channel_id = owner.channel.clone();
        let resigned = Sent {
            parts: sent.parts.clone(),
            record: record.encode(),
        };
        assert!(matches!(
            take(&follower, &owner, &resigned).await,
            Err(FollowError::Record(_))
        ));
        // A record for another block.
        let wrong = Sent {
            parts: sent.parts.clone(),
            record: owner.sent[0].record.clone(),
        };
        assert!(matches!(
            take(&follower, &owner, &wrong).await,
            Err(FollowError::Mismatch(_))
        ));
        // The author's signature is still checked.
        let mut tampered = Sent {
            parts: sent.parts.clone(),
            record: sent.record.clone(),
        };
        tampered.parts.2[0] ^= 1;
        assert!(matches!(
            take(&follower, &owner, &tampered).await,
            Err(FollowError::Block(IngestError::InvalidSignature))
        ));
        assert!(
            follower
                .store
                .ingest_record_bytes(&owner.channel, 1)
                .unwrap()
                .is_none()
        );
        take(&follower, &owner, sent).await.unwrap();
    }

    /// Rule 22a: the owner's order is the authority. A block its gate would
    /// not have let in still lands on the follower once the owner signed it.
    #[tokio::test]
    async fn a_follower_runs_no_write_gate_of_its_own() {
        let owner = Owner::new().await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        // A stranger's member-add of someone else: the owner's gate refuses
        // it, but this owner signed it anyway.
        let stranger = SigningKey::from_bytes(&[6; 32]);
        let added = did(&SigningKey::from_bytes(&[7; 32]));
        let parts = signed(
            &stranger,
            BlockKind::MemberAdd,
            serde_json::json!({"channel_id": owner.channel, "member_did": added}),
        );
        assert!(
            ingest(
                &owner.ctx,
                bundle(&parts),
                parts.2.clone(),
                IngestSource::LocalClient {
                    conn_id: 1,
                    tiers: true
                }
            )
            .await
            .is_err(),
            "the owner's own gate refuses it"
        );
        let genesis = IngestRecord::decode(&owner.sent[0].record).unwrap();
        let sent = Sent {
            record: owner.sign_at(&parts, 1, genesis.hash()),
            parts,
        };
        take(&follower, &owner, &sent).await.unwrap();
        assert!(
            follower
                .store
                .is_member_by_id(&owner.channel, &added)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn the_follower_writes_nothing_of_its_own_into_a_carried_channel() {
        let owner = Owner::new().await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        let parts = signed(
            &owner.user,
            BlockKind::TextRender,
            serde_json::json!({"channel_id": owner.channel, "body": "here"}),
        );
        match ingest(
            &follower,
            bundle(&parts),
            parts.2.clone(),
            IngestSource::LocalClient {
                conn_id: 1,
                tiers: true,
            },
        )
        .await
        {
            Err(IngestError::CarriedChannel { sequencer, .. }) => {
                assert_eq!(sequencer, owner.did())
            }
            other => panic!("refused: {other:?}"),
        }
        assert!(
            follower
                .store
                .ingest_record_bytes(&owner.channel, 1)
                .unwrap()
                .is_none()
        );
    }

    /// An owner of an encrypted channel, with its group's first member.
    struct MlsOwner {
        owner: Owner,
        creator: jig_mls::member::Member,
        group_id: Vec<u8>,
    }

    impl MlsOwner {
        async fn new() -> Self {
            use base64::Engine as _;
            let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
            let seed: [u8; 32] = rand::random();
            let user = SigningKey::from_bytes(&seed);
            let creator = jig_mls::member::Member::new(&seed, &did_of_key(&user)).unwrap();
            let created = creator.create_group().unwrap();
            let mut owner = Owner {
                ctx: ctx(),
                user,
                channel: String::new(),
                sent: Vec::new(),
            };
            owner.channel = owner
                .post(
                    BlockKind::ChannelCreate,
                    serde_json::json!({
                        "slug": "#sealed",
                        "visibility": "restricted",
                        "suite": "mls",
                        "mls_group_info": b64(&created.group_info),
                        "mls_ratchet_tree": b64(&created.ratchet_tree),
                    }),
                )
                .await;
            MlsOwner {
                owner,
                creator,
                group_id: created.group_id,
            }
        }

        /// The creator adds a fresh member; its commit, as posted.
        async fn add(&mut self) -> Vec<u8> {
            self.add_did().await.0
        }

        /// The creator removes `did`, as posted.
        async fn remove(&mut self, did: &str) {
            use base64::Engine as _;
            let commit = self.creator.remove(&self.group_id, did).unwrap();
            let channel = self.owner.channel.clone();
            self.owner
                .post(
                    BlockKind::MemberRemove,
                    serde_json::json!({
                        "channel_id": channel,
                        "member_did": did,
                        "mls_commit": base64::engine::general_purpose::STANDARD
                            .encode(&commit.commit),
                    }),
                )
                .await;
            self.creator.confirm(&self.group_id).unwrap();
        }

        /// [`Self::add`], with the added member's DID.
        async fn add_did(&mut self) -> (Vec<u8>, String) {
            use base64::Engine as _;
            let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
            let seed: [u8; 32] = rand::random();
            let did = did_of_key(&SigningKey::from_bytes(&seed));
            let joiner = jig_mls::member::Member::new(&seed, &did).unwrap();
            let kp = joiner.key_packages(1, false).unwrap().remove(0);
            let commit = self
                .creator
                .add(&self.group_id, &kp, &did.to_did_jig_string())
                .unwrap();
            let channel = self.owner.channel.clone();
            self.owner
                .post(
                    BlockKind::MemberAdd,
                    serde_json::json!({
                        "channel_id": channel,
                        "member_did": did.to_did_jig_string(),
                        "mls_commit": b64(&commit.commit),
                        "mls_welcome": b64(commit.welcome.as_ref().unwrap()),
                    }),
                )
                .await;
            self.creator.confirm(&self.group_id).unwrap();
            (commit.commit, did.to_did_jig_string())
        }

        /// A message the creator seals for the group, as posted.
        async fn seal(&mut self, text: &str) -> String {
            let parts = self.sealed(text);
            self.owner.post_parts(BlockKind::TextRender, parts).await
        }

        fn sealed(&self, text: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            self.sealed_in(&self.owner.channel, text)
        }

        /// A message this group's creator seals, posted into `channel`.
        fn sealed_in(&self, channel: &str, text: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            use base64::Engine as _;
            let (ct, epoch) = self
                .creator
                .encrypt(&self.group_id, text.as_bytes())
                .unwrap();
            signed_as(
                &self.owner.user,
                BlockKind::TextRender,
                serde_json::json!({
                    "channel_id": channel,
                    "mls_message": base64::engine::general_purpose::STANDARD.encode(ct),
                    "mls_epoch": epoch,
                }),
                jig_core::EncryptionSuite::Mls,
            )
        }
    }

    fn did_of_key(key: &SigningKey) -> Did {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes())
    }

    /// Slice 7: a follower carries an MLS channel through its mirror of the
    /// group's public state, moving with each commit the owner sequenced,
    /// and stores sealed content as the ciphertext it is.
    #[tokio::test]
    async fn a_follower_mirrors_an_mls_channels_group() {
        let mut o = MlsOwner::new().await;
        o.add().await;
        let sealed = o.seal("only the group reads this").await;
        let follower = o.owner.follower();
        for sent in &o.owner.sent {
            take(&follower, &o.owner, sent).await.unwrap();
        }
        let ours = follower
            .store
            .get_mls_group_by_id(&o.owner.channel)
            .unwrap()
            .unwrap();
        let theirs = o
            .owner
            .ctx
            .store
            .get_mls_group_by_id(&o.owner.channel)
            .unwrap()
            .unwrap();
        assert_eq!((ours.epoch, &ours.group_id), (1, &theirs.group_id));
        assert_eq!(
            ours.state, theirs.state,
            "the same public state as the owner's"
        );
        // The commit again is the block already held, not one the mirror
        // refuses: only the chain's next record is judged.
        assert!(matches!(
            take(&follower, &o.owner, &o.owner.sent[1]).await,
            Ok(Followed::Duplicate { .. })
        ));
        let block = follower.store.get_block(&sealed).unwrap().unwrap();
        assert!(block.is_synthetic, "ciphertext is never executed");
        assert!(
            !String::from_utf8_lossy(&block.bundle_bytes).contains("only the group"),
            "stored as ciphertext"
        );
    }

    /// A removed member's client gets its own removal from the follower, as
    /// from the owner: on an MLS channel that block carries the commit that
    /// tells the client the group is gone.
    #[tokio::test]
    async fn a_removed_member_receives_its_removal_from_the_follower() {
        let mut o = MlsOwner::new().await;
        let (_, member) = o.add_did().await;
        let follower = o.owner.follower();
        for sent in &o.owner.sent {
            take(&follower, &o.owner, sent).await.unwrap();
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        follower
            .fanout
            .subscribe_local(
                crate::fanout::SubscriptionScope::Channel(o.owner.channel.clone()),
                crate::fanout::SubscriberIdentity::Did(member.clone()),
                tx,
            )
            .await;
        o.remove(&member).await;
        let removal = o.owner.sent.last().unwrap();
        take(&follower, &o.owner, removal).await.unwrap();
        assert!(
            rx.try_recv().is_ok(),
            "the removed member receives its removal"
        );
    }

    /// Rule 19: a commit the owner sequenced that does not apply to the
    /// mirror is not delivered. The evidence is kept, and the channel takes
    /// nothing more, as at a fork.
    #[tokio::test]
    async fn a_commit_the_mirror_refuses_stops_the_channel() {
        use base64::Engine as _;
        let mut o = MlsOwner::new().await;
        let commit = o.add().await;
        let follower = o.owner.follower();
        for sent in &o.owner.sent {
            take(&follower, &o.owner, sent).await.unwrap();
        }
        // The same commit again: the group is past its epoch.
        let again = signed(
            &o.owner.user,
            BlockKind::MemberAdd,
            serde_json::json!({
                "channel_id": o.owner.channel,
                "member_did": "did:jig:zsomeoneelse",
                "mls_commit": base64::engine::general_purpose::STANDARD.encode(&commit),
                "mls_welcome": "AA==",
            }),
        );
        let head = IngestRecord::decode(&o.owner.sent.last().unwrap().record).unwrap();
        let stale = Sent {
            record: o.owner.sign_at(&again, head.seq + 1, head.hash()),
            parts: again,
        };
        match take(&follower, &o.owner, &stale).await {
            Err(FollowError::Unapplied { seq, .. }) => assert_eq!(seq, head.seq + 1),
            other => panic!("{other:?}"),
        }
        let cid = bundle(&stale.parts).block_cid().unwrap().to_string();
        assert!(
            follower.store.get_block(&cid).unwrap().is_none(),
            "not delivered"
        );
        assert_eq!(
            follower
                .store
                .chain_evidence(&o.owner.channel)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            follower
                .store
                .get_mls_group_by_id(&o.owner.channel)
                .unwrap()
                .unwrap()
                .epoch,
            1,
            "the mirror did not move"
        );
        // Stopped: even a block that would apply is not taken.
        let later = o.sealed("later");
        let next = Sent {
            record: o.owner.sign_at(&later, head.seq + 1, head.hash()),
            parts: later,
        };
        let got = take(&follower, &o.owner, &next).await;
        assert!(matches!(got, Err(FollowError::Stopped { .. })), "{got:?}");
    }

    /// A sealed message must be ciphertext for the mirror's group, as at the
    /// owner: one for another group is refused.
    #[tokio::test]
    async fn sealed_content_is_checked_against_the_mirror() {
        let o = MlsOwner::new().await;
        let other = MlsOwner::new().await;
        let follower = o.owner.follower();
        take(&follower, &o.owner, &o.owner.sent[0]).await.unwrap();
        let foreign = other.sealed_in(&o.owner.channel, "not for this group");
        let genesis = IngestRecord::decode(&o.owner.sent[0].record).unwrap();
        let sent = Sent {
            record: o.owner.sign_at(&foreign, 1, genesis.hash()),
            parts: foreign,
        };
        let got = take(&follower, &o.owner, &sent).await;
        assert!(matches!(got, Err(FollowError::Unapplied { .. })), "{got:?}");
    }

    // --- JEP-0005 rule 14c: blocks of a kind this build does not implement ---

    /// A block of kind `name`, which this build does not implement, signed by
    /// `key`. Built as JSON: no `BlockKind` names it.
    fn unknown(
        key: &SigningKey,
        name: &str,
        meta: serde_json::Value,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (manifest_bytes, _, _) = signed(key, BlockKind::TextRender, meta);
        let mut manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        manifest["kind"] = serde_json::json!(name);
        manifest["metadata"].as_object_mut().unwrap().remove("body");
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let code_bytes = Vec::new();
        let sig = key
            .sign(&serde_json::to_vec(&(&manifest_bytes, &code_bytes)).unwrap())
            .to_bytes()
            .to_vec();
        (manifest_bytes, code_bytes, sig)
    }

    impl Owner {
        /// Sequence `parts` as the next link after `after` (the record sent
        /// last), as an owner that implements its kind would.
        fn next_after(&self, after: &[u8], parts: (Vec<u8>, Vec<u8>, Vec<u8>)) -> Sent {
            let last = IngestRecord::decode(after).unwrap();
            Sent {
                record: self.sign_at(&parts, last.seq + 1, last.hash()),
                parts,
            }
        }

        fn unknown(&self, name: &str, extra: serde_json::Value) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let mut meta = serde_json::json!({"channel_id": self.channel});
            if let serde_json::Value::Object(extra) = extra {
                meta.as_object_mut().unwrap().extend(extra);
            }
            unknown(&self.user, name, meta)
        }

        fn text_parts(&self, body: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let meta = serde_json::json!({"channel_id": self.channel, "body": body});
            signed(&self.user, BlockKind::TextRender, meta)
        }
    }

    fn cid_of(sent: &Sent) -> String {
        bundle(&sent.parts).block_cid().unwrap().to_string()
    }

    /// A local subscription to `channel` on `follower` that takes notices.
    async fn watch(
        follower: &IngestContext,
        channel: &str,
    ) -> tokio::sync::mpsc::UnboundedReceiver<(u64, crate::fanout::ChannelNotice)> {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let id = follower
            .fanout
            .subscribe_local(
                crate::fanout::SubscriptionScope::Channel(channel.to_string()),
                crate::fanout::SubscriberIdentity::Unchecked,
                tx,
            )
            .await;
        let (notice_tx, notice_rx) = tokio::sync::mpsc::unbounded_channel();
        follower.fanout.watch_notices(id, notice_tx);
        std::mem::forget(_rx);
        notice_rx
    }

    #[tokio::test]
    async fn a_critical_unknown_kind_stops_its_channel_and_only_it() {
        let mut owner = Owner::new().await;
        owner.text("before").await;
        let follower = owner.follower();
        let mut other = Owner::new().await;
        share(&follower, &other.channel, &other.did());
        for sent in &owner.sent {
            take(&follower, &owner, sent).await.unwrap();
        }
        take(&follower, &other, &other.sent[0]).await.unwrap();
        let mut notices = watch(&follower, &owner.channel).await;

        let critical = owner.next_after(
            &owner.sent[1].record,
            owner.unknown("future-kind", serde_json::json!({})),
        );
        match take(&follower, &owner, &critical).await {
            Err(FollowError::NeedsUpgrade {
                channel_id,
                seq,
                kind,
            }) => {
                assert_eq!(
                    (channel_id.as_str(), seq, kind.as_str()),
                    (owner.channel.as_str(), 2, "future-kind")
                );
            }
            got => panic!("{got:?}"),
        }
        // Nothing of the block is kept but the stop; the head stays before it.
        assert!(
            follower
                .store
                .get_block(&cid_of(&critical))
                .unwrap()
                .is_none()
        );
        assert!(
            follower
                .store
                .ingest_record_bytes(&owner.channel, 2)
                .unwrap()
                .is_none()
        );
        let stop = follower
            .store
            .carried_upgrade(&owner.channel)
            .unwrap()
            .unwrap();
        assert_eq!(
            (stop.seq, stop.block_cid.as_str()),
            (2, cid_of(&critical).as_str())
        );
        assert_eq!(
            follower.store.carried_upgrades().unwrap(),
            vec![stop.clone()]
        );

        // Its subscribers are told once, as the existing error frame would.
        let (_, notice) = notices.try_recv().unwrap();
        assert_eq!(notice.code, crate::fanout::CHANNEL_NEEDS_UPGRADE);
        assert_eq!(notice.channel_id, owner.channel);
        assert!(
            notice.message.contains("`future-kind` at seq 2"),
            "{}",
            notice.message
        );

        // What comes after is the same stop, never a gap to fill: the next
        // link, one further on, and the block itself again.
        let after = owner.next_after(&critical.record, owner.text_parts("after"));
        let further = owner.next_after(&after.record, owner.text_parts("further"));
        for sent in [&after, &further, &critical] {
            let got = take(&follower, &owner, sent).await;
            assert!(
                matches!(got, Err(FollowError::NeedsUpgrade { seq: 2, .. })),
                "{got:?}"
            );
        }
        assert!(
            notices.try_recv().is_err(),
            "told once, not once per record"
        );

        // The other channel goes on.
        let text = other.text("still here").await;
        assert!(matches!(
            take(&follower, &other, other.sent.last().unwrap()).await,
            Ok(Followed::Landed { seq: 1, .. })
        ));
        assert!(follower.store.get_block(&text).unwrap().is_some());
    }

    #[tokio::test]
    async fn a_non_critical_unknown_kind_lands_and_the_chain_goes_on() {
        let owner = Owner::new().await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();

        let reaction = owner.next_after(
            &owner.sent[0].record,
            owner.unknown("opt-reaction", serde_json::json!({"to": "x"})),
        );
        assert!(matches!(
            take(&follower, &owner, &reaction).await,
            Ok(Followed::Landed { seq: 1, .. })
        ));
        let stored = follower
            .store
            .get_block(&cid_of(&reaction))
            .unwrap()
            .unwrap();
        assert_eq!(stored.block_kind, "opt-reaction");
        assert!(stored.is_synthetic, "never executed");
        assert_eq!(
            follower
                .store
                .ingest_record_bytes(&owner.channel, 1)
                .unwrap()
                .unwrap(),
            reaction.record
        );

        let next = owner.next_after(&reaction.record, owner.text_parts("next"));
        assert!(matches!(
            take(&follower, &owner, &next).await,
            Ok(Followed::Landed { seq: 2, .. })
        ));
        // Again is a duplicate, as any block is.
        assert!(matches!(
            take(&follower, &owner, &reaction).await,
            Ok(Followed::Duplicate { seq: 1, .. })
        ));
        assert!(follower.store.carried_upgrades().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unknown_kind_carrying_an_mls_group_key_is_critical_whatever_its_name() {
        let owner = Owner::new().await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        let commit = owner.next_after(
            &owner.sent[0].record,
            owner.unknown("opt-reaction", serde_json::json!({"mls_commit": "AAAA"})),
        );
        assert!(matches!(
            take(&follower, &owner, &commit).await,
            Err(FollowError::NeedsUpgrade { seq: 1, .. })
        ));
        assert!(
            follower
                .store
                .get_block(&cid_of(&commit))
                .unwrap()
                .is_none()
        );
    }

    /// The marker is the kind name, in the bytes the author signed: one put
    /// there afterwards, by a relay or anyone, breaks the signature, so the
    /// block is refused before anything of it is kept.
    #[tokio::test]
    async fn a_marker_added_after_signing_fails_the_signature() {
        let owner = Owner::new().await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        let (manifest, code, sig) = owner.unknown("future-kind", serde_json::json!({}));
        let relabelled = String::from_utf8(manifest)
            .unwrap()
            .replace("\"future-kind\"", "\"opt-future-kind\"")
            .into_bytes();
        let forged = owner.next_after(&owner.sent[0].record, (relabelled, code, sig));
        assert!(matches!(
            take(&follower, &owner, &forged).await,
            Err(FollowError::Block(IngestError::InvalidSignature))
        ));
        assert!(
            follower
                .store
                .get_block(&cid_of(&forged))
                .unwrap()
                .is_none()
        );
        assert!(follower.store.carried_upgrades().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unknown_kind_must_name_the_records_channel_and_be_its_authors() {
        let owner = Owner::new().await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        let after = &owner.sent[0].record;

        // No channel id: a kind this build does not know names no channel it
        // can tell by slug.
        let unnamed = owner.next_after(
            after,
            unknown(&owner.user, "opt-reaction", serde_json::json!({})),
        );
        assert!(matches!(
            take(&follower, &owner, &unnamed).await,
            Err(FollowError::Mismatch(_))
        ));
        // Another channel's id.
        let elsewhere = owner.next_after(
            after,
            unknown(
                &owner.user,
                "opt-reaction",
                serde_json::json!({"channel_id": "bafkother"}),
            ),
        );
        assert!(matches!(
            take(&follower, &owner, &elsewhere).await,
            Err(FollowError::Mismatch(_))
        ));
        // The right channel, signed by another key than its author's: refused
        // before anything is kept, critical or not.
        for name in ["opt-reaction", "future-kind"] {
            let (manifest, code, _) = owner.unknown(name, serde_json::json!({}));
            let stranger = SigningKey::from_bytes(&rand::random());
            let sig = stranger
                .sign(&serde_json::to_vec(&(&manifest, &code)).unwrap())
                .to_bytes()
                .to_vec();
            let forged = owner.next_after(after, (manifest, code, sig));
            assert!(matches!(
                take(&follower, &owner, &forged).await,
                Err(FollowError::Block(IngestError::InvalidSignature))
            ));
            assert!(
                follower
                    .store
                    .get_block(&cid_of(&forged))
                    .unwrap()
                    .is_none()
            );
        }
        for sent in [&unnamed, &elsewhere] {
            assert!(follower.store.get_block(&cid_of(sent)).unwrap().is_none());
        }
        assert!(follower.store.carried_upgrades().unwrap().is_empty());
        assert!(
            follower
                .store
                .ingest_record_bytes(&owner.channel, 1)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_critical_unknown_kind_past_a_gap_is_the_gap_first() {
        let owner = Owner::new().await;
        let follower = owner.follower();
        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        let skipped = owner.next_after(&owner.sent[0].record, owner.text_parts("skipped"));
        let critical = owner.next_after(
            &skipped.record,
            owner.unknown("future-kind", serde_json::json!({})),
        );
        assert!(matches!(
            take(&follower, &owner, &critical).await,
            Err(FollowError::Gap {
                head: Some(0),
                got: 2,
                ..
            })
        ));
        assert!(follower.store.carried_upgrades().unwrap().is_empty());
    }

    #[test]
    fn a_build_that_implements_the_kind_drops_the_stop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = SqliteStore::open(&path).unwrap();
            let conn = store.conn.lock().unwrap();
            for (channel, kind) in [("a", "member-add"), ("b", "future-kind")] {
                conn.execute(
                    "INSERT INTO carried_upgrades (channel_id, seq, block_cid, kind, found_at)
                     VALUES (?1, 3, 'bafy', ?2, 0)",
                    params![channel, kind],
                )
                .unwrap();
            }
        }
        let store = SqliteStore::open(&path).unwrap();
        assert!(store.carried_upgrade("a").unwrap().is_none());
        assert_eq!(
            store.carried_upgrade("b").unwrap().unwrap().kind,
            "future-kind"
        );
    }

    /// `vectors/0005/unknown-kinds.json` (JEP-0005 rule 14c): each case's
    /// signature and criticality, as a follower reads them. With
    /// `JIG_BLESS_VECTORS` set, the file is written instead: the key and
    /// manifests are fixed, and Ed25519 signs deterministically.
    #[test]
    fn unknown_kind_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../jig-spec/jep/vectors/0005/unknown-kinds.json");
        if std::env::var_os("JIG_BLESS_VECTORS").is_some() {
            std::fs::write(&path, bless_unknown_kind_vectors()).unwrap();
        }
        let vectors: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let cases = vectors["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 6);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let manifest = case["manifest"].as_str().unwrap().as_bytes();
            let sig = hex::decode(case["sig_hex"].as_str().unwrap()).unwrap();
            let read = jig_core::UnknownKindManifest::parse(manifest).expect(name);
            assert_eq!(read.kind, case["kind"].as_str().unwrap(), "{name}");
            assert_eq!(read.critical, case["critical"].as_bool().unwrap(), "{name}");
            let verifies = crate::ingest::verify_sig(manifest, &[], &read.manifest, &sig).is_ok();
            assert_eq!(verifies, case["verifies"].as_bool().unwrap(), "{name}");
        }
    }

    fn bless_unknown_kind_vectors() -> String {
        let key = SigningKey::from_bytes(&[0x14; 32]);
        let author = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
        let manifest = |kind: &str, metadata: serde_json::Value| -> Vec<u8> {
            let mut m = serde_json::to_value(
                BlockManifest::builder()
                    .version(Version::new(0, 1, 0))
                    .author(Author {
                        did: author.clone(),
                        public_key: None,
                        roles: vec![],
                    })
                    .build()
                    .unwrap(),
            )
            .unwrap();
            m["kind"] = serde_json::json!(kind);
            m["metadata"] = metadata;
            serde_json::to_vec(&m).unwrap()
        };
        let sign = |m: &[u8]| {
            hex::encode(
                key.sign(&serde_json::to_vec(&(m, &[] as &[u8])).unwrap())
                    .to_bytes(),
            )
        };
        let channel = "bafkreiaxnnnb7qz2focittuqq3ya25q7rcv3bqynnczfzao65fdpjsbv4i";
        let case = |name: &str, kind: &str, meta: serde_json::Value, critical: bool| {
            let m = manifest(kind, meta);
            serde_json::json!({
                "name": name,
                "manifest": String::from_utf8(m.clone()).unwrap(),
                "sig_hex": sign(&m),
                "kind": kind,
                "critical": critical,
                "verifies": true,
            })
        };
        let plain = manifest("future-kind", serde_json::json!({"channel_id": channel}));
        let relabelled = String::from_utf8(plain.clone())
            .unwrap()
            .replace("\"future-kind\"", "\"opt-future-kind\"");
        let vectors = serde_json::json!({
            "description": "JEP-0005 rule 14c. Each manifest is of a kind no v0.2 build implements, signed by the Ed25519 key whose 32-byte seed is all 0x14, over the JSON array [manifest bytes, code bytes] with empty code. `critical` is the rule's verdict on the manifest's bytes; `verifies` whether the author's signature holds. A follower refuses a block whose signature fails before judging it.",
            "cases": [
                case("no marker: critical", "future-kind", serde_json::json!({"channel_id": channel}), true),
                case("opt- prefix: non-critical", "opt-reaction", serde_json::json!({"channel_id": channel, "to": "x"}), false),
                case("opt- prefix carrying mls_commit: critical", "opt-reaction", serde_json::json!({"channel_id": channel, "mls_commit": "AAAA"}), true),
                case("opt- prefix carrying only mls_message and mls_epoch: non-critical", "opt-reaction", serde_json::json!({"channel_id": channel, "mls_message": "AAAA", "mls_epoch": 3}), false),
                case("opt- prefix carrying an mls_ key not yet named: critical", "opt-reaction", serde_json::json!({"channel_id": channel, "mls_proposal": "AAAA"}), true),
                {
                    "name": "marker added after signing: the signature fails",
                    "manifest": relabelled,
                    "sig_hex": sign(&plain),
                    "kind": "opt-future-kind",
                    "critical": false,
                    "verifies": false,
                },
            ],
        });
        serde_json::to_string_pretty(&vectors).unwrap() + "\n"
    }

    /// Every `mls_` key the gate reads is named by rule 14c as a group key
    /// or as content, so the override does not rest on the prefix alone.
    #[test]
    fn every_mls_key_the_gate_reads_is_named_by_rule_14c() {
        use crate::mls_gate::keys;
        for key in [
            keys::GROUP_INFO,
            keys::RATCHET_TREE,
            keys::COMMIT,
            keys::WELCOME,
            keys::MESSAGE,
            keys::EPOCH,
        ] {
            assert!(
                jig_core::block_kind::MLS_GROUP_KEYS.contains(&key)
                    || jig_core::block_kind::MLS_CONTENT_KEYS.contains(&key),
                "{key}"
            );
        }
        for key in jig_core::block_kind::MLS_GROUP_KEYS {
            assert!(!jig_core::block_kind::MLS_CONTENT_KEYS.contains(key));
        }
    }
}
