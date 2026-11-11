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
//! MLS channels are followed in a later slice (JEP-0005 rule 19); a block of
//! one is refused here, so the stream stops rather than carry what it cannot
//! validate.

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
    /// The owner's record at `seq` names a block this server holds in
    /// another of its channels, `holder`, whose chain names it too. One CID
    /// is one block, so the record cannot land, and the carried channel
    /// waits at `seq` ([`CarriedStall`]).
    #[error(
        "channel {channel_id} is stalled at seq {seq}: block {block_cid} is held in channel {holder}"
    )]
    Held {
        channel_id: String,
        seq: u64,
        block_cid: String,
        holder: String,
    },
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

/// A carried channel waiting at `seq`: the owner's record there names
/// `block_cid`, which this server holds in its own channel `holder`
/// ([`FollowError::Held`]). Kept until a record of the channel lands.
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

/// The `chain_evidence` and `carried_stalls` tables, created by
/// [`SqliteStore`]'s migration.
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
        "#,
    )?;
    Ok(())
}

/// How a landing attempt ended, inside its transaction.
enum Landing {
    Landed,
    Duplicate,
    Gap(Option<u64>),
    Fork,
    Stopped,
    /// The block is held in `holder`, another channel; the stall is kept.
    Held(String),
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

    /// The stored bytes of `channel_id`'s record at `seq`, as they arrived.
    pub fn ingest_record_bytes(
        &self,
        channel_id: &str,
        seq: u64,
    ) -> crate::persist::Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().expect("poisoned");
        Ok(conn
            .query_row(
                "SELECT record FROM ingest_records WHERE channel_id = ?1 AND seq = ?2",
                params![channel_id, seq as i64],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Store `block` with the owner's `record`, verified already, as the next
    /// link of its chain, in one transaction: or keep the evidence that it
    /// cannot be one.
    fn land_carried(
        &self,
        block: &StoredBlock,
        record: &IngestRecord,
        record_bytes: &[u8],
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
        let held_at = |seq: u64| -> crate::persist::Result<Option<Vec<u8>>> {
            Ok(tx
                .query_row(
                    "SELECT record FROM ingest_records WHERE channel_id = ?1 AND seq = ?2",
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
                "SELECT seq, record FROM ingest_records WHERE channel_id = ?1
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
        // A block held already in a relayed copy of this channel, set aside
        // ([`SqliteStore::quarantine_relayed_copy`]): one CID is one block, so
        // the owner's chain takes it back into the channel. A block held in
        // any other channel stays where it is, and the insert refuses it: a
        // block named by slug can sit in this server's own channel of the
        // same slug, whose chain still names it.
        let in_copy: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blocks b JOIN quarantined_copies q
                 ON b.channel_id = q.copy_id
             WHERE b.cid = ?1 AND q.channel_id = ?2)",
            params![block.cid, channel_id],
            |r| r.get(0),
        )?;
        let holder: Option<Option<String>> = tx
            .query_row(
                "SELECT channel_id FROM blocks WHERE cid = ?1",
                [&block.cid],
                |r| r.get(0),
            )
            .optional()?;
        match holder {
            Some(_) if in_copy => {
                tx.execute(
                    "UPDATE blocks SET channel_id = ?2 WHERE cid = ?1",
                    params![block.cid, channel_id],
                )?;
            }
            Some(holder) => {
                let holder = holder.unwrap_or_default();
                tx.execute(
                    "INSERT INTO carried_stalls
                         (channel_id, seq, block_cid, holder, found_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(channel_id) DO UPDATE SET
                         seq = excluded.seq, block_cid = excluded.block_cid,
                         holder = excluded.holder",
                    params![
                        channel_id,
                        record.seq as i64,
                        block.cid,
                        holder,
                        chrono::Utc::now().timestamp()
                    ],
                )?;
                tx.commit()?;
                return Ok(Landing::Held(holder));
            }
            None => crate::persist::insert_block_on(&tx, block)?,
        }
        tx.execute(
            "INSERT INTO ingest_records (block_cid, channel_id, seq, record) VALUES (?1, ?2, ?3, ?4)",
            params![record.block_cid, channel_id, record.seq as i64, record_bytes],
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
    let manifest = crate::ingest::parse_manifest(bundle.manifest_bytes)?;
    crate::ingest::check_manifest_dids(&manifest)?;
    let sender =
        crate::ingest::verify_sig(bundle.manifest_bytes, bundle.code_bytes, &manifest, &sig)?;
    let kind = manifest.kind.ok_or(IngestError::KindRequired)?;

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

    // The channel the record puts the block in, and the block's own word for
    // it, must agree.
    let channel = if kind == BlockKind::ChannelCreate {
        if channel_id != block_cid {
            return Err(FollowError::Mismatch(
                "a channel-create's record names another channel",
            ));
        }
        let terms = crate::ingest::channel_terms(&manifest, sequencer)?;
        if terms.sequencer != crate::effect::canonical_did_string(sequencer) {
            return Err(not_carried());
        }
        if crate::mls_gate::requested_suite(&manifest).ok()
            != Some(jig_core::EncryptionSuite::Unencrypted)
        {
            return Err(FollowError::Unsupported(
                "an MLS channel is followed from slice 7",
            ));
        }
        None
    } else {
        let chan = ctx
            .store
            .get_channel_by_id_including_archived(&channel_id)?
            .filter(|c| {
                crate::effect::canonical_did_string(&c.sequencer_did)
                    == crate::effect::canonical_did_string(sequencer)
            })
            .ok_or_else(not_carried)?;
        let names_it = match manifest
            .metadata
            .get(crate::ingest::CHANNEL_ID_KEY)
            .and_then(|v| v.as_str())
        {
            Some(id) => id == channel_id,
            None => crate::ingest::channel_slug_of(kind, &manifest) == Some(chan.slug.as_str()),
        };
        if !names_it {
            return Err(FollowError::Mismatch("the block names another channel"));
        }
        if chan.suite != jig_core::EncryptionSuite::Unencrypted.as_str() {
            return Err(FollowError::Unsupported(
                "an MLS channel is followed from slice 7",
            ));
        }
        Some(chan)
    };
    // This server carries only what it agreed to: an accepted share of the
    // channel, with this sequencer.
    if !ctx.store.has_accepted_share(&channel_id, sequencer)? {
        return Err(FollowError::NoShare {
            channel_id,
            sequencer: sequencer.to_string(),
        });
    }
    // Rule 12: the owner's signature, exactly, and nothing of this server's.
    record.verify(sequencer)?;

    let canonical = crate::ingest::bundle_canonical_bytes(bundle.manifest_bytes, bundle.code_bytes)
        .map_err(IngestError::BundleMalformed)?;
    let hlc = manifest.hlc_ts.as_ref();
    let stored = StoredBlock {
        cid: block_cid.clone(),
        channel_id: Some(channel_id.clone()),
        block_kind: kind.as_str().to_string(),
        sender_did: sender.to_did_jig_string(),
        sender_sig: sig,
        bundle_bytes: canonical,
        is_synthetic: !kind.is_wasm_executable(),
        hlc_wall_ms: hlc.map(|h| h.wall_ms).unwrap_or(0),
        hlc_logical: hlc.map(|h| h.logical).unwrap_or(0),
        hlc_origin: hlc.map(|h| h.server_did.to_string()).unwrap_or_default(),
        posted_at: chrono::Utc::now().timestamp(),
        origin_server: sequencer.to_string(),
        federated_from: Some(sequencer.to_string()),
    };
    let seq = record.seq;
    let effect = |conn: &rusqlite::Connection| {
        crate::effect::apply_carried_effect(
            conn,
            &manifest,
            &block_cid,
            channel.as_ref(),
            sequencer,
        )
    };
    match ctx
        .store
        .land_carried(&stored, &record, record_bytes, effect)?
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
        Landing::Held(holder) => {
            tracing::warn!(
                channel_id,
                seq,
                block_cid,
                holder,
                sequencer,
                "a carried channel is stalled: the owner's record names a block this server \
                 holds in another channel (`jig-server contracts list` shows it)"
            );
            return Err(FollowError::Held {
                channel_id,
                seq,
                block_cid,
                holder,
            });
        }
        Landing::EffectFailed(e) => return Err(FollowError::Other(e)),
        Landing::Landed => {}
    }
    deliver(ctx, &stored, &channel_id).await;
    Ok(Followed::Landed { block_cid, seq })
}

/// Hand a carried block to this server's own subscribers, under the
/// channel's policy as it now stands. Never to peers: the owner sends its
/// blocks to each follower itself.
async fn deliver(ctx: &IngestContext, block: &StoredBlock, channel_id: &str) {
    let policy = match ctx.store.get_channel_by_id_including_archived(channel_id) {
        Ok(Some(chan)) => {
            let members = ctx
                .store
                .list_members(&chan.id)
                .map(|ms| ms.into_iter().map(|m| m.member_did).collect())
                .unwrap_or_default();
            // Not to this server's federation subscribers either: a peer of
            // this one would take the channel as a copy of its own, and a
            // channel has one sequencer (JEP-0005 rule 1).
            DeliveryPolicy {
                federates: false,
                ..DeliveryPolicy::for_channel(&chan, members)
            }
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
        .broadcast_local_only(block, &receipt, Some(&policy))
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
            allowed_block_kinds: ["text-render", "channel-create", "member-add"]
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
        async fn post(&mut self, kind: BlockKind, meta: serde_json::Value) -> String {
            let parts = signed(&self.user, kind, meta);
            let cid = ingest(
                &self.ctx,
                bundle(&parts),
                parts.2.clone(),
                IngestSource::LocalClient { conn_id: 1 },
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

    /// The owner's chain takes back a block only from this channel's relayed
    /// copy. The same CID held in another of the follower's channels stays
    /// there, and the record for it does not land.
    #[tokio::test]
    async fn a_block_held_in_another_channel_is_not_taken() {
        let mut owner = Owner::new().await;
        let text = owner.text("one").await;
        let follower = owner.follower();
        let mut held = owner.ctx.store.get_block(&text).unwrap().unwrap();
        held.channel_id = Some("bafyours".to_string());
        follower.store.insert_block(&held).unwrap();

        take(&follower, &owner, &owner.sent[0]).await.unwrap();
        match take(&follower, &owner, &owner.sent[1]).await {
            Err(FollowError::Held {
                channel_id,
                seq: 1,
                block_cid,
                holder,
            }) => {
                assert_eq!(channel_id, owner.channel);
                assert_eq!(block_cid, text);
                assert_eq!(holder, "bafyours");
            }
            other => panic!("{other:?}"),
        }
        let block = follower.store.get_block(&text).unwrap().unwrap();
        assert_eq!(block.channel_id.as_deref(), Some("bafyours"));
        assert_eq!(
            follower
                .store
                .ingest_record_bytes(&owner.channel, 1)
                .unwrap(),
            None
        );
        // The stall is kept for an operator to see, once, however often the
        // record comes again.
        assert!(take(&follower, &owner, &owner.sent[1]).await.is_err());
        let stalls = follower.store.carried_stalls().unwrap();
        assert_eq!(stalls.len(), 1);
        assert_eq!(
            (stalls[0].channel_id.as_str(), stalls[0].seq),
            (owner.channel.as_str(), 1)
        );
        assert_eq!(
            stalls[0].to_string(),
            format!(
                "channel {} stalled at seq 1: block {text} is held in channel bafyours",
                owner.channel
            )
        );

        // Once the block is out of the way, the record lands and the stall
        // is gone.
        follower
            .store
            .conn
            .lock()
            .unwrap()
            .execute("DELETE FROM blocks WHERE cid = ?1", [&text])
            .unwrap();
        take(&follower, &owner, &owner.sent[1]).await.unwrap();
        assert!(follower.store.carried_stalls().unwrap().is_empty());
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
                IngestSource::LocalClient { conn_id: 1 },
            )
            .await;
            let too_large = matches!(got, Err(IngestError::BundleTooLarge { .. }));
            assert_eq!(too_large, refused, "a local post of {len} bytes: {got:?}");
        }
        // A kind this build does not know is refused as the manifest it is.
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
            Err(FollowError::Block(IngestError::BundleMalformed(_)))
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
                IngestSource::LocalClient { conn_id: 1 }
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
            IngestSource::LocalClient { conn_id: 1 },
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

    #[tokio::test]
    async fn an_mls_channel_is_not_followed_yet() {
        let owner = Owner::new().await;
        let follower = ctx();
        // An MLS creation block, signed and recorded by the owner's key.
        let parts = signed(
            &owner.user,
            BlockKind::ChannelCreate,
            serde_json::json!({"slug": "#sealed", "suite": "mls"}),
        );
        let cid = bundle(&parts).block_cid().unwrap().to_string();
        share(&follower, &cid, &owner.did());
        let record = RecordSigner {
            channel_id: cid.clone(),
            key: &owner.ctx.server_key,
            ingest_wall_ms: 1,
            ingest_logical: 0,
        }
        .sign(0, &cid, crate::ingest_record::GENESIS_PREV)
        .unwrap()
        .encode();
        let sent = Sent { parts, record };
        assert!(matches!(
            take(&follower, &owner, &sent).await,
            Err(FollowError::Unsupported(_))
        ));
    }
}
