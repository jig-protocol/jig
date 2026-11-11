//! The channel contract's blocks (JEP-0005 rules 7, 10 and 11).
//!
//! A share is driven by blocks in the channel's own log:
//! - `channel-share {to, grant}` and `channel-unshare {to}`, signed by a DID
//!   holding the `share` right, ask the owning server to offer the channel to
//!   `to`, or to end the share it has with `to`;
//! - `contract-accept`, `contract-refuse` and `contract-end` record what came
//!   of it. Only the channel's sequencer writes them, and each carries the
//!   signed contract messages ([`jig_core::contract`]) it records, base64
//!   in metadata, so any member can check them without trusting the
//!   sequencer's word.
//!
//! This module reads and checks those blocks' metadata, and keeps the offers
//! a server made or received ([`StoredOffer`]). Who may sign each block is
//! [`crate::authorize_write`]'s call.

use base64::Engine as _;
use cid::Cid;
use jig_core::BlockManifest;
use jig_core::block_kind::BlockKind;
use jig_core::contract::{
    ContractAccept, ContractEnd, ContractError, ContractOffer, ContractRefuse, Grant, RefuseCode,
};
use rusqlite::{OptionalExtension, params};

use crate::ingest_record::IngestRecord;
use crate::persist::SqliteStore;

/// The server a share names: the target of `channel-share` and
/// `channel-unshare`, and the follower a `contract-*` record is about.
pub const TO_KEY: &str = "to";
/// The grant a `channel-share` asks for (rule 7a).
pub const GRANT_KEY: &str = "grant";
/// The signed `contract-offer`, base64.
pub const OFFER_KEY: &str = "offer";
/// The signed `contract-accept`, base64.
pub const ACCEPT_KEY: &str = "accept";
/// The signed `contract-refuse`, base64.
pub const REFUSE_KEY: &str = "refuse";
/// A `contract-refuse`'s code (rule 8), in clear so it reads without
/// decoding the envelope, and present when there is none.
pub const CODE_KEY: &str = "code";
/// The signed `contract-end`, base64.
pub const END_KEY: &str = "end";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContractBlockError {
    #[error("`{0}` is missing")]
    Missing(&'static str),
    #[error("`{0}` is not a canonical did:jig")]
    BadServer(String),
    #[error("`{0}` is not base64")]
    NotBase64(&'static str),
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error("{0}")]
    Mismatch(&'static str),
}

/// What a `channel-share` or `channel-unshare` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRequest {
    /// The target server's DID, canonical.
    pub to: String,
    /// The grant asked for; `None` for a `channel-unshare`.
    pub grant: Option<Grant>,
}

/// Read a `channel-share` or `channel-unshare`.
pub fn share_request(
    kind: BlockKind,
    manifest: &BlockManifest,
) -> Result<ShareRequest, ContractBlockError> {
    let to = server(manifest)?;
    let grant = match kind {
        BlockKind::ChannelShare => Some(Grant::parse(
            meta_str(manifest, GRANT_KEY).ok_or(ContractBlockError::Missing(GRANT_KEY))?,
        )?),
        _ => None,
    };
    Ok(ShareRequest { to, grant })
}

/// Check a `contract-accept`, `contract-refuse` or `contract-end` record for
/// the channel `channel_id`, whose sequencer is `sequencer`: its envelopes are
/// signed by whom they name, are about this channel, and fit together.
pub fn check_record(
    kind: BlockKind,
    manifest: &BlockManifest,
    channel_id: &Cid,
    sequencer: &str,
) -> Result<(), ContractBlockError> {
    let to = server(manifest)?;
    let same_channel = |cid: &Cid| {
        if cid == channel_id {
            Ok(())
        } else {
            Err(ContractBlockError::Mismatch(
                "the message is for another channel",
            ))
        }
    };
    let owners_offer = |offer: &ContractOffer| {
        same_channel(&offer.channel_id)?;
        if offer.owner != sequencer {
            return Err(ContractBlockError::Mismatch(
                "the offer is not signed by the channel's sequencer",
            ));
        }
        if offer.to != to {
            return Err(ContractBlockError::Mismatch(
                "the offer is to another server",
            ));
        }
        Ok(())
    };
    match kind {
        BlockKind::ContractAccept => {
            let offer = ContractOffer::from_envelope(&envelope(manifest, OFFER_KEY)?)?;
            let accept = ContractAccept::from_envelope(&envelope(manifest, ACCEPT_KEY)?)?;
            owners_offer(&offer)?;
            accept.answers(&offer)?;
            Ok(())
        }
        BlockKind::ContractRefuse => {
            let code = RefuseCode::parse(
                meta_str(manifest, CODE_KEY).ok_or(ContractBlockError::Missing(CODE_KEY))?,
            )?;
            // The owning server's own refusal has no message from the target
            // to carry: a target that is not a peer, or an accept claiming one
            // of the owner's suffixes under another authority. Any other code
            // is the target's reason, so it comes with the target's message.
            if !manifest.metadata.contains_key(REFUSE_KEY) {
                let owners = matches!(code, RefuseCode::NotAPeer | RefuseCode::SuffixConflict);
                if !owners || manifest.metadata.contains_key(OFFER_KEY) {
                    return Err(ContractBlockError::Mismatch(
                        "a refusal without the target's message is the owner's own: NOT_A_PEER or SUFFIX_CONFLICT, with no offer",
                    ));
                }
                return Ok(());
            }
            let refuse = ContractRefuse::from_envelope(&envelope(manifest, REFUSE_KEY)?)?;
            let offer = ContractOffer::from_envelope(&envelope(manifest, OFFER_KEY)?)?;
            owners_offer(&offer)?;
            refuse.answers(&offer)?;
            if refuse.code != code {
                return Err(ContractBlockError::Mismatch(
                    "`code` is not the refusal's code",
                ));
            }
            Ok(())
        }
        BlockKind::ContractEnd => {
            let end = ContractEnd::from_envelope(&envelope(manifest, END_KEY)?)?;
            same_channel(&end.channel_id)?;
            if end.server != sequencer && end.server != to {
                return Err(ContractBlockError::Mismatch(
                    "the end is signed by neither side of the share",
                ));
            }
            Ok(())
        }
        _ => Err(ContractBlockError::Mismatch("not a contract record")),
    }
}

/// The base64 envelope under `key`, decoded.
pub fn envelope(
    manifest: &BlockManifest,
    key: &'static str,
) -> Result<Vec<u8>, ContractBlockError> {
    let b64 = meta_str(manifest, key).ok_or(ContractBlockError::Missing(key))?;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| ContractBlockError::NotBase64(key))
}

/// `to`, which must be a did:jig in canonical form: a share names a server
/// the way the peer list and the contract messages do, so one server has
/// one spelling.
fn server(manifest: &BlockManifest) -> Result<String, ContractBlockError> {
    let to = meta_str(manifest, TO_KEY).ok_or(ContractBlockError::Missing(TO_KEY))?;
    let canonical = crate::effect::canonical_did_string(to);
    if canonical != to || jig_core::Did::from_did_jig_string(to).is_err() {
        return Err(ContractBlockError::BadServer(to.to_string()));
    }
    Ok(canonical)
}

fn meta_str<'a>(manifest: &'a BlockManifest, key: &str) -> Option<&'a str> {
    manifest.metadata.get(key).and_then(|v| v.as_str())
}

/// Which side of a share this server is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The channel's sequencer, which made the offer.
    Owner,
    /// The server the offer was made to.
    Follower,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Owner => "owner",
            Side::Follower => "follower",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(Side::Owner),
            "follower" => Some(Side::Follower),
            _ => None,
        }
    }
}

/// Where an offer stands, on either side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferState {
    /// Made, and not yet answered.
    Offered,
    /// Received, and waiting for this server's operator.
    Held,
    /// Accepted: the share it names is live.
    Accepted,
    Refused,
    /// A live share either side ended.
    Ended,
    /// A live share a later accepted offer, for the same channel and peer,
    /// replaced (rule 11: a grant changes by a new offer and accept).
    Superseded,
    /// Never answered, and taken back by a `channel-unshare`.
    Withdrawn,
    /// Held, and the operator has decided to accept it: the running server
    /// signs and sends the accept.
    Accepting,
    /// Held, and the operator has decided to refuse it.
    Refusing,
    /// A live share this side has decided to end. It stays here until the
    /// signed end reaches the other side on a live connection.
    Ending,
}

impl OfferState {
    pub fn as_str(self) -> &'static str {
        match self {
            OfferState::Offered => "offered",
            OfferState::Held => "held",
            OfferState::Accepted => "accepted",
            OfferState::Refused => "refused",
            OfferState::Ended => "ended",
            OfferState::Superseded => "superseded",
            OfferState::Withdrawn => "withdrawn",
            OfferState::Accepting => "accepting",
            OfferState::Refusing => "refusing",
            OfferState::Ending => "ending",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "offered" => OfferState::Offered,
            "held" => OfferState::Held,
            "accepted" => OfferState::Accepted,
            "refused" => OfferState::Refused,
            "ended" => OfferState::Ended,
            "superseded" => OfferState::Superseded,
            "withdrawn" => OfferState::Withdrawn,
            "accepting" => OfferState::Accepting,
            "refusing" => OfferState::Refusing,
            "ending" => OfferState::Ending,
            _ => return None,
        })
    }
}

/// An offer this server made or received, with its answer once there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOffer {
    pub offer_id: [u8; 32],
    /// The channel's id, canonical CID text.
    pub channel_id: String,
    pub side: Side,
    /// The other server: the follower on the owner's side, the owner on the
    /// follower's.
    pub peer_did: String,
    pub grant: Grant,
    pub state: OfferState,
    /// The signed `contract-offer`.
    pub offer: Vec<u8>,
    /// The signed `contract-accept` or `contract-refuse`, once answered.
    pub answer: Option<Vec<u8>>,
    /// On the owner's side, the `channel-share` block that asked for it.
    pub share_cid: Option<String>,
}

const OFFER_COLUMNS: &str =
    "offer_id, channel_id, side, peer_did, grant, state, offer, answer, share_cid";

fn offer_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredOffer> {
    let bad = |i: usize, what: &str| {
        rusqlite::Error::FromSqlConversionFailure(
            i,
            rusqlite::types::Type::Text,
            format!("not a {what}").into(),
        )
    };
    let id: Vec<u8> = r.get(0)?;
    let side: String = r.get(2)?;
    let grant: String = r.get(4)?;
    let state: String = r.get(5)?;
    Ok(StoredOffer {
        offer_id: id.try_into().map_err(|_| bad(0, "32-byte offer id"))?,
        channel_id: r.get(1)?,
        side: Side::parse(&side).ok_or_else(|| bad(2, "side"))?,
        peer_did: r.get(3)?,
        grant: Grant::parse(&grant).map_err(|_| bad(4, "grant"))?,
        state: OfferState::parse(&state).ok_or_else(|| bad(5, "offer state"))?,
        offer: r.get(6)?,
        answer: r.get(7)?,
        share_cid: r.get(8)?,
    })
}

/// A relayed copy set aside ([`SqliteStore::quarantine_relayed_copy`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedCopy {
    /// The copy's own id, under which its row and blocks are kept.
    pub copy_id: String,
    pub slug: String,
    /// Blocks this server's own users posted in the copy, which no peer
    /// relayed: the owner may never have taken them.
    pub own_blocks: u64,
}

/// The `contract_offers` table, created by [`SqliteStore`]'s migration.
pub(crate) fn migrate(conn: &rusqlite::Connection) -> crate::persist::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS contract_offers (
            offer_id   BLOB PRIMARY KEY,
            channel_id TEXT NOT NULL,
            side       TEXT NOT NULL,
            peer_did   TEXT NOT NULL,
            grant      TEXT NOT NULL,
            state      TEXT NOT NULL,
            offer      BLOB NOT NULL,
            answer     BLOB,
            share_cid  TEXT
        );
        CREATE INDEX IF NOT EXISTS contract_offers_share
            ON contract_offers(channel_id, peer_did, side, state);

        -- A copy of a channel the federation relay made, set aside when this
        -- server came to follow the channel's owner for it
        -- ([`SqliteStore::quarantine_relayed_copy`]): kept, never relayed or
        -- followed. Its rows live on under `copy_id`; its records, whose
        -- blocks the owner's chain lands again, here.
        CREATE TABLE IF NOT EXISTS quarantined_copies (
            copy_id       TEXT PRIMARY KEY,
            channel_id    TEXT NOT NULL,
            own_blocks    INTEGER NOT NULL,
            quarantined_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS quarantined_records (
            copy_id    TEXT NOT NULL,
            block_cid  TEXT NOT NULL,
            seq        INTEGER NOT NULL,
            record     BLOB NOT NULL,
            PRIMARY KEY (copy_id, seq)
        );
        "#,
    )?;
    Ok(())
}

impl SqliteStore {
    /// Keep `offer`. An offer already kept, by `offer_id`, is left as it is:
    /// the same offer arriving twice is one offer. Says whether it was new.
    pub fn put_contract_offer(&self, offer: &StoredOffer) -> crate::persist::Result<bool> {
        let conn = self.conn.lock().expect("poisoned");
        let n = conn.execute(
            &format!("INSERT OR IGNORE INTO contract_offers ({OFFER_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"),
            params![
                offer.offer_id.as_slice(),
                offer.channel_id,
                offer.side.as_str(),
                offer.peer_did,
                offer.grant.as_str(),
                offer.state.as_str(),
                offer.offer,
                offer.answer,
                offer.share_cid,
            ],
        )?;
        Ok(n == 1)
    }

    pub fn get_contract_offer(
        &self,
        offer_id: &[u8; 32],
    ) -> crate::persist::Result<Option<StoredOffer>> {
        let conn = self.conn.lock().expect("poisoned");
        Ok(conn
            .query_row(
                &format!("SELECT {OFFER_COLUMNS} FROM contract_offers WHERE offer_id = ?1"),
                [offer_id.as_slice()],
                offer_from_row,
            )
            .optional()?)
    }

    /// Move an offer from `from` to `to`, keeping `answer` if one is given.
    /// Says whether it moved: an offer no longer in `from` stays as it is,
    /// so an answer or an end that arrives twice is recorded once.
    pub fn move_contract_offer(
        &self,
        offer_id: &[u8; 32],
        from: OfferState,
        to: OfferState,
        answer: Option<&[u8]>,
    ) -> crate::persist::Result<bool> {
        let mut conn = self.conn.lock().expect("poisoned");
        let tx = conn.transaction()?;
        let moved = tx.execute(
            "UPDATE contract_offers SET state = ?3, answer = COALESCE(?4, answer)
             WHERE offer_id = ?1 AND state = ?2",
            params![offer_id.as_slice(), from.as_str(), to.as_str(), answer],
        )? == 1;
        // A new accept replaces the live share it supersedes (rule 11).
        if moved && to == OfferState::Accepted {
            tx.execute(
                "UPDATE contract_offers SET state = ?2
                 WHERE state = ?3 AND offer_id != ?1
                   AND (channel_id, peer_did, side) =
                       (SELECT channel_id, peer_did, side FROM contract_offers WHERE offer_id = ?1)",
                params![
                    offer_id.as_slice(),
                    OfferState::Superseded.as_str(),
                    OfferState::Accepted.as_str()
                ],
            )?;
        }
        tx.commit()?;
        Ok(moved)
    }

    /// Every offer this server made or received, oldest first.
    pub fn list_contract_offers(&self) -> crate::persist::Result<Vec<StoredOffer>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(&format!(
            "SELECT {OFFER_COLUMNS} FROM contract_offers ORDER BY rowid"
        ))?;
        let rows = stmt
            .query_map([], offer_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Offers on `side` in `state`, oldest first.
    pub fn contract_offers_in(
        &self,
        side: Side,
        state: OfferState,
    ) -> crate::persist::Result<Vec<StoredOffer>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(&format!(
            "SELECT {OFFER_COLUMNS} FROM contract_offers WHERE side = ?1 AND state = ?2 ORDER BY rowid"
        ))?;
        let rows = stmt
            .query_map(params![side.as_str(), state.as_str()], offer_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The offers on `side` of `channel_id` with `peer_did` in `state`.
    pub fn contract_offers_for(
        &self,
        channel_id: &str,
        peer_did: &str,
        side: Side,
        state: OfferState,
    ) -> crate::persist::Result<Vec<StoredOffer>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(&format!(
            "SELECT {OFFER_COLUMNS} FROM contract_offers
             WHERE channel_id = ?1 AND peer_did = ?2 AND side = ?3 AND state = ?4 ORDER BY rowid"
        ))?;
        let rows = stmt
            .query_map(
                params![channel_id, peer_did, side.as_str(), state.as_str()],
                offer_from_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Whether this server follows `channel_id` for `owner_did` under an
    /// accepted share: the follower side of rule 9's accept.
    pub fn has_accepted_share(
        &self,
        channel_id: &str,
        owner_did: &str,
    ) -> crate::persist::Result<bool> {
        let canonical = crate::effect::canonical_did_string(owner_did);
        let conn = self.conn.lock().expect("poisoned");
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM contract_offers
             WHERE channel_id = ?1 AND peer_did IN (?2, ?3) AND side = ?4 AND state = ?5)",
            params![
                channel_id,
                owner_did,
                canonical,
                Side::Follower.as_str(),
                OfferState::Accepted.as_str()
            ],
            |r| r.get(0),
        )?)
    }

    /// Whether this server carries `channel_id` under a share it accepted,
    /// live or ended: its blocks reach it from the owner's stream, never by
    /// the federation relay.
    pub fn is_followed(&self, channel_id: &str) -> crate::persist::Result<bool> {
        let conn = self.conn.lock().expect("poisoned");
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM contract_offers
             WHERE channel_id = ?1 AND side = ?2 AND state IN (?3, ?4, ?5))",
            params![
                channel_id,
                Side::Follower.as_str(),
                OfferState::Accepted.as_str(),
                OfferState::Ending.as_str(),
                OfferState::Ended.as_str()
            ],
            |r| r.get(0),
        )?)
    }

    /// The channels this server holds as copies the federation relay made:
    /// a row it sequences, created by a `channel-create` a peer relayed.
    /// Every server peered the older way holds one per open channel of its
    /// peers.
    pub fn relayed_copies(&self) -> crate::persist::Result<Vec<String>> {
        let local = self.local_sequencer().to_string();
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT c.id FROM channels c JOIN blocks b ON b.cid = c.id
             WHERE (c.sequencer_did = '' OR c.sequencer_did = ?1)
               AND b.federated_from IS NOT NULL
             ORDER BY c.id",
        )?;
        let rows = stmt
            .query_map([local], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Set aside this server's relayed copy of `channel_id`
    /// ([`Self::relayed_copies`]), now that it follows the channel's owner
    /// for it, so the owner's stream can land the channel under its own id.
    /// Nothing is deleted, in one transaction:
    ///
    /// - the row moves to the copy's own id and a `#jig/relayed-…` slug, so
    ///   it is readable by that id, never relayed (`#jig/` channels do not
    ///   federate), and never followed;
    /// - its blocks, memberships and chain evidence move with it, as do any
    ///   offers this server made as though it owned the channel, ended so
    ///   that nothing acts on them;
    /// - its records, signed by this server, move to `quarantined_records`:
    ///   the owner's chain signs its own records for the same blocks, which
    ///   take them back into the channel as they land
    ///   ([`crate::follow::ingest_sequenced`]).
    ///
    /// The blocks the owner's chain never lands, such as posts this server's
    /// users made that the owner never took, stay in the copy. `None` unless
    /// `channel_id` is such a copy.
    pub fn quarantine_relayed_copy(
        &self,
        channel_id: &str,
    ) -> crate::persist::Result<Option<QuarantinedCopy>> {
        let local = self.local_sequencer().to_string();
        let mut conn = self.conn.lock().expect("poisoned");
        let tx = conn.transaction()?;
        let copy: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM channels c JOIN blocks b ON b.cid = c.id
             WHERE c.id = ?1 AND (c.sequencer_did = '' OR c.sequencer_did = ?2)
               AND b.federated_from IS NOT NULL)",
            params![channel_id, local],
            |r| r.get(0),
        )?;
        if !copy {
            return Ok(None);
        }
        let copy_id = crate::ingest_record::label_cid(&format!("relayed-copy:{channel_id}"));
        let slug = format!(
            "#jig/relayed-{}",
            &copy_id[copy_id.len().saturating_sub(40)..]
        );
        let own_blocks: i64 = tx.query_row(
            "SELECT COUNT(*) FROM blocks
             WHERE (channel_id = ?1 OR cid = ?1) AND federated_from IS NULL",
            [channel_id],
            |r| r.get(0),
        )?;
        tx.execute(
            "UPDATE channels SET id = ?2, slug = ?3 WHERE id = ?1",
            params![channel_id, copy_id, slug],
        )?;
        tx.execute(
            "UPDATE blocks SET channel_id = ?2 WHERE channel_id = ?1 OR cid = ?1",
            params![channel_id, copy_id],
        )?;
        tx.execute(
            "INSERT INTO quarantined_records (copy_id, block_cid, seq, record)
             SELECT ?2, block_cid, seq, record FROM ingest_records WHERE channel_id = ?1",
            params![channel_id, copy_id],
        )?;
        tx.execute(
            "DELETE FROM ingest_records WHERE channel_id = ?1",
            [channel_id],
        )?;
        tx.execute(
            "UPDATE memberships SET channel_id = ?2 WHERE channel_id = ?1",
            params![channel_id, copy_id],
        )?;
        tx.execute(
            "UPDATE chain_evidence SET channel_id = ?2 WHERE channel_id = ?1",
            params![channel_id, copy_id],
        )?;
        tx.execute(
            "UPDATE contract_offers SET channel_id = ?2, state = ?4
             WHERE channel_id = ?1 AND side = ?3",
            params![
                channel_id,
                copy_id,
                Side::Owner.as_str(),
                OfferState::Ended.as_str()
            ],
        )?;
        tx.execute(
            "INSERT INTO quarantined_copies (copy_id, channel_id, own_blocks, quarantined_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                copy_id,
                channel_id,
                own_blocks,
                chrono::Utc::now().timestamp()
            ],
        )?;
        tx.commit()?;
        Ok(Some(QuarantinedCopy {
            copy_id,
            slug,
            own_blocks: own_blocks as u64,
        }))
    }

    /// The records of a quarantined copy ([`Self::quarantine_relayed_copy`]),
    /// in seq order, as this server signed them.
    pub fn quarantined_records(
        &self,
        copy_id: &str,
    ) -> crate::persist::Result<Vec<(u64, String, Vec<u8>)>> {
        let conn = self.conn.lock().expect("poisoned");
        let mut stmt = conn.prepare(
            "SELECT seq, block_cid, record FROM quarantined_records
             WHERE copy_id = ?1 ORDER BY seq",
        )?;
        let rows = stmt
            .query_map([copy_id], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The newest record of `channel_id`'s chain: its `ingest` head.
    pub fn latest_ingest_record(
        &self,
        channel_id: &str,
    ) -> crate::persist::Result<Option<IngestRecord>> {
        let conn = self.conn.lock().expect("poisoned");
        let bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT record FROM ingest_records WHERE channel_id = ?1 ORDER BY seq DESC LIMIT 1",
                [channel_id],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .map(|b| {
                IngestRecord::decode(&b).map_err(|e| {
                    crate::persist::PersistError::Corrupt(format!("ingest record: {e}"))
                })
            })
            .transpose()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use jig_core::Author;
    use jig_core::contract::ManifestRef;
    use semver::Version;
    use serde_json::json;

    pub(crate) struct Parties {
        pub owner: SigningKey,
        pub follower: SigningKey,
        pub channel_id: Cid,
    }

    pub(crate) fn did(key: &SigningKey) -> String {
        jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    pub(crate) fn parties() -> Parties {
        Parties {
            owner: SigningKey::from_bytes(&[1; 32]),
            follower: SigningKey::from_bytes(&[2; 32]),
            channel_id: jig_core::canonical_cid::of(b"channel-create"),
        }
    }

    impl Parties {
        pub(crate) fn offer(&self) -> ContractOffer {
            let manifest = ManifestRef {
                cid: jig_core::canonical_cid::of(b"server-manifest"),
                seq: 1,
            };
            ContractOffer::sign(
                &self.owner,
                &did(&self.follower),
                self.channel_id,
                Grant::Write,
                b"creation".to_vec(),
                b"head".to_vec(),
                manifest,
                vec![],
            )
        }

        pub(crate) fn accept(&self, offer: &ContractOffer) -> ContractAccept {
            let manifest = ManifestRef {
                cid: jig_core::canonical_cid::of(b"follower-manifest"),
                seq: 3,
            };
            ContractAccept::sign(&self.follower, offer, manifest, vec![], vec![])
        }
    }

    pub(crate) fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    pub(crate) fn block(
        kind: BlockKind,
        author: &str,
        metadata: serde_json::Value,
    ) -> BlockManifest {
        let mut builder = BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: author.into(),
                public_key: None,
                roles: vec![],
            });
        if let serde_json::Value::Object(map) = metadata {
            for (k, v) in map {
                builder = builder.metadata_entry(&k, v);
            }
        }
        builder.build().unwrap().with_kind(kind)
    }

    /// A `contract-accept` record as the sequencer writes it.
    pub(crate) fn accept_record(p: &Parties) -> BlockManifest {
        let offer = p.offer();
        let accept = p.accept(&offer);
        block(
            BlockKind::ContractAccept,
            &did(&p.owner),
            json!({
                "to": did(&p.follower),
                "offer": b64(&offer.envelope),
                "accept": b64(&accept.envelope),
            }),
        )
    }

    fn check(p: &Parties, kind: BlockKind, m: &BlockManifest) -> Result<(), ContractBlockError> {
        check_record(kind, m, &p.channel_id, &did(&p.owner))
    }

    #[test]
    fn a_share_names_a_canonical_server_and_a_grant() {
        let to = did(&parties().follower);
        let share = |meta| {
            share_request(
                BlockKind::ChannelShare,
                &block(BlockKind::ChannelShare, "x", meta),
            )
        };
        assert_eq!(
            share(json!({"to": to, "grant": "member"})),
            Ok(ShareRequest {
                to: to.clone(),
                grant: Some(Grant::Member)
            })
        );
        assert_eq!(
            share(json!({"grant": "read"})),
            Err(ContractBlockError::Missing(TO_KEY))
        );
        assert_eq!(
            share(json!({"to": to})),
            Err(ContractBlockError::Missing(GRANT_KEY))
        );
        assert!(matches!(
            share(json!({"to": to, "grant": "admin"})),
            Err(ContractBlockError::Contract(ContractError::UnknownGrant(_)))
        ));
        // Another spelling of the same key, and something that is no DID.
        let body = to.strip_prefix("did:jig:z").unwrap();
        for bad in [
            format!("did:jig:z{}", body.to_uppercase()),
            "did:jig:zNope".into(),
        ] {
            assert_eq!(
                share(json!({"to": bad, "grant": "read"})),
                Err(ContractBlockError::BadServer(bad.clone()))
            );
        }
        // An unshare needs no grant.
        let unshare = block(BlockKind::ChannelUnshare, "x", json!({"to": to}));
        assert_eq!(
            share_request(BlockKind::ChannelUnshare, &unshare),
            Ok(ShareRequest { to, grant: None })
        );
    }

    #[test]
    fn an_accept_record_carries_the_owners_offer_and_its_answer() {
        let p = parties();
        assert_eq!(
            check(&p, BlockKind::ContractAccept, &accept_record(&p)),
            Ok(())
        );

        // An offer for another channel.
        let elsewhere = Parties {
            channel_id: jig_core::canonical_cid::of(b"another channel"),
            ..parties()
        };
        assert_eq!(
            check(&p, BlockKind::ContractAccept, &accept_record(&elsewhere)),
            Err(ContractBlockError::Mismatch(
                "the message is for another channel"
            ))
        );

        // An offer someone other than the sequencer signed.
        let impostor = Parties {
            owner: SigningKey::from_bytes(&[9; 32]),
            ..parties()
        };
        assert_eq!(
            check(&p, BlockKind::ContractAccept, &accept_record(&impostor)),
            Err(ContractBlockError::Mismatch(
                "the offer is not signed by the channel's sequencer"
            ))
        );

        // An accept of a different offer.
        let offer = p.offer();
        let other = ContractOffer::sign(
            &p.owner,
            &did(&p.follower),
            p.channel_id,
            Grant::Read,
            vec![],
            vec![],
            ManifestRef {
                cid: p.channel_id,
                seq: 0,
            },
            vec![],
        );
        let m = block(
            BlockKind::ContractAccept,
            &did(&p.owner),
            json!({
                "to": did(&p.follower),
                "offer": b64(&offer.envelope),
                "accept": b64(&p.accept(&other).envelope),
            }),
        );
        assert!(matches!(
            check(&p, BlockKind::ContractAccept, &m),
            Err(ContractBlockError::Contract(ContractError::NotAnAnswer(_)))
        ));

        // `to` that is not the server the offer was made to.
        let mut m = accept_record(&p);
        m.metadata.insert("to".into(), json!(did(&p.owner)));
        assert_eq!(
            check(&p, BlockKind::ContractAccept, &m),
            Err(ContractBlockError::Mismatch(
                "the offer is to another server"
            ))
        );

        // A tampered envelope, and one that is not base64.
        let mut m = accept_record(&p);
        let mut bytes = envelope(&m, ACCEPT_KEY).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        m.metadata.insert("accept".into(), json!(b64(&bytes)));
        assert!(matches!(
            check(&p, BlockKind::ContractAccept, &m),
            Err(ContractBlockError::Contract(_))
        ));
        m.metadata.insert("accept".into(), json!("not base64!"));
        assert_eq!(
            check(&p, BlockKind::ContractAccept, &m),
            Err(ContractBlockError::NotBase64(ACCEPT_KEY))
        );
    }

    #[test]
    fn a_refuse_record_carries_the_targets_refusal_or_the_owners_own() {
        let p = parties();
        let offer = p.offer();
        let refuse = ContractRefuse::sign(&p.follower, &offer, RefuseCode::UnsupportedSuite);
        let record = |code: &str| {
            block(
                BlockKind::ContractRefuse,
                &did(&p.owner),
                json!({
                    "to": did(&p.follower),
                    "code": code,
                    "offer": b64(&offer.envelope),
                    "refuse": b64(&refuse.envelope),
                }),
            )
        };
        assert_eq!(
            check(&p, BlockKind::ContractRefuse, &record("UNSUPPORTED_SUITE")),
            Ok(())
        );
        assert_eq!(
            check(&p, BlockKind::ContractRefuse, &record("NOT_A_PEER")),
            Err(ContractBlockError::Mismatch(
                "`code` is not the refusal's code"
            ))
        );
        assert!(matches!(
            check(&p, BlockKind::ContractRefuse, &record("NOPE")),
            Err(ContractBlockError::Contract(ContractError::UnknownCode(_)))
        ));

        // The owning server's own refusal: no offer was sent, so there is no
        // answer to carry.
        let own = block(
            BlockKind::ContractRefuse,
            &did(&p.owner),
            json!({"to": did(&p.follower), "code": "NOT_A_PEER"}),
        );
        assert_eq!(check(&p, BlockKind::ContractRefuse, &own), Ok(()));
        let conflict = block(
            BlockKind::ContractRefuse,
            &did(&p.owner),
            json!({"to": did(&p.follower), "code": "SUFFIX_CONFLICT"}),
        );
        assert_eq!(check(&p, BlockKind::ContractRefuse, &conflict), Ok(()));
        // The target's reasons need the target's message, and an owner's
        // refusal carries no offer.
        let mismatch = Err(ContractBlockError::Mismatch(
            "a refusal without the target's message is the owner's own: NOT_A_PEER or SUFFIX_CONFLICT, with no offer",
        ));
        for code in ["POLICY_REFUSED", "UNSUPPORTED_SUITE", "UNSUPPORTED_VERSION"] {
            let unsigned = block(
                BlockKind::ContractRefuse,
                &did(&p.owner),
                json!({"to": did(&p.follower), "code": code}),
            );
            assert_eq!(
                check(&p, BlockKind::ContractRefuse, &unsigned),
                mismatch,
                "{code}"
            );
        }
        let with_offer = block(
            BlockKind::ContractRefuse,
            &did(&p.owner),
            json!({"to": did(&p.follower), "code": "NOT_A_PEER", "offer": b64(&offer.envelope)}),
        );
        assert_eq!(check(&p, BlockKind::ContractRefuse, &with_offer), mismatch);
    }

    #[test]
    fn an_end_record_is_signed_by_one_side_of_the_share() {
        let p = parties();
        let offer_id = p.offer().offer_id;
        let record = |key: &SigningKey| {
            let end = ContractEnd::sign(key, p.channel_id, offer_id);
            block(
                BlockKind::ContractEnd,
                &did(&p.owner),
                json!({"to": did(&p.follower), "end": b64(&end.envelope)}),
            )
        };
        assert_eq!(check(&p, BlockKind::ContractEnd, &record(&p.owner)), Ok(()));
        assert_eq!(
            check(&p, BlockKind::ContractEnd, &record(&p.follower)),
            Ok(())
        );
        assert_eq!(
            check(
                &p,
                BlockKind::ContractEnd,
                &record(&SigningKey::from_bytes(&[9; 32]))
            ),
            Err(ContractBlockError::Mismatch(
                "the end is signed by neither side of the share"
            ))
        );
    }

    fn stored(p: &Parties, offer: &ContractOffer, side: Side, state: OfferState) -> StoredOffer {
        StoredOffer {
            offer_id: offer.offer_id,
            channel_id: p.channel_id.to_string(),
            side,
            peer_did: did(&p.follower),
            grant: offer.grant,
            state,
            offer: offer.envelope.clone(),
            answer: None,
            share_cid: None,
        }
    }

    #[test]
    fn an_offer_is_kept_once_and_moves_once() {
        let store = SqliteStore::open_in_memory().unwrap();
        let p = parties();
        let first = p.offer();
        let row = stored(&p, &first, Side::Owner, OfferState::Offered);
        assert!(store.put_contract_offer(&row).unwrap());
        assert!(
            !store.put_contract_offer(&row).unwrap(),
            "the same offer twice is one offer"
        );
        assert_eq!(
            store.get_contract_offer(&first.offer_id).unwrap(),
            Some(row)
        );

        let accept = p.accept(&first);
        let mv = |from, to, answer| {
            store
                .move_contract_offer(&first.offer_id, from, to, answer)
                .unwrap()
        };
        assert!(mv(
            OfferState::Offered,
            OfferState::Accepted,
            Some(accept.envelope.as_slice())
        ));
        assert!(
            !mv(OfferState::Offered, OfferState::Refused, None),
            "answered once"
        );
        let kept = store.get_contract_offer(&first.offer_id).unwrap().unwrap();
        assert_eq!(
            (kept.state, kept.answer),
            (OfferState::Accepted, Some(accept.envelope))
        );

        // A second offer for the same channel and follower, once accepted,
        // replaces the first. The follower's own rows are another side.
        let second = ContractOffer::sign(
            &p.owner,
            &did(&p.follower),
            p.channel_id,
            Grant::Member,
            vec![],
            vec![],
            ManifestRef {
                cid: p.channel_id,
                seq: 2,
            },
            vec![],
        );
        store
            .put_contract_offer(&stored(&p, &second, Side::Owner, OfferState::Offered))
            .unwrap();
        let theirs = ContractOffer::sign(
            &p.owner,
            &did(&p.follower),
            p.channel_id,
            Grant::Read,
            vec![],
            vec![],
            ManifestRef {
                cid: p.channel_id,
                seq: 3,
            },
            vec![],
        );
        store
            .put_contract_offer(&stored(&p, &theirs, Side::Follower, OfferState::Accepted))
            .unwrap();
        assert!(
            store
                .move_contract_offer(
                    &second.offer_id,
                    OfferState::Offered,
                    OfferState::Accepted,
                    None
                )
                .unwrap()
        );
        let state = |id| store.get_contract_offer(id).unwrap().unwrap().state;
        assert_eq!(state(&first.offer_id), OfferState::Superseded);
        assert_eq!(state(&second.offer_id), OfferState::Accepted);
        assert_eq!(state(&theirs.offer_id), OfferState::Accepted);
        let live = store
            .contract_offers_for(
                &p.channel_id.to_string(),
                &did(&p.follower),
                Side::Owner,
                OfferState::Accepted,
            )
            .unwrap();
        assert_eq!(
            live.iter().map(|o| o.grant).collect::<Vec<_>>(),
            [Grant::Member]
        );
        assert_eq!(
            store
                .contract_offers_in(Side::Follower, OfferState::Accepted)
                .unwrap()
                .len(),
            1
        );
    }

    /// Setting a relayed copy aside deletes nothing: its row, blocks,
    /// records, memberships, chain evidence and owner-side offers all move
    /// under the copy's id, and the offers are ended.
    #[test]
    fn a_quarantined_copy_keeps_everything() {
        use crate::persist::{StoredBlock, StoredChannel, StoredMembership};
        let store = SqliteStore::open_in_memory().unwrap();
        let local = "did:jig:zlocal";
        store.adopt_local_sequencer(local).unwrap();
        let channel = crate::ingest_record::label_cid("a relayed channel");
        let block = |cid: &str, federated_from: Option<&str>| StoredBlock {
            cid: cid.to_string(),
            channel_id: Some(channel.clone()),
            block_kind: "text-render".to_string(),
            sender_did: "did:jig:zuser".to_string(),
            sender_sig: vec![1],
            bundle_bytes: vec![2],
            is_synthetic: false,
            hlc_wall_ms: 0,
            hlc_logical: 0,
            hlc_origin: String::new(),
            posted_at: 0,
            origin_server: String::new(),
            federated_from: federated_from.map(str::to_string),
        };
        store
            .insert_block(&block(&channel, Some("ws://peer")))
            .unwrap();
        let own = crate::ingest_record::label_cid("a post only here");
        store.insert_block(&block(&own, None)).unwrap();
        store
            .upsert_channel(&StoredChannel {
                id: channel.clone(),
                slug: "#k".to_string(),
                visibility: "open".to_string(),
                created_at: 0,
                owner_did: "did:jig:zuser".to_string(),
                suite: "none".to_string(),
                sequencer_did: local.to_string(),
                co_owners: Vec::new(),
                tiering: crate::persist::ChannelTiering::current("open", "none"),
            })
            .unwrap();
        store
            .upsert_membership(&StoredMembership {
                channel_id: channel.clone(),
                member_did: "did:jig:zuser".to_string(),
                role: "owner".to_string(),
                joined_at: 0,
                source_block_cid: channel.clone(),
            })
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO ingest_records (block_cid, channel_id, seq, record) VALUES (?1, ?2, 0, x'01')",
                params![channel, channel],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chain_evidence (channel_id, seq, held, offered, found_at)
                 VALUES (?1, 1, x'02', x'03', 0)",
                [&channel],
            )
            .unwrap();
        }
        store
            .put_contract_offer(&StoredOffer {
                offer_id: rand::random(),
                channel_id: channel.clone(),
                side: Side::Owner,
                peer_did: "did:jig:zelsewhere".to_string(),
                grant: Grant::Read,
                state: OfferState::Held,
                offer: vec![],
                answer: None,
                share_cid: None,
            })
            .unwrap();

        let copy = store.quarantine_relayed_copy(&channel).unwrap().unwrap();
        assert_eq!(copy.own_blocks, 1);
        assert!(store.get_channel_by_id(&channel).unwrap().is_none());
        let row = store.get_channel_by_id(&copy.copy_id).unwrap().unwrap();
        assert_eq!(row.slug, copy.slug);
        assert_eq!(
            jig_core::slug::classify_slug(&row.slug),
            Ok(jig_core::slug::SlugClass::Server)
        );
        for cid in [&channel, &own] {
            let kept = store.get_block(cid).unwrap().unwrap();
            assert_eq!(kept.channel_id.as_deref(), Some(copy.copy_id.as_str()));
        }
        assert_eq!(store.quarantined_records(&copy.copy_id).unwrap().len(), 1);
        assert!(store.latest_ingest_record(&channel).unwrap().is_none());
        assert_eq!(store.chain_evidence(&copy.copy_id).unwrap().len(), 1);
        assert!(
            store
                .is_member_by_id(&copy.copy_id, "did:jig:zuser")
                .unwrap()
        );
        assert_eq!(
            store
                .contract_offers_for(
                    &copy.copy_id,
                    "did:jig:zelsewhere",
                    Side::Owner,
                    OfferState::Ended
                )
                .unwrap()
                .len(),
            1
        );
        // Once only: it is no longer a relayed copy.
        assert!(store.quarantine_relayed_copy(&channel).unwrap().is_none());
    }
}
