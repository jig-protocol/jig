//! Head gossip, the store's side (JEP-0002 rule 10; design D11 item 6).
//!
//! A client, or another server, hands this server the latest `ingest`
//! record it verified for a channel: a head. This server holds the channel's
//! chain, as its sequencer or as a follower, so it can compare:
//!
//! - the record it holds at that `seq`, byte for byte: the same head again,
//!   which costs no signature check;
//! - another record at that `seq`, signed by the channel's sequencer: two
//!   records one key signed for one `seq`, a fork. A follower keeps them as
//!   the channel's chain evidence, which stops it (JEP-0005 rule 14);
//! - a record past its head: this server is behind, or is being withheld
//!   from. The highest such head is kept, for the server to fetch up to it
//!   and to forward.
//!
//! What the network side does around this (rate limits, who is told) is
//! `jig-server`'s. The order here is the cheap checks first: whether the
//! channel is held, then the bytes against the record held at that `seq`
//! and the head kept, and only then the signature.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rusqlite::{OptionalExtension, params};

use crate::ingest_record::IngestRecord;
use crate::persist::SqliteStore;

pub(crate) fn migrate(conn: &rusqlite::Connection) -> crate::persist::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS channel_heads (
            channel_id  TEXT PRIMARY KEY,
            seq         INTEGER NOT NULL,
            record      BLOB NOT NULL,
            received_at INTEGER NOT NULL
        );
        "#,
    )?;
    Ok(())
}

/// The refusal of a head past its sender's allowance. It answers no request
/// the client made, so the client handles it apart from the errors that
/// answer a subscribe or a submit, and it is no other refusal's code.
pub const HEADS_RATE_LIMITED: &str = "HEADS_RATE_LIMITED";

/// The answer to a head on a connection whose welcome did not grant `heads`.
/// Like [`HEADS_RATE_LIMITED`], it answers no request.
pub const HEADS_NOT_NEGOTIATED: &str = "HEADS_NOT_NEGOTIATED";

/// What a head showed against this server's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadCheck {
    /// The channel is not one this server holds: nothing to compare, and
    /// nothing said back, so a head is no way to ask which channels it holds.
    NotHeld,
    /// Not a record of the channel, or too large to be one.
    Malformed(String),
    /// The record this server holds at that `seq`, or the head it keeps:
    /// nothing new. No signature was checked.
    Duplicate,
    /// A record that does not verify as the channel's sequencer's.
    NotSequencer,
    /// Past this server's head. `advanced`: it is the highest head this
    /// server has been handed for the channel, and is now kept.
    Ahead { seq: u64, advanced: bool },
    /// At or behind this server's head, where it holds no record (a gap):
    /// nothing to compare it with.
    Unchecked,
    /// Another record than this server's at that `seq`, signed by the
    /// sequencer. `held` is this server's record there, in its stored form.
    /// `first`: this is the first fork kept for the channel.
    Fork {
        seq: u64,
        held: Vec<u8>,
        first: bool,
    },
}

impl HeadCheck {
    /// Whether the check verified a signature: what a flood of heads costs.
    pub fn verified(&self) -> bool {
        matches!(
            self,
            Self::NotSequencer | Self::Ahead { .. } | Self::Unchecked | Self::Fork { .. }
        )
    }
}

impl SqliteStore {
    /// Compare `envelope`, a head (a record's COSE_Sign1 envelope) handed in
    /// for `channel_id`, with this server's chain of it, and keep what it
    /// shows ([`HeadCheck`]). The caller has rate-limited whoever handed it
    /// in, before this.
    pub fn check_head(
        &self,
        channel_id: &str,
        envelope: &[u8],
    ) -> crate::persist::Result<HeadCheck> {
        let Some(channel) = self.get_channel_by_id(channel_id)? else {
            return Ok(HeadCheck::NotHeld);
        };
        let head = match IngestRecord::from_cose(envelope) {
            Ok(head) if head.channel_id == channel.id => head,
            Ok(head) => {
                return Ok(HeadCheck::Malformed(format!(
                    "a record of {}, not of {channel_id}",
                    head.channel_id
                )));
            }
            Err(e) => return Ok(HeadCheck::Malformed(e.to_string())),
        };
        let sent = STANDARD.encode(envelope);
        // Cheap first: the bytes against what is held, no signature checked.
        let held = self
            .list_ingest_records_by_id(channel_id, head.seq, 1)?
            .into_iter()
            .find(|r| r.seq == head.seq);
        // The kept head again is nothing new only while no other record is
        // held at its `seq`: once the chain lands one there, it is compared.
        let duplicate = match &held {
            Some(h) => h.cose == sent,
            None => self.kept_head(channel_id)? == Some(sent),
        };
        if duplicate {
            return Ok(HeadCheck::Duplicate);
        }
        let sequencer = if channel.sequencer_did.is_empty() {
            self.local_sequencer().to_string()
        } else {
            channel.sequencer_did.clone()
        };
        if head.verify(&sequencer).is_err() {
            return Ok(HeadCheck::NotSequencer);
        }
        if let Some(held) = held {
            let held = held.encode();
            let first = self.keep_head_fork(&channel, head.seq, &held, &head.encode())?;
            return Ok(HeadCheck::Fork {
                seq: head.seq,
                held,
                first,
            });
        }
        let ours = self.latest_ingest_record(channel_id)?;
        if ours.is_some_and(|h| h.seq >= head.seq) {
            return Ok(HeadCheck::Unchecked);
        }
        if channel.sequencer_did.is_empty()
            || crate::handshake::same_did(&channel.sequencer_did, self.local_sequencer())
        {
            // Past this server's own chain, by its own key: a record it never
            // signed as its sequencer, or signed and lost.
            tracing::error!(
                channel_id,
                seq = head.seq,
                "a head signed by this server's key is past its own chain"
            );
        }
        let advanced = self.keep_head(channel_id, &head, envelope)?;
        Ok(HeadCheck::Ahead {
            seq: head.seq,
            advanced,
        })
    }

    /// The highest head this server has been handed for `channel_id` past
    /// its own chain, as base64 of its envelope.
    pub fn kept_head(&self, channel_id: &str) -> crate::persist::Result<Option<String>> {
        let conn = self.conn.lock().expect("poisoned");
        let bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT record FROM channel_heads WHERE channel_id = ?1",
                [channel_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(bytes.map(|b| STANDARD.encode(b)))
    }

    /// The highest head kept for `channel_id`, as its record and `seq`.
    pub fn kept_head_record(
        &self,
        channel_id: &str,
    ) -> crate::persist::Result<Option<IngestRecord>> {
        let conn = self.conn.lock().expect("poisoned");
        let bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT record FROM channel_heads WHERE channel_id = ?1",
                [channel_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(bytes.and_then(|b| IngestRecord::from_cose(&b).ok()))
    }

    /// Keep `head` for `channel_id` if it is past the one kept. Whether it
    /// was.
    fn keep_head(
        &self,
        channel_id: &str,
        head: &IngestRecord,
        envelope: &[u8],
    ) -> crate::persist::Result<bool> {
        let conn = self.conn.lock().expect("poisoned");
        let changed = conn.execute(
            "INSERT INTO channel_heads (channel_id, seq, record, received_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(channel_id) DO UPDATE SET
                seq = excluded.seq, record = excluded.record, received_at = excluded.received_at
             WHERE excluded.seq > channel_heads.seq",
            params![
                channel_id,
                head.seq as i64,
                envelope,
                chrono::Utc::now().timestamp()
            ],
        )?;
        Ok(changed > 0)
    }

    /// Keep a fork a head showed. On a channel this server follows, it is the
    /// channel's chain evidence, which stops it, as a fork in the owner's
    /// stream does (JEP-0005 rule 14). On one it sequences, its own key
    /// signed both records: that is logged, and nothing is stopped, since
    /// stopping its own channel would hand whoever holds the key a way to
    /// silence it. Whether this is the first fork kept for the channel.
    fn keep_head_fork(
        &self,
        channel: &crate::persist::StoredChannel,
        seq: u64,
        held: &[u8],
        offered: &[u8],
    ) -> crate::persist::Result<bool> {
        let ours = channel.sequencer_did.is_empty()
            || crate::handshake::same_did(&channel.sequencer_did, self.local_sequencer());
        if ours {
            tracing::error!(
                channel_id = %channel.id,
                seq,
                "a head signed by this server's key is not this server's record at that seq: \
                 the key signed two records for one seq"
            );
            return Ok(false);
        }
        let conn = self.conn.lock().expect("poisoned");
        let kept = conn.execute(
            "INSERT OR IGNORE INTO chain_evidence (channel_id, seq, held, offered, found_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                channel.id,
                seq as i64,
                held,
                offered,
                chrono::Utc::now().timestamp()
            ],
        )?;
        Ok(kept > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest_record::{GENESIS_PREV, RecordSigner, label_cid};
    use crate::persist::{ChannelTiering, StoredChannel};
    use jig_core::crypto::ed25519::generate_signing_key;

    fn did(key: &ed25519_dalek::SigningKey) -> String {
        jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    /// A store following `channel`, whose owner signs with `owner`, holding
    /// its records 0 and 1.
    fn follower(owner: &ed25519_dalek::SigningKey) -> (SqliteStore, Vec<IngestRecord>) {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .adopt_local_sequencer(&did(&generate_signing_key()))
            .unwrap();
        let channel = label_cid("Create");
        store
            .upsert_channel(&StoredChannel {
                id: channel.clone(),
                slug: "#c".into(),
                visibility: "open".into(),
                created_at: 0,
                owner_did: did(owner),
                suite: "none".into(),
                sequencer_did: did(owner),
                co_owners: Vec::new(),
                tiering: ChannelTiering::current("open", "none"),
            })
            .unwrap();
        let sign = |seq: u64, block: &str, prev| {
            RecordSigner {
                channel_id: channel.clone(),
                key: owner,
                ingest_wall_ms: 10 + seq,
                ingest_logical: 0,
            }
            .sign(seq, &label_cid(block), prev)
            .unwrap()
        };
        let r0 = sign(0, "Create", GENESIS_PREV);
        let r1 = sign(1, "b1", r0.hash());
        {
            let conn = store.conn.lock().unwrap();
            // The records alone: this is about the chain, not the blocks.
            conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
            for r in [&r0, &r1] {
                conn.execute(
                    "INSERT INTO carried_records (block_cid, channel_id, seq, record)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![r.block_cid, r.channel_id, r.seq as i64, r.encode()],
                )
                .unwrap();
            }
        }
        (store, vec![r0, r1])
    }

    fn sign_at(
        owner: &ed25519_dalek::SigningKey,
        seq: u64,
        block: &str,
        prev: [u8; 32],
    ) -> IngestRecord {
        RecordSigner {
            channel_id: label_cid("Create"),
            key: owner,
            ingest_wall_ms: 50 + seq,
            ingest_logical: 0,
        }
        .sign(seq, &label_cid(block), prev)
        .unwrap()
    }

    #[test]
    fn a_head_this_server_holds_costs_no_signature() {
        let owner = generate_signing_key();
        let (store, held) = follower(&owner);
        let check = store
            .check_head(&label_cid("Create"), &held[1].cose_bytes().unwrap())
            .unwrap();
        assert_eq!(check, HeadCheck::Duplicate);
        assert!(!check.verified());
    }

    #[test]
    fn a_head_for_a_channel_this_server_does_not_hold_says_nothing() {
        let owner = generate_signing_key();
        let (store, held) = follower(&owner);
        let check = store
            .check_head(&label_cid("Elsewhere"), &held[1].cose_bytes().unwrap())
            .unwrap();
        assert_eq!(check, HeadCheck::NotHeld);
        assert!(!check.verified());
    }

    #[test]
    fn a_head_past_the_chain_is_kept_once() {
        let owner = generate_signing_key();
        let (store, held) = follower(&owner);
        let ahead = sign_at(&owner, 3, "b3", [7; 32]);
        let envelope = ahead.cose_bytes().unwrap();
        let channel = label_cid("Create");
        assert_eq!(
            store.check_head(&channel, &envelope).unwrap(),
            HeadCheck::Ahead {
                seq: 3,
                advanced: true
            }
        );
        assert_eq!(store.kept_head_record(&channel).unwrap(), Some(ahead));
        // The same again is a duplicate, unverified; a lower one is kept no
        // longer than the higher.
        assert_eq!(
            store.check_head(&channel, &envelope).unwrap(),
            HeadCheck::Duplicate
        );
        let lower = sign_at(&owner, 2, "b2", held[1].hash());
        assert_eq!(
            store
                .check_head(&channel, &lower.cose_bytes().unwrap())
                .unwrap(),
            HeadCheck::Ahead {
                seq: 2,
                advanced: false
            }
        );
    }

    #[test]
    fn the_kept_head_again_is_a_fork_once_another_record_is_held_there() {
        let owner = generate_signing_key();
        let (store, held) = follower(&owner);
        let channel = label_cid("Create");
        let kept = sign_at(&owner, 2, "b2", held[1].hash());
        let envelope = kept.cose_bytes().unwrap();
        assert!(matches!(
            store.check_head(&channel, &envelope).unwrap(),
            HeadCheck::Ahead { advanced: true, .. }
        ));
        // The chain then holds another record at that seq.
        let landed = sign_at(&owner, 2, "b2Other", held[1].hash());
        {
            let conn = store.conn.lock().unwrap();
            conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
            conn.execute(
                "INSERT INTO carried_records (block_cid, channel_id, seq, record)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    landed.block_cid,
                    landed.channel_id,
                    landed.seq as i64,
                    landed.encode()
                ],
            )
            .unwrap();
        }
        let check = store.check_head(&channel, &envelope).unwrap();
        assert!(
            matches!(
                check,
                HeadCheck::Fork {
                    seq: 2,
                    first: true,
                    ..
                }
            ),
            "{check:?}"
        );
        assert_eq!(store.chain_evidence(&channel).unwrap().len(), 1);
    }

    #[test]
    fn another_record_at_a_held_seq_is_a_fork_that_stops_the_channel() {
        let owner = generate_signing_key();
        let (store, held) = follower(&owner);
        let channel = label_cid("Create");
        let other = sign_at(&owner, 1, "bOther", held[0].hash());
        let check = store
            .check_head(&channel, &other.cose_bytes().unwrap())
            .unwrap();
        assert!(
            matches!(
                check,
                HeadCheck::Fork {
                    seq: 1,
                    first: true,
                    ..
                }
            ),
            "{check:?}"
        );
        let evidence = store.chain_evidence(&channel).unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(IngestRecord::decode(&evidence[0].offered).unwrap(), other);
        assert_eq!(IngestRecord::decode(&evidence[0].held).unwrap(), held[1]);
        // Kept once.
        let again = sign_at(&owner, 0, "bOther0", GENESIS_PREV);
        assert!(matches!(
            store
                .check_head(&channel, &again.cose_bytes().unwrap())
                .unwrap(),
            HeadCheck::Fork { first: false, .. }
        ));
    }

    #[test]
    fn a_head_from_another_key_or_channel_proves_nothing() {
        let owner = generate_signing_key();
        let (store, _) = follower(&owner);
        let channel = label_cid("Create");
        let forged = sign_at(&generate_signing_key(), 1, "bOther", [0; 32]);
        assert_eq!(
            store
                .check_head(&channel, &forged.cose_bytes().unwrap())
                .unwrap(),
            HeadCheck::NotSequencer
        );
        assert!(store.chain_evidence(&channel).unwrap().is_empty());
        assert!(matches!(
            store.check_head(&channel, b"not a record").unwrap(),
            HeadCheck::Malformed(_)
        ));
    }
}
