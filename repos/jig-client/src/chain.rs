//! Checking a channel's `ingest` chain (JEP-0002 rule 9; design D11 item 5).
//!
//! Every block of a channel carries a record signed by the channel's
//! sequencer: its `seq`, the sequencer's clock, and the hash of the record
//! before it. A client that keeps the last record it verified can tell, from
//! the next one it sees:
//!
//! - that it is the next entry (`seq` one more, `prev` naming the last);
//! - that entries were skipped (a gap), which it fills from the records
//!   endpoint before it trusts anything after;
//! - that the server rewrote history (a different record at a `seq` this
//!   client already holds, a `prev` that names something else, a clock that
//!   runs backwards, a record for another block or channel, or one signed by
//!   another key).
//!
//! The last kind is a contradiction: the server signed two incompatible
//! things. A gap is not, on its own: the server may simply not have sent the
//! records in between yet.

/// For tests and tools that need a chain to check against.
pub use jig_pipeline::ingest_record::{GENESIS_PREV, RECORD_FORMAT, RecordSigner, label_cid};
pub use jig_pipeline::ingest_record::{IngestRecord, RecordError};
use serde::{Deserialize, Serialize};

/// The last record this client verified for a channel, as kept between
/// sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHead {
    /// The record format the head was verified in ([`IngestRecord::format`]).
    /// Empty for a pin written before formats were named.
    #[serde(default)]
    pub format: String,
    pub seq: u64,
    /// Hex hash of the record ([`IngestRecord::hash`]).
    pub hash: String,
    pub ingest_wall_ms: u64,
    pub ingest_logical: u32,
    /// The record itself, exactly as signed, so that a later record which
    /// contradicts it can be shown with both halves ([`ChainProof`]). `None`
    /// in a pin written before heads were kept whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<IngestRecord>,
}

impl ChainHead {
    /// Whether this head is in the record format this build signs and
    /// verifies. A head in another format cannot be compared with records
    /// in this one: its hash covers different bytes.
    pub fn is_current(&self) -> bool {
        self.format == RECORD_FORMAT
    }

    pub fn of(record: &IngestRecord) -> Self {
        Self {
            format: record.format.clone(),
            seq: record.seq,
            hash: hex::encode(record.hash()),
            ingest_wall_ms: record.ingest_wall_ms,
            ingest_logical: record.ingest_logical,
            record: Some(record.clone()),
        }
    }
}

/// What a record that verified means for the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The next entry. The head moved to it.
    Next,
    /// An entry at or before the head, which this client cannot compare
    /// beyond its signature: a re-delivery or a page of history. The head did
    /// not move.
    Behind,
    /// Entries `from..to` are missing. The head did not move; fetch them and
    /// [`ChannelChain::accept`] each, in order.
    Gap { from: u64, to: u64 },
}

/// Why a record shows the server contradicting itself.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainBreak {
    #[error(transparent)]
    Unsigned(#[from] RecordError),
    #[error("the record names channel {got}, not {expected}")]
    OtherChannel { expected: String, got: String },
    #[error("the record is for block {record}, delivered with block {delivered}")]
    OtherBlock { record: String, delivered: String },
    #[error("record {seq} does not follow record {head}: its prev names another history")]
    Forked { head: u64, seq: u64 },
    #[error("record {seq} is not the record {seq} this device already holds")]
    Rewritten { seq: u64 },
    #[error("record {seq}'s sequencer clock runs backwards from record {head}'s")]
    ClockBackwards { head: u64, seq: u64 },
    #[error("the chain does not start at a channel-create: record 0 names a previous record")]
    BadGenesis,
}

impl ChainBreak {
    /// A stable name for the break, as evidence bundles file it.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsigned(_) => "chain-unsigned",
            Self::OtherChannel { .. } => "chain-other-channel",
            Self::OtherBlock { .. } => "chain-other-block",
            Self::Forked { .. } => "chain-forked",
            Self::Rewritten { .. } => "chain-rewritten",
            Self::ClockBackwards { .. } => "chain-clock-backwards",
            Self::BadGenesis => "chain-bad-genesis",
        }
    }

    /// Whether the break is the sequencer signing two things that cannot both
    /// hold, provable from its records alone: two records at one `seq`, a
    /// `prev` that names another history, a clock that runs backwards, a
    /// record 0 that names a previous one. A record that does not verify, or
    /// one delivered with another block or on another channel, proves nothing
    /// against the sequencer: anyone can sign with their own key, and which
    /// record came with which block is not signed.
    pub fn is_signed_proof(&self) -> bool {
        matches!(
            self,
            Self::Forked { .. }
                | Self::Rewritten { .. }
                | Self::ClockBackwards { .. }
                | Self::BadGenesis
        )
    }
}

/// A chain break as anyone can check it later: the records that contradict
/// each other, exactly as the sequencer signed them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainProof {
    pub channel_id: String,
    pub sequencer: String,
    /// The record the chain stood at; `None` for a bad record 0.
    pub head: Option<IngestRecord>,
    pub record: IngestRecord,
}

impl ChainProof {
    /// Re-run the check that broke: both records must verify as the
    /// sequencer's, on the channel, and break in a way
    /// [`ChainBreak::is_signed_proof`] counts.
    pub fn verify(&self) -> Result<ChainBreak, String> {
        let mut chain = ChannelChain::new(&self.channel_id, &self.sequencer, None);
        if let Some(head) = &self.head {
            head.verify(&self.sequencer)
                .map_err(|e| format!("the head record does not verify: {e}"))?;
            if head.channel_id != self.channel_id {
                return Err("the head record is for another channel".to_string());
            }
            chain.head = Some(ChainHead::of(head));
        }
        match chain.accept(&self.record, None) {
            Err(e) if e.is_signed_proof() => Ok(e),
            Err(e) => Err(format!("the records break, but prove nothing: {e}")),
            Ok(_) => Err("the records do not contradict each other".to_string()),
        }
    }
}

/// One channel's chain as this client has verified it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelChain {
    channel_id: String,
    sequencer: String,
    head: Option<ChainHead>,
}

impl ChannelChain {
    /// A chain for `channel_id`, signed by `sequencer`, verified up to
    /// `head` (`None` when this client has seen none of it).
    pub fn new(channel_id: &str, sequencer: &str, head: Option<ChainHead>) -> Self {
        Self {
            channel_id: channel_id.to_string(),
            sequencer: sequencer.to_string(),
            head,
        }
    }

    pub fn head(&self) -> Option<&ChainHead> {
        self.head.as_ref()
    }

    /// What shows `broke`, which [`Self::accept`] returned for `record`, to
    /// someone who does not trust this client: `None` when the break proves
    /// nothing against the sequencer, or when the head it broke against was
    /// pinned without its record.
    pub fn proof(&self, record: &IngestRecord, broke: &ChainBreak) -> Option<ChainProof> {
        if !broke.is_signed_proof() {
            return None;
        }
        let head = match broke {
            ChainBreak::BadGenesis => None,
            _ => Some(self.head.as_ref()?.record.clone()?),
        };
        Some(ChainProof {
            channel_id: self.channel_id.clone(),
            sequencer: self.sequencer.clone(),
            head,
            record: record.clone(),
        })
    }

    /// Check `record`, delivered with the block whose CID is `block_cid`
    /// (`None` when it came alone, from the records endpoint).
    pub fn accept(
        &mut self,
        record: &IngestRecord,
        block_cid: Option<&str>,
    ) -> Result<Step, ChainBreak> {
        record.verify(&self.sequencer)?;
        if record.channel_id != self.channel_id {
            return Err(ChainBreak::OtherChannel {
                expected: self.channel_id.clone(),
                got: record.channel_id.clone(),
            });
        }
        if let Some(delivered) = block_cid
            && delivered != record.block_cid
        {
            return Err(ChainBreak::OtherBlock {
                record: record.block_cid.clone(),
                delivered: delivered.to_string(),
            });
        }
        if record.seq == 0 && !record.is_genesis() {
            return Err(ChainBreak::BadGenesis);
        }
        let Some(head) = &self.head else {
            // First contact with this channel's chain. Trust on first use, as
            // with every pin; from here on the server is held to it.
            return if record.seq == 0 {
                self.head = Some(ChainHead::of(record));
                Ok(Step::Next)
            } else {
                Ok(Step::Gap {
                    from: 0,
                    to: record.seq,
                })
            };
        };
        if record.seq == head.seq {
            return if hex::encode(record.hash()) == head.hash {
                Ok(Step::Behind)
            } else {
                Err(ChainBreak::Rewritten { seq: record.seq })
            };
        }
        if record.seq < head.seq {
            return Ok(Step::Behind);
        }
        if record.seq > head.seq + 1 {
            return Ok(Step::Gap {
                from: head.seq + 1,
                to: record.seq,
            });
        }
        if record.prev != head.hash {
            return Err(ChainBreak::Forked {
                head: head.seq,
                seq: record.seq,
            });
        }
        if (record.ingest_wall_ms, record.ingest_logical)
            < (head.ingest_wall_ms, head.ingest_logical)
        {
            return Err(ChainBreak::ClockBackwards {
                head: head.seq,
                seq: record.seq,
            });
        }
        self.head = Some(ChainHead::of(record));
        Ok(Step::Next)
    }

    /// [`Self::accept`], except that a gap moves the head to `record` (which
    /// verified) instead of holding it back. For a live stream, which cannot
    /// stop to fetch what it missed: the caller fills the reported gap later,
    /// and every record after this one is still checked against it.
    pub fn accept_live(
        &mut self,
        record: &IngestRecord,
        block_cid: Option<&str>,
    ) -> Result<Step, ChainBreak> {
        let step = self.accept(record, block_cid)?;
        if matches!(step, Step::Gap { .. }) {
            self.head = Some(ChainHead::of(record));
        }
        Ok(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::crypto::ed25519::generate_signing_key;

    struct Seq {
        key: ed25519_dalek::SigningKey,
        records: Vec<IngestRecord>,
    }

    impl Seq {
        fn new() -> Self {
            Self {
                key: generate_signing_key(),
                records: Vec::new(),
            }
        }

        fn did(&self) -> String {
            jig_core::Did::from_ed25519_pubkey(self.key.verifying_key().as_bytes())
                .to_did_jig_string()
        }

        fn push(&mut self, block: &str, wall: u64) -> IngestRecord {
            let seq = self.records.len() as u64;
            let prev = self.records.last().map_or(GENESIS_PREV, IngestRecord::hash);
            let record = RecordSigner {
                channel_id: label_cid("bafyCreate"),
                key: &self.key,
                ingest_wall_ms: wall,
                ingest_logical: 0,
            }
            .sign(seq, &label_cid(block), prev)
            .unwrap();
            self.records.push(record.clone());
            record
        }
    }

    #[test]
    fn a_chain_read_in_order_moves_its_head() {
        let mut server = Seq::new();
        let mut chain = ChannelChain::new(&label_cid("bafyCreate"), &server.did(), None);
        let first = server.push("bafyCreate", 10);
        assert_eq!(
            chain.accept(&first, Some(label_cid("bafyCreate").as_str())),
            Ok(Step::Next)
        );
        let second = server.push("bafyPost", 20);
        assert_eq!(
            chain.accept(&second, Some(label_cid("bafyPost").as_str())),
            Ok(Step::Next)
        );
        assert_eq!(chain.head().unwrap().seq, 1);
        assert_eq!(
            chain.accept(&first, None),
            Ok(Step::Behind),
            "a page of history"
        );
        assert_eq!(
            chain.accept(&second, None),
            Ok(Step::Behind),
            "a re-delivery"
        );
    }

    #[test]
    fn a_skipped_entry_is_a_gap_to_fill_not_a_contradiction() {
        let mut server = Seq::new();
        let mut chain = ChannelChain::new(&label_cid("bafyCreate"), &server.did(), None);
        let records: Vec<_> = (0..4).map(|i| server.push(&format!("b{i}"), i)).collect();
        chain.accept(&records[0], None).unwrap();
        assert_eq!(
            chain.accept(&records[3], None),
            Ok(Step::Gap { from: 1, to: 3 })
        );
        for r in &records[1..] {
            assert_eq!(chain.accept(r, None), Ok(Step::Next));
        }
        // Joining late: everything before the first record seen is a gap.
        let mut late = ChannelChain::new(&label_cid("bafyCreate"), &server.did(), None);
        assert_eq!(
            late.accept(&records[2], None),
            Ok(Step::Gap { from: 0, to: 2 })
        );
    }

    #[test]
    fn a_live_gap_moves_on_and_keeps_checking() {
        let mut server = Seq::new();
        let records: Vec<_> = (0..4).map(|i| server.push(&format!("b{i}"), i)).collect();
        let mut chain = ChannelChain::new(&label_cid("bafyCreate"), &server.did(), None);
        chain.accept_live(&records[0], None).unwrap();
        assert_eq!(
            chain.accept_live(&records[2], None),
            Ok(Step::Gap { from: 1, to: 2 })
        );
        assert_eq!(chain.head().unwrap().seq, 2);
        assert_eq!(chain.accept_live(&records[3], None), Ok(Step::Next));
    }

    #[test]
    fn a_rewritten_history_is_a_contradiction() {
        let mut honest = Seq::new();
        let did = honest.did();
        let first = honest.push("bafyCreate", 10);
        let second = honest.push("bafyPost", 20);

        // The same key signs another history after the same first entry.
        let mut fork = Seq {
            key: honest.key.clone(),
            records: vec![first.clone()],
        };
        let other_second = fork.push("bafyOther", 20);

        let mut chain = ChannelChain::new(&label_cid("bafyCreate"), &did, None);
        chain.accept(&first, None).unwrap();
        chain.accept(&second, None).unwrap();
        assert_eq!(
            chain.accept(&other_second, None),
            Err(ChainBreak::Rewritten { seq: 1 })
        );
        let third_on_fork = fork.push("bafyMore", 30);
        assert_eq!(
            chain.accept(&third_on_fork, None),
            Err(ChainBreak::Forked { head: 1, seq: 2 })
        );
    }

    #[test]
    fn a_record_that_does_not_fit_is_a_contradiction() {
        let mut server = Seq::new();
        let did = server.did();
        let first = server.push("bafyCreate", 50);
        let mut chain = ChannelChain::new(&label_cid("bafyCreate"), &did, None);
        chain.accept(&first, None).unwrap();

        let slow = server.push("bafyPost", 10);
        assert_eq!(
            chain.clone().accept(&slow, None),
            Err(ChainBreak::ClockBackwards { head: 0, seq: 1 })
        );
        assert!(matches!(
            chain
                .clone()
                .accept(&slow, Some(label_cid("bafyNotThisOne").as_str())),
            Err(ChainBreak::OtherBlock { .. })
        ));
        let mut stranger_chain =
            ChannelChain::new(&label_cid("bafyCreate"), &Seq::new().did(), None);
        assert!(matches!(
            stranger_chain.accept(&first, None),
            Err(ChainBreak::Unsigned(RecordError::WrongSequencer { .. }))
        ));
        let mut other_channel = ChannelChain::new(&label_cid("bafyElsewhere"), &did, None);
        assert!(matches!(
            other_channel.accept(&first, None),
            Err(ChainBreak::OtherChannel { .. })
        ));
    }

    #[test]
    fn a_signed_break_carries_a_proof_anyone_can_check() {
        let mut honest = Seq::new();
        let did = honest.did();
        let first = honest.push("bafyCreate", 10);
        let second = honest.push("bafyPost", 20);
        let mut fork = Seq {
            key: honest.key.clone(),
            records: vec![first.clone()],
        };
        let other_second = fork.push("bafyOther", 20);

        let mut chain = ChannelChain::new(&label_cid("bafyCreate"), &did, None);
        chain.accept(&first, None).unwrap();
        chain.accept(&second, None).unwrap();
        let broke = chain.accept(&other_second, None).unwrap_err();
        let proof = chain
            .proof(&other_second, &broke)
            .expect("two records at seq 1");
        assert_eq!(proof.head.as_ref(), Some(&second));
        assert_eq!(proof.verify(), Ok(broke));

        // Round-trips as kept, and fails once either half is not the
        // sequencer's or the halves agree.
        let kept: ChainProof =
            serde_json::from_str(&serde_json::to_string(&proof).unwrap()).unwrap();
        assert_eq!(kept.verify(), Ok(ChainBreak::Rewritten { seq: 1 }));
        let mut agreeing = proof.clone();
        agreeing.record = second.clone();
        assert!(agreeing.verify().is_err());
        let mut stranger = proof.clone();
        stranger.sequencer = Seq::new().did();
        assert!(stranger.verify().is_err());
        let mut elsewhere = proof;
        elsewhere.channel_id = label_cid("bafyElsewhere");
        assert!(elsewhere.verify().is_err());
    }

    #[test]
    fn a_break_that_proves_nothing_has_no_proof() {
        let mut server = Seq::new();
        let did = server.did();
        let first = server.push("bafyCreate", 50);
        let mut chain = ChannelChain::new(&label_cid("bafyCreate"), &did, None);
        chain.accept(&first, None).unwrap();
        let next = server.push("bafyPost", 60);
        let broke = chain
            .clone()
            .accept(&next, Some(label_cid("bafyNotThisOne").as_str()))
            .unwrap_err();
        assert!(matches!(broke, ChainBreak::OtherBlock { .. }));
        assert_eq!(chain.proof(&next, &broke), None);

        // A head pinned without its record cannot show the other half.
        let mut bare = chain.head().unwrap().clone();
        bare.record = None;
        let mut pinned = ChannelChain::new(&label_cid("bafyCreate"), &did, Some(bare));
        let slow = {
            let mut s = Seq {
                key: server.key.clone(),
                records: vec![first],
            };
            s.push("bafySlow", 10)
        };
        let broke = pinned.accept(&slow, None).unwrap_err();
        assert!(broke.is_signed_proof());
        assert_eq!(pinned.proof(&slow, &broke), None);
    }
}
