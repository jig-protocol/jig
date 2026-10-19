//! The `ingest` record: one per block in a channel, signed by the channel's
//! sequencer (JEP-0002 rule 9; design D11 item 5).
//!
//! A record says "I, the sequencer, accepted `block_cid` as entry `seq` of
//! `channel_id` at `ingest_hlc`, after the record whose hash is `prev`". It is
//! what orders history (TM-02), what clients check for gaps and reordering
//! (OP-06), and the time lanes A and C run a block at.
//!
//! Signed as a COSE_Sign1 over a deterministic CBOR payload ([`jig_core::cose`],
//! [`jig_core::dcbor`]), like every new signed object. The JSON fields beside
//! the envelope are a view of the payload for readers; [`IngestRecord::verify`]
//! requires them to be exactly what was signed.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use jig_core::Did;
use jig_core::dcbor::{self, Value};
use serde::{Deserialize, Serialize};

/// The format a record is signed in, named on the record and in the signed
/// payload's `domain`. A record in any other format is refused by name.
pub const RECORD_FORMAT: &str = "jig-ingest-v2";

/// The hash a chain starts from: `prev` at `seq` 0.
pub const GENESIS_PREV: [u8; 32] = [0; 32];

/// A signed ingest record, as it travels on the wire and is stored.
///
/// `prev` and `cose` are hex and base64 strings so the JSON form is plain;
/// [`IngestRecord::hash`] and [`IngestRecord::verify`] decode them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestRecord {
    /// How `cose` is made: [`RECORD_FORMAT`]. Named so that another encoding
    /// is told apart from a damaged record.
    pub format: String,
    /// The CID of the channel's `channel-create` block.
    pub channel_id: String,
    pub seq: u64,
    /// The sequencer's HLC when it accepted the block.
    pub ingest_wall_ms: u64,
    pub ingest_logical: u32,
    pub block_cid: String,
    /// Hex BLAKE3 of the previous record ([`IngestRecord::hash`]).
    pub prev: String,
    /// The DID that signed this record.
    pub sequencer: String,
    /// Base64 COSE_Sign1 over [`IngestRecord::payload`], by `sequencer`.
    pub cose: String,
}

/// Why a record is not one this client can rely on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("the record is signed in format `{format}`, which this build does not verify")]
    UnknownFormat { format: String },
    #[error("the record is signed by {got}, not the channel's sequencer {expected}")]
    WrongSequencer { expected: String, got: String },
    #[error("the record's signature does not verify")]
    BadSignature,
    #[error("the record is malformed: {0}")]
    Malformed(&'static str),
}

/// What a sequencer signs a new record with. `prev` and `seq` come from the
/// chain as stored, inside the transaction that stores the block.
pub struct RecordSigner<'a> {
    pub channel_id: String,
    pub key: &'a SigningKey,
    pub ingest_wall_ms: u64,
    pub ingest_logical: u32,
}

impl RecordSigner<'_> {
    /// Sign `block_cid` as entry `seq`, after the record hashing to `prev`.
    /// Refused when `block_cid` or the channel id is not a CIDv1.
    pub fn sign(
        &self,
        seq: u64,
        block_cid: &str,
        prev: [u8; 32],
    ) -> Result<IngestRecord, RecordError> {
        let mut record = IngestRecord {
            format: RECORD_FORMAT.to_string(),
            channel_id: self.channel_id.clone(),
            seq,
            ingest_wall_ms: self.ingest_wall_ms,
            ingest_logical: self.ingest_logical,
            block_cid: block_cid.to_string(),
            prev: hex::encode(prev),
            sequencer: Did::from_ed25519_pubkey(self.key.verifying_key().as_bytes())
                .to_did_jig_string(),
            cose: String::new(),
        };
        let payload = record.payload()?;
        record.cose = STANDARD.encode(jig_core::cose::sign1(self.key, &payload));
        Ok(record)
    }
}

/// A CID as the binary CID it names, in the one form JEP-0004 rule 0 allows
/// ([`jig_core::canonical_cid`]: CIDv1, raw, BLAKE3-256). Text CIDs (any
/// multibase) parse; every other form is refused.
fn cid_bytes(text: &str) -> Result<Vec<u8>, RecordError> {
    match cid::Cid::try_from(text) {
        Ok(cid) if jig_core::canonical_cid::check(&cid).is_ok() => Ok(cid.to_bytes()),
        _ => Err(RecordError::Malformed(
            "a CID in the record is not canonical",
        )),
    }
}

/// A CIDv1 naming `label`'s bytes, for test fixtures and tools that need a
/// channel or block id a record can sign: records sign only real CIDs.
pub fn label_cid(label: &str) -> String {
    jig_core::canonical_cid::of(label.as_bytes()).to_string()
}

impl IngestRecord {
    /// The deterministic CBOR payload the sequencer signs: a text-keyed map
    /// with `domain` = [`RECORD_FORMAT`] and every field. CIDs are binary
    /// CIDv1 byte strings (JEP-0004 rule 0); `prev` is the 32 hash bytes.
    pub fn payload(&self) -> Result<Vec<u8>, RecordError> {
        let prev: [u8; 32] = hex::decode(&self.prev)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(RecordError::Malformed("prev is not 32 hex bytes"))?;
        dcbor::encode(&Value::text_map([
            ("domain", Value::text(RECORD_FORMAT)),
            ("channel_id", Value::Bytes(cid_bytes(&self.channel_id)?)),
            ("seq", Value::Unsigned(self.seq)),
            ("ingest_wall_ms", Value::Unsigned(self.ingest_wall_ms)),
            (
                "ingest_logical",
                Value::Unsigned(u64::from(self.ingest_logical)),
            ),
            ("block_cid", Value::Bytes(cid_bytes(&self.block_cid)?)),
            ("prev", Value::Bytes(prev.to_vec())),
            ("sequencer", Value::text(&self.sequencer)),
        ]))
        .map_err(|_| RecordError::Malformed("record fields do not encode"))
    }

    /// The hash the next record's `prev` names: BLAKE3 of the COSE envelope,
    /// so a chain binds every payload and signature in it.
    pub fn hash(&self) -> [u8; 32] {
        let envelope = STANDARD.decode(&self.cose).unwrap_or_default();
        *blake3::hash(&envelope).as_bytes()
    }

    /// Check the signature, by `expected_sequencer`, and that the fields are
    /// exactly what was signed.
    pub fn verify(&self, expected_sequencer: &str) -> Result<(), RecordError> {
        if self.format != RECORD_FORMAT {
            return Err(RecordError::UnknownFormat {
                format: self.format.clone(),
            });
        }
        let key_of = |s: &str| {
            Did::from_did_jig_string(s)
                .and_then(|did| did.as_bytes())
                .ok()
        };
        let same = matches!(
            (key_of(&self.sequencer), key_of(expected_sequencer)),
            (Some(a), Some(b)) if a == b
        );
        if !same {
            return Err(RecordError::WrongSequencer {
                expected: expected_sequencer.to_string(),
                got: self.sequencer.clone(),
            });
        }
        let envelope = STANDARD
            .decode(&self.cose)
            .map_err(|_| RecordError::Malformed("cose is not base64"))?;
        let signed = jig_core::cose::open_sign1(&envelope)
            .map_err(|_| RecordError::Malformed("cose is not a COSE_Sign1"))?;
        if signed.payload != self.payload()? {
            return Err(RecordError::BadSignature);
        }
        signed
            .verify(&self.sequencer)
            .map_err(|_| RecordError::BadSignature)
    }

    /// Whether this record follows `previous` in its chain: same channel, the
    /// next `seq`, and `prev` naming it.
    pub fn follows(&self, previous: &IngestRecord) -> bool {
        self.channel_id == previous.channel_id
            && previous.seq.checked_add(1) == Some(self.seq)
            && self.prev == hex::encode(previous.hash())
    }

    /// Whether this is the first record of its chain.
    pub fn is_genesis(&self) -> bool {
        self.seq == 0 && self.prev == hex::encode(GENESIS_PREV)
    }

    /// The stored form.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a record always serializes")
    }

    /// Read the stored form.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        serde_json::from_slice(bytes).map_err(|_| RecordError::Malformed("not a stored record"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::crypto::ed25519::generate_signing_key;

    fn did_of(key: &SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    fn signer(key: &SigningKey) -> RecordSigner<'_> {
        RecordSigner {
            channel_id: label_cid("Create"),
            key,
            ingest_wall_ms: 1_000,
            ingest_logical: 2,
        }
    }

    #[test]
    fn a_chain_verifies_and_links() {
        let key = generate_signing_key();
        let first = signer(&key)
            .sign(0, &label_cid("Create"), GENESIS_PREV)
            .unwrap();
        let second = signer(&key)
            .sign(1, &label_cid("Post"), first.hash())
            .unwrap();
        for record in [&first, &second] {
            record.verify(&did_of(&key)).unwrap();
        }
        assert!(first.is_genesis());
        assert!(second.follows(&first));
        assert!(!first.follows(&second));
        let skipped = signer(&key)
            .sign(2, &label_cid("Later"), first.hash())
            .unwrap();
        assert!(!skipped.follows(&first), "a gap is not a link");
        assert_eq!(IngestRecord::decode(&second.encode()).unwrap(), second);
    }

    #[test]
    fn every_field_is_signed() {
        let key = generate_signing_key();
        let record = signer(&key)
            .sign(3, &label_cid("Post"), GENESIS_PREV)
            .unwrap();
        let tampered: Vec<IngestRecord> = vec![
            IngestRecord {
                channel_id: label_cid("Other"),
                ..record.clone()
            },
            IngestRecord {
                seq: 4,
                ..record.clone()
            },
            IngestRecord {
                ingest_wall_ms: 9,
                ..record.clone()
            },
            IngestRecord {
                ingest_logical: 9,
                ..record.clone()
            },
            IngestRecord {
                block_cid: label_cid("Else"),
                ..record.clone()
            },
            IngestRecord {
                prev: hex::encode([1; 32]),
                ..record.clone()
            },
        ];
        for t in tampered {
            assert_eq!(
                t.verify(&did_of(&key)),
                Err(RecordError::BadSignature),
                "{t:?}"
            );
        }
    }

    #[test]
    fn a_record_in_another_format_is_refused_by_name() {
        let key = generate_signing_key();
        let record = IngestRecord {
            format: "jig-ingest-v1".into(),
            ..signer(&key)
                .sign(0, &label_cid("Create"), GENESIS_PREV)
                .unwrap()
        };
        assert!(matches!(
            record.verify(&did_of(&key)),
            Err(RecordError::UnknownFormat { format }) if format == "jig-ingest-v1"
        ));
    }

    #[test]
    fn an_envelope_from_another_record_is_refused() {
        let key = generate_signing_key();
        let first = signer(&key)
            .sign(0, &label_cid("Create"), GENESIS_PREV)
            .unwrap();
        let second = signer(&key)
            .sign(1, &label_cid("Post"), first.hash())
            .unwrap();
        let swapped = IngestRecord {
            cose: first.cose.clone(),
            ..second.clone()
        };
        assert_eq!(
            swapped.verify(&did_of(&key)),
            Err(RecordError::BadSignature)
        );
        assert_ne!(first.hash(), second.hash());
    }

    #[test]
    fn cids_are_signed_as_canonical_binary_cids_and_nothing_else_signs() {
        let key = generate_signing_key();
        let record = signer(&key)
            .sign(0, &label_cid("Create"), GENESIS_PREV)
            .unwrap();
        let payload = jig_core::dcbor::decode(&record.payload().unwrap()).unwrap();
        let block = payload.get("block_cid").and_then(|v| v.as_bytes()).unwrap();
        assert_eq!(
            cid::Cid::try_from(block).unwrap().to_string(),
            record.block_cid
        );
        assert_eq!(
            signer(&key).sign(1, "not-a-cid", record.hash()),
            Err(RecordError::Malformed(
                "a CID in the record is not canonical"
            ))
        );
        let dag_cbor = cid::Cid::new_v1(
            0x71,
            *cid::Cid::try_from(record.block_cid.as_str())
                .unwrap()
                .hash(),
        );
        assert!(
            signer(&key)
                .sign(1, &dag_cbor.to_string(), record.hash())
                .is_err(),
            "a CIDv1 with another codec is refused"
        );
        let v0 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
        assert!(
            signer(&key).sign(1, v0, record.hash()).is_err(),
            "CIDv0 is refused"
        );
    }

    #[test]
    fn only_the_expected_sequencer_signs() {
        let key = generate_signing_key();
        let record = signer(&key)
            .sign(0, &label_cid("Create"), GENESIS_PREV)
            .unwrap();
        let other = did_of(&generate_signing_key());
        assert!(matches!(
            record.verify(&other),
            Err(RecordError::WrongSequencer { .. })
        ));
    }
}
