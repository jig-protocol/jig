//! The `ingest` record: one per block in a channel, signed by the channel's
//! sequencer (JEP-0002 rule 9; design D11 item 5).
//!
//! A record says "I, the sequencer, accepted `block_cid` as entry `seq` of
//! `channel_id` at `ingest_hlc`, after the record whose hash is `prev`". It is
//! what orders history (TM-02), what clients check for gaps and reordering
//! (OP-06), and the time lanes A and C run a block at.
//!
//! The encoding and signature live here and nowhere else. Whether signed
//! objects move to deterministic CBOR with COSE_Sign1 (as v0.3 receipts do)
//! is still open; switching is a change to this module alone.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use jig_core::Did;
use serde::{Deserialize, Serialize};

/// The format a record is signed in, named on the record and in the signed
/// bytes. A record in any other format is refused by name.
pub const RECORD_FORMAT: &str = "jig-ingest-v1";
const DOMAIN: &[u8] = RECORD_FORMAT.as_bytes();

/// The hash a chain starts from: `prev` at `seq` 0.
pub const GENESIS_PREV: [u8; 32] = [0; 32];

/// A signed ingest record, as it travels on the wire and is stored.
///
/// `prev` and `sig` are hex and base64 strings so the JSON form is plain;
/// [`IngestRecord::hash`] and [`IngestRecord::verify`] decode them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestRecord {
    /// How `sig` is made: [`RECORD_FORMAT`]. Named so that a later encoding
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
    /// Base64 ed25519 over [`IngestRecord::signed_bytes`].
    pub sig: String,
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
    pub fn sign(&self, seq: u64, block_cid: &str, prev: [u8; 32]) -> IngestRecord {
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
            sig: String::new(),
        };
        record.sig = STANDARD.encode(self.key.sign(&record.signed_bytes()).to_bytes());
        record
    }
}

impl IngestRecord {
    /// Length-prefixed and domain-separated, in a fixed field order, so the
    /// signature does not depend on JSON key order.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in [
            DOMAIN,
            self.channel_id.as_bytes(),
            &self.seq.to_le_bytes(),
            &self.ingest_wall_ms.to_le_bytes(),
            &self.ingest_logical.to_le_bytes(),
            self.block_cid.as_bytes(),
            self.prev.as_bytes(),
            self.sequencer.as_bytes(),
        ] {
            let len = u64::try_from(field.len()).expect("record field fits in u64");
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    /// The hash the next record's `prev` names: the signed bytes and the
    /// signature, so a chain binds every signature in it.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.signed_bytes());
        hasher.update(self.sig.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Check the signature, by `expected_sequencer`.
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
        let key = Did::from_did_jig_string(&self.sequencer)
            .and_then(|did| did.as_bytes())
            .map_err(|_| RecordError::Malformed("sequencer is not a did:jig key"))?;
        let key = VerifyingKey::from_bytes(&key)
            .map_err(|_| RecordError::Malformed("sequencer is not an ed25519 key"))?;
        let sig = STANDARD
            .decode(&self.sig)
            .map_err(|_| RecordError::Malformed("sig is not base64"))?;
        let sig = Signature::from_slice(&sig)
            .map_err(|_| RecordError::Malformed("sig is not ed25519"))?;
        key.verify(&self.signed_bytes(), &sig)
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
            channel_id: "bafyCreate".to_string(),
            key,
            ingest_wall_ms: 1_000,
            ingest_logical: 2,
        }
    }

    #[test]
    fn a_chain_verifies_and_links() {
        let key = generate_signing_key();
        let first = signer(&key).sign(0, "bafyCreate", GENESIS_PREV);
        let second = signer(&key).sign(1, "bafyPost", first.hash());
        for record in [&first, &second] {
            record.verify(&did_of(&key)).unwrap();
        }
        assert!(first.is_genesis());
        assert!(second.follows(&first));
        assert!(!first.follows(&second));
        let skipped = signer(&key).sign(2, "bafyLater", first.hash());
        assert!(!skipped.follows(&first), "a gap is not a link");
        assert_eq!(IngestRecord::decode(&second.encode()).unwrap(), second);
    }

    #[test]
    fn every_field_is_signed() {
        let key = generate_signing_key();
        let record = signer(&key).sign(3, "bafyPost", GENESIS_PREV);
        let tampered: Vec<IngestRecord> = vec![
            IngestRecord {
                channel_id: "bafyOther".into(),
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
                block_cid: "bafyElse".into(),
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
            format: "jig-ingest-cose-v1".into(),
            ..signer(&key).sign(0, "bafyCreate", GENESIS_PREV)
        };
        assert!(matches!(
            record.verify(&did_of(&key)),
            Err(RecordError::UnknownFormat { format }) if format == "jig-ingest-cose-v1"
        ));
    }

    #[test]
    fn only_the_expected_sequencer_signs() {
        let key = generate_signing_key();
        let record = signer(&key).sign(0, "bafyCreate", GENESIS_PREV);
        let other = did_of(&generate_signing_key());
        assert!(matches!(
            record.verify(&other),
            Err(RecordError::WrongSequencer { .. })
        ));
    }
}
