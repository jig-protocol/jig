//! Head gossip between servers (JEP-0002 rule 10; design D11 item 6): the
//! `channel-head` peer frame.
//!
//! A server forwards the latest `ingest` record it verified for a channel to
//! the other servers that hold the channel, so that two records one sequencer
//! signed for the same `seq` can meet. The frame carries the record's signed
//! envelope and nothing about who first sent it.
//!
//! The frame is sent only on a peer connection whose welcome granted
//! [`jig_pipeline::handshake::Capabilities::heads`]; a server that predates
//! it ignores the kind. Its body is deterministic CBOR, like the stream's
//! frames ([`crate::v0_0_2_stream`]).

use jig_core::dcbor::{self, Value};
use jig_pipeline::ingest_record::MAX_COSE_BYTES;

/// The peer frame kind for one channel's head.
pub const HEAD_FRAME: &str = "channel-head";

/// One channel's head, as a [`HEAD_FRAME`] carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelHead {
    /// The CID of the channel's `channel-create` block.
    pub channel_id: String,
    /// The record's COSE_Sign1 envelope
    /// ([`jig_pipeline::ingest_record::IngestRecord::cose_bytes`]).
    pub record: Vec<u8>,
}

/// The most a [`HEAD_FRAME`] body may hold: the record's envelope, a CID and
/// the keys. Anything larger is refused before it is parsed.
pub const MAX_HEAD_BODY: usize = MAX_COSE_BYTES + 256;

impl ChannelHead {
    pub fn encode(&self) -> Vec<u8> {
        dcbor::encode(&Value::text_map([
            ("channel_id", Value::text(&self.channel_id)),
            ("record", Value::Bytes(self.record.clone())),
        ]))
        .expect("text keys never repeat")
    }

    /// `None` for a body past [`MAX_HEAD_BODY`], one that is not
    /// deterministic CBOR, or a map with any key but the two above.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_HEAD_BODY {
            return None;
        }
        let value = dcbor::decode(bytes).ok()?;
        let Value::Map(entries) = &value else {
            return None;
        };
        if entries.len() != 2 {
            return None;
        }
        let record = value.get("record")?.as_bytes()?;
        if record.len() > MAX_COSE_BYTES {
            return None;
        }
        Some(Self {
            channel_id: value.get("channel_id")?.as_text()?.to_string(),
            record: record.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_head_round_trips() {
        let head = ChannelHead {
            channel_id: jig_pipeline::ingest_record::label_cid("Create"),
            record: vec![1, 2, 3],
        };
        assert_eq!(ChannelHead::decode(&head.encode()), Some(head));
    }

    #[test]
    fn a_body_that_is_not_a_head_is_refused() {
        let extra = dcbor::encode(&Value::text_map([
            ("channel_id", Value::text("c")),
            ("record", Value::Bytes(vec![1])),
            ("from", Value::text("someone")),
        ]))
        .unwrap();
        let oversize = ChannelHead {
            channel_id: "c".into(),
            record: vec![0; MAX_COSE_BYTES + 1],
        }
        .encode();
        for bad in [
            b"not cbor".to_vec(),
            extra,
            oversize,
            vec![0; MAX_HEAD_BODY + 1],
        ] {
            assert_eq!(ChannelHead::decode(&bad), None);
        }
    }

    /// `jig-spec/jep/vectors/0002/heads.json` (JEP-0002 rule 10): one record,
    /// signed by a fixed key, as a block's `seen`, as a client's `head` frame
    /// and as a `channel-head` peer frame body. Regenerate after an intended
    /// change with `JIG_BLESS_HEADS_VECTORS=1`, and review the diff.
    #[test]
    fn heads_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../jig-spec/jep/vectors/0002/heads.json");
        let blessed = bless_heads_vectors();
        if std::env::var_os("JIG_BLESS_HEADS_VECTORS").is_some() {
            std::fs::write(&path, &blessed).unwrap();
        }
        let committed = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            committed, blessed,
            "regenerate with JIG_BLESS_HEADS_VECTORS=1"
        );

        // What an independent reader does with the committed bytes.
        let v: serde_json::Value = serde_json::from_str(&committed).unwrap();
        let envelope = hex::decode(v["record_cose_hex"].as_str().unwrap()).unwrap();
        let record = IngestRecord::from_cose(&envelope).unwrap();
        record.verify(v["sequencer"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(record.hash()), v["record_hash_hex"]);
        let body = hex::decode(v["channel_head_body_hex"].as_str().unwrap()).unwrap();
        assert_eq!(ChannelHead::decode(&body).unwrap().record, envelope);
        let frame = jig_pipeline::Envelope::parse(&v["head_frame"].to_string()).unwrap();
        assert!(matches!(frame.frame, jig_pipeline::Frame::Head { .. }));
    }

    use base64::Engine as _;
    use jig_pipeline::ingest_record::{
        GENESIS_PREV, IngestRecord, RecordSigner, SEEN_KEY, label_cid, seen_value,
    };

    fn bless_heads_vectors() -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let channel_id = label_cid("vector channel-create");
        let record = RecordSigner {
            channel_id: channel_id.clone(),
            key: &key,
            ingest_wall_ms: 1_700_000_000_000,
            ingest_logical: 3,
        }
        .sign(5, &label_cid("vector block"), GENESIS_PREV)
        .unwrap();
        let envelope = record.cose_bytes().unwrap();
        let frame = jig_pipeline::Envelope::new(jig_pipeline::Frame::Head {
            channel_id: channel_id.clone(),
            record_b64: base64::engine::general_purpose::STANDARD.encode(&envelope),
        });
        let vectors = serde_json::json!({
            "description": "One ingest record, signed by the ed25519 key whose seed is 32 bytes of \
                0x07, in the three places JEP-0002 rule 10 carries it: as a block's `seen` \
                (manifest metadata, base64 of the COSE_Sign1 envelope), in a client's `head` \
                frame, and as the deterministic-CBOR body of a `channel-head` peer frame. \
                `record` is the envelope's payload as fields; `record_hash_hex` is BLAKE3 of the \
                envelope, what the next record's `prev` names.",
            "sequencer": record.sequencer,
            "record": {
                "channel_id": record.channel_id,
                "seq": record.seq,
                "ingest_wall_ms": record.ingest_wall_ms,
                "ingest_logical": record.ingest_logical,
                "block_cid": record.block_cid,
                "prev": record.prev,
            },
            "record_cose_hex": hex::encode(&envelope),
            "record_hash_hex": hex::encode(record.hash()),
            "seen": { SEEN_KEY: seen_value(&record).unwrap() },
            "head_frame": serde_json::to_value(&frame).unwrap(),
            "channel_head_body_hex": hex::encode(ChannelHead {
                channel_id,
                record: envelope,
            }.encode()),
        });
        serde_json::to_string_pretty(&vectors).unwrap() + "\n"
    }
}
