//! Transport-agnostic WSS envelope codec.
//!
//! The same frame format is used for CLI clients connecting to jig-server,
//! federated peers exchanging blocks, and (in v0.0.3+) other transports like
//! SSH and gRPC. v0.0.2 ships WSS as the only transport; the codec does not
//! bake in WebSocket-specific semantics.
//!
//! ## Wire format
//!
//! ```json
//! { "v": 1, "op": "subscribe", "scope": {"kind": "channel", "slug": "#hello"} }
//! { "v": 1, "op": "submit", "bundle_b64": "...", "sig_b64": "..." }
//! { "v": 1, "op": "ack", "block_cid": "bafy..." }
//! { "v": 1, "op": "block", "bundle_b64": "...", "sig_b64": "...", "receipts": [...], "delivery_cid": "..." }
//! { "v": 1, "op": "catch_up", "since_hlc": {"wall_ms":1234,"logical":5,"origin":"did:jig:..."} }
//! { "v": 1, "op": "error", "status": 401, "code": "INVALID_SIG", "message": "..." }
//! ```
//!
//! `sig_b64` on `Frame::Block` is `Option<String>` for v0.0.2 backward
//! compatibility (older peers don't carry it). v0.0.3 servers re-verify
//! the signature against the manifest's claimed sender_did when the field
//! is present; the `naively_trust_peer_authored_blocks` antipattern flag
//! bypasses that check (see `jig-config::v0_0_2_server::FederationSection`).

use serde::{Deserialize, Serialize};

/// Wire envelope: every frame is wrapped with a protocol version field.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    #[serde(flatten)]
    pub frame: Frame,
}

impl Envelope {
    /// Build an envelope at protocol version 1 (the v0.0.2 default).
    pub fn new(frame: Frame) -> Self {
        Self { v: 1, frame }
    }
}

/// One protocol frame. Variants tagged by the `op` field on the wire.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Frame {
    /// Subscribe to a scope (channel or federation).
    Subscribe { scope: Scope },
    /// Submit a signed block bundle for ingest.
    Submit { bundle_b64: String, sig_b64: String },
    /// Request a catch-up replay since a given HLC cursor.
    CatchUp { since_hlc: HlcCursor },
    /// Acknowledge a submitted block's persistence.
    Ack { block_cid: String },
    /// Deliver a block to a subscriber, with all known receipts.
    ///
    /// `sig_b64` carries the sender's ed25519 signature over the canonical
    /// bundle bytes. It's `Option<String>` for v0.0.2 wire compatibility
    /// with peers that don't emit it; v0.0.3 servers MUST emit it and
    /// reject inbound peer blocks whose claimed sender_did doesn't verify
    /// against this signature.
    Block {
        bundle_b64: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sig_b64: Option<String>,
        receipts: Vec<ReceiptRef>,
        delivery_cid: String,
    },
    /// Report an error in reply to a prior frame.
    ///
    /// `status` carries the HTTP-style status the REST surface would have
    /// returned for the same condition, so a client sees the same status and
    /// error code regardless of transport. Deliberately not a claim about
    /// `message`: a few WS messages word themselves differently from their REST
    /// counterparts, and the WS submit path collapses several `IngestError`
    /// variants into one code that REST reports distinctly.
    ///
    /// `Option` for wire compatibility with peers predating the field: absent
    /// means "this peer does not speak status codes", which is not the same as
    /// any particular code.
    Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
        code: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_cid: Option<String>,
        message: String,
    },
}

/// Subscription scope: a single channel by slug or a federation-wide subscription
/// filtered to specified block kinds.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scope {
    Channel { slug: String },
    Federation { block_kinds: Vec<String> },
}

/// A receipt summary suitable for cross-server fanout — carries the producing
/// server's DID + render_hash for parity checks and the canonical receipt bytes.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptRef {
    pub server_did: String,
    /// `None` for synthetic (non-Wasm-executed) receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render_hash: Option<String>,
    pub receipt_bytes_b64: String,
}

/// HLC catch-up cursor: the highest HLC point a subscriber has already seen.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HlcCursor {
    pub wall_ms: u64,
    pub logical: u32,
    pub origin: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_channel_frame_serializes_via_envelope() {
        let env = Envelope::new(Frame::Subscribe {
            scope: Scope::Channel {
                slug: "#hello".into(),
            },
        });
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("\"v\":1"));
        assert!(json.contains("\"op\":\"subscribe\""));
        assert!(json.contains("\"scope\":{\"kind\":\"channel\""));
        assert!(json.contains("\"slug\":\"#hello\""));
    }

    #[test]
    fn submit_envelope_round_trips() {
        let env = Envelope::new(Frame::Submit {
            bundle_b64: "dGVzdA==".into(),
            sig_b64: "c2ln".into(),
        });
        let json = serde_json::to_string(&env).unwrap();
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn block_delivery_envelope_carries_receipts() {
        let env = Envelope::new(Frame::Block {
            bundle_b64: "Yg==".into(),
            sig_b64: Some("c2ln".into()),
            receipts: vec![ReceiptRef {
                server_did: "did:jig:zA".into(),
                render_hash: Some("rh".into()),
                receipt_bytes_b64: "cmI=".into(),
            }],
            delivery_cid: "bafy".into(),
        });
        let json = serde_json::to_string(&env).unwrap();
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn block_delivery_envelope_back_compat_without_sig() {
        // Older v0.0.2 peers don't include sig_b64; deserialization must still work.
        let json =
            r##"{"v":1,"op":"block","bundle_b64":"Yg==","receipts":[],"delivery_cid":"bafy"}"##;
        let parsed: Envelope = serde_json::from_str(json).unwrap();
        match parsed.frame {
            Frame::Block { sig_b64, .. } => assert!(sig_b64.is_none()),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn catch_up_carries_hlc_cursor() {
        let env = Envelope::new(Frame::CatchUp {
            since_hlc: HlcCursor {
                wall_ms: 1234,
                logical: 5,
                origin: "did:jig:zOrigin".into(),
            },
        });
        let json = serde_json::to_string(&env).unwrap();
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn version_field_is_always_v1() {
        let env = Envelope::new(Frame::Ack {
            block_cid: "bafy".into(),
        });
        let json = serde_json::to_string(&env).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["v"], 1);
    }

    #[test]
    fn unknown_op_returns_error() {
        let json = r##"{"v":1,"op":"teleport","scope":{"kind":"channel","slug":"#x"}}"##;
        let result: Result<Envelope, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "envelope deserialization should reject unknown op variant"
        );
    }

    #[test]
    fn error_envelope_round_trips_with_optional_ref_cid() {
        let env = Envelope::new(Frame::Error {
            status: None,
            code: "INVALID_SIG".into(),
            ref_cid: None,
            message: "signature verification failed".into(),
        });
        let json = serde_json::to_string(&env).unwrap();
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);

        let env_with_ref = Envelope::new(Frame::Error {
            status: None,
            code: "DISALLOWED_BLOCK_KIND".into(),
            ref_cid: Some("bafy123".into()),
            message: "block kind not in allow list".into(),
        });
        let json2 = serde_json::to_string(&env_with_ref).unwrap();
        let parsed2: Envelope = serde_json::from_str(&json2).unwrap();
        assert_eq!(parsed2, env_with_ref);
    }

    /// A frame from an older peer carries no `status`. It must still parse,
    /// with `status: None` meaning "this peer does not speak status codes"
    /// rather than defaulting to a number that would be a lie.
    #[test]
    fn error_frame_without_status_still_parses() {
        let json = r#"{"v":1,"op":"error","code":"INVALID_SIG","message":"nope"}"#;
        let parsed: Envelope = serde_json::from_str(json).unwrap();
        match parsed.frame {
            Frame::Error { status, code, .. } => {
                assert_eq!(status, None, "absent status must not invent a value");
                assert_eq!(code, "INVALID_SIG");
            }
            other => panic!("expected Frame::Error, got {other:?}"),
        }
    }

    /// A status, when present, round-trips and is emitted on the wire.
    #[test]
    fn error_frame_with_status_round_trips() {
        let env = Envelope::new(Frame::Error {
            status: Some(403),
            code: "NOT_CHANNEL_OWNER".into(),
            ref_cid: None,
            message: "not the owner".into(),
        });
        let json = serde_json::to_string(&env).unwrap();
        assert!(
            json.contains(r#""status":403"#),
            "status must be emitted: {json}"
        );
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    /// An absent status must be omitted entirely, not serialized as null —
    /// matching how `ref_cid` and `sig_b64` already behave in this codec.
    #[test]
    fn absent_status_is_omitted_not_null() {
        let env = Envelope::new(Frame::Error {
            status: None,
            code: "INVALID_SIG".into(),
            ref_cid: None,
            message: "nope".into(),
        });
        let json = serde_json::to_string(&env).unwrap();
        // Parse rather than substring-scan the document: `!json.contains("status")`
        // passes here only because this fixture's message happens not to contain
        // the word, and would fail spuriously on one that did.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            parsed.get("status").is_none(),
            "absent status must be omitted, not serialized as null: {json}"
        );
    }
}
