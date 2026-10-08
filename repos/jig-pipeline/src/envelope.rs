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
//! { "v": 1, "suite": "none", "op": "subscribe", "scope": {"kind": "channel", "slug": "#hello"} }
//! { "v": 1, "suite": "none", "op": "submit", "bundle_b64": "...", "sig_b64": "..." }
//! { "v": 1, "op": "ack", "block_cid": "bafy..." }
//! { "v": 1, "op": "block", "bundle_b64": "...", "sig_b64": "...", "receipts": [...], "delivery_cid": "..." }
//! { "v": 1, "op": "catch_up", "since_hlc": {"wall_ms":1234,"logical":5,"origin":"did:jig:..."} }
//! { "v": 1, "op": "error", "status": 401, "code": "INVALID_SIG", "message": "..." }
//! ```
//!
//! Every frame carries `suite`; the remaining examples omit it for brevity.
//!
//! `sig_b64` on `Frame::Block` is `Option<String>` for v0.0.2 backward
//! compatibility (older peers don't carry it). v0.0.3 servers re-verify
//! the signature against the manifest's claimed sender_did when the field
//! is present; the `naively_trust_peer_authored_blocks` antipattern flag
//! bypasses that check (see `jig-config::v0_0_2_server::FederationSection`).

use jig_core::{EncryptionSuite, SuiteNotImplemented};
use serde::{Deserialize, Serialize};

/// The only envelope version this implementation speaks. A frame with any
/// other `v` does not deserialize.
pub const ENVELOPE_VERSION: u8 = 1;

/// Wire envelope: every frame carries a protocol version and the encryption
/// suite applied to its payload.
///
/// Deserialization is the gate: an unsupported `v`, an unregistered `suite`,
/// or a registered suite this version does not implement is a parse error, so
/// no caller can act on a frame it cannot interpret. An absent `suite` means
/// `none`, which is what every frame before the field existed was.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedEnvelope")]
pub struct Envelope {
    pub v: u8,
    pub suite: EncryptionSuite,
    #[serde(flatten)]
    pub frame: Frame,
}

impl Envelope {
    /// Build an unencrypted envelope at [`ENVELOPE_VERSION`].
    pub fn new(frame: Frame) -> Self {
        Self {
            v: ENVELOPE_VERSION,
            suite: EncryptionSuite::Unencrypted,
            frame,
        }
    }

    /// Parse a frame, telling a gate refusal apart from malformed input so
    /// the reply can say "unsupported" rather than "bad JSON".
    pub fn parse(text: &str) -> Result<Self, EnvelopeParseError> {
        serde_json::from_str(text).map_err(|e| {
            #[derive(Deserialize)]
            struct Probe {
                v: Option<u64>,
                suite: Option<String>,
            }
            match serde_json::from_str::<Probe>(text) {
                Ok(probe) => match gate(probe.v, probe.suite.as_deref()) {
                    Err(refusal) => EnvelopeParseError::Gate(refusal),
                    Ok(()) => EnvelopeParseError::Malformed(e),
                },
                Err(_) => EnvelopeParseError::Malformed(e),
            }
        })
    }
}

/// Why an envelope did not parse.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeParseError {
    #[error(transparent)]
    Gate(EnvelopeGateError),
    #[error("envelope parse failed: {0}")]
    Malformed(serde_json::Error),
}

/// A well-formed envelope this implementation refuses to interpret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeGateError {
    #[error("unsupported envelope version {0}; this implementation speaks v{ENVELOPE_VERSION}")]
    UnsupportedVersion(u64),
    #[error(transparent)]
    UnknownSuite(#[from] jig_core::UnknownSuite),
    #[error(transparent)]
    SuiteNotImplemented(#[from] SuiteNotImplemented),
}

impl EnvelopeGateError {
    /// Reply code when `v` is not the version this implementation speaks.
    pub const UNSUPPORTED_VERSION_CODE: &'static str = "UNSUPPORTED_VERSION";
    /// Reply code when `suite` is unknown or registered but not implemented.
    pub const UNSUPPORTED_SUITE_CODE: &'static str = "UNSUPPORTED_SUITE";

    /// The error code a server replies with.
    pub fn code(&self) -> &'static str {
        match self {
            EnvelopeGateError::UnsupportedVersion(_) => Self::UNSUPPORTED_VERSION_CODE,
            EnvelopeGateError::UnknownSuite(_) | EnvelopeGateError::SuiteNotImplemented(_) => {
                Self::UNSUPPORTED_SUITE_CODE
            }
        }
    }
}

fn gate(v: Option<u64>, suite: Option<&str>) -> Result<(), EnvelopeGateError> {
    if let Some(v) = v
        && v != u64::from(ENVELOPE_VERSION)
    {
        return Err(EnvelopeGateError::UnsupportedVersion(v));
    }
    if let Some(suite) = suite {
        suite.parse::<EncryptionSuite>()?.ensure_implemented()?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct UncheckedEnvelope {
    v: u8,
    #[serde(default)]
    suite: EncryptionSuite,
    #[serde(flatten)]
    frame: Frame,
}

impl TryFrom<UncheckedEnvelope> for Envelope {
    type Error = EnvelopeGateError;

    fn try_from(raw: UncheckedEnvelope) -> Result<Self, Self::Error> {
        gate(Some(u64::from(raw.v)), Some(raw.suite.as_str()))?;
        Ok(Envelope {
            v: raw.v,
            suite: raw.suite,
            frame: raw.frame,
        })
    }
}

/// One protocol frame. Variants tagged by the `op` field on the wire.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Frame {
    /// Client's first frame. See [`crate::handshake`].
    ///
    /// `versions` is a list, not the envelope's `v`: the envelope `v` is the
    /// version of this frame, and the list is what the client is willing to
    /// speak. Those collide if they share a JSON key.
    Hello {
        versions: Vec<u64>,
        suites: Vec<String>,
        capabilities: crate::handshake::Capabilities,
        nonce: String,
    },
    /// Server's signed answer to [`Frame::Hello`]. The envelope's `v` is the
    /// chosen version; `suite` is the suite this frame is carried under.
    /// `reputation` is null until JEP-0003.
    Welcome {
        server_did: String,
        suites: Vec<String>,
        capabilities: crate::handshake::Capabilities,
        reputation: crate::handshake::Reputation,
        nonce: String,
        /// base64 ed25519 over [`crate::handshake::WelcomeStatement::canonical_bytes`].
        sig: String,
    },
    /// Subscribe to a scope (channel or federation).
    ///
    /// `auth` carries the same tier-0 proof of possession the REST path takes
    /// in headers. `Option` for wire compatibility: absent means the caller
    /// offered no proof, which a server requiring authentication refuses.
    Subscribe {
        scope: Scope,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<SubscribeAuth>,
    },
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
    /// `Option` because a status is not always available. Absent means exactly
    /// that — **no status, for either of two reasons**: the peer predates the
    /// field, or this server declined to classify the failure. The WS submit
    /// path does the latter deliberately, sending `None` with `INGEST_ERROR`
    /// where it cannot tell which underlying failure occurred and any single
    /// code would be a guess.
    ///
    /// So absence is **not** a capability signal: a consumer must not infer
    /// "this peer is old" from it. What it does guarantee is that a present
    /// status is meaningful.
    Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
        code: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_cid: Option<String>,
        message: String,
    },
}

/// Tier-0 proof of possession carried on a [`Frame::Subscribe`].
///
/// The transport-specific envelope for the same five values the REST path sends
/// as headers. Only the carriage differs; verification is shared, which is what
/// keeps the design transport-agnostic.
///
/// **`did` is what the caller CLAIMS.** It is not trustworthy until the server
/// verifies the signature against it. A server must bind the DID its verifier
/// returns, never this field as received — trusting it would let any client
/// subscribe as anyone, which is worse than no authorization because it looks
/// enforced.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SubscribeAuth {
    /// The identity the caller claims. Untrusted until verified.
    pub did: String,
    pub hlc_wall_ms: u64,
    pub hlc_logical: u32,
    pub nonce: String,
    /// base64 ed25519 signature over the canonical subscribe hash.
    pub sig_b64: String,
}

/// Subscription scope: a single channel by slug or a federation-wide subscription
/// filtered to specified block kinds.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scope {
    Channel { slug: String },
    Federation { block_kinds: Vec<String> },
}

impl Scope {
    /// A stable string identifying this scope, for signing.
    ///
    /// Lives here rather than in the server so client and server cannot drift
    /// into signing and verifying different strings — the same reasoning that
    /// puts `canonical_request_hash` in `jig-core`. A drift would present as
    /// "every subscribe signature is invalid" with no indication which side is
    /// wrong.
    ///
    /// Block kinds are sorted so a client that lists them in a different order
    /// still produces the same string. Without that, a signature would depend
    /// on incidental ordering the wire format does not otherwise care about.
    pub fn canonical_string(&self) -> String {
        match self {
            Scope::Channel { slug } => format!("channel:{slug}"),
            Scope::Federation { block_kinds } => {
                let mut kinds = block_kinds.clone();
                kinds.sort();
                format!("federation:{}", kinds.join(","))
            }
        }
    }
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
            auth: None,
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
    fn suite_is_emitted_and_defaults_to_none_when_absent() {
        let env = Envelope::new(Frame::Ack {
            block_cid: "bafy".into(),
        });
        let json: serde_json::Value = serde_json::to_value(&env).unwrap();
        assert_eq!(json["suite"], "none");

        let legacy = r#"{"v":1,"op":"ack","block_cid":"bafy"}"#;
        assert_eq!(Envelope::parse(legacy).unwrap(), env);
    }

    #[test]
    fn unsupported_version_is_refused_by_every_parse_path() {
        let json = r#"{"v":2,"op":"ack","block_cid":"bafy"}"#;
        assert!(serde_json::from_str::<Envelope>(json).is_err());
        assert!(matches!(
            Envelope::parse(json),
            Err(EnvelopeParseError::Gate(
                EnvelopeGateError::UnsupportedVersion(2)
            ))
        ));
    }

    #[test]
    fn unimplemented_suite_is_refused() {
        let json = r#"{"v":1,"suite":"mls","op":"ack","block_cid":"bafy"}"#;
        assert!(serde_json::from_str::<Envelope>(json).is_err());
        let err = Envelope::parse(json).unwrap_err();
        match err {
            EnvelopeParseError::Gate(gate) => {
                assert_eq!(
                    gate,
                    EnvelopeGateError::SuiteNotImplemented(SuiteNotImplemented(
                        EncryptionSuite::Mls
                    ))
                );
                assert_eq!(gate.code(), "UNSUPPORTED_SUITE");
            }
            other => panic!("expected a gate refusal, got {other:?}"),
        }
    }

    #[test]
    fn unknown_suite_is_refused_not_ignored() {
        let json = r#"{"v":1,"suite":"rot13","op":"ack","block_cid":"bafy"}"#;
        assert!(serde_json::from_str::<Envelope>(json).is_err());
        assert!(matches!(
            Envelope::parse(json),
            Err(EnvelopeParseError::Gate(EnvelopeGateError::UnknownSuite(_)))
        ));
    }

    #[test]
    fn malformed_frame_with_supported_gates_is_reported_as_malformed() {
        let json = r#"{"v":1,"suite":"none","op":"teleport"}"#;
        assert!(matches!(
            Envelope::parse(json),
            Err(EnvelopeParseError::Malformed(_))
        ));
        assert!(matches!(
            Envelope::parse("not json"),
            Err(EnvelopeParseError::Malformed(_))
        ));
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
    fn scope_canonical_string_distinguishes_scopes() {
        let a = Scope::Channel {
            slug: "#hello".into(),
        };
        let b = Scope::Channel {
            slug: "#other".into(),
        };
        assert_ne!(a.canonical_string(), b.canonical_string());

        let fed = Scope::Federation {
            block_kinds: vec!["text-render".into()],
        };
        assert_ne!(
            a.canonical_string(),
            fed.canonical_string(),
            "a channel named like a federation filter must not collide"
        );
    }

    /// Block-kind order is incidental on the wire, so it must not change the
    /// signed string — otherwise a client that reorders its filter list would
    /// produce a signature the server rejects for no meaningful reason.
    #[test]
    fn federation_scope_is_order_independent() {
        let a = Scope::Federation {
            block_kinds: vec!["b".into(), "a".into()],
        };
        let b = Scope::Federation {
            block_kinds: vec!["a".into(), "b".into()],
        };
        assert_eq!(a.canonical_string(), b.canonical_string());
    }

    #[test]
    fn subscribe_frame_round_trips_with_and_without_auth() {
        let unsigned = Envelope::new(Frame::Subscribe {
            scope: Scope::Channel {
                slug: "#hello".into(),
            },
            auth: None,
        });
        let json = serde_json::to_string(&unsigned).unwrap();
        assert!(
            !json.contains("auth"),
            "absent auth must be omitted: {json}"
        );
        assert_eq!(
            serde_json::from_str::<Envelope>(&json).unwrap(),
            unsigned,
            "an unsigned subscribe must round-trip"
        );

        let signed = Envelope::new(Frame::Subscribe {
            scope: Scope::Channel {
                slug: "#hello".into(),
            },
            auth: Some(SubscribeAuth {
                did: "did:jig:zabc".into(),
                hlc_wall_ms: 7,
                hlc_logical: 0,
                nonce: "n1".into(),
                sig_b64: "c2ln".into(),
            }),
        });
        let json = serde_json::to_string(&signed).unwrap();
        assert_eq!(serde_json::from_str::<Envelope>(&json).unwrap(), signed);
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
