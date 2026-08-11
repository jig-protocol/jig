//! Block-kind discriminator for jig-protocol v0.0.2+.
//!
//! Every block manifest carries a kind tag identifying which block-shape
//! contract its payload satisfies. v0.0.2 ships one Wasm-executable kind
//! (`text-render`); the rest are synthetic/reserved for v0.0.3+ work
//! per the v0.0.2 hello-world design.

use serde::{Deserialize, Serialize};

/// v0.0.2+ block kinds.
///
/// Serialised as kebab-case strings on the wire (e.g. `"text-render"`,
/// `"channel-create"`). Variants without a Wasm artifact in v0.0.2 are
/// produced as "synthetic" blocks server-side; see [`is_wasm_executable`].
///
/// [`is_wasm_executable`]: BlockKind::is_wasm_executable
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockKind {
    /// Canonical chat-message block. Pure, deterministic, ships in v0.0.2.
    TextRender,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+.
    ChannelCreate,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+.
    MemberAdd,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+.
    ChannelPromote,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+. Retires a channel by
    /// marking it archived — a soft delete. Never destroys blocks; see
    /// `jig_pipeline::effect::apply_channel_archive` for the rationale.
    ChannelArchive,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+. Federation handshake.
    FedHello,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+. Nameserver registration.
    NsRegister,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+. Nameserver key rotation.
    NsRotate,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+. Nameserver attestation TTL refresh.
    NsRenew,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+. Nameserver alias attestation.
    NsAttestation,
    /// Reserved for v0.0.3+ time-attestation authority emitters.
    TimeAttestation,
    /// Reserved for v0.0.3 email-bridge milestone.
    EmailRender,
    /// Reserved for v0.0.4+ inbound encrypted-email pass-through.
    EmailEncrypted,
    /// Reserved for v0.0.3+ receipt-as-block consolidation.
    Receipt,
}

impl BlockKind {
    /// Stable wire-format string (kebab-case).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TextRender => "text-render",
            Self::ChannelCreate => "channel-create",
            Self::MemberAdd => "member-add",
            Self::ChannelPromote => "channel-promote",
            Self::ChannelArchive => "channel-archive",
            Self::FedHello => "fed-hello",
            Self::NsRegister => "ns-register",
            Self::NsRotate => "ns-rotate",
            Self::NsRenew => "ns-renew",
            Self::NsAttestation => "ns-attestation",
            Self::TimeAttestation => "time-attestation",
            Self::EmailRender => "email-render",
            Self::EmailEncrypted => "email-encrypted",
            Self::Receipt => "receipt",
        }
    }

    /// Whether this kind ships with a Wasm artifact in v0.0.2 that the
    /// ingest pipeline should execute (vs. emit a server-signed synthetic
    /// pseudo-receipt). Only `TextRender` returns true in v0.0.2.
    pub fn is_wasm_executable(&self) -> bool {
        matches!(self, Self::TextRender)
    }
}

impl std::str::FromStr for BlockKind {
    type Err = BlockKindError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "text-render" => Ok(Self::TextRender),
            "channel-create" => Ok(Self::ChannelCreate),
            "member-add" => Ok(Self::MemberAdd),
            "channel-promote" => Ok(Self::ChannelPromote),
            "channel-archive" => Ok(Self::ChannelArchive),
            "fed-hello" => Ok(Self::FedHello),
            "ns-register" => Ok(Self::NsRegister),
            "ns-rotate" => Ok(Self::NsRotate),
            "ns-renew" => Ok(Self::NsRenew),
            "ns-attestation" => Ok(Self::NsAttestation),
            "time-attestation" => Ok(Self::TimeAttestation),
            "email-render" => Ok(Self::EmailRender),
            "email-encrypted" => Ok(Self::EmailEncrypted),
            "receipt" => Ok(Self::Receipt),
            _ => Err(BlockKindError::Unknown(s.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlockKindError {
    #[error("unknown block kind: `{0}`")]
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn all_v002_block_kinds_round_trip_via_string() {
        let kinds = [
            ("text-render", BlockKind::TextRender),
            ("channel-create", BlockKind::ChannelCreate),
            ("member-add", BlockKind::MemberAdd),
            ("channel-promote", BlockKind::ChannelPromote),
            ("channel-archive", BlockKind::ChannelArchive),
            ("fed-hello", BlockKind::FedHello),
            ("ns-register", BlockKind::NsRegister),
            ("ns-rotate", BlockKind::NsRotate),
            ("ns-renew", BlockKind::NsRenew),
            ("ns-attestation", BlockKind::NsAttestation),
            ("time-attestation", BlockKind::TimeAttestation),
            ("email-render", BlockKind::EmailRender),
            ("email-encrypted", BlockKind::EmailEncrypted),
            ("receipt", BlockKind::Receipt),
        ];
        for (s, k) in kinds {
            assert_eq!(k.as_str(), s);
            assert_eq!(BlockKind::from_str(s).unwrap(), k);
        }
    }

    #[test]
    fn block_kind_is_wasm_executable() {
        assert!(BlockKind::TextRender.is_wasm_executable());
        assert!(!BlockKind::ChannelCreate.is_wasm_executable());
        assert!(!BlockKind::MemberAdd.is_wasm_executable());
        assert!(!BlockKind::ChannelPromote.is_wasm_executable());
        assert!(!BlockKind::ChannelArchive.is_wasm_executable());
        assert!(!BlockKind::FedHello.is_wasm_executable());
        assert!(!BlockKind::NsRegister.is_wasm_executable());
        assert!(!BlockKind::NsRotate.is_wasm_executable());
        assert!(!BlockKind::NsRenew.is_wasm_executable());
        assert!(!BlockKind::NsAttestation.is_wasm_executable());
        assert!(!BlockKind::TimeAttestation.is_wasm_executable());
        assert!(!BlockKind::EmailRender.is_wasm_executable());
        assert!(!BlockKind::EmailEncrypted.is_wasm_executable());
        assert!(!BlockKind::Receipt.is_wasm_executable());
    }

    #[test]
    fn block_kind_serde_uses_kebab_case() {
        let json = serde_json::to_string(&BlockKind::TextRender).unwrap();
        assert_eq!(json, "\"text-render\"");

        let parsed: BlockKind = serde_json::from_str("\"channel-create\"").unwrap();
        assert_eq!(parsed, BlockKind::ChannelCreate);
    }

    #[test]
    fn block_kind_unknown_string_errors() {
        assert!(BlockKind::from_str("not-a-kind").is_err());
        let json = "\"not-a-kind\"";
        assert!(serde_json::from_str::<BlockKind>(json).is_err());
    }
}
