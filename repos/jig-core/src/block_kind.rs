//! Block-kind discriminator for jig-protocol v0.0.2+.
//!
//! Every block manifest carries a kind tag identifying which block-shape
//! contract its payload satisfies. v0.0.2 ships one Wasm-executable kind
//! (`text-render`); the rest are synthetic/reserved for v0.0.3+ work
//! per the v0.0.2 hello-world design.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A kind name with this prefix is non-critical (JEP-0005 rule 14c): a
/// follower or client that does not implement it keeps it in the chain and
/// skips its content. Every other kind name is critical. No kind this build
/// implements uses it.
pub const NON_CRITICAL_PREFIX: &str = "opt-";

/// The metadata keys that change an MLS group: a block that carries any of
/// them is critical whatever its kind name, since skipping it would leave the
/// reader in the wrong epoch.
pub const MLS_GROUP_KEYS: &[&str] = &[
    "mls_commit",
    "mls_welcome",
    "mls_group_info",
    "mls_ratchet_tree",
];

/// The `mls_`-prefixed metadata keys that change no group: an application
/// message and the epoch it was sealed in. Any other `mls_` key, named in
/// [`MLS_GROUP_KEYS`] or not, makes a block critical (fail closed).
pub const MLS_CONTENT_KEYS: &[&str] = &["mls_message", "mls_epoch"];

/// Whether a block of kind `name`, which this build does not implement, is
/// critical (JEP-0005 rule 14c): its name lacks [`NON_CRITICAL_PREFIX`], or
/// its metadata carries an MLS key other than [`MLS_CONTENT_KEYS`].
pub fn is_critical(name: &str, metadata: &BTreeMap<String, Value>) -> bool {
    !name.starts_with(NON_CRITICAL_PREFIX)
        || metadata
            .keys()
            .any(|key| key.starts_with("mls_") && !MLS_CONTENT_KEYS.contains(&key.as_str()))
}

/// The block kinds `v0.2.0` implements, as their wire names. Fixed: a kind
/// added to [`BlockKind`] later is not one of them. A reader older than such a
/// kind cannot act on it, so a server serves a channel to a client that does
/// not list the kind only up to the first block of it, when the kind is
/// critical (JEP-0005 rules 11a and 14c; [`gates_older_readers`]).
pub const V0_2_0_KINDS: [&str; 23] = [
    "text-render",
    "channel-create",
    "member-add",
    "member-remove",
    "channel-promote",
    "channel-archive",
    "role-assign",
    "role-unassign",
    "fed-hello",
    "ns-register",
    "ns-rotate",
    "ns-renew",
    "ns-attestation",
    "time-attestation",
    "email-render",
    "email-encrypted",
    "receipt",
    "server-manifest",
    "channel-share",
    "channel-unshare",
    "contract-accept",
    "contract-refuse",
    "contract-end",
];

/// Whether a block of kind `name` stops a reader that predates it: a critical
/// kind (no `opt-` prefix, JEP-0005 rule 14c) that `v0.2.0` does not
/// implement. A non-critical kind never does, since an older reader skips it.
pub fn gates_older_readers(name: &str) -> bool {
    !name.starts_with(NON_CRITICAL_PREFIX) && !V0_2_0_KINDS.contains(&name)
}

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
    /// Removes a member: the owner removing someone, or a member leaving.
    /// On an encrypted channel it carries the MLS commit removing the leaf.
    MemberRemove,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+.
    ChannelPromote,
    /// Synthetic in v0.0.2; real Wasm in v0.0.3+. Retires a channel by
    /// marking it archived — a soft delete. Never destroys blocks; see
    /// `jig_pipeline::effect::apply_channel_archive` for the rationale.
    ChannelArchive,
    /// Gives a DID a role in a channel (JEP-0005 rule 7b). v0.2 defines one
    /// assignable role, `admin`. Only an owner may sign it.
    RoleAssign,
    /// Takes a role away again (JEP-0005 rule 7b). The channel's root owners
    /// (its creator and the co-owners its `channel-create` lists) have no
    /// role to take: they cannot be unassigned.
    RoleUnassign,
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
    /// What a server advertises (JEP-0002 rule 12), written only by that
    /// server, only into its manifest log. Synthetic: the document is in its
    /// metadata (`jig_pipeline::server_manifest`).
    ServerManifest,
    /// Shares a channel with another server under a grant (JEP-0005 rule 7):
    /// the owning server then offers it the contract. Signed by a DID that
    /// holds the `share` right at the block's position in the chain.
    ChannelShare,
    /// Ends a share the channel made (JEP-0005 rule 11): the owning server
    /// then sends the follower a `contract-end`. Needs the `share` right.
    ChannelUnshare,
    /// The record of a server's acceptance (JEP-0005 rule 10), carrying the
    /// offer and the signed accept. Written only by the channel's sequencer.
    ContractAccept,
    /// The record of a refused share, carrying the target's signed refusal,
    /// or none when the owning server refused it itself (a target that is
    /// not a configured peer). Written only by the channel's sequencer.
    ContractRefuse,
    /// The record of an ended share, carrying the signed `contract-end` of
    /// whichever side ended it. Written only by the channel's sequencer.
    ContractEnd,
    /// The owner moves the channel's sequencer to another server (JEP-0005
    /// rule 11a); its metadata is [`crate::sequencer_move::SequencerSet`]'s.
    /// Its record is signed by the new sequencer. Critical: no `opt-` prefix.
    SequencerSet,
    /// A DID's channel-scoped key link (JEP-0005 rule 7b): authored by the
    /// new DID, carrying a link whose audience is this channel. From its
    /// `seq`, the old DID's roles and membership are the new DID's; its
    /// metadata is [`crate::sequencer_move::KeyLinkBlock`]'s. Critical: no
    /// `opt-` prefix.
    KeyLink,
}

impl BlockKind {
    /// Every kind this build implements.
    pub const ALL: [BlockKind; 25] = [
        Self::TextRender,
        Self::ChannelCreate,
        Self::MemberAdd,
        Self::MemberRemove,
        Self::ChannelPromote,
        Self::ChannelArchive,
        Self::RoleAssign,
        Self::RoleUnassign,
        Self::FedHello,
        Self::NsRegister,
        Self::NsRotate,
        Self::NsRenew,
        Self::NsAttestation,
        Self::TimeAttestation,
        Self::EmailRender,
        Self::EmailEncrypted,
        Self::Receipt,
        Self::ServerManifest,
        Self::ChannelShare,
        Self::ChannelUnshare,
        Self::ContractAccept,
        Self::ContractRefuse,
        Self::ContractEnd,
        Self::SequencerSet,
        Self::KeyLink,
    ];

    /// Stable wire-format string (kebab-case).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TextRender => "text-render",
            Self::ChannelCreate => "channel-create",
            Self::MemberAdd => "member-add",
            Self::MemberRemove => "member-remove",
            Self::ChannelPromote => "channel-promote",
            Self::ChannelArchive => "channel-archive",
            Self::RoleAssign => "role-assign",
            Self::RoleUnassign => "role-unassign",
            Self::FedHello => "fed-hello",
            Self::NsRegister => "ns-register",
            Self::NsRotate => "ns-rotate",
            Self::NsRenew => "ns-renew",
            Self::NsAttestation => "ns-attestation",
            Self::TimeAttestation => "time-attestation",
            Self::EmailRender => "email-render",
            Self::EmailEncrypted => "email-encrypted",
            Self::Receipt => "receipt",
            Self::ServerManifest => "server-manifest",
            Self::ChannelShare => "channel-share",
            Self::ChannelUnshare => "channel-unshare",
            Self::ContractAccept => "contract-accept",
            Self::ContractRefuse => "contract-refuse",
            Self::ContractEnd => "contract-end",
            Self::SequencerSet => "sequencer-set",
            Self::KeyLink => "key-link",
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
            "member-remove" => Ok(Self::MemberRemove),
            "channel-promote" => Ok(Self::ChannelPromote),
            "channel-archive" => Ok(Self::ChannelArchive),
            "role-assign" => Ok(Self::RoleAssign),
            "role-unassign" => Ok(Self::RoleUnassign),
            "fed-hello" => Ok(Self::FedHello),
            "ns-register" => Ok(Self::NsRegister),
            "ns-rotate" => Ok(Self::NsRotate),
            "ns-renew" => Ok(Self::NsRenew),
            "ns-attestation" => Ok(Self::NsAttestation),
            "time-attestation" => Ok(Self::TimeAttestation),
            "email-render" => Ok(Self::EmailRender),
            "email-encrypted" => Ok(Self::EmailEncrypted),
            "receipt" => Ok(Self::Receipt),
            "server-manifest" => Ok(Self::ServerManifest),
            "channel-share" => Ok(Self::ChannelShare),
            "channel-unshare" => Ok(Self::ChannelUnshare),
            "contract-accept" => Ok(Self::ContractAccept),
            "contract-refuse" => Ok(Self::ContractRefuse),
            "contract-end" => Ok(Self::ContractEnd),
            "sequencer-set" => Ok(Self::SequencerSet),
            "key-link" => Ok(Self::KeyLink),
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

    /// The `v0.2.0` set is pinned: adding a kind to [`BlockKind`] does not
    /// change it, and every kind added since gates older readers unless it
    /// is `opt-`. Today those are `sequencer-set` and `key-link`.
    #[test]
    fn the_v0_2_0_kinds_are_pinned_and_every_later_kind_gates_older_readers() {
        assert_eq!(V0_2_0_KINDS.len(), 23);
        for name in V0_2_0_KINDS {
            assert!(name.parse::<BlockKind>().is_ok(), "{name}");
            assert!(!gates_older_readers(name), "{name}");
        }
        let later: Vec<&str> = BlockKind::ALL
            .iter()
            .map(BlockKind::as_str)
            .filter(|k| !V0_2_0_KINDS.contains(k))
            .collect();
        assert_eq!(later, ["sequencer-set", "key-link"]);
        assert!(later.iter().all(|k| gates_older_readers(k)));
        assert!(gates_older_readers("key-link"));
        assert!(!gates_older_readers("opt-reaction"));
    }
    use std::str::FromStr;

    #[test]
    fn all_v002_block_kinds_round_trip_via_string() {
        let kinds = [
            ("text-render", BlockKind::TextRender),
            ("channel-create", BlockKind::ChannelCreate),
            ("member-add", BlockKind::MemberAdd),
            ("member-remove", BlockKind::MemberRemove),
            ("channel-promote", BlockKind::ChannelPromote),
            ("channel-archive", BlockKind::ChannelArchive),
            ("role-assign", BlockKind::RoleAssign),
            ("role-unassign", BlockKind::RoleUnassign),
            ("fed-hello", BlockKind::FedHello),
            ("ns-register", BlockKind::NsRegister),
            ("ns-rotate", BlockKind::NsRotate),
            ("ns-renew", BlockKind::NsRenew),
            ("ns-attestation", BlockKind::NsAttestation),
            ("time-attestation", BlockKind::TimeAttestation),
            ("email-render", BlockKind::EmailRender),
            ("email-encrypted", BlockKind::EmailEncrypted),
            ("receipt", BlockKind::Receipt),
            ("server-manifest", BlockKind::ServerManifest),
            ("channel-share", BlockKind::ChannelShare),
            ("channel-unshare", BlockKind::ChannelUnshare),
            ("contract-accept", BlockKind::ContractAccept),
            ("contract-refuse", BlockKind::ContractRefuse),
            ("contract-end", BlockKind::ContractEnd),
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
        assert!(!BlockKind::MemberRemove.is_wasm_executable());
        assert!(!BlockKind::ChannelPromote.is_wasm_executable());
        assert!(!BlockKind::ChannelArchive.is_wasm_executable());
        assert!(!BlockKind::RoleAssign.is_wasm_executable());
        assert!(!BlockKind::RoleUnassign.is_wasm_executable());
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
    fn all_lists_every_kind_once() {
        let names: std::collections::BTreeSet<_> =
            BlockKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), BlockKind::ALL.len());
        for k in BlockKind::ALL {
            assert_eq!(BlockKind::from_str(k.as_str()).unwrap(), k);
        }
    }

    #[test]
    fn no_implemented_kind_is_non_critical_by_name() {
        for k in BlockKind::ALL {
            assert!(
                !k.as_str().starts_with(NON_CRITICAL_PREFIX),
                "{}",
                k.as_str()
            );
        }
    }

    #[test]
    fn criticality_fails_closed() {
        let none = BTreeMap::new();
        let meta = |key: &str| BTreeMap::from([(key.to_string(), Value::from("x"))]);
        assert!(is_critical("sequencer-set", &none));
        assert!(
            is_critical("optional-thing", &none),
            "only the exact prefix counts"
        );
        assert!(!is_critical("opt-reaction", &none));
        assert!(!is_critical("opt-reaction", &meta("body")));
        for key in MLS_CONTENT_KEYS {
            assert!(!is_critical("opt-reaction", &meta(key)), "{key}");
        }
        for key in MLS_GROUP_KEYS {
            assert!(is_critical("opt-reaction", &meta(key)), "{key}");
        }
        assert!(
            is_critical("opt-reaction", &meta("mls_proposal")),
            "an MLS key not yet named"
        );
    }

    #[test]
    fn block_kind_unknown_string_errors() {
        assert!(BlockKind::from_str("not-a-kind").is_err());
        let json = "\"not-a-kind\"";
        assert!(serde_json::from_str::<BlockKind>(json).is_err());
    }
}
