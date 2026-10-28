//! Channel tiers (JEP-0014): who joins a channel and whether it is encrypted.
//!
//! Every channel belongs to one of four tiers, fixed by its `channel-create`:
//!
//! | Tier | Who joins | Suite |
//! | --- | --- | --- |
//! | `private` | added by a member or admin | `mls` |
//! | `server` | anyone holding the `join` role on the server | `mls` |
//! | `shared` | as `server`, across servers under a contract | `mls` |
//! | `public` | anyone | `none` |
//!
//! A channel created before tiers has none; [`legacy_tier`] reads one from its
//! stored visibility and suite (JEP-0014 rule 21), and a channel that maps to
//! no tier is [`StoredTier::Frozen`].
//!
//! Every value here parses strictly: an identifier this build does not know is
//! an error, never a default, so an unknown tier can never be carried along and
//! read as a weaker one.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::slug::{SlugClass, reserved_class};
use crate::suite::EncryptionSuite;

/// The capability a client requests in its `hello`, a server signs into its
/// `welcome` when asked, and a server manifest lists under `features`
/// (JEP-0014 rules 1 and 5).
pub const TIERS_FEATURE: &str = "tiers";

/// An identifier that names no tier, join role, join-servers rule or history
/// policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{value}` is not a {what}")]
pub struct UnknownValue {
    pub what: &'static str,
    pub value: String,
}

/// Generates `as_str`, `FromStr`, `Display` and string serde for an enum whose
/// variants each have one wire identifier.
macro_rules! wire_enum {
    ($ty:ident, $what:literal, { $($variant:ident => $wire:literal),+ $(,)? }) => {
        impl $ty {
            /// Every value, in declaration order.
            pub const ALL: &'static [$ty] = &[$($ty::$variant),+];

            /// The identifier on the wire and in storage.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($ty::$variant => $wire),+
                }
            }
        }

        impl FromStr for $ty {
            type Err = UnknownValue;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($wire => Ok($ty::$variant),)+
                    _ => Err(UnknownValue { what: $what, value: s.to_string() }),
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

/// A channel's tier, fixed for its life (JEP-0014 rule 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// Members are added by a DID holding the `membership` right. Today's
    /// `restricted`, and every DM.
    Private,
    /// A DID holding the channel's `join` role on the server adds itself.
    Server,
    /// As `server`, across servers under a JEP-0005 contract.
    Shared,
    /// Signed but not encrypted: anyone, the operator included, can read it.
    Public,
}

wire_enum!(Tier, "channel tier", {
    Private => "private",
    Server => "server",
    Shared => "shared",
    Public => "public",
});

impl Tier {
    /// Whether the tier's content is encrypted. Only `public` is not.
    pub const fn is_encrypted(self) -> bool {
        !matches!(self, Tier::Public)
    }

    /// The suite the tier requires (JEP-0014 rule 3): `none` for `public`,
    /// and today `mls`, the one operator-confidential suite, for the others.
    pub const fn required_suite(self) -> EncryptionSuite {
        match self {
            Tier::Public => EncryptionSuite::Unencrypted,
            Tier::Private | Tier::Server | Tier::Shared => EncryptionSuite::Mls,
        }
    }

    /// Whether a channel of this tier may be created under `suite`. An
    /// encrypted tier takes any operator-confidential suite; `public` takes
    /// only `none`.
    pub const fn admits_suite(self, suite: EncryptionSuite) -> bool {
        if self.is_encrypted() {
            suite.is_operator_confidential()
        } else {
            matches!(suite, EncryptionSuite::Unencrypted)
        }
    }

    /// The `visibility` a client that predates tiers reads for this tier
    /// (JEP-0014, Backwards Compatibility): `private` is `restricted`, the
    /// others are `open`.
    pub const fn legacy_visibility(self) -> &'static str {
        match self {
            Tier::Private => "restricted",
            Tier::Server | Tier::Shared | Tier::Public => "open",
        }
    }

    /// Whether the creation block carries a `join` role (rules 12 and 13).
    pub const fn takes_join(self) -> bool {
        matches!(self, Tier::Server | Tier::Shared)
    }

    /// Whether the creation block carries `join_servers` (rule 13).
    pub const fn takes_join_servers(self) -> bool {
        matches!(self, Tier::Shared)
    }
}

/// The lowest server role that may join a `server` or `shared` channel
/// (JEP-0014 rule 12). `member` is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum JoinRole {
    #[default]
    Member,
    Guest,
}

wire_enum!(JoinRole, "join role", {
    Member => "member",
    Guest => "guest",
});

/// Whose server roles count for a self-join to a `shared` channel (JEP-0014
/// rule 13). `owner` is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum JoinServers {
    #[default]
    Owner,
    Granted,
}

wire_enum!(JoinServers, "join-servers rule", {
    Owner => "owner",
    Granted => "granted",
});

/// Whether members may re-share history with a joiner (JEP-0014 rule 17).
/// The mechanism is reserved; the field is fixed at creation. `none` is the
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HistoryPolicy {
    #[default]
    None,
    MembersMayShare,
}

wire_enum!(HistoryPolicy, "history policy", {
    None => "none",
    MembersMayShare => "members-may-share",
});

/// A stored channel's tier: one of the four, or frozen.
///
/// A frozen channel is a legacy plaintext channel that maps to no tier
/// (JEP-0014 rule 22): its history stays readable and nothing new lands in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoredTier {
    Tier(Tier),
    Frozen,
}

impl StoredTier {
    /// The identifier stored for a frozen channel.
    pub const FROZEN: &'static str = "frozen";

    /// The tier, or `None` for a frozen channel.
    pub const fn tier(self) -> Option<Tier> {
        match self {
            StoredTier::Tier(tier) => Some(tier),
            StoredTier::Frozen => None,
        }
    }

    pub const fn is_frozen(self) -> bool {
        matches!(self, StoredTier::Frozen)
    }

    /// The identifier in storage and in channel listings.
    pub const fn as_str(self) -> &'static str {
        match self {
            StoredTier::Tier(tier) => tier.as_str(),
            StoredTier::Frozen => Self::FROZEN,
        }
    }
}

impl From<Tier> for StoredTier {
    fn from(tier: Tier) -> Self {
        StoredTier::Tier(tier)
    }
}

impl FromStr for StoredTier {
    type Err = UnknownValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == Self::FROZEN {
            return Ok(StoredTier::Frozen);
        }
        s.parse::<Tier>()
            .map(StoredTier::Tier)
            .map_err(|_| UnknownValue {
                what: "stored channel tier",
                value: s.to_string(),
            })
    }
}

impl fmt::Display for StoredTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for StoredTier {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for StoredTier {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// What a channel without a `tier` is read as (JEP-0014 rule 21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyTier {
    pub tier: StoredTier,
    /// `guest` for an open `mls` channel, which any admitted caller could
    /// join; `None` for every other row.
    pub join: Option<JoinRole>,
}

/// Read a tier from a legacy channel's slug, stored visibility and suite
/// (JEP-0014 rule 21), checking the `#jig/` row first:
///
/// | slug / `visibility` | `suite` | tier |
/// | --- | --- | --- |
/// | under `#jig/` | `none` | `public` |
/// | `restricted` | `mls` | `private` |
/// | `open` | `mls` | `server`, `join = guest` |
/// | `open` | `none` | frozen |
/// | `restricted` | `none` | frozen |
///
/// It fails closed like the rest of the channel code: a visibility other than
/// exactly `open` is `restricted`, and a suite that is neither `none` nor `mls`
/// is frozen rather than guessed.
pub fn legacy_tier(slug: &str, visibility: &str, suite: &str) -> LegacyTier {
    let frozen = LegacyTier {
        tier: StoredTier::Frozen,
        join: None,
    };
    match suite {
        "none" if reserved_class(slug) == Some(SlugClass::Server) => LegacyTier {
            tier: Tier::Public.into(),
            join: None,
        },
        "mls" if visibility == "open" => LegacyTier {
            tier: Tier::Server.into(),
            join: Some(JoinRole::Guest),
        },
        "mls" => LegacyTier {
            tier: Tier::Private.into(),
            join: None,
        },
        _ => frozen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_identifier_round_trips_and_nothing_else_parses() {
        for tier in Tier::ALL {
            assert_eq!(tier.as_str().parse::<Tier>(), Ok(*tier));
            let json = serde_json::to_string(tier).unwrap();
            assert_eq!(serde_json::from_str::<Tier>(&json).unwrap(), *tier);
        }
        for role in JoinRole::ALL {
            assert_eq!(role.as_str().parse::<JoinRole>(), Ok(*role));
        }
        for rule in JoinServers::ALL {
            assert_eq!(rule.as_str().parse::<JoinServers>(), Ok(*rule));
        }
        for policy in HistoryPolicy::ALL {
            assert_eq!(policy.as_str().parse::<HistoryPolicy>(), Ok(*policy));
        }
        for bad in [
            "",
            "Public",
            "PUBLIC",
            " public",
            "open",
            "restricted",
            "frozen",
        ] {
            assert!(
                bad.parse::<Tier>().is_err(),
                "{bad:?} must not parse as a tier"
            );
        }
        assert!(serde_json::from_str::<Tier>("\"open\"").is_err());
        assert!("stranger".parse::<JoinRole>().is_err());
        assert!("all".parse::<JoinServers>().is_err());
        assert!("members".parse::<HistoryPolicy>().is_err());
    }

    #[test]
    fn a_stored_tier_is_one_of_the_four_or_frozen() {
        assert_eq!("frozen".parse::<StoredTier>(), Ok(StoredTier::Frozen));
        for tier in Tier::ALL {
            let stored = StoredTier::from(*tier);
            assert_eq!(stored.as_str().parse::<StoredTier>(), Ok(stored));
            assert_eq!(stored.tier(), Some(*tier));
        }
        assert_eq!(StoredTier::Frozen.tier(), None);
        assert!("".parse::<StoredTier>().is_err());
        assert!("open".parse::<StoredTier>().is_err());
    }

    #[test]
    fn suites_by_tier() {
        for tier in [Tier::Private, Tier::Server, Tier::Shared] {
            assert!(tier.is_encrypted());
            assert_eq!(tier.required_suite(), EncryptionSuite::Mls);
            assert!(tier.admits_suite(EncryptionSuite::Mls));
            assert!(!tier.admits_suite(EncryptionSuite::Unencrypted));
        }
        assert!(!Tier::Public.is_encrypted());
        assert_eq!(Tier::Public.required_suite(), EncryptionSuite::Unencrypted);
        assert!(Tier::Public.admits_suite(EncryptionSuite::Unencrypted));
        assert!(!Tier::Public.admits_suite(EncryptionSuite::Mls));
    }

    #[test]
    fn old_clients_read_private_as_restricted_and_the_rest_as_open() {
        assert_eq!(Tier::Private.legacy_visibility(), "restricted");
        for tier in [Tier::Server, Tier::Shared, Tier::Public] {
            assert_eq!(tier.legacy_visibility(), "open");
        }
    }

    #[test]
    fn join_fields_belong_to_the_tiers_that_self_join() {
        assert!(Tier::Server.takes_join() && Tier::Shared.takes_join());
        assert!(!Tier::Private.takes_join() && !Tier::Public.takes_join());
        assert!(Tier::Shared.takes_join_servers());
        for tier in [Tier::Private, Tier::Server, Tier::Public] {
            assert!(!tier.takes_join_servers());
        }
    }

    /// JEP-0014 rule 21's table, with the `#jig/` row checked first.
    #[test]
    fn legacy_channels_map_by_rule_21() {
        let public = LegacyTier {
            tier: Tier::Public.into(),
            join: None,
        };
        let frozen = LegacyTier {
            tier: StoredTier::Frozen,
            join: None,
        };
        // The manifest log is open and plaintext, and must not freeze.
        assert_eq!(legacy_tier("#jig/manifest", "open", "none"), public);
        assert_eq!(legacy_tier("#JIG/manifest", "open", "none"), public);
        assert_eq!(legacy_tier("#jig/other", "restricted", "none"), public);
        assert_eq!(
            legacy_tier("#team", "restricted", "mls"),
            LegacyTier {
                tier: Tier::Private.into(),
                join: None
            }
        );
        assert_eq!(
            legacy_tier("#team", "open", "mls"),
            LegacyTier {
                tier: Tier::Server.into(),
                join: Some(JoinRole::Guest)
            }
        );
        assert_eq!(legacy_tier("#team", "open", "none"), frozen);
        assert_eq!(legacy_tier("#team", "restricted", "none"), frozen);
        // A DM is restricted: MLS DMs are private, plaintext ones frozen.
        let dm = "#dm/0123456789abcdef";
        assert_eq!(
            legacy_tier(dm, "restricted", "mls").tier,
            Tier::Private.into()
        );
        assert_eq!(legacy_tier(dm, "restricted", "none"), frozen);
    }

    #[test]
    fn legacy_mapping_fails_closed() {
        // Anything other than exactly `open` is restricted.
        assert_eq!(
            legacy_tier("#team", "Open", "mls").tier,
            Tier::Private.into()
        );
        assert_eq!(legacy_tier("#team", "", "mls").tier, Tier::Private.into());
        // An unknown suite is never guessed into a tier, `#jig/` included.
        for suite in ["", "MLS", "test-aead", "future"] {
            assert_eq!(legacy_tier("#team", "open", suite).tier, StoredTier::Frozen);
            assert_eq!(
                legacy_tier("#jig/manifest", "open", suite).tier,
                StoredTier::Frozen
            );
        }
    }
}
