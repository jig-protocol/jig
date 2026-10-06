//! Encryption-suite identifiers.
//!
//! Carried on every wire envelope (`suite`) and in a block manifest's
//! `privacy.encryption`. The registry is normative in the spec
//! (`jig-spec/src/encryption.md`); this enum mirrors it.
//!
//! Two separate refusals, both fail-closed:
//!
//! - An identifier that is not in the registry does not parse. There is no
//!   catch-all variant, so an unknown suite can never be carried along and
//!   treated as plaintext by a later step.
//! - A registered suite this implementation cannot speak parses, then fails
//!   [`EncryptionSuite::ensure_implemented`]. v0.1 implements only `none`.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A registered encryption suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum EncryptionSuite {
    /// Content is not encrypted. The only suite v0.1 implements.
    #[default]
    #[serde(rename = "none")]
    Unencrypted,
    /// MLS (RFC 9420). Registered as the v0.2 default; not implemented.
    #[serde(rename = "mls")]
    Mls,
}

impl EncryptionSuite {
    /// Every registered suite, in registry order.
    pub const REGISTERED: &'static [EncryptionSuite] =
        &[EncryptionSuite::Unencrypted, EncryptionSuite::Mls];

    /// The registry identifier, as it appears on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            EncryptionSuite::Unencrypted => "none",
            EncryptionSuite::Mls => "mls",
        }
    }

    /// Whether this implementation can produce and consume the suite.
    pub const fn is_implemented(self) -> bool {
        matches!(self, EncryptionSuite::Unencrypted)
    }

    /// Refuse a registered suite this implementation cannot speak.
    pub fn ensure_implemented(self) -> Result<Self, SuiteNotImplemented> {
        if self.is_implemented() {
            Ok(self)
        } else {
            Err(SuiteNotImplemented(self))
        }
    }
}

impl fmt::Display for EncryptionSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EncryptionSuite {
    type Err = UnknownSuite;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EncryptionSuite::REGISTERED
            .iter()
            .copied()
            .find(|suite| suite.as_str() == s)
            .ok_or_else(|| UnknownSuite(s.to_string()))
    }
}

/// An identifier that is not in the suite registry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown encryption suite `{0}`")]
pub struct UnknownSuite(pub String);

/// A registered suite this implementation does not speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("encryption suite `{0}` is registered but not implemented in this version")]
pub struct SuiteNotImplemented(pub EncryptionSuite);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_suites_round_trip_by_identifier() {
        for suite in EncryptionSuite::REGISTERED {
            let json = serde_json::to_string(suite).unwrap();
            assert_eq!(json, format!("\"{}\"", suite.as_str()));
            assert_eq!(
                serde_json::from_str::<EncryptionSuite>(&json).unwrap(),
                *suite
            );
            assert_eq!(suite.as_str().parse::<EncryptionSuite>().unwrap(), *suite);
        }
    }

    #[test]
    fn unknown_identifiers_do_not_parse() {
        for unknown in ["age+x25519", "NONE", "", "mls-pq", "signal-pqxdh"] {
            assert!(
                serde_json::from_str::<EncryptionSuite>(&format!("\"{unknown}\"")).is_err(),
                "`{unknown}` must not parse"
            );
            assert_eq!(
                unknown.parse::<EncryptionSuite>(),
                Err(UnknownSuite(unknown.to_string()))
            );
        }
    }

    #[test]
    fn only_none_is_implemented() {
        assert_eq!(EncryptionSuite::default(), EncryptionSuite::Unencrypted);
        assert!(EncryptionSuite::Unencrypted.ensure_implemented().is_ok());
        assert_eq!(
            EncryptionSuite::Mls.ensure_implemented(),
            Err(SuiteNotImplemented(EncryptionSuite::Mls))
        );
    }
}
