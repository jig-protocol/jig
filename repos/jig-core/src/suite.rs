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
//!   [`EncryptionSuite::ensure_implemented`].
//!
//! v0.2 implements `none` and `mls` as **content** suites: what protects a
//! block's payload, fixed per channel. A wire *frame* is never encrypted as a
//! unit — it carries blocks, and an encrypted block is encrypted inside its
//! manifest — so the only frame suite is `none`
//! ([`EncryptionSuite::ensure_frame_suite`]).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A registered encryption suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum EncryptionSuite {
    /// Content is not encrypted. Signatures still apply.
    #[default]
    #[serde(rename = "none")]
    Unencrypted,
    /// MLS (RFC 9420). One channel is one MLS group; content is an MLS
    /// `PrivateMessage` the server cannot read.
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

    /// Whether this implementation can carry content under the suite.
    pub const fn is_implemented(self) -> bool {
        matches!(self, EncryptionSuite::Unencrypted | EncryptionSuite::Mls)
    }

    /// Whether a wire frame may declare this suite. Frames are never
    /// encrypted as a unit, so only `none`.
    pub const fn is_frame_suite(self) -> bool {
        matches!(self, EncryptionSuite::Unencrypted)
    }

    /// Refuse a suite a wire frame may not declare. A registered content suite
    /// on a frame is refused the same way as an unimplemented one: reading it
    /// as `none` is the downgrade the refusal exists to prevent.
    pub fn ensure_frame_suite(self) -> Result<Self, SuiteNotImplemented> {
        if self.is_frame_suite() {
            Ok(self)
        } else {
            Err(SuiteNotImplemented(self))
        }
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
    fn none_and_mls_are_content_suites() {
        assert_eq!(EncryptionSuite::default(), EncryptionSuite::Unencrypted);
        assert!(EncryptionSuite::Unencrypted.ensure_implemented().is_ok());
        assert!(EncryptionSuite::Mls.ensure_implemented().is_ok());
    }

    #[test]
    fn only_none_is_a_frame_suite() {
        assert!(EncryptionSuite::Unencrypted.ensure_frame_suite().is_ok());
        assert_eq!(
            EncryptionSuite::Mls.ensure_frame_suite(),
            Err(SuiteNotImplemented(EncryptionSuite::Mls))
        );
    }
}
