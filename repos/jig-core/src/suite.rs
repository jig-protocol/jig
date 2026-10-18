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
//!
//! Identifiers starting `test-` are reserved for conformance testing. The one
//! such suite, `test-aead` ([`test_aead`]), exists only with the `test-suite`
//! feature, which only dev-dependencies enable: a production build does not
//! know the identifier and refuses it as unregistered.

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
    /// The conformance-test suite: ChaCha20-Poly1305 under a published key.
    /// Real authenticated encryption that hides nothing, so it is open-only
    /// and never advertised. See [`test_aead`].
    #[cfg(feature = "test-suite")]
    #[serde(rename = "test-aead")]
    TestAead,
}

impl EncryptionSuite {
    /// Every registered suite, in registry order.
    #[cfg(not(feature = "test-suite"))]
    pub const REGISTERED: &'static [EncryptionSuite] =
        &[EncryptionSuite::Unencrypted, EncryptionSuite::Mls];
    /// Every registered suite, in registry order.
    #[cfg(feature = "test-suite")]
    pub const REGISTERED: &'static [EncryptionSuite] = &[
        EncryptionSuite::Unencrypted,
        EncryptionSuite::Mls,
        EncryptionSuite::TestAead,
    ];

    /// The registry identifier, as it appears on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            EncryptionSuite::Unencrypted => "none",
            EncryptionSuite::Mls => "mls",
            #[cfg(feature = "test-suite")]
            EncryptionSuite::TestAead => "test-aead",
        }
    }

    /// Whether this implementation can carry content under the suite.
    pub const fn is_implemented(self) -> bool {
        match self {
            EncryptionSuite::Unencrypted | EncryptionSuite::Mls => true,
            #[cfg(feature = "test-suite")]
            EncryptionSuite::TestAead => true,
        }
    }

    /// Whether content under the suite is ciphertext. A server stores and
    /// relays it, refuses a plaintext `body` beside it, and never executes it.
    pub const fn is_encrypted(self) -> bool {
        !matches!(self, EncryptionSuite::Unencrypted)
    }

    /// The block-metadata key that carries a content block's ciphertext, for
    /// an encrypted suite.
    pub const fn payload_field(self) -> Option<&'static str> {
        match self {
            EncryptionSuite::Unencrypted => None,
            EncryptionSuite::Mls => Some("mls_message"),
            #[cfg(feature = "test-suite")]
            EncryptionSuite::TestAead => Some(test_aead::PAYLOAD_FIELD),
        }
    }

    /// Whether a server lists the suite in its handshake. A test suite is
    /// never offered: no client should pick it, even against a test build.
    pub const fn is_advertised(self) -> bool {
        match self {
            EncryptionSuite::Unencrypted | EncryptionSuite::Mls => true,
            #[cfg(feature = "test-suite")]
            EncryptionSuite::TestAead => false,
        }
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

/// `test-aead`: the suite reserved for conformance testing (JEP-0001).
///
/// ChaCha20-Poly1305 under one static key published here and in the suite's
/// vectors. The payload field carries `nonce ‖ ciphertext`; the AAD binds it
/// to its channel and author, so it does not read anywhere else. It protects
/// nothing and is not meant to: it shows a second suite running through the
/// registry, the manifest, the gates and the sealed receipt without MLS.
#[cfg(feature = "test-suite")]
pub mod test_aead {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    /// The published key: bytes `0x00..=0x1f`.
    pub const KEY: [u8; 32] = {
        let mut k = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            k[i] = i as u8;
            i += 1;
        }
        k
    };

    /// The metadata key of a content block's payload.
    pub const PAYLOAD_FIELD: &str = "test_ciphertext";

    /// The nonce length, prefixed to the ciphertext in the payload.
    pub const NONCE_LEN: usize = 12;

    /// Additional data: `jig-test-aead-v1|<slug>|<sender DID>`.
    pub fn aad(slug: &str, sender: &str) -> Vec<u8> {
        format!("jig-test-aead-v1|{slug}|{sender}").into_bytes()
    }

    /// Seal `plaintext` for `slug` from `sender`, under `nonce`.
    pub fn seal(slug: &str, sender: &str, nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&KEY));
        let aad = aad(slug, sender);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("ChaCha20-Poly1305 encryption does not fail on in-memory input");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        out
    }

    /// Open a payload sealed by [`seal`]. `None` if it is too short, or was
    /// sealed for another channel or author, or altered.
    pub fn open(slug: &str, sender: &str, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < NONCE_LEN {
            return None;
        }
        let (nonce, ct) = payload.split_at(NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&KEY));
        let aad = aad(slug, sender);
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            .ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn seals_and_opens_only_for_its_channel_and_author() {
            let nonce = [7u8; NONCE_LEN];
            let sealed = seal("#a", "did:jig:zx", &nonce, b"hello");
            assert_eq!(sealed.len(), NONCE_LEN + 5 + 16);
            assert_eq!(
                open("#a", "did:jig:zx", &sealed).as_deref(),
                Some(&b"hello"[..])
            );
            assert_eq!(open("#b", "did:jig:zx", &sealed), None);
            assert_eq!(open("#a", "did:jig:zy", &sealed), None);
            let mut bent = sealed.clone();
            *bent.last_mut().unwrap() ^= 1;
            assert_eq!(open("#a", "did:jig:zx", &bent), None);
            assert_eq!(open("#a", "did:jig:zx", &sealed[..4]), None);
        }
    }
}

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
    fn suite_properties() {
        assert!(!EncryptionSuite::Unencrypted.is_encrypted());
        assert_eq!(EncryptionSuite::Unencrypted.payload_field(), None);
        assert!(EncryptionSuite::Mls.is_encrypted());
        assert_eq!(EncryptionSuite::Mls.payload_field(), Some("mls_message"));
        for suite in EncryptionSuite::REGISTERED {
            assert_eq!(suite.is_encrypted(), suite.payload_field().is_some());
            assert_eq!(suite.is_advertised(), !suite.as_str().starts_with("test-"));
        }
    }

    /// The `test-` prefix is reserved: without the feature, `test-aead` is
    /// as unknown as any other identifier.
    #[cfg(not(feature = "test-suite"))]
    #[test]
    fn test_suites_are_unregistered_in_a_production_build() {
        assert!("test-aead".parse::<EncryptionSuite>().is_err());
    }

    #[cfg(feature = "test-suite")]
    #[test]
    fn test_aead_is_registered_encrypted_and_never_advertised() {
        let suite: EncryptionSuite = "test-aead".parse().unwrap();
        assert_eq!(suite, EncryptionSuite::TestAead);
        assert!(suite.ensure_implemented().is_ok());
        assert!(suite.ensure_frame_suite().is_err());
        assert!(suite.is_encrypted());
        assert!(!suite.is_advertised());
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
