//! Decentralised Identity (DID) primitives for the Jig protocol.
//!
//! DIDs are the canonical identity anchor for authors, recipients, and servers.
//! A canonical Jig DID is derived from an Ed25519 public key and encoded as
//! `did:jig:z<base32-nopad-lowercase>`, where the `z` is the multibase prefix
//! for base32upper (repurposed here as a versioning sigil for jig-native DIDs).
//!
//! Legacy or test DIDs (e.g. `did:jig:alice123`) are accepted on input but
//! cannot be decoded to bytes; they round-trip through their string form.
//!
//! ## Wire format
//!
//! The [`Did`] type serialises/deserialises as a plain JSON string so that
//! existing manifest and receipt fixtures remain valid:
//! ```json
//! { "did": "did:jig:zaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
//! ```

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;
use std::ops::Deref;
use thiserror::Error;

/// A Jig DID — either a canonical `did:jig:z<base32>` key-derived identifier
/// or a legacy/test string identifier.
///
/// Derives from an Ed25519 public key via [`Did::from_ed25519_pubkey`].
/// Legacy string DIDs are created with [`Did::from_str_unchecked`] (or via
/// `From<&str>` / `From<String>`).
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct Did(String);

/// Errors produced by DID encoding/decoding helpers.
#[derive(Debug, Error)]
pub enum DidError {
    /// String does not start with `did:jig:z`.
    #[error("DID must start with `did:jig:z`")]
    BadPrefix,
    /// The base32 body after the prefix is not valid.
    #[error("DID body is not valid base32")]
    BadEncoding,
    /// Decoded bytes are not exactly 32 bytes (not an Ed25519 key).
    #[error("decoded DID is not 32 bytes")]
    WrongLength,
    /// DID is not in canonical key-derived form and cannot provide raw bytes.
    #[error("DID is not a canonical key-derived `did:jig:z…` identifier")]
    NotCanonical,
}

impl Did {
    /// Create a canonical `did:jig:z<base32>` DID from an Ed25519 public key.
    pub fn from_ed25519_pubkey(pubkey: &[u8; 32]) -> Self {
        // BASE32_NOPAD produces uppercase; we lowercase it for readability.
        let body = BASE32_NOPAD.encode(pubkey).to_lowercase();
        Self(format!("did:jig:z{body}"))
    }

    /// Return the raw 32-byte public key for a canonical `did:jig:z…` DID.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::NotCanonical`] if this DID was not created from
    /// a public key (e.g. it is a legacy test DID like `did:jig:alice`).
    pub fn as_bytes(&self) -> Result<[u8; 32], DidError> {
        let body = self
            .0
            .strip_prefix("did:jig:z")
            .ok_or(DidError::NotCanonical)?;
        let bytes = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|_| DidError::BadEncoding)?;
        if bytes.len() != 32 {
            return Err(DidError::WrongLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Return the full `did:jig:…` string representation.
    pub fn to_did_jig_string(&self) -> String {
        self.0.clone()
    }

    /// Parse a canonical `did:jig:z<base32>` string into a [`Did`].
    ///
    /// Only accepts the canonical key-derived form. Use `From<&str>` for
    /// accepting arbitrary DID strings (including legacy forms).
    pub fn from_did_jig_string(s: &str) -> Result<Self, DidError> {
        let body = s.strip_prefix("did:jig:z").ok_or(DidError::BadPrefix)?;
        let bytes = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|_| DidError::BadEncoding)?;
        if bytes.len() != 32 {
            return Err(DidError::WrongLength);
        }
        Ok(Self(s.to_string()))
    }

    /// Create a Did directly from any string without validation.
    ///
    /// Intended for legacy strings and test helpers. Prefer
    /// [`Did::from_ed25519_pubkey`] for production code.
    pub fn from_str_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Return the inner DID string as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derive a deterministic Did from any test-label string via blake3.
    ///
    /// The resulting DID is in canonical `did:jig:z…` form so it supports
    /// [`Did::as_bytes`]. Do not use in production — only in `#[cfg(test)]`
    /// code to avoid allocating real key material.
    #[cfg(test)]
    pub fn from_test_string(s: &str) -> Self {
        let hash = crate::blake3_hash(s.as_bytes());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(hash.as_bytes());
        Self::from_ed25519_pubkey(&arr)
    }
}

// ── Conversions ────────────────────────────────────────────────────────────

impl From<&str> for Did {
    fn from(s: &str) -> Self {
        Self::from_str_unchecked(s)
    }
}

impl From<String> for Did {
    fn from(s: String) -> Self {
        Self::from_str_unchecked(s)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for Did {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq<str> for Did {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Did {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Did {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl PartialOrd for Did {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Did {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

// ── Serde: round-trips as a plain JSON string ──────────────────────────────

impl Serialize for Did {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Err(de::Error::custom("DID must not be empty"));
        }
        Ok(Self(s))
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_jig_roundtrip() {
        let pubkey = [42u8; 32];
        let did = Did::from_ed25519_pubkey(&pubkey);
        let s = did.to_did_jig_string();
        assert!(s.starts_with("did:jig:"));
        let parsed = Did::from_did_jig_string(&s).unwrap();
        assert_eq!(parsed, did);
    }

    #[test]
    fn did_jig_rejects_bad_prefix() {
        assert!(Did::from_did_jig_string("did:web:example.com").is_err());
        assert!(Did::from_did_jig_string("foo").is_err());
    }

    #[test]
    fn did_jig_pubkey_round_trips() {
        let pubkey = [42u8; 32];
        let did = Did::from_ed25519_pubkey(&pubkey);
        // as_bytes() succeeds only for canonical key-derived DIDs.
        assert_eq!(did.as_bytes().unwrap(), pubkey);
    }

    #[test]
    fn did_legacy_from_str_roundtrips_as_string() {
        let did: Did = "did:jig:alice123".into();
        assert_eq!(did.to_did_jig_string(), "did:jig:alice123");
        // Legacy DIDs cannot provide raw bytes.
        assert!(did.as_bytes().is_err());
    }

    #[test]
    fn did_serde_roundtrip_canonical() {
        let pubkey = [1u8; 32];
        let did = Did::from_ed25519_pubkey(&pubkey);
        let json = serde_json::to_string(&did).unwrap();
        let parsed: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, did);
    }

    #[test]
    fn did_serde_accepts_legacy_string() {
        let json = r#""did:jig:alice123""#;
        let did: Did = serde_json::from_str(json).unwrap();
        assert_eq!(did, "did:jig:alice123");
    }

    #[test]
    fn did_deref_to_str() {
        let did: Did = "did:jig:test".into();
        assert!(did.starts_with("did:jig:"));
    }

    #[test]
    fn did_from_test_string_is_canonical() {
        let did = Did::from_test_string("server-a");
        // Must be parseable as canonical and round-trip bytes.
        let bytes = did.as_bytes().unwrap();
        let did2 = Did::from_ed25519_pubkey(&bytes);
        assert_eq!(did, did2);
    }

    #[test]
    fn did_ordering_is_lexicographic() {
        let a: Did = "did:jig:aaa".into();
        let b: Did = "did:jig:bbb".into();
        assert!(a < b);
    }
}
