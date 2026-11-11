//! Decentralised Identity (DID) primitives for the Jig protocol.
//!
//! DIDs are the canonical identity anchor for authors, recipients, and servers.
//! A canonical Jig DID is derived from an Ed25519 public key and encoded as
//! `did:jig:z<base32-nopad-lowercase>`: a literal `z`, then the 32-byte key in
//! RFC 4648 base32, lowercase and unpadded (52 characters). The `z` is a jig
//! version sigil, not a multibase prefix: in multibase `z` means base58btc, so a
//! generic multibase decoder misreads these DIDs.
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
//!
//! The 52-char base32-nopad-lowercase body encodes a 32-byte Ed25519 public key
//! (the all-zeros example above). Standard BASE32_NOPAD: `ceil(32 * 8 / 5) = 52` chars.
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
    /// The body decodes to a key, but not in the one spelling that key
    /// encodes to (lowercase). Two spellings of one key would compare unequal
    /// as strings, so signed data carrying one is refused; human input goes
    /// through [`Did::canonicalize`] instead.
    #[error("DID is not in its canonical lowercase spelling")]
    NotLowercase,
}

impl Did {
    /// Create a canonical `did:jig:z<base32>` DID from an Ed25519 public key.
    pub fn from_ed25519_pubkey(pubkey: &[u8; 32]) -> Self {
        // BASE32_NOPAD produces uppercase; we lowercase it for readability.
        let body = BASE32_NOPAD.encode(pubkey).to_lowercase();
        Self(format!("did:jig:z{body}"))
    }

    /// Returns the 32-byte ed25519 public key embedded in a canonical `did:jig:z<base32>` DID.
    ///
    /// Error semantics (callers handling identity must distinguish these):
    /// - [`DidError::NotCanonical`] — this DID string does not begin with `did:jig:z`
    ///   (e.g. a legacy DID like `did:jig:alice`). Such DIDs cannot be decoded to
    ///   pubkey bytes and are treated as opaque labels.
    /// - [`DidError::BadEncoding`] — the `did:jig:z` prefix is present but the body
    ///   is not valid base32-nopad.
    /// - [`DidError::WrongLength`] — the `did:jig:z` prefix is present and the body
    ///   decodes, but the result is not exactly 32 bytes.
    ///
    /// - [`DidError::NotLowercase`] — the body decodes to a key, but is not
    ///   spelled the way that key encodes (an upper-cased body, say).
    ///
    /// Note: a z-prefixed-but-corrupted DID returns `BadEncoding` or `WrongLength`,
    /// NOT `NotCanonical`. Callers that pattern-match on `NotCanonical` to "fall back
    /// to opaque-label handling" will miss z-prefixed corrupted DIDs — those are
    /// genuine errors and should be rejected, not treated as legacy labels.
    pub fn as_bytes(&self) -> Result<[u8; 32], DidError> {
        let body = self
            .0
            .strip_prefix("did:jig:z")
            .ok_or(DidError::NotCanonical)?;
        let key = decode_body(body)?;
        if Self::from_ed25519_pubkey(&key).0 != self.0 {
            return Err(DidError::NotLowercase);
        }
        Ok(key)
    }

    /// Return the full `did:jig:…` string representation.
    pub fn to_did_jig_string(&self) -> String {
        self.0.clone()
    }

    /// Parse a canonical `did:jig:z<base32>` string into a [`Did`].
    ///
    /// Only accepts the canonical key-derived form. Use `From<&str>` for
    /// accepting arbitrary DID strings (including legacy forms).
    /// A key spelled any other way is refused with [`DidError::NotLowercase`].
    pub fn from_did_jig_string(s: &str) -> Result<Self, DidError> {
        let body = s.strip_prefix("did:jig:z").ok_or(DidError::BadPrefix)?;
        let did = Self::from_ed25519_pubkey(&decode_body(body)?);
        if did.0 != s {
            return Err(DidError::NotLowercase);
        }
        Ok(did)
    }

    /// Parse a DID a person typed or configured: surrounding whitespace is
    /// dropped and the body may be in any letter case. Returns the canonical
    /// DID for the key.
    ///
    /// Only for human input (command-line arguments, operator config). A DID
    /// inside signed data must already be canonical: use
    /// [`Did::from_did_jig_string`], which refuses any other spelling.
    pub fn canonicalize(s: &str) -> Result<Self, DidError> {
        let body = s
            .trim()
            .strip_prefix("did:jig:z")
            .ok_or(DidError::BadPrefix)?;
        Ok(Self::from_ed25519_pubkey(&decode_body(body)?))
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

/// Decode a DID body in either letter case to its 32-byte key.
fn decode_body(body: &str) -> Result<[u8; 32], DidError> {
    let bytes = BASE32_NOPAD
        .decode(body.to_uppercase().as_bytes())
        .map_err(|_| DidError::BadEncoding)?;
    bytes.try_into().map_err(|_| DidError::WrongLength)
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

/// The key behind [`log_tag`], set once per process by [`set_log_tag_key`].
static LOG_TAG_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// Key [`log_tag`] with a value derived from the server's signing-key seed
/// (BLAKE3 `derive_key`, context `jig-log-did-v1`), so tags are stable
/// across restarts of one server but cannot be reversed by hashing a list of
/// public DIDs, nor linked across servers. Call once at startup, before
/// anything logs. The key is process-wide and set once: returns `true` when
/// the key in effect is this seed's (newly set, or set before from the same
/// seed), and `false` when an earlier, different key stays in effect.
pub fn set_log_tag_key(seed: &[u8; 32]) -> bool {
    let key = blake3::derive_key("jig-log-did-v1", seed);
    *LOG_TAG_KEY.get_or_init(|| key) == key
}

/// A process-random key, used when nothing called [`set_log_tag_key`]: tags
/// then correlate within one run only, and still never fall back to an
/// unkeyed, reversible hash.
fn random_log_tag_key() -> [u8; 32] {
    use std::hash::{BuildHasher, Hasher};
    let mut key = [0u8; 32];
    for chunk in key.chunks_mut(8) {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u8(0);
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    key
}

fn log_tag_with(key: &[u8; 32], did: &str) -> String {
    hex::encode(&blake3::keyed_hash(key, did.as_bytes()).as_bytes()[..6])
}

/// A short, stable tag for a DID in logs: the first 12 hex digits of a keyed
/// BLAKE3 hash of the DID. Lines about one DID correlate, but the DID itself
/// is never written (zero-trust, "Logging and metadata retention"), and
/// without the server's key a tag cannot be matched to a DID.
pub fn log_tag(did: &str) -> String {
    log_tag_with(LOG_TAG_KEY.get_or_init(random_log_tag_key), did)
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

    #[test]
    fn did_jig_is_stable_across_versions() {
        // GOLDEN — protocol-level wire-format anchor.
        // If this assertion changes, every receipt fixture in every test in
        // the project must be regenerated. Treat any change here as a
        // breaking protocol-version bump.
        let did = Did::from_ed25519_pubkey(&[0u8; 32]);
        assert_eq!(
            did.to_did_jig_string(),
            "did:jig:zaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn did_as_bytes_z_prefix_short_body_is_not_not_canonical() {
        // A z-prefixed DID with a body too short to decode to 32 bytes
        // must NOT return NotCanonical (NotCanonical is reserved for
        // non-z-prefixed legacy DIDs). It should return BadEncoding or
        // WrongLength — a callers-must-reject error, not a legacy-label
        // fallback signal.
        let did: Did = "did:jig:zdj".into();
        let err = did.as_bytes().unwrap_err();
        assert!(
            !matches!(err, DidError::NotCanonical),
            "z-prefixed corrupted DID returned NotCanonical, which would let \
             callers silently fall back to legacy-label handling. err: {err:?}"
        );
    }

    #[test]
    fn one_key_has_one_spelling() {
        let did = Did::from_ed25519_pubkey(&[42u8; 32]).to_did_jig_string();
        let body = &did["did:jig:z".len()..];
        let shouted = format!("did:jig:z{}", body.to_uppercase());
        let mixed = format!("did:jig:z{}{}", body[..1].to_uppercase(), &body[1..]);
        for other in [&shouted, &mixed] {
            assert!(matches!(
                Did::from_did_jig_string(other),
                Err(DidError::NotLowercase)
            ));
            assert!(matches!(
                Did::from_str_unchecked(other.as_str()).as_bytes(),
                Err(DidError::NotLowercase)
            ));
            // A person may type it that way; the result is the one spelling.
            assert_eq!(Did::canonicalize(other).unwrap().to_did_jig_string(), did);
        }
        assert_eq!(
            Did::canonicalize(&format!("  {did}\n"))
                .unwrap()
                .to_did_jig_string(),
            did
        );
        assert!(Did::canonicalize("did:jig:alice").is_err());
        assert!(Did::canonicalize("DID:JIG:Z").is_err());
    }

    #[test]
    fn log_tags_hide_the_did_but_correlate_it() {
        let a = "did:jig:zaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "did:jig:zbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let tag = log_tag(a);
        assert_eq!(tag, log_tag(a), "the same DID always gets the same tag");
        assert_ne!(tag, log_tag(b));
        assert_eq!(tag.len(), 12);
        assert!(!tag.contains("did:jig"), "a tag never carries the DID");
    }

    #[test]
    fn log_tags_need_the_key() {
        let a = "did:jig:zaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let k1 = blake3::derive_key("jig-log-did-v1", &[1; 32]);
        let k2 = blake3::derive_key("jig-log-did-v1", &[2; 32]);
        assert_eq!(log_tag_with(&k1, a), log_tag_with(&k1, a));
        // Another server's key gives another tag, so tags don't link servers.
        assert_ne!(log_tag_with(&k1, a), log_tag_with(&k2, a));
        // Nor does the old public, unkeyed construction reproduce it.
        let unkeyed = crate::crypto::hash_labeled_parts(&[
            ("domain", b"jig-log-did-v1"),
            ("did", a.as_bytes()),
        ]);
        assert_ne!(log_tag_with(&k1, a), hex::encode(&unkeyed.as_bytes()[..6]));
        assert_ne!(random_log_tag_key(), random_log_tag_key());
    }
}
