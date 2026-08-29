//! Canonical bytes a caller signs to prove possession of a DID's key.
//!
//! Lives in `jig-core` rather than in the server so that client and server
//! cannot drift into hashing different things — a drift that would present as
//! "every signature is invalid" with no indication of which side is wrong.
//!
//! # Domain separation
//!
//! The label below is load-bearing. Without it, a signature produced over a
//! request could potentially be replayed as a signature over some other
//! protocol artefact that happened to hash the same bytes. Every distinct thing
//! jig asks a key to sign gets its own label.

use blake3::Hash;

use crate::crypto::hash_labeled_parts;

/// Domain label for request authentication. Never reuse this for anything else,
/// and never sign a request without it.
const DOMAIN: &str = "jig-request-auth-v1";

/// Hash the canonical form of a request.
///
/// Every parameter is covered, and `hash_labeled_parts` length-prefixes each
/// field, so no two different requests can produce the same hash by shifting
/// bytes across a field boundary.
///
/// `body` is the exact bytes of the request body; pass `b""` for a body-less
/// request such as a GET.
pub fn canonical_request_hash(
    method: &str,
    path: &str,
    body: &[u8],
    hlc_wall_ms: u64,
    hlc_logical: u32,
    nonce: &str,
) -> Hash {
    hash_labeled_parts(&[
        ("domain", DOMAIN.as_bytes()),
        ("method", method.as_bytes()),
        ("path", path.as_bytes()),
        ("body", body),
        ("hlc_wall_ms", &hlc_wall_ms.to_le_bytes()),
        ("hlc_logical", &hlc_logical.to_le_bytes()),
        ("nonce", nonce.as_bytes()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field must change the hash. A field that does not is a field an
    /// attacker can alter freely while reusing a captured signature.
    #[test]
    fn every_field_is_covered_by_the_hash() {
        let base = canonical_request_hash("GET", "/api/v1/channels", b"", 1000, 0, "n1");

        assert_ne!(
            base,
            canonical_request_hash("POST", "/api/v1/channels", b"", 1000, 0, "n1"),
            "method must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash("GET", "/api/v1/blocks", b"", 1000, 0, "n1"),
            "path must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash("GET", "/api/v1/channels", b"x", 1000, 0, "n1"),
            "body must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash("GET", "/api/v1/channels", b"", 1001, 0, "n1"),
            "hlc wall_ms must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash("GET", "/api/v1/channels", b"", 1000, 1, "n1"),
            "hlc logical must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash("GET", "/api/v1/channels", b"", 1000, 0, "n2"),
            "nonce must be covered"
        );
    }

    /// The same inputs must always produce the same hash, or a client and a
    /// server on different machines could never agree.
    #[test]
    fn hashing_is_deterministic() {
        let a = canonical_request_hash("GET", "/x", b"body", 42, 7, "nonce");
        let b = canonical_request_hash("GET", "/x", b"body", 42, 7, "nonce");
        assert_eq!(a, b);
    }

    /// Field boundaries must be unambiguous. Without length prefixing,
    /// ("ab", "c") and ("a", "bc") would hash identically, letting an attacker
    /// shift bytes between path and nonce while keeping a captured signature
    /// valid.
    #[test]
    fn adjacent_fields_cannot_be_confused() {
        let a = canonical_request_hash("GET", "ab", b"", 1, 0, "c");
        let b = canonical_request_hash("GET", "a", b"", 1, 0, "bc");
        assert_ne!(a, b, "field boundaries must be unambiguous");
    }

    /// A request signature must not be usable under any other jig protocol that
    /// signs with the same key. The domain label is what guarantees it.
    ///
    /// Comparing against a bare `blake3_hash` of concatenated bytes would NOT
    /// test this — that differs for trivial reasons (length prefixing alone)
    /// and still passes if the domain label is deleted entirely. Instead,
    /// reconstruct the identical labelled parts with the domain omitted, and
    /// with a *different* domain, and require all three to differ. Deleting
    /// `DOMAIN` from the implementation then fails the first assertion.
    #[test]
    fn the_domain_label_is_load_bearing() {
        use crate::crypto::hash_labeled_parts;

        let (method, path, body, wall, logical, nonce) =
            ("GET", "/api/v1/channels", b"".as_slice(), 7u64, 0u32, "n1");

        let with_domain = canonical_request_hash(method, path, body, wall, logical, nonce);

        let parts_without_domain = [
            ("method", method.as_bytes()),
            ("path", path.as_bytes()),
            ("body", body),
            ("hlc_wall_ms", &wall.to_le_bytes()[..]),
            ("hlc_logical", &logical.to_le_bytes()[..]),
            ("nonce", nonce.as_bytes()),
        ];
        assert_ne!(
            with_domain,
            hash_labeled_parts(&parts_without_domain),
            "removing the domain label must change the hash — if this passes, \
             DOMAIN is not actually being mixed in"
        );

        // A hypothetical sibling protocol signing the same fields under its own
        // label must land somewhere else entirely.
        let mut other = vec![("domain", "jig-some-other-protocol-v1".as_bytes())];
        other.extend_from_slice(&parts_without_domain);
        assert_ne!(
            with_domain,
            hash_labeled_parts(&other),
            "a different domain must produce a different hash"
        );
    }
}
