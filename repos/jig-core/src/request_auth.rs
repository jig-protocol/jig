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
//!
//! # Audience
//!
//! A proof names the server it is addressed to (its DID, as the client pinned
//! it for the base URL it sends to) and the server verifies against its own
//! DID. So a proof made for one server does not verify at another, even on the
//! same path inside the freshness window. JEP-0015 §"Request proofs" is the
//! normative text; the vectors are in `repos/jig-spec/jep/vectors/0015/`.

use blake3::Hash;

use crate::crypto::hash_labeled_parts;

/// Domain label for request authentication. Never reuse this for anything else,
/// and never sign a request without it.
///
/// `v2` binds the audience and the signer's DID. `v1` bound neither and is no
/// longer accepted; a COSE successor is reserved as `jig-request-auth-v3`
/// (JEP-0013 §3.3).
pub const DOMAIN: &str = "jig-request-auth-v2";

/// The name a server lists, in its welcome's capabilities and at
/// `/.well-known/jig`, for each request-proof version it accepts. The same
/// string as [`DOMAIN`]: the version is the domain.
pub const VERSION: &str = DOMAIN;

/// The most bytes a request-proof nonce may have, as for admission and PoW
/// nonces ([`crate::pow::MAX_NONCE_LEN`]). A server refuses a longer one
/// before verifying anything, so it is never recorded.
pub const MAX_NONCE_LEN: usize = 64;

/// Header names carrying a proof over HTTP: the six values the server
/// verifies, exactly as [`canonical_request_hash`] consumes them.
///
/// Defined here, beside the hash, so a client signing a request and a server
/// verifying one read the same names from the same place. HTTP-specific by
/// necessity; the verification is not, which is what keeps the design
/// transport-agnostic — a future SSH or gRPC transport carries the same
/// values however it can.
pub mod headers {
    pub const DID: &str = "x-jig-did";
    /// The server DID the proof is addressed to. Its presence marks a v2
    /// proof; a proof without it is a v1 proof, which is refused.
    pub const AUDIENCE: &str = "x-jig-audience";
    pub const HLC_WALL_MS: &str = "x-jig-hlc-wall-ms";
    pub const HLC_LOGICAL: &str = "x-jig-hlc-logical";
    pub const NONCE: &str = "x-jig-nonce";
    pub const SIGNATURE: &str = "x-jig-signature";
}

/// Error codes a server answers a refused proof with, where the client has
/// something to do about it. Here, beside the hash, so the server that sends
/// them and the client that acts on them read one spelling.
pub mod refusal {
    /// The proof's audience is not the server's current DID. The client
    /// re-handshakes (moving its pin along any key links), and retries once
    /// with a freshly signed proof.
    pub const WRONG_AUDIENCE: &str = "WRONG_AUDIENCE";
    /// The proof is in a version the server does not accept (v1).
    pub const PROOF_VERSION_UNSUPPORTED: &str = "PROOF_VERSION_UNSUPPORTED";
}

/// Hash the canonical form of a request.
///
/// Every parameter is covered, and `hash_labeled_parts` length-prefixes each
/// field, so no two different requests can produce the same hash by shifting
/// bytes across a field boundary.
///
/// `audience` is the DID of the server the request is sent to and `did` the
/// signer's; both in canonical form (`Did::canonicalize`), since a re-cased
/// spelling hashes differently. `body` is the exact bytes of the request body;
/// pass `b""` for a body-less request such as a GET.
#[allow(clippy::too_many_arguments)]
pub fn canonical_request_hash(
    audience: &str,
    did: &str,
    method: &str,
    path: &str,
    body: &[u8],
    hlc_wall_ms: u64,
    hlc_logical: u32,
    nonce: &str,
) -> Hash {
    hash_labeled_parts(&[
        ("domain", DOMAIN.as_bytes()),
        ("audience", audience.as_bytes()),
        ("did", did.as_bytes()),
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

    const A: &str = "did:jig:zaudience";
    const D: &str = "did:jig:zsigner";

    fn base() -> Hash {
        canonical_request_hash(A, D, "GET", "/api/v1/channels", b"", 1000, 0, "n1")
    }

    /// Every field must change the hash. A field that does not is a field an
    /// attacker can alter freely while reusing a captured signature.
    #[test]
    fn every_field_is_covered_by_the_hash() {
        let base = base();
        let p = "/api/v1/channels";

        assert_ne!(
            base,
            canonical_request_hash("did:jig:zother", D, "GET", p, b"", 1000, 0, "n1"),
            "audience must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash(A, "did:jig:zother", "GET", p, b"", 1000, 0, "n1"),
            "signer DID must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash(A, D, "POST", p, b"", 1000, 0, "n1"),
            "method must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash(A, D, "GET", "/api/v1/blocks", b"", 1000, 0, "n1"),
            "path must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash(A, D, "GET", p, b"x", 1000, 0, "n1"),
            "body must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash(A, D, "GET", p, b"", 1001, 0, "n1"),
            "hlc wall_ms must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash(A, D, "GET", p, b"", 1000, 1, "n1"),
            "hlc logical must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash(A, D, "GET", p, b"", 1000, 0, "n2"),
            "nonce must be covered"
        );
    }

    /// The same inputs must always produce the same hash, or a client and a
    /// server on different machines could never agree.
    #[test]
    fn hashing_is_deterministic() {
        let a = canonical_request_hash(A, D, "GET", "/x", b"body", 42, 7, "nonce");
        let b = canonical_request_hash(A, D, "GET", "/x", b"body", 42, 7, "nonce");
        assert_eq!(a, b);
    }

    /// Field boundaries must be unambiguous. Without length prefixing,
    /// ("ab", "c") and ("a", "bc") would hash identically, letting an attacker
    /// shift bytes between fields while keeping a captured signature valid —
    /// audience into signer included.
    #[test]
    fn adjacent_fields_cannot_be_confused() {
        let a = canonical_request_hash(A, D, "GET", "ab", b"", 1, 0, "c");
        let b = canonical_request_hash(A, D, "GET", "a", b"", 1, 0, "bc");
        assert_ne!(a, b, "field boundaries must be unambiguous");
        let c = canonical_request_hash("did:jig:za", "did:jig:zbc", "GET", "/", b"", 1, 0, "n");
        let d = canonical_request_hash("did:jig:zab", "did:jig:zc", "GET", "/", b"", 1, 0, "n");
        assert_ne!(c, d, "audience and signer must not run together");
    }

    /// The parts as the function hashes them, rebuilt by hand, so the tests
    /// below can delete one and show the implementation depends on it.
    fn parts<'a>(
        domain: &'a str,
        audience: Option<&'a str>,
        did: Option<&'a str>,
        wall: &'a [u8; 8],
        logical: &'a [u8; 4],
    ) -> Vec<(&'static str, &'a [u8])> {
        let mut out = vec![("domain", domain.as_bytes())];
        if let Some(a) = audience {
            out.push(("audience", a.as_bytes()));
        }
        if let Some(d) = did {
            out.push(("did", d.as_bytes()));
        }
        out.extend_from_slice(&[
            ("method", b"GET".as_slice()),
            ("path", b"/api/v1/channels".as_slice()),
            ("body", b"".as_slice()),
            ("hlc_wall_ms", wall.as_slice()),
            ("hlc_logical", logical.as_slice()),
            ("nonce", b"n1".as_slice()),
        ]);
        out
    }

    /// A request signature must not be usable under any other jig protocol that
    /// signs with the same key. The domain label is what guarantees it.
    ///
    /// Comparing against a bare `blake3_hash` of concatenated bytes would NOT
    /// test this — that differs for trivial reasons (length prefixing alone)
    /// and still passes if the domain label is deleted entirely. Instead,
    /// reconstruct the identical labelled parts, check they reproduce the
    /// hash exactly, then require that omitting or changing the domain
    /// changes it. Deleting `DOMAIN` from the implementation fails the first
    /// assertion.
    #[test]
    fn the_domain_label_is_load_bearing() {
        let (wall, logical) = (1000u64.to_le_bytes(), 0u32.to_le_bytes());
        let full = parts(DOMAIN, Some(A), Some(D), &wall, &logical);
        assert_eq!(
            base(),
            hash_labeled_parts(&full),
            "the hand-built parts must be exactly what the function hashes"
        );
        let without: Vec<_> = full[1..].to_vec();
        assert_ne!(
            base(),
            hash_labeled_parts(&without),
            "DOMAIN must be mixed in"
        );
        let other = parts(
            "jig-some-other-protocol-v1",
            Some(A),
            Some(D),
            &wall,
            &logical,
        );
        assert_ne!(
            base(),
            hash_labeled_parts(&other),
            "a different domain must differ"
        );
    }

    /// The mutation check for #464: the audience and the signer DID must each
    /// be in what the function hashes. The exact-match assertion in
    /// [`the_domain_label_is_load_bearing`] fails if either is deleted from
    /// the implementation; this shows the hand-built parts without one hash
    /// elsewhere, so that assertion cannot pass by accident.
    #[test]
    fn audience_and_signer_are_load_bearing() {
        let (wall, logical) = (1000u64.to_le_bytes(), 0u32.to_le_bytes());
        assert_ne!(
            base(),
            hash_labeled_parts(&parts(DOMAIN, None, Some(D), &wall, &logical)),
            "removing the audience must change the hash"
        );
        assert_ne!(
            base(),
            hash_labeled_parts(&parts(DOMAIN, Some(A), None, &wall, &logical)),
            "removing the signer DID must change the hash"
        );
    }

    /// The v1 layout, computed here only so the vectors can show v1 and v2
    /// differ for the same request. No code path accepts v1.
    fn v1_hash(
        method: &str,
        path: &str,
        body: &[u8],
        wall: u64,
        logical: u32,
        nonce: &str,
    ) -> Hash {
        hash_labeled_parts(&[
            ("domain", b"jig-request-auth-v1".as_slice()),
            ("method", method.as_bytes()),
            ("path", path.as_bytes()),
            ("body", body),
            ("hlc_wall_ms", &wall.to_le_bytes()),
            ("hlc_logical", &logical.to_le_bytes()),
            ("nonce", nonce.as_bytes()),
        ])
    }

    #[test]
    fn v1_and_v2_differ_for_the_same_request() {
        assert_ne!(
            base().as_bytes(),
            v1_hash("GET", "/api/v1/channels", b"", 1000, 0, "n1").as_bytes()
        );
    }

    #[cfg(feature = "ed25519")]
    mod vectors {
        use super::*;
        use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

        use crate::did::Did;

        /// Fixed keys: the signer is seed 0x01…, the audience server 0x02….
        fn keys() -> (SigningKey, Did, Did) {
            let signer = SigningKey::from_bytes(&[1u8; 32]);
            let server = SigningKey::from_bytes(&[2u8; 32]);
            let did = Did::from_ed25519_pubkey(signer.verifying_key().as_bytes());
            let aud = Did::from_ed25519_pubkey(server.verifying_key().as_bytes());
            (signer, did, aud)
        }

        /// The cases: a body-less GET, a POST with a body, and a WS
        /// subscribe (method `SUBSCRIBE`, the scope's canonical string as
        /// the path).
        fn cases() -> Vec<(&'static str, &'static str, &'static str, &'static [u8])> {
            vec![
                ("get", "GET", "/api/v1/channels/general/blocks", b""),
                (
                    "post_with_body",
                    "POST",
                    "/api/v1/blocks",
                    b"{\"kind\":\"text\"}",
                ),
                ("subscribe", "SUBSCRIBE", "channel:general", b""),
            ]
        }

        const WALL: u64 = 1_790_000_000_000;
        const LOGICAL: u32 = 3;
        const NONCE: &str = "1790000000000-42-0";

        fn vectors() -> serde_json::Value {
            let (signer, did, aud) = keys();
            let mut out = serde_json::Map::new();
            out.insert("domain".into(), DOMAIN.into());
            out.insert("signer_seed_hex".into(), hex::encode([1u8; 32]).into());
            out.insert("audience_seed_hex".into(), hex::encode([2u8; 32]).into());
            out.insert("did".into(), did.as_str().into());
            out.insert("audience".into(), aud.as_str().into());
            out.insert("hlc_wall_ms".into(), WALL.into());
            out.insert("hlc_logical".into(), LOGICAL.into());
            out.insert("nonce".into(), NONCE.into());
            for (name, method, path, body) in cases() {
                let hash = canonical_request_hash(
                    aud.as_str(),
                    did.as_str(),
                    method,
                    path,
                    body,
                    WALL,
                    LOGICAL,
                    NONCE,
                );
                let sig = signer.sign(hash.as_bytes());
                out.insert(
                    name.into(),
                    serde_json::json!({
                        "method": method,
                        "path": path,
                        "body_hex": hex::encode(body),
                        "hash_hex": hex::encode(hash.as_bytes()),
                        "signature_hex": hex::encode(sig.to_bytes()),
                        "v1_hash_hex": hex::encode(
                            v1_hash(method, path, body, WALL, LOGICAL, NONCE).as_bytes()
                        ),
                    }),
                );
            }
            serde_json::Value::Object(out)
        }

        fn hex32(v: &serde_json::Value) -> [u8; 32] {
            hex::decode(v.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        }

        #[test]
        fn hashes_match_the_committed_vectors() {
            let v: serde_json::Value = serde_json::from_str(include_str!(
                "../../jig-spec/jep/vectors/0015/request-auth-v2.json"
            ))
            .unwrap();
            assert_eq!(vectors(), v);
            let key = keys().0.verifying_key();
            for (name, ..) in cases() {
                let case = &v[name];
                assert_ne!(
                    case["hash_hex"], case["v1_hash_hex"],
                    "{name}: v1 and v2 differ"
                );
                let sig: [u8; 64] = hex::decode(case["signature_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let sig = ed25519_dalek::Signature::from_bytes(&sig);
                key.verify_strict(&hex32(&case["hash_hex"]), &sig).unwrap();
                // And not under the v1 hash of the same request.
                assert!(key.verify(&hex32(&case["v1_hash_hex"]), &sig).is_err());
            }
        }

        /// `cargo test -p jig-core --features ed25519 request_auth::tests::vectors::print_vectors -- --ignored --nocapture`
        #[test]
        #[ignore]
        fn print_vectors() {
            println!("{}", serde_json::to_string_pretty(&vectors()).unwrap());
        }
    }
}
