//! Proof of possession for a REST read, as the server's tier-0 gate verifies
//! it: five headers carrying a signature over the canonical request hash.
//!
//! The hash and the header names both live in `jig-core`, so this module
//! cannot drift from the server on either — it only decides what to sign and
//! when.

use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use jig_core::request_auth::{canonical_request_hash, headers};

use crate::identity::Identity;

/// Nonces need only be UNIQUE among one DID's requests inside the server's
/// acceptance window, not unpredictable — the signature already provides
/// unforgeability, and the server records nonces per verified DID. A process
/// counter does that without a `rand` dependency, which `jig-client`
/// deliberately does not carry; the process id keeps two processes signing as
/// the same identity (a `jig chat` beside a `jig history`) from colliding in
/// the same millisecond.
///
/// One counter for every proof this process signs — REST reads and WSS
/// subscribes alike — so the two transports cannot hand the server the same
/// nonce in the same millisecond.
static NONCE_SEQ: AtomicU64 = AtomicU64::new(0);

/// A nonce no other proof from this process, or from another process on this
/// host, will repeat: wall-clock millisecond, process id, sequence number.
pub(crate) fn fresh_nonce(hlc_wall_ms: u64) -> String {
    format!(
        "{hlc_wall_ms}-{}-{}",
        std::process::id(),
        NONCE_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// A signed proof for one request. Sending the same proof twice is a replay,
/// and the server will refuse the second; sign every request afresh.
#[derive(Debug, Clone)]
pub struct ReadProof {
    pub did: String,
    pub hlc_wall_ms: u64,
    pub hlc_logical: u32,
    pub nonce: String,
    pub sig_b64: String,
}

impl ReadProof {
    /// Sign `method` + `path` as `identity`.
    ///
    /// `path` must be the path exactly as it will be sent — percent-encoding
    /// included, query string excluded — because that is what the server
    /// hashes on arrival. A mismatch presents as "signature invalid".
    pub fn sign(identity: &Identity, method: &str, path: &str) -> Self {
        let hlc_wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let nonce = fresh_nonce(hlc_wall_ms);
        let hash = canonical_request_hash(method, path, b"", hlc_wall_ms, 0, &nonce);
        Self {
            did: identity.did_string(),
            hlc_wall_ms,
            hlc_logical: 0,
            nonce,
            sig_b64: base64::engine::general_purpose::STANDARD
                .encode(identity.sign(hash.as_bytes()).to_bytes()),
        }
    }

    /// The proof as HTTP headers, in the names the server reads.
    pub fn headers(&self) -> [(&'static str, String); 5] {
        [
            (headers::DID, self.did.clone()),
            (headers::HLC_WALL_MS, self.hlc_wall_ms.to_string()),
            (headers::HLC_LOGICAL, self.hlc_logical.to_string()),
            (headers::NONCE, self.nonce.clone()),
            (headers::SIGNATURE, self.sig_b64.clone()),
        ]
    }
}

/// The path component of `url` in the form the server hashes: as sent, query
/// string excluded.
///
/// A helper rather than something callers derive by hand, because the one
/// way to get it wrong — signing the path with its query, or after decoding
/// `%23` back to `#` — fails on every request with no hint which side is
/// wrong.
pub fn signable_path(url: &str) -> &str {
    let after_scheme = url.find("://").map_or(url, |i| &url[i + 3..]);
    let path = after_scheme.find('/').map_or("/", |i| &after_scheme[i..]);
    path.split('?').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Verifier as _};

    fn identity() -> Identity {
        Identity::from_signing_key(SigningKey::from_bytes(&[7u8; 32]))
    }

    #[test]
    fn the_signature_verifies_over_the_canonical_hash() {
        let id = identity();
        let proof = ReadProof::sign(&id, "GET", "/api/v1/channels");
        let hash = canonical_request_hash(
            "GET",
            "/api/v1/channels",
            b"",
            proof.hlc_wall_ms,
            proof.hlc_logical,
            &proof.nonce,
        );
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&proof.sig_b64)
            .unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        id.public_key().verify(hash.as_bytes(), &sig).unwrap();
        assert_eq!(proof.did, id.did_string());
    }

    /// Two proofs for the same request must carry different nonces, or the
    /// server refuses the second as a replay.
    #[test]
    fn every_proof_gets_a_fresh_nonce() {
        let id = identity();
        let a = ReadProof::sign(&id, "GET", "/x");
        let b = ReadProof::sign(&id, "GET", "/x");
        assert_ne!(a.nonce, b.nonce);
    }

    /// Two processes on one host signing in the same millisecond must not
    /// mint the same nonce, so the process id is part of it.
    #[test]
    fn a_nonce_carries_the_process_id() {
        let nonce = fresh_nonce(1_000);
        assert!(
            nonce.starts_with(&format!("1000-{}-", std::process::id())),
            "{nonce}"
        );
    }

    #[test]
    fn headers_carry_the_five_values_under_the_server_names() {
        let proof = ReadProof::sign(&identity(), "GET", "/x");
        let h = proof.headers();
        assert_eq!(h[0], (headers::DID, proof.did.clone()));
        assert_eq!(h[3], (headers::NONCE, proof.nonce.clone()));
        assert_eq!(h[4], (headers::SIGNATURE, proof.sig_b64.clone()));
    }

    #[test]
    fn signable_path_is_the_encoded_path_without_the_query() {
        assert_eq!(
            signable_path("http://127.0.0.1:7117/api/v1/channels/%23hello/blocks?limit=100"),
            "/api/v1/channels/%23hello/blocks"
        );
        assert_eq!(
            signable_path("https://jig.onl/api/v1/channels"),
            "/api/v1/channels"
        );
        assert_eq!(signable_path("http://host:1"), "/");
    }
}
