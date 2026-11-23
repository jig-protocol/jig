//! Proof of possession for a REST request, as the server's tier-0 gate
//! verifies it: six headers carrying a signature over the canonical request
//! hash, addressed to the server it is sent to.
//!
//! The hash and the header names both live in `jig-core`, so this module
//! cannot drift from the server on either — it only decides what to sign and
//! when.
//!
//! # Audience
//!
//! Every proof names the server it is for: the DID this device pinned for the
//! base URL, or one a signed welcome just proved. [`audience_of`] takes it
//! from a verified welcome, and refuses a server that does not list
//! `jig-request-auth-v2`: an older one would hash the request without the
//! audience, and this client never signs the older version.

use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use jig_core::Did;
use jig_core::request_auth::{VERSION, canonical_request_hash, headers};
use jig_pipeline::handshake::VerifiedWelcome;

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

/// A server this client will not sign a request proof for.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AudienceError {
    /// Its welcome does not list `jig-request-auth-v2`. It would verify the
    /// older, unbound proof, which this client does not make.
    #[error("{server_did} does not support {VERSION}; upgrade the server")]
    Unsupported { server_did: String },
    /// Its DID is not one a request can be addressed to.
    #[error("{server_did} is not a DID a request proof can be addressed to")]
    BadDid { server_did: String },
}

/// The audience for request proofs to the server that signed `welcome`: its
/// DID, in canonical form, once the welcome lists `jig-request-auth-v2`.
///
/// The welcome is verified, and the handshake held its DID to this device's
/// pin, so this is the DID the client pinned for the base URL.
pub fn audience_of(welcome: &VerifiedWelcome) -> Result<String, AudienceError> {
    if !welcome
        .capabilities
        .request_auth
        .iter()
        .any(|v| v == VERSION)
    {
        return Err(AudienceError::Unsupported {
            server_did: welcome.server_did.clone(),
        });
    }
    canonical_audience(&welcome.server_did)
}

/// `did` in the spelling a proof must sign it in.
pub fn canonical_audience(did: &str) -> Result<String, AudienceError> {
    Did::canonicalize(did)
        .map(|d| d.as_str().to_string())
        .map_err(|_| AudienceError::BadDid {
            server_did: did.to_string(),
        })
}

/// A signed proof for one request. Sending the same proof twice is a replay,
/// and the server will refuse the second; sign every request afresh,
/// including a retry.
#[derive(Debug, Clone)]
pub struct ReadProof {
    pub did: String,
    /// The DID of the server the proof is for.
    pub audience: String,
    pub hlc_wall_ms: u64,
    pub hlc_logical: u32,
    pub nonce: String,
    pub sig_b64: String,
}

impl ReadProof {
    /// Sign `method` + `path` as `identity`, for the server whose DID is
    /// `audience` ([`audience_of`]).
    ///
    /// `path` must be the path exactly as it will be sent — percent-encoding
    /// included, query string excluded — because that is what the server
    /// hashes on arrival. A mismatch presents as "signature invalid".
    pub fn sign(identity: &Identity, audience: &str, method: &str, path: &str) -> Self {
        Self::sign_body(identity, audience, method, path, b"")
    }

    /// [`Self::sign`] over a request with a body: the proof covers `body`'s
    /// exact bytes, so it cannot be replayed with another body. Send those
    /// bytes unchanged.
    pub fn sign_body(
        identity: &Identity,
        audience: &str,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Self {
        let hlc_wall_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let nonce = fresh_nonce(hlc_wall_ms);
        let did = identity.did_string();
        let hash =
            canonical_request_hash(audience, &did, method, path, body, hlc_wall_ms, 0, &nonce);
        Self {
            did,
            audience: audience.to_string(),
            hlc_wall_ms,
            hlc_logical: 0,
            nonce,
            sig_b64: base64::engine::general_purpose::STANDARD
                .encode(identity.sign(hash.as_bytes()).to_bytes()),
        }
    }

    /// The proof as HTTP headers, in the names the server reads.
    pub fn headers(&self) -> [(&'static str, String); 6] {
        [
            (headers::DID, self.did.clone()),
            (headers::AUDIENCE, self.audience.clone()),
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
    use ed25519_dalek::SigningKey;

    fn identity() -> Identity {
        Identity::from_signing_key(SigningKey::from_bytes(&[7u8; 32]))
    }

    fn server() -> String {
        Identity::from_signing_key(SigningKey::from_bytes(&[9u8; 32])).did_string()
    }

    #[test]
    fn the_signature_verifies_over_the_canonical_hash() {
        let id = identity();
        let proof = ReadProof::sign(&id, &server(), "GET", "/api/v1/channels");
        let hash = canonical_request_hash(
            &server(),
            &id.did_string(),
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
        id.public_key()
            .verify_strict(hash.as_bytes(), &sig)
            .unwrap();
        assert_eq!(proof.audience, server());
        assert_eq!(proof.did, id.did_string());
    }

    /// Two proofs for the same request must carry different nonces, or the
    /// server refuses the second as a replay.
    #[test]
    fn every_proof_gets_a_fresh_nonce() {
        let id = identity();
        let a = ReadProof::sign(&id, &server(), "GET", "/x");
        let b = ReadProof::sign(&id, &server(), "GET", "/x");
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
    fn headers_carry_the_six_values_under_the_server_names() {
        let proof = ReadProof::sign(&identity(), &server(), "GET", "/x");
        let h = proof.headers();
        assert_eq!(h[0], (headers::DID, proof.did.clone()));
        assert_eq!(h[1], (headers::AUDIENCE, server()));
        assert_eq!(h[4], (headers::NONCE, proof.nonce.clone()));
        assert_eq!(h[5], (headers::SIGNATURE, proof.sig_b64.clone()));
    }

    fn welcome(request_auth: Vec<String>, server_did: String) -> VerifiedWelcome {
        VerifiedWelcome {
            server_did,
            version: 1,
            suites: vec!["none".into()],
            capabilities: jig_pipeline::handshake::Capabilities {
                request_auth,
                ..Default::default()
            },
            reputation: jig_pipeline::handshake::Reputation::none(),
            nonce: String::new(),
            server_nonce: String::new(),
            tls_exporter: Vec::new(),
            manifest: None,
            admit: None,
            ruleset: None,
            moved_from: None,
            evidence: String::new(),
        }
    }

    /// A server whose welcome does not list v2 gets no proof: the client
    /// refuses before signing, and never falls back to v1.
    #[test]
    fn a_server_without_v2_is_refused_before_signing() {
        let err = audience_of(&welcome(vec![], server())).unwrap_err();
        assert!(matches!(err, AudienceError::Unsupported { .. }));
        assert!(
            err.to_string()
                .contains("does not support jig-request-auth-v2; upgrade the server"),
            "{err}"
        );
        let other = audience_of(&welcome(vec!["jig-request-auth-v1".into()], server()));
        assert!(matches!(other, Err(AudienceError::Unsupported { .. })));
    }

    /// The audience is the welcome's DID, in the spelling the server hashes.
    #[test]
    fn the_audience_is_the_welcomes_canonical_did() {
        let did = server();
        let (prefix, body) = did.split_at("did:jig:z".len());
        let recased = format!("{prefix}{}", body.to_uppercase());
        assert_eq!(
            audience_of(&welcome(vec![VERSION.into()], recased)),
            Ok(server())
        );
        assert!(matches!(
            audience_of(&welcome(vec![VERSION.into()], "did:jig:nope".into())),
            Err(AudienceError::BadDid { .. })
        ));
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
