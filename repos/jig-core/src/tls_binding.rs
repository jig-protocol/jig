//! A server's TLS certificate, vouched for by the server's DID.
//!
//! A jig server serves TLS by default with a certificate it made itself, which
//! no certificate authority vouches for. The server vouches for it instead:
//! `/.well-known/jig` carries a [`TlsBinding`], signed with the DID key, that
//! names the certificate. A client that knows which DID it expects (pinned on
//! first contact, or configured, as a federation peer's `expected_did` is)
//! accepts the certificate the binding names. A stranger's certificate
//! needs the DID key to be vouched for, so it is refused.
//!
//! Both hashes are [`hash_labeled_parts`]: the certificate is hashed as
//! (`domain`, [`CERT_DOMAIN`]), (`cert`, its DER bytes), and the signed message
//! is (`domain`, [`BINDING_DOMAIN`]), (`server`, the server's DID), (`cert`,
//! that hash).

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::hash_labeled_parts;
use crate::did::Did;

pub const CERT_DOMAIN: &str = "jig-tls-cert-v1";
pub const BINDING_DOMAIN: &str = "jig-tls-binding-v1";

/// The hash a binding names a certificate by.
pub fn cert_hash(cert_der: &[u8]) -> [u8; 32] {
    *hash_labeled_parts(&[("domain", CERT_DOMAIN.as_bytes()), ("cert", cert_der)]).as_bytes()
}

/// What the server's DID key signs.
pub fn binding_message(server_did: &str, cert_hash: &[u8; 32]) -> [u8; 32] {
    *hash_labeled_parts(&[
        ("domain", BINDING_DOMAIN.as_bytes()),
        ("server", server_did.as_bytes()),
        ("cert", cert_hash),
    ])
    .as_bytes()
}

/// `server_did` vouches for the certificate whose [`cert_hash`] is
/// `cert_blake3`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsBinding {
    /// [`cert_hash`] of the certificate's DER bytes, hex.
    pub cert_blake3: String,
    /// The server DID key's signature over [`binding_message`], base64.
    pub sig_b64: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("`{0}` is not a did:jig key")]
    BadDid(String),
    #[error("the binding names another certificate than the one presented")]
    OtherCertificate,
    #[error("the binding is not signed by {0}")]
    BadSignature(String),
}

impl TlsBinding {
    /// Vouch, as `key`, for the certificate `cert_der`.
    pub fn sign(key: &SigningKey, cert_der: &[u8]) -> Self {
        let server_did = Did::from_ed25519_pubkey(key.verifying_key().as_bytes());
        let hash = cert_hash(cert_der);
        let sig = key.sign(&binding_message(&server_did.to_did_jig_string(), &hash));
        Self {
            cert_blake3: hex::encode(hash),
            sig_b64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        }
    }

    /// Whether `server_did` vouches for `cert_der` here.
    pub fn verify(&self, server_did: &str, cert_der: &[u8]) -> Result<(), BindingError> {
        let bad_did = || BindingError::BadDid(server_did.to_string());
        let key = Did::from_did_jig_string(server_did)
            .and_then(|did| did.as_bytes())
            .map_err(|_| bad_did())?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| bad_did())?;
        let hash = cert_hash(cert_der);
        if self.cert_blake3 != hex::encode(hash) {
            return Err(BindingError::OtherCertificate);
        }
        let bad_sig = || BindingError::BadSignature(server_did.to_string());
        let sig = base64::engine::general_purpose::STANDARD
            .decode(&self.sig_b64)
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
            .ok_or_else(bad_sig)?;
        key.verify(&binding_message(server_did, &hash), &sig)
            .map_err(|_| bad_sig())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn did(key: &SigningKey) -> String {
        Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
    }

    #[test]
    fn a_binding_vouches_for_one_certificate_under_one_did() {
        let server = key(1);
        let binding = TlsBinding::sign(&server, b"cert A");
        assert_eq!(binding.verify(&did(&server), b"cert A"), Ok(()));
        assert_eq!(
            binding.verify(&did(&server), b"cert B"),
            Err(BindingError::OtherCertificate)
        );
        assert_eq!(
            binding.verify(&did(&key(2)), b"cert A"),
            Err(BindingError::BadSignature(did(&key(2))))
        );
        assert_eq!(
            binding.verify("did:jig:nope", b"cert A"),
            Err(BindingError::BadDid("did:jig:nope".to_string()))
        );
    }

    /// Someone else's key cannot vouch for a certificate in this server's
    /// name, even naming the right certificate.
    #[test]
    fn a_binding_signed_by_another_key_is_refused() {
        let (server, mallory) = (key(1), key(2));
        let forged = TlsBinding {
            cert_blake3: hex::encode(cert_hash(b"mallory's cert")),
            sig_b64: TlsBinding::sign(&mallory, b"mallory's cert").sig_b64,
        };
        assert_eq!(
            forged.verify(&did(&server), b"mallory's cert"),
            Err(BindingError::BadSignature(did(&server)))
        );
    }
}
