//! Admission proof of work, client side: the body of
//! `POST /api/v1/admission` for a server that asks a new identity for work.
//!
//! The digest and the signed message live in [`jig_core::admission_pow`], so
//! this module cannot drift from the server on either.

use std::num::NonZeroU64;

use base64::Engine as _;
use jig_core::admission_pow;
use jig_core::pow::Proof;
use serde::Serialize;

use crate::identity::Identity;

/// A nonce worth the server's bits, signed by the identity it admits.
#[derive(Debug, Clone, Serialize)]
pub struct AdmissionProof {
    pub did: String,
    pub nonce: String,
    pub sig_b64: String,
}

impl AdmissionProof {
    /// Do `bits` of work for `server_did` as `identity`, and sign it.
    ///
    /// CPU-bound, about 2^`bits` digests: run it off the async executor
    /// (`spawn_blocking`).
    pub fn solve(identity: &Identity, server_did: &str, bits: u8) -> Self {
        let nonce = admission_pow::solve(server_did, &identity.did_string(), bits);
        Self::sign(identity, server_did, nonce)
    }

    /// Sign a `nonce` already found with [`admission_pow::solve`], for a
    /// caller that did the work on another thread.
    pub fn sign(identity: &Identity, server_did: &str, nonce: String) -> Self {
        let did = identity.did_string();
        let sig = identity.sign(&admission_pow::signed_message(server_did, &did, &nonce));
        Self {
            did,
            nonce,
            sig_b64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        }
    }
}

/// JEP-0008 admission work (the `admit` action), signed by the identity it
/// admits. What a server that advertises `admission_pow` expects.
#[derive(Debug, Clone, Serialize)]
pub struct PowAdmissionProof {
    pub did: String,
    pub pow: Proof,
    pub sig_b64: String,
}

impl PowAdmissionProof {
    /// Do `effort` of work for `server_did` as `identity`, and sign it.
    ///
    /// CPU-bound, about `effort` digests: run it off the async executor
    /// (`spawn_blocking`).
    pub fn solve(identity: &Identity, server_did: &str, effort: NonZeroU64) -> Self {
        let pow = admission_pow::puzzle(server_did, &identity.did_string()).solve(effort);
        Self::sign(identity, server_did, pow)
    }

    /// Sign a proof already found, for a caller that did the work on another
    /// thread.
    pub fn sign(identity: &Identity, server_did: &str, pow: Proof) -> Self {
        let did = identity.did_string();
        let sig = identity.sign(&admission_pow::proof_message(server_did, &did, &pow));
        Self {
            did,
            pow,
            sig_b64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier as _;

    #[test]
    fn the_proof_is_work_for_this_server_signed_by_the_identity() {
        let identity =
            Identity::from_signing_key(jig_core::crypto::ed25519::generate_signing_key());
        let proof = AdmissionProof::solve(&identity, "did:jig:zServer", 8);
        assert_eq!(proof.did, identity.did_string());
        assert!(admission_pow::meets(
            "did:jig:zServer",
            &proof.did,
            &proof.nonce,
            8
        ));
        let sig = base64::engine::general_purpose::STANDARD
            .decode(&proof.sig_b64)
            .unwrap();
        identity
            .public_key()
            .verify(
                &admission_pow::signed_message("did:jig:zServer", &proof.did, &proof.nonce),
                &ed25519_dalek::Signature::from_slice(&sig).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn the_pow_proof_is_admit_work_for_this_server_signed_by_the_identity() {
        let identity =
            Identity::from_signing_key(jig_core::crypto::ed25519::generate_signing_key());
        let effort = NonZeroU64::new(256).unwrap();
        let proof = PowAdmissionProof::solve(&identity, "did:jig:zServer", effort);
        assert_eq!(proof.did, identity.did_string());
        assert_eq!(
            admission_pow::puzzle("did:jig:zServer", &proof.did).check(&proof.pow, effort),
            Ok(())
        );
        let sig = base64::engine::general_purpose::STANDARD
            .decode(&proof.sig_b64)
            .unwrap();
        identity
            .public_key()
            .verify(
                &admission_pow::proof_message("did:jig:zServer", &proof.did, &proof.pow),
                &ed25519_dalek::Signature::from_slice(&sig).unwrap(),
            )
            .unwrap();
    }
}
