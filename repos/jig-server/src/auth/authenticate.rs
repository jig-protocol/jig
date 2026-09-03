//! Gate 1: does the caller hold the key for the DID it claims?
//!
//! Tier 0 — per-request proof. The caller signs the canonical request hash from
//! [`jig_core::request_auth`]; the server recomputes that hash from the request
//! it actually received and verifies the signature against the public key
//! recovered from the claimed DID.
//!
//! **Recomputing rather than trusting any digest the caller supplies is the
//! whole security property.** It binds the signature to *this* request, so a
//! signature captured against one path cannot authenticate another.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jig_core::did::Did;
use jig_core::request_auth::canonical_request_hash;

use crate::auth::{GateOutcome, ReplayGuard, ReplayRejection};

/// A caller's proof of possession, however the transport carried it.
///
/// REST parses this from headers; a future SSH or gRPC transport carries the
/// same values however it can and calls the same [`authenticate`]. Keeping it a
/// plain struct is what lets one verification path serve every transport.
///
/// `did` is what the caller **claims**. It is not trustworthy until
/// [`authenticate`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProof {
    /// The identity the caller claims.
    pub did: Did,
    /// Wall-clock component of the request's HLC, milliseconds since epoch.
    pub hlc_wall_ms: u64,
    /// Logical component of the request's HLC.
    pub hlc_logical: u32,
    /// Single-use value making an otherwise identical request unique.
    pub nonce: String,
    /// ed25519 signature over the canonical request hash.
    pub signature: Vec<u8>,
}

/// Verify a caller's proof of possession for a specific request.
///
/// Returns the authenticated DID, which gates 2 and 3 then reason about. The
/// returned value is the only trustworthy source of the caller's identity.
///
/// Order matters: the signature and freshness are checked **before** the nonce
/// is recorded, so unauthenticated or expired traffic cannot occupy guard
/// capacity and deny service to legitimate callers.
pub fn authenticate(
    proof: &AuthProof,
    method: &str,
    path: &str,
    body: &[u8],
    now_ms: u64,
    guard: &mut ReplayGuard,
) -> Result<Did, GateOutcome> {
    let hash = canonical_request_hash(
        method,
        path,
        body,
        proof.hlc_wall_ms,
        proof.hlc_logical,
        &proof.nonce,
    );

    // Every malformed-input path collapses to one refusal: a caller who cannot
    // authenticate has not earned a breakdown of which part was wrong. The DID
    // string is attacker-controlled, so this must refuse rather than panic.
    let pubkey_bytes = proof
        .did
        .as_bytes()
        .map_err(|_| GateOutcome::AuthSignatureInvalid)?;
    let pubkey =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| GateOutcome::AuthSignatureInvalid)?;
    let signature =
        Signature::from_slice(&proof.signature).map_err(|_| GateOutcome::AuthSignatureInvalid)?;
    pubkey
        .verify(hash.as_bytes(), &signature)
        .map_err(|_| GateOutcome::AuthSignatureInvalid)?;

    match guard.check_and_record(&proof.nonce, proof.hlc_wall_ms, now_ms) {
        Ok(()) => Ok(proof.did.clone()),
        Err(ReplayRejection::AlreadySeen) => Err(GateOutcome::AuthReplayed),
        Err(ReplayRejection::OutsideWindow) => Err(GateOutcome::AuthStale),
        // The guard is full of live nonces. This is a availability failure, not
        // an authentication one, but the caller cannot be admitted: accepting
        // without recording would leave the request replayable.
        Err(ReplayRejection::CapacityExhausted) => Err(GateOutcome::AuthReplayed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use jig_core::did::Did;

    /// Deterministic test identity — fixed seed, so no `rand` dependency and no
    /// flaky key material.
    fn identity(seed: u8) -> (SigningKey, Did) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let did = Did::from_ed25519_pubkey(&signing.verifying_key().to_bytes());
        (signing, did)
    }

    fn proof_for(
        signing: &SigningKey,
        did: &Did,
        method: &str,
        path: &str,
        body: &[u8],
        ms: u64,
        nonce: &str,
    ) -> AuthProof {
        let hash = jig_core::request_auth::canonical_request_hash(method, path, body, ms, 0, nonce);
        AuthProof {
            did: did.clone(),
            hlc_wall_ms: ms,
            hlc_logical: 0,
            nonce: nonce.to_string(),
            signature: signing.sign(hash.as_bytes()).to_bytes().to_vec(),
        }
    }

    #[test]
    fn a_correctly_signed_request_authenticates() {
        let (signing, did) = identity(1);
        let proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let mut guard = ReplayGuard::new(30_000, 128);

        let got = authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard)
            .expect("a correctly signed request must authenticate");
        assert_eq!(got, did);
    }

    #[test]
    fn a_corrupted_signature_is_refused() {
        let (signing, did) = identity(1);
        let mut proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        proof.signature[0] ^= 0xff;
        let mut guard = ReplayGuard::new(30_000, 128);

        assert_eq!(
            authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthSignatureInvalid)
        );
    }

    /// The attack this prevents: capture a signed read of a public channel and
    /// replay it against a private one. The signature is genuine; the request
    /// it authorizes is not this one.
    #[test]
    fn a_signature_for_another_path_is_refused() {
        let (signing, did) = identity(1);
        let proof = proof_for(
            &signing,
            &did,
            "GET",
            "/api/v1/channels/%23public/blocks",
            b"",
            5_000,
            "n1",
        );
        let mut guard = ReplayGuard::new(30_000, 128);

        assert_eq!(
            authenticate(
                &proof,
                "GET",
                "/api/v1/channels/%23private/blocks",
                b"",
                5_000,
                &mut guard
            ),
            Err(GateOutcome::AuthSignatureInvalid),
            "a signature bound to one path must not authenticate another"
        );
    }

    /// A DID whose key did not sign the request. The signature is well-formed
    /// and verifies against the SIGNER's key — it just is not the claimed one.
    #[test]
    fn a_proof_claiming_another_did_is_refused() {
        let (attacker_signing, _attacker_did) = identity(1);
        let (_victim_signing, victim_did) = identity(2);

        // Attacker signs, but claims to be the victim.
        let hash = jig_core::request_auth::canonical_request_hash(
            "GET",
            "/api/v1/channels",
            b"",
            5_000,
            0,
            "n1",
        );
        let proof = AuthProof {
            did: victim_did,
            hlc_wall_ms: 5_000,
            hlc_logical: 0,
            nonce: "n1".to_string(),
            signature: attacker_signing.sign(hash.as_bytes()).to_bytes().to_vec(),
        };
        let mut guard = ReplayGuard::new(30_000, 128);

        assert_eq!(
            authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthSignatureInvalid),
            "impersonation must fail: the signature is verified against the CLAIMED did"
        );
    }

    /// A validly signed request presented twice. The signature is genuine both
    /// times — which is why this is tested here and not left to the signature
    /// check alone.
    #[test]
    fn a_replayed_request_is_refused_despite_a_valid_signature() {
        let (signing, did) = identity(1);
        let proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let mut guard = ReplayGuard::new(30_000, 128);

        authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard).unwrap();
        assert_eq!(
            authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthReplayed)
        );
    }

    #[test]
    fn a_stale_request_is_refused() {
        let (signing, did) = identity(1);
        let proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let mut guard = ReplayGuard::new(1_000, 128);

        assert_eq!(
            authenticate(&proof, "GET", "/api/v1/channels", b"", 500_000, &mut guard),
            Err(GateOutcome::AuthStale)
        );
    }

    /// A malformed DID is attacker-controlled input. It must refuse, never panic.
    #[test]
    fn a_malformed_did_is_refused_not_panicked_on() {
        let (signing, did) = identity(1);
        let mut proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        proof.did = Did::from_str_unchecked("did:jig:not-a-real-key");
        let mut guard = ReplayGuard::new(30_000, 128);

        assert_eq!(
            authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthSignatureInvalid)
        );
    }

    /// A stale request must not consume a nonce slot. Otherwise an attacker
    /// could flood expired requests to fill the guard and deny service to
    /// legitimate callers.
    #[test]
    fn a_stale_request_does_not_consume_guard_capacity() {
        let (signing, did) = identity(1);
        let mut guard = ReplayGuard::new(1_000, 128);
        let before = guard.len();

        let proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let _ = authenticate(&proof, "GET", "/api/v1/channels", b"", 500_000, &mut guard);

        assert_eq!(
            guard.len(),
            before,
            "a stale request must not occupy a slot"
        );
    }

    /// A bad signature must not consume a nonce slot either — same reasoning.
    #[test]
    fn a_bad_signature_does_not_consume_guard_capacity() {
        let (signing, did) = identity(1);
        let mut guard = ReplayGuard::new(30_000, 128);
        let before = guard.len();

        let mut proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        proof.signature[0] ^= 0xff;
        let _ = authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard);

        assert_eq!(
            guard.len(),
            before,
            "an unauthenticated request must not occupy a slot"
        );
    }
}
