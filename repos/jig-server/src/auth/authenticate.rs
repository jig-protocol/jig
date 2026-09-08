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
        // Not a replay: the guard had no room to record this nonce, and
        // accepting it unrecorded would leave the request replayable.
        Err(ReplayRejection::CapacityExhausted) => Err(GateOutcome::AuthCapacityExhausted),
    }
}

/// Canonical hash a caller signs to subscribe.
///
/// Expressed through [`canonical_request_hash`] with a synthetic method so
/// there is exactly ONE canonicalization in the system. A second scheme would
/// be a second thing to keep in sync, and the first divergence would present as
/// "every signature is invalid" with no clue which side is wrong.
///
/// The scope's canonical string is the path, so a proof for `#public` cannot
/// authorize a subscription to `#private`.
pub fn canonical_subscribe_hash(
    scope: &str,
    hlc_wall_ms: u64,
    hlc_logical: u32,
    nonce: &str,
) -> blake3::Hash {
    canonical_request_hash("SUBSCRIBE", scope, b"", hlc_wall_ms, hlc_logical, nonce)
}

/// Verify a subscribe proof, returning the DID the signature actually proves.
///
/// **The returned DID is the only trustworthy one.** `auth.did` is a claim; a
/// caller can put anything there. Binding the claimed value instead of this
/// return would let any client subscribe as anyone — worse than no
/// authorization, because it looks enforced.
pub fn authenticate_subscribe(
    auth: &jig_pipeline::envelope::SubscribeAuth,
    scope: &str,
    now_ms: u64,
    guard: &mut ReplayGuard,
) -> Result<Did, GateOutcome> {
    use base64::Engine as _;

    let signature = base64::engine::general_purpose::STANDARD
        .decode(&auth.sig_b64)
        .map_err(|_| GateOutcome::AuthSignatureInvalid)?;
    let did = Did::from_did_jig_string(&auth.did).map_err(|_| GateOutcome::AuthSignatureInvalid)?;

    let proof = AuthProof {
        did,
        hlc_wall_ms: auth.hlc_wall_ms,
        hlc_logical: auth.hlc_logical,
        nonce: auth.nonce.clone(),
        signature,
    };

    // Same verifier as REST: one code path, so the two transports cannot drift
    // into enforcing different things.
    authenticate(&proof, "SUBSCRIBE", scope, b"", now_ms, guard)
}

/// Header names carrying a tier-0 proof over HTTP.
///
/// HTTP-specific by necessity; the *verification* is not, which is what keeps
/// the design transport-agnostic. A future SSH or gRPC transport carries the
/// same five values however it can and calls the same [`authenticate`].
pub mod headers {
    pub const DID: &str = "x-jig-did";
    pub const HLC_WALL_MS: &str = "x-jig-hlc-wall-ms";
    pub const HLC_LOGICAL: &str = "x-jig-hlc-logical";
    pub const NONCE: &str = "x-jig-nonce";
    pub const SIGNATURE: &str = "x-jig-signature";
}

/// Extract a proof from HTTP headers, if one is present and well-formed.
///
/// Returns `None` both when no proof was offered and when one was offered but
/// malformed. The caller maps that to [`GateOutcome::AuthMissing`].
///
/// Deliberately not distinguishing the two: telling an unauthenticated caller
/// precisely which header they got wrong is detail they have not earned, and
/// the distinction is not one a legitimate client needs — a correct client
/// sends all five correctly or has a bug it can find locally.
pub fn proof_from_headers(headers: &axum::http::HeaderMap) -> Option<AuthProof> {
    use base64::Engine as _;

    let get = |name: &str| headers.get(name)?.to_str().ok();

    Some(AuthProof {
        did: Did::from_did_jig_string(get(headers::DID)?).ok()?,
        hlc_wall_ms: get(headers::HLC_WALL_MS)?.parse().ok()?,
        hlc_logical: get(headers::HLC_LOGICAL)?.parse().ok()?,
        nonce: get(headers::NONCE)?.to_string(),
        signature: base64::engine::general_purpose::STANDARD
            .decode(get(headers::SIGNATURE)?)
            .ok()?,
    })
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

    fn headers_for(proof: &AuthProof) -> axum::http::HeaderMap {
        use base64::Engine as _;
        let mut h = axum::http::HeaderMap::new();
        h.insert(headers::DID, proof.did.as_str().parse().unwrap());
        h.insert(
            headers::HLC_WALL_MS,
            proof.hlc_wall_ms.to_string().parse().unwrap(),
        );
        h.insert(
            headers::HLC_LOGICAL,
            proof.hlc_logical.to_string().parse().unwrap(),
        );
        h.insert(headers::NONCE, proof.nonce.parse().unwrap());
        h.insert(
            headers::SIGNATURE,
            base64::engine::general_purpose::STANDARD
                .encode(&proof.signature)
                .parse()
                .unwrap(),
        );
        h
    }

    #[test]
    fn a_proof_round_trips_through_headers() {
        let (signing, did) = identity(1);
        let proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let parsed = proof_from_headers(&headers_for(&proof)).expect("round-trips");
        assert_eq!(parsed, proof, "header carriage must not alter the proof");
    }

    #[test]
    fn no_headers_yields_no_proof() {
        assert!(proof_from_headers(&axum::http::HeaderMap::new()).is_none());
    }

    /// Every header is required. Dropping any one must yield no proof rather
    /// than a partially-populated one that could verify against something.
    #[test]
    fn a_missing_header_yields_no_proof() {
        let (signing, did) = identity(1);
        let proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");

        for name in [
            headers::DID,
            headers::HLC_WALL_MS,
            headers::HLC_LOGICAL,
            headers::NONCE,
            headers::SIGNATURE,
        ] {
            let mut h = headers_for(&proof);
            h.remove(name);
            assert!(
                proof_from_headers(&h).is_none(),
                "dropping {name} must yield no proof"
            );
        }
    }

    /// Malformed values are refused the same way an absent header is — a caller
    /// who cannot authenticate does not get a parse diagnosis.
    #[test]
    fn malformed_header_values_yield_no_proof() {
        let (signing, did) = identity(1);
        let proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");

        let mut bad_ms = headers_for(&proof);
        bad_ms.insert(headers::HLC_WALL_MS, "not-a-number".parse().unwrap());
        assert!(proof_from_headers(&bad_ms).is_none());

        let mut bad_sig = headers_for(&proof);
        bad_sig.insert(headers::SIGNATURE, "!!!not-base64!!!".parse().unwrap());
        assert!(proof_from_headers(&bad_sig).is_none());

        let mut bad_did = headers_for(&proof);
        bad_did.insert(headers::DID, "not-a-did".parse().unwrap());
        assert!(proof_from_headers(&bad_did).is_none());
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
