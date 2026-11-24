//! Gate 1: does the caller hold the key for the DID it claims?
//!
//! Tier 0 — per-request proof. The caller signs the canonical request hash from
//! [`jig_core::request_auth`]; the server recomputes that hash from the request
//! it actually received, addressed to its own DID, and verifies the signature
//! strictly against the public key recovered from the claimed DID.
//!
//! **Recomputing rather than trusting any digest the caller supplies is the
//! whole security property.** It binds the signature to *this* request at
//! *this* server, so a signature captured against one path cannot authenticate
//! another, and one addressed to another server does not authenticate here.

use ed25519_dalek::{Signature, VerifyingKey};
use jig_core::did::Did;
use jig_core::request_auth::{MAX_NONCE_LEN, canonical_request_hash};

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
    /// The server DID the proof is addressed to, as sent. `None` is a v1
    /// proof, which binds no audience and is refused.
    pub audience: Option<String>,
    /// Wall-clock component of the request's HLC, milliseconds since epoch.
    pub hlc_wall_ms: u64,
    /// Logical component of the request's HLC.
    pub hlc_logical: u32,
    /// Single-use value making an otherwise identical request unique.
    pub nonce: String,
    /// ed25519 signature over the canonical request hash.
    pub signature: Vec<u8>,
}

/// Verify a caller's proof of possession for a specific request addressed to
/// `server_did`, this server's current DID.
///
/// Returns the authenticated DID, which gates 2 and 3 then reason about. The
/// returned value is the only trustworthy source of the caller's identity.
///
/// Only the current DID is an audience: a DID this server signed as before a
/// key change is not, since that key may no longer be this server's alone. A
/// client whose pin is behind is refused with
/// [`GateOutcome::AuthWrongAudience`], re-handshakes (which moves its pin
/// along the key links) and signs afresh.
///
/// Order matters: the signature and freshness are checked **before** the nonce
/// is recorded, so unauthenticated or expired traffic cannot occupy guard
/// capacity and deny service to legitimate callers.
pub fn authenticate(
    proof: &AuthProof,
    server_did: &Did,
    method: &str,
    path: &str,
    body: &[u8],
    now_ms: u64,
    guard: &mut ReplayGuard,
) -> Result<Did, GateOutcome> {
    // A v1 proof binds no audience. Said so by name, so an old client is
    // told to upgrade rather than that its signature is wrong.
    let Some(audience) = proof.audience.as_deref() else {
        return Err(GateOutcome::AuthProofVersionUnsupported);
    };
    // The audience is inside signed data, so it must already be canonical.
    // Any other DID, or none, is not this server: the proof was made for
    // somewhere else. Checked before the signature: it costs nothing, and
    // this server's DID is public, so naming the mismatch discloses nothing.
    if Did::from_did_jig_string(audience).ok().as_ref() != Some(server_did) {
        return Err(GateOutcome::AuthWrongAudience);
    }

    // Every malformed-input path collapses to one refusal: a caller who cannot
    // authenticate has not earned a breakdown of which part was wrong. The DID
    // string is attacker-controlled, so this must refuse rather than panic.
    //
    // A nonce over the bound (JEP-0015 rule 25) is malformed too. Checked
    // before any key work, so it costs nothing and is never recorded.
    if proof.nonce.len() > MAX_NONCE_LEN {
        return Err(GateOutcome::AuthSignatureInvalid);
    }
    //
    // The DID header is transient: nothing below stores or forwards it, only
    // the canonical DID rebuilt from its key, which is also what the hash
    // covers. So a re-cased spelling is read as its key here.
    let pubkey_bytes = Did::canonicalize(proof.did.as_str())
        .and_then(|did| did.as_bytes())
        .map_err(|_| GateOutcome::AuthSignatureInvalid)?;
    let pubkey =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| GateOutcome::AuthSignatureInvalid)?;
    let signature =
        Signature::from_slice(&proof.signature).map_err(|_| GateOutcome::AuthSignatureInvalid)?;

    // The identity this proof establishes is the KEY, not the string the
    // caller spelled it with: a DID's base32 body decodes case-insensitively,
    // so `zabc…` and `zABC…` are one key. Rebuild the DID from the pubkey and
    // use that everywhere downstream — in the hash, the replay record (or one
    // captured proof would replay once per spelling) and the returned
    // identity (or a re-cased caller would never match its own membership
    // rows).
    let did = Did::from_ed25519_pubkey(&pubkey_bytes);

    let hash = canonical_request_hash(
        server_did.as_str(),
        did.as_str(),
        method,
        path,
        body,
        proof.hlc_wall_ms,
        proof.hlc_logical,
        &proof.nonce,
    );
    // Strict (JEP-0013 §1 rule 4): refuses small-order keys and
    // non-canonical encodings, which plain verification lets through.
    pubkey
        .verify_strict(hash.as_bytes(), &signature)
        .map_err(|_| GateOutcome::AuthSignatureInvalid)?;

    match guard.check_and_record(did.as_str(), &proof.nonce, proof.hlc_wall_ms, now_ms) {
        Ok(()) => Ok(did),
        Err(ReplayRejection::AlreadySeen) => Err(GateOutcome::AuthReplayed),
        Err(ReplayRejection::OutsideWindow) => Err(GateOutcome::AuthStale),
        // Not a replay: the guard had no room to record this nonce, and
        // accepting it unrecorded would leave the request replayable.
        Err(ReplayRejection::CapacityExhausted) => Err(GateOutcome::AuthCapacityExhausted),
        Err(ReplayRejection::DidOverShare) => Err(GateOutcome::RateLimited),
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
    audience: &str,
    did: &str,
    scope: &str,
    hlc_wall_ms: u64,
    hlc_logical: u32,
    nonce: &str,
) -> blake3::Hash {
    canonical_request_hash(
        audience,
        did,
        "SUBSCRIBE",
        scope,
        b"",
        hlc_wall_ms,
        hlc_logical,
        nonce,
    )
}

/// Verify a subscribe proof, returning the DID the signature actually proves.
///
/// **The returned DID is the only trustworthy one.** `auth.did` is a claim; a
/// caller can put anything there. Binding the claimed value instead of this
/// return would let any client subscribe as anyone — worse than no
/// authorization, because it looks enforced.
pub fn authenticate_subscribe(
    auth: &jig_pipeline::envelope::SubscribeAuth,
    server_did: &Did,
    scope: &str,
    now_ms: u64,
    guard: &mut ReplayGuard,
) -> Result<Did, GateOutcome> {
    use base64::Engine as _;

    let signature = base64::engine::general_purpose::STANDARD
        .decode(&auth.sig_b64)
        .map_err(|_| GateOutcome::AuthSignatureInvalid)?;
    // Transient, like a request proof: see `authenticate`.
    let did = Did::canonicalize(&auth.did).map_err(|_| GateOutcome::AuthSignatureInvalid)?;

    let proof = AuthProof {
        did,
        audience: auth.audience.clone(),
        hlc_wall_ms: auth.hlc_wall_ms,
        hlc_logical: auth.hlc_logical,
        nonce: auth.nonce.clone(),
        signature,
    };

    // Same verifier as REST: one code path, so the two transports cannot drift
    // into enforcing different things.
    authenticate(&proof, server_did, "SUBSCRIBE", scope, b"", now_ms, guard)
}

/// Header names carrying a tier-0 proof over HTTP. Defined in `jig-core` next
/// to the canonical hash, so the client that signs and this verifier read the
/// same names from one place; re-exported here for the server's own callers.
pub use jig_core::request_auth::headers;

/// Extract a proof from HTTP headers, if one is present and well-formed.
///
/// Returns `None` both when no proof was offered and when one was offered but
/// malformed. The caller maps that to [`GateOutcome::AuthMissing`].
///
/// Deliberately not distinguishing the two: telling an unauthenticated caller
/// precisely which header they got wrong is detail they have not earned, and
/// the distinction is not one a legitimate client needs — a correct client
/// sends all of them correctly or has a bug it can find locally.
///
/// The audience header is the one exception: its absence is not malformed
/// but a v1 proof, returned with `audience: None` so [`authenticate`] can
/// refuse it by name.
pub fn proof_from_headers(headers: &axum::http::HeaderMap) -> Option<AuthProof> {
    use base64::Engine as _;

    let get = |name: &str| headers.get(name)?.to_str().ok();

    Some(AuthProof {
        // The proof is never kept, and the hash covers the DID rebuilt from
        // its key, so a re-cased spelling is read as its key (see
        // `authenticate`).
        did: Did::canonicalize(get(headers::DID)?).ok()?,
        // Absent is v1. Present but not text is still an audience, and not
        // this server's: refused as WRONG_AUDIENCE, not read as no proof.
        // Lossy decoding cannot turn it into a DID, which is ASCII.
        audience: headers
            .get(headers::AUDIENCE)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()),
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

    /// The server the proofs below are addressed to.
    fn server() -> Did {
        identity(200).1
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
        proof_to(&server(), signing, did, method, path, body, ms, nonce)
    }

    #[allow(clippy::too_many_arguments)]
    fn proof_to(
        audience: &Did,
        signing: &SigningKey,
        did: &Did,
        method: &str,
        path: &str,
        body: &[u8],
        ms: u64,
        nonce: &str,
    ) -> AuthProof {
        let hash = jig_core::request_auth::canonical_request_hash(
            audience.as_str(),
            did.as_str(),
            method,
            path,
            body,
            ms,
            0,
            nonce,
        );
        AuthProof {
            did: did.clone(),
            audience: Some(audience.as_str().to_string()),
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
        if let Some(audience) = &proof.audience {
            h.insert(headers::AUDIENCE, audience.parse().unwrap());
        }
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

        // The audience is not among them: without it the proof is v1, which
        // parses and is refused by name (`a_v1_proof_is_refused_by_name`).
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

        let got = authenticate(
            &proof,
            &server(),
            "GET",
            "/api/v1/channels",
            b"",
            5_000,
            &mut guard,
        )
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
            authenticate(
                &proof,
                &server(),
                "GET",
                "/api/v1/channels",
                b"",
                5_000,
                &mut guard
            ),
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
                &server(),
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
            server().as_str(),
            victim_did.as_str(),
            "GET",
            "/api/v1/channels",
            b"",
            5_000,
            0,
            "n1",
        );
        let proof = AuthProof {
            did: victim_did,
            audience: Some(server().as_str().to_string()),
            hlc_wall_ms: 5_000,
            hlc_logical: 0,
            nonce: "n1".to_string(),
            signature: attacker_signing.sign(hash.as_bytes()).to_bytes().to_vec(),
        };
        let mut guard = ReplayGuard::new(30_000, 128);

        assert_eq!(
            authenticate(
                &proof,
                &server(),
                "GET",
                "/api/v1/channels",
                b"",
                5_000,
                &mut guard
            ),
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

        authenticate(
            &proof,
            &server(),
            "GET",
            "/api/v1/channels",
            b"",
            5_000,
            &mut guard,
        )
        .unwrap();
        assert_eq!(
            authenticate(
                &proof,
                &server(),
                "GET",
                "/api/v1/channels",
                b"",
                5_000,
                &mut guard
            ),
            Err(GateOutcome::AuthReplayed)
        );
    }

    /// A proof that spells its DID with an upper-cased body verifies (the
    /// key is the same) but must come back as the canonical DID, and must be
    /// the same identity to the replay guard as the lower-cased spelling.
    #[test]
    fn a_recased_did_authenticates_as_its_canonical_self() {
        let (signing, did) = identity(1);
        let mut proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let (prefix, body) = did.as_str().split_at("did:jig:z".len());
        let recased = Did::from_str_unchecked(format!("{prefix}{}", body.to_uppercase()));
        assert_ne!(recased, did);
        proof.did = recased;
        let mut guard = ReplayGuard::new(30_000, 128);

        let established = authenticate(
            &proof,
            &server(),
            "GET",
            "/api/v1/channels",
            b"",
            5_000,
            &mut guard,
        )
        .unwrap();
        assert_eq!(established, did, "the canonical spelling, not the one sent");

        // The lower-cased original is the same proof to the guard.
        let original = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        assert_eq!(
            authenticate(
                &original,
                &server(),
                "GET",
                "/api/v1/channels",
                b"",
                5_000,
                &mut guard
            ),
            Err(GateOutcome::AuthReplayed)
        );
    }

    #[test]
    fn a_stale_request_is_refused() {
        let (signing, did) = identity(1);
        let proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let mut guard = ReplayGuard::new(1_000, 128);

        assert_eq!(
            authenticate(
                &proof,
                &server(),
                "GET",
                "/api/v1/channels",
                b"",
                500_000,
                &mut guard
            ),
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
            authenticate(
                &proof,
                &server(),
                "GET",
                "/api/v1/channels",
                b"",
                5_000,
                &mut guard
            ),
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
        let _ = authenticate(
            &proof,
            &server(),
            "GET",
            "/api/v1/channels",
            b"",
            500_000,
            &mut guard,
        );

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
        let _ = authenticate(
            &proof,
            &server(),
            "GET",
            "/api/v1/channels",
            b"",
            5_000,
            &mut guard,
        );

        assert_eq!(
            guard.len(),
            before,
            "an unauthenticated request must not occupy a slot"
        );
    }
    /// #464: a proof made for server A, presented at server B on the same
    /// path inside the window, is refused at B — and stays usable at A,
    /// because the refusal recorded nothing.
    #[test]
    fn a_proof_for_another_server_is_refused() {
        let (signing, did) = identity(1);
        let a = identity(201).1;
        let proof = proof_to(
            &a,
            &signing,
            &did,
            "GET",
            "/api/v1/channels",
            b"",
            5_000,
            "n1",
        );
        let mut guard_b = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate(
                &proof,
                &server(),
                "GET",
                "/api/v1/channels",
                b"",
                5_000,
                &mut guard_b
            ),
            Err(GateOutcome::AuthWrongAudience)
        );
        assert_eq!(
            guard_b.len(),
            0,
            "a refused audience must not occupy a slot"
        );
        let mut guard_a = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate(
                &proof,
                &a,
                "GET",
                "/api/v1/channels",
                b"",
                5_000,
                &mut guard_a
            ),
            Ok(did)
        );
    }

    /// Rewriting the audience header to this server's DID does not help: the
    /// signature covers the audience the client signed.
    #[test]
    fn a_rewritten_audience_fails_the_signature() {
        let (signing, did) = identity(1);
        let a = identity(201).1;
        let mut proof = proof_to(
            &a,
            &signing,
            &did,
            "GET",
            "/api/v1/channels",
            b"",
            5_000,
            "n1",
        );
        proof.audience = Some(server().as_str().to_string());
        let mut guard = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate(
                &proof,
                &server(),
                "GET",
                "/api/v1/channels",
                b"",
                5_000,
                &mut guard
            ),
            Err(GateOutcome::AuthSignatureInvalid)
        );
    }

    /// Only the current DID is an audience: a proof addressed to a DID this
    /// server signed as before a key change is refused like any other.
    #[test]
    fn a_proof_for_a_prior_did_is_refused() {
        let (signing, did) = identity(1);
        let prior = identity(199).1;
        let proof = proof_to(&prior, &signing, &did, "GET", "/x", b"", 5_000, "n1");
        let mut guard = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate(&proof, &server(), "GET", "/x", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthWrongAudience)
        );
    }

    /// The audience is signed data: a re-cased spelling of this server's DID
    /// is not accepted as it.
    #[test]
    fn a_non_canonical_audience_is_refused() {
        let (signing, did) = identity(1);
        let mut proof = proof_for(&signing, &did, "GET", "/x", b"", 5_000, "n1");
        let server_did = server();
        let (prefix, body) = server_did.as_str().split_at("did:jig:z".len());
        proof.audience = Some(format!("{prefix}{}", body.to_uppercase()));
        let mut guard = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate(&proof, &server(), "GET", "/x", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthWrongAudience)
        );
    }

    /// An audience header that is present but not text is still an audience,
    /// refused as another server's, not read as no proof at all.
    #[test]
    fn an_unreadable_audience_is_a_wrong_audience() {
        let (signing, did) = identity(1);
        let proof = proof_for(&signing, &did, "GET", "/x", b"", 5_000, "n1");
        let mut h = headers_for(&proof);
        h.insert(
            headers::AUDIENCE,
            axum::http::HeaderValue::from_bytes(b"did:jig:z\xff").unwrap(),
        );
        let parsed = proof_from_headers(&h).expect("the proof is still read");
        assert!(parsed.audience.is_some());
        let mut guard = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate(&parsed, &server(), "GET", "/x", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthWrongAudience)
        );
    }

    /// A v1 proof (no audience) is refused by name, whatever it signed, and
    /// parses from headers as one rather than as a malformed proof.
    #[test]
    fn a_v1_proof_is_refused_by_name() {
        let (signing, did) = identity(1);
        let mut proof = proof_for(&signing, &did, "GET", "/x", b"", 5_000, "n1");
        proof.audience = None;
        let parsed = proof_from_headers(&headers_for(&proof)).expect("a v1 proof parses");
        assert_eq!(parsed.audience, None);
        let mut guard = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate(&parsed, &server(), "GET", "/x", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthProofVersionUnsupported)
        );
        assert_eq!(guard.len(), 0);
    }

    /// A signature with S + ℓ (the same point, a non-canonical scalar) is
    /// refused. ed25519-dalek refuses it under plain verification too, so
    /// this does not show strictness; `a_small_order_key_is_refused` does.
    #[test]
    fn a_non_canonical_s_is_refused() {
        let (signing, did) = identity(1);
        let mut proof = proof_for(&signing, &did, "GET", "/x", b"", 5_000, "n1");
        // ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut carry = 0u16;
        for (s, l) in proof.signature[32..].iter_mut().zip(L) {
            let sum = u16::from(*s) + u16::from(l) + carry;
            *s = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "S + ℓ fits in 32 bytes for any reduced S");
        let mut guard = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate(&proof, &server(), "GET", "/x", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthSignatureInvalid)
        );
    }

    /// Strict verification: a small-order public key (here the identity
    /// point) with R = identity and S = 0 satisfies the plain verification
    /// equation for every message. Plain `verify` accepts it; this gate must
    /// not.
    #[test]
    fn a_small_order_key_is_refused() {
        use ed25519_dalek::Verifier as _;
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        let did = Did::from_ed25519_pubkey(&identity_point);
        let mut sig = [0u8; 64];
        sig[0] = 1; // R = identity, S = 0
        let hash = jig_core::request_auth::canonical_request_hash(
            server().as_str(),
            did.as_str(),
            "GET",
            "/x",
            b"",
            5_000,
            0,
            "n1",
        );
        // The forgery is real under plain verification, so the test shows
        // strictness is what refuses it.
        let key = VerifyingKey::from_bytes(&identity_point).unwrap();
        assert!(
            key.verify(hash.as_bytes(), &Signature::from_bytes(&sig))
                .is_ok(),
            "plain verify accepts the small-order forgery"
        );
        let proof = AuthProof {
            did,
            audience: Some(server().as_str().to_string()),
            hlc_wall_ms: 5_000,
            hlc_logical: 0,
            nonce: "n1".into(),
            signature: sig.to_vec(),
        };
        let mut guard = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate(&proof, &server(), "GET", "/x", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthSignatureInvalid)
        );
    }

    /// A subscribe proof is held to its audience like a REST one.
    #[test]
    fn a_subscribe_proof_for_another_server_is_refused() {
        use base64::Engine as _;
        let (signing, did) = identity(1);
        let a = identity(201).1;
        let sign = |aud: &Did, nonce: &str| {
            let hash =
                canonical_subscribe_hash(aud.as_str(), did.as_str(), "channel:x", 5_000, 0, nonce);
            jig_pipeline::envelope::SubscribeAuth {
                did: did.as_str().to_string(),
                audience: Some(aud.as_str().to_string()),
                hlc_wall_ms: 5_000,
                hlc_logical: 0,
                nonce: nonce.to_string(),
                sig_b64: base64::engine::general_purpose::STANDARD
                    .encode(signing.sign(hash.as_bytes()).to_bytes()),
            }
        };
        let mut guard = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate_subscribe(&sign(&a, "n1"), &server(), "channel:x", 5_000, &mut guard),
            Err(GateOutcome::AuthWrongAudience)
        );
        let mut v1 = sign(&server(), "n2");
        v1.audience = None;
        assert_eq!(
            authenticate_subscribe(&v1, &server(), "channel:x", 5_000, &mut guard),
            Err(GateOutcome::AuthProofVersionUnsupported)
        );
        assert_eq!(
            authenticate_subscribe(
                &sign(&server(), "n3"),
                &server(),
                "channel:x",
                5_000,
                &mut guard
            ),
            Ok(did)
        );
    }

    /// A nonce is at most [`MAX_NONCE_LEN`] bytes. One byte over is refused
    /// though correctly signed, and takes no guard capacity; at the bound it
    /// is accepted.
    #[test]
    fn a_nonce_over_the_bound_is_refused_and_not_recorded() {
        let (signing, did) = identity(1);
        let mut guard = ReplayGuard::new(30_000, 128);
        let check = |nonce: &str, guard: &mut ReplayGuard| {
            let proof = proof_for(&signing, &did, "GET", "/api/v1/channels", b"", 5_000, nonce);
            authenticate(
                &proof,
                &server(),
                "GET",
                "/api/v1/channels",
                b"",
                5_000,
                guard,
            )
        };

        let over = "n".repeat(MAX_NONCE_LEN + 1);
        assert_eq!(
            check(&over, &mut guard),
            Err(GateOutcome::AuthSignatureInvalid)
        );
        assert_eq!(guard.len(), 0, "a refused nonce takes no capacity");

        let at = "n".repeat(MAX_NONCE_LEN);
        assert_eq!(check(&at, &mut guard), Ok(did.clone()));
        assert_eq!(guard.len(), 1);
    }

    /// The bound holds for subscriptions too: they share the verifier.
    #[test]
    fn a_subscribe_nonce_over_the_bound_is_refused() {
        use base64::Engine as _;
        let (signing, did) = identity(1);
        let nonce = "n".repeat(MAX_NONCE_LEN + 1);
        let hash = canonical_subscribe_hash(
            server().as_str(),
            did.as_str(),
            "channel:x",
            5_000,
            0,
            &nonce,
        );
        let auth = jig_pipeline::envelope::SubscribeAuth {
            did: did.as_str().to_string(),
            audience: Some(server().as_str().to_string()),
            hlc_wall_ms: 5_000,
            hlc_logical: 0,
            nonce,
            sig_b64: base64::engine::general_purpose::STANDARD
                .encode(signing.sign(hash.as_bytes()).to_bytes()),
        };
        let mut guard = ReplayGuard::new(30_000, 128);
        assert_eq!(
            authenticate_subscribe(&auth, &server(), "channel:x", 5_000, &mut guard),
            Err(GateOutcome::AuthSignatureInvalid)
        );
        assert_eq!(guard.len(), 0);
    }
}
