//! Proof of work for admitting an identity a server has never seen.
//!
//! A server whose `[auth.admission]` policy is `proof-of-work` asks a new DID
//! to do some work once before it deals with it, so minting identities to
//! spread a flood across many rate-limit buckets costs something. The work is
//! bound to the server and the DID: it cannot be reused against another server
//! or for another identity. Unlike a keyed scheme, anyone can check it, so the
//! client can tell when it is done.
//!
//! Two forms are accepted. The current one is JEP-0008's `admit` action
//! ([`puzzle`], [`proof_message`]): a [`crate::pow::Proof`] on the shared
//! puzzle, with an empty binding and salt. The legacy `jig-admission-pow-v1`
//! form below is kept for one release (JEP-0008, Backwards Compatibility) so
//! clients from before it keep working; its `bits` is effort `2^bits`.
//!
//! TODO(R1, release after v0.2.0-alpha.2): remove the legacy form ([`DOMAIN`],
//! [`digest`], [`meets`], [`solve`], [`signed_message`]) and its acceptance in
//! `jig-server`'s `/api/v1/admission`. Deprecated in alpha.2.
//!
//! Legacy: the digest is [`hash_labeled_parts`] over (`domain`, [`DOMAIN`]),
//! (`server`, the server's DID), (`did`, the new DID) and (`nonce`, the
//! client's nonce). The work is done when the digest has at least `bits`
//! leading zero bits. The client signs [`signed_message`] with the DID's key, so
//! nobody can admit an identity whose key they do not hold.

use std::num::NonZeroU64;

use crate::crypto::hash_labeled_parts;
use crate::pow::{Action, Proof, Puzzle};

pub const DOMAIN: &str = "jig-admission-pow-v1";

/// The most work a server may ask for, and a client will do. 2^28 digests is
/// about a minute on one laptop core; past that a server is closed while
/// claiming to be open, and a client that obeyed could be pinned for hours.
pub const MAX_BITS: u8 = 28;

/// The digest the work is measured on.
pub fn digest(server_did: &str, did: &str, nonce: &str) -> [u8; 32] {
    *hash_labeled_parts(&[
        ("domain", DOMAIN.as_bytes()),
        ("server", server_did.as_bytes()),
        ("did", did.as_bytes()),
        ("nonce", nonce.as_bytes()),
    ])
    .as_bytes()
}

/// Leading zero bits of `bytes`, most significant first.
pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in bytes {
        if *byte == 0 {
            bits += 8;
        } else {
            return bits + byte.leading_zeros();
        }
    }
    bits
}

/// Whether `nonce` is at least `bits` of work for `did` on `server_did`.
pub fn meets(server_did: &str, did: &str, nonce: &str, bits: u8) -> bool {
    leading_zero_bits(&digest(server_did, did, nonce)) >= u32::from(bits)
}

/// Find a nonce worth `bits`. Expected cost is 2^bits digests.
pub fn solve(server_did: &str, did: &str, bits: u8) -> String {
    (0u64..)
        .map(|n| format!("{n:x}"))
        .find(|nonce| meets(server_did, did, nonce, bits))
        .expect("an unbounded search finds a nonce")
}

/// What the DID signs alongside the work: proof that whoever did it holds the
/// key, for this server.
pub fn signed_message(server_did: &str, did: &str, nonce: &str) -> [u8; 32] {
    *hash_labeled_parts(&[
        ("domain", b"jig-admission-v1"),
        ("server", server_did.as_bytes()),
        ("did", did.as_bytes()),
        ("nonce", nonce.as_bytes()),
    ])
    .as_bytes()
}

/// The JEP-0008 `admit` puzzle: `subject` asks `server_did` to admit it. The
/// binding and salt are empty (rule 13, admission mode).
pub fn puzzle<'a>(server_did: &'a str, subject: &'a str) -> Puzzle<'a> {
    Puzzle::new(server_did, subject, Action::Admit, b"").expect("admit is an admission-mode action")
}

/// The effort a legacy `bits` setting stands for: `2^bits` (JEP-0008 rule 7).
/// `bits` above 63 saturates at the largest effort.
pub fn effort_for_bits(bits: u8) -> NonZeroU64 {
    NonZeroU64::new(1u64.checked_shl(u32::from(bits)).unwrap_or(u64::MAX))
        .expect("a power of two is never zero")
}

/// The whole bits of work `effort` is worth, for the proof store's bit count:
/// `floor(log2(effort))`.
pub fn bits_for_effort(effort: NonZeroU64) -> u8 {
    (63 - effort.leading_zeros()) as u8
}

/// What the DID signs alongside a JEP-0008 `admit` proof: that whoever did
/// the work holds the key, for this server, for this exact proof.
pub fn proof_message(server_did: &str, did: &str, proof: &Proof) -> [u8; 32] {
    *hash_labeled_parts(&[
        ("domain", b"jig-admission-v2"),
        ("server", server_did.as_bytes()),
        ("did", did.as_bytes()),
        ("alg", proof.alg.id().to_string().as_bytes()),
        ("effort", &proof.effort.get().to_be_bytes()),
        ("nonce", &proof.nonce),
        ("salt_id", &proof.salt_id.to_be_bytes()),
    ])
    .as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_counts_across_bytes() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0x10]), 11);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn work_is_bound_to_the_server_and_the_did() {
        let nonce = solve("did:jig:zServer", "did:jig:zAlice", 8);
        assert!(meets("did:jig:zServer", "did:jig:zAlice", &nonce, 8));
        // The same nonce is a fresh, unsolved puzzle anywhere else (at 16 bits
        // a chance hit is one in 65 536).
        let nonce = solve("did:jig:zServer", "did:jig:zAlice", 16);
        assert!(!meets("did:jig:zOther", "did:jig:zAlice", &nonce, 16));
        assert!(!meets("did:jig:zServer", "did:jig:zMallory", &nonce, 16));
    }

    /// The digest as the module docs specify it, rebuilt from raw BLAKE3, so
    /// an independent client can compute it.
    #[test]
    fn the_digest_is_the_specified_derivation() {
        // Any nonce will do; take the one the solver finds.
        let nonce = solve("did:jig:zS", "did:jig:zD", 1);
        let mut h = blake3::Hasher::new();
        for (label, value) in [
            ("domain", DOMAIN),
            ("server", "did:jig:zS"),
            ("did", "did:jig:zD"),
            ("nonce", nonce.as_str()),
        ] {
            h.update(label.as_bytes());
            h.update(&(value.len() as u64).to_le_bytes());
            h.update(value.as_bytes());
        }
        assert_eq!(
            digest("did:jig:zS", "did:jig:zD", &nonce),
            *h.finalize().as_bytes()
        );
    }

    #[test]
    fn bits_and_effort_agree() {
        assert_eq!(effort_for_bits(20).get(), 1 << 20);
        assert_eq!(bits_for_effort(effort_for_bits(20)), 20);
        assert_eq!(bits_for_effort(NonZeroU64::new(3).unwrap()), 1);
        assert_eq!(effort_for_bits(64).get(), u64::MAX);
    }

    #[test]
    fn an_admit_proof_is_bound_to_the_server_and_the_did() {
        let effort = effort_for_bits(10);
        let proof = puzzle("did:jig:zServer", "did:jig:zAlice").solve(effort);
        assert_eq!(
            puzzle("did:jig:zServer", "did:jig:zAlice").check(&proof, effort),
            Ok(())
        );
        assert!(
            puzzle("did:jig:zOther", "did:jig:zAlice")
                .check(&proof, effort)
                .is_err()
        );
        assert!(
            puzzle("did:jig:zServer", "did:jig:zMallory")
                .check(&proof, effort)
                .is_err()
        );
        // The signed message changes with every part of the proof.
        let m = proof_message("did:jig:zServer", "did:jig:zAlice", &proof);
        let mut other = proof.clone();
        other.effort = effort_for_bits(11);
        assert_ne!(
            m,
            proof_message("did:jig:zServer", "did:jig:zAlice", &other)
        );
        assert_ne!(m, proof_message("did:jig:zOther", "did:jig:zAlice", &proof));
    }
}
