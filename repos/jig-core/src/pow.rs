//! Proof of work: the puzzle of JEP-0008.
//!
//! One puzzle serves every action a verifier prices: admitting a new DID,
//! registering a name, stamping a post. The work is bound to the verifier,
//! the subject, the action and what the action acts on, so it cannot be
//! reused anywhere else. Nothing is keyed: anyone can check a proof, and a
//! solver knows when it is done.
//!
//! The digest is the labelled hash of [`crate::crypto::hash_labeled_parts`] over, in order, (`domain`,
//! [`DOMAIN`]), (`alg`, the algorithm id as decimal ASCII), (`verifier`),
//! (`subject`), (`action`, the [`Action`] label), (`binding`), (`salt`) and
//! (`nonce`) (rule 6). Work is valid for effort `E` when the first 8 bytes of
//! the digest, read big-endian, are at most `⌊(2^64 − 1) / E⌋` (rule 7), so a
//! solver expects to compute `E` digests.
//!
//! This module holds the puzzle only. Who asks for how much effort, and when,
//! is the verifier's (JEP-0008 rules 16–33). Test vectors live in
//! `repos/jig-spec/jep/vectors/0008/`.

use std::fmt;
use std::num::NonZeroU64;

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use blake3::Hasher;

pub const DOMAIN: &str = "jig-pow-v1";

/// Longest nonce a verifier accepts, in bytes (rule 6).
pub const MAX_NONCE_LEN: usize = 64;

/// The most effort a verifier may ask for `admit` or a challenge action, and
/// the most a client should do (rule 19). It is a hard ceiling, not a
/// default: at the 5.5 million digests a second `benches/pow.rs` measured on
/// one server core, 2^28 is about 50 seconds, and a phone is slower. A
/// verifier's own `max_effort` must fit its `max_solve_secs` on the slowest
/// client it serves.
pub const MAX_EFFORT: u64 = 1 << 28;

/// The `salt_id` of the empty salt that admission and challenge modes use.
/// A stamp's `salt_id` is its epoch number, and epochs start at 1 (rule 13).
pub const EMPTY_SALT_ID: u64 = 0;

/// A registered algorithm (rule 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alg {
    /// The digest of rule 6 itself.
    Blake3 = 1,
}

impl Alg {
    pub fn id(self) -> u8 {
        self as u8
    }

    pub fn from_id(id: u8) -> Option<Self> {
        (id == 1).then_some(Alg::Blake3)
    }

    /// The id as decimal ASCII, as the digest takes it (rule 6).
    fn ascii(self) -> &'static [u8] {
        match self {
            Alg::Blake3 => b"1",
        }
    }
}

impl Serialize for Alg {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.id())
    }
}

impl<'de> Deserialize<'de> for Alg {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let id = u8::deserialize(d)?;
        Alg::from_id(id).ok_or_else(|| serde::de::Error::custom(format!("unknown alg {id}")))
    }
}

/// How an action's work is kept fresh (rule 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Empty salt; the verifier records the subject as proven.
    Admission,
    /// The verifier's epoch salt; the verifier keeps the digests it accepted.
    Stamp,
    /// Empty salt; a single-use challenge sits inside the binding.
    Challenge,
}

/// A registered action (rule 11). The caller computes the binding the table
/// names for it; this module only hashes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Admit,
    Post,
    KpRequest,
    Dial,
    NsRegister,
    NsRenew,
    NsRotate,
}

impl Action {
    pub const ALL: [Action; 7] = [
        Action::Admit,
        Action::Post,
        Action::KpRequest,
        Action::Dial,
        Action::NsRegister,
        Action::NsRenew,
        Action::NsRotate,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Action::Admit => "admit",
            Action::Post => "post",
            Action::KpRequest => "kp-request",
            Action::Dial => "dial",
            Action::NsRegister => "ns-register",
            Action::NsRenew => "ns-renew",
            Action::NsRotate => "ns-rotate",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        Action::ALL.into_iter().find(|a| a.label() == label)
    }

    pub fn mode(self) -> Mode {
        match self {
            Action::Admit => Mode::Admission,
            Action::Post | Action::KpRequest | Action::Dial => Mode::Stamp,
            Action::NsRegister | Action::NsRenew | Action::NsRotate => Mode::Challenge,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A proof of work: `{alg, effort, nonce, salt_id}` (rule 10). On the wire
/// the nonce is unpadded base64url.
///
/// `effort` is what the solver bid, which may be more than the verifier asked
/// for (rule 20). It is never zero: an effort of zero means no work is asked,
/// and then there is no proof to send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub alg: Alg,
    pub effort: NonZeroU64,
    #[serde(with = "nonce_b64u")]
    pub nonce: Vec<u8>,
    pub salt_id: u64,
}

mod nonce_b64u {
    use super::{BASE64URL_NOPAD, MAX_NONCE_LEN};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(nonce: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64URL_NOPAD.encode(nonce))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let nonce = BASE64URL_NOPAD
            .decode(s.as_bytes())
            .map_err(|_| serde::de::Error::custom("nonce is not unpadded base64url"))?;
        if nonce.len() > MAX_NONCE_LEN {
            return Err(serde::de::Error::custom(format!(
                "nonce is longer than {MAX_NONCE_LEN} bytes"
            )));
        }
        Ok(nonce)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PowError {
    #[error("the proof uses alg {got}; this verifier asked for alg {asked}")]
    OtherAlg { asked: u8, got: u8 },
    #[error("the proof names salt {got}; this verifier asked for salt {asked}")]
    OtherSalt { asked: u64, got: u64 },
    #[error("the nonce is longer than {MAX_NONCE_LEN} bytes")]
    NonceTooLong,
    #[error("the proof bids effort {offered}; at least {required} is required")]
    Insufficient { offered: u64, required: u64 },
    #[error("the work does not meet the effort it claims")]
    Invalid,
}

/// One puzzle: everything a proof commits to except the nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Puzzle<'a> {
    pub alg: Alg,
    pub verifier: &'a str,
    pub subject: &'a str,
    pub action: Action,
    pub binding: &'a [u8],
    pub salt: &'a [u8],
    pub salt_id: u64,
}

impl<'a> Puzzle<'a> {
    /// A puzzle for an admission or challenge action: the salt is empty.
    ///
    /// # Panics
    /// If `action` is a stamp action, which needs [`Puzzle::stamp`].
    pub fn new(verifier: &'a str, subject: &'a str, action: Action, binding: &'a [u8]) -> Self {
        assert!(
            action.mode() != Mode::Stamp,
            "{action} is a stamp action and needs an epoch salt"
        );
        Self {
            alg: Alg::Blake3,
            verifier,
            subject,
            action,
            binding,
            salt: &[],
            salt_id: EMPTY_SALT_ID,
        }
    }

    /// A puzzle for a stamp action under the epoch salt numbered `epoch`.
    ///
    /// # Panics
    /// If `action` is not a stamp action, or `epoch` is 0.
    pub fn stamp(
        verifier: &'a str,
        subject: &'a str,
        action: Action,
        binding: &'a [u8],
        salt: &'a [u8],
        epoch: u64,
    ) -> Self {
        assert!(
            action.mode() == Mode::Stamp,
            "{action} is not a stamp action"
        );
        assert!(epoch != EMPTY_SALT_ID, "epochs start at 1");
        Self {
            alg: Alg::Blake3,
            verifier,
            subject,
            action,
            binding,
            salt,
            salt_id: epoch,
        }
    }

    /// The digest of rule 6 for `nonce`.
    pub fn digest(&self, nonce: &[u8]) -> [u8; 32] {
        finish(self.prefix(), nonce)
    }

    /// The hasher fed every part but the nonce, the same way
    /// [`crate::crypto::hash_labeled_parts`] feeds them. The solver clones it per nonce
    /// instead of hashing the fixed parts again.
    fn prefix(&self) -> Hasher {
        let mut h = Hasher::new();
        for (label, value) in [
            ("domain", DOMAIN.as_bytes()),
            ("alg", self.alg.ascii()),
            ("verifier", self.verifier.as_bytes()),
            ("subject", self.subject.as_bytes()),
            ("action", self.action.label().as_bytes()),
            ("binding", self.binding),
            ("salt", self.salt),
        ] {
            h.update(label.as_bytes());
            h.update(&(value.len() as u64).to_le_bytes());
            h.update(value);
        }
        h
    }

    /// Check `proof` against this puzzle with one digest (rule 10), requiring
    /// at least `required`. The cheap comparisons run first.
    pub fn check(&self, proof: &Proof, required: NonZeroU64) -> Result<(), PowError> {
        if proof.alg != self.alg {
            return Err(PowError::OtherAlg {
                asked: self.alg.id(),
                got: proof.alg.id(),
            });
        }
        if proof.salt_id != self.salt_id {
            return Err(PowError::OtherSalt {
                asked: self.salt_id,
                got: proof.salt_id,
            });
        }
        if proof.nonce.len() > MAX_NONCE_LEN {
            return Err(PowError::NonceTooLong);
        }
        if proof.effort < required {
            return Err(PowError::Insufficient {
                offered: proof.effort.get(),
                required: required.get(),
            });
        }
        if !meets(&self.digest(&proof.nonce), proof.effort) {
            return Err(PowError::Invalid);
        }
        Ok(())
    }

    /// Search `budget` nonces from `start` for one worth `effort`. Nonces are
    /// the counter as 8 big-endian bytes, so callers can split the space
    /// between threads, report progress between calls, and stop.
    pub fn try_solve(&self, effort: NonZeroU64, start: u64, budget: u64) -> Option<Proof> {
        let prefix = self.prefix();
        let end = start.saturating_add(budget);
        (start..end)
            .map(u64::to_be_bytes)
            .find(|nonce| meets(&finish(prefix.clone(), nonce), effort))
            .map(|nonce| Proof {
                alg: self.alg,
                effort,
                nonce: nonce.to_vec(),
                salt_id: self.salt_id,
            })
    }

    /// Find a proof worth `effort`. Expected cost is `effort` digests.
    pub fn solve(&self, effort: NonZeroU64) -> Proof {
        self.try_solve(effort, 0, u64::MAX)
            .expect("2^64 nonces hold a solution for any effort")
    }
}

fn finish(mut prefix: Hasher, nonce: &[u8]) -> [u8; 32] {
    prefix.update(b"nonce");
    prefix.update(&(nonce.len() as u64).to_le_bytes());
    prefix.update(nonce);
    *prefix.finalize().as_bytes()
}

/// Whether `digest` is worth `effort` (rule 7), written without overflow.
pub fn meets(digest: &[u8; 32], effort: NonZeroU64) -> bool {
    let d = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"));
    d <= u64::MAX / effort.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_labeled_parts;

    const VERIFIER: &str = "did:jig:zverifier";
    const SUBJECT: &str = "did:jig:zsubject";

    fn e(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).unwrap()
    }

    fn admit() -> Puzzle<'static> {
        Puzzle::new(VERIFIER, SUBJECT, Action::Admit, b"")
    }

    #[test]
    fn effort_one_accepts_every_digest() {
        assert!(meets(&[0xff; 32], e(1)));
        assert!(meets(&[0x00; 32], e(1)));
    }

    #[test]
    fn effort_two_to_the_b_is_b_leading_zero_bits() {
        let mut d = [0xff; 32];
        d[0] = 0x00;
        d[1] = 0x7f; // 9 leading zero bits
        assert!(meets(&d, e(1 << 9)));
        assert!(!meets(&d, e(1 << 10)));
    }

    #[test]
    fn the_largest_effort_passes_only_a_zero_prefix() {
        let mut d = [0xff; 32];
        d[..8].copy_from_slice(&[0; 8]);
        assert!(meets(&d, e(u64::MAX)));
        d[7] = 2;
        assert!(!meets(&d, e(u64::MAX)));
    }

    #[test]
    fn a_solved_proof_checks() {
        let proof = admit().solve(e(256));
        assert_eq!(admit().check(&proof, e(256)), Ok(()));
        assert_eq!(proof.salt_id, EMPTY_SALT_ID);
    }

    #[test]
    fn a_proof_is_bound_to_every_part() {
        let binding = b"binding";
        let base = Puzzle::new(VERIFIER, SUBJECT, Action::NsRegister, binding);
        let proof = base.solve(e(1 << 16));
        assert_eq!(base.check(&proof, e(1 << 16)), Ok(()));
        // Change any one part and the work is a fresh, unsolved puzzle (at 2^16
        // a chance hit is one in 65 536).
        let others = [
            Puzzle {
                verifier: "did:jig:zother",
                ..base
            },
            Puzzle {
                subject: "did:jig:zother",
                ..base
            },
            Puzzle {
                action: Action::NsRenew,
                ..base
            },
            Puzzle {
                binding: b"other",
                ..base
            },
            Puzzle {
                salt: b"salt",
                ..base
            },
        ];
        for other in others {
            assert_eq!(other.check(&proof, e(1 << 16)), Err(PowError::Invalid));
        }
    }

    #[test]
    fn checks_refuse_before_hashing() {
        let proof = admit().solve(e(16));
        assert_eq!(
            admit().check(&proof, e(32)),
            Err(PowError::Insufficient {
                offered: 16,
                required: 32
            })
        );
        let stamped = Proof {
            salt_id: 3,
            ..proof.clone()
        };
        assert_eq!(
            admit().check(&stamped, e(16)),
            Err(PowError::OtherSalt { asked: 0, got: 3 })
        );
        let long = Proof {
            nonce: vec![0; MAX_NONCE_LEN + 1],
            ..proof
        };
        assert_eq!(admit().check(&long, e(16)), Err(PowError::NonceTooLong));
    }

    #[test]
    fn a_higher_bid_must_be_real() {
        // A proof worth 2 that claims 2^20 is checked at its claim, and fails.
        let p = admit();
        let mut start = 0;
        let mut proof = loop {
            let found = p.try_solve(e(2), start, u64::MAX - start).unwrap();
            if !meets(&p.digest(&found.nonce), e(1 << 20)) {
                break found;
            }
            start = u64::from_be_bytes(found.nonce[..].try_into().unwrap()) + 1;
        };
        proof.effort = e(1 << 20);
        assert_eq!(p.check(&proof, e(2)), Err(PowError::Invalid));
    }

    #[test]
    fn a_stamp_carries_its_epoch() {
        let salt = [7u8; 32];
        let p = Puzzle::stamp(VERIFIER, SUBJECT, Action::Post, b"cid", &salt, 5);
        let proof = p.solve(e(64));
        assert_eq!(proof.salt_id, 5);
        assert_eq!(p.check(&proof, e(64)), Ok(()));
        let next = Puzzle::stamp(VERIFIER, SUBJECT, Action::Post, b"cid", &salt, 6);
        assert_eq!(
            next.check(&proof, e(64)),
            Err(PowError::OtherSalt { asked: 6, got: 5 })
        );
    }

    #[test]
    #[should_panic(expected = "needs an epoch salt")]
    fn a_stamp_action_needs_a_salt() {
        let _ = Puzzle::new(VERIFIER, SUBJECT, Action::Post, b"");
    }

    #[test]
    #[should_panic(expected = "epochs start at 1")]
    fn epoch_zero_is_the_empty_salt() {
        let _ = Puzzle::stamp(VERIFIER, SUBJECT, Action::Dial, b"", &[1; 32], 0);
    }

    #[test]
    fn actions_round_trip_their_labels() {
        for action in Action::ALL {
            assert_eq!(Action::from_label(action.label()), Some(action));
        }
        assert_eq!(Action::from_label("register"), None);
    }

    #[test]
    fn the_wire_form_is_strict() {
        let proof = admit().solve(e(4));
        let json = serde_json::to_value(&proof).unwrap();
        assert_eq!(json["alg"], 1);
        assert_eq!(json["effort"], 4);
        assert_eq!(json["salt_id"], 0);
        assert_eq!(
            serde_json::from_value::<Proof>(json.clone()).unwrap(),
            proof
        );

        let bad = |patch: serde_json::Value| {
            let mut v = json.clone();
            for (k, val) in patch.as_object().unwrap() {
                v[k] = val.clone();
            }
            serde_json::from_value::<Proof>(v).is_err()
        };
        assert!(bad(serde_json::json!({ "effort": 0 })), "zero effort");
        assert!(bad(serde_json::json!({ "alg": 2 })), "unknown alg");
        assert!(
            bad(serde_json::json!({ "nonce": "AAAA==" })),
            "padded nonce"
        );
        assert!(
            bad(serde_json::json!({ "nonce": BASE64URL_NOPAD.encode(&[0; 65]) })),
            "long nonce"
        );
        assert!(bad(serde_json::json!({ "extra": 1 })), "unknown field");
    }

    /// The digest as rule 6 specifies it, rebuilt from raw BLAKE3, so an
    /// independent implementation can compute it.
    #[test]
    fn the_digest_is_the_specified_derivation() {
        let nonce = [1u8, 2, 3];
        let mut h = blake3::Hasher::new();
        for (label, value) in [
            ("domain", DOMAIN.as_bytes()),
            ("alg", b"1".as_slice()),
            ("verifier", VERIFIER.as_bytes()),
            ("subject", SUBJECT.as_bytes()),
            ("action", b"admit"),
            ("binding", b""),
            ("salt", b""),
            ("nonce", &nonce),
        ] {
            h.update(label.as_bytes());
            h.update(&(value.len() as u64).to_le_bytes());
            h.update(value);
        }
        assert_eq!(admit().digest(&nonce), *h.finalize().as_bytes());
        // The same as the crate's labelled hash, so the encodings cannot drift.
        assert_eq!(
            admit().digest(&nonce),
            *hash_labeled_parts(&[
                ("domain", DOMAIN.as_bytes()),
                ("alg", b"1"),
                ("verifier", VERIFIER.as_bytes()),
                ("subject", SUBJECT.as_bytes()),
                ("action", b"admit"),
                ("binding", b""),
                ("salt", b""),
                ("nonce", &nonce),
            ])
            .as_bytes()
        );
    }

    // ---- Vectors: repos/jig-spec/jep/vectors/0008/vectors.json ----

    const VECTOR_EFFORT: u64 = 1 << 12;

    /// One case per action in rule 11. Bindings are opaque to the puzzle, so
    /// they are fixed stand-ins of the right shape, not derived from real
    /// objects; the consumers' own vectors cover how each binding is built.
    fn vector_cases() -> Vec<Puzzle<'static>> {
        const SALT: &[u8] = &[0x5a; 32];
        const HASH: &[u8] = &[0x11; 32];
        const CID: &[u8] = b"bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy";
        const DIALER: &[u8] = b"did:jig:zdialer";
        Action::ALL
            .into_iter()
            .map(|action| match action {
                Action::Admit => Puzzle::new(VERIFIER, SUBJECT, action, b""),
                Action::Post => Puzzle::stamp(VERIFIER, SUBJECT, action, CID, SALT, 7),
                Action::KpRequest => Puzzle::stamp(VERIFIER, SUBJECT, action, HASH, SALT, 7),
                Action::Dial => Puzzle::stamp(VERIFIER, SUBJECT, action, DIALER, SALT, 7),
                Action::NsRegister | Action::NsRenew | Action::NsRotate => {
                    Puzzle::new(VERIFIER, SUBJECT, action, HASH)
                }
            })
            .collect()
    }

    /// The edge of rule 7 for a power of two and for an effort that is not one.
    fn boundary(effort: u64) -> serde_json::Value {
        let max = u64::MAX / effort;
        let digest_with = |prefix: u64| {
            let mut d = [0xffu8; 32];
            d[..8].copy_from_slice(&prefix.to_be_bytes());
            d
        };
        let (pass, fail) = (digest_with(max), digest_with(max + 1));
        assert!(meets(&pass, e(effort)) && !meets(&fail, e(effort)));
        serde_json::json!({
            "effort": effort,
            "max_prefix_hex": format!("{max:016x}"),
            "passes_digest_hex": hex::encode(pass),
            "fails_digest_hex": hex::encode(fail),
        })
    }

    fn vectors() -> serde_json::Value {
        let cases: Vec<serde_json::Value> = vector_cases()
            .into_iter()
            .map(|p| {
                let proof = p.solve(e(VECTOR_EFFORT));
                serde_json::json!({
                    "alg": p.alg.id(),
                    "verifier": p.verifier,
                    "subject": p.subject,
                    "action": p.action.label(),
                    "binding_hex": hex::encode(p.binding),
                    "salt_hex": hex::encode(p.salt),
                    "salt_id": p.salt_id,
                    "effort": VECTOR_EFFORT,
                    "nonce_hex": hex::encode(&proof.nonce),
                    "digest_hex": hex::encode(p.digest(&proof.nonce)),
                    "proof": proof,
                })
            })
            .collect();
        serde_json::json!({
            "domain": DOMAIN,
            "rule_7": "valid when u64_be(digest[0..8]) <= floor((2^64 - 1) / effort)",
            "boundaries": [boundary(1 << 20), boundary(1_000_003)],
            "cases": cases,
        })
    }

    #[test]
    fn digests_match_the_committed_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../jig-spec/jep/vectors/0008/vectors.json"))
                .unwrap();
        assert_eq!(vectors(), v);
        // And every committed proof checks, read back from its wire form.
        for (case, p) in v["cases"].as_array().unwrap().iter().zip(vector_cases()) {
            let proof: Proof = serde_json::from_value(case["proof"].clone()).unwrap();
            assert_eq!(p.check(&proof, e(VECTOR_EFFORT)), Ok(()));
        }
    }

    /// `cargo test -p jig-core pow::tests::print_vectors -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_vectors() {
        println!("{}", serde_json::to_string_pretty(&vectors()).unwrap());
    }
}
