//! Verified names: the signed objects of JEP-0004 and the exact bytes each signs.
//!
//! A name is `alias@suffix`. A nameserver vouches that a name belongs to a DID
//! with an [`Attestation`]; a [`SuffixDelegation`] says which DIDs may vouch for
//! a suffix; a [`RotationStatement`], signed by both keys, moves a name from one
//! DID to another; a [`ReachabilityRecord`], signed by the DID itself, says where
//! the DID wants to be found. Whoever acts on a binding verifies it here; who
//! fetched it does not matter.
//!
//! Every signature is Ed25519 over a [`hash_labeled_parts`] digest whose first
//! part is (`domain`, a tag naming the object). Times, counts and sequence
//! numbers are decimal ASCII. Test vectors live in
//! `repos/jig-spec/jep/vectors/0004/`.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::hash_labeled_parts;
use crate::did::Did;

pub const ATTESTATION_DOMAIN: &str = "jig-alias-attestation-v1";
pub const ROTATION_DOMAIN: &str = "jig-alias-rotate-v1";
pub const DELEGATION_DOMAIN: &str = "jig-suffix-delegation-v1";
pub const REACHABILITY_DOMAIN: &str = "jig-reach-v1";

/// Longest alias local part, in characters.
pub const MAX_ALIAS_LEN: usize = 24;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NamingError {
    #[error("`{0}` is not a name of the form alias@suffix")]
    BadName(String),
    #[error("`{0}` is not a did:jig key")]
    BadDid(String),
    #[error("the signature is not by {0}")]
    BadSignature(String),
    #[error("{0} is not an authority for suffix `{1}`")]
    NotAuthoritative(String, String),
    #[error("the delegation for `{0}` lacks a signature from {1}")]
    MissingDelegationSignature(String, String),
    #[error("the delegation is for `{0}`, not `{1}`")]
    OtherSuffix(String, String),
    #[error("the attestation is for `{0}`, not `{1}`")]
    OtherAlias(String, String),
    #[error("the attestation is not valid until {0}")]
    NotYetValid(i64),
    #[error("the attestation expired at {0}")]
    Expired(i64),
    #[error("the delegation expired at {0}")]
    DelegationExpired(i64),
    #[error("the rotation chain does not lead from {0} to {1}")]
    BrokenChain(String, String),
    #[error("a rotation was accepted by {0}, not by {1}")]
    OtherNameserver(String, String),
}

/// A parsed, normalised `alias@suffix`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Name {
    pub alias: String,
    pub suffix: String,
}

impl Name {
    /// Parse and normalise: the alias is 1–[`MAX_ALIAS_LEN`] characters of
    /// `[A-Za-z0-9_-]`, both parts are lowercased, and the suffix is a dotted
    /// name of `[a-z0-9-]` labels with no empty label.
    pub fn parse(s: &str) -> Result<Self, NamingError> {
        let bad = || NamingError::BadName(s.to_string());
        let (alias, suffix) = s.split_once('@').ok_or_else(bad)?;
        let alias_ok = !alias.is_empty()
            && alias.chars().count() <= MAX_ALIAS_LEN
            && alias
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        let suffix_ok = !suffix.is_empty()
            && suffix.split('.').all(|label| {
                !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
        if !alias_ok || !suffix_ok {
            return Err(bad());
        }
        Ok(Self {
            alias: alias.to_ascii_lowercase(),
            suffix: suffix.to_ascii_lowercase(),
        })
    }

    /// The canonical `alias@suffix` form signed into attestations.
    pub fn as_alias(&self) -> String {
        format!("{}@{}", self.alias, self.suffix)
    }
}

/// What makes a [`SuffixDelegation`] authoritative (JEP-0004 rule 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Root {
    Config,
    Dns,
    Contract,
}

impl Root {
    pub fn as_str(self) -> &'static str {
        match self {
            Root::Config => "config",
            Root::Dns => "dns",
            Root::Contract => "contract",
        }
    }
}

/// The action a proof of control is bound to (JEP-0004 rule 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Register,
    Renew,
    Rotate,
}

impl Action {
    pub fn domain(self) -> &'static str {
        match self {
            Action::Register => "jig-alias-register-v1",
            Action::Renew => "jig-alias-renew-v1",
            Action::Rotate => "jig-alias-rotate-proof-v1",
        }
    }
}

/// What a DID signs to prove control for `action` on `alias` at `ns_did`.
pub fn proof_hash(action: Action, ns_did: &str, alias: &str, challenge: &str) -> [u8; 32] {
    *hash_labeled_parts(&[
        ("domain", action.domain().as_bytes()),
        ("ns_did", ns_did.as_bytes()),
        ("alias", alias.as_bytes()),
        ("challenge", challenge.as_bytes()),
    ])
    .as_bytes()
}

/// Sign a proof of control as `key`.
pub fn sign_proof(
    key: &SigningKey,
    action: Action,
    ns_did: &str,
    alias: &str,
    challenge: &str,
) -> String {
    b64(&key.sign(&proof_hash(action, ns_did, alias, challenge)))
}

/// Check a proof of control by `did`.
pub fn verify_proof(
    did: &str,
    sig_b64: &str,
    action: Action,
    ns_did: &str,
    alias: &str,
    challenge: &str,
) -> Result<(), NamingError> {
    verify_sig(did, sig_b64, &proof_hash(action, ns_did, alias, challenge))
}

/// A nameserver's claim that `alias` belongs to `did` (JEP-0004 rule 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub did: String,
    pub alias: String,
    pub ns_did: String,
    pub valid_from: i64,
    pub valid_until: i64,
    /// `ns_did`'s signature over [`Attestation::signed_hash`], base64.
    pub sig: String,
}

impl Attestation {
    pub fn signed_hash(&self) -> [u8; 32] {
        let from = self.valid_from.to_string();
        let until = self.valid_until.to_string();
        *hash_labeled_parts(&[
            ("domain", ATTESTATION_DOMAIN.as_bytes()),
            ("did", self.did.as_bytes()),
            ("alias", self.alias.as_bytes()),
            ("ns_did", self.ns_did.as_bytes()),
            ("valid_from", from.as_bytes()),
            ("valid_until", until.as_bytes()),
        ])
        .as_bytes()
    }

    /// Issue an attestation signed by `ns_key`.
    pub fn sign(
        ns_key: &SigningKey,
        did: &str,
        alias: &str,
        valid_from: i64,
        valid_until: i64,
    ) -> Self {
        let mut att = Self {
            did: did.to_string(),
            alias: alias.to_string(),
            ns_did: did_of(ns_key),
            valid_from,
            valid_until,
            sig: String::new(),
        };
        att.sig = b64(&ns_key.sign(&att.signed_hash()));
        att
    }

    /// The signature is `ns_did`'s. Says nothing about authority or time.
    pub fn verify(&self) -> Result<(), NamingError> {
        verify_sig(&self.ns_did, &self.sig, &self.signed_hash())
    }
}

/// Both keys' agreement that `alias` moves from `old_did` to `new_did`
/// (JEP-0004 rule 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationStatement {
    pub alias: String,
    /// The nameserver that accepted the rotation.
    pub ns_did: String,
    pub old_did: String,
    pub new_did: String,
    pub at: i64,
    pub sig_old: String,
    pub sig_new: String,
}

impl RotationStatement {
    pub fn signed_hash(&self) -> [u8; 32] {
        let at = self.at.to_string();
        *hash_labeled_parts(&[
            ("domain", ROTATION_DOMAIN.as_bytes()),
            ("alias", self.alias.as_bytes()),
            ("ns_did", self.ns_did.as_bytes()),
            ("old_did", self.old_did.as_bytes()),
            ("new_did", self.new_did.as_bytes()),
            ("at", at.as_bytes()),
        ])
        .as_bytes()
    }

    pub fn sign(
        old_key: &SigningKey,
        new_key: &SigningKey,
        alias: &str,
        ns_did: &str,
        at: i64,
    ) -> Self {
        let mut st = Self {
            alias: alias.to_string(),
            ns_did: ns_did.to_string(),
            old_did: did_of(old_key),
            new_did: did_of(new_key),
            at,
            sig_old: String::new(),
            sig_new: String::new(),
        };
        let hash = st.signed_hash();
        st.sig_old = b64(&old_key.sign(&hash));
        st.sig_new = b64(&new_key.sign(&hash));
        st
    }

    pub fn verify(&self) -> Result<(), NamingError> {
        let hash = self.signed_hash();
        verify_sig(&self.old_did, &self.sig_old, &hash)?;
        verify_sig(&self.new_did, &self.sig_new, &hash)
    }
}

/// Which DIDs speak for a suffix, under which root (JEP-0004 rule 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuffixDelegation {
    pub suffix: String,
    pub authorities: Vec<String>,
    pub root: Root,
    /// For `config`, a local identifier never sent to anyone; for `dns`, the
    /// domain; for `contract`, the contract's CID.
    pub root_id: String,
    pub valid_until: i64,
    /// One `(authority DID, signature)` per authority.
    pub sigs: Vec<(String, String)>,
}

impl SuffixDelegation {
    pub fn signed_hash(&self) -> [u8; 32] {
        let mut authorities: Vec<&str> = self.authorities.iter().map(String::as_str).collect();
        authorities.sort_unstable();
        let count = authorities.len().to_string();
        let until = self.valid_until.to_string();
        let mut parts: Vec<(&str, &[u8])> = vec![
            ("domain", DELEGATION_DOMAIN.as_bytes()),
            ("suffix", self.suffix.as_bytes()),
            ("root", self.root.as_str().as_bytes()),
            ("root_id", self.root_id.as_bytes()),
            ("count", count.as_bytes()),
        ];
        parts.extend(authorities.iter().map(|a| ("authority", a.as_bytes())));
        parts.push(("valid_until", until.as_bytes()));
        *hash_labeled_parts(&parts).as_bytes()
    }

    /// A delegation signed by every key in `authority_keys`.
    pub fn sign(
        authority_keys: &[&SigningKey],
        suffix: &str,
        root: Root,
        root_id: &str,
        valid_until: i64,
    ) -> Self {
        let mut deleg = Self {
            suffix: suffix.to_string(),
            authorities: authority_keys.iter().map(|k| did_of(k)).collect(),
            root,
            root_id: root_id.to_string(),
            valid_until,
            sigs: Vec::new(),
        };
        let hash = deleg.signed_hash();
        deleg.sigs = authority_keys
            .iter()
            .map(|k| (did_of(k), b64(&k.sign(&hash))))
            .collect();
        deleg
    }

    /// Every listed authority signed, and nobody else counts.
    pub fn verify(&self) -> Result<(), NamingError> {
        let hash = self.signed_hash();
        for authority in &self.authorities {
            let sig = self
                .sigs
                .iter()
                .find(|(did, _)| did == authority)
                .map(|(_, sig)| sig)
                .ok_or_else(|| {
                    NamingError::MissingDelegationSignature(self.suffix.clone(), authority.clone())
                })?;
            verify_sig(authority, sig, &hash)?;
        }
        Ok(())
    }
}

/// Where a DID wants to be found, signed by that DID (JEP-0004 rule 21).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityRecord {
    pub did: String,
    /// `(server DID, URL)` pairs, in the order signed.
    pub servers: Vec<(String, String)>,
    pub seq: u64,
    pub sig: String,
}

impl ReachabilityRecord {
    pub fn signed_hash(&self) -> [u8; 32] {
        let seq = self.seq.to_string();
        let count = self.servers.len().to_string();
        let mut parts: Vec<(&str, &[u8])> = vec![
            ("domain", REACHABILITY_DOMAIN.as_bytes()),
            ("did", self.did.as_bytes()),
            ("seq", seq.as_bytes()),
            ("count", count.as_bytes()),
        ];
        for (server_did, url) in &self.servers {
            parts.push(("server_did", server_did.as_bytes()));
            parts.push(("url", url.as_bytes()));
        }
        *hash_labeled_parts(&parts).as_bytes()
    }

    pub fn sign(key: &SigningKey, servers: Vec<(String, String)>, seq: u64) -> Self {
        let mut rec = Self {
            did: did_of(key),
            servers,
            seq,
            sig: String::new(),
        };
        rec.sig = b64(&key.sign(&rec.signed_hash()));
        rec
    }

    pub fn verify(&self) -> Result<(), NamingError> {
        verify_sig(&self.did, &self.sig, &self.signed_hash())
    }
}

/// Everything a resolver checks before acting on a binding (JEP-0004 rule 13):
/// the delegation is for this suffix, unexpired and fully signed; the signer is
/// one of its authorities; the attestation's signature, time window and alias.
/// `now` is the verifier's clock.
pub fn verify_binding(
    att: &Attestation,
    deleg: &SuffixDelegation,
    name: &Name,
    now: i64,
) -> Result<(), NamingError> {
    if deleg.suffix != name.suffix {
        return Err(NamingError::OtherSuffix(
            deleg.suffix.clone(),
            name.suffix.clone(),
        ));
    }
    if now >= deleg.valid_until {
        return Err(NamingError::DelegationExpired(deleg.valid_until));
    }
    deleg.verify()?;
    if !deleg.authorities.contains(&att.ns_did) {
        return Err(NamingError::NotAuthoritative(
            att.ns_did.clone(),
            name.suffix.clone(),
        ));
    }
    att.verify()?;
    if now < att.valid_from {
        return Err(NamingError::NotYetValid(att.valid_from));
    }
    if now >= att.valid_until {
        return Err(NamingError::Expired(att.valid_until));
    }
    let wanted = name.as_alias();
    if att.alias != wanted {
        return Err(NamingError::OtherAlias(att.alias.clone(), wanted));
    }
    Ok(())
}

/// A chain of rotations leads from `pinned` to `new` for `alias`, each signed
/// by both keys and accepted by `ns_did` (JEP-0004 rule 18). An empty chain
/// only connects a DID to itself.
pub fn verify_rotation_chain(
    alias: &str,
    ns_did: &str,
    pinned: &str,
    chain: &[RotationStatement],
    new: &str,
) -> Result<(), NamingError> {
    let mut current = pinned;
    for st in chain {
        if st.alias != alias || st.old_did != current {
            return Err(NamingError::BrokenChain(pinned.into(), new.into()));
        }
        if st.ns_did != ns_did {
            return Err(NamingError::OtherNameserver(
                st.ns_did.clone(),
                ns_did.into(),
            ));
        }
        st.verify()?;
        current = &st.new_did;
    }
    if current == new {
        Ok(())
    } else {
        Err(NamingError::BrokenChain(pinned.into(), new.into()))
    }
}

fn did_of(key: &SigningKey) -> String {
    Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
}

fn b64(sig: &Signature) -> String {
    base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
}

fn verify_sig(did: &str, sig_b64: &str, msg: &[u8; 32]) -> Result<(), NamingError> {
    let key = Did::from_did_jig_string(did)
        .and_then(|d| d.as_bytes())
        .ok()
        .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        .ok_or_else(|| NamingError::BadDid(did.to_string()))?;
    let bad_sig = || NamingError::BadSignature(did.to_string());
    let sig = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(bad_sig)?;
    key.verify(msg, &sig).map_err(|_| bad_sig())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn name() -> Name {
        Name::parse("Alice@Example.org").unwrap()
    }

    fn ns() -> SigningKey {
        key(7)
    }

    fn deleg(keys: &[&SigningKey]) -> SuffixDelegation {
        SuffixDelegation::sign(keys, "example.org", Root::Dns, "example.org", NOW + 1000)
    }

    fn att(ns: &SigningKey, did: &str) -> Attestation {
        Attestation::sign(ns, did, "alice@example.org", NOW - 10, NOW + 100)
    }

    #[test]
    fn names_parse_and_normalise() {
        let n = name();
        assert_eq!(n.alias, "alice");
        assert_eq!(n.suffix, "example.org");
        assert_eq!(n.as_alias(), "alice@example.org");
        for bad in [
            "alice",
            "@example.org",
            "alice@",
            "a@b@c",
            "al ice@example.org",
            "alice@exa mple.org",
            "alice@example.org.",
            "alice@.org",
            "aaaaaaaaaaaaaaaaaaaaaaaaa@example.org",
        ] {
            assert!(Name::parse(bad).is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn an_honest_binding_verifies() {
        let alice = did_of(&key(9));
        assert_eq!(
            verify_binding(&att(&ns(), &alice), &deleg(&[&ns()]), &name(), NOW),
            Ok(())
        );
    }

    #[test]
    fn each_broken_binding_fails_for_its_own_reason() {
        let alice = did_of(&key(9));
        let d = deleg(&[&ns()]);

        let stranger = key(42);
        assert_eq!(
            verify_binding(&att(&stranger, &alice), &d, &name(), NOW),
            Err(NamingError::NotAuthoritative(
                did_of(&stranger),
                "example.org".into()
            ))
        );

        let mut forged = att(&ns(), &alice);
        forged.did = did_of(&key(11));
        assert_eq!(
            verify_binding(&forged, &d, &name(), NOW),
            Err(NamingError::BadSignature(did_of(&ns())))
        );

        let a = att(&ns(), &alice);
        assert_eq!(
            verify_binding(&a, &d, &name(), NOW + 100),
            Err(NamingError::Expired(NOW + 100))
        );
        assert_eq!(
            verify_binding(&a, &d, &name(), NOW - 11),
            Err(NamingError::NotYetValid(NOW - 10))
        );

        let other = Name::parse("bob@example.org").unwrap();
        assert_eq!(
            verify_binding(&a, &d, &other, NOW),
            Err(NamingError::OtherAlias(
                "alice@example.org".into(),
                "bob@example.org".into()
            ))
        );

        let elsewhere = Name::parse("alice@example.net").unwrap();
        assert!(matches!(
            verify_binding(&a, &d, &elsewhere, NOW),
            Err(NamingError::OtherSuffix(..))
        ));

        assert_eq!(
            verify_binding(&a, &d, &name(), NOW + 1000),
            Err(NamingError::DelegationExpired(NOW + 1000))
        );
    }

    #[test]
    fn a_delegation_needs_every_authority_and_no_more() {
        let (a, b) = (key(7), key(8));
        let mut d = deleg(&[&a, &b]);
        assert_eq!(d.verify(), Ok(()));
        d.sigs.retain(|(did, _)| *did == did_of(&a));
        assert_eq!(
            d.verify(),
            Err(NamingError::MissingDelegationSignature(
                "example.org".into(),
                did_of(&b)
            ))
        );
        // Authority order does not change the signed bytes.
        let mut swapped = deleg(&[&a, &b]);
        swapped.authorities.reverse();
        assert_eq!(swapped.verify(), Ok(()));
    }

    #[test]
    fn rotation_chains_move_a_pin_only_with_both_keys() {
        let (k1, k2, k3) = (key(9), key(11), key(13));
        let ns_did = did_of(&ns());
        let r1 = RotationStatement::sign(&k1, &k2, "alice@example.org", &ns_did, NOW);
        let r2 = RotationStatement::sign(&k2, &k3, "alice@example.org", &ns_did, NOW + 1);
        let (d1, d3) = (did_of(&k1), did_of(&k3));
        let chain = [r1.clone(), r2.clone()];
        assert_eq!(
            verify_rotation_chain("alice@example.org", &ns_did, &d1, &chain, &d3),
            Ok(())
        );
        assert!(
            verify_rotation_chain(
                "alice@example.org",
                &ns_did,
                &d1,
                std::slice::from_ref(&r2),
                &d3
            )
            .is_err()
        );
        assert!(verify_rotation_chain("alice@example.org", &ns_did, &d1, &[], &d3).is_err());

        let mut tampered = r1.clone();
        tampered.new_did = did_of(&key(42));
        assert!(matches!(
            tampered.verify(),
            Err(NamingError::BadSignature(_))
        ));

        let other_ns = did_of(&key(8));
        assert_eq!(
            verify_rotation_chain("alice@example.org", &other_ns, &d1, &chain, &d3),
            Err(NamingError::OtherNameserver(ns_did, other_ns))
        );
    }

    #[test]
    fn proofs_are_bound_to_the_action() {
        let k = key(9);
        let did = did_of(&k);
        let ns_did = did_of(&ns());
        let sig = sign_proof(&k, Action::Register, &ns_did, "alice@example.org", "c0ffee");
        assert_eq!(
            verify_proof(
                &did,
                &sig,
                Action::Register,
                &ns_did,
                "alice@example.org",
                "c0ffee"
            ),
            Ok(())
        );
        for (action, alias, challenge) in [
            (Action::Renew, "alice@example.org", "c0ffee"),
            (Action::Register, "bob@example.org", "c0ffee"),
            (Action::Register, "alice@example.org", "beef"),
        ] {
            assert!(verify_proof(&did, &sig, action, &ns_did, alias, challenge).is_err());
        }
        // A signature over the bare challenge is not a proof.
        let bare = b64(&k.sign(b"c0ffee"));
        assert!(
            verify_proof(
                &did,
                &bare,
                Action::Register,
                &ns_did,
                "alice@example.org",
                "c0ffee"
            )
            .is_err()
        );
    }

    #[test]
    fn reachability_records_sign_their_server_order() {
        let k = key(9);
        let servers = vec![
            (
                "did:jig:zserverone".to_string(),
                "https://one.example".to_string(),
            ),
            (
                "did:jig:zservertwo".to_string(),
                "https://two.example".to_string(),
            ),
        ];
        let rec = ReachabilityRecord::sign(&k, servers, 3);
        assert_eq!(rec.verify(), Ok(()));
        let mut reordered = rec.clone();
        reordered.servers.reverse();
        assert!(reordered.verify().is_err());
    }

    /// The committed vectors pin the encoding: a change to any signed byte
    /// fails here, and the JEP's vectors must be regenerated on purpose.
    #[test]
    fn signed_bytes_match_the_committed_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../jig-spec/jep/vectors/0004/vectors.json"))
                .unwrap();
        assert_eq!(vectors(), v);
    }

    /// `cargo test -p jig-core --features ed25519 naming::tests::print_vectors -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_vectors() {
        println!("{}", serde_json::to_string_pretty(&vectors()).unwrap());
    }

    fn vectors() -> serde_json::Value {
        let (ns, alice, alice2) = (key(7), key(9), key(11));
        let att = Attestation::sign(
            &ns,
            &did_of(&alice),
            "alice@example.org",
            1_800_000_000,
            1_807_776_000,
        );
        let rot = RotationStatement::sign(
            &alice,
            &alice2,
            "alice@example.org",
            &did_of(&ns),
            1_800_000_500,
        );
        let deleg = SuffixDelegation::sign(
            &[&ns],
            "example.org",
            Root::Dns,
            "example.org",
            1_831_536_000,
        );
        let reach = ReachabilityRecord::sign(
            &alice,
            vec![(did_of(&key(13)), "https://chat.example.org".to_string())],
            1,
        );
        let proof = sign_proof(
            &alice,
            Action::Register,
            &did_of(&ns),
            "alice@example.org",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        serde_json::json!({
            "keys": {
                "comment": "Ed25519 seeds: every byte set to the given value",
                "nameserver": {"seed_byte": 7, "did": did_of(&ns)},
                "alice": {"seed_byte": 9, "did": did_of(&alice)},
                "alice_rotated": {"seed_byte": 11, "did": did_of(&alice2)},
                "server": {"seed_byte": 13, "did": did_of(&key(13))},
            },
            "attestation": {"object": att, "signed_hash_hex": hex::encode(att.signed_hash())},
            "rotation": {"object": rot, "signed_hash_hex": hex::encode(rot.signed_hash())},
            "delegation": {"object": deleg, "signed_hash_hex": hex::encode(deleg.signed_hash())},
            "reachability": {"object": reach, "signed_hash_hex": hex::encode(reach.signed_hash())},
            "register_proof": {
                "action": "register",
                "ns_did": did_of(&ns),
                "alias": "alice@example.org",
                "challenge": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "signed_hash_hex": hex::encode(proof_hash(
                    Action::Register,
                    &did_of(&ns),
                    "alice@example.org",
                    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                )),
                "sig": proof,
            },
        })
    }
}
