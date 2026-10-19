//! Verified names: the signed objects of JEP-0004 and the exact bytes each signs.
//!
//! A name is `alias@suffix`. A nameserver vouches that a name belongs to a DID
//! with an [`Attestation`]; a [`SuffixDelegation`] says which DIDs may vouch for
//! a suffix; a link from the identity design (lane I), signed by both keys and
//! scoped to one nameserver and alias, moves a name from one DID to another
//! ([`AliasLink`]); a [`ReachabilityRecord`], signed by the DID itself, says where
//! the DID wants to be found. Whoever acts on a binding verifies it here; who
//! fetched it does not matter.
//!
//! Every signed object is a COSE_Sign1 ([`crate::cose`]) whose payload is a
//! text-keyed map in deterministic CBOR ([`crate::dcbor`]) with a `domain`
//! entry naming the object. Times and sequence numbers are CBOR integers. The
//! envelope bytes are what travels and what a resolver keeps as evidence. Test
//! vectors live in `repos/jig-spec/jep/vectors/0004/`.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::cose::{self, CoseError};
use crate::dcbor::{self, Value};
use crate::did::Did;

pub const ATTESTATION_DOMAIN: &str = "jig-alias-attestation-v1";
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
    #[error("not a {0}")]
    BadPayload(&'static str),
    #[error(transparent)]
    Envelope(CoseError),
    #[error("{0} is not an authority for suffix `{1}`")]
    NotAuthoritative(String, String),
    #[error("the delegation for `{0}` lacks a signature from {1}")]
    MissingDelegationSignature(String, String),
    #[error("a contract root_id must be a canonical CIDv1 (base32, `b` prefix), not `{0}`")]
    BadContractRootId(String),
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
    #[error(
        "this build has no authority for `@{DEFAULT_SUFFIX}` names: the project nameserver's \
         DID is still a placeholder"
    )]
    NoDefaultAuthority,
    #[error("the rotation chain does not lead from {0} to {1}")]
    BrokenChain(String, String),
    #[error("a rotation was accepted by {0}, not by {1}")]
    OtherNameserver(String, String),
}

impl From<CoseError> for NamingError {
    fn from(e: CoseError) -> Self {
        match e {
            CoseError::BadDid(did) => NamingError::BadDid(did),
            CoseError::BadSignature(did) => NamingError::BadSignature(did),
            other => NamingError::Envelope(other),
        }
    }
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

    fn parse(s: &str) -> Option<Self> {
        [Root::Config, Root::Dns, Root::Contract]
            .into_iter()
            .find(|r| r.as_str() == s)
    }
}

/// The action a proof of control is bound to (JEP-0004 rule 10). Rotation
/// proves control through a link instead (rule 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Register,
    Renew,
}

impl Action {
    pub fn domain(self) -> &'static str {
        match self {
            Action::Register => "jig-alias-register-v1",
            Action::Renew => "jig-alias-renew-v1",
        }
    }
}

/// The payload a DID signs to prove control for `action` on `alias` at
/// `ns_did`: `{domain, ns_did, alias, challenge}`.
pub fn proof_payload(action: Action, ns_did: &str, alias: &str, challenge: &str) -> Vec<u8> {
    encode(Value::text_map([
        ("domain", Value::Text(action.domain().into())),
        ("ns_did", Value::Text(ns_did.into())),
        ("alias", Value::Text(alias.into())),
        ("challenge", Value::Text(challenge.into())),
    ]))
}

/// BLAKE3 of [`proof_payload`]: what an admission proof-of-work binds to.
pub fn proof_hash(action: Action, ns_did: &str, alias: &str, challenge: &str) -> [u8; 32] {
    *blake3::hash(&proof_payload(action, ns_did, alias, challenge)).as_bytes()
}

/// Sign a proof of control as `key`: a COSE_Sign1 over [`proof_payload`].
pub fn sign_proof(
    key: &SigningKey,
    action: Action,
    ns_did: &str,
    alias: &str,
    challenge: &str,
) -> Vec<u8> {
    cose::sign1(key, &proof_payload(action, ns_did, alias, challenge))
}

/// Check a proof of control by `did`.
pub fn verify_proof(
    did: &str,
    envelope: &[u8],
    action: Action,
    ns_did: &str,
    alias: &str,
    challenge: &str,
) -> Result<(), NamingError> {
    verify_envelope(
        envelope,
        &proof_payload(action, ns_did, alias, challenge),
        did,
    )
}

/// A nameserver's claim that `alias` belongs to `did` (JEP-0004 rule 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub did: String,
    pub alias: String,
    pub ns_did: String,
    pub valid_from: i64,
    pub valid_until: i64,
    /// `ns_did`'s COSE_Sign1 over [`Attestation::payload`].
    pub envelope: Vec<u8>,
}

impl Attestation {
    const WHAT: &'static str = "alias attestation";

    pub fn payload(&self) -> Vec<u8> {
        encode(Value::text_map([
            ("domain", Value::Text(ATTESTATION_DOMAIN.into())),
            ("did", Value::Text(self.did.clone())),
            ("alias", Value::Text(self.alias.clone())),
            ("ns_did", Value::Text(self.ns_did.clone())),
            ("valid_from", Value::int(self.valid_from)),
            ("valid_until", Value::int(self.valid_until)),
        ]))
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
            envelope: Vec::new(),
        };
        att.envelope = cose::sign1(ns_key, &att.payload());
        att
    }

    /// Parse an envelope and check that its `ns_did` signed it.
    pub fn from_envelope(envelope: &[u8]) -> Result<Self, NamingError> {
        let p = open(envelope, ATTESTATION_DOMAIN, Self::WHAT)?;
        let att = Self {
            did: text(&p, "did", Self::WHAT)?,
            alias: text(&p, "alias", Self::WHAT)?,
            ns_did: text(&p, "ns_did", Self::WHAT)?,
            valid_from: int(&p, "valid_from", Self::WHAT)?,
            valid_until: int(&p, "valid_until", Self::WHAT)?,
            envelope: envelope.to_vec(),
        };
        att.verify()?;
        Ok(att)
    }

    /// The envelope carries exactly these fields and is `ns_did`'s. Says
    /// nothing about authority or time.
    pub fn verify(&self) -> Result<(), NamingError> {
        verify_envelope(&self.envelope, &self.payload(), &self.ns_did)
    }
}

/// A link that moves `alias` from one DID to another (JEP-0004 rule 9).
///
/// The link itself is the identity design's dual-signed, audience-scoped
/// statement (COSE over deterministic CBOR, lane I), with the audience set to
/// one nameserver and one alias. This crate does not own that encoding; it
/// only needs to read a link's fields and check its signatures.
pub trait AliasLink {
    fn old_did(&self) -> &str;
    fn new_did(&self) -> &str;
    /// The nameserver the link's audience names.
    fn audience_ns_did(&self) -> &str;
    /// The alias the link's audience names.
    fn audience_alias(&self) -> &str;
    /// Both keys signed the link.
    fn verify_signatures(&self) -> Result<(), NamingError>;
}

/// Which DIDs speak for a suffix, under which root (JEP-0004 rule 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuffixDelegation {
    pub suffix: String,
    /// Signed in bytewise ascending order, whatever the order here.
    pub authorities: Vec<String>,
    pub root: Root,
    /// For `config`, a local identifier never sent to anyone; for `dns`, the
    /// domain; for `contract`, the contract's CID.
    pub root_id: String,
    pub valid_until: i64,
    /// One COSE_Sign1 per authority, each over the same
    /// [`SuffixDelegation::payload`].
    pub envelopes: Vec<Vec<u8>>,
}

impl SuffixDelegation {
    const WHAT: &'static str = "suffix delegation";

    pub fn payload(&self) -> Vec<u8> {
        let mut authorities = self.authorities.clone();
        authorities.sort_unstable();
        encode(Value::text_map([
            ("domain", Value::Text(DELEGATION_DOMAIN.into())),
            ("suffix", Value::Text(self.suffix.clone())),
            (
                "authorities",
                Value::Array(authorities.into_iter().map(Value::Text).collect()),
            ),
            ("root", Value::Text(self.root.as_str().into())),
            ("root_id", Value::Text(self.root_id.clone())),
            ("valid_until", Value::int(self.valid_until)),
        ]))
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
            envelopes: Vec::new(),
        };
        let payload = deleg.payload();
        deleg.envelopes = authority_keys
            .iter()
            .map(|k| cose::sign1(k, &payload))
            .collect();
        deleg
    }

    /// Parse the envelopes and check that every authority signed.
    pub fn from_envelopes(envelopes: &[Vec<u8>]) -> Result<Self, NamingError> {
        let first = envelopes
            .first()
            .ok_or(NamingError::BadPayload(Self::WHAT))?;
        let p = open(first, DELEGATION_DOMAIN, Self::WHAT)?;
        let authorities = array(&p, "authorities", Self::WHAT)?
            .iter()
            .map(|a| match a {
                Value::Text(t) => Ok(t.clone()),
                _ => Err(NamingError::BadPayload(Self::WHAT)),
            })
            .collect::<Result<_, _>>()?;
        let deleg = Self {
            suffix: text(&p, "suffix", Self::WHAT)?,
            authorities,
            root: Root::parse(&text(&p, "root", Self::WHAT)?)
                .ok_or(NamingError::BadPayload(Self::WHAT))?,
            root_id: text(&p, "root_id", Self::WHAT)?,
            valid_until: int(&p, "valid_until", Self::WHAT)?,
            envelopes: envelopes.to_vec(),
        };
        deleg.verify()?;
        Ok(deleg)
    }

    /// Every listed authority signed these fields. An envelope signed by
    /// anyone else, or over other bytes, does not count. A `contract` root's
    /// `root_id` must be the contract CID's one canonical text form (JEP-0004
    /// rule 3), so one root has one encoding.
    pub fn verify(&self) -> Result<(), NamingError> {
        if self.root == Root::Contract && !is_canonical_cidv1(&self.root_id) {
            return Err(NamingError::BadContractRootId(self.root_id.clone()));
        }
        let payload = self.payload();
        for authority in &self.authorities {
            if !self
                .envelopes
                .iter()
                .any(|e| verify_envelope(e, &payload, authority).is_ok())
            {
                return Err(NamingError::MissingDelegationSignature(
                    self.suffix.clone(),
                    authority.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// Where a DID wants to be found, signed by that DID (JEP-0004 rule 21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityRecord {
    pub did: String,
    /// `(server DID, URL)` pairs, in the order signed.
    pub servers: Vec<(String, String)>,
    pub seq: u64,
    /// `did`'s COSE_Sign1 over [`ReachabilityRecord::payload`].
    pub envelope: Vec<u8>,
}

impl ReachabilityRecord {
    const WHAT: &'static str = "reachability record";

    pub fn payload(&self) -> Vec<u8> {
        let servers = self
            .servers
            .iter()
            .map(|(server_did, url)| {
                Value::text_map([
                    ("server_did", Value::Text(server_did.clone())),
                    ("url", Value::Text(url.clone())),
                ])
            })
            .collect();
        encode(Value::text_map([
            ("domain", Value::Text(REACHABILITY_DOMAIN.into())),
            ("did", Value::Text(self.did.clone())),
            ("servers", Value::Array(servers)),
            ("seq", Value::Unsigned(self.seq)),
        ]))
    }

    pub fn sign(key: &SigningKey, servers: Vec<(String, String)>, seq: u64) -> Self {
        let mut rec = Self {
            did: did_of(key),
            servers,
            seq,
            envelope: Vec::new(),
        };
        rec.envelope = cose::sign1(key, &rec.payload());
        rec
    }

    /// Parse an envelope and check that its `did` signed it.
    pub fn from_envelope(envelope: &[u8]) -> Result<Self, NamingError> {
        let p = open(envelope, REACHABILITY_DOMAIN, Self::WHAT)?;
        let servers = array(&p, "servers", Self::WHAT)?
            .iter()
            .map(|s| {
                Ok((
                    text(s, "server_did", Self::WHAT)?,
                    text(s, "url", Self::WHAT)?,
                ))
            })
            .collect::<Result<_, NamingError>>()?;
        let rec = Self {
            did: text(&p, "did", Self::WHAT)?,
            servers,
            seq: uint(&p, "seq", Self::WHAT)?,
            envelope: envelope.to_vec(),
        };
        rec.verify()?;
        Ok(rec)
    }

    pub fn verify(&self) -> Result<(), NamingError> {
        verify_envelope(&self.envelope, &self.payload(), &self.did)
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
    verify_attestation(att, &deleg.authorities, name, now)
}

/// The attestation half of [`verify_binding`], for a resolver whose
/// authorities come from its own configuration (a `config` root) rather than
/// from a signed delegation: the signer is one of `authorities`, and the
/// attestation's signature, time window and alias.
pub fn verify_attestation(
    att: &Attestation,
    authorities: &[String],
    name: &Name,
    now: i64,
) -> Result<(), NamingError> {
    if !authorities.contains(&att.ns_did) {
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

/// A chain of links leads from `pinned` to `new` for `alias`, each signed by
/// both keys and scoped to `ns_did` and `alias` (JEP-0004 rule 18). An empty
/// chain only connects a DID to itself.
pub fn verify_rotation_chain<L: AliasLink>(
    alias: &str,
    ns_did: &str,
    pinned: &str,
    chain: &[L],
    new: &str,
) -> Result<(), NamingError> {
    let mut current = pinned;
    for link in chain {
        if link.audience_alias() != alias || link.old_did() != current {
            return Err(NamingError::BrokenChain(pinned.into(), new.into()));
        }
        if link.audience_ns_did() != ns_did {
            return Err(NamingError::OtherNameserver(
                link.audience_ns_did().to_string(),
                ns_did.into(),
            ));
        }
        link.verify_signatures()?;
        current = link.new_did();
    }
    if current == new {
        Ok(())
    } else {
        Err(NamingError::BrokenChain(pinned.into(), new.into()))
    }
}

/// `s` is the canonical text form (base32 lowercase, `b` prefix, exactly as
/// it round-trips) of a CID that JEP-0004 rule 0 admits
/// ([`crate::canonical_cid::check`]).
fn is_canonical_cidv1(s: &str) -> bool {
    cid::Cid::try_from(s)
        .is_ok_and(|c| crate::canonical_cid::check(&c).is_ok() && c.to_string() == s)
}

fn did_of(key: &SigningKey) -> String {
    Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string()
}

fn encode(map: Value) -> Vec<u8> {
    dcbor::encode(&map).expect("a map of text, integers and arrays encodes")
}

fn text(map: &Value, key: &str, what: &'static str) -> Result<String, NamingError> {
    match map.get(key) {
        Some(Value::Text(t)) => Ok(t.clone()),
        _ => Err(NamingError::BadPayload(what)),
    }
}

fn int(map: &Value, key: &str, what: &'static str) -> Result<i64, NamingError> {
    map.get(key)
        .and_then(Value::as_i64)
        .ok_or(NamingError::BadPayload(what))
}

fn uint(map: &Value, key: &str, what: &'static str) -> Result<u64, NamingError> {
    map.get(key)
        .and_then(Value::as_u64)
        .ok_or(NamingError::BadPayload(what))
}

fn array<'a>(map: &'a Value, key: &str, what: &'static str) -> Result<&'a [Value], NamingError> {
    match map.get(key) {
        Some(Value::Array(items)) => Ok(items),
        _ => Err(NamingError::BadPayload(what)),
    }
}

/// Open `envelope`, decode its payload and check its `domain`. The caller
/// still verifies the signature, through its own `verify`.
fn open(envelope: &[u8], domain: &str, what: &'static str) -> Result<Value, NamingError> {
    let opened = cose::open_sign1(envelope)?;
    let payload = dcbor::decode(&opened.payload).map_err(|_| NamingError::BadPayload(what))?;
    if text(&payload, "domain", what)? != domain {
        return Err(NamingError::BadPayload(what));
    }
    Ok(payload)
}

/// `envelope` carries exactly `payload` and is signed by `did`. Comparing
/// the re-encoded fields with the signed bytes also refuses unknown keys.
fn verify_envelope(envelope: &[u8], payload: &[u8], did: &str) -> Result<(), NamingError> {
    let opened = cose::open_sign1(envelope)?;
    if opened.payload != payload {
        return Err(NamingError::BadSignature(did.to_string()));
    }
    Ok(opened.verify(did)?)
}

// ----------------------------------------------------------------------------
// The default suffix
// ----------------------------------------------------------------------------

/// The suffix default names live under: `alice@jig`. Single-label, so JEP-0004
/// rule 4 makes it `config`-rooted only: its authority comes from this crate,
/// never from discovery.
pub const DEFAULT_SUFFIX: &str = "jig";

/// The authority for [`DEFAULT_SUFFIX`], read through [`default_jig_authority`].
///
/// TODO(DJ): set this to the project nameserver's DID from the key ceremony.
/// The same change must flip `the_default_authority_is_refused_while_it_is_the_placeholder`
/// to assert `Ok`: that test is what keeps the swap from going unnoticed.
pub const DEFAULT_JIG_AUTHORITY: &str = PLACEHOLDER_JIG_AUTHORITY;

/// Where [`DEFAULT_SUFFIX`] names are asked by default; config overrides it.
/// Integrity rests on [`DEFAULT_JIG_AUTHORITY`], not on this URL: whatever
/// answers here must still be signed by the authority.
pub const DEFAULT_JIG_NAMESERVER: &str = "https://ns.jig-protocol.org";

/// The DID of the ed25519 key with the public seed `[0x4a; 32]`. Anyone can
/// sign as it, so only a build with the `test-default-authority` feature
/// (dev-dependencies only, guarded in CI) accepts it as an authority.
pub const PLACEHOLDER_JIG_AUTHORITY: &str =
    "did:jig:zgu6iu77ozi4lfrctnyf5ewdp3mmna4hfbycz6hkd7c767ol2ptqq";

/// [`DEFAULT_JIG_AUTHORITY`], or [`NamingError::NoDefaultAuthority`] while it
/// is the placeholder in any build without `test-default-authority`, debug
/// builds included. Callers then add no `@jig` delegation, and `@jig` names
/// fail closed at lookup.
pub fn default_jig_authority() -> Result<&'static str, NamingError> {
    unless_placeholder(
        DEFAULT_JIG_AUTHORITY,
        cfg!(feature = "test-default-authority"),
    )
}

fn unless_placeholder(authority: &'static str, allowed: bool) -> Result<&'static str, NamingError> {
    if authority == PLACEHOLDER_JIG_AUTHORITY && !allowed {
        return Err(NamingError::NoDefaultAuthority);
    }
    Ok(authority)
}

#[cfg(test)]
mod default_authority_tests {
    use super::*;

    #[test]
    fn the_placeholder_is_the_did_of_the_public_test_seed() {
        // A typo here would be a silent "no delegation", not a failure.
        assert_eq!(
            did_of(&SigningKey::from_bytes(&[0x4a; 32])),
            PLACEHOLDER_JIG_AUTHORITY
        );
    }

    #[test]
    fn the_placeholder_is_accepted_only_where_allowed() {
        assert_eq!(
            unless_placeholder(PLACEHOLDER_JIG_AUTHORITY, false),
            Err(NamingError::NoDefaultAuthority)
        );
        assert_eq!(
            unless_placeholder(PLACEHOLDER_JIG_AUTHORITY, true),
            Ok(PLACEHOLDER_JIG_AUTHORITY)
        );
        assert_eq!(
            unless_placeholder("did:jig:zReal", false),
            Ok("did:jig:zReal")
        );
    }

    /// What every build without `test-default-authority` gets. It checks
    /// that case directly rather than under `cfg(not(feature = ...))`: CI
    /// runs jig-core's tests together with crates that enable the feature
    /// from dev-dependencies, which would unify it in and skip a cfg-gated
    /// test silently. Flip it to `Ok` with the real DID.
    #[test]
    fn the_default_authority_is_refused_while_it_is_the_placeholder() {
        assert_eq!(
            unless_placeholder(DEFAULT_JIG_AUTHORITY, false),
            Err(NamingError::NoDefaultAuthority)
        );
    }
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
    fn a_configured_authority_list_stands_in_for_a_delegation() {
        let alice = did_of(&key(9));
        let authorities = vec![did_of(&ns())];
        assert_eq!(
            verify_attestation(&att(&ns(), &alice), &authorities, &name(), NOW),
            Ok(())
        );
        let stranger = key(42);
        assert_eq!(
            verify_attestation(&att(&stranger, &alice), &authorities, &name(), NOW),
            Err(NamingError::NotAuthoritative(
                did_of(&stranger),
                "example.org".into()
            ))
        );
        assert_eq!(
            verify_attestation(&att(&ns(), &alice), &[], &name(), NOW),
            Err(NamingError::NotAuthoritative(
                did_of(&ns()),
                "example.org".into()
            ))
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
        d.envelopes.truncate(1);
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
    fn a_contract_root_needs_a_canonical_cidv1() {
        use multihash_codetable::MultihashDigest as _;
        let k = key(7);
        let cid = cid::Cid::new_v1(
            0x55,
            multihash_codetable::Code::Blake3_256.digest(b"contract"),
        );
        let dag_cbor = cid::Cid::new_v1(
            0x71,
            multihash_codetable::Code::Blake3_256.digest(b"contract"),
        )
        .to_string();
        let sha2 = cid::Cid::new_v1(
            0x55,
            cid::multihash::Multihash::<64>::wrap(0x12, &[7; 32]).unwrap(),
        )
        .to_string();
        let canonical = cid.to_string();
        assert!(canonical.starts_with('b'));
        let ok = SuffixDelegation::sign(&[&k], "example.org", Root::Contract, &canonical, NOW);
        assert_eq!(ok.verify(), Ok(()));
        let upper = canonical.to_uppercase();
        let v0 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
        for bad in [upper.as_str(), v0, "not-a-cid", &dag_cbor, &sha2] {
            let d = SuffixDelegation::sign(&[&k], "example.org", Root::Contract, bad, NOW);
            assert_eq!(d.verify(), Err(NamingError::BadContractRootId(bad.into())));
        }
        // Other roots keep free text.
        assert_eq!(deleg(&[&k]).verify(), Ok(()));
    }

    /// A stand-in for lane I's link: the chain logic only reads fields and
    /// asks whether both signatures hold.
    struct TestLink {
        old: String,
        new: String,
        ns: String,
        alias: String,
        signed: bool,
    }

    impl AliasLink for TestLink {
        fn old_did(&self) -> &str {
            &self.old
        }
        fn new_did(&self) -> &str {
            &self.new
        }
        fn audience_ns_did(&self) -> &str {
            &self.ns
        }
        fn audience_alias(&self) -> &str {
            &self.alias
        }
        fn verify_signatures(&self) -> Result<(), NamingError> {
            if self.signed {
                Ok(())
            } else {
                Err(NamingError::BadSignature(self.old.clone()))
            }
        }
    }

    fn link(old: &str, new: &str, ns: &str) -> TestLink {
        TestLink {
            old: old.into(),
            new: new.into(),
            ns: ns.into(),
            alias: "alice@example.org".into(),
            signed: true,
        }
    }

    #[test]
    fn rotation_chains_move_a_pin_only_along_signed_scoped_links() {
        let ns = "did:jig:zns";
        let chain = [
            link("did:jig:z1", "did:jig:z2", ns),
            link("did:jig:z2", "did:jig:z3", ns),
        ];
        let alias = "alice@example.org";
        assert_eq!(
            verify_rotation_chain(alias, ns, "did:jig:z1", &chain, "did:jig:z3"),
            Ok(())
        );
        // A gap, an empty chain, or the wrong end breaks it.
        assert!(verify_rotation_chain(alias, ns, "did:jig:z1", &chain[1..], "did:jig:z3").is_err());
        assert!(
            verify_rotation_chain::<TestLink>(alias, ns, "did:jig:z1", &[], "did:jig:z3").is_err()
        );
        assert!(verify_rotation_chain(alias, ns, "did:jig:z1", &chain, "did:jig:z2").is_err());
        // A link scoped to another alias or nameserver does not count here.
        let mut other_alias = link("did:jig:z1", "did:jig:z3", ns);
        other_alias.alias = "bob@example.org".into();
        assert!(
            verify_rotation_chain(alias, ns, "did:jig:z1", &[other_alias], "did:jig:z3").is_err()
        );
        assert_eq!(
            verify_rotation_chain(alias, "did:jig:zother", "did:jig:z1", &chain, "did:jig:z3"),
            Err(NamingError::OtherNameserver(
                ns.into(),
                "did:jig:zother".into()
            ))
        );
        // An unsigned link is refused.
        let mut unsigned = link("did:jig:z1", "did:jig:z3", ns);
        unsigned.signed = false;
        assert!(verify_rotation_chain(alias, ns, "did:jig:z1", &[unsigned], "did:jig:z3").is_err());
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
        let bare = cose::sign1(&k, b"c0ffee");
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

    #[test]
    fn envelopes_round_trip_and_refuse_other_objects() {
        let (ns, alice) = (key(7), key(9));
        let att = att(&ns, &did_of(&alice));
        assert_eq!(Attestation::from_envelope(&att.envelope), Ok(att.clone()));
        let d = deleg(&[&ns, &key(8)]);
        assert_eq!(
            SuffixDelegation::from_envelopes(&d.envelopes),
            Ok(d.clone())
        );
        let rec =
            ReachabilityRecord::sign(&alice, vec![("did:jig:zs".into(), "https://s".into())], 1);
        assert_eq!(
            ReachabilityRecord::from_envelope(&rec.envelope),
            Ok(rec.clone())
        );
        // A validly signed object of another kind is not an attestation.
        assert_eq!(
            Attestation::from_envelope(&rec.envelope),
            Err(NamingError::BadPayload(Attestation::WHAT))
        );
        // A signed payload with an extra key is refused, though the signature holds.
        let mut extra = dcbor::decode(&att.payload()).unwrap();
        if let Value::Map(entries) = &mut extra {
            entries.push((Value::Text("note".into()), Value::Text("x".into())));
        }
        let envelope = cose::sign1(&ns, &dcbor::encode(&extra).unwrap());
        assert_eq!(
            Attestation::from_envelope(&envelope),
            Err(NamingError::BadSignature(did_of(&ns)))
        );
    }

    fn vectors() -> serde_json::Value {
        const CHALLENGE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let (ns, alice) = (key(7), key(9));
        let att = Attestation::sign(
            &ns,
            &did_of(&alice),
            "alice@example.org",
            1_800_000_000,
            1_807_776_000,
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
        let ns_did = did_of(&ns);
        let proof = sign_proof(
            &alice,
            Action::Register,
            &ns_did,
            "alice@example.org",
            CHALLENGE,
        );
        serde_json::json!({
            "comment": "payload_hex is the deterministic CBOR payload; cose_sign1_hex is the envelope",
            "keys": {
                "comment": "Ed25519 seeds: every byte set to the given value",
                "nameserver": {"seed_byte": 7, "did": ns_did},
                "alice": {"seed_byte": 9, "did": did_of(&alice)},
                "server": {"seed_byte": 13, "did": did_of(&key(13))},
            },
            "attestation": {
                "payload_hex": hex::encode(att.payload()),
                "cose_sign1_hex": hex::encode(&att.envelope),
            },
            "delegation": {
                "payload_hex": hex::encode(deleg.payload()),
                "cose_sign1_hex": deleg.envelopes.iter().map(hex::encode).collect::<Vec<_>>(),
            },
            "reachability": {
                "payload_hex": hex::encode(reach.payload()),
                "cose_sign1_hex": hex::encode(&reach.envelope),
            },
            "register_proof": {
                "payload_hex": hex::encode(proof_payload(Action::Register, &ns_did, "alice@example.org", CHALLENGE)),
                "proof_hash_hex": hex::encode(proof_hash(Action::Register, &ns_did, "alice@example.org", CHALLENGE)),
                "cose_sign1_hex": hex::encode(&proof),
            },
        })
    }
}
