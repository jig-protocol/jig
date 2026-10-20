//! Program manifests and program CIDs (JEP-0011 §2).
//!
//! A *program* is a component plus a signed manifest that pins what the code requests and which
//! children it calls. Its CID, the *program CID*, is what an install, a parent's `children`, an
//! operator policy's `programs` list and a `render` message name.
//!
//! # Payload
//!
//! A deterministic-CBOR map ([`crate::dcbor`]) with exactly these keys, signed by `author` as a
//! `COSE_Sign1` ([`crate::cose`]):
//!
//! | Key | Type |
//! | --- | --- |
//! | `domain` | text, `jig-program-manifest-v1` |
//! | `author` | text, the author's `did:jig`; the signer |
//! | `name`, `version` | text; display and lineage only, never resolved to a CID |
//! | `world` | text, a `jig:block` world with its version |
//! | `component` | bytes, BLAKE3-256 of the component |
//! | `requests` | map, a [`Grant`] (JEP-0007 §1) |
//! | `children` | array of program CIDs, strictly ascending |
//! | `offers` | map from a child's program CID to a [`Grant`]; every key is in `children` |
//! | `limits` | map `{memory_max_pages, fuel_max}` |
//! | `examples` | array; its entries are carried as given |
//! | `supersedes` | optional program CID |
//! | `source` | optional map `{repo, commit, lock_hash, rustc}` of text; an unverified claim |
//!
//! The payload carries no timestamp: when a program was published is its `ingest` record's job,
//! so the same payload and component always give the same CID. CIDs are the canonical form of
//! JEP-0004 rule 0 ([`crate::canonical_cid`]).
//!
//! # Program CID
//!
//! The block-bundle derivation ([`crate::bundle::compute_cid`]) over the labelled parts
//! `manifest`, the payload bytes (the signature is not part of it), and `code`, the component
//! bytes.
//!
//! # What this module checks, and what it leaves to the caller
//!
//! [`SignedProgram::open`] checks the encoding, the author's signature, the `component` hash
//! against the component bytes, and computes the CID. Validating the component against
//! `jig-det-1` for `world`, and resolving and checking every child, need the runtime and the
//! store, so the caller does them (JEP-0011 §2.4).

use cid::Cid;

use crate::canonical_cid::{self, CidError};
use crate::dcbor::{self, DcborError, Value};
use crate::grant::{Grant, GrantError};
use crate::operator_policy::{ComponentHash, ProgramFacts};

/// The payload's `domain`.
pub const DOMAIN: &str = "jig-program-manifest-v1";

/// The program's limits, as the author tested it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub memory_max_pages: u32,
    pub fuel_max: u64,
}

/// Where the author says the program came from. Nothing checks it: builds are not reproducible
/// (JEP-0011 §6.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Source {
    pub repo: String,
    pub commit: String,
    pub lock_hash: String,
    pub rustc: String,
}

/// A program manifest (JEP-0011 §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramManifest {
    pub author: String,
    pub name: String,
    pub version: String,
    pub world: String,
    pub component: ComponentHash,
    pub requests: Grant,
    /// Child program CIDs. Kept sorted; repeats are dropped when encoding.
    pub children: Vec<Cid>,
    /// Per-child offers, keyed by a CID in `children`.
    pub offers: Vec<(Cid, Grant)>,
    pub limits: Limits,
    pub examples: Vec<Value>,
    pub supersedes: Option<Cid>,
    pub source: Option<Source>,
}

/// Why a manifest or a signed program was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProgramError {
    #[error(transparent)]
    Cbor(#[from] DcborError),
    #[error(transparent)]
    Cid(#[from] CidError),
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error("not a program manifest: {0}")]
    Shape(&'static str),
    #[error("the payload is not in its one canonical encoding")]
    NotCanonical,
    #[error("`component` does not match the component's bytes")]
    ComponentMismatch,
    #[cfg(feature = "ed25519")]
    #[error(transparent)]
    Cose(#[from] crate::cose::CoseError),
}

impl ProgramManifest {
    /// A built-in renderer: requesting nothing and pinning nothing, so a default operator policy
    /// allows it by component hash (JEP-0011 §5.1).
    ///
    /// JEP-0011 has each server author its built-ins (`author_did` is the server's DID, signed at
    /// start), so the program CID differs between servers and comparison keys on the component.
    /// If built-ins move to one project-signed manifest shipped in the binary, `author_did` is the
    /// project's DID and the call is the same.
    pub fn builtin_renderer(
        author_did: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        world: impl Into<String>,
        component_bytes: &[u8],
        limits: Limits,
    ) -> Self {
        Self {
            author: author_did.into(),
            name: name.into(),
            version: version.into(),
            world: world.into(),
            component: *blake3::hash(component_bytes).as_bytes(),
            requests: Grant::empty(),
            children: Vec::new(),
            offers: Vec::new(),
            limits,
            examples: Vec::new(),
            supersedes: None,
            source: None,
        }
    }

    /// The deterministic-CBOR payload.
    pub fn to_payload(&self) -> Result<Vec<u8>, ProgramError> {
        let mut children: Vec<Vec<u8>> = self.children.iter().map(Cid::to_bytes).collect();
        children.sort_unstable_by_key(|b| bytes_key(b));
        children.dedup();

        let mut entries = vec![
            ("domain", Value::text(DOMAIN)),
            ("author", Value::text(self.author.clone())),
            ("name", Value::text(self.name.clone())),
            ("version", Value::text(self.version.clone())),
            ("world", Value::text(self.world.clone())),
            ("component", Value::Bytes(self.component.to_vec())),
            ("requests", self.requests.to_value()),
            (
                "children",
                Value::Array(children.into_iter().map(Value::Bytes).collect()),
            ),
            (
                "offers",
                Value::Map(
                    self.offers
                        .iter()
                        .map(|(cid, grant)| (Value::Bytes(cid.to_bytes()), grant.to_value()))
                        .collect(),
                ),
            ),
            (
                "limits",
                Value::text_map([
                    (
                        "memory_max_pages",
                        Value::Unsigned(u64::from(self.limits.memory_max_pages)),
                    ),
                    ("fuel_max", Value::Unsigned(self.limits.fuel_max)),
                ]),
            ),
            ("examples", Value::Array(self.examples.clone())),
        ];
        if let Some(s) = &self.supersedes {
            entries.push(("supersedes", Value::Bytes(s.to_bytes())));
        }
        if let Some(s) = &self.source {
            entries.push((
                "source",
                Value::text_map([
                    ("repo", Value::text(s.repo.clone())),
                    ("commit", Value::text(s.commit.clone())),
                    ("lock_hash", Value::text(s.lock_hash.clone())),
                    ("rustc", Value::text(s.rustc.clone())),
                ]),
            ));
        }
        Ok(dcbor::encode(&Value::text_map(entries))?)
    }

    /// Parse a payload. It must be the manifest's one canonical encoding: re-encoding the parsed
    /// manifest must give the same bytes, so that one program has exactly one CID.
    pub fn from_payload(bytes: &[u8]) -> Result<Self, ProgramError> {
        let value = dcbor::decode(bytes)?;
        let mut map = Fields::new(&value)?;
        if map.text("domain")? != DOMAIN {
            return Err(ProgramError::Shape("wrong domain"));
        }
        let author = map.text("author")?.to_string();
        let name = map.text("name")?.to_string();
        let version = map.text("version")?.to_string();
        let world = map.text("world")?.to_string();
        let component = map
            .take("component")?
            .as_bytes()
            .and_then(|b| ComponentHash::try_from(b).ok())
            .ok_or(ProgramError::Shape("component is not 32 bytes"))?;
        let requests = Grant::from_value(map.take("requests")?)?;
        let children = map
            .take("children")?
            .as_array()
            .ok_or(ProgramError::Shape("children is not an array"))?
            .iter()
            .map(cid_value)
            .collect::<Result<Vec<_>, _>>()?;
        let Value::Map(offer_entries) = map.take("offers")? else {
            return Err(ProgramError::Shape("offers is not a map"));
        };
        let mut offers = Vec::with_capacity(offer_entries.len());
        for (k, v) in offer_entries {
            let child = cid_value(k)?;
            if !children.contains(&child) {
                return Err(ProgramError::Shape("an offer names a CID not in children"));
            }
            offers.push((child, Grant::from_value(v)?));
        }
        let limits_value = map.take("limits")?;
        let mut lim = Fields::new(limits_value)?;
        let limits = Limits {
            memory_max_pages: u32::try_from(lim.unsigned("memory_max_pages")?)
                .map_err(|_| ProgramError::Shape("memory_max_pages is too large"))?,
            fuel_max: lim.unsigned("fuel_max")?,
        };
        lim.finish()?;
        let examples = map
            .take("examples")?
            .as_array()
            .ok_or(ProgramError::Shape("examples is not an array"))?
            .to_vec();
        let supersedes = map.optional("supersedes").map(cid_value).transpose()?;
        let source = match map.optional("source") {
            None => None,
            Some(v) => {
                let mut s = Fields::new(v)?;
                let source = Source {
                    repo: s.text("repo")?.to_string(),
                    commit: s.text("commit")?.to_string(),
                    lock_hash: s.text("lock_hash")?.to_string(),
                    rustc: s.text("rustc")?.to_string(),
                };
                s.finish()?;
                Some(source)
            }
        };
        map.finish()?;

        let manifest = Self {
            author,
            name,
            version,
            world,
            component,
            requests,
            children,
            offers,
            limits,
            examples,
            supersedes,
            source,
        };
        // Catches what a field-by-field parse cannot: unsorted or repeated children, and
        // capability names written with another compatible version.
        if manifest.to_payload()? != bytes {
            return Err(ProgramError::NotCanonical);
        }
        Ok(manifest)
    }

    /// What operator policy needs to decide whether a server runs this program.
    pub fn facts<'a>(&'a self, program: &'a Cid) -> ProgramFacts<'a> {
        ProgramFacts {
            program,
            author: &self.author,
            world: &self.world,
            component: &self.component,
            requests_none: self.requests.is_empty(),
            children_none: self.children.is_empty(),
        }
    }
}

/// The program CID over a payload and a component (JEP-0011 §2.3).
pub fn program_cid(payload: &[u8], component_bytes: &[u8]) -> Cid {
    crate::bundle::compute_cid(payload, component_bytes, &[])
        .expect("the bundle derivation does not fail")
}

/// A signed program: the author's envelope, the manifest it carries, and its program CID.
#[cfg(feature = "ed25519")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProgram {
    /// The `COSE_Sign1` envelope.
    pub envelope: Vec<u8>,
    pub manifest: ProgramManifest,
    pub cid: Cid,
}

#[cfg(feature = "ed25519")]
impl SignedProgram {
    /// Sign `manifest` as its author. `author_key` must be the key of `manifest.author`, or
    /// [`Self::open`] refuses the envelope.
    pub fn sign(
        manifest: ProgramManifest,
        author_key: &ed25519_dalek::SigningKey,
        component_bytes: &[u8],
    ) -> Result<Self, ProgramError> {
        if *blake3::hash(component_bytes).as_bytes() != manifest.component {
            return Err(ProgramError::ComponentMismatch);
        }
        let payload = manifest.to_payload()?;
        Ok(Self {
            envelope: crate::cose::sign1(author_key, &payload),
            cid: program_cid(&payload, component_bytes),
            manifest,
        })
    }

    /// Open and verify an envelope against the component it names: canonical encoding, the
    /// author's signature, the component hash. Then compute the program CID.
    pub fn open(envelope: &[u8], component_bytes: &[u8]) -> Result<Self, ProgramError> {
        let sign1 = crate::cose::open_sign1(envelope)?;
        let manifest = ProgramManifest::from_payload(&sign1.payload)?;
        sign1.verify(&manifest.author)?;
        if *blake3::hash(component_bytes).as_bytes() != manifest.component {
            return Err(ProgramError::ComponentMismatch);
        }
        Ok(Self {
            envelope: envelope.to_vec(),
            cid: program_cid(&sign1.payload, component_bytes),
            manifest,
        })
    }
}

fn bytes_key(b: &[u8]) -> Vec<u8> {
    dcbor::encode(&Value::Bytes(b.to_vec())).expect("bytes always encode")
}

fn cid_value(v: &Value) -> Result<Cid, ProgramError> {
    let bytes = v
        .as_bytes()
        .ok_or(ProgramError::Shape("a CID is not a byte string"))?;
    Ok(canonical_cid::from_bytes(bytes)?)
}

/// The fields of a text-keyed map, taken one by one; [`Fields::finish`] refuses any left over.
struct Fields<'a> {
    entries: Vec<(&'a str, &'a Value)>,
}

impl<'a> Fields<'a> {
    fn new(value: &'a Value) -> Result<Self, ProgramError> {
        let Value::Map(entries) = value else {
            return Err(ProgramError::Shape("not a map"));
        };
        let entries = entries
            .iter()
            .map(|(k, v)| {
                k.as_text()
                    .map(|k| (k, v))
                    .ok_or(ProgramError::Shape("a key is not text"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { entries })
    }

    fn optional(&mut self, key: &str) -> Option<&'a Value> {
        let i = self.entries.iter().position(|(k, _)| *k == key)?;
        Some(self.entries.swap_remove(i).1)
    }

    fn take(&mut self, key: &str) -> Result<&'a Value, ProgramError> {
        self.optional(key)
            .ok_or(ProgramError::Shape("a required field is missing"))
    }

    fn text(&mut self, key: &str) -> Result<&'a str, ProgramError> {
        self.take(key)?
            .as_text()
            .ok_or(ProgramError::Shape("a field is not text"))
    }

    fn unsigned(&mut self, key: &str) -> Result<u64, ProgramError> {
        self.take(key)?
            .as_u64()
            .ok_or(ProgramError::Shape("a field is not an unsigned integer"))
    }

    fn finish(self) -> Result<(), ProgramError> {
        if self.entries.is_empty() {
            Ok(())
        } else {
            Err(ProgramError::Shape("unknown field"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPONENT: &[u8] = b"not really a component, but the manifest only hashes it";
    const RENDERER: &str = "jig:block/renderer@0.1.0";
    const LIMITS: Limits = Limits {
        memory_max_pages: 256,
        fuel_max: 50_000_000,
    };

    fn manifest() -> ProgramManifest {
        ProgramManifest::builtin_renderer(
            "did:jig:zauthor",
            "hello",
            "0.1.0",
            RENDERER,
            COMPONENT,
            LIMITS,
        )
    }

    #[test]
    fn a_payload_round_trips() {
        let mut m = manifest();
        m.children = vec![canonical_cid::of(b"b"), canonical_cid::of(b"a")];
        m.offers = vec![(canonical_cid::of(b"a"), Grant::empty())];
        m.supersedes = Some(canonical_cid::of(b"old"));
        m.source = Some(Source {
            repo: "https://example.org/hello".into(),
            commit: "abc".into(),
            lock_hash: "def".into(),
            rustc: "1.99.0".into(),
        });
        let payload = m.to_payload().unwrap();
        let back = ProgramManifest::from_payload(&payload).unwrap();
        assert_eq!(back.to_payload().unwrap(), payload);
        assert_eq!(back.supersedes, m.supersedes);
        assert_eq!(back.source, m.source);
        // Children come back in canonical order.
        let mut sorted = m.children.clone();
        sorted.sort_by_key(|c| bytes_key(&c.to_bytes()));
        assert_eq!(back.children, sorted);
    }

    #[test]
    fn the_same_manifest_and_component_give_the_same_cid() {
        let p = manifest().to_payload().unwrap();
        assert_eq!(program_cid(&p, COMPONENT), program_cid(&p, COMPONENT));
        assert_ne!(program_cid(&p, COMPONENT), program_cid(&p, b"other code"));
        let mut other = manifest();
        other.version = "0.1.1".into();
        assert_ne!(
            program_cid(&p, COMPONENT),
            program_cid(&other.to_payload().unwrap(), COMPONENT)
        );
        canonical_cid::check(&program_cid(&p, COMPONENT)).expect("a canonical CID");
    }

    /// The payload a test builds by hand, so the refusals below can each break one rule.
    fn raw(entries: Vec<(&'static str, Value)>) -> Vec<u8> {
        dcbor::encode(&Value::text_map(entries)).unwrap()
    }

    fn fields() -> Vec<(&'static str, Value)> {
        let Value::Map(entries) = dcbor::decode(&manifest().to_payload().unwrap()).unwrap() else {
            unreachable!()
        };
        entries
            .into_iter()
            .map(|(k, v)| {
                let k: &'static str = Box::leak(k.as_text().unwrap().to_string().into_boxed_str());
                (k, v)
            })
            .collect()
    }

    #[test]
    fn refusals() {
        let with = |key: &str, value: Option<Value>| {
            let mut f = fields();
            f.retain(|(k, _)| *k != key);
            if let Some(v) = value {
                let k: &'static str = Box::leak(key.to_string().into_boxed_str());
                f.push((k, v));
            }
            ProgramManifest::from_payload(&raw(f))
        };
        assert!(with("domain", Some(Value::text("jig-operator-policy-v1"))).is_err());
        assert!(with("author", None).is_err(), "a missing field");
        assert!(
            with("timestamp", Some(Value::Unsigned(1))).is_err(),
            "an unknown field"
        );
        assert!(with("component", Some(Value::Bytes(vec![1; 31]))).is_err());
        // A CIDv0 is a bare SHA-256 multihash: 0x12, 0x20, then the digest.
        let v0: Vec<u8> = [0x12, 0x20].into_iter().chain([7; 32]).collect();
        assert!(
            with("children", Some(Value::Array(vec![Value::Bytes(v0)]))).is_err(),
            "a CIDv0"
        );
        let (a, b) = (canonical_cid::of(b"a"), canonical_cid::of(b"b"));
        let mut kids = [a, b];
        kids.sort_by_key(|c| bytes_key(&c.to_bytes()));
        assert_eq!(
            with(
                "children",
                Some(Value::Array(vec![
                    Value::Bytes(kids[1].to_bytes()),
                    Value::Bytes(kids[0].to_bytes()),
                ]))
            ),
            Err(ProgramError::NotCanonical),
            "children out of order"
        );
        assert!(
            with(
                "offers",
                Some(Value::Map(vec![(
                    Value::Bytes(a.to_bytes()),
                    Grant::empty().to_value()
                )]))
            )
            .is_err(),
            "an offer to a CID that is not a child"
        );
    }

    #[test]
    fn facts_feed_the_operator_policy() {
        use crate::operator_policy::OperatorPolicy;
        let m = manifest();
        let cid = program_cid(&m.to_payload().unwrap(), COMPONENT);
        let facts = m.facts(&cid);
        assert!(facts.requests_none && facts.children_none);
        let policy = OperatorPolicy::default_for("did:jig:zserver", &[m.component]);
        assert!(
            policy.allows(&facts),
            "a shipped renderer is allowed by component"
        );
    }

    #[cfg(feature = "ed25519")]
    mod signed {
        use super::*;
        use crate::did::Did;
        use ed25519_dalek::SigningKey;

        fn author() -> (SigningKey, String) {
            let key = SigningKey::from_bytes(&[42; 32]);
            let did = Did::from_ed25519_pubkey(&key.verifying_key().to_bytes()).to_did_jig_string();
            (key, did)
        }

        fn signed() -> (SignedProgram, SigningKey) {
            let (key, did) = author();
            let m = ProgramManifest::builtin_renderer(
                did, "hello", "0.1.0", RENDERER, COMPONENT, LIMITS,
            );
            (SignedProgram::sign(m, &key, COMPONENT).unwrap(), key)
        }

        #[test]
        fn a_signed_program_opens_with_the_same_cid() {
            let (s, _) = signed();
            let opened = SignedProgram::open(&s.envelope, COMPONENT).unwrap();
            assert_eq!(opened, s);
            let payload = s.manifest.to_payload().unwrap();
            assert_eq!(
                s.cid,
                program_cid(&payload, COMPONENT),
                "the signature is not in the CID"
            );
        }

        #[test]
        fn signing_twice_gives_the_same_envelope_and_cid() {
            let (a, key) = signed();
            let b = SignedProgram::sign(a.manifest.clone(), &key, COMPONENT).unwrap();
            assert_eq!(a.envelope, b.envelope);
            assert_eq!(a.cid, b.cid);
        }

        #[test]
        fn another_component_is_refused() {
            let (s, _) = signed();
            assert_eq!(
                SignedProgram::open(&s.envelope, b"tampered"),
                Err(ProgramError::ComponentMismatch)
            );
        }

        #[test]
        fn a_manifest_signed_by_someone_else_is_refused() {
            let (_, did) = author();
            let m = ProgramManifest::builtin_renderer(
                did, "hello", "0.1.0", RENDERER, COMPONENT, LIMITS,
            );
            let impostor = SigningKey::from_bytes(&[1; 32]);
            let s = SignedProgram::sign(m, &impostor, COMPONENT).unwrap();
            assert!(matches!(
                SignedProgram::open(&s.envelope, COMPONENT),
                Err(ProgramError::Cose(_))
            ));
        }

        /// Golden vector: pins the payload encoding and the CID derivation. If this changes,
        /// every published program's CID changes with it.
        #[test]
        fn golden_vector() {
            let (s, _) = signed();
            let payload = s.manifest.to_payload().unwrap();
            assert_eq!(
                blake3::hash(&payload).to_hex().as_str(),
                GOLDEN_PAYLOAD_HASH,
                "payload encoding changed"
            );
            assert_eq!(
                s.cid.to_string(),
                GOLDEN_CID,
                "program CID derivation changed"
            );
        }

        const GOLDEN_PAYLOAD_HASH: &str =
            "c02428e28471f05345a80a909b2bf3019872462693835fb2d999312120c3e902";
        const GOLDEN_CID: &str = "bafkr4igrjio5sifc2bwsmhrwkuor7ah65odffzlzegnc44ewwrlxb5dhhu";
    }
}
