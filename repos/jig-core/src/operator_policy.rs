//! The `operator-policy` object: which programs a server will execute (JEP-0011 §5.1).
//!
//! JEP-0006 Q7 and JEP-0007 §2 leave the choice of third-party code to the server operator. This
//! is that choice, published: a deterministic-CBOR payload, signed by the server as a
//! `COSE_Sign1` ([`crate::cose`]) and named by the CID of its envelope. A server executes a
//! `render` only if its current policy allows the program, and the `exec` receipt names the
//! policy's CID.
//!
//! # Payload
//!
//! ```text
//! {domain: "jig-operator-policy-v1", server, seq,
//!  allow: {programs: [cid…], authors: [did…], components: [hash…]}}
//! ```
//!
//! - `server` is the signer's `did:jig`, as text.
//! - `programs` are program CIDs, each a binary CIDv1 as an untagged CBOR byte string (JEP-0004
//!   rule 0) with the raw codec and a BLAKE3-256 multihash ([`crate::canonical_cid`]). A tag-42
//!   or text CID, a CIDv0, another codec or another hash is refused.
//! - `authors` are `did:jig` strings.
//! - `components` are BLAKE3-256 hashes of component bytes, as 32-byte strings.
//!
//! Each list is strictly ascending and has no repeats (bytewise, by the entry's own encoding),
//! so one policy has exactly one payload.
//!
//! # The match rule
//!
//! [`OperatorPolicy::allows`] admits a program when any of these holds:
//!
//! - its program CID is in `programs`;
//! - its author is in `authors`;
//! - its component hash is in `components`, **and** it is a `renderer`-world program that requests
//!   no capabilities and pins no children. Such a manifest adds nothing to the code it wraps, so
//!   whoever authored it, the server runs only code it already chose. Every other program, every
//!   `bot`-world install included, needs `programs` or `authors`.
//!
//! A program's pinned children are separate programs, and each one is checked on its own:
//! allowing an author does not extend to children by other authors.
//! [`OperatorPolicy::allows_closure`] applies the rule to a program and all its children.
//!
//! The default policy a server publishes lists the renderer components it ships (today,
//! text-block's) in `components`, and nothing else ([`OperatorPolicy::default_for`]).

use cid::Cid;

use crate::dcbor::{self, DcborError, Value};

/// The payload's `domain`.
pub const DOMAIN: &str = "jig-operator-policy-v1";

/// The prefix every `renderer`-world version shares (JEP-0006).
const RENDERER_WORLD_PREFIX: &str = "jig:block/renderer@";

/// A BLAKE3-256 hash of component bytes.
pub type ComponentHash = [u8; 32];

/// The programs a policy allows. Each list is kept sorted and free of repeats.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allow {
    pub programs: Vec<Cid>,
    pub authors: Vec<String>,
    pub components: Vec<ComponentHash>,
}

/// One version of a server's operator policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorPolicy {
    /// The server's `did:jig`. It signs the policy.
    pub server: String,
    /// Version number. A later policy has a higher `seq`.
    pub seq: u64,
    pub allow: Allow,
}

/// What [`OperatorPolicy::allows`] needs to know about a program, taken from its verified
/// manifest (JEP-0011 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramFacts<'a> {
    pub program: &'a Cid,
    pub author: &'a str,
    /// The manifest's `world`, with its version, e.g. `jig:block/renderer@0.1.0`.
    pub world: &'a str,
    pub component: &'a ComponentHash,
    /// Whether the manifest's `requests` map is empty.
    pub requests_none: bool,
    /// Whether the manifest's `children` array is empty.
    pub children_none: bool,
}

/// Why a payload is not a well-formed operator policy.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error(transparent)]
    Cbor(#[from] DcborError),
    #[error("not an operator-policy payload: {0}")]
    Shape(&'static str),
    #[error("`{0}` is not strictly ascending, or repeats an entry")]
    Unordered(&'static str),
    #[error("a program entry is not a canonical CID: {0}")]
    BadCid(#[from] crate::canonical_cid::CidError),
    #[cfg(feature = "ed25519")]
    #[error(transparent)]
    Cose(#[from] crate::cose::CoseError),
}

impl OperatorPolicy {
    /// The policy a server publishes by default: the renderer components it ships, and nothing
    /// else.
    pub fn default_for(server: impl Into<String>, shipped_renderers: &[ComponentHash]) -> Self {
        let mut components = shipped_renderers.to_vec();
        components.sort_unstable();
        components.dedup();
        Self {
            server: server.into(),
            seq: 0,
            allow: Allow {
                components,
                ..Allow::default()
            },
        }
    }

    /// Whether this policy lets the server execute `program` (JEP-0011 §5.1). Its children are
    /// not looked at; see [`Self::allows_closure`].
    pub fn allows(&self, program: &ProgramFacts<'_>) -> bool {
        if self.allow.programs.contains(program.program)
            || self.allow.authors.iter().any(|a| a == program.author)
        {
            return true;
        }
        program.world.starts_with(RENDERER_WORLD_PREFIX)
            && program.requests_none
            && program.children_none
            && self.allow.components.contains(program.component)
    }

    /// Whether this policy allows `root` and every program in `children`, each on its own.
    /// `children` is the whole closure of pinned children, which the caller resolves from
    /// verified manifests.
    pub fn allows_closure(&self, root: &ProgramFacts<'_>, children: &[ProgramFacts<'_>]) -> bool {
        self.allows(root) && children.iter().all(|c| self.allows(c))
    }

    /// The deterministic-CBOR payload.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut programs: Vec<Vec<u8>> = self.allow.programs.iter().map(Cid::to_bytes).collect();
        programs.sort_unstable_by_key(|b| bytes_key(b));
        programs.dedup();
        let mut authors = self.allow.authors.clone();
        authors.sort_unstable_by_key(|a| text_key(a));
        authors.dedup();
        let mut components = self.allow.components.clone();
        components.sort_unstable();
        components.dedup();

        let allow = Value::text_map([
            (
                "programs",
                Value::Array(programs.into_iter().map(Value::Bytes).collect()),
            ),
            (
                "authors",
                Value::Array(authors.into_iter().map(Value::Text).collect()),
            ),
            (
                "components",
                Value::Array(
                    components
                        .into_iter()
                        .map(|c| Value::Bytes(c.to_vec()))
                        .collect(),
                ),
            ),
        ]);
        let payload = Value::text_map([
            ("domain", Value::text(DOMAIN)),
            ("server", Value::text(self.server.clone())),
            ("seq", Value::Unsigned(self.seq)),
            ("allow", allow),
        ]);
        dcbor::encode(&payload).expect("an operator policy always encodes")
    }

    /// Parse a payload, refusing anything that is not exactly one well-formed policy.
    pub fn from_payload(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value = dcbor::decode(bytes)?;
        let map = exact_map(&value, &["domain", "server", "seq", "allow"])?;
        if map.get("domain").copied().and_then(Value::as_text) != Some(DOMAIN) {
            return Err(PolicyError::Shape("wrong domain"));
        }
        let server = map
            .get("server")
            .copied()
            .and_then(Value::as_text)
            .ok_or(PolicyError::Shape("server is not text"))?
            .to_string();
        let seq = map
            .get("seq")
            .copied()
            .and_then(Value::as_u64)
            .ok_or(PolicyError::Shape("seq is not an unsigned integer"))?;
        let allow_value = map.get("allow").expect("checked by exact_map");
        let allow = exact_map(allow_value, &["programs", "authors", "components"])?;

        let programs = ascending_bytes(allow.get("programs").copied(), "programs")?
            .iter()
            .map(|b| crate::canonical_cid::from_bytes(b))
            .collect::<Result<Vec<_>, _>>()?;

        let authors = text_array(allow.get("authors").copied())?;
        if !strictly_ascending(authors.iter().map(|a| text_key(a))) {
            return Err(PolicyError::Unordered("authors"));
        }

        let components = ascending_bytes(allow.get("components").copied(), "components")?
            .into_iter()
            .map(|b| {
                ComponentHash::try_from(b.as_slice())
                    .map_err(|_| PolicyError::Shape("a component hash is not 32 bytes"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            server,
            seq,
            allow: Allow {
                programs,
                authors,
                components,
            },
        })
    }
}

/// A signed policy: the `COSE_Sign1` envelope, the policy it carries, and its CID.
#[cfg(feature = "ed25519")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOperatorPolicy {
    pub envelope: Vec<u8>,
    pub policy: OperatorPolicy,
    /// The `operator_policy_cid` a receipt or approval cites: CIDv1, raw codec, BLAKE3-256 over
    /// the envelope bytes.
    pub cid: Cid,
}

#[cfg(feature = "ed25519")]
impl SignedOperatorPolicy {
    /// Sign `policy` as its server. `key` must be the key of `policy.server`; [`Self::open`]
    /// refuses the envelope otherwise.
    pub fn sign(policy: OperatorPolicy, key: &ed25519_dalek::SigningKey) -> Self {
        let envelope = crate::cose::sign1(key, &policy.to_payload());
        let cid = envelope_cid(&envelope);
        Self {
            envelope,
            policy,
            cid,
        }
    }

    /// Parse and verify an envelope: deterministic, well formed, and signed by the `server` it
    /// names.
    pub fn open(envelope: &[u8]) -> Result<Self, PolicyError> {
        let sign1 = crate::cose::open_sign1(envelope)?;
        let policy = OperatorPolicy::from_payload(&sign1.payload)?;
        sign1.verify(&policy.server)?;
        Ok(Self {
            envelope: envelope.to_vec(),
            cid: envelope_cid(envelope),
            policy,
        })
    }
}

#[cfg(feature = "ed25519")]
fn envelope_cid(envelope: &[u8]) -> Cid {
    crate::canonical_cid::of(envelope)
}

/// The bytes a text entry sorts by: its own deterministic encoding.
fn text_key(s: &str) -> Vec<u8> {
    dcbor::encode(&Value::text(s)).expect("text always encodes")
}

/// The bytes a byte-string entry sorts by: its own deterministic encoding.
fn bytes_key(b: &[u8]) -> Vec<u8> {
    dcbor::encode(&Value::Bytes(b.to_vec())).expect("bytes always encode")
}

fn strictly_ascending<T: Ord>(items: impl IntoIterator<Item = T>) -> bool {
    let items: Vec<T> = items.into_iter().collect();
    items.windows(2).all(|w| w[0] < w[1])
}

/// The entries of a text-keyed map that has exactly `keys`.
///
/// Collecting into a map cannot hide a repeated key: [`dcbor::decode`] already refuses one
/// (`DcborError::DuplicateKey`).
fn exact_map<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<std::collections::HashMap<&'a str, &'a Value>, PolicyError> {
    let Value::Map(entries) = value else {
        return Err(PolicyError::Shape("not a map"));
    };
    let mut out = std::collections::HashMap::new();
    for (k, v) in entries {
        let k = k.as_text().ok_or(PolicyError::Shape("a key is not text"))?;
        if !keys.contains(&k) {
            return Err(PolicyError::Shape("unknown key"));
        }
        out.insert(k, v);
    }
    if out.len() != keys.len() {
        return Err(PolicyError::Shape("missing key"));
    }
    Ok(out)
}

/// A byte-string array, checked strictly ascending (shorter first, then bytewise, as their
/// encodings sort).
fn ascending_bytes(value: Option<&Value>, name: &'static str) -> Result<Vec<Vec<u8>>, PolicyError> {
    let items = value
        .and_then(|v| v.as_array())
        .ok_or(PolicyError::Shape("an allow entry is not an array"))?;
    let bytes = items
        .iter()
        .map(|i| {
            i.as_bytes()
                .map(<[u8]>::to_vec)
                .ok_or(PolicyError::Shape("an entry is not a byte string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !strictly_ascending(bytes.iter().map(|b| bytes_key(b))) {
        return Err(PolicyError::Unordered(name));
    }
    Ok(bytes)
}

fn text_array(value: Option<&Value>) -> Result<Vec<String>, PolicyError> {
    value
        .and_then(|v| v.as_array())
        .ok_or(PolicyError::Shape("an allow entry is not an array"))?
        .iter()
        .map(|i| {
            i.as_text()
                .map(str::to_string)
                .ok_or(PolicyError::Shape("an author is not text"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_cid::{self, RAW_CODEC};

    const RENDERER: &str = "jig:block/renderer@0.1.0";
    const BOT: &str = "jig:block/bot@0.1.0";
    const TEXT_BLOCK: ComponentHash = [7; 32];

    fn cid(seed: u8) -> Cid {
        canonical_cid::of(&[seed])
    }

    /// A program by `author` wrapping `component`, with no requests and no children.
    fn program<'a>(
        cid: &'a Cid,
        author: &'a str,
        world: &'a str,
        component: &'a ComponentHash,
    ) -> ProgramFacts<'a> {
        ProgramFacts {
            program: cid,
            author,
            world,
            component,
            requests_none: true,
            children_none: true,
        }
    }

    fn default_policy() -> OperatorPolicy {
        OperatorPolicy::default_for("did:jig:zserverY", &[TEXT_BLOCK])
    }

    // JEP-0011 §5.1's federation case: server X publishes text-block as its own program, so the
    // program CID and author are X's. Server Y's default policy still runs it, by component.
    #[test]
    fn another_servers_text_block_runs_under_the_default_policy() {
        let x_program = cid(1);
        let facts = program(&x_program, "did:jig:zserverX", RENDERER, &TEXT_BLOCK);
        assert!(default_policy().allows(&facts));
    }

    #[test]
    fn a_bot_allowed_only_by_component_is_refused() {
        let p = cid(2);
        let facts = program(&p, "did:jig:zstranger", BOT, &TEXT_BLOCK);
        assert!(!default_policy().allows(&facts));
    }

    #[test]
    fn a_renderer_that_requests_a_capability_is_refused_by_component() {
        let p = cid(3);
        let facts = ProgramFacts {
            requests_none: false,
            ..program(&p, "did:jig:zstranger", RENDERER, &TEXT_BLOCK)
        };
        assert!(!default_policy().allows(&facts));
    }

    #[test]
    fn a_renderer_that_pins_a_child_is_refused_by_component() {
        let p = cid(4);
        let facts = ProgramFacts {
            children_none: false,
            ..program(&p, "did:jig:zstranger", RENDERER, &TEXT_BLOCK)
        };
        assert!(!default_policy().allows(&facts));
    }

    #[test]
    fn an_unlisted_component_is_refused() {
        let p = cid(5);
        let other = [9; 32];
        assert!(!default_policy().allows(&program(&p, "did:jig:zstranger", RENDERER, &other)));
    }

    #[test]
    fn programs_and_authors_admit_any_world() {
        let p = cid(6);
        let other = [9; 32];
        let mut policy = default_policy();
        policy.allow.programs.push(p);
        assert!(policy.allows(&ProgramFacts {
            requests_none: false,
            children_none: false,
            ..program(&p, "did:jig:zstranger", BOT, &other)
        }));

        let q = cid(7);
        let mut policy = default_policy();
        policy.allow.authors.push("did:jig:ztrusted".into());
        assert!(policy.allows(&program(&q, "did:jig:ztrusted", BOT, &other)));
    }

    // Allowing an author does not extend to that author's children by other authors.
    #[test]
    fn each_child_is_checked_on_its_own() {
        let (root_cid, child_cid) = (cid(8), cid(9));
        let other = [9; 32];
        let mut policy = default_policy();
        policy.allow.authors.push("did:jig:ztrusted".into());
        let root = ProgramFacts {
            children_none: false,
            ..program(&root_cid, "did:jig:ztrusted", RENDERER, &other)
        };
        let child = program(&child_cid, "did:jig:zstranger", RENDERER, &other);
        assert!(policy.allows(&root));
        assert!(!policy.allows_closure(&root, &[child]));

        let text_block_child = program(&child_cid, "did:jig:zstranger", RENDERER, &TEXT_BLOCK);
        assert!(policy.allows_closure(&root, &[text_block_child]));
    }

    #[test]
    fn the_payload_round_trips_and_is_order_independent() {
        let mut a = default_policy();
        a.seq = 3;
        a.allow.programs = vec![cid(2), cid(1)];
        a.allow.authors = vec![
            "did:jig:zb".into(),
            "did:jig:za".into(),
            "did:jig:zb".into(),
        ];
        a.allow.components = vec![[2; 32], TEXT_BLOCK, [2; 32]];
        let payload = a.to_payload();

        let mut b = a.clone();
        b.allow.programs.reverse();
        b.allow.authors.reverse();
        assert_eq!(
            b.to_payload(),
            payload,
            "list order and repeats do not change the payload"
        );

        let back = OperatorPolicy::from_payload(&payload).expect("parses");
        assert_eq!(back.to_payload(), payload);
        assert_eq!(
            back.allow.authors,
            vec!["did:jig:za".to_string(), "did:jig:zb".to_string()]
        );
        assert_eq!(back.allow.components.len(), 2);
    }

    #[test]
    fn a_payload_with_an_unsorted_list_is_refused() {
        let payload = dcbor::encode(&Value::text_map([
            ("domain", Value::text(DOMAIN)),
            ("server", Value::text("did:jig:zs")),
            ("seq", Value::Unsigned(0)),
            (
                "allow",
                Value::text_map([
                    ("programs", Value::Array(vec![])),
                    (
                        "authors",
                        Value::Array(vec![Value::text("did:jig:zb"), Value::text("did:jig:za")]),
                    ),
                    ("components", Value::Array(vec![])),
                ]),
            ),
        ]))
        .unwrap();
        assert!(matches!(
            OperatorPolicy::from_payload(&payload),
            Err(PolicyError::Unordered("authors"))
        ));
    }

    /// A payload whose `programs` holds exactly `entry`.
    fn payload_with_program(entry: Value) -> Vec<u8> {
        dcbor::encode(&Value::text_map([
            ("domain", Value::text(DOMAIN)),
            ("server", Value::text("did:jig:zs")),
            ("seq", Value::Unsigned(0)),
            (
                "allow",
                Value::text_map([
                    ("programs", Value::Array(vec![entry])),
                    ("authors", Value::Array(vec![])),
                    ("components", Value::Array(vec![])),
                ]),
            ),
        ]))
        .unwrap()
    }

    // JEP-0004 rule 0: a CID in a payload is a binary CIDv1 as an untagged byte string.
    #[test]
    fn a_program_cid_in_any_other_form_is_refused() {
        let v1 = cid(1);
        assert!(
            OperatorPolicy::from_payload(&payload_with_program(Value::Bytes(v1.to_bytes())))
                .is_ok()
        );

        let tag42 = Value::Tag(
            42,
            Box::new(Value::Bytes([&[0u8][..], &v1.to_bytes()].concat())),
        );
        let text = Value::text(v1.to_string());
        let sha2_256 = || cid::multihash::Multihash::<64>::wrap(0x12, &[0; 32]).unwrap();
        let v0 = Cid::new_v0(sha2_256()).unwrap();
        let dag_cbor = Cid::new_v1(0x71, v1.hash().to_owned());
        let sha2 = Cid::new_v1(RAW_CODEC, sha2_256());
        for entry in [
            tag42,
            text,
            Value::Bytes(v0.to_bytes()),
            Value::Bytes(dag_cbor.to_bytes()),
            Value::Bytes(sha2.to_bytes()),
        ] {
            assert!(
                OperatorPolicy::from_payload(&payload_with_program(entry.clone())).is_err(),
                "{entry:?}"
            );
        }
    }

    #[test]
    fn a_payload_with_an_extra_key_or_wrong_domain_is_refused() {
        let base = |domain: &str, extra: bool| {
            let mut entries = vec![
                ("domain", Value::text(domain)),
                ("server", Value::text("did:jig:zs")),
                ("seq", Value::Unsigned(0)),
                (
                    "allow",
                    Value::text_map([
                        ("programs", Value::Array(vec![])),
                        ("authors", Value::Array(vec![])),
                        ("components", Value::Array(vec![])),
                    ]),
                ),
            ];
            if extra {
                entries.push(("note", Value::text("x")));
            }
            dcbor::encode(&Value::text_map(entries)).unwrap()
        };
        assert!(OperatorPolicy::from_payload(&base(DOMAIN, false)).is_ok());
        assert!(OperatorPolicy::from_payload(&base(DOMAIN, true)).is_err());
        assert!(OperatorPolicy::from_payload(&base("jig-channel-policy-v1", false)).is_err());
    }

    #[cfg(feature = "ed25519")]
    mod signed {
        use super::*;
        use crate::did::Did;
        use ed25519_dalek::SigningKey;

        fn server_key() -> (SigningKey, String) {
            let key = SigningKey::from_bytes(&[42; 32]);
            let did = Did::from_ed25519_pubkey(&key.verifying_key().to_bytes()).to_did_jig_string();
            (key, did)
        }

        #[test]
        fn a_signed_policy_opens_with_the_same_cid() {
            let (key, did) = server_key();
            let signed =
                SignedOperatorPolicy::sign(OperatorPolicy::default_for(did, &[TEXT_BLOCK]), &key);
            let opened = SignedOperatorPolicy::open(&signed.envelope).expect("opens");
            assert_eq!(opened, signed);
            assert_eq!(opened.cid.codec(), RAW_CODEC);
        }

        #[test]
        fn a_policy_signed_by_another_key_is_refused() {
            let (_, did) = server_key();
            let impostor = SigningKey::from_bytes(&[1; 32]);
            let signed = SignedOperatorPolicy::sign(
                OperatorPolicy::default_for(did, &[TEXT_BLOCK]),
                &impostor,
            );
            assert!(matches!(
                SignedOperatorPolicy::open(&signed.envelope),
                Err(PolicyError::Cose(_))
            ));
        }
    }
}
