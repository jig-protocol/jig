//! The server manifest (JEP-0002 rule 12; design D11 item 13).
//!
//! Each server keeps one reserved channel, its manifest log
//! ([`LOG_SLUG`]). Only the server's DID writes it, and only
//! `server-manifest` blocks (after the channel-create). Each one carries this
//! document, in deterministic CBOR: what the server advertises in every
//! welcome, plus its signed peer policy (JEP-0005 rule 16). A welcome cites
//! the current one by CID and `seq`, so a server that tells one client
//! something else than the rest has signed both into one gap-checked chain.
//!
//! The document has one encoding per state, so equal facts are equal bytes:
//!
//! - every key is always present (an empty list is an empty array);
//! - every list is sorted by each element's deterministic CBOR encoding,
//!   with no repeats.
//!
//! [`ServerManifest::decode`] refuses anything else, and any key it does not
//! know: a new field is a new [`FORMAT`].
//!
//! jig-server fills the peer-policy keys from its `[federation]` config
//! (`v0_0_2_manifest_log`).

use jig_core::dcbor::{self, Value};

use crate::handshake::Capabilities;

/// The document's format, its `domain` key.
pub const FORMAT: &str = "jig-server-manifest-v1";

/// The manifest log's slug. The `#jig/` prefix is reserved: no one but the
/// server creates a channel under it.
pub const LOG_SLUG: &str = "#jig/manifest";

/// The prefix of the slugs only the server creates.
pub const RESERVED_PREFIX: &str = "#jig/";

/// The block metadata key that carries the document, base64.
pub const METADATA_KEY: &str = "server_manifest";

/// What a server advertises, as its manifest log records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerManifest {
    /// Envelope versions it speaks.
    pub versions: Vec<u64>,
    pub suites: Vec<String>,
    pub capabilities: Capabilities,
    pub peer_policy: PeerPolicy,
}

/// The server's published peer policy (JEP-0005 rule 16).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerPolicy {
    /// One entry per block kind it relays.
    pub relayed_kinds: Vec<String>,
    /// For every listed peer without its own entry.
    pub default_peer_quota: Quota,
    /// Each `peer` must be in [`Self::peers`], once.
    pub peer_quotas: Vec<PeerQuota>,
    /// The peers it chooses to publish (did:jig).
    pub peers: Vec<String>,
    /// Never a `config`-rooted suffix.
    pub attested_suffixes: Vec<AttestedSuffix>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Quota {
    pub blocks_per_min: u64,
    pub bytes_per_min: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerQuota {
    pub peer: String,
    pub quota: Quota,
}

/// A suffix the server attests, by its root (JEP-0004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestedSuffix {
    /// `domain` is the lowercased suffix.
    Dns { suffix: String, domain: String },
    /// `contract` is the contract's CID as an untagged binary CID.
    Contract { suffix: String, contract: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("not deterministic CBOR: {0}")]
    Cbor(#[from] dcbor::DcborError),
    #[error("not a {FORMAT} document")]
    Format,
    #[error("`{0}` is missing or has the wrong type")]
    Field(&'static str),
    #[error("`{0}` is not in canonical order, or repeats an entry")]
    Order(&'static str),
    #[error("unknown key `{0}`")]
    UnknownKey(String),
    #[error("{0}")]
    Invalid(String),
}

const KEYS: &[&str] = &[
    "domain",
    "versions",
    "suites",
    "capabilities",
    "relayed_kinds",
    "default_peer_quota",
    "peer_quotas",
    "peers",
    "attested_suffixes",
];

impl ServerManifest {
    /// The document's deterministic CBOR. Lists are put in canonical order
    /// here; a repeated entry is refused, not dropped.
    pub fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        self.check()?;
        let caps = &self.capabilities;
        let policy = &self.peer_policy;
        let doc = Value::text_map([
            ("domain", Value::text(FORMAT)),
            (
                "versions",
                canonical(
                    self.versions.iter().map(|v| Value::Unsigned(*v)),
                    "versions",
                )?,
            ),
            ("suites", texts(&self.suites, "suites")?),
            (
                "capabilities",
                Value::text_map([
                    ("block_kinds", texts(&caps.block_kinds, "block_kinds")?),
                    ("execution", Value::Bool(caps.execution)),
                    ("federation", Value::Bool(caps.federation)),
                    (
                        "max_future_skew_ms",
                        Value::Unsigned(caps.max_future_skew_ms),
                    ),
                ]),
            ),
            (
                "relayed_kinds",
                texts(&policy.relayed_kinds, "relayed_kinds")?,
            ),
            ("default_peer_quota", quota(policy.default_peer_quota, None)),
            (
                "peer_quotas",
                canonical(
                    policy
                        .peer_quotas
                        .iter()
                        .map(|q| quota(q.quota, Some(&q.peer))),
                    "peer_quotas",
                )?,
            ),
            ("peers", texts(&policy.peers, "peers")?),
            (
                "attested_suffixes",
                canonical(
                    policy.attested_suffixes.iter().map(|s| match s {
                        AttestedSuffix::Dns { suffix, domain } => Value::text_map([
                            ("suffix", Value::text(suffix)),
                            ("root", Value::text("dns")),
                            ("domain", Value::text(domain)),
                        ]),
                        AttestedSuffix::Contract { suffix, contract } => Value::text_map([
                            ("suffix", Value::text(suffix)),
                            ("root", Value::text("contract")),
                            ("contract", Value::Bytes(contract.clone())),
                        ]),
                    }),
                    "attested_suffixes",
                )?,
            ),
        ]);
        Ok(dcbor::encode(&doc)?)
    }

    /// Read a document, refusing any encoding but [`Self::encode`]'s.
    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let doc = dcbor::decode(bytes)?;
        let Value::Map(entries) = &doc else {
            return Err(ManifestError::Format);
        };
        for (key, _) in entries {
            let key = key.as_text().ok_or(ManifestError::Format)?;
            if !KEYS.contains(&key) {
                return Err(ManifestError::UnknownKey(key.to_string()));
            }
        }
        if doc.get("domain").and_then(Value::as_text) != Some(FORMAT) {
            return Err(ManifestError::Format);
        }
        let caps = field(&doc, "capabilities")?;
        let quota_of = |v: &Value, name| -> Result<Quota, ManifestError> {
            Ok(Quota {
                blocks_per_min: uint(v, "blocks_per_min")
                    .map_err(|_| ManifestError::Field(name))?,
                bytes_per_min: uint(v, "bytes_per_min").map_err(|_| ManifestError::Field(name))?,
            })
        };
        let manifest = Self {
            versions: array(&doc, "versions")?
                .iter()
                .map(|v| v.as_u64().ok_or(ManifestError::Field("versions")))
                .collect::<Result<_, _>>()?,
            suites: text_list(&doc, "suites")?,
            capabilities: Capabilities {
                block_kinds: text_list(caps, "block_kinds")?,
                execution: boolean(caps, "execution")?,
                federation: boolean(caps, "federation")?,
                max_future_skew_ms: uint(caps, "max_future_skew_ms")?,
                // Not in the document: a key old decoders do not know would
                // make them refuse it. A welcome carries it (`Capabilities::tiers`).
                tiers: false,
            },
            peer_policy: PeerPolicy {
                relayed_kinds: text_list(&doc, "relayed_kinds")?,
                default_peer_quota: quota_of(
                    field(&doc, "default_peer_quota")?,
                    "default_peer_quota",
                )?,
                peer_quotas: array(&doc, "peer_quotas")?
                    .iter()
                    .map(|q| {
                        Ok(PeerQuota {
                            peer: text(q, "peer")
                                .map_err(|_| ManifestError::Field("peer_quotas"))?,
                            quota: quota_of(q, "peer_quotas")?,
                        })
                    })
                    .collect::<Result<_, ManifestError>>()?,
                peers: text_list(&doc, "peers")?,
                attested_suffixes: array(&doc, "attested_suffixes")?
                    .iter()
                    .map(|s| {
                        let bad = || ManifestError::Field("attested_suffixes");
                        let suffix = text(s, "suffix").map_err(|_| bad())?;
                        match s.get("root").and_then(Value::as_text) {
                            Some("dns") => Ok(AttestedSuffix::Dns {
                                suffix,
                                domain: text(s, "domain").map_err(|_| bad())?,
                            }),
                            Some("contract") => Ok(AttestedSuffix::Contract {
                                suffix,
                                contract: s
                                    .get("contract")
                                    .and_then(Value::as_bytes)
                                    .ok_or_else(bad)?
                                    .to_vec(),
                            }),
                            _ => Err(bad()),
                        }
                    })
                    .collect::<Result<_, ManifestError>>()?,
            },
        };
        // One encoding per state: anything else (order, repeats, a quota for
        // an unpublished peer, an extra key in a nested map) differs here.
        if manifest.encode()? != bytes {
            return Err(ManifestError::Order("document"));
        }
        Ok(manifest)
    }

    /// The rules the encoding alone does not carry.
    fn check(&self) -> Result<(), ManifestError> {
        let policy = &self.peer_policy;
        for q in &policy.peer_quotas {
            if !policy.peers.contains(&q.peer) {
                return Err(ManifestError::Invalid(format!(
                    "a quota for {}, which is not a published peer",
                    q.peer
                )));
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        if !policy.peer_quotas.iter().all(|q| seen.insert(&q.peer)) {
            return Err(ManifestError::Order("peer_quotas"));
        }
        let mut seen = std::collections::BTreeSet::new();
        let unique = policy.attested_suffixes.iter().all(|s| {
            seen.insert(match s {
                AttestedSuffix::Dns { suffix, .. } => (suffix, "dns"),
                AttestedSuffix::Contract { suffix, .. } => (suffix, "contract"),
            })
        });
        if !unique {
            return Err(ManifestError::Order("attested_suffixes"));
        }
        Ok(())
    }
}

/// `items` as an array in canonical order: by each one's encoding, with no
/// repeats.
fn canonical(
    items: impl Iterator<Item = Value>,
    name: &'static str,
) -> Result<Value, ManifestError> {
    let mut encoded = items
        .map(|v| dcbor::encode(&v).map(|bytes| (bytes, v)))
        .collect::<Result<Vec<_>, _>>()?;
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(ManifestError::Order(name));
    }
    Ok(Value::Array(encoded.into_iter().map(|(_, v)| v).collect()))
}

fn texts(items: &[String], name: &'static str) -> Result<Value, ManifestError> {
    canonical(items.iter().map(Value::text), name)
}

fn quota(q: Quota, peer: Option<&str>) -> Value {
    let mut entries = vec![
        ("blocks_per_min", Value::Unsigned(q.blocks_per_min)),
        ("bytes_per_min", Value::Unsigned(q.bytes_per_min)),
    ];
    if let Some(peer) = peer {
        entries.push(("peer", Value::text(peer)));
    }
    Value::text_map(entries)
}

fn field<'a>(v: &'a Value, key: &'static str) -> Result<&'a Value, ManifestError> {
    v.get(key).ok_or(ManifestError::Field(key))
}

fn array<'a>(v: &'a Value, key: &'static str) -> Result<&'a [Value], ManifestError> {
    field(v, key)?.as_array().ok_or(ManifestError::Field(key))
}

fn text_list(v: &Value, key: &'static str) -> Result<Vec<String>, ManifestError> {
    array(v, key)?
        .iter()
        .map(|t| {
            t.as_text()
                .map(str::to_string)
                .ok_or(ManifestError::Field(key))
        })
        .collect()
}

fn text(v: &Value, key: &'static str) -> Result<String, ManifestError> {
    field(v, key)?
        .as_text()
        .map(str::to_string)
        .ok_or(ManifestError::Field(key))
}

fn uint(v: &Value, key: &'static str) -> Result<u64, ManifestError> {
    match field(v, key)? {
        Value::Unsigned(n) => Ok(*n),
        _ => Err(ManifestError::Field(key)),
    }
}

fn boolean(v: &Value, key: &'static str) -> Result<bool, ManifestError> {
    match field(v, key)? {
        Value::Bool(b) => Ok(*b),
        _ => Err(ManifestError::Field(key)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ServerManifest {
        ServerManifest {
            versions: vec![1],
            suites: vec!["none".into(), "mls".into()],
            capabilities: Capabilities {
                block_kinds: vec!["text-render".into(), "channel-create".into()],
                execution: false,
                federation: true,
                max_future_skew_ms: 300_000,
                tiers: false,
            },
            peer_policy: PeerPolicy::default(),
        }
    }

    #[test]
    fn a_manifest_has_one_encoding_and_round_trips() {
        let m = sample();
        let bytes = m.encode().unwrap();
        let back = ServerManifest::decode(&bytes).unwrap();
        // Lists come back in canonical order: shorter encodings first.
        assert_eq!(back.suites, ["mls", "none"]);
        assert_eq!(
            back.capabilities.block_kinds,
            ["text-render", "channel-create"]
        );
        let mut shuffled = m.clone();
        shuffled.suites.reverse();
        shuffled.capabilities.block_kinds.reverse();
        assert_eq!(
            shuffled.encode().unwrap(),
            bytes,
            "order in memory does not matter"
        );
        assert_eq!(back.encode().unwrap(), bytes);
        // Every reserved key is present, empty.
        let doc = dcbor::decode(&bytes).unwrap();
        for key in KEYS {
            assert!(doc.get(key).is_some(), "{key}");
        }
    }

    #[test]
    fn anything_but_the_one_encoding_is_refused() {
        let mut m = sample();
        m.suites.push("none".into());
        assert_eq!(m.encode(), Err(ManifestError::Order("suites")));

        let bytes = sample().encode().unwrap();
        let mut doc = dcbor::decode(&bytes).unwrap();
        let Value::Map(entries) = &mut doc else {
            panic!("map")
        };
        // Lists out of order.
        for (k, v) in entries.iter_mut() {
            if k.as_text() == Some("suites") {
                *v = Value::Array(vec![Value::text("none"), Value::text("mls")]);
            }
        }
        let unordered = dcbor::encode(&doc).unwrap();
        assert!(ServerManifest::decode(&unordered).is_err());
        // An unknown key, a missing one, another format.
        let mut extra = dcbor::decode(&bytes).unwrap();
        if let Value::Map(e) = &mut extra {
            e.push((Value::text("surprise"), Value::Null));
        }
        assert_eq!(
            ServerManifest::decode(&dcbor::encode(&extra).unwrap()),
            Err(ManifestError::UnknownKey("surprise".into()))
        );
        let mut missing = dcbor::decode(&bytes).unwrap();
        if let Value::Map(e) = &mut missing {
            e.retain(|(k, _)| k.as_text() != Some("peers"));
        }
        assert_eq!(
            ServerManifest::decode(&dcbor::encode(&missing).unwrap()),
            Err(ManifestError::Field("peers"))
        );
        let mut other = dcbor::decode(&bytes).unwrap();
        if let Value::Map(e) = &mut other {
            for (k, v) in e.iter_mut() {
                if k.as_text() == Some("domain") {
                    *v = Value::text("jig-server-manifest-v0");
                }
            }
        }
        assert_eq!(
            ServerManifest::decode(&dcbor::encode(&other).unwrap()),
            Err(ManifestError::Format)
        );
    }

    #[test]
    fn peer_policy_rules_hold() {
        let mut m = sample();
        m.peer_policy.peers = vec!["did:jig:zA".into()];
        m.peer_policy.peer_quotas = vec![PeerQuota {
            peer: "did:jig:zB".into(),
            quota: Quota::default(),
        }];
        assert!(
            matches!(m.encode(), Err(ManifestError::Invalid(_))),
            "unpublished peer"
        );
        m.peer_policy.peer_quotas = vec![
            PeerQuota {
                peer: "did:jig:zA".into(),
                quota: Quota::default(),
            },
            PeerQuota {
                peer: "did:jig:zA".into(),
                quota: Quota {
                    blocks_per_min: 1,
                    bytes_per_min: 1,
                },
            },
        ];
        assert_eq!(m.encode(), Err(ManifestError::Order("peer_quotas")));
        m.peer_policy.peer_quotas.truncate(1);
        m.peer_policy.attested_suffixes = vec![
            AttestedSuffix::Dns {
                suffix: "example.org".into(),
                domain: "example.org".into(),
            },
            AttestedSuffix::Contract {
                suffix: "example.org".into(),
                contract: vec![1, 2],
            },
        ];
        let back = ServerManifest::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(
            back.peer_policy.attested_suffixes.len(),
            2,
            "same suffix, two roots"
        );
        m.peer_policy.attested_suffixes.push(AttestedSuffix::Dns {
            suffix: "example.org".into(),
            domain: "other".into(),
        });
        assert_eq!(m.encode(), Err(ManifestError::Order("attested_suffixes")));
    }
}
