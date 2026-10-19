//! Capability names, typed scopes and their attenuation order (JEP-0007 §1).
//!
//! A program manifest's `requests` and a grant (a `block-install`'s `grant`, a parent's offer to a
//! child) have the same shape: a map from capability name to scope. This module is that shape,
//! its deterministic-CBOR encoding, and the two operations the authority rule of JEP-0007 §2 is
//! built from:
//!
//! - `a ⊑ b` ([`Grant::is_within`]): `a` allows nothing `b` does not;
//! - `a ⊓ b` ([`Grant::meet`]): the most that both allow.
//!
//! Effective authority is `request ⊓ grant ⊓ policy`, and a child's is
//! `request(child) ⊓ offer ⊓ effective(parent)`. Because a meet only shrinks, a child can never
//! hold more than its parent, at any depth.
//!
//! # Names
//!
//! A name is `<package>/<interface>[.<effect>]@<semver>`, for example `jig:host/blocks@0.1.0` or
//! `jig:host/effects.post@0.1.0`. A name this host does not know is refused, as is a version that
//! is not compatible with the one it links: the same major, and the same minor while the major is
//! 0 (JEP-0006). Names are encoded with the host's own version, so a decoded `0.1.3` re-encodes as
//! `0.1.0`.
//!
//! # Scopes
//!
//! Every field of every scope is required, and a field the scope does not define is refused, so
//! a scope written for a later version never silently widens. Fields have one of three types:
//!
//! | Type | `a ⊑ b` | `a ⊓ b` |
//! | --- | --- | --- |
//! | set | `a ⊆ b` | intersection |
//! | quota | `a ≤ b` | min |
//! | floor | `a ≥ b` | max |
//!
//! Sets are arrays of binary CIDs in canonical form ([`crate::canonical_cid`]), strictly
//! ascending by their bytes, so one grant has exactly one encoding.

use std::collections::{BTreeMap, BTreeSet};

use cid::Cid;

use crate::dcbor::{self, DcborError, Value};

/// The version of the `jig:host` package this host links.
pub const HOST_VERSION: (u64, u64, u64) = (0, 1, 0);

/// A capability this host knows (JEP-0007 §1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// `jig:host/blocks`: fetch a block by CID. An import.
    Blocks,
    /// `jig:host/compose`: invoke a declared child. An import.
    Compose,
    /// `jig:host/effects.post`: post a block into a channel. An effect.
    Post,
    /// `jig:host/effects.state`: replace the instance's state. An effect.
    State,
    /// `jig:host/effects.timer`: arm the instance's timer. An effect.
    Timer,
}

impl Capability {
    pub const ALL: [Capability; 5] = [
        Capability::Blocks,
        Capability::Compose,
        Capability::Post,
        Capability::State,
        Capability::Timer,
    ];

    /// The name without its version, e.g. `jig:host/effects.post`.
    pub fn base_name(self) -> &'static str {
        match self {
            Capability::Blocks => "jig:host/blocks",
            Capability::Compose => "jig:host/compose",
            Capability::Post => "jig:host/effects.post",
            Capability::State => "jig:host/effects.state",
            Capability::Timer => "jig:host/effects.timer",
        }
    }

    /// Whether the block calls it during execution (an import) rather than returning it (an
    /// effect). Only imports appear in the linker (JEP-0007 §3).
    pub fn is_import(self) -> bool {
        matches!(self, Capability::Blocks | Capability::Compose)
    }

    /// The full name at the host's version, e.g. `jig:host/blocks@0.1.0`.
    pub fn name(self) -> String {
        let (major, minor, patch) = HOST_VERSION;
        format!("{}@{major}.{minor}.{patch}", self.base_name())
    }

    /// Parse a full name, refusing unknown names and incompatible versions.
    pub fn parse(name: &str) -> Result<Self, GrantError> {
        let (base, version) = name
            .rsplit_once('@')
            .ok_or_else(|| GrantError::UnknownCapability(name.to_string()))?;
        let cap = Capability::ALL
            .into_iter()
            .find(|c| c.base_name() == base)
            .ok_or_else(|| GrantError::UnknownCapability(name.to_string()))?;
        if !version_compatible(version) {
            return Err(GrantError::IncompatibleVersion(name.to_string()));
        }
        Ok(cap)
    }

    fn field_names(self) -> &'static [&'static str] {
        match self {
            Capability::Blocks => &["channels", "cids", "max_bytes", "max_calls"],
            Capability::Compose => &["children", "max_calls", "max_depth"],
            Capability::Post => &["channels", "per_hour", "per_invocation"],
            Capability::State => &["max_bytes"],
            Capability::Timer => &["max_horizon_ms", "min_interval_ms"],
        }
    }
}

/// `major.minor.patch` with no pre-release or build part, compatible with [`HOST_VERSION`].
fn version_compatible(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    let [major, minor, patch] = parts.as_slice() else {
        return false;
    };
    let parse = |s: &str| -> Option<u64> {
        // No leading zeros, no signs: one spelling per number.
        if s.is_empty()
            || (s.len() > 1 && s.starts_with('0'))
            || !s.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        s.parse().ok()
    };
    let (Some(major), Some(minor), Some(_)) = (parse(major), parse(minor), parse(patch)) else {
        return false;
    };
    let (host_major, host_minor, _) = HOST_VERSION;
    major == host_major && (host_major != 0 || minor == host_minor)
}

/// The typed scope of one capability. Field meanings are in JEP-0007 §1.4 and §6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Blocks {
        channels: BTreeSet<Cid>,
        cids: BTreeSet<Cid>,
        max_bytes: u64,
        max_calls: u64,
    },
    Compose {
        children: BTreeSet<Cid>,
        max_depth: u64,
        max_calls: u64,
    },
    Post {
        channels: BTreeSet<Cid>,
        per_invocation: u64,
        per_hour: u64,
    },
    State {
        max_bytes: u64,
    },
    Timer {
        min_interval_ms: u64,
        max_horizon_ms: u64,
    },
}

impl Scope {
    /// The capability this scope belongs to.
    pub fn capability(&self) -> Capability {
        match self {
            Scope::Blocks { .. } => Capability::Blocks,
            Scope::Compose { .. } => Capability::Compose,
            Scope::Post { .. } => Capability::Post,
            Scope::State { .. } => Capability::State,
            Scope::Timer { .. } => Capability::Timer,
        }
    }

    /// `self ⊑ other`. Scopes of different capabilities are never comparable.
    pub fn is_within(&self, other: &Scope) -> bool {
        use Scope::*;
        match (self, other) {
            (
                Blocks {
                    channels: c1,
                    cids: d1,
                    max_bytes: b1,
                    max_calls: n1,
                },
                Blocks {
                    channels: c2,
                    cids: d2,
                    max_bytes: b2,
                    max_calls: n2,
                },
            ) => c1.is_subset(c2) && d1.is_subset(d2) && b1 <= b2 && n1 <= n2,
            (
                Compose {
                    children: c1,
                    max_depth: d1,
                    max_calls: n1,
                },
                Compose {
                    children: c2,
                    max_depth: d2,
                    max_calls: n2,
                },
            ) => c1.is_subset(c2) && d1 <= d2 && n1 <= n2,
            (
                Post {
                    channels: c1,
                    per_invocation: i1,
                    per_hour: h1,
                },
                Post {
                    channels: c2,
                    per_invocation: i2,
                    per_hour: h2,
                },
            ) => c1.is_subset(c2) && i1 <= i2 && h1 <= h2,
            (State { max_bytes: b1 }, State { max_bytes: b2 }) => b1 <= b2,
            (
                Timer {
                    min_interval_ms: f1,
                    max_horizon_ms: h1,
                },
                Timer {
                    min_interval_ms: f2,
                    max_horizon_ms: h2,
                },
            ) => f1 >= f2 && h1 <= h2,
            _ => false,
        }
    }

    /// `self ⊓ other`, or `None` when the scopes belong to different capabilities.
    pub fn meet(&self, other: &Scope) -> Option<Scope> {
        use Scope::*;
        let both = |a: &BTreeSet<Cid>, b: &BTreeSet<Cid>| a.intersection(b).copied().collect();
        Some(match (self, other) {
            (
                Blocks {
                    channels: c1,
                    cids: d1,
                    max_bytes: b1,
                    max_calls: n1,
                },
                Blocks {
                    channels: c2,
                    cids: d2,
                    max_bytes: b2,
                    max_calls: n2,
                },
            ) => Blocks {
                channels: both(c1, c2),
                cids: both(d1, d2),
                max_bytes: *b1.min(b2),
                max_calls: *n1.min(n2),
            },
            (
                Compose {
                    children: c1,
                    max_depth: d1,
                    max_calls: n1,
                },
                Compose {
                    children: c2,
                    max_depth: d2,
                    max_calls: n2,
                },
            ) => Compose {
                children: both(c1, c2),
                max_depth: *d1.min(d2),
                max_calls: *n1.min(n2),
            },
            (
                Post {
                    channels: c1,
                    per_invocation: i1,
                    per_hour: h1,
                },
                Post {
                    channels: c2,
                    per_invocation: i2,
                    per_hour: h2,
                },
            ) => Post {
                channels: both(c1, c2),
                per_invocation: *i1.min(i2),
                per_hour: *h1.min(h2),
            },
            (State { max_bytes: b1 }, State { max_bytes: b2 }) => State {
                max_bytes: *b1.min(b2),
            },
            (
                Timer {
                    min_interval_ms: f1,
                    max_horizon_ms: h1,
                },
                Timer {
                    min_interval_ms: f2,
                    max_horizon_ms: h2,
                },
            ) => Timer {
                min_interval_ms: *f1.max(f2),
                max_horizon_ms: *h1.min(h2),
            },
            _ => return None,
        })
    }

    fn to_value(&self) -> Value {
        let set = |s: &BTreeSet<Cid>| {
            let mut items: Vec<Vec<u8>> = s.iter().map(|c| c.to_bytes()).collect();
            items.sort();
            Value::Array(items.into_iter().map(Value::Bytes).collect())
        };
        let n = |v: u64| Value::Unsigned(v);
        match self {
            Scope::Blocks {
                channels,
                cids,
                max_bytes,
                max_calls,
            } => Value::text_map([
                ("channels", set(channels)),
                ("cids", set(cids)),
                ("max_bytes", n(*max_bytes)),
                ("max_calls", n(*max_calls)),
            ]),
            Scope::Compose {
                children,
                max_depth,
                max_calls,
            } => Value::text_map([
                ("children", set(children)),
                ("max_calls", n(*max_calls)),
                ("max_depth", n(*max_depth)),
            ]),
            Scope::Post {
                channels,
                per_invocation,
                per_hour,
            } => Value::text_map([
                ("channels", set(channels)),
                ("per_hour", n(*per_hour)),
                ("per_invocation", n(*per_invocation)),
            ]),
            Scope::State { max_bytes } => Value::text_map([("max_bytes", n(*max_bytes))]),
            Scope::Timer {
                min_interval_ms,
                max_horizon_ms,
            } => Value::text_map([
                ("max_horizon_ms", n(*max_horizon_ms)),
                ("min_interval_ms", n(*min_interval_ms)),
            ]),
        }
    }

    fn from_value(cap: Capability, value: &Value) -> Result<Scope, GrantError> {
        let Value::Map(entries) = value else {
            return Err(GrantError::Malformed(format!(
                "{}: scope is not a map",
                cap.base_name()
            )));
        };
        let expected = cap.field_names();
        for (key, _) in entries {
            let key = key.as_text().ok_or_else(|| {
                GrantError::Malformed(format!("{}: non-text field", cap.base_name()))
            })?;
            if !expected.contains(&key) {
                return Err(GrantError::UnknownField {
                    capability: cap.base_name(),
                    field: key.to_string(),
                });
            }
        }
        let field = |name: &'static str| {
            value.get(name).ok_or(GrantError::MissingField {
                capability: cap.base_name(),
                field: name,
            })
        };
        let quota = |name: &'static str| -> Result<u64, GrantError> {
            field(name)?.as_u64().ok_or_else(|| {
                GrantError::Malformed(format!(
                    "{}.{name}: not an unsigned integer",
                    cap.base_name()
                ))
            })
        };
        let set = |name: &'static str| -> Result<BTreeSet<Cid>, GrantError> {
            let items = field(name)?.as_array().ok_or_else(|| {
                GrantError::Malformed(format!("{}.{name}: not an array", cap.base_name()))
            })?;
            let mut previous: Option<&[u8]> = None;
            let mut out = BTreeSet::new();
            for item in items {
                let bytes = item.as_bytes().ok_or_else(|| {
                    GrantError::Malformed(format!(
                        "{}.{name}: entry is not a byte string",
                        cap.base_name()
                    ))
                })?;
                if previous.is_some_and(|p| p >= bytes) {
                    return Err(GrantError::Malformed(format!(
                        "{}.{name}: entries are not strictly ascending",
                        cap.base_name()
                    )));
                }
                previous = Some(bytes);
                let cid = crate::canonical_cid::from_bytes(bytes).map_err(|e| {
                    GrantError::Malformed(format!("{}.{name}: {e}", cap.base_name()))
                })?;
                out.insert(cid);
            }
            Ok(out)
        };
        Ok(match cap {
            Capability::Blocks => Scope::Blocks {
                channels: set("channels")?,
                cids: set("cids")?,
                max_bytes: quota("max_bytes")?,
                max_calls: quota("max_calls")?,
            },
            Capability::Compose => Scope::Compose {
                children: set("children")?,
                max_depth: quota("max_depth")?,
                max_calls: quota("max_calls")?,
            },
            Capability::Post => Scope::Post {
                channels: set("channels")?,
                per_invocation: quota("per_invocation")?,
                per_hour: quota("per_hour")?,
            },
            Capability::State => Scope::State {
                max_bytes: quota("max_bytes")?,
            },
            Capability::Timer => Scope::Timer {
                min_interval_ms: quota("min_interval_ms")?,
                max_horizon_ms: quota("max_horizon_ms")?,
            },
        })
    }
}

/// A map from capability to scope: a program's `requests`, an install's `grant`, an offer, or an
/// effective authority. A capability absent from the map is not held.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grant {
    scopes: BTreeMap<Capability, Scope>,
}

impl Grant {
    /// The grant that holds nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a grant from scopes. A capability given twice is refused.
    pub fn from_scopes(scopes: impl IntoIterator<Item = Scope>) -> Result<Self, GrantError> {
        let mut out = BTreeMap::new();
        for scope in scopes {
            let cap = scope.capability();
            if out.insert(cap, scope).is_some() {
                return Err(GrantError::Duplicate(cap.base_name()));
            }
        }
        Ok(Self { scopes: out })
    }

    pub fn get(&self, cap: Capability) -> Option<&Scope> {
        self.scopes.get(&cap)
    }

    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    pub fn scopes(&self) -> impl Iterator<Item = &Scope> {
        self.scopes.values()
    }

    /// The import interfaces this grant names: what a linker for it defines (JEP-0007 §3.2).
    pub fn imports(&self) -> impl Iterator<Item = Capability> + '_ {
        self.scopes.keys().copied().filter(|c| c.is_import())
    }

    /// The full names of [`Self::imports`], in the form
    /// [`crate::component_validation::ComponentProfile::granted`] takes.
    pub fn import_names(&self) -> Vec<String> {
        self.imports().map(Capability::name).collect()
    }

    /// `self ⊑ other`: every capability `self` holds, `other` holds at least as widely.
    pub fn is_within(&self, other: &Grant) -> bool {
        self.scopes.iter().all(|(cap, scope)| {
            other
                .scopes
                .get(cap)
                .is_some_and(|theirs| scope.is_within(theirs))
        })
    }

    /// `self ⊓ other`: the capabilities both hold, each at the meet of the two scopes.
    pub fn meet(&self, other: &Grant) -> Grant {
        let scopes = self
            .scopes
            .iter()
            .filter_map(|(cap, scope)| {
                let theirs = other.scopes.get(cap)?;
                Some((*cap, scope.meet(theirs).expect("same capability")))
            })
            .collect();
        Grant { scopes }
    }

    /// The deterministic-CBOR value: a map from full name to scope.
    pub fn to_value(&self) -> Value {
        Value::Map(
            self.scopes
                .iter()
                .map(|(cap, scope)| (Value::text(cap.name()), scope.to_value()))
                .collect(),
        )
    }

    pub fn to_dcbor(&self) -> Result<Vec<u8>, DcborError> {
        dcbor::encode(&self.to_value())
    }

    /// Parse a grant, refusing unknown names, incompatible versions, a capability named twice,
    /// and any scope with a missing or unknown field.
    pub fn from_value(value: &Value) -> Result<Self, GrantError> {
        let Value::Map(entries) = value else {
            return Err(GrantError::Malformed("grant is not a map".to_string()));
        };
        let mut scopes = Vec::with_capacity(entries.len());
        for (key, scope) in entries {
            let name = key
                .as_text()
                .ok_or_else(|| GrantError::Malformed("capability name is not text".to_string()))?;
            let cap = Capability::parse(name)?;
            scopes.push(Scope::from_value(cap, scope)?);
        }
        Self::from_scopes(scopes)
    }

    pub fn from_dcbor(bytes: &[u8]) -> Result<Self, GrantError> {
        Self::from_value(&dcbor::decode(bytes)?)
    }
}

/// Why a grant or a request was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("unknown capability: {0}")]
    UnknownCapability(String),
    #[error("capability version not linked by this host: {0}")]
    IncompatibleVersion(String),
    #[error("capability named twice: {0}")]
    Duplicate(&'static str),
    #[error("{capability}: unknown scope field `{field}`")]
    UnknownField {
        capability: &'static str,
        field: String,
    },
    #[error("{capability}: missing scope field `{field}`")]
    MissingField {
        capability: &'static str,
        field: &'static str,
    },
    #[error("malformed grant: {0}")]
    Malformed(String),
    #[error(transparent)]
    Dcbor(#[from] DcborError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cid(seed: u8) -> Cid {
        crate::canonical_cid::of(&[seed])
    }

    fn set(seeds: &[u8]) -> BTreeSet<Cid> {
        seeds.iter().map(|s| cid(*s)).collect()
    }

    fn blocks(channels: &[u8], max_bytes: u64) -> Scope {
        Scope::Blocks {
            channels: set(channels),
            cids: BTreeSet::new(),
            max_bytes,
            max_calls: 10,
        }
    }

    #[test]
    fn names_round_trip_and_unknown_names_are_refused() {
        for cap in Capability::ALL {
            assert_eq!(Capability::parse(&cap.name()), Ok(cap));
        }
        assert!(matches!(
            Capability::parse("jig:host/net.fetch@0.1.0"),
            Err(GrantError::UnknownCapability(_))
        ));
        assert!(matches!(
            Capability::parse("net.fetch"),
            Err(GrantError::UnknownCapability(_))
        ));
        // The three vocabularies that disagreed before this module are all refused.
        for old in [
            "net:http:fetch",
            "net.fetch",
            "jig_host::net::fetch",
            "storage.read",
        ] {
            assert!(Capability::parse(old).is_err(), "{old}");
        }
    }

    #[test]
    fn versions_match_by_semver_at_0_x() {
        assert_eq!(
            Capability::parse("jig:host/blocks@0.1.7"),
            Ok(Capability::Blocks)
        );
        for v in [
            "0.2.0",
            "1.1.0",
            "0.1",
            "0.1.0-rc1",
            "00.1.0",
            "0.01.0",
            "+0.1.0",
        ] {
            assert!(
                matches!(
                    Capability::parse(&format!("jig:host/blocks@{v}")),
                    Err(GrantError::IncompatibleVersion(_))
                ),
                "{v}"
            );
        }
    }

    #[test]
    fn imports_are_only_blocks_and_compose() {
        let grant = Grant::from_scopes([
            blocks(&[1], 100),
            Scope::State { max_bytes: 64 },
            Scope::Compose {
                children: set(&[2]),
                max_depth: 1,
                max_calls: 1,
            },
        ])
        .unwrap();
        assert_eq!(
            grant.imports().collect::<Vec<_>>(),
            [Capability::Blocks, Capability::Compose]
        );
        assert_eq!(
            grant.import_names(),
            ["jig:host/blocks@0.1.0", "jig:host/compose@0.1.0"]
        );
    }

    #[test]
    fn a_capability_given_twice_is_refused() {
        assert_eq!(
            Grant::from_scopes([blocks(&[1], 1), blocks(&[2], 2)]),
            Err(GrantError::Duplicate("jig:host/blocks"))
        );
    }

    #[test]
    fn timer_floor_attenuates_upwards() {
        let wide = Scope::Timer {
            min_interval_ms: 1_000,
            max_horizon_ms: 86_400_000,
        };
        let narrow = Scope::Timer {
            min_interval_ms: 60_000,
            max_horizon_ms: 3_600_000,
        };
        assert!(narrow.is_within(&wide));
        assert!(!wide.is_within(&narrow));
        assert_eq!(wide.meet(&narrow), Some(narrow));
    }

    #[test]
    fn withholding_a_capability_removes_it_from_the_meet() {
        let parent =
            Grant::from_scopes([blocks(&[1, 2], 100), Scope::State { max_bytes: 64 }]).unwrap();
        let offer = Grant::from_scopes([blocks(&[2, 3], 1_000)]).unwrap();
        let child = parent.meet(&offer);
        assert_eq!(child, Grant::from_scopes([blocks(&[2], 100)]).unwrap());
        assert!(child.get(Capability::State).is_none());
        assert!(child.is_within(&parent));
        assert!(child.is_within(&offer));
    }

    #[test]
    fn unknown_and_missing_fields_are_refused() {
        let mut value = Grant::from_scopes([Scope::State { max_bytes: 1 }])
            .unwrap()
            .to_value();
        let Value::Map(entries) = &mut value else {
            unreachable!()
        };
        let Value::Map(fields) = &mut entries[0].1 else {
            unreachable!()
        };
        fields.push((Value::text("max_keys"), Value::Unsigned(1)));
        assert_eq!(
            Grant::from_value(&value),
            Err(GrantError::UnknownField {
                capability: "jig:host/effects.state",
                field: "max_keys".to_string()
            })
        );

        let missing = Value::text_map([(
            "jig:host/effects.timer@0.1.0",
            Value::text_map([("min_interval_ms", Value::Unsigned(1))]),
        )]);
        assert_eq!(
            Grant::from_value(&missing),
            Err(GrantError::MissingField {
                capability: "jig:host/effects.timer",
                field: "max_horizon_ms"
            })
        );
    }

    #[test]
    fn sets_must_be_strictly_ascending_canonical_cids() {
        let mut ids: Vec<Vec<u8>> = [cid(1), cid(2)].iter().map(|c| c.to_bytes()).collect();
        ids.sort();
        ids.reverse();
        let scope = |items: Vec<Value>| {
            Value::text_map([(
                "jig:host/effects.post@0.1.0",
                Value::text_map([
                    ("channels", Value::Array(items)),
                    ("per_hour", Value::Unsigned(1)),
                    ("per_invocation", Value::Unsigned(1)),
                ]),
            )])
        };
        let descending = scope(ids.iter().cloned().map(Value::Bytes).collect());
        assert!(matches!(
            Grant::from_value(&descending),
            Err(GrantError::Malformed(_))
        ));
        let repeated = scope(vec![
            Value::Bytes(ids[0].clone()),
            Value::Bytes(ids[0].clone()),
        ]);
        assert!(matches!(
            Grant::from_value(&repeated),
            Err(GrantError::Malformed(_))
        ));
        let text = scope(vec![Value::text(cid(1).to_string())]);
        assert!(matches!(
            Grant::from_value(&text),
            Err(GrantError::Malformed(_))
        ));
    }

    #[test]
    fn a_later_patch_version_re_encodes_at_the_host_version() {
        let value = Value::text_map([(
            "jig:host/effects.state@0.1.9",
            Value::text_map([("max_bytes", Value::Unsigned(5))]),
        )]);
        let grant = Grant::from_value(&value).unwrap();
        let again = Grant::from_dcbor(&grant.to_dcbor().unwrap()).unwrap();
        assert_eq!(grant, again);
        assert!(
            grant
                .to_value()
                .get("jig:host/effects.state@0.1.0")
                .is_some()
        );
    }

    // --- the algebra, as properties ---

    fn arb_set() -> impl Strategy<Value = BTreeSet<Cid>> {
        prop::collection::btree_set(0u8..6, 0..4).prop_map(|s| s.into_iter().map(cid).collect())
    }

    fn arb_scope(cap: Capability) -> BoxedStrategy<Scope> {
        let q = || 0u64..8;
        match cap {
            Capability::Blocks => (arb_set(), arb_set(), q(), q())
                .prop_map(|(channels, cids, max_bytes, max_calls)| Scope::Blocks {
                    channels,
                    cids,
                    max_bytes,
                    max_calls,
                })
                .boxed(),
            Capability::Compose => (arb_set(), q(), q())
                .prop_map(|(children, max_depth, max_calls)| Scope::Compose {
                    children,
                    max_depth,
                    max_calls,
                })
                .boxed(),
            Capability::Post => (arb_set(), q(), q())
                .prop_map(|(channels, per_invocation, per_hour)| Scope::Post {
                    channels,
                    per_invocation,
                    per_hour,
                })
                .boxed(),
            Capability::State => q().prop_map(|max_bytes| Scope::State { max_bytes }).boxed(),
            Capability::Timer => (q(), q())
                .prop_map(|(min_interval_ms, max_horizon_ms)| Scope::Timer {
                    min_interval_ms,
                    max_horizon_ms,
                })
                .boxed(),
        }
    }

    fn arb_grant() -> impl Strategy<Value = Grant> {
        let per_cap: Vec<_> = Capability::ALL
            .into_iter()
            .map(|cap| prop::option::of(arb_scope(cap)))
            .collect();
        per_cap.prop_map(|scopes| Grant::from_scopes(scopes.into_iter().flatten()).unwrap())
    }

    proptest! {
        #[test]
        fn meet_is_commutative(a in arb_grant(), b in arb_grant()) {
            prop_assert_eq!(a.meet(&b), b.meet(&a));
        }

        #[test]
        fn meet_is_associative(a in arb_grant(), b in arb_grant(), c in arb_grant()) {
            prop_assert_eq!(a.meet(&b).meet(&c), a.meet(&b.meet(&c)));
        }

        #[test]
        fn meet_is_idempotent(a in arb_grant()) {
            prop_assert_eq!(a.meet(&a), a);
        }

        #[test]
        fn meet_is_within_both_operands(a in arb_grant(), b in arb_grant()) {
            let m = a.meet(&b);
            prop_assert!(m.is_within(&a));
            prop_assert!(m.is_within(&b));
        }

        #[test]
        fn meet_is_the_greatest_lower_bound(a in arb_grant(), b in arb_grant(), c in arb_grant()) {
            if c.is_within(&a) && c.is_within(&b) {
                prop_assert!(c.is_within(&a.meet(&b)));
            }
        }

        #[test]
        fn within_matches_meet(a in arb_grant(), b in arb_grant()) {
            prop_assert_eq!(a.is_within(&b), a.meet(&b) == a);
        }

        #[test]
        fn within_is_transitive(a in arb_grant(), b in arb_grant(), c in arb_grant()) {
            if a.is_within(&b) && b.is_within(&c) {
                prop_assert!(a.is_within(&c));
            }
        }

        /// The nesting guarantee: however many offers a chain of children passes through, the
        /// result never exceeds the root's authority.
        #[test]
        fn no_chain_of_meets_exceeds_its_first_operand(
            root in arb_grant(),
            offers in prop::collection::vec(arb_grant(), 0..6),
        ) {
            let mut effective = root.clone();
            for offer in &offers {
                effective = effective.meet(offer);
                prop_assert!(effective.is_within(&root));
            }
        }

        #[test]
        fn the_empty_grant_is_bottom(a in arb_grant()) {
            prop_assert!(Grant::empty().is_within(&a));
            prop_assert_eq!(a.meet(&Grant::empty()), Grant::empty());
        }

        #[test]
        fn dcbor_round_trips(a in arb_grant()) {
            let bytes = a.to_dcbor().unwrap();
            prop_assert_eq!(Grant::from_dcbor(&bytes).unwrap(), a);
        }
    }
}
