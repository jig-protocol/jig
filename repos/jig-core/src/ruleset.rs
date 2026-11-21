//! The ruleset document (JEP-0009 rule 3).
//!
//! A ruleset fixes how standing is computed and recommends what a server does with it. It is a
//! signed object: a `COSE_Sign1` over a deterministic-CBOR payload (rule 1),
//! and its **hash** is the CID of the envelope ([`crate::canonical_cid`]). A server declares the
//! hash in its welcome and `server-manifest` (rule 4), and a subject acknowledges it (rule 5).
//!
//! # Payload
//!
//! ```text
//! {v: 1, id, version, authors: [did], maths: {id, version}, epoch: {epoch_secs,
//!  witness_threshold}, parameters: {pow, pools, standing, invites}, events: {code: weight},
//!  consequences: [{band, pool, effort, join, note?, score_ppm}], tribunal, useful_work,
//!  invites, binding: [text]}
//! ```
//!
//! The four reference rulesets in `jig-spec/jep/vectors/0009/rulesets/` are this payload as
//! JSON; the tests read them.
//!
//! # What parsing refuses
//!
//! - A payload that is not deterministic CBOR ([`crate::dcbor`] refuses floats too, so no
//!   parameter can be one: rule 52).
//! - An unknown **critical** field, at any depth. A field is critical unless its name starts
//!   with `x-` (rule 1). `x-` fields are skipped: they are covered by the hash, and nothing here
//!   reads them. So [`RulesetDocument::to_payload`] re-encodes a parsed document byte for byte
//!   only when it had none.
//! - A missing field. Optional fields are named in each type's docs; absent means off.
//! - A value outside its unit's range (rule 52): a fraction or score in parts per million above
//!   10⁶, pool shares that leave members nothing, an `epoch_secs` of 0.
//! - `authors` or `binding` out of order or repeated, so one document has one payload.
//!
//! What the numbers mean is not checked here. `f` reads `standing`, `events`, `epoch` and
//! `useful_work`; JEP-0008 reads `pow` and `pools`; JEP-0010 reads `tribunal`.

use std::collections::{BTreeMap, BTreeSet};

use cid::Cid;

use crate::dcbor::{self, DcborError, Value};

/// The payload version this module reads and writes.
pub const VERSION: u64 = 1;

/// One unit of evidence, in micro-units (JEP-0009 rule 40).
pub const UNIT: u64 = 1_000_000;

/// The whole of a fraction or a score, in parts per million (rule 52).
pub const PPM: u64 = 1_000_000;

/// Why a payload or envelope is not a ruleset document.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RulesetError {
    #[error(transparent)]
    Cbor(#[from] DcborError),
    #[cfg(feature = "ed25519")]
    #[error(transparent)]
    Cose(#[from] crate::cose::CoseError),
    #[error("`{path}`: {reason}")]
    Field { path: String, reason: &'static str },
    #[error("unknown critical field `{0}`")]
    UnknownCritical(String),
    #[error("ruleset payload version {0} is not {VERSION}")]
    Version(u64),
    #[cfg(feature = "ed25519")]
    #[error("the envelope is not signed by any of the document's authors")]
    NotByAnAuthor,
}

fn field(path: impl Into<String>, reason: &'static str) -> RulesetError {
    RulesetError::Field {
        path: path.into(),
        reason,
    }
}

/// A ruleset document's payload (rule 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetDocument {
    /// A stable name.
    pub id: String,
    /// Increases with every change.
    pub version: u64,
    /// `did:jig` strings, strictly ascending. The envelope is signed by one of them.
    pub authors: Vec<String>,
    pub maths: Maths,
    pub epoch: EpochRule,
    pub parameters: Parameters,
    /// Event code (rule 9) to weight, in micro-units.
    pub events: BTreeMap<String, i64>,
    /// The recommended table from standing to local action (rule 50), in the document's order.
    pub consequences: Vec<Consequence>,
    /// JEP-0010's parameters, or `None`.
    pub tribunal: Option<Tribunal>,
    /// JEP-0016's parameters (its rule 35), or `None`.
    pub useful_work: Option<UsefulWork>,
    /// Whether the ruleset uses invites.
    pub invites: bool,
    /// The optional mechanisms it declares (rules 27, 28), strictly ascending.
    pub binding: Vec<String>,
}

/// The reputation maths, by id and version (rule 14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Maths {
    pub id: String,
    pub version: u64,
}

/// How epochs close (rule 36).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRule {
    /// Epoch time per epoch. Never 0.
    pub epoch_secs: u64,
    /// Witness cosignatures that close an epoch; 0 for a single server.
    pub witness_threshold: u64,
}

/// Everything JEP-0008 and JEP-0009 leave to a ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameters {
    pub pow: Pow,
    pub pools: Pools,
    pub standing: Standing,
    pub invites: Invites,
}

/// JEP-0008's effort bounds, in its own units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pow {
    pub admit: AdmitEffort,
    pub max_penalty_multiplier: u64,
    pub max_standing_discount: u64,
}

/// JEP-0008 rule 19's admission bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmitEffort {
    pub min_effort: u64,
    pub max_effort: u64,
    pub max_solve_secs: u64,
}

/// JEP-0008 rule 23's shares, in percent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pools {
    pub stranger_share: u8,
    pub invited_share: u8,
    /// Of the member pool, not of the whole.
    pub aged_share: u8,
}

/// The parameters `f` reads (rules 16, 17, 40, 41, 49).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    /// Score, ppm, below 10⁶.
    pub established: u64,
    pub min_age_epochs: u64,
    /// `None`: no idle limit.
    pub max_idle_epochs: Option<u64>,
    /// Micro-units.
    pub accrual_per_period: u64,
    /// Micro-units.
    pub per_reporter_cap: u64,
    /// Micro-units.
    pub per_reporter_neg_cap: u64,
    /// ppm.
    pub unknown_reporter_weight: u64,
    /// Per-epoch decay, ppm, below 10⁶.
    pub lambda_pos: u64,
    /// Per-epoch decay, ppm, below 10⁶.
    pub lambda_neg: u64,
    /// Micro-units.
    pub minor: u64,
    /// `None`: no membership by aged proof (rule 49).
    pub admit_age_epochs: Option<u64>,
    pub receipt_positions: u64,
    /// Linked vouching (rule 27), both or neither.
    pub vouch: Option<Vouch>,
}

/// Linked vouching's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vouch {
    pub vouch_cap: u64,
    pub vouch_min_epochs: u64,
}

/// Invite budgets (rule 23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invites {
    pub invite_start: u64,
    pub invite_window_epochs: u64,
    pub invites_per_window: u64,
}

/// One row of the consequences table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consequence {
    pub band: String,
    pub pool: ConsequencePool,
    pub effort: String,
    pub join: JoinRole,
    pub note: Option<String>,
    /// Inclusive score range in ppm, or `None` for subjects with no score.
    pub score_ppm: Option<(i64, i64)>,
}

/// The pool a band recommends (JEP-0008 rule 21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsequencePool {
    Member,
    Invited,
    Stranger,
}

/// The join role a band recommends (JEP-0014).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinRole {
    Member,
    Guest,
    /// Refuse new joins.
    None,
}

/// JEP-0010's parameters, in its own units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tribunal {
    pub appeal_window: u64,
    pub evidence_threshold: u64,
    pub panel_size: u64,
    pub panel_sustain: u64,
    pub provisional_threshold: u64,
    pub provisional_ttl: u64,
    pub response_window: u64,
    pub seat_admission_threshold: u64,
    pub seats: u64,
}

/// A useful-work kind (JEP-0016 rule 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkKind {
    Witness,
    Validate,
    Reexecute,
    Retrieve,
}

impl WorkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkKind::Witness => "witness",
            WorkKind::Validate => "validate",
            WorkKind::Reexecute => "reexecute",
            WorkKind::Retrieve => "retrieve",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "witness" => WorkKind::Witness,
            "validate" => WorkKind::Validate,
            "reexecute" => WorkKind::Reexecute,
            "retrieve" => WorkKind::Retrieve,
            _ => return None,
        })
    }
}

/// JEP-0016 rule 35's block. `credit`, `n` and `k` have one entry per kind in `kinds`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsefulWork {
    /// In the document's order, no repeats.
    pub kinds: Vec<WorkKind>,
    /// Micro-units per completed task.
    pub credit: BTreeMap<WorkKind, u64>,
    pub n: BTreeMap<WorkKind, u64>,
    pub k: BTreeMap<WorkKind, u64>,
    pub n_escalate: u64,
    pub k_escalate: u64,
    /// ppm of `accrual_per_period` (JEP-0016 rule 31).
    pub credit_cap_per_period: u64,
    /// Micro-units, at most 0.
    pub fraud_weight: i64,
    /// Micro-units, at most 0.
    pub beacon_withheld_weight: i64,
    pub beacon_exclusion_epochs: u64,
    pub beacon_min_reveals: u64,
    /// ppm of `epoch_secs`.
    pub beacon_reveal_min: u64,
    pub beacon_reveal_positions: u64,
    /// ppm of `epoch_secs`.
    pub commit_min: u64,
    pub commit_positions: u64,
    /// ppm of `epoch_secs`.
    pub reveal_min: u64,
    pub reveal_positions: u64,
    pub dispute_retention_epochs: u64,
    pub max_carry: u64,
    pub max_missed: u64,
    pub miss_pause_epochs: u64,
    pub miss_window_epochs: u64,
    /// ppm.
    pub reexecute_rate: u64,
    pub retrievability_epochs: u64,
    pub retrieve_samples: u64,
    pub same_subject_cooldown_epochs: u64,
    /// ppm.
    pub sample_rate: u64,
}

// ---------------------------------------------------------------------------
// Reading

/// A text-keyed map whose every critical key is one of `known`. `x-` keys are skipped.
struct Obj<'a> {
    path: String,
    entries: BTreeMap<&'a str, &'a Value>,
}

impl<'a> Obj<'a> {
    fn new(value: &'a Value, path: &str, known: &[&str]) -> Result<Self, RulesetError> {
        let Value::Map(pairs) = value else {
            return Err(field(path, "not a map"));
        };
        let mut entries = BTreeMap::new();
        for (k, v) in pairs {
            let k = k
                .as_text()
                .ok_or_else(|| field(path, "a key is not text"))?;
            if k.starts_with("x-") {
                continue;
            }
            if !known.contains(&k) {
                return Err(RulesetError::UnknownCritical(join(path, k)));
            }
            entries.insert(k, v);
        }
        Ok(Self {
            path: path.to_string(),
            entries,
        })
    }

    fn path(&self, key: &str) -> String {
        join(&self.path, key)
    }

    fn opt(&self, key: &str) -> Option<&'a Value> {
        self.entries.get(key).copied()
    }

    fn req(&self, key: &str) -> Result<&'a Value, RulesetError> {
        self.opt(key)
            .ok_or_else(|| field(self.path(key), "missing"))
    }

    fn u64(&self, key: &str) -> Result<u64, RulesetError> {
        self.req(key)?
            .as_u64()
            .ok_or_else(|| field(self.path(key), "not an unsigned integer"))
    }

    fn opt_u64(&self, key: &str) -> Result<Option<u64>, RulesetError> {
        self.opt(key)
            .map(|v| {
                v.as_u64()
                    .ok_or_else(|| field(self.path(key), "not an unsigned integer"))
            })
            .transpose()
    }

    /// A multiplier or divisor: 1 means none, and 0 is undefined.
    fn positive(&self, key: &str) -> Result<u64, RulesetError> {
        let n = self.u64(key)?;
        if n == 0 {
            return Err(field(self.path(key), "0; 1 means none"));
        }
        Ok(n)
    }

    fn ppm(&self, key: &str) -> Result<u64, RulesetError> {
        let n = self.u64(key)?;
        if n > PPM {
            return Err(field(self.path(key), "above 10⁶ parts per million"));
        }
        Ok(n)
    }

    fn i64(&self, key: &str) -> Result<i64, RulesetError> {
        self.req(key)?
            .as_i64()
            .ok_or_else(|| field(self.path(key), "not an integer"))
    }

    fn penalty(&self, key: &str) -> Result<i64, RulesetError> {
        let n = self.i64(key)?;
        if n > 0 {
            return Err(field(self.path(key), "a penalty weight above 0"));
        }
        Ok(n)
    }

    fn pct(&self, key: &str) -> Result<u8, RulesetError> {
        u8::try_from(self.u64(key)?)
            .ok()
            .filter(|n| *n <= 100)
            .ok_or_else(|| field(self.path(key), "not a percentage"))
    }

    fn text(&self, key: &str) -> Result<String, RulesetError> {
        self.req(key)?
            .as_text()
            .map(str::to_string)
            .ok_or_else(|| field(self.path(key), "not text"))
    }

    fn bool(&self, key: &str) -> Result<bool, RulesetError> {
        match self.req(key)? {
            Value::Bool(b) => Ok(*b),
            _ => Err(field(self.path(key), "not a boolean")),
        }
    }

    fn obj(&self, key: &str, known: &[&str]) -> Result<Obj<'a>, RulesetError> {
        Obj::new(self.req(key)?, &self.path(key), known)
    }

    /// `null`, or an object.
    fn nullable(&self, key: &str) -> Result<Option<&'a Value>, RulesetError> {
        Ok(match self.req(key)? {
            Value::Null => None,
            v => Some(v),
        })
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

/// The sort key CBOR gives text: its own deterministic encoding.
fn text_key(s: &str) -> Vec<u8> {
    dcbor::encode(&Value::text(s)).expect("text always encodes")
}

fn ascending_texts(value: &Value, path: &str) -> Result<Vec<String>, RulesetError> {
    let items = value
        .as_array()
        .ok_or_else(|| field(path, "not an array"))?
        .iter()
        .map(|v| {
            v.as_text()
                .map(str::to_string)
                .ok_or_else(|| field(path, "an entry is not text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let keys: Vec<Vec<u8>> = items.iter().map(|s| text_key(s)).collect();
    if !keys.windows(2).all(|w| w[0] < w[1]) {
        return Err(field(path, "not strictly ascending"));
    }
    Ok(items)
}

const TOP: &[&str] = &[
    "v",
    "id",
    "version",
    "authors",
    "maths",
    "epoch",
    "parameters",
    "events",
    "consequences",
    "tribunal",
    "useful_work",
    "invites",
    "binding",
];

impl RulesetDocument {
    /// Parse a payload, refusing anything that is not exactly one ruleset document.
    pub fn from_payload(bytes: &[u8]) -> Result<Self, RulesetError> {
        Self::from_value(&dcbor::decode(bytes)?)
    }

    fn from_value(value: &Value) -> Result<Self, RulesetError> {
        let top = Obj::new(value, "", TOP)?;
        let v = top.u64("v")?;
        if v != VERSION {
            return Err(RulesetError::Version(v));
        }
        let id = top.text("id")?;
        if id.is_empty() {
            return Err(field("id", "empty"));
        }
        let authors = ascending_texts(top.req("authors")?, "authors")?;
        for author in &authors {
            if crate::did::Did::from_did_jig_string(author)
                .map(|d| d.to_did_jig_string())
                .ok()
                .as_deref()
                != Some(author.as_str())
            {
                return Err(field("authors", "an author is not a canonical did:jig"));
            }
        }

        let maths = top.obj("maths", &["id", "version"])?;
        let maths = Maths {
            id: maths.text("id")?,
            version: maths.u64("version")?,
        };

        let epoch = top.obj("epoch", &["epoch_secs", "witness_threshold"])?;
        let epoch = EpochRule {
            epoch_secs: epoch.u64("epoch_secs")?,
            witness_threshold: epoch.u64("witness_threshold")?,
        };
        if epoch.epoch_secs == 0 {
            return Err(field("epoch.epoch_secs", "0"));
        }

        let parameters =
            parse_parameters(&top.obj("parameters", &["pow", "pools", "standing", "invites"])?)?;

        let Value::Map(pairs) = top.req("events")? else {
            return Err(field("events", "not a map"));
        };
        let mut events = BTreeMap::new();
        for (k, w) in pairs {
            let code = k
                .as_text()
                .ok_or_else(|| field("events", "a code is not text"))?;
            if code.starts_with("x-") {
                continue;
            }
            let w = w
                .as_i64()
                .ok_or_else(|| field(join("events", code), "not an integer"))?;
            events.insert(code.to_string(), w);
        }

        let consequences = top
            .req("consequences")?
            .as_array()
            .ok_or_else(|| field("consequences", "not an array"))?
            .iter()
            .enumerate()
            .map(|(i, row)| parse_consequence(row, &format!("consequences[{i}]")))
            .collect::<Result<Vec<_>, _>>()?;

        let tribunal = top.nullable("tribunal")?.map(parse_tribunal).transpose()?;
        let useful_work = top
            .nullable("useful_work")?
            .map(parse_useful_work)
            .transpose()?;

        Ok(Self {
            id,
            version: top.u64("version")?,
            authors,
            maths,
            epoch,
            parameters,
            events,
            consequences,
            tribunal,
            useful_work,
            invites: top.bool("invites")?,
            binding: ascending_texts(top.req("binding")?, "binding")?,
        })
    }
}

fn parse_parameters(p: &Obj<'_>) -> Result<Parameters, RulesetError> {
    let pow = p.obj(
        "pow",
        &["admit", "max_penalty_multiplier", "max_standing_discount"],
    )?;
    let admit = pow.obj("admit", &["min_effort", "max_effort", "max_solve_secs"])?;
    let admit = AdmitEffort {
        min_effort: admit.u64("min_effort")?,
        max_effort: admit.u64("max_effort")?,
        max_solve_secs: admit.u64("max_solve_secs")?,
    };
    if admit.min_effort > admit.max_effort {
        return Err(field(
            "parameters.pow.admit",
            "min_effort is above max_effort",
        ));
    }
    let pow = Pow {
        admit,
        max_penalty_multiplier: pow.positive("max_penalty_multiplier")?,
        max_standing_discount: pow.positive("max_standing_discount")?,
    };

    let pools = p.obj("pools", &["stranger_share", "invited_share", "aged_share"])?;
    let pools = Pools {
        stranger_share: pools.pct("stranger_share")?,
        invited_share: pools.pct("invited_share")?,
        aged_share: pools.pct("aged_share")?,
    };
    if u16::from(pools.stranger_share) + u16::from(pools.invited_share) >= 100 {
        return Err(field(
            "parameters.pools",
            "stranger_share + invited_share leaves members nothing",
        ));
    }

    let s = p.obj(
        "standing",
        &[
            "established",
            "min_age_epochs",
            "max_idle_epochs",
            "accrual_per_period",
            "per_reporter_cap",
            "per_reporter_neg_cap",
            "unknown_reporter_weight",
            "lambda_pos",
            "lambda_neg",
            "minor",
            "admit_age_epochs",
            "receipt_positions",
            "vouch_cap",
            "vouch_min_epochs",
        ],
    )?;
    let established = s.ppm("established")?;
    if established >= PPM {
        return Err(field(s.path("established"), "a score is below 10⁶"));
    }
    let (lambda_pos, lambda_neg) = (s.ppm("lambda_pos")?, s.ppm("lambda_neg")?);
    if lambda_pos >= PPM || lambda_neg >= PPM {
        return Err(field(
            s.path("lambda_*"),
            "a decay of 10⁶ erases everything",
        ));
    }
    let vouch = match (s.opt_u64("vouch_cap")?, s.opt_u64("vouch_min_epochs")?) {
        (Some(vouch_cap), Some(vouch_min_epochs)) => Some(Vouch {
            vouch_cap,
            vouch_min_epochs,
        }),
        (None, None) => None,
        _ => {
            return Err(field(
                s.path("vouch_*"),
                "vouch_cap and vouch_min_epochs come together",
            ));
        }
    };
    let standing = Standing {
        established,
        min_age_epochs: s.u64("min_age_epochs")?,
        max_idle_epochs: s.opt_u64("max_idle_epochs")?,
        accrual_per_period: s.u64("accrual_per_period")?,
        per_reporter_cap: s.u64("per_reporter_cap")?,
        per_reporter_neg_cap: s.u64("per_reporter_neg_cap")?,
        unknown_reporter_weight: s.ppm("unknown_reporter_weight")?,
        lambda_pos,
        lambda_neg,
        minor: s.u64("minor")?,
        admit_age_epochs: s.opt_u64("admit_age_epochs")?,
        receipt_positions: s.u64("receipt_positions")?,
        vouch,
    };

    let i = p.obj(
        "invites",
        &["invite_start", "invite_window_epochs", "invites_per_window"],
    )?;
    let invites = Invites {
        invite_start: i.u64("invite_start")?,
        invite_window_epochs: i.u64("invite_window_epochs")?,
        invites_per_window: i.u64("invites_per_window")?,
    };
    Ok(Parameters {
        pow,
        pools,
        standing,
        invites,
    })
}

fn parse_consequence(value: &Value, path: &str) -> Result<Consequence, RulesetError> {
    let c = Obj::new(
        value,
        path,
        &["band", "pool", "effort", "join", "note", "score_ppm"],
    )?;
    let pool = match c.text("pool")?.as_str() {
        "member" => ConsequencePool::Member,
        "invited" => ConsequencePool::Invited,
        "stranger" => ConsequencePool::Stranger,
        _ => return Err(field(c.path("pool"), "not member, invited or stranger")),
    };
    let join_role = match c.text("join")?.as_str() {
        "member" => JoinRole::Member,
        "guest" => JoinRole::Guest,
        "none" => JoinRole::None,
        _ => return Err(field(c.path("join"), "not member, guest or none")),
    };
    let note = c
        .opt("note")
        .map(|v| {
            v.as_text()
                .map(str::to_string)
                .ok_or_else(|| field(c.path("note"), "not text"))
        })
        .transpose()?;
    let score_ppm = match c.req("score_ppm")? {
        Value::Null => None,
        v => {
            let bound = |v: &Value| {
                v.as_i64()
                    .filter(|n| (-(PPM as i64)..PPM as i64).contains(n))
                    .ok_or_else(|| field(c.path("score_ppm"), "not a score in [−10⁶, 10⁶)"))
            };
            let [lo, hi] = v.as_array().unwrap_or_default() else {
                return Err(field(c.path("score_ppm"), "not null or [low, high]"));
            };
            let (lo, hi) = (bound(lo)?, bound(hi)?);
            if lo > hi {
                return Err(field(c.path("score_ppm"), "low is above high"));
            }
            Some((lo, hi))
        }
    };
    Ok(Consequence {
        band: c.text("band")?,
        pool,
        effort: c.text("effort")?,
        join: join_role,
        note,
        score_ppm,
    })
}

const TRIBUNAL: &[&str] = &[
    "appeal_window",
    "evidence_threshold",
    "panel_size",
    "panel_sustain",
    "provisional_threshold",
    "provisional_ttl",
    "response_window",
    "seat_admission_threshold",
    "seats",
];

fn parse_tribunal(value: &Value) -> Result<Tribunal, RulesetError> {
    let t = Obj::new(value, "tribunal", TRIBUNAL)?;
    Ok(Tribunal {
        appeal_window: t.u64("appeal_window")?,
        evidence_threshold: t.u64("evidence_threshold")?,
        panel_size: t.u64("panel_size")?,
        panel_sustain: t.u64("panel_sustain")?,
        provisional_threshold: t.u64("provisional_threshold")?,
        provisional_ttl: t.u64("provisional_ttl")?,
        response_window: t.u64("response_window")?,
        seat_admission_threshold: t.u64("seat_admission_threshold")?,
        seats: t.u64("seats")?,
    })
}

const USEFUL_WORK: &[&str] = &[
    "kinds",
    "credit",
    "n",
    "k",
    "n_escalate",
    "k_escalate",
    "credit_cap_per_period",
    "fraud_weight",
    "beacon_withheld_weight",
    "beacon_exclusion_epochs",
    "beacon_min_reveals",
    "beacon_reveal_min",
    "beacon_reveal_positions",
    "commit_min",
    "commit_positions",
    "reveal_min",
    "reveal_positions",
    "dispute_retention_epochs",
    "max_carry",
    "max_missed",
    "miss_pause_epochs",
    "miss_window_epochs",
    "reexecute_rate",
    "retrievability_epochs",
    "retrieve_samples",
    "same_subject_cooldown_epochs",
    "sample_rate",
];

fn parse_useful_work(value: &Value) -> Result<UsefulWork, RulesetError> {
    let u = Obj::new(value, "useful_work", USEFUL_WORK)?;
    let mut kinds = Vec::new();
    for v in u
        .req("kinds")?
        .as_array()
        .ok_or_else(|| field(u.path("kinds"), "not an array"))?
    {
        let kind = v
            .as_text()
            .and_then(WorkKind::parse)
            .ok_or_else(|| field(u.path("kinds"), "not a useful-work kind"))?;
        if kinds.contains(&kind) {
            return Err(field(u.path("kinds"), "a kind repeats"));
        }
        kinds.push(kind);
    }
    let wanted: BTreeSet<WorkKind> = kinds.iter().copied().collect();
    let per_kind = |key: &str| -> Result<BTreeMap<WorkKind, u64>, RulesetError> {
        let names: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
        let o = u.obj(key, &names)?;
        let map = kinds
            .iter()
            .map(|k| Ok((*k, o.u64(k.as_str())?)))
            .collect::<Result<BTreeMap<_, _>, RulesetError>>()?;
        debug_assert_eq!(map.keys().copied().collect::<BTreeSet<_>>(), wanted);
        Ok(map)
    };
    Ok(UsefulWork {
        credit: per_kind("credit")?,
        n: per_kind("n")?,
        k: per_kind("k")?,
        n_escalate: u.u64("n_escalate")?,
        k_escalate: u.u64("k_escalate")?,
        credit_cap_per_period: u.ppm("credit_cap_per_period")?,
        fraud_weight: u.penalty("fraud_weight")?,
        beacon_withheld_weight: u.penalty("beacon_withheld_weight")?,
        beacon_exclusion_epochs: u.u64("beacon_exclusion_epochs")?,
        beacon_min_reveals: u.u64("beacon_min_reveals")?,
        beacon_reveal_min: u.ppm("beacon_reveal_min")?,
        beacon_reveal_positions: u.u64("beacon_reveal_positions")?,
        commit_min: u.ppm("commit_min")?,
        commit_positions: u.u64("commit_positions")?,
        reveal_min: u.ppm("reveal_min")?,
        reveal_positions: u.u64("reveal_positions")?,
        dispute_retention_epochs: u.u64("dispute_retention_epochs")?,
        max_carry: u.u64("max_carry")?,
        max_missed: u.u64("max_missed")?,
        miss_pause_epochs: u.u64("miss_pause_epochs")?,
        miss_window_epochs: u.u64("miss_window_epochs")?,
        reexecute_rate: u.ppm("reexecute_rate")?,
        retrievability_epochs: u.u64("retrievability_epochs")?,
        retrieve_samples: u.u64("retrieve_samples")?,
        same_subject_cooldown_epochs: u.u64("same_subject_cooldown_epochs")?,
        sample_rate: u.ppm("sample_rate")?,
        kinds,
    })
}

// ---------------------------------------------------------------------------
// Writing

fn uint(n: u64) -> Value {
    Value::Unsigned(n)
}

fn texts(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::Text).collect())
}

impl RulesetDocument {
    /// The deterministic-CBOR payload. [`Self::from_payload`] of it gives `self` back.
    pub fn to_payload(&self) -> Vec<u8> {
        dcbor::encode(&self.to_value()).expect("a ruleset document always encodes")
    }

    fn to_value(&self) -> Value {
        let p = &self.parameters;
        let s = &p.standing;
        let mut standing = vec![
            ("established", uint(s.established)),
            ("min_age_epochs", uint(s.min_age_epochs)),
            ("accrual_per_period", uint(s.accrual_per_period)),
            ("per_reporter_cap", uint(s.per_reporter_cap)),
            ("per_reporter_neg_cap", uint(s.per_reporter_neg_cap)),
            ("unknown_reporter_weight", uint(s.unknown_reporter_weight)),
            ("lambda_pos", uint(s.lambda_pos)),
            ("lambda_neg", uint(s.lambda_neg)),
            ("minor", uint(s.minor)),
            ("receipt_positions", uint(s.receipt_positions)),
        ];
        if let Some(n) = s.max_idle_epochs {
            standing.push(("max_idle_epochs", uint(n)));
        }
        if let Some(n) = s.admit_age_epochs {
            standing.push(("admit_age_epochs", uint(n)));
        }
        if let Some(v) = s.vouch {
            standing.push(("vouch_cap", uint(v.vouch_cap)));
            standing.push(("vouch_min_epochs", uint(v.vouch_min_epochs)));
        }
        let parameters = Value::text_map([
            (
                "pow",
                Value::text_map([
                    (
                        "admit",
                        Value::text_map([
                            ("min_effort", uint(p.pow.admit.min_effort)),
                            ("max_effort", uint(p.pow.admit.max_effort)),
                            ("max_solve_secs", uint(p.pow.admit.max_solve_secs)),
                        ]),
                    ),
                    ("max_penalty_multiplier", uint(p.pow.max_penalty_multiplier)),
                    ("max_standing_discount", uint(p.pow.max_standing_discount)),
                ]),
            ),
            (
                "pools",
                Value::text_map([
                    ("stranger_share", uint(p.pools.stranger_share.into())),
                    ("invited_share", uint(p.pools.invited_share.into())),
                    ("aged_share", uint(p.pools.aged_share.into())),
                ]),
            ),
            ("standing", Value::text_map(standing)),
            (
                "invites",
                Value::text_map([
                    ("invite_start", uint(p.invites.invite_start)),
                    ("invite_window_epochs", uint(p.invites.invite_window_epochs)),
                    ("invites_per_window", uint(p.invites.invites_per_window)),
                ]),
            ),
        ]);
        let events = Value::Map(
            self.events
                .iter()
                .map(|(k, w)| (Value::text(k.clone()), Value::int(*w)))
                .collect(),
        );
        let consequences = Value::Array(self.consequences.iter().map(consequence_value).collect());
        Value::text_map([
            ("v", uint(VERSION)),
            ("id", Value::text(self.id.clone())),
            ("version", uint(self.version)),
            ("authors", texts(&self.authors)),
            (
                "maths",
                Value::text_map([
                    ("id", Value::text(self.maths.id.clone())),
                    ("version", uint(self.maths.version)),
                ]),
            ),
            (
                "epoch",
                Value::text_map([
                    ("epoch_secs", uint(self.epoch.epoch_secs)),
                    ("witness_threshold", uint(self.epoch.witness_threshold)),
                ]),
            ),
            ("parameters", parameters),
            ("events", events),
            ("consequences", consequences),
            (
                "tribunal",
                self.tribunal.as_ref().map_or(Value::Null, tribunal_value),
            ),
            (
                "useful_work",
                self.useful_work
                    .as_ref()
                    .map_or(Value::Null, useful_work_value),
            ),
            ("invites", Value::Bool(self.invites)),
            ("binding", texts(&self.binding)),
        ])
    }
}

fn consequence_value(c: &Consequence) -> Value {
    let pool = match c.pool {
        ConsequencePool::Member => "member",
        ConsequencePool::Invited => "invited",
        ConsequencePool::Stranger => "stranger",
    };
    let join = match c.join {
        JoinRole::Member => "member",
        JoinRole::Guest => "guest",
        JoinRole::None => "none",
    };
    let mut entries = vec![
        ("band", Value::text(c.band.clone())),
        ("pool", Value::text(pool)),
        ("effort", Value::text(c.effort.clone())),
        ("join", Value::text(join)),
        (
            "score_ppm",
            c.score_ppm.map_or(Value::Null, |(lo, hi)| {
                Value::Array(vec![Value::int(lo), Value::int(hi)])
            }),
        ),
    ];
    if let Some(note) = &c.note {
        entries.push(("note", Value::text(note.clone())));
    }
    Value::text_map(entries)
}

fn tribunal_value(t: &Tribunal) -> Value {
    Value::text_map([
        ("appeal_window", uint(t.appeal_window)),
        ("evidence_threshold", uint(t.evidence_threshold)),
        ("panel_size", uint(t.panel_size)),
        ("panel_sustain", uint(t.panel_sustain)),
        ("provisional_threshold", uint(t.provisional_threshold)),
        ("provisional_ttl", uint(t.provisional_ttl)),
        ("response_window", uint(t.response_window)),
        ("seat_admission_threshold", uint(t.seat_admission_threshold)),
        ("seats", uint(t.seats)),
    ])
}

fn useful_work_value(u: &UsefulWork) -> Value {
    let per_kind = |m: &BTreeMap<WorkKind, u64>| {
        Value::Map(
            m.iter()
                .map(|(k, n)| (Value::text(k.as_str()), uint(*n)))
                .collect(),
        )
    };
    Value::text_map([
        (
            "kinds",
            Value::Array(u.kinds.iter().map(|k| Value::text(k.as_str())).collect()),
        ),
        ("credit", per_kind(&u.credit)),
        ("n", per_kind(&u.n)),
        ("k", per_kind(&u.k)),
        ("n_escalate", uint(u.n_escalate)),
        ("k_escalate", uint(u.k_escalate)),
        ("credit_cap_per_period", uint(u.credit_cap_per_period)),
        ("fraud_weight", Value::int(u.fraud_weight)),
        (
            "beacon_withheld_weight",
            Value::int(u.beacon_withheld_weight),
        ),
        ("beacon_exclusion_epochs", uint(u.beacon_exclusion_epochs)),
        ("beacon_min_reveals", uint(u.beacon_min_reveals)),
        ("beacon_reveal_min", uint(u.beacon_reveal_min)),
        ("beacon_reveal_positions", uint(u.beacon_reveal_positions)),
        ("commit_min", uint(u.commit_min)),
        ("commit_positions", uint(u.commit_positions)),
        ("reveal_min", uint(u.reveal_min)),
        ("reveal_positions", uint(u.reveal_positions)),
        ("dispute_retention_epochs", uint(u.dispute_retention_epochs)),
        ("max_carry", uint(u.max_carry)),
        ("max_missed", uint(u.max_missed)),
        ("miss_pause_epochs", uint(u.miss_pause_epochs)),
        ("miss_window_epochs", uint(u.miss_window_epochs)),
        ("reexecute_rate", uint(u.reexecute_rate)),
        ("retrievability_epochs", uint(u.retrievability_epochs)),
        ("retrieve_samples", uint(u.retrieve_samples)),
        (
            "same_subject_cooldown_epochs",
            uint(u.same_subject_cooldown_epochs),
        ),
        ("sample_rate", uint(u.sample_rate)),
    ])
}

// ---------------------------------------------------------------------------
// Signing

/// A signed ruleset: the envelope, the document it carries, and its hash. Its fields are
/// read-only, so the document and hash always describe the envelope; to change a document,
/// clone it and sign the copy.
#[cfg(feature = "ed25519")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRuleset {
    envelope: Vec<u8>,
    document: RulesetDocument,
    hash: Cid,
    signer: String,
}

#[cfg(feature = "ed25519")]
impl SignedRuleset {
    /// Sign `document` with `key`. Refuses a document that [`Self::open`] would refuse: one that
    /// does not parse back from its own payload, or whose `authors` do not include the key's DID.
    pub fn sign(
        document: RulesetDocument,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, RulesetError> {
        let payload = document.to_payload();
        RulesetDocument::from_payload(&payload)?;
        let signer = crate::did::Did::from_ed25519_pubkey(&key.verifying_key().to_bytes())
            .to_did_jig_string();
        if !document.authors.contains(&signer) {
            return Err(RulesetError::NotByAnAuthor);
        }
        let envelope = crate::cose::sign1(key, &payload);
        Ok(Self {
            hash: crate::canonical_cid::of(&envelope),
            envelope,
            document,
            signer,
        })
    }

    /// Parse and verify an envelope: a deterministic, well-formed document, signed by one of the
    /// authors it names. A document with no authors cannot be opened: nobody vouches for it.
    pub fn open(envelope: &[u8]) -> Result<Self, RulesetError> {
        let sign1 = crate::cose::open_sign1(envelope)?;
        let document = RulesetDocument::from_payload(&sign1.payload)?;
        let signer = document
            .authors
            .iter()
            .find(|author| sign1.verify(author).is_ok())
            .ok_or(RulesetError::NotByAnAuthor)?
            .clone();
        Ok(Self {
            envelope: envelope.to_vec(),
            hash: crate::canonical_cid::of(envelope),
            document,
            signer,
        })
    }

    /// The `COSE_Sign1` bytes.
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// The document the envelope carries.
    pub fn document(&self) -> &RulesetDocument {
        &self.document
    }

    /// The ruleset's **hash** (rule 3): the canonical CID of the envelope.
    pub fn hash(&self) -> &Cid {
        &self.hash
    }

    /// The author whose key signed it.
    pub fn signer(&self) -> &str {
        &self.signer
    }
}

/// The ruleset hash of an envelope, without opening it.
pub fn hash_of(envelope: &[u8]) -> Cid {
    crate::canonical_cid::of(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../jig-spec/jep/vectors/0009/rulesets"
    );
    const NAMES: [&str; 4] = ["jig-reference", "high-sec", "community", "null-sec"];

    /// JSON to the CBOR value it denotes: the vectors are the payloads written as JSON.
    fn json_to_value(j: &serde_json::Value) -> Value {
        match j {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => Value::int(n.as_i64().expect("vectors are integers")),
            serde_json::Value::String(s) => Value::text(s.clone()),
            serde_json::Value::Array(a) => Value::Array(a.iter().map(json_to_value).collect()),
            serde_json::Value::Object(o) => Value::Map(
                o.iter()
                    .map(|(k, v)| (Value::text(k.clone()), json_to_value(v)))
                    .collect(),
            ),
        }
    }

    fn vector(name: &str) -> Value {
        let text = std::fs::read_to_string(format!("{VECTORS}/{name}.json")).unwrap();
        json_to_value(&serde_json::from_str(&text).unwrap())
    }

    fn payload(name: &str) -> Vec<u8> {
        dcbor::encode(&vector(name)).unwrap()
    }

    /// Replace the value at `path` (dot-separated keys) in a map value.
    fn set(value: &mut Value, path: &[&str], new: Option<Value>) {
        let Value::Map(entries) = value else {
            panic!("not a map at {path:?}")
        };
        let (key, rest) = path.split_first().unwrap();
        let at = entries.iter().position(|(k, _)| k.as_text() == Some(key));
        if rest.is_empty() {
            match (at, new) {
                (Some(i), Some(v)) => entries[i].1 = v,
                (Some(i), None) => {
                    entries.remove(i);
                }
                (None, Some(v)) => entries.push((Value::text(*key), v)),
                (None, None) => {}
            }
        } else {
            set(&mut entries[at.expect("path exists")].1, rest, new);
        }
    }

    fn with(
        name: &str,
        path: &[&str],
        new: Option<Value>,
    ) -> Result<RulesetDocument, RulesetError> {
        let mut v = vector(name);
        set(&mut v, path, new);
        RulesetDocument::from_payload(&dcbor::encode(&v).unwrap())
    }

    /// Every reference ruleset parses, and re-encodes to the same bytes: one document, one
    /// payload.
    #[test]
    fn the_reference_rulesets_parse_and_round_trip() {
        for name in NAMES {
            let bytes = payload(name);
            let doc =
                RulesetDocument::from_payload(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(doc.id, name);
            assert_eq!(doc.maths.id, "jig-beta-v1");
            assert_eq!(doc.to_payload(), bytes, "{name} re-encodes");
        }
    }

    /// The values the reference rulesets page states, read back from the parsed documents.
    #[test]
    fn the_parsed_reference_values_match_the_tables() {
        let r = RulesetDocument::from_payload(&payload("jig-reference")).unwrap();
        assert_eq!(r.parameters.pools.aged_share, 25);
        assert_eq!(r.parameters.standing.established, 300_000);
        assert_eq!(r.parameters.standing.max_idle_epochs, Some(14));
        assert_eq!(r.events["signed-contradiction"], -25 * UNIT as i64);
        assert!(r.tribunal.is_none() && r.useful_work.is_none());

        let h = RulesetDocument::from_payload(&payload("high-sec")).unwrap();
        assert_eq!(h.parameters.standing.admit_age_epochs, None);
        assert_eq!(h.parameters.pools.aged_share, 0);
        let uw = h.useful_work.unwrap();
        assert_eq!(uw.n[&WorkKind::Witness], 5);
        assert_eq!(uw.credit[&WorkKind::Validate], 200_000);
        assert_eq!((uw.commit_min, uw.beacon_reveal_min), (20_000, 10_000));
        assert_eq!(h.tribunal.unwrap().seats, 5);

        let c = RulesetDocument::from_payload(&payload("community")).unwrap();
        assert!(c.parameters.standing.vouch.is_some());
        assert_eq!(c.parameters.standing.unknown_reporter_weight, 250_000);

        let n = RulesetDocument::from_payload(&payload("null-sec")).unwrap();
        assert_eq!(n.parameters.standing.max_idle_epochs, None);
        assert_eq!(n.parameters.standing.accrual_per_period, 0);
    }

    /// Rule 1: an unknown critical field is refused at any depth; an `x-` field is skipped, and
    /// the document is otherwise the same.
    #[test]
    fn unknown_critical_fields_are_refused_and_x_fields_skipped() {
        for path in [
            &["surprise"][..],
            &["parameters", "surprise"],
            &["parameters", "standing", "surprise"],
            &["epoch", "surprise"],
        ] {
            let err = with("jig-reference", path, Some(Value::Unsigned(1))).unwrap_err();
            assert!(
                matches!(err, RulesetError::UnknownCritical(ref p) if p.ends_with("surprise")),
                "{path:?}: {err}"
            );
        }
        let base = RulesetDocument::from_payload(&payload("high-sec")).unwrap();
        for path in [
            &["x-note"][..],
            &["parameters", "standing", "x-note"],
            &["useful_work", "x-note"],
            &["events", "x-note"],
        ] {
            let doc = with("high-sec", path, Some(Value::text("ignored"))).unwrap();
            assert_eq!(doc, base, "{path:?}");
        }
        let mut row = vector("jig-reference");
        let Value::Map(top) = &mut row else {
            unreachable!()
        };
        let (_, Value::Array(rows)) = top
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("consequences"))
            .unwrap()
        else {
            unreachable!()
        };
        set(&mut rows[0], &["surprise"], Some(Value::Null));
        let err = RulesetDocument::from_payload(&dcbor::encode(&row).unwrap()).unwrap_err();
        assert_eq!(
            err,
            RulesetError::UnknownCritical("consequences[0].surprise".into())
        );
    }

    #[test]
    fn a_payload_not_in_deterministic_encoding_is_refused() {
        let mut bytes = payload("jig-reference");
        // `v: 1` as a two-byte integer: well formed, not shortest.
        let at = bytes.windows(2).position(|w| w == [0x61, b'v']).unwrap() + 2;
        assert_eq!(bytes[at], 0x01);
        bytes.splice(at..=at, [0x18, 0x01]);
        assert_eq!(
            RulesetDocument::from_payload(&bytes),
            Err(RulesetError::Cbor(DcborError::NotDeterministic))
        );
    }

    #[test]
    fn missing_and_out_of_range_values_are_refused() {
        let cases: &[(&[&str], Option<Value>, &str)] = &[
            (&["parameters", "standing", "minor"], None, "missing"),
            (&["v"], Some(Value::Unsigned(2)), "version 2"),
            (&["epoch", "epoch_secs"], Some(Value::Unsigned(0)), "0"),
            (
                &["parameters", "standing", "established"],
                Some(Value::Unsigned(1_000_000)),
                "below 10⁶",
            ),
            (
                &["parameters", "standing", "lambda_pos"],
                Some(Value::Unsigned(1_000_001)),
                "above 10⁶",
            ),
            (
                &["parameters", "pools", "stranger_share"],
                Some(Value::Unsigned(90)),
                "leaves members nothing",
            ),
            (
                &["parameters", "pools", "aged_share"],
                Some(Value::Unsigned(101)),
                "percentage",
            ),
            (
                &["parameters", "standing", "accrual_per_period"],
                Some(Value::int(-1)),
                "unsigned",
            ),
            (
                &["parameters", "standing", "vouch_cap"],
                Some(Value::Unsigned(3)),
                "come together",
            ),
            (
                &["authors"],
                Some(Value::Array(vec![Value::text("alice")])),
                "did:jig",
            ),
            (
                &["binding"],
                Some(Value::Array(vec![Value::text("b"), Value::text("a")])),
                "ascending",
            ),
            (&["invites"], Some(Value::Unsigned(0)), "boolean"),
            (
                &["parameters", "pow", "max_standing_discount"],
                Some(Value::Unsigned(0)),
                "1 means none",
            ),
            (
                &["parameters", "pow", "max_penalty_multiplier"],
                Some(Value::Unsigned(0)),
                "1 means none",
            ),
        ];
        for (path, new, want) in cases {
            let err = with("jig-reference", path, new.clone()).unwrap_err();
            assert!(err.to_string().contains(want), "{path:?}: {err}");
        }
    }

    /// Scores run over [−10⁶, 10⁶) (rule 40), so a consequence row may start at −10⁶ but not
    /// reach 10⁶.
    #[test]
    fn consequence_scores_cover_the_whole_range() {
        let row = |lo: i64, hi: i64| {
            let mut v = vector("jig-reference");
            let Value::Map(top) = &mut v else {
                unreachable!()
            };
            let (_, Value::Array(rows)) = top
                .iter_mut()
                .find(|(k, _)| k.as_text() == Some("consequences"))
                .unwrap()
            else {
                unreachable!()
            };
            set(
                &mut rows[0],
                &["score_ppm"],
                Some(Value::Array(vec![Value::int(lo), Value::int(hi)])),
            );
            RulesetDocument::from_payload(&dcbor::encode(&v).unwrap())
        };
        let doc = row(-1_000_000, -1).unwrap();
        assert_eq!(doc.consequences[0].score_ppm, Some((-1_000_000, -1)));
        assert!(row(-1_000_001, -1).is_err());
        assert!(row(0, 1_000_000).is_err());
        assert!(row(0, 999_999).is_ok());
    }

    #[test]
    fn useful_work_kinds_must_match_their_tables() {
        let cases: &[(&[&str], Value, &str)] = &[
            (
                &["useful_work", "kinds"],
                Value::Array(vec![Value::text("witness"), Value::text("witness")]),
                "repeats",
            ),
            (
                &["useful_work", "kinds"],
                Value::Array(vec![Value::text("mine")]),
                "kind",
            ),
            (
                &["useful_work", "fraud_weight"],
                Value::Unsigned(5),
                "above 0",
            ),
            (
                &["useful_work", "credit_cap_per_period"],
                Value::Unsigned(1_000_001),
                "above 10⁶",
            ),
        ];
        for (path, new, want) in cases {
            let err = with("high-sec", path, Some(new.clone())).unwrap_err();
            assert!(err.to_string().contains(want), "{path:?}: {err}");
        }
        // A kind dropped from `kinds` but still in `n` is an unknown critical field there.
        let only_witness = Value::Array(vec![Value::text("witness")]);
        let err = with("high-sec", &["useful_work", "kinds"], Some(only_witness)).unwrap_err();
        assert!(matches!(err, RulesetError::UnknownCritical(_)), "{err}");
    }

    #[cfg(feature = "ed25519")]
    mod signed {
        use super::*;
        use ed25519_dalek::SigningKey;

        fn key(seed: u8) -> (SigningKey, String) {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let did = crate::did::Did::from_ed25519_pubkey(&key.verifying_key().to_bytes())
                .to_did_jig_string();
            (key, did)
        }

        fn authored(authors: Vec<String>) -> RulesetDocument {
            let mut doc = RulesetDocument::from_payload(&payload("jig-reference")).unwrap();
            let mut authors = authors;
            authors.sort_by_key(|a| text_key(a));
            doc.authors = authors;
            doc
        }

        #[test]
        fn a_signed_ruleset_opens_with_the_same_hash() {
            let (alice, alice_did) = key(1);
            let (_, bob_did) = key(2);
            let signed =
                SignedRuleset::sign(authored(vec![alice_did.clone(), bob_did]), &alice).unwrap();
            let opened = SignedRuleset::open(signed.envelope()).unwrap();
            assert_eq!(opened, signed);
            assert_eq!(opened.signer(), alice_did);
            assert_eq!(*opened.hash(), hash_of(signed.envelope()));
            crate::canonical_cid::check(opened.hash()).unwrap();
        }

        #[test]
        fn a_ruleset_signed_by_a_non_author_is_refused() {
            let (_, alice_did) = key(1);
            let (mallory, _) = key(3);
            let doc = authored(vec![alice_did]);
            assert_eq!(
                SignedRuleset::sign(doc.clone(), &mallory),
                Err(RulesetError::NotByAnAuthor)
            );
            // An envelope made outside `sign` is refused on open too.
            let forged = crate::cose::sign1(&mallory, &doc.to_payload());
            assert_eq!(
                SignedRuleset::open(&forged),
                Err(RulesetError::NotByAnAuthor)
            );
            // With no authors, nobody vouches for it.
            let unsigned = crate::cose::sign1(&mallory, &authored(Vec::new()).to_payload());
            assert_eq!(
                SignedRuleset::open(&unsigned),
                Err(RulesetError::NotByAnAuthor)
            );
        }

        #[test]
        fn any_change_changes_the_hash() {
            let (alice, alice_did) = key(1);
            let doc = authored(vec![alice_did]);
            let a = SignedRuleset::sign(doc.clone(), &alice).unwrap();
            let mut next = doc;
            next.version += 1;
            let b = SignedRuleset::sign(next, &alice).unwrap();
            assert_ne!(a.hash(), b.hash());
        }

        /// `sign` refuses what `open` would refuse, so it never returns an envelope nobody can
        /// open.
        #[test]
        fn an_invalid_document_is_not_signed() {
            let (alice, alice_did) = key(1);
            let mut doc = authored(vec![alice_did]);
            doc.epoch.epoch_secs = 0;
            let err = SignedRuleset::sign(doc, &alice).unwrap_err();
            assert!(err.to_string().contains("epoch_secs"), "{err}");
        }
    }
}
