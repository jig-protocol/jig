//! v0.3 block receipts: `exec`, `sealed` and `accepted` (JEP-0006 decision A5).
//!
//! One receipt format replaces the four v0.2 JSON formats. A receipt is a deterministic-CBOR
//! payload ([`crate::dcbor`]) with text keys, signed by its executor as a `COSE_Sign1`
//! ([`crate::cose`]). As for every signed jig object, the envelope names no signer: the payload's
//! `executor` is the signer, and [`SignedReceipt::open`] verifies against it.
//!
//! # Payload
//!
//! Every kind carries `domain` (`jig-block-receipt-v1`), `kind`, `block_cid`, `executor` (DID),
//! `role` (`server` or `member`) and `produced_at` (milliseconds; the executor's own claim, never
//! compared). An `exec` receipt adds:
//!
//! - `component` (BLAKE3-256 of the component bytes), `program` (program CID), `world` (with its
//!   version) and `invocation_hash`;
//! - `operator_policy_cid`, the operator policy that authorised the run (JEP-0011 §3.2). Present
//!   exactly when `role` is `server`;
//! - `outcome`: `{class: "ok", hash}`, `{class: "error", hash}`, `{class: "error", trap, hash}` or
//!   `{class: "incomplete", reason}`;
//! - `limits`: `{fuel, max_wasm_stack, memory_max_pages, timeout_ms}`, the limits the run had, so
//!   an `incomplete` outcome can be read against them;
//! - `engine`: `{name, version, profile, config_fingerprint, fuel_used}`.
//!
//! CIDs are canonical binary CIDv1s ([`crate::canonical_cid`]); hashes are 32-byte strings.
//! `cost` is reserved for pricing: an executor MUST NOT emit it, and [`Receipt::from_payload`]
//! ignores it.
//!
//! # Comparison
//!
//! Two `exec` receipts are evidence about the same run when their `component`, `world` and
//! `invocation_hash` match. Two such runs that both reached a comparable outcome (`ok` or `error`)
//! MUST agree on it, class, trap code and hash; [`compare`] says whether they do. `program`,
//! `limits`, `engine` (fuel included) and `produced_at` are never compared: the program CID
//! differs between servers for the same component, and the rest is engine telemetry.
//!
//! # Encrypted channels
//!
//! A server never executes encrypted content, so `server`-role receipts exist only for channels
//! the server can read. A `member`-role `exec` receipt for a block in an encrypted channel MUST
//! travel only inside the group's ciphertext, never as a plaintext block the server stores. Its
//! `invocation_hash` and outcome `hash` are derived from the plaintext, so for a low-entropy input
//! (a yes or no, a vote, a dice roll) anyone holding the receipt could confirm a guess by hashing
//! it. [`compare_in_channel`] refuses such a receipt when it came from the server's store.

use cid::Cid;

use crate::canonical_cid::{self, CidError};
use crate::dcbor::{self, DcborError, Value};

/// The payload's `domain`.
pub const DOMAIN: &str = "jig-block-receipt-v1";

/// A 32-byte BLAKE3-256 hash.
pub type Hash = [u8; 32];

/// Who executed: the server hosting the channel, or a member on their own device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Member,
}

/// A run's outcome (JEP-0006 decision A3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The export returned `ok`; `hash` is the outcome hash.
    Ok { hash: Hash },
    /// The export returned `err` (`trap` is `None`), or the guest trapped with the JEP-0006 trap
    /// code `trap`. `hash` is the outcome hash.
    Error { trap: Option<String>, hash: Hash },
    /// The run asserts nothing about the block; `reason` says why (e.g. `fuel-exhausted`).
    Incomplete { reason: String },
}

impl Outcome {
    /// Whether two executors must agree on this outcome.
    pub fn is_comparable(&self) -> bool {
        !matches!(self, Outcome::Incomplete { .. })
    }
}

/// The limits a run had. Never compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub fuel: u64,
    pub max_wasm_stack: u64,
    pub memory_max_pages: u32,
    pub timeout_ms: u64,
}

/// The engine that ran it. Telemetry; never compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Engine {
    pub name: String,
    pub version: String,
    pub profile: String,
    pub config_fingerprint: String,
    pub fuel_used: u64,
}

/// What an `exec` receipt adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exec {
    pub component: Hash,
    pub program: Cid,
    pub world: String,
    pub invocation_hash: Hash,
    /// Present exactly when the receipt's role is [`Role::Server`].
    pub operator_policy_cid: Option<Cid>,
    pub outcome: Outcome,
    pub limits: Limits,
    pub engine: Engine,
}

/// The receipt kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Exec(Box<Exec>),
    /// For encrypted content: carries no content-derived value (PV-02).
    Sealed,
    /// Stored without executing.
    Accepted,
}

/// A receipt payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub block_cid: Cid,
    pub executor: String,
    pub role: Role,
    pub produced_at: u64,
    pub body: Body,
}

/// Why a payload or envelope is not a valid receipt.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    #[error(transparent)]
    Cbor(#[from] DcborError),
    #[error("not a receipt payload: {0}")]
    Shape(&'static str),
    #[error(transparent)]
    Cid(#[from] CidError),
    #[error("operator_policy_cid must be present exactly for server-role exec receipts")]
    PolicyCidRole,
    #[error(
        "a member receipt for an encrypted channel may only be read from the group's ciphertext"
    )]
    MemberReceiptFromPlaintextStore,
    #[cfg(feature = "ed25519")]
    #[error(transparent)]
    Cose(#[from] crate::cose::CoseError),
}

impl Receipt {
    /// The deterministic-CBOR payload. Refuses a receipt that breaks the role rule.
    pub fn to_payload(&self) -> Result<Vec<u8>, ReceiptError> {
        let mut entries = vec![
            ("domain", Value::text(DOMAIN)),
            ("block_cid", Value::Bytes(self.block_cid.to_bytes())),
            ("executor", Value::text(self.executor.clone())),
            ("role", Value::text(role_name(self.role))),
            ("produced_at", Value::Unsigned(self.produced_at)),
        ];
        match &self.body {
            Body::Sealed => entries.push(("kind", Value::text("sealed"))),
            Body::Accepted => entries.push(("kind", Value::text("accepted"))),
            Body::Exec(exec) => {
                if exec.operator_policy_cid.is_some() != (self.role == Role::Server) {
                    return Err(ReceiptError::PolicyCidRole);
                }
                entries.push(("kind", Value::text("exec")));
                entries.push(("component", Value::Bytes(exec.component.to_vec())));
                entries.push(("program", Value::Bytes(exec.program.to_bytes())));
                entries.push(("world", Value::text(exec.world.clone())));
                entries.push((
                    "invocation_hash",
                    Value::Bytes(exec.invocation_hash.to_vec()),
                ));
                if let Some(cid) = &exec.operator_policy_cid {
                    entries.push(("operator_policy_cid", Value::Bytes(cid.to_bytes())));
                }
                entries.push(("outcome", outcome_value(&exec.outcome)));
                entries.push(("limits", limits_value(&exec.limits)));
                entries.push(("engine", engine_value(&exec.engine)));
            }
        }
        Ok(dcbor::encode(&Value::text_map(entries)).expect("a receipt always encodes"))
    }

    /// Parse a payload strictly: exact keys for its kind and role, canonical CIDs, 32-byte
    /// hashes. A `cost` entry is ignored.
    pub fn from_payload(bytes: &[u8]) -> Result<Self, ReceiptError> {
        let value = dcbor::decode(bytes)?;
        let mut map = Fields::new(&value)?;
        map.ignore("cost");
        if map.text("domain")? != DOMAIN {
            return Err(ReceiptError::Shape("wrong domain"));
        }
        let block_cid = map.cid("block_cid")?;
        let executor = map.text("executor")?.to_string();
        let role = match map.text("role")? {
            "server" => Role::Server,
            "member" => Role::Member,
            _ => return Err(ReceiptError::Shape("unknown role")),
        };
        let produced_at = map.unsigned("produced_at")?;
        let body = match map.text("kind")? {
            "sealed" => Body::Sealed,
            "accepted" => Body::Accepted,
            "exec" => {
                let operator_policy_cid = map.optional_cid("operator_policy_cid")?;
                if operator_policy_cid.is_some() != (role == Role::Server) {
                    return Err(ReceiptError::PolicyCidRole);
                }
                Body::Exec(Box::new(Exec {
                    component: map.hash("component")?,
                    program: map.cid("program")?,
                    world: map.text("world")?.to_string(),
                    invocation_hash: map.hash("invocation_hash")?,
                    operator_policy_cid,
                    outcome: parse_outcome(map.take("outcome")?)?,
                    limits: parse_limits(map.take("limits")?)?,
                    engine: parse_engine(map.take("engine")?)?,
                }))
            }
            _ => return Err(ReceiptError::Shape("unknown kind")),
        };
        map.finish()?;
        Ok(Self {
            block_cid,
            executor,
            role,
            produced_at,
            body,
        })
    }
}

/// What comparing two `exec` receipts shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    /// Different component, world or invocation: not evidence about the same run.
    DifferentRuns,
    /// At least one outcome is `incomplete`, which asserts nothing.
    NotComparable,
    /// Both reached the same comparable outcome.
    Agree,
    /// Both reached a comparable outcome, and they differ: evidence against one executor, to be
    /// surfaced to the user.
    Diverge,
}

/// Compare two `exec` payloads on (component, world, invocation_hash, outcome) only.
pub fn compare(a: &Exec, b: &Exec) -> Comparison {
    if a.component != b.component || a.world != b.world || a.invocation_hash != b.invocation_hash {
        return Comparison::DifferentRuns;
    }
    if !a.outcome.is_comparable() || !b.outcome.is_comparable() {
        return Comparison::NotComparable;
    }
    if a.outcome == b.outcome {
        Comparison::Agree
    } else {
        Comparison::Diverge
    }
}

/// Where a client got a receipt from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Decrypted from the group's application messages.
    GroupCiphertext,
    /// Read from blocks the server stores in plaintext.
    ServerStore,
}

/// [`compare`] for a client checking another executor's receipt against its own run in a channel.
///
/// Refuses a `member`-role receipt for an encrypted channel that came from the server's store:
/// such a receipt must only ever travel inside the group's ciphertext (see the module docs).
pub fn compare_in_channel(
    ours: &Exec,
    theirs: &Receipt,
    theirs_from: Provenance,
    channel_encrypted: bool,
) -> Result<Option<Comparison>, ReceiptError> {
    if channel_encrypted && theirs.role == Role::Member && theirs_from == Provenance::ServerStore {
        return Err(ReceiptError::MemberReceiptFromPlaintextStore);
    }
    Ok(match &theirs.body {
        Body::Exec(exec) => Some(compare(ours, exec)),
        Body::Sealed | Body::Accepted => None,
    })
}

/// A signed receipt: the `COSE_Sign1` envelope and the receipt it carries.
#[cfg(feature = "ed25519")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReceipt {
    pub envelope: Vec<u8>,
    pub receipt: Receipt,
}

#[cfg(feature = "ed25519")]
impl SignedReceipt {
    /// Sign `receipt` as its executor. `key` must be `receipt.executor`'s key; [`Self::open`]
    /// refuses the envelope otherwise.
    pub fn sign(receipt: Receipt, key: &ed25519_dalek::SigningKey) -> Result<Self, ReceiptError> {
        let envelope = crate::cose::sign1(key, &receipt.to_payload()?);
        Ok(Self { envelope, receipt })
    }

    /// Parse and verify: deterministic, well formed, and signed by the `executor` it names.
    pub fn open(envelope: &[u8]) -> Result<Self, ReceiptError> {
        let sign1 = crate::cose::open_sign1(envelope)?;
        let receipt = Receipt::from_payload(&sign1.payload)?;
        sign1.verify(&receipt.executor)?;
        Ok(Self {
            envelope: envelope.to_vec(),
            receipt,
        })
    }

    /// The receipt's CID: canonical, over the envelope bytes.
    pub fn cid(&self) -> Cid {
        canonical_cid::of(&self.envelope)
    }
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Server => "server",
        Role::Member => "member",
    }
}

fn outcome_value(outcome: &Outcome) -> Value {
    match outcome {
        Outcome::Ok { hash } => Value::text_map([
            ("class", Value::text("ok")),
            ("hash", Value::Bytes(hash.to_vec())),
        ]),
        Outcome::Error { trap: None, hash } => Value::text_map([
            ("class", Value::text("error")),
            ("hash", Value::Bytes(hash.to_vec())),
        ]),
        Outcome::Error {
            trap: Some(trap),
            hash,
        } => Value::text_map([
            ("class", Value::text("error")),
            ("trap", Value::text(trap.clone())),
            ("hash", Value::Bytes(hash.to_vec())),
        ]),
        Outcome::Incomplete { reason } => Value::text_map([
            ("class", Value::text("incomplete")),
            ("reason", Value::text(reason.clone())),
        ]),
    }
}

fn limits_value(limits: &Limits) -> Value {
    Value::text_map([
        ("fuel", Value::Unsigned(limits.fuel)),
        ("max_wasm_stack", Value::Unsigned(limits.max_wasm_stack)),
        (
            "memory_max_pages",
            Value::Unsigned(u64::from(limits.memory_max_pages)),
        ),
        ("timeout_ms", Value::Unsigned(limits.timeout_ms)),
    ])
}

fn engine_value(engine: &Engine) -> Value {
    Value::text_map([
        ("name", Value::text(engine.name.clone())),
        ("version", Value::text(engine.version.clone())),
        ("profile", Value::text(engine.profile.clone())),
        (
            "config_fingerprint",
            Value::text(engine.config_fingerprint.clone()),
        ),
        ("fuel_used", Value::Unsigned(engine.fuel_used)),
    ])
}

fn parse_outcome(value: &Value) -> Result<Outcome, ReceiptError> {
    let mut map = Fields::new(value)?;
    let outcome = match map.text("class")? {
        "ok" => Outcome::Ok {
            hash: map.hash("hash")?,
        },
        "error" => Outcome::Error {
            trap: map.optional_text("trap")?.map(str::to_string),
            hash: map.hash("hash")?,
        },
        "incomplete" => Outcome::Incomplete {
            reason: map.text("reason")?.to_string(),
        },
        _ => return Err(ReceiptError::Shape("unknown outcome class")),
    };
    map.finish()?;
    Ok(outcome)
}

fn parse_limits(value: &Value) -> Result<Limits, ReceiptError> {
    let mut map = Fields::new(value)?;
    let limits = Limits {
        fuel: map.unsigned("fuel")?,
        max_wasm_stack: map.unsigned("max_wasm_stack")?,
        memory_max_pages: u32::try_from(map.unsigned("memory_max_pages")?)
            .map_err(|_| ReceiptError::Shape("memory_max_pages is out of range"))?,
        timeout_ms: map.unsigned("timeout_ms")?,
    };
    map.finish()?;
    Ok(limits)
}

fn parse_engine(value: &Value) -> Result<Engine, ReceiptError> {
    let mut map = Fields::new(value)?;
    let engine = Engine {
        name: map.text("name")?.to_string(),
        version: map.text("version")?.to_string(),
        profile: map.text("profile")?.to_string(),
        config_fingerprint: map.text("config_fingerprint")?.to_string(),
        fuel_used: map.unsigned("fuel_used")?,
    };
    map.finish()?;
    Ok(engine)
}

/// A text-keyed map read field by field; [`Fields::finish`] refuses any field left unread.
/// [`dcbor::decode`] has already refused repeated keys.
struct Fields<'a> {
    entries: Vec<(&'a str, &'a Value)>,
}

impl<'a> Fields<'a> {
    fn new(value: &'a Value) -> Result<Self, ReceiptError> {
        let Value::Map(entries) = value else {
            return Err(ReceiptError::Shape("not a map"));
        };
        let entries = entries
            .iter()
            .map(|(k, v)| {
                k.as_text()
                    .map(|k| (k, v))
                    .ok_or(ReceiptError::Shape("a key is not text"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { entries })
    }

    fn optional(&mut self, key: &str) -> Option<&'a Value> {
        let i = self.entries.iter().position(|(k, _)| *k == key)?;
        Some(self.entries.swap_remove(i).1)
    }

    fn take(&mut self, key: &str) -> Result<&'a Value, ReceiptError> {
        self.optional(key)
            .ok_or(ReceiptError::Shape("a required field is missing"))
    }

    fn ignore(&mut self, key: &str) {
        self.optional(key);
    }

    fn text(&mut self, key: &str) -> Result<&'a str, ReceiptError> {
        self.take(key)?
            .as_text()
            .ok_or(ReceiptError::Shape("a field is not text"))
    }

    fn optional_text(&mut self, key: &str) -> Result<Option<&'a str>, ReceiptError> {
        self.optional(key)
            .map(|v| {
                v.as_text()
                    .ok_or(ReceiptError::Shape("a field is not text"))
            })
            .transpose()
    }

    fn unsigned(&mut self, key: &str) -> Result<u64, ReceiptError> {
        self.take(key)?
            .as_u64()
            .ok_or(ReceiptError::Shape("a field is not an unsigned integer"))
    }

    fn hash(&mut self, key: &str) -> Result<Hash, ReceiptError> {
        self.take(key)?
            .as_bytes()
            .and_then(|b| Hash::try_from(b).ok())
            .ok_or(ReceiptError::Shape("a hash is not 32 bytes"))
    }

    fn cid(&mut self, key: &str) -> Result<Cid, ReceiptError> {
        let bytes = self
            .take(key)?
            .as_bytes()
            .ok_or(ReceiptError::Shape("a CID is not a byte string"))?;
        Ok(canonical_cid::from_bytes(bytes)?)
    }

    fn optional_cid(&mut self, key: &str) -> Result<Option<Cid>, ReceiptError> {
        self.optional(key)
            .map(|v| {
                let bytes = v
                    .as_bytes()
                    .ok_or(ReceiptError::Shape("a CID is not a byte string"))?;
                Ok(canonical_cid::from_bytes(bytes)?)
            })
            .transpose()
    }

    fn finish(self) -> Result<(), ReceiptError> {
        if self.entries.is_empty() {
            Ok(())
        } else {
            Err(ReceiptError::Shape("unknown field"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec(outcome: Outcome, server: bool) -> Box<Exec> {
        Box::new(Exec {
            component: [7; 32],
            program: canonical_cid::of(b"program"),
            world: "jig:block/renderer@0.1.0".into(),
            invocation_hash: [3; 32],
            operator_policy_cid: server.then(|| canonical_cid::of(b"policy")),
            outcome,
            limits: Limits {
                fuel: 50_000_000,
                max_wasm_stack: 512 * 1024,
                memory_max_pages: 256,
                timeout_ms: 250,
            },
            engine: Engine {
                name: "wasmtime".into(),
                version: "49.0.3".into(),
                profile: "jig-det-1".into(),
                config_fingerprint: "blake3:00".into(),
                fuel_used: 1234,
            },
        })
    }

    fn receipt(role: Role, body: Body) -> Receipt {
        Receipt {
            block_cid: canonical_cid::of(b"block"),
            executor: "did:jig:zexecutor".into(),
            role,
            produced_at: 1_747_680_000_000,
            body,
        }
    }

    fn ok(hash: u8) -> Outcome {
        Outcome::Ok { hash: [hash; 32] }
    }

    #[test]
    fn every_kind_round_trips() {
        let cases = [
            receipt(Role::Server, Body::Exec(exec(ok(1), true))),
            receipt(
                Role::Member,
                Body::Exec(exec(
                    Outcome::Error {
                        trap: Some("unreachable".into()),
                        hash: [2; 32],
                    },
                    false,
                )),
            ),
            receipt(
                Role::Server,
                Body::Exec(exec(
                    Outcome::Incomplete {
                        reason: "fuel-exhausted".into(),
                    },
                    true,
                )),
            ),
            receipt(Role::Server, Body::Sealed),
            receipt(Role::Server, Body::Accepted),
        ];
        for r in cases {
            let payload = r.to_payload().expect("encodes");
            assert_eq!(Receipt::from_payload(&payload).as_ref(), Ok(&r));
        }
    }

    #[test]
    fn the_policy_cid_follows_the_role() {
        let server_without = receipt(Role::Server, Body::Exec(exec(ok(1), false)));
        let member_with = receipt(Role::Member, Body::Exec(exec(ok(1), true)));
        assert_eq!(
            server_without.to_payload(),
            Err(ReceiptError::PolicyCidRole)
        );
        assert_eq!(member_with.to_payload(), Err(ReceiptError::PolicyCidRole));
    }

    /// The payload of `r` with `key` set to `value` at the top level.
    fn with_entry(r: &Receipt, key: &str, value: Value) -> Vec<u8> {
        let Value::Map(mut entries) = dcbor::decode(&r.to_payload().unwrap()).unwrap() else {
            unreachable!()
        };
        entries.retain(|(k, _)| k.as_text() != Some(key));
        entries.push((Value::text(key), value));
        dcbor::encode(&Value::Map(entries)).unwrap()
    }

    #[test]
    fn unknown_fields_are_refused_and_cost_is_ignored() {
        let r = receipt(Role::Server, Body::Exec(exec(ok(1), true)));
        assert!(Receipt::from_payload(&with_entry(&r, "note", Value::text("x"))).is_err());
        assert_eq!(
            Receipt::from_payload(&with_entry(&r, "cost", Value::Unsigned(9))),
            Ok(r.clone())
        );
        let sealed = receipt(Role::Server, Body::Sealed);
        assert!(
            Receipt::from_payload(&with_entry(&sealed, "component", Value::Bytes(vec![0; 32])))
                .is_err(),
            "a sealed receipt carries no content-derived value"
        );
    }

    #[test]
    fn a_non_canonical_cid_is_refused() {
        let r = receipt(Role::Server, Body::Accepted);
        let dag_cbor = Cid::new_v1(0x71, canonical_cid::of(b"x").hash().to_owned());
        assert_eq!(
            Receipt::from_payload(&with_entry(
                &r,
                "block_cid",
                Value::Bytes(dag_cbor.to_bytes())
            )),
            Err(ReceiptError::Cid(CidError::NotRaw))
        );
    }

    #[test]
    fn comparison_uses_only_the_run_and_its_outcome() {
        let a = exec(ok(1), true);
        let mut b = exec(ok(1), false);
        // Another server's program CID, other limits and fuel: still the same run, and agreeing.
        b.program = canonical_cid::of(b"another server's program");
        b.limits.fuel = 1;
        b.engine.fuel_used = 999;
        assert_eq!(compare(&a, &b), Comparison::Agree);

        b.outcome = ok(2);
        assert_eq!(compare(&a, &b), Comparison::Diverge);

        b.outcome = Outcome::Error {
            trap: None,
            hash: [1; 32],
        };
        assert_eq!(
            compare(&a, &b),
            Comparison::Diverge,
            "ok and err differ even with one hash"
        );

        b.outcome = Outcome::Incomplete {
            reason: "stack-exhausted".into(),
        };
        assert_eq!(compare(&a, &b), Comparison::NotComparable);

        let mut c = exec(ok(1), true);
        c.invocation_hash = [9; 32];
        assert_eq!(compare(&a, &c), Comparison::DifferentRuns);
        let mut d = exec(ok(1), true);
        d.world = "jig:block/renderer@0.2.0".into();
        assert_eq!(compare(&a, &d), Comparison::DifferentRuns);
    }

    // PV-02: a member's receipt for encrypted content is never read from the plaintext store.
    #[test]
    fn a_member_receipt_for_an_encrypted_channel_is_refused_from_the_server_store() {
        let ours = exec(ok(1), false);
        let theirs = receipt(Role::Member, Body::Exec(exec(ok(1), false)));
        assert_eq!(
            compare_in_channel(&ours, &theirs, Provenance::ServerStore, true),
            Err(ReceiptError::MemberReceiptFromPlaintextStore)
        );
        assert_eq!(
            compare_in_channel(&ours, &theirs, Provenance::GroupCiphertext, true),
            Ok(Some(Comparison::Agree))
        );
        assert_eq!(
            compare_in_channel(&ours, &theirs, Provenance::ServerStore, false),
            Ok(Some(Comparison::Agree)),
            "an open channel's receipts may come from the store"
        );
        let server = receipt(Role::Server, Body::Exec(exec(ok(1), true)));
        assert_eq!(
            compare_in_channel(&ours, &server, Provenance::ServerStore, false),
            Ok(Some(Comparison::Agree))
        );
    }

    /// Pins the encoding: an `accepted` receipt's keys, in encoded-byte order (shorter keys
    /// first, then bytewise), and its payload byte for byte. A change here changes every
    /// signature over a receipt.
    #[test]
    fn an_accepted_receipt_has_a_fixed_encoding() {
        let payload = receipt(Role::Server, Body::Accepted).to_payload().unwrap();
        let Value::Map(entries) = dcbor::decode(&payload).unwrap() else {
            unreachable!()
        };
        let keys: Vec<String> = entries
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_string())
            .collect();
        assert_eq!(
            keys,
            [
                "kind",
                "role",
                "domain",
                "executor",
                "block_cid",
                "produced_at"
            ]
        );
        assert_eq!(hex::encode(&payload), PINNED_ACCEPTED);
    }

    const PINNED_ACCEPTED: &str = "a6646b696e6468616363657074656464726f6c656673657276657266646f6d61696e746a69672d626c6f636b2d726563656970742d7631686578656375746f72716469643a6a69673a7a6578656375746f7269626c6f636b5f636964582401551e20a98489a784bbc2177d6cb7324cc042f52f9d5104a6b675e4409b5f227dc685306b70726f64756365645f61741b00000196e9d87800";

    #[cfg(feature = "ed25519")]
    mod signed {
        use super::*;
        use crate::did::Did;
        use ed25519_dalek::SigningKey;

        fn executor() -> (SigningKey, String) {
            let key = SigningKey::from_bytes(&[5; 32]);
            let did = Did::from_ed25519_pubkey(&key.verifying_key().to_bytes()).to_did_jig_string();
            (key, did)
        }

        #[test]
        fn a_signed_receipt_opens_and_names_its_signer_only_in_the_payload() {
            let (key, did) = executor();
            let mut r = receipt(Role::Server, Body::Exec(exec(ok(1), true)));
            r.executor = did;
            let signed = SignedReceipt::sign(r, &key).unwrap();
            assert_eq!(SignedReceipt::open(&signed.envelope), Ok(signed.clone()));
            assert_eq!(signed.cid(), canonical_cid::of(&signed.envelope));
        }

        #[test]
        fn a_receipt_signed_by_someone_else_is_refused() {
            let (_, did) = executor();
            let mut r = receipt(Role::Member, Body::Accepted);
            r.executor = did;
            let signed = SignedReceipt::sign(r, &SigningKey::from_bytes(&[6; 32])).unwrap();
            assert!(matches!(
                SignedReceipt::open(&signed.envelope),
                Err(ReceiptError::Cose(_))
            ));
        }
    }
}
