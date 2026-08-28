# Authn/Authz Phase 1: Inert Plumbing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the error-disclosure types and the single classifier that phases 2 and 3 will hang authentication and authorization off, changing no server behaviour at all.

**Architecture:** Two new types separate what happened (`GateOutcome`, internal truth) from what we say happened (`Disclosure`, a policy mapping to an HTTP-style triple). A `status` field is added to `Frame::Error` so WSS and REST speak one vocabulary. The dead `capability/` module is deleted so nobody mistakes it for the foundation of this work.

**Compatibility, stated precisely:** REST responses are unchanged — no status, error code, or message text differs. WebSocket error frames **do** change: they gain an optional `status` field, and the server begins populating it on malformed input and on the ingest failures it can classify. Older clients ignore it via `serde(default)`. So this phase is inert in the sense that no existing value changes, not in the sense that no byte on the wire changes.

**Tech Stack:** Rust 2024, axum 0.7, serde, `cargo nextest`, `cargo clippy`.

**Spec:** [`docs/superpowers/specs/2026-08-24-jig-server-authn-authz-design.md`](../specs/2026-08-24-jig-server-authn-authz-design.md)

**Working directory:** All `cargo` commands run from `repos/`, not the repo root. The workspace manifest lives at `repos/Cargo.toml`.

**Toolchain:** Use `cargo +stable` for clippy. The local default is nightly 1.99, whose clippy reports findings stable does not; CI runs stable 1.97.1.

---

### Task 1: Delete the dead `capability/` module

`repos/jig-server/src/capability/` is 442 LOC of HMAC-signed token machinery with **zero references from anywhere outside itself**. It is symmetric-secret based, which cuts against the DID/ed25519 model, and its name will collide conceptually with the tier-1 capabilities introduced in phase 5. Delete it before the work starts.

**Files:**
- Delete: `repos/jig-server/src/capability/mod.rs`
- Delete: `repos/jig-server/src/capability/token.rs`
- Delete: `repos/jig-server/src/capability/registry.rs`
- Delete: `repos/jig-server/src/capability/fuel_tracker.rs`
- Modify: `repos/jig-server/src/lib.rs:3`

- [ ] **Step 1: Prove nothing outside the module references it**

`jig-server` is a **library** crate, so `pub mod capability` is public API and
integration tests in `tests/` link against it from outside. Grepping `src/`
alone is NOT sufficient and will miss them — search the whole crate:

```bash
grep -rn 'capability::' --include='*.rs' repos/jig-server/ | grep -v 'src/capability/'
```

Expected: matches ONLY in `repos/jig-server/tests/capability_enforcement.rs`
and `repos/jig-server/tests/fuel_tracker_tests.rs`. Both import solely from the
doomed module, so they are deleted with it in step 2. Any match outside those
two files means the premise of this task is wrong — STOP, report it, do not
delete.

Sibling crates have their own unrelated `capability` concepts
(`CapabilityMeter`, `CapabilityUsageKey`, `CapabilityCall`,
`fuel_by_capability`) in jig-runtime and jig-core. Those are live and must not
be touched.

- [ ] **Step 2: Delete the module directory**

```bash
git rm -r repos/jig-server/src/capability/
git rm repos/jig-server/tests/capability_enforcement.rs \
      repos/jig-server/tests/fuel_tracker_tests.rs
```

Deleting test files is a destructive step beyond the module itself — get the
user's explicit approval before running it, per the repo working agreement.

Expect the suite to drop by **25** tests, not 15: 10 inline `#[cfg(test)]`
tests inside the module (token.rs 3, registry.rs 4, fuel_tracker.rs 3) plus the
15 integration tests. If the delta is anything else, stop and account for it.

- [ ] **Step 3: Remove the module declaration**

In `repos/jig-server/src/lib.rs`, delete this line:

```rust
pub mod capability;
```

- [ ] **Step 4: Verify the crate still builds and tests pass**

Run:
```bash
cd repos && cargo +stable clippy -p jig-server --all-targets -- -D warnings && cargo +stable nextest run -p jig-server
```

Expected: clippy clean, all tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore(jig-server): delete the unwired capability module

442 LOC of HMAC-signed capability tokens, declared pub mod in lib.rs, with
zero references from anywhere outside itself. Deleted rather than built on:
it is symmetric-secret based against a DID/ed25519 system, and its name
would collide with the tier-1 capabilities the authn/authz design
introduces, inviting a future reader to mistake it for the foundation."
```

---

### Task 2: Add `status` to `Frame::Error`

REST already produces `(StatusCode, code, message)` via `classify_ingest_error`, while `Frame::Error` carries no numeric status. One vocabulary across transports requires the field.

Use `Option<u16>` with `#[serde(default, skip_serializing_if = "Option::is_none")]` — this is the file's own established pattern for additive fields (`ref_cid` and `Frame::Block::sig_b64` both do exactly this), and it keeps older peers' frames parsing.

**Files:**
- Modify: `repos/jig-pipeline/src/envelope.rs:69-74`
- Modify: `repos/jig-server/src/v0_0_2_ws.rs:509-522`
- Modify: `repos/jig-client/src/connection.rs:574`
- Test: `repos/jig-pipeline/src/envelope.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `repos/jig-pipeline/src/envelope.rs`:

```rust
    /// A frame from an older peer carries no `status`. It must still parse,
    /// with `status: None` meaning "this peer does not speak status codes"
    /// rather than defaulting to a number that would be a lie.
    #[test]
    fn error_frame_without_status_still_parses() {
        let json = r#"{"v":1,"op":"error","code":"INVALID_SIG","message":"nope"}"#;
        let parsed: Envelope = serde_json::from_str(json).unwrap();
        match parsed.frame {
            Frame::Error { status, code, .. } => {
                assert_eq!(status, None, "absent status must not invent a value");
                assert_eq!(code, "INVALID_SIG");
            }
            other => panic!("expected Frame::Error, got {other:?}"),
        }
    }

    /// A status, when present, round-trips and is emitted on the wire.
    #[test]
    fn error_frame_with_status_round_trips() {
        let env = Envelope::new(Frame::Error {
            status: Some(403),
            code: "NOT_CHANNEL_OWNER".into(),
            ref_cid: None,
            message: "not the owner".into(),
        });
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""status":403"#), "status must be emitted: {json}");
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    /// An absent status must be omitted entirely, not serialized as null —
    /// matching how `ref_cid` and `sig_b64` already behave in this codec.
    #[test]
    fn absent_status_is_omitted_not_null() {
        let env = Envelope::new(Frame::Error {
            status: None,
            code: "INVALID_SIG".into(),
            ref_cid: None,
            message: "nope".into(),
        });
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("status"), "absent status must be omitted: {json}");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-pipeline --lib envelope
```

Expected: compile error — `Frame::Error` has no field named `status`.

- [ ] **Step 3: Add the field**

In `repos/jig-pipeline/src/envelope.rs`, replace the `Error` variant:

```rust
    /// Report an error in reply to a prior frame.
    ///
    /// `status` carries the HTTP-style status the REST surface would have
    /// returned for the same condition, so a client sees one vocabulary
    /// regardless of transport. `Option` for wire compatibility with peers
    /// predating the field: absent means "this peer does not speak status
    /// codes", which is not the same as any particular code.
    Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
        code: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ref_cid: Option<String>,
        message: String,
    },
```

Also update the wire-format doc comment near the top of the file (line ~16):

```rust
//! { "v": 1, "op": "error", "status": 401, "code": "INVALID_SIG", "ref_cid": null, "message": "..." }
```

- [ ] **Step 4: Fix the two existing envelope tests**

The pre-existing test `error_envelope_round_trips_with_optional_ref_cid` constructs `Frame::Error` twice. Add `status: None,` as the first field of both literals.

- [ ] **Step 5: Fix the other construction sites**

In `repos/jig-server/src/v0_0_2_ws.rs`, change `send_error` to accept and pass a status:

```rust
async fn send_error(
    socket: &mut WebSocket,
    status: Option<u16>,
    code: &str,
    ref_cid: Option<String>,
    message: &str,
) -> Result<(), axum::Error> {
    let frame = Envelope::new(Frame::Error {
        status,
        code: code.to_string(),
        ref_cid,
        message: message.to_string(),
    });
    let json = serde_json::to_string(&frame).map_err(axum::Error::new)?;
    socket.send(Message::Text(json)).await
}
```

Then update every `send_error(` call site in that file to pass a status as the second argument. Find them with:

```bash
grep -n 'send_error(' repos/jig-server/src/v0_0_2_ws.rs
```

For the existing signature-verification failure at line ~437, pass `Some(401)` to match what `classify_ingest_error` already returns for `IngestError::InvalidSignature` (`StatusCode::UNAUTHORIZED`). For any call site whose condition has no REST equivalent, pass `None` rather than guessing a code.

In `repos/jig-client/src/connection.rs:574`, add `status: None,` to the `Frame::Error` literal — this is a test double emitting a canned error, and it is not a server.

- [ ] **Step 6: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-pipeline -p jig-server -p jig-client
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(jig-pipeline): carry an HTTP-style status on Frame::Error

REST already produced (StatusCode, code, message) while the WSS frame
carried no numeric status, so the two transports could not speak a common
error vocabulary. Option<u16> with serde default + skip_serializing_if,
matching how ref_cid and sig_b64 already handle additive fields in this
codec: an absent status means the peer does not speak status codes, which
is deliberately not the same as any particular code."
```

---

### Task 3: `GateOutcome` — the internal truth

**Files:**
- Create: `repos/jig-server/src/auth/mod.rs`
- Create: `repos/jig-server/src/auth/outcome.rs`
- Modify: `repos/jig-server/src/lib.rs`

Note: every item here is `pub`. jig-server is a library crate, and public items are not reported as dead code — which is what lets this phase land before anything calls it, without `-D warnings` failing.

- [ ] **Step 1: Write the failing test**

Create `repos/jig-server/src/auth/outcome.rs` containing ONLY the test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Each gate's outcomes must be distinguishable from the others'. The
    /// ordering property the design depends on — admission refusals must never
    /// surface as authorization refusals — is only checkable if the outcome
    /// itself says which gate produced it.
    #[test]
    fn every_outcome_names_its_gate() {
        assert_eq!(GateOutcome::AuthSignatureInvalid.gate(), Gate::Authenticate);
        assert_eq!(GateOutcome::AuthReplayed.gate(), Gate::Authenticate);
        assert_eq!(GateOutcome::AdmissionUnknownDid.gate(), Gate::Admit);
        assert_eq!(GateOutcome::AdmissionBanned.gate(), Gate::Admit);
        assert_eq!(GateOutcome::AuthzNotMember.gate(), Gate::Authorize);
        assert_eq!(GateOutcome::AuthzNotOwner.gate(), Gate::Authorize);
    }

    /// `unknown` and `below-threshold` are separate variants, not one variant
    /// with a score field. Collapsing them is the specific bug the design
    /// guards against: a holder who ablated a key under deanonymization
    /// pressure lands on a fresh DID, and must not be refused as though they
    /// had a bad score.
    #[test]
    fn unknown_and_below_threshold_are_distinct_variants() {
        let unknown = GateOutcome::AdmissionUnknownDid;
        let below = GateOutcome::AdmissionBelowRuleset {
            ruleset_key: "highsec.v1".to_string(),
        };
        assert_ne!(unknown, below);
        assert_eq!(unknown.gate(), below.gate());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --lib auth
```

Expected: compile error — `GateOutcome` and `Gate` are not defined, and the module is not declared.

- [ ] **Step 3: Write the implementation**

Prepend to `repos/jig-server/src/auth/outcome.rs` (above the test module):

```rust
//! What actually happened at a gate.
//!
//! This is the **internal truth** and it never crosses the wire. The wire sees
//! whatever [`crate::auth::disclosure`] policy maps it to, which by default is
//! the truthful mapping but need not be. Keeping the two apart is what lets a
//! server return 404 for a restricted channel later without touching a single
//! call site — and what keeps the operator's own logs honest while it does.

/// Which gate produced an outcome.
///
/// Recorded on every outcome because gate ordering is a security property:
/// a caller refused at admission must never receive an authorization
/// outcome, since "you are not a member" confirms the channel exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Authenticate,
    Admit,
    Authorize,
}

/// The precise reason a request was refused.
///
/// Variants are deliberately fine-grained. Anything coarser would force the
/// disclosure policy to guess, and would rob the audit log of the detail an
/// operator needs to run the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    /// The signature did not verify against the claimed DID's key.
    AuthSignatureInvalid,
    /// A well-formed, correctly signed request whose nonce was already seen
    /// inside the replay window.
    AuthReplayed,
    /// The request's HLC fell outside the acceptance window.
    AuthStale,
    /// A capability was presented after its expiry.
    AuthCapabilityExpired,
    /// A capability issued to one DID was presented by another.
    AuthCapabilitySubjectMismatch,
    /// No proof of possession accompanied the request at all.
    AuthMissing,

    /// The server has no reputation entry for this DID under any ruleset it
    /// consults. **Not** the same as a bad score: this is a caller the server
    /// has never seen, which is the expected state of a freshly-minted or
    /// deliberately ablated identity.
    AdmissionUnknownDid,
    /// The DID is known under `ruleset_key` and scores below this server's
    /// configured floor for it.
    AdmissionBelowRuleset { ruleset_key: String },
    /// The DID is explicitly refused by this server.
    AdmissionBanned,

    /// The caller is not a member of a restricted channel.
    AuthzNotMember,
    /// The caller is not the channel's owner and the action requires it.
    AuthzNotOwner,
    /// The named channel does not exist.
    AuthzChannelUnknown,
}

impl GateOutcome {
    /// Which gate produced this outcome.
    pub fn gate(&self) -> Gate {
        match self {
            GateOutcome::AuthSignatureInvalid
            | GateOutcome::AuthReplayed
            | GateOutcome::AuthStale
            | GateOutcome::AuthCapabilityExpired
            | GateOutcome::AuthCapabilitySubjectMismatch
            | GateOutcome::AuthMissing => Gate::Authenticate,

            GateOutcome::AdmissionUnknownDid
            | GateOutcome::AdmissionBelowRuleset { .. }
            | GateOutcome::AdmissionBanned => Gate::Admit,

            GateOutcome::AuthzNotMember
            | GateOutcome::AuthzNotOwner
            | GateOutcome::AuthzChannelUnknown => Gate::Authorize,
        }
    }
}
```

Create `repos/jig-server/src/auth/mod.rs`:

```rust
//! Authentication, admission, and authorization for jig-server.
//!
//! Three sequential gates, in this order:
//!
//! 1. **Authenticate** — do you hold the key for this DID?
//! 2. **Admit** — will this server talk to you at all?
//! 3. **Authorize** — may you do this, here?
//!
//! The order is load-bearing. A caller refused at admission must receive the
//! admission outcome, never the authorization one, because "you are not a
//! member" confirms the channel exists.
//!
//! Phase 1 establishes only the outcome and disclosure types. The gates
//! themselves arrive in phases 2 and 3.

pub mod outcome;

pub use outcome::{Gate, GateOutcome};
```

Add to `repos/jig-server/src/lib.rs`, keeping the existing alphabetical grouping (it belongs with the `pub mod` block near `config`):

```rust
pub mod auth;
```

- [ ] **Step 4: Run the test to verify it passes**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --lib auth
```

Expected: 2 tests pass.

- [ ] **Step 5: Verify clippy is clean**

Run:
```bash
cd repos && cargo +stable clippy -p jig-server --all-targets -- -D warnings
```

Expected: no output. If dead-code warnings appear, an item is not `pub` — fix by making it `pub`, not by adding `#[allow(dead_code)]`.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(jig-server): add GateOutcome, the internal truth of a refusal

First half of the truth/disclosure split. GateOutcome records precisely what
happened and which of the three gates produced it; it never crosses the wire.
Recording the gate is what makes the ordering property checkable — a caller
refused at admission must not receive an authorization outcome, since 'you
are not a member' confirms the channel exists.

AdmissionUnknownDid and AdmissionBelowRuleset are separate variants on
purpose. Collapsing them would mean a freshly-minted or deliberately ablated
DID gets refused as though it had a bad score, punishing exactly the
behaviour the anonymity model requires."
```

---

### Task 4: `Disclosure` — the policy mapping

**Files:**
- Create: `repos/jig-server/src/auth/disclosure.rs`
- Modify: `repos/jig-server/src/auth/mod.rs`
- Test: inline `#[cfg(test)]` in `disclosure.rs`

- [ ] **Step 1: Write the failing test**

Create `repos/jig-server/src/auth/disclosure.rs` containing ONLY the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::GateOutcome;

    /// The default policy tells the truth. Anything else would mean v0.0.x
    /// servers lie by default, which is not a decision to make implicitly.
    #[test]
    fn truthful_policy_reports_each_gate_honestly() {
        let p = DisclosurePolicy::Truthful;

        let (status, code, _) = p.disclose(&GateOutcome::AuthSignatureInvalid);
        assert_eq!(status, 401);
        assert_eq!(code, "INVALID_SIG");

        let (status, code, _) = p.disclose(&GateOutcome::AuthzNotMember);
        assert_eq!(status, 403);
        assert_eq!(code, "NOT_A_MEMBER");

        let (status, code, _) = p.disclose(&GateOutcome::AuthzChannelUnknown);
        assert_eq!(status, 404);
        assert_eq!(code, "NO_SUCH_CHANNEL");
    }

    /// The obfuscating policy collapses "you may not" into "there is nothing
    /// here", so probing cannot distinguish a restricted channel from an
    /// absent one. This is the case that must work without touching call
    /// sites — it is the whole reason truth and disclosure are separate types.
    #[test]
    fn restricted_as_not_found_hides_existence() {
        let p = DisclosurePolicy::RestrictedAsNotFound;

        let (status, code, _) = p.disclose(&GateOutcome::AuthzNotMember);
        assert_eq!(status, 404, "a refused member must look like an absent channel");
        assert_eq!(code, "NO_SUCH_CHANNEL");

        let (absent_status, absent_code, _) =
            p.disclose(&GateOutcome::AuthzChannelUnknown);
        assert_eq!(
            (status, code),
            (absent_status, absent_code),
            "refusal and absence must be indistinguishable on the wire"
        );
    }

    /// Obfuscation is client-facing only. If it also blinded the operator's
    /// own logs, nobody could run the server, and the feature would be torn
    /// out within months.
    #[test]
    fn the_audit_line_records_the_truth_even_when_the_wire_does_not() {
        let outcome = GateOutcome::AuthzNotMember;
        let p = DisclosurePolicy::RestrictedAsNotFound;

        let (status, _, _) = p.disclose(&outcome);
        assert_eq!(status, 404, "precondition: the wire is being obfuscated");

        let audit = audit_line(&outcome);
        assert!(
            audit.contains("AuthzNotMember"),
            "the log must name the real outcome, got: {audit}"
        );
        assert!(
            audit.contains("Authorize"),
            "the log must name the real gate, got: {audit}"
        );
    }

    /// Authentication failures are never obfuscated into 404s: a caller who
    /// cannot authenticate has not named a resource yet, so there is nothing
    /// to hide the existence of, and a misleading 404 would just make clients
    /// retry forever instead of fixing their signature.
    #[test]
    fn obfuscation_does_not_touch_authentication_outcomes() {
        let truthful = DisclosurePolicy::Truthful.disclose(&GateOutcome::AuthSignatureInvalid);
        let obfuscated =
            DisclosurePolicy::RestrictedAsNotFound.disclose(&GateOutcome::AuthSignatureInvalid);
        assert_eq!(truthful.0, obfuscated.0);
        assert_eq!(truthful.1, obfuscated.1);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --lib auth::disclosure
```

Expected: compile error — `DisclosurePolicy` and `audit_line` are not defined.

- [ ] **Step 3: Write the implementation**

Prepend to `repos/jig-server/src/auth/disclosure.rs`:

```rust
//! What we tell the caller happened, which is not always what happened.
//!
//! [`GateOutcome`] is the truth. `DisclosurePolicy` maps it to the triple that
//! goes on the wire. The default is the truthful mapping; an operator may
//! choose one that conceals.
//!
//! The split exists so concealment costs nothing to add later. Every refusal
//! in the server routes through [`DisclosurePolicy::disclose`], so a new policy
//! is a new match arm rather than an edit to every call site — which is what
//! "compatibly-built" means here.
//!
//! **Obfuscation is client-facing only.** [`audit_line`] always renders the
//! true outcome, whatever the policy says. An operator who cannot tell a 401
//! from a 404 in their own logs cannot run the server.

use crate::auth::{Gate, GateOutcome};

/// How much of the truth this server tells a refused caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisclosurePolicy {
    /// Report each outcome honestly. The v0.0.x default: a server that lies
    /// should do so because an operator asked it to.
    #[default]
    Truthful,
    /// Report authorization refusals on a channel as though the channel did
    /// not exist, so probing cannot enumerate restricted channels. The
    /// familiar pattern from sites that 404 rather than 403 on customer
    /// resources.
    ///
    /// Authentication outcomes are untouched: a caller who has not
    /// authenticated has not named a resource, so there is no existence to
    /// conceal, and a 404 there would only make clients retry instead of
    /// fixing their credentials.
    RestrictedAsNotFound,
}

impl DisclosurePolicy {
    /// Map an outcome to `(http_status, error_code, message)`.
    pub fn disclose(&self, outcome: &GateOutcome) -> (u16, &'static str, String) {
        match self {
            DisclosurePolicy::Truthful => truthful(outcome),
            DisclosurePolicy::RestrictedAsNotFound => match outcome.gate() {
                Gate::Authorize => (
                    404,
                    "NO_SUCH_CHANNEL",
                    "no such channel".to_string(),
                ),
                _ => truthful(outcome),
            },
        }
    }
}

/// The honest mapping, used directly by [`DisclosurePolicy::Truthful`] and as
/// the fallback for outcomes a concealing policy does not rewrite.
fn truthful(outcome: &GateOutcome) -> (u16, &'static str, String) {
    match outcome {
        GateOutcome::AuthMissing => (
            401,
            "AUTH_REQUIRED",
            "request carries no proof of possession".to_string(),
        ),
        GateOutcome::AuthSignatureInvalid => (
            401,
            "INVALID_SIG",
            "signature verification failed".to_string(),
        ),
        GateOutcome::AuthReplayed => (
            401,
            "REPLAYED",
            "this request was already seen".to_string(),
        ),
        GateOutcome::AuthStale => (
            401,
            "STALE_REQUEST",
            "request timestamp is outside the acceptance window".to_string(),
        ),
        GateOutcome::AuthCapabilityExpired => (
            401,
            "CAPABILITY_EXPIRED",
            "capability has expired".to_string(),
        ),
        GateOutcome::AuthCapabilitySubjectMismatch => (
            401,
            "CAPABILITY_SUBJECT_MISMATCH",
            "capability was issued to a different DID".to_string(),
        ),

        // 403 rather than 401: the caller authenticated fine, this server
        // simply will not deal with them. Re-authenticating cannot help.
        GateOutcome::AdmissionUnknownDid => (
            403,
            "NOT_ADMITTED",
            "this server does not admit unknown identities".to_string(),
        ),
        GateOutcome::AdmissionBelowRuleset { ruleset_key } => (
            403,
            "NOT_ADMITTED",
            format!("reputation under ruleset {ruleset_key} is below this server's floor"),
        ),
        GateOutcome::AdmissionBanned => (
            403,
            "NOT_ADMITTED",
            "this identity is refused by this server".to_string(),
        ),

        GateOutcome::AuthzNotMember => (
            403,
            "NOT_A_MEMBER",
            "not a member of this channel".to_string(),
        ),
        GateOutcome::AuthzNotOwner => (
            403,
            "NOT_CHANNEL_OWNER",
            "not the owner of this channel".to_string(),
        ),
        GateOutcome::AuthzChannelUnknown => {
            (404, "NO_SUCH_CHANNEL", "no such channel".to_string())
        }
    }
}

/// Render an outcome for the audit log. Always the truth, never the policy.
pub fn audit_line(outcome: &GateOutcome) -> String {
    format!("gate={:?} outcome={:?}", outcome.gate(), outcome)
}
```

Add to `repos/jig-server/src/auth/mod.rs`:

```rust
pub mod disclosure;

pub use disclosure::{DisclosurePolicy, audit_line};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --lib auth
```

Expected: 6 tests pass (2 from Task 3, 4 here).

- [ ] **Step 5: Verify the whole workspace is still green**

Crate-scoped first, for fast feedback:
```bash
cd repos && cargo +stable clippy -p jig-server --all-targets -- -D warnings
```

Then the real gate — workspace-wide, matching what CI runs. A crate-scoped pass is NOT
evidence the workspace is green, since a change here can break a dependent crate:
```bash
cd repos && cargo +stable fmt --all \
  && cargo +stable build --workspace \
  && cargo +stable clippy --workspace --all-targets -- -D warnings \
  && cargo +stable nextest run
```

Expected: fmt clean, build clean, clippy silent, full suite passing.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(jig-server): add DisclosurePolicy, separating truth from what we say

Second half of the truth/disclosure split. Every refusal will route through
disclose(), so an obfuscating policy becomes a new match arm rather than an
edit to every call site. RestrictedAsNotFound makes a refused member
indistinguishable from an absent channel, which is what stops probing from
enumerating restricted channels.

Two deliberate limits. Authentication outcomes are never rewritten to 404: a
caller who has not authenticated has named no resource, so there is no
existence to conceal. And audit_line always renders the true outcome
regardless of policy — obfuscation is client-facing only, because an
operator who cannot tell a 401 from a 404 in their own logs cannot run the
server."
```

---

## Phase 1 exit criteria

- [ ] `repos/jig-server/src/capability/` no longer exists and nothing references it.
- [ ] `Frame::Error` carries `status: Option<u16>`, absent-safe in both directions.
- [ ] `GateOutcome` names its gate; `AdmissionUnknownDid` and `AdmissionBelowRuleset` are distinct.
- [ ] `DisclosurePolicy::Truthful` is the default and `RestrictedAsNotFound` needs no call-site changes.
- [ ] `audit_line` records the truth under every policy.
- [ ] `cargo +stable clippy --all-targets -- -D warnings` clean across the workspace's 11 crates.
- [ ] Full suite green: `cargo +stable nextest run` with no exclusions.
- [ ] **No existing status code, error code, or message text has changed value.** Verify by diffing for removed or altered assertions in surviving files: `git diff <base>..HEAD -- '*.rs' | grep -E '^-\s+' | grep assert`. Every hit must be an assertion that was *expanded*, or one belonging to a deleted module — never an expectation whose value changed.
- [ ] **WebSocket error frames gain an optional `status` field, and that is the phase's one intended wire change.** Old clients ignore it via `serde(default)`. Do not describe this phase as "no wire change".
