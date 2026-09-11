# Authn/Authz Phase 4: Admission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a server the ability to refuse a caller *before* asking what they want — the "private club" and "known bad actor" cases DJ locked in — without building reputation scoring, which stays out of scope.

**Architecture:** Gate 2 is a pure function `admit(did, view, policy)` with no I/O, no clock, no network, so it can later run as a sandboxed policy block. It consumes a `ReputationView` (ruleset-scoped `key → score` for one DID) and an `AdmissionPolicy` from `[auth.admission]` config. It runs after gate 1 and before gate 3 on **every** surface: REST reads (listing, history, fetch-by-CID), WSS subscribe, and every write, via a trait seam on `IngestContext` so the pipeline stays free of policy. The view in this phase comes from operator-seeded records in config; the seam is where a ledger plugs in later.

**Tech Stack:** Rust 2024, axum 0.7, rusqlite, tokio, `cargo nextest`.

**Spec:** [`docs/superpowers/specs/2026-08-24-jig-server-authn-authz-design.md`](../specs/2026-08-24-jig-server-authn-authz-design.md) — "Admission as a future policy block", "`unknown` and `below-threshold` are different", Configuration, Testing → Admit.

**Depends on:** Phases 1–3 (PRs #44, #45) merged.

**Working directory:** All `cargo` commands run from `repos/`. Use `cargo +stable`.

**Not in this phase:** reputation scoring, ledgers, PoW, rate limits, tier-1 capabilities (phase 5). Refusing is the product; deciding *scores* is someone else's.

---

## Locked semantics (from the spec and DJ)

1. **Order is a security property.** A banned or unknown DID asking about a channel it is not a member of receives the admission outcome, never the authorization one — "not a member" confirms the channel exists.
2. **Unknown is a choice, never a comparison.** `unknown_dids = "admit" | "refuse"` is explicit. A DID with no score under a ruleset a floor names is *unknown for that ruleset* and governed by `unknown_dids`; the floor's `minimum` is never applied to an absent score. Otherwise a holder who ablated a key under deanonymization pressure lands on a fresh DID and is refused everywhere — the system would punish exactly the behaviour the anonymity model requires.
3. **Tier 0 is refusable.** A per-request proof that verifies is still refused if admission says so.
4. **Writes are refusable too.** "Blocks authenticating their own request … need to be refusable based on server preference." Admission runs inside `ingest` after signature verification, so REST, WSS, admin and bridge paths all get it.
5. **Refusing unknowns is not unsafe.** Nothing here is a `dangerously_` carve-out; it narrows access.

---

### Task 1: The reputation view and the pure `admit` (jig-server)

**Files:**
- Create: `repos/jig-server/src/auth/admission.rs`
- Modify: `repos/jig-server/src/auth/mod.rs` (declare + re-export)

- [ ] **Step 1: Write the failing unit tests** in `admission.rs`:
  - unknown DID admitted when `unknown_dids = Admit`, refused (`AdmissionUnknownDid`) when `Refuse`, with no floors configured and an empty view;
  - a floor `{ruleset_key: "r", minimum: 0}` **does not** refuse a DID with no `"r"` score when `unknown_dids = Admit` (the numeric-comparison bug);
  - the same floor refuses a DID with `"r" = -1` (`AdmissionBelowRuleset { ruleset_key: "r" }`) and admits `"r" = 0`;
  - a DID with a score under some *other* ruleset but none under `"r"` is unknown-for-`r` → governed by `unknown_dids`;
  - `banned_dids` refuses (`AdmissionBanned`) regardless of scores, and **before** floors;
  - `banned` beats `unknown`: a banned DID with no records gets `AdmissionBanned`, not `AdmissionUnknownDid`;
  - order among floors: the first failing floor names its key.

- [ ] **Step 2: Implement**
  ```rust
  pub struct ReputationView { pub scores: BTreeMap<String, i64> }   // ruleset_key → score, for ONE did
  pub enum UnknownDids { Admit, Refuse }
  pub struct Floor { pub ruleset_key: String, pub minimum: i64 }
  pub struct AdmissionPolicy { pub unknown_dids: UnknownDids, pub floors: Vec<Floor>, pub banned_dids: BTreeSet<String> }
  pub fn admit(did: &str, view: &ReputationView, policy: &AdmissionPolicy) -> Result<(), GateOutcome>
  ```
  Pure: no store, no clock. Banned first. Then each floor in config order: `Some(score) if score < minimum` → `AdmissionBelowRuleset`; `None` → unknown for this ruleset → `Refuse` ⇒ `AdmissionUnknownDid`. With no floors, "unknown" means the view is empty.

- [ ] **Step 3: Run, commit** — `feat(jig-server): the pure admission decision`.

---

### Task 2: `[auth.admission]` configuration and seeded records (jig-config)

**Files:**
- Modify: `repos/jig-config/src/v0_0_2_server.rs` (`AuthSection` gains `admission: AdmissionSection`)
- Modify: `repos/jig-server/src/config.rs` template + `deploy/config.example.toml`

- [ ] **Step 1: Tests**: default section admits unknowns with no floors and no bans; a partial `[auth.admission]` keeps the safe defaults (same `#[serde(default)]`-on-the-struct discipline as `[auth]`); records parse; `unknown_dids` accepts only `"admit"`/`"refuse"`.

- [ ] **Step 2: Shape**
  ```toml
  [auth.admission]
  unknown_dids = "admit"            # explicit; "refuse" makes this a members-only server
  banned_dids  = []
  [[auth.admission.floors]]
  ruleset_key = "gigue.highsec.v1"
  minimum     = 0
  [[auth.admission.records]]        # operator-seeded reputation, the view until a ledger exists
  did         = "did:jig:z…"
  ruleset_key = "gigue.highsec.v1"
  score       = 5
  ```

- [ ] **Step 3: Commit** — `feat(jig-config): [auth.admission] policy and seeded records`.

---

### Task 3: A `ReputationSource` seam and the server's implementation

**Files:**
- Modify: `repos/jig-server/src/auth/admission.rs` (`trait ReputationSource { fn view(&self, did: &str) -> ReputationView }`, `SeededRecords` impl from config)
- Modify: `repos/jig-server/src/auth/state.rs` (`AuthState` gains `admission: AdmissionPolicy` + `reputation: Arc<dyn ReputationSource>`, and `fn admit(&self, did) -> Result<(), GateOutcome>`)

- [ ] Tests: `AuthState::from_config` builds the policy and the seeded view; `admit` on state composes them.
- [ ] Commit — `feat(jig-server): admission state from config`.

---

### Task 4: Gate 2 on every read surface

**Files:**
- Modify: `repos/jig-server/src/v0_0_2_blocks.rs` — after `authenticate_read` returns `Some(did)`, run `state.auth.admit(did)`; refuse through `refuse()` (audit + disclosure). All three handlers.
- Modify: `repos/jig-server/src/v0_0_2_ws.rs` — after `authenticate_subscribe` binds `conn_did`, before gate 3 / `subscribe_local`.
- Test: `repos/jig-server/tests/admission.rs` (create), through `support::TestServer` with a builder that takes an `AdmissionSection`.

- [ ] Tests (each with gate 1 genuinely passing — real signatures):
  - banned DID: history 403 `NOT_ADMITTED`; listing 403; fetch-by-CID 403; WSS subscribe error frame 403 `NOT_ADMITTED`;
  - **gate order**: a banned DID reading a restricted channel it is not a member of gets `NOT_ADMITTED`, not `NOT_A_MEMBER`; and reading an *unknown* slug gets `NOT_ADMITTED`, not an empty 200;
  - `unknown_dids = "refuse"` with one seeded record: the seeded DID reads, a fresh DID gets `NOT_ADMITTED`;
  - a floor refuses a seeded below-floor DID and admits an unseeded one under `unknown_dids = "admit"`;
  - escape hatch (`require_authenticated_reads = false`) skips admission too — there is nobody to admit.
- [ ] Fault-inject: make `admit` always `Ok` → the banned tests fail.
- [ ] Commit — `feat(jig-server): run admission on every read`.

---

### Task 5: Gate 2 on writes, through ingest

**Files:**
- Modify: `repos/jig-pipeline/src/ingest.rs` — `pub trait Admission: Send + Sync { fn admit(&self, sender_did: &str) -> Result<(), AdmissionRefusal> }`, `pub enum AdmissionRefusal { Unknown, BelowRuleset { ruleset_key }, Banned }`, `IngestContext.admission: Arc<dyn Admission>`, `AdmitEveryone` default; run it as **step 1b**, right after `verify_sig` (the author DID is a claim until then). Typed `IngestError::NotAdmitted { sender, refusal }`.
- Modify: `repos/jig-server/src/v0_0_2.rs` — wire `AuthState` as the `Admission` impl; `v0_0_2_ingest_error.rs` → 403 `NOT_ADMITTED`; `v0_0_2_bridges.rs` → `PolicyBlocked`.
- Every `IngestContext { .. }` literal in tests gets `admission: Arc::new(AdmitEveryone)`.

- [ ] Tests: pipeline — a banned sender's validly signed text-render is refused `NotAdmitted` and nothing persists; server — banned DID's `POST /api/v1/blocks` is 403 `NOT_ADMITTED`; WSS `Submit` error frame 403 `NOT_ADMITTED`; admin `channel-create` by a banned DID refused; a banned *owner* cannot even archive their own channel (admission precedes ownership).
- [ ] Fault-inject: `AdmitEveryone` wired instead of `AuthState` → the write tests fail.
- [ ] Commit — `feat: admission on every write, through ingest`.

---

### Task 6: Docs

- `deploy/README.md` "Security model": admission exists; how to run a members-only server (`unknown_dids = "refuse"` + records); what it is not (no scoring, no rate limits).
- `docs/RELEASE_READINESS.md` §1.1: admission policy landed; remaining gap = rate limiting / PoW and phase 5.
- Commit — `docs: admission policy`.

---

## Exit criteria

- [ ] A banned DID with a valid proof is refused on every read and write surface with 403 `NOT_ADMITTED`, and the audit line records the true outcome.
- [ ] Gate order proven: admission refusals never surface as authorization refusals or as empty timelines.
- [ ] A floor never refuses a DID that has no score under its ruleset.
- [ ] `unknown_dids = "refuse"` + seeded records = a working members-only server, verified against the real binaries.
- [ ] Full suite green; clippy clean on stable; `cargo deny check` clean.
