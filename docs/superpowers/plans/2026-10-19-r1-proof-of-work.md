# R1: Proof-of-Work — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** registration under a suffix can be opened to strangers without letting one party take
the namespace. That needs three things:
- every binding request at a nameserver carries proof-of-work that anyone can solve and verify;
- the price adapts to load;
- a capacity cap bounds how fast any number of strangers can register, however much compute they
  have.

Servers then move their one-time admission work onto the same puzzle. Admission PoW becomes on
by default (D26).

**Why now:** DJ decided that `@jig` registration stays closed until proof-of-work lands on the
nameserver's registration path. This plan is that path, plus the checklist for opening `@jig`
(section "What opening `@jig` requires").

**Spec:**
- [JEP-0008](../../../repos/jig-spec/jep/jep-0008-proof-of-work.md); rule numbers below are
  JEP-0008's.
- Design and decisions:
  [reputation, PoW and tribunals framing](../specs/2026-10-18-reputation-pow-tribunals-framing.md),
  sections 4–5 and 17 (questions 1, 3, 4 and 5).
- Registration proofs and the reserved `pow` field:
  [F1 plan](2026-10-18-f1-verified-names.md), task 2, step 3b.

**What PoW does and does not buy here:**
- PoW is a price on strangers' capacity, never an identity price (framing, section 4).
- Against a GPU or a botnet, no effort a phone can afford stops a squatter. 2^20 digests take a
  GPU about a millisecond (an estimate; task 0 measures it).
- What actually bounds squatting is the **registration pool** (task 3). It is a per-suffix cap
  on stranger registrations per unit of time, ordered by effort. Compute cannot raise the cap.
- PoW orders and prices the requests that fit under it.
- Short names, which are scarce, cost more (task 3).

**Tech stack:** Rust 2024, axum 0.7, serde, `jig_core::{cose, dcbor}`, `cargo nextest`,
`cargo clippy`.

**Working directory:** all `cargo` commands run from `repos/`. Build with `CARGO_INCREMENTAL=0`,
and run `scripts/clean-build-artifacts.sh --here --yes` when a slice is done (`AGENTS.md`).

---

## What exists on `main` (checked at `6aa5724`)

| Piece | Where | State |
| --- | --- | --- |
| Reserved `pow` field | `RegisterReq` in `repos/jig-nameserver/src/v0_0_2_register.rs`; `RenewReq` and `RotateReq` in `repos/jig-nameserver/src/v0_0_2_rotate_renew.rs` | `Option<serde_json::Value>`, `#[serde(default)]`, accepted and ignored. A test pins this: `an_arbitrary_pow_field_is_accepted_and_ignored` |
| Challenges | `GET /v1/challenge` in `v0_0_2_register.rs`; `remember_challenge` and `take_challenge` in `repos/jig-nameserver/src/v0_0_2.rs` | 32 random bytes, hex, 60 s TTL. Held in an in-memory map swept by TTL, with **no count bound**. One challenge serves every action |
| Proof binding | `jig_core::naming::{proof_payload, proof_hash}` in `repos/jig-core/src/naming.rs` | `Action` has only `Register` and `Renew`. Rotate still signs the bare challenge (`verify_bare_challenge_sig`) until lane I's I3 |
| Order of checks | `register` in `v0_0_2_register.rs` | Parse, then proof of control, then reachability, then consume the challenge. Nothing cheap runs before the signature check |
| Alias-route rate limits | `repos/jig-nameserver/src/v0_0_2_rate_limit.rs`, `AliasRateLimitConfig` in `repos/jig-nameserver/src/config.rs` | Per IP (30 a minute) and per DID (10 a minute, charged on 2xx) across register, rotate and renew. `GET /v1/challenge` is **not** limited |
| Suffix | `NameserverSection::alias_suffix` in `repos/jig-config/src/v0_0_2_server.rs` | One suffix per nameserver process |
| Server admission PoW | `repos/jig-core/src/admission_pow.rs`; `repos/jig-server/src/v0_0_2_admission.rs`; `repos/jig-server/src/auth/{admission,state}.rs`; `AdmissionSection` in `repos/jig-config/src/v0_0_2_server.rs` | `jig-admission-pow-v1`, a bit count (1–28, default 20), off by default. Advertised unsigned as `admission_pow_bits` at `/.well-known/jig` (`repos/jig-server/src/handler.rs`) |
| Client solver | `repos/jig-client/src/admission.rs`; `repos/jig-cli/src/cmd/admission.rs` | Solves the admission PoW only. The register, renew and rotate builders (`repos/jig-cli/src/cmd/{init,keys}.rs`) send no `pow` |
| Server rate limits | `repos/jig-server/src/auth/rate.rs` | Token buckets per DID and per address. No capacity partition |
| L6's namespace policy | #224 (`feat/nameserver-multi-suffix`, draft, at `8936481`): `SuffixConfig` in `repos/jig-config/src/v0_0_2_server.rs`; `Suffixes`, `SuffixPolicy::admit` in `repos/jig-nameserver/src/v0_0_2_policy.rs` | `[[v0_0_2.nameserver.alias_suffixes]]`, one entry per suffix: `registration = "open" \| "closed"` (`#[non_exhaustive]`), `single_label_authority`, `min_alias_len` (default 3), `reserved`, `reserved_contains`, `reserved_affixes` (matched after normalization), `registration_allow = [{did, aliases}]`. `admit(did, alias)` returns `Admission::{Ordinary, Allowlisted}` or `Refusal::{Closed, TooShort, Reserved}` (`REGISTRATION_CLOSED`, `ALIAS_TOO_SHORT`, `ALIAS_RESERVED`). One name per DID per suffix: a second gets `409 DID_HOLDS_NAME`. `GET /v1/challenge?did=&name=` (both optional) binds a challenge as `v0_0_2::PendingChallenge { issued_at, did, name }`; only that DID on that name consumes it, and a mismatch is `CHALLENGE_UNKNOWN` with the challenge left in place. Rotate consumes its challenge last. `RegisterReq.suffix` is optional (`SUFFIX_REQUIRED` when several are served). **Confirmed against #224; re-check if it changes before merge** |

---

## Ownership and order

Each slice is one PR. Where the plan's author (lane R) does not own a file, the owning lane builds
the slice, or agrees through the orchestrator that someone else may.

| Slice | What | Files | Owner | Depends on |
| --- | --- | --- | --- | --- |
| 0 | `jig_core::pow`: the JEP-0008 digest, effort test, solver and proof type; test vectors; a throughput benchmark | `repos/jig-core/src/pow.rs` (new), `repos/jig-core/src/lib.rs`, `repos/jig-spec/jep/vectors/0008/` (new), `repos/jig-core/benches/pow.rs` (new) | orchestrator to assign (proposed: L6, the first consumer) | nothing |
| 1 | Nameserver: `pow` required on register, renew and rotate; effort signed and stated with the challenge; cheap checks first; challenge map bounded | `repos/jig-nameserver/src/v0_0_2.rs`, `v0_0_2_register.rs`, `v0_0_2_rotate_renew.rs`, `v0_0_2_rate_limit.rs`, `config.rs` | L6 | 0; L6's namespace PR (to order checks) |
| 2 | Client and CLI: solve and send `pow` for register, renew and rotate; verify the signed effort; refuse effort above the cap | `repos/jig-client/src/pow.rs` (new), `repos/jig-client/src/lib.rs`, `repos/jig-cli/src/cmd/{init,keys,ns}.rs` | L3 | 0, 1 |
| 3 | Registration pool and adaptive effort per suffix: a stranger cap, an effort controller, length-scaled effort for short names | `repos/jig-nameserver/src/v0_0_2_pow_policy.rs` (new), `v0_0_2_register.rs`, `config.rs` | L6 | 1 |
| 4 | Server admission moves onto `jig_core::pow`: the `admit` action, effort instead of bits, signed effort in the welcome, legacy proofs accepted for one release, adaptive default on (D26) | `repos/jig-core/src/admission_pow.rs`, `repos/jig-server/src/v0_0_2_admission.rs`, `repos/jig-server/src/auth/{admission,state}.rs`, `repos/jig-server/src/handler.rs`, `repos/jig-config/src/v0_0_2_server.rs`, `repos/jig-client/src/admission.rs`, `repos/jig-cli/src/cmd/admission.rs` | orchestrator to assign (L7 if the signed effort rides in the welcome; L3 for config and CLI) | 0, 1 (D26: the nameserver carries PoW first) |
| 5 | Capacity pools at servers: member, invited and stranger shares; the PoW priority queue inside the stranger pool; `post` stamps under load | `repos/jig-server/src/auth/rate.rs`, `repos/jig-server/src/auth/pools.rs` (new), `repos/jig-config/src/v0_0_2_server.rs` | orchestrator to assign (L7 or F, wherever ingest admission sits) | 4 |
| 6 | End-to-end tests: a registration flood, a closed suffix, a squatting run against short names | `repos/integration-tests/tests/h14_registration_pow.rs` (new) | L6 | 1, 2, 3 |
| 7 | Spec and threat register: the proof-of-work and alias sections, AB-01, AB-02 and AB-05 status, operator docs | `repos/jig-spec/src/identity-and-reputation.md`, `repos/jig-spec/src/threat-register.md`, `docs/operations/nameserver-abuse-runbook.md`, `docs/security/nameserver-abuse-economics.md` | L1 for the docs; the implementing lane for the spec rows, in its own PRs | 6 |

Slices 0 and the namespace PR can run in parallel. Then 1, then 2 and 3 in parallel. Ship 1 and 2
in the same release: once `pow` is required, an old CLI cannot register. Slices 4 and 5 can
follow `@jig`'s opening. They are not on its path.

---

## Parameters are configuration

Nothing below is a constant in code. Every value is a config key with a documented default, so an
operator, and later a ruleset (JEP-0009), sets it.

Proposed nameserver keys: two optional tables on each `[[v0_0_2.nameserver.alias_suffixes]]`
entry, beside L6's policy fields (#224). `SuffixConfig` is `deny_unknown_fields`, so task 1
adds `pow: PowPolicy` and task 3 adds `pool: PoolPolicy` to the struct, both
`#[serde(default)]`:

```toml
[[v0_0_2.nameserver.alias_suffixes]]   # L6's fields (#224)
suffix = "jig"
registration = "closed"                # open | closed
single_label_authority = true
min_alias_len = 3
# reserved, reserved_contains, reserved_affixes: L6's defaults
registration_allow = [{ did = "did:jig:z…", aliases = ["dj"] }]

[v0_0_2.nameserver.alias_suffixes.pow] # this plan, task 1
alg = 1                                # JEP-0008 rule 8
min_effort = 1_048_576                 # 2^20; the floor for strangers (rule 19)
max_effort = 268_435_456               # 2^28; the cap, and the client's refusal point
max_solve_secs = 10                    # what max_effort must fit, on the slowest client meant to be served
short_name_len = 5                     # names shorter than this pay the length multiplier
short_name_factor = 4                  # effort × factor^(short_name_len − len)
renew_effort = 1                       # rule 31: renew and rotate by the holder pay the minimum

[v0_0_2.nameserver.alias_suffixes.pool] # task 3: the stranger cap
strangers_per_hour = 60                # admitted stranger registrations per hour; compute cannot raise it (decision 2)
burst = 10
controller = "doubling"                # how effort follows the queue (task 3)
controller_window_secs = 300
queue_len = 20                         # stranger requests held for a token, highest effort first (task 3)
queue_wait_secs = 10                   # longest a held request waits before 503 REGISTRATION_BUSY
```

- **Per suffix.** #224 serves several suffixes per process, so each suffix carries its own
  `pow` and `pool`, and `Suffixes::from_config` validates them at boot (`min_effort ≤
  max_effort`, `max_effort` solvable in `max_solve_secs` on the benchmark from task 0).
  `SuffixPolicy` gains `pow()` and `pool()` accessors; task 3 keeps its controller state per
  suffix.
- **How effort adapts (task 3).** Rule 17 lets the controller be local. The proposed
  `doubling` controller works per window:
  - **Raise:** when admitted stranger registrations reached the pool's cap and requests were
    refused for capacity, double the suggested effort, up to `max_effort`.
  - **Lower:** when the window ran below half the cap, halve the suggested effort, down to
    `min_effort`.
  - **Floor:** registration never drops below `min_effort`, because a registration creates a
    binding (D23).
- **Allowlisted registrations** (`Admission::Allowlisted`, from `registration_allow`) are member
  requests (rule 24). They skip the pool and pay `min_effort`, not the length multiplier (decision
  3). The allowlist is per (DID, exact alias), not per DID, so the effort cannot be
  known until the alias is: see the challenge below.
- **Server admission (task 4).** `[auth.admission] pow_bits` becomes `min_effort` and
  `max_effort`, plus the same controller keys. `pow_bits` stays accepted for one release and
  maps to `min_effort = 2^pow_bits`.

---

## Task 0: `jig_core::pow`

**Files:**
- Create: `repos/jig-core/src/pow.rs`
- Modify: `repos/jig-core/src/lib.rs`
- Create: `repos/jig-spec/jep/vectors/0008/` (one JSON vector per action)
- Create: `repos/jig-core/benches/pow.rs`

What it holds (JEP-0008 rules 6–10):
- `digest(alg, verifier, subject, action, binding, salt, nonce)`, the labelled BLAKE3 hash;
- `meets(digest, effort)`, the rule-7 test, written without overflow as
  `d <= u64::MAX / effort`. `effort` is a `NonZeroU64` (rule 4: effort is at least 1), so
  `meets` cannot divide by zero. A suggested effort of zero means no proof is asked (rule 17):
  the verifier skips the check rather than calling `meets`. Tests: `meets` at effort 1 accepts
  every digest; a zero `effort` in a received proof fails to deserialise (`POW_INVALID`);
- `solve(…, effort) -> nonce`;
- `Proof { alg, effort, nonce, salt_id }`;
- `Action` labels: `admit`, `post`, `kp-request`, `dial`, `ns-register`, `ns-renew`,
  `ns-rotate`.

- [ ] **Step 1: Failing tests.**
  - The vector for each action reproduces its digest.
  - For `effort = 2^20`, `meets` agrees with "20 leading zero bits" on 10^4 random digests.
  - An effort that is not a power of two (3 × 2^18) accepts and refuses at the boundary value.
  - A proof for one verifier, subject, action or binding fails for any other.
  - The nonce is capped at 64 bytes.
- [ ] **Step 2: Implement.** Pure code, no I/O. `solve` is CPU-bound, and its doc says to run it
  off the async executor.
- [ ] **Step 3: Benchmark.**
  - `cargo bench -p jig-core --bench pow` reports digests per second on one core.
  - The PR body records the numbers measured on the reference laptop and the reference potato.
  - GPU throughput is cited from a published BLAKE3 figure or measured by DJ, and marked as
    either.
  - These numbers set `min_effort`, `max_effort` and `max_solve_secs`.
- [ ] **Step 4:** `cargo nextest run -p jig-core pow`;
  `cargo +stable clippy -p jig-core -- -D warnings`.
- [ ] **Step 5:** commit `feat(core): jig_core::pow, JEP-0008's puzzle, vectors and benchmark`.

---

## Task 1: The nameserver requires proof-of-work

**Files:**
- Modify: `repos/jig-nameserver/src/v0_0_2_register.rs`
  - `RegisterReq.pow` becomes `Option<PowProof>`, required when the policy asks for work.
  - `get_challenge` states the effort, signed.
  - `register` runs its cheap checks first.
- Modify: `repos/jig-nameserver/src/v0_0_2_rotate_renew.rs` (the same for renew and rotate)
- Modify: `repos/jig-nameserver/src/v0_0_2.rs` (store the effort promised with each challenge;
  bound the challenge map by count)
- Modify: `repos/jig-nameserver/src/v0_0_2_rate_limit.rs` (limit `GET /v1/challenge` per IP:
  rule 31)
- Modify: `repos/jig-config/src/v0_0_2_server.rs` (`PowPolicy` on `SuffixConfig`, defaults and
  boot validation)
- Modify: `repos/jig-nameserver/src/v0_0_2_policy.rs` (`SuffixPolicy::pow()`, and
  `effort_for(Admission, alias)`; `admit` itself is unchanged)

Wire changes:
- **`GET /v1/challenge?action=register|renew|rotate&did=<did>&name=<alias@suffix>`** returns
  `{challenge, pow: {alg, effort, salt_id, expires_at}, sig}`.
  - `salt_id` is `0` for the empty salt that admission and challenge modes use (rule 13); a
    stamp's `salt_id` is its epoch number, and epochs start at 1. JEP-0008 does not yet name
    the empty-salt id; task 7 adds it to rule 13.
  - #224 already takes `did` and `name` as optional and binds them in `PendingChallenge`.
    Task 1 adds `action` and the promised effort to that record, and makes all three
    required on a suffix whose `pow.min_effort > 0`.
  - The name is needed because the effort depends on it: length scaling (task 3) and the
    per-alias allowlist both need it. The DID is needed because `registration_allow` is keyed
    on (DID, alias). Neither is authenticated here; the proof later has to match them. For
    rotate, the bound DID is the **old** DID, as in #224.
  - For `action=register` the endpoint runs the cheap refusals first, so nobody solves work for
    nothing: `SuffixPolicy::admit` (`REGISTRATION_CLOSED`, `ALIAS_TOO_SHORT`,
    `ALIAS_RESERVED`), `ALIAS_TAKEN` by another DID, and `DID_HOLDS_NAME`. These are hints,
    not authority: `register` repeats every one, since the store can change while a client
    solves.
  - `sig` is a COSE_Sign1 by the nameserver's DID over the deterministic-CBOR map
    `{challenge, action, name, did, alg, effort, salt_id, expires_at}`. This is rule 16's signed
    effort; JEP-0009 rule 1 sets the encoding.
  - The nameserver records `(challenge → action, name, did, effort)`. It checks a proof
    against the effort it promised, not against whatever the controller says when the proof
    arrives, so a client is never refused for an effort rise mid-solve. A challenge used for
    another DID or name is refused `CHALLENGE_UNKNOWN` (#224's behaviour, challenge kept); one
    used for another action gets the same refusal, before any crypto.
  - Today's bare `GET /v1/challenge` keeps working for one release for clients that predate
    task 2; on a suffix whose `pow.min_effort > 0` it can only lead to `428 POW_REQUIRED`.
- **`pow`** on register, renew and rotate is the rule-10 proof `{alg, effort, nonce, salt_id}`,
  with `salt_id = 0`: the salt is empty (rule 13, challenge mode).
- **The binding (rule 11):**
  - register and renew: `naming::proof_hash(action, ns_did, alias, challenge)`;
  - rotate (interim): `Action` has no `Rotate` until lane I's I3. Until then the binding is
    the labelled BLAKE3 of (`domain`, `jig-alias-rotate-pow-v1`), (`ns_did`), (`alias`),
    (`old_did`), (`new_did`), (`challenge`). When I3 adds `Action::Rotate`, it becomes
    `proof_hash(Rotate, …)` like the other two. **JEP-0008 rule 11 needs this interim stated**
    (decision 4).
  - The subject is `did` for register and renew, and `old_did` for rotate.
- **Order of checks in `register`** (rule 10; framing 5.10's "refuse before working"). Steps 1,
  2 and 5–7 are #224's `register` as it stands; this plan inserts 3 and 4 between
  `policy.admit(...)` and `verify_action_proof(...)`, the pre-proof spot L6 asked for, so a
  refusal there leaves the challenge usable:
  1. `validate_local_part`, `requested_suffix`, `parse_name`.
  2. `SuffixPolicy::admit` → `Admission` or `Refusal`. Cheap, no crypto.
  3. The challenge is known, unexpired, and recorded for this action, alias and DID, with a
     promised effort.
  4. **Proof-of-work:** one digest; refuse `POW_INVALID`, or `POW_INSUFFICIENT` when below the
     promised effort. An `Allowlisted` admission was promised `min_effort`.
  5. `verify_action_proof` (proof of control).
  6. `parse_reachability`.
  7. `consume_challenge`; then #224's `ALIAS_TAKEN` and `refuse_second_name`
     (`DID_HOLDS_NAME`), which read the store and so stay after the consume. The challenge
     endpoint's early copies of those two keep honest clients from paying for them.
- **Renew** already verifies before it consumes; PoW goes before `verify_action_proof` there
  too.
- **Rotate** consumes its challenge last on #224 (after both signatures, the holder check and
  `DID_HOLDS_NAME`). PoW goes before the signature checks, so a bad `pow` cannot burn a
  holder's challenge.
- **Refusals:** `428 POW_REQUIRED`, carrying the signed effort as in `get_challenge`;
  `400 POW_INVALID`; `400 POW_INSUFFICIENT`. The points feed task 3's multiplier.
  - A `pow` that fails charges a point to the source IP only. PoW is checked before the
    signature, so the `did` is not yet proven, and charging (alias, DID) would let anyone raise
    another DID's effort by sending bad work in its name.
  - Rule 26's (target, requester) point is charged only for a failure after
    `verify_action_proof` has passed, when the requester is the DID that signed.
- **Challenge map:** cap the number of pending challenges (config, default 100 000). When it is
  full, refuse new challenges with `503 BUSY` rather than evict live ones.

- [ ] **Step 1: Failing tests.** Change `an_arbitrary_pow_field_is_accepted_and_ignored` to expect
  refusal; that is the planned break.
  - Register, renew and rotate without `pow` → 428 with a signed effort that verifies under the
    nameserver's DID.
  - A valid `pow` at the promised effort → 200.
  - A valid `pow` at less than the promised effort → `POW_INSUFFICIENT`, and the challenge is
    still usable.
  - A register `pow` replayed on renew, or for another alias or challenge → `POW_INVALID`.
  - A bad `pow` with a bad signature fails on the `pow`, and no signature check runs (asserted
    with a counter or a mock).
  - A closed suffix: `GET /v1/challenge?action=register` for a DID and alias not in
    `registration_allow` → `REGISTRATION_CLOSED`; the listed (DID, alias) → 200 at
    `min_effort`; the listed DID with another alias → `REGISTRATION_CLOSED`.
  - A reserved alias (including a normalized match, e.g. `4dm1n-x`) and a too-short alias are
    refused at the challenge and at register, before any `pow` is checked.
  - A DID that already holds a name on the suffix → `409 DID_HOLDS_NAME` at the challenge.
  - A challenge issued for alias A, used to register alias B → `CHALLENGE_UNKNOWN`, and no
    signature check runs.
  - Rotate with a bad `pow` → refused, and the challenge is still usable.
  - Two suffixes with different `pow.min_effort` promise different efforts.
  - `GET /v1/challenge` beyond the per-IP limit → 429.
  - With the challenge map at its cap → `503 BUSY`, and existing challenges still work.
- [ ] **Step 2: Implement** in the order of checks above. `PowProof` deserialises strictly
  (`deny_unknown_fields`).
- [ ] **Step 3:** `cargo nextest run -p jig-nameserver`; `--test h6_nameserver_mode --test
  h10_nameserver_binary_surface`. Update their requests to carry `pow` at a test effort
  (`min_effort = 1`).
- [ ] **Step 4:** commit `feat(nameserver): proof-of-work on register, renew and rotate (JEP-0008)`.

---

## Task 2: Client and CLI solve

**Files:**
- Create: `repos/jig-client/src/pow.rs` (fetch and verify the signed effort, solve on
  `spawn_blocking`, build `PowProof`)
- Modify: `repos/jig-client/src/lib.rs`
- Modify: `repos/jig-cli/src/cmd/init.rs` (`build_register_request` gains `pow`),
  `repos/jig-cli/src/cmd/keys.rs` (renew, rotate), `repos/jig-cli/src/cmd/ns.rs`
  (`Nameserver::challenge` takes the action and returns the signed effort)

Behaviour (rules 16 and 20):
- The client verifies the effort's signature against the nameserver DID it learned from the
  suffix delegation (F1). It ignores an unsigned or wrongly signed effort.
- It refuses an effort above its own cap, `2^28` by default and configurable. The message says
  the nameserver is asking more than this client will do.
- It shows progress for solves expected to take more than 2 s, and gives an estimate up front
  from the effort and its measured rate.
- On a 428, `POW_INSUFFICIENT` or `REGISTRATION_BUSY` it fetches a new challenge and retries
  once, bidding `min(max_effort, max(new signed effort, 2 × previous bid))` (rule 20), so the
  retry doubles even when the new challenge states the same effort. Then it stops and says the
  nameserver is under load.

- [ ] **Step 1: Failing tests.**
  - `build_register_request` carries a `pow` that verifies for the register binding.
  - An effort signed by a key other than the delegation's is refused before solving.
  - An effort above the cap is refused with the cap in the message.
  - One retry after a 428, at twice the previous bid when the new challenge states the same
    effort, capped at `max_effort`; then a clear error.
- [ ] **Step 2: Implement.**
- [ ] **Step 3:** `cargo nextest run -p jig-client -p jig-cli`.
- [ ] **Step 4:** commit `feat(cli): solve the nameserver's proof-of-work for register, renew and rotate`.

---

## Task 3: Registration pool, adaptive and length-scaled effort

**Files:**
- Create: `repos/jig-nameserver/src/v0_0_2_pow_policy.rs`
- Modify: `repos/jig-nameserver/src/v0_0_2_register.rs`, `config.rs`

What it does, per suffix (rules 17, 18, 21–24, 26–27):
- **The stranger pool.** A token bucket of `strangers_per_hour`, `burst`. Every `ns-register` by
  a DID that is not allowlisted takes a token when it is about to be admitted, after its
  `pow` verified.
  - **The queue (rule 23).** With no token, a request whose `pow` and signature verified waits
    in a bounded queue served highest effort first, ties in arrival order. Config:
    `queue_len` (default 20) and `queue_wait_secs` (default 10).
  - The next token goes to the head of the queue.
  - When the queue is full, a new request with more effort than the queue's lowest bumps that
    request out; otherwise the new request is refused.
  - A request that is bumped, or that waits `queue_wait_secs` without a token, gets
    `503 REGISTRATION_BUSY`. The refusal carries `Retry-After`, set to the seconds until the
    next token, and the current signed effort.
  - The challenge is consumed only on admission, so a client refused here retries with a fresh
    challenge (task 2).
  - Rate limits apply before the queue (rule 23).
- **The controller** is `doubling` as above, and its input is the queue (rule 17):
  - "at the cap with refusals" means the queue was full during the window;
  - "below half the cap" means the queue stayed empty.
  The suggested effort for each action is recomputed each window and stated in new challenges.
- **Effort for one registration** (rule 18, extended):

  ```
  E = clamp( max(min_effort, suggested)
             × m_length(alias)
             × m_penalty(alias, did)
             × m_standing(did),
             min_effort, max_effort )
  m_length(alias) = short_name_factor ^ max(0, short_name_len − len(alias))
  ```

  - `m_standing` is 1 until JEP-0009 standing exists. `ns-register` is a stranger action, and
    rule 28 gives unknown subjects 1.
  - Two terms go beyond rule 18, and task 7 amends rule 18 for them:
    - `m_length`, from decision 1;
    - the inner `max(min_effort, …)`. Without it an idle controller (`suggested = 0`) would
      price a 3-letter name at the bare floor, the same as a 5-letter one, and decision 1 would
      lapse whenever the server is quiet.
  - Allowlisted registrations skip this formula and pay `min_effort` (decision 3).
- **Penalties** key on (alias, requesting DID) and the IP. Decay doubles per repeat offence
  inside the window (rule 27).
- **Metrics:** admitted and refused registrations per suffix, the suggested effort, and pool
  fill. They feed the runbook and the opening checklist.

- [ ] **Step 1: Failing tests.**
  - With `strangers_per_hour = 2, burst = 2`, a third stranger registration in the hour →
    `REGISTRATION_BUSY`.
  - An allowlisted DID registers while the pool is empty.
  - A 3-letter alias costs `factor^2 ×` a 5-letter one at the same suggested effort, including
    an idle controller (`suggested = 0`).
  - Clamping: with `m_length × m_penalty` large enough, effort stops at `max_effort`.
  - The queue: with no token, a higher-effort request is admitted before a lower one that
    arrived first. With the queue full, a request bidding less than the queue's lowest gets
    `503 REGISTRATION_BUSY` with `Retry-After`. After `queue_wait_secs` without a token → 503.
  - A bad `pow` sent in another DID's name charges only the IP; that DID's effort is
    unchanged.
  - After a window at the cap with refusals, the suggested effort doubles; after a quiet window,
    it halves, never below `min_effort`.
  - Penalty points raise effort for (alias, DID) and leave other DIDs on the same alias
    untouched (no griefing).
- [ ] **Step 2: Implement.**
- [ ] **Step 3:** `cargo nextest run -p jig-nameserver pow_policy`.
- [ ] **Step 4:** commit `feat(nameserver): registration pool, adaptive and length-scaled effort`.

---

## Task 4: Server admission on `jig_core::pow` (D26)

**Files:** as in the slice table.

- `jig_core::admission_pow` becomes a thin wrapper: the `admit` action with an empty salt
  and binding (rule 13).
  - It keeps `jig-admission-pow-v1` verification for one release (JEP-0008, Backwards
    Compatibility). A DID already proven stays proven.
- `/api/v1/admission` accepts `{did, pow: {alg, effort, nonce, salt_id: 0}, sig_b64}`, and the legacy
  `{did, nonce, sig_b64}` for one release.
- The signed welcome (L7) states `{admit: {alg, effort, salt_id, expires_at}}` (rule 15).
  `/.well-known/jig` keeps `admission_pow_bits` for one release as an unsigned hint, then drops
  it.
- **Default on (D26):** the default becomes `unknown_dids = "proof-of-work"` with the
  controller and no floor. Effort is zero when idle, so admission costs nothing until a flood.
  This ships only after task 1 is in a release.

- [ ] **Step 1: Failing tests.**
  - A legacy proof still admits during the transition release.
  - A `jig-pow-v1` `admit` proof admits.
  - With the controller idle, an unknown DID is admitted with no work.
  - Under a simulated flood (the stranger queue above target), the effort rises and an
    unproven DID is asked for work.
  - The welcome's effort verifies under the server DID.
- [ ] **Step 2: Implement.**
- [ ] **Step 3:** `cargo nextest run -p jig-core -p jig-server -p jig-client -p jig-cli`;
  `--test h11_signed_reads`.
- [ ] **Step 4:** commit `feat(server): admission on JEP-0008, adaptive and on by default (D26)`.

---

## Task 5: Capacity pools at servers

Rules 21–23: member, invited and stranger shares of writes, subscriptions and handshakes; the
PoW priority queue in the stranger pool; `post` stamps while it is loaded. Membership is local
policy until JEP-0009 (rule 21): admission `records`, or DIDs seen for `local_member_age`
without a penalty.

- [ ] **Step 1: Failing tests.**
  - A flood from 10^3 fresh DIDs leaves a member's p99 write latency within the configured
    bound (an integration test with a scaled-down share).
  - Unused stranger capacity is lent to members and returned under demand.
  - An `--anon` key is always a stranger.
- [ ] **Steps 2–4** as above. This slice is not on `@jig`'s path.

---

## Task 6: End to end

`repos/integration-tests/tests/h14_registration_pow.rs`:
- **Closed suffix:** register is refused before any work; an allowlisted DID registers.
- **Open suffix, flood:** 200 registrations from 200 fresh DIDs in a minute against
  `strangers_per_hour = 60` admit at most the burst plus the refill, and every admitted request
  carries valid `pow`.
- **Squatting run:** an attempt to register every 3-letter alias from one IP is stopped by the
  per-IP limit. From many DIDs, it is bounded by the pool. The test asserts the bound, not that
  squatting is impossible.
- **Old client:** a request without `pow` gets a clear 428, not a 500.

---

## Task 7: Spec and docs

In the implementing lanes' PRs (spec rows) and L1's (docs), after task 6:
- `identity-and-reputation.md`:
  - replace the old challenge-flow and difficulty sections with JEP-0008's;
  - state the registration pool and the length scaling;
  - drop the `/v1/register` "not yet implemented" status.
- `threat-register.md`:
  - AB-01: work bound to the action, alias, nameserver and challenge;
  - AB-02: the nameserver binding endpoints carry PoW and a capacity cap; server admission
    adaptive;
  - AB-05: unchanged (Open until JEP-0009).
- `docs/operations/nameserver-abuse-runbook.md`:
  - how to close a suffix fast;
  - how to read the pool metrics;
  - how to raise or lower `strangers_per_hour`.
- `jep-0008-proof-of-work.md` amendments, each one line:
  - rule 11: the interim rotate binding (decision 4);
  - rule 13: `salt_id = 0` names the empty salt;
  - rule 18: the per-action floor taken before the multipliers, and a target-dependent
    `m_length` term for name actions;
  - rule 26: a pre-authentication failure charges the address bucket only.
- `docs/security/nameserver-abuse-economics.md`: rewrite against JEP-0008, replacing the
  penalty-point model of the removed prototype.

---

## What opening `@jig` requires

A checklist for DJ to sign off. Every box is checked against `main` and a deployed nameserver
before the `jig` entry's `registration` changes to `"open"`.

- [ ] **Naming is verified end to end.**
  - F1: action-bound proofs, the nameserver over TLS, the `@jig` delegation published and
    built in (#214, #218), clients pinning names.
  - JEP-0004's done-when holds for `@jig`.
- [ ] **L6's namespace policy (#224) is merged.**
  - `jig` entry: `single_label_authority = true`, `min_alias_len = 3`.
  - The reserved lists are reviewed by DJ (`reserved`, `reserved_contains`,
    `reserved_affixes`): protocol words, project and operator names, abuse-prone words.
  - Normalization covers the confusables of every reserved name (case, `-_.`, `0/o`, `1/i/l`,
    `3/e`, `4/a`, `5/s`, `7/t`). Not covered: Unicode confusables, which the local-part
    charset rules out today.
  - `registration_allow` works while closed, and every allowlisted registration is logged.
  - One name per DID per suffix (`DID_HOLDS_NAME`) holds across register and rotate.
- [ ] **Tasks 0–3 and 6 are merged and released together with task 2's CLI.**
  - Every register, renew and rotate carries valid `pow`.
  - The effort is signed.
  - The registration pool caps strangers per hour.
- [ ] **Parameters are set from measurements.**
  - Task 0's benchmark numbers are in the PR.
  - `min_effort` fits `max_solve_secs` on the reference potato.
  - `strangers_per_hour`, `burst` and the short-name factor are set by decisions 1 and 2.
- [ ] **Old clients fail clearly** (task 6), and the release notes say that registration needs
  the new CLI.
- [ ] **Operations.**
  - The pool and effort metrics are scraped.
  - The runbook covers closing the suffix, adjusting the pool, and handling a squatting
    complaint.
  - A squatting-complaint path exists until tribunals do (decision 5: signed, logged operator removal).
- [ ] **Threat register and spec updated** (task 7). The release notes list AB-01 and AB-02 as
  mitigated for the nameserver path.
- [ ] **A staged opening.**
  - Allowlist-only first.
  - Then `open` with a low `strangers_per_hour`, watched for a week.
  - Then the long-run value.

---

## Decisions (DJ, 2026-10-19)

1. **Short names: length-scaled effort, plus a flat reserve below 3 characters.**
   - 3 and 4 characters pay effort × 4^(5 − len): 16× and 4× a 5-character name.
   - 1 and 2 characters are reserved: only a `registration_allow` entry can register them. #224
     already does this, since `min_alias_len = 3` refuses them and the allowlist bypasses the
     minimum length. Task 6 pins it with a test, so a later change to `min_alias_len` cannot
     silently open them.
2. **Pool on `@jig` at opening:** `strangers_per_hour = 60` and `burst = 10` for the first week,
   then a review against the metrics. These are the values in the config sketch above.
3. **Allowlisted registrations pay `min_effort`.** They skip the pool and the length multiplier,
   so every request takes one code path and a leaked entry still costs work.
4. **Rotate before I3: the interim binding.** Use the labelled hash over (`jig-alias-rotate-pow-v1`,
   ns_did, alias, old_did, new_did, challenge), switching to `proof_hash(Rotate, …)` in I3.
   Task 7 adds a one-line amendment to JEP-0008 rule 11.
5. **Squatting before tribunals: signed, logged operator removal.** The nameserver operator
   alone removes a binding, signed and logged, with a published reason. It is a stopgap,
   retired once R6's tribunal can rule on name disputes. Scoped as a follow-up after task 6
   (owner: L6), since it adds an admin endpoint and a log record.
6. **Legacy admission proofs:** `jig-admission-pow-v1` is accepted for exactly one release
   after task 4, then refused.

---

## Done when

- `h14_registration_pow` passes in CI.
- `@jig` can be switched to `open` with every box above checked.
- No nameserver binding endpoint accepts a request without valid, signed-effort proof-of-work.
- Server admission is on by default and free when idle (D26), on the same puzzle.
