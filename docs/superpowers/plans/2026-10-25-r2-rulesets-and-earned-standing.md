# R2: Rulesets and earned standing — Design plan

> **Design only. No code lands from this document.** It proposes slices and lists the decisions
> DJ has to make. Each slice becomes its own implementation plan once DJ has answered.

**Goal:** a server's admission and pool membership rest on standing the subject **earned**, under
rules the subject was shown and agreed to. Today they rest on what the operator typed into
`[auth.admission] records`, or, with R1 task 5a (#318), on how old a DID's admission proof of
work is (`local_member_age_secs`).

**Why now:** this is the weakest part of the "agents at scale" story.
- A server with ten thousand agents cannot list them by hand.
- Proof-of-work age is not standing. A key that did 2^20 hashes a week ago and has spammed every
  day since is a member under `local_member_age_secs`. Nothing the server observes moves it.
- Nothing reaches the subject: it cannot see what rules it is judged by (GV-03).

**Spec:**
- [JEP-0009](../../../repos/jig-spec/jep/jep-0009-rulesets-reputation-logs.md), rules 3–6
  (rulesets, declaration, ack) and 12–22 (net computation, standing). The rule numbers below are
  JEP-0009's.
- [JEP-0010](../../../repos/jig-spec/jep/jep-0010-reports-tribunals-lists.md): only for what a
  penalty is. Tribunals are R6.
- [JEP-0008](../../../repos/jig-spec/jep/jep-0008-proof-of-work.md) rules 21–23 and 28: what
  standing feeds (pools and effort).
- Framing: [reputation, PoW and tribunals](../specs/2026-10-18-reputation-pow-tribunals-framing.md),
  sections 6, 7 and 14.

---

## The naming question first (decision 1)

The framing's milestone table defines **R2** as "rulesets declared and acknowledged". That covers
rules 3–6 and nothing else: the ruleset document, the declaration in the welcome and manifest,
and the subject's `ack`. Under that definition **R2 earns nothing**. Earned standing per JEP-0009
is **R3**: reports, maths, threshold-signed net changes. R3 in turn needs a ruleset **group** of
several nameservers, because a net change is authoritative only at a threshold of them (rule 13,
NS-03), and group time comes from R4's witnessed logs (rules 16, 33).

Today there is one nameserver and no group. Read literally, earned reputation is three
milestones away (R2, R3, R4) and gated on infrastructure that does not exist yet.

**This plan proposes:**
- **R2** as the framing defines it (slices R2.1 to R2.3).
- **A new slice, R2.4: local earned standing.** A server computes standing from its **own**
  observations, under the ruleset it declared and the subject acknowledged, with JEP-0009's maths
  and accrual cap. It feeds the server's own pools and effort only. It is **local policy**, not
  a protocol input: OP-10 and rule 20 still wait for R3.
- R2.4 replaces `local_member_age_secs` and does not replace operator records.

It gives the server an earned signal now. R3 then swaps R2.4's single local reporter for the
group's threshold result, with the same maths and the same ruleset document.

---

## What exists on `main` (checked at `a740fa8`)

| Piece | Where | State |
| --- | --- | --- |
| Admission policy | `repos/jig-server/src/auth/admission.rs` | A pure `admit(did, view, policy)`. `ReputationView { scores: ruleset_key → i64, proven }`. The `ReputationSource` trait is the seam a ledger plugs into |
| Operator records | `SeededRecords`; `[auth.admission] records`, `floors` | Hand-written scores per `ruleset_key`. A floor names its ruleset, and an unknown DID is never compared against it |
| Capacity pools | `repos/jig-server/src/auth/pools.rs` (R1 task 5a, #318, in review) | Member = a record with no negative score, or an admission proof `local_member_age_secs` old. Invited is empty. The rest are strangers |
| Admission effort | `repos/jig-server/src/auth/admission_effort.rs` (R1 task 4b, #325, in review) | The rule-17 controller; `m_standing` is 1 for everyone |
| Admission proofs | `admission_proofs (did, bits, proven_at)` in `jig-pipeline/src/persist.rs` | The only per-DID history the server keeps |
| Welcome | `WelcomeStatement` in `jig-pipeline/src/handshake.rs` | Has `reputation: Reputation`, still the v0.1 `null` placeholder. Has `manifest: Option<ManifestRef>` and `admit: Option<PowOffer>` |
| Server manifest | `repos/jig-server/src/v0_0_2_manifest_log.rs` | A signed `server-manifest` block, republished when what the server advertises changes |
| Encoding | `jig_core::{cose, dcbor}` | COSE_Sign1 over deterministic CBOR, as rule 1 asks |
| Penalties at the server | none | The server records no offence against a DID. Rate-limit refusals are logged, not kept |

---

## Slices

Each slice is one PR. Owners are proposals for the orchestrator.

| Slice | What | Files (proposed) | Owner | Depends on |
| --- | --- | --- | --- | --- |
| R2.1 | The ruleset document: type, COSE/dCBOR encoding, validation, a hash; the reference ruleset `jig-reference` v1; vectors | `repos/jig-core/src/ruleset.rs` (new), `repos/jig-spec/jep/vectors/0009/` (new) | R′ | nothing |
| R2.2 | Declaration: the server loads a ruleset document from config, names `{id, version, hash, url}` in its signed welcome and its `server-manifest`, and serves the document | `jig-pipeline/src/handshake.rs` (`WelcomeStatement`), `jig-server/src/v0_0_2_manifest_log.rs`, `jig-config` `[ruleset]` | L7 (welcome), R′ (config) | R2.1 |
| R2.3 | The `ack`: the client shows the ruleset and signs `{v, ruleset_hash, server, at}`; the server keeps it and refuses to apply a penalty under an unacknowledged hash (GV-03) | `jig-core/src/ruleset.rs`, `jig-client`, `jig-cli`, `jig-server/src/auth/` | L3 (client), R′ (server) | R2.2 |
| R2.4 | Local earned standing: the server observes, keeps `r` and `s` per acknowledged subject, computes `jig-beta-v1` with the accrual cap, and feeds pools and effort from it | `jig-server/src/auth/standing.rs` (new), `jig-pipeline/src/persist.rs` (a table), `auth/state.rs` | R′ | R2.1, R2.3 |
| R2.5 | Spec and docs: JEP-0009 amendments, threat register (AB-05 status), the operator guide | `jig-spec`, `docs/` | R′ / L1 | R2.4 |

R2.1 can start at once. R2.2 and R2.3 need L7's welcome. R2.4 can be built against R2.1 and a
stub `ack` store in parallel with R2.3, but must not merge before it: standing applied without
an `ack` breaks rule 5.

---

## R2.1: the ruleset document

Rule 3's fields, with a schema for `parameters` fixed for the reference maths:

```
{ v: 1,
  id: "jig-reference", version: 1,
  authors: [did],
  maths: { id: "jig-beta-v1", version: 1 },
  parameters: {
    pow:      { admit: {min_effort, max_effort, max_solve_secs}, post: {...} },  // JEP-0008 rule 19
    pools:    { stranger_share_pct: 20, invited_share_pct: 10 },                // rule 23
    standing: { established, min_age_secs, accrual_per_period, period_secs,
                lambda_pos, lambda_neg, per_reporter_cap, minor },
    penalty:  { max_penalty_multiplier, decay_secs, offence_window_secs, max_decay_secs },
    invites:  { invites_per_period: 0 }                                          // R7
  },
  events:  { "good-standing-interval": +1, "quota-breach": -1, "invalid-proof": -1,
             "spam-confirmed": -4, "signed-contradiction": -8, "verdict-applied": 0,
             "invite-redeemed": 0 },
  tribunal: null, invites: false, binding: [] }
```

- The `hash` is the CID of the signed document (rule 3).
- Unknown critical fields are refused (rule 1); `x-` fields are carried and ignored.
- Every number is an integer or a fixed-point decimal at the precision the vectors set (rule 14).
  No floats in the document.
- **Server config refers to the document; it does not repeat it.** When a ruleset is declared,
  `[auth.pools]` shares and admission effort bounds come from `parameters`, and boot refuses a
  config that sets both (decision 6).

Tests: round trip; a non-deterministic encoding refused; an unknown critical field refused; the
vectors reproduce the hash.

## R2.2: declaration

- `[ruleset] path = "…"` in the server config: a signed ruleset document on disk.
- The welcome names `{id, version, hash, url}` (rule 4). The field rides on the welcome statement
  beside `reputation`, which stays `null` until R3 gives it the server's own authoritative
  standing (rule 20).
  - A new field changes the welcome's signed bytes (`WelcomeStatement::canonical_bytes`), so old
    clients would fail to verify it. It needs a welcome version bump, or a separately signed
    object beside the welcome. R1 task 5b's stamp offer raises the same question: decide once
    (decision 10).
- The `server-manifest` names the same `{id, version, hash, url}`. The manifest log already
  republishes on a change.
- `GET /api/v1/ruleset/{hash}` serves the document. `url` points there by default.
- A server with no `[ruleset]` declares none (rule 4 allows it). It then keeps today's behaviour:
  operator records and `local_member_age_secs`.

Tests: the welcome's ruleset verifies under the server DID; a client that reads the welcome can
fetch the document by `url`, check its CID against `hash`, and refuse a mismatch.

## R2.3: the `ack`

- The client fetches the document, shows `id`, `version` and `hash` (rule 5), and signs
  `{v, ruleset_hash, server, at}` with the DID's key.
- `POST /api/v1/ruleset/ack` stores it (`ruleset_acks (did, ruleset_hash, at, cose)`).
- **GV-03 in code.** Every place that lowers standing or applies a penalty takes the subject's
  `ack` for the declared hash as an argument. Without one it cannot be called, so the server
  cannot penalise under an unacknowledged ruleset by forgetting a check.
- **No `ack` is not a refusal.** A subject that has not acknowledged is unknown under the ruleset:
  a stranger, admitted as strangers are. It gains no standing and is never penalised under the
  ruleset. Bans and rate limits are local policy and still apply.
- A version change asks for a new `ack`. Standing carries over unless `maths` changed (rule 5).
- An `--anon` key never signs one (rule 6). The CLI refuses to.

Tests (the framing's R2 exit criterion):
- A client shows the ruleset before acting.
- A penalty against a subject with no `ack` for the declared hash is refused.
- After a version bump, the old `ack` no longer applies.

## R2.4: local earned standing

The server is its own and only reporter. It feeds itself events, never a nameserver.

- **Events observed (per subject, per `period_secs`):**
  - `good-standing-interval`: the subject wrote at least once in the period, and drew no negative
    event. The cap is one per period (rule 17), whatever the activity;
  - `quota-breach`: refused by its pool or its DID rate more than `n` times in the period;
  - `invalid-proof`: a proof of work, a signature or a stamp that did not verify, **after** the
    subject's signature verified (so it cannot be charged to a victim's DID; JEP-0008 rule 26);
  - `spam-confirmed`, `signed-contradiction`: only from an operator action, signed and logged,
    until R6 (as R1's decision 5 does for names).
- **Maths:** `jig-beta-v1` (rule 14), with `r` and `s` per subject. Decay per period. The score
  is `(r − s) / (r + s + 2)`. With no events the subject has no score (unknown).
- **Established** (rule 16): score ≥ `established`, and age ≥ `min_age_secs`. Age counts from the
  first event about the subject **on this server's clock**: there is no group time yet
  (decision 4).
- **What it feeds:** pool membership (JEP-0009 rule 19: established subjects are members) and
  `m_standing` in effort (JEP-0008 rule 28). Nothing else: no floors and no admission refusal
  (rule 21: no floor applies to an unknown subject; decision 5).
- **It replaces `local_member_age_secs`**, which becomes a no-op on a server that declares a
  ruleset. Operator records stay as local policy (JEP-0009, Backwards Compatibility), and stay
  members (decision 7).
- **Storage:** `standing (did, ruleset_hash, r, s, first_seen, last_period)`, fixed-point, one row
  per acknowledged subject. Bounded by the subjects that acked. A stranger with no `ack` costs no
  row.
- **Clock:** injected everywhere, as in `pools.rs`. Tests drive periods with no wall-clock sleep.

Tests:
- A subject that writes every period with no offence becomes established after `min_age_secs`
  and no sooner, however much it writes.
- 10^3 subjects created at once are all established at the same moment, and none sooner. Compute
  does not buy it. This is the property the plan can prove locally; see the attacks below for
  what it does not prove.
- A `quota-breach` period lowers the score. A subject below `established` is moved back to the
  stranger pool.
- A subject with no `ack` never accrues and is never penalised.
- Decay: a subject that goes quiet loses standing at `lambda_pos`.

### What R2.4 does not buy (say this in the PR, the docs and the threat register)

- **A patient farm on one server.** `N` identities that each write once per period for
  `min_age_secs` become `N` members. Accrual is gated by time, not by identity count. That is the
  same bound as `local_member_age_secs`, with one gain: a member that misbehaves loses membership.
  JEP-0009's answer to the farm is reports from **other** servers (rule 17's "only reports by
  servers other than the subject") and the invite budget (R7). Neither exists on one server.
- **A server's own word.** Its standing is unverifiable by anyone else, so it is never a protocol
  input (rule 20) and never goes in the handshake's `reputation` field.
- **The member pool is shared.** A farm of members dilutes real members' share. R2.4 should cap
  the members that a single address range brings in (decision 8).

---

## Decisions for DJ

1. **What is R2?**
   - (a) The framing's R2 only (declare and ack). Earned standing waits for R3 and a group.
   - (b) **Recommended:** the framing's R2 plus R2.4, local earned standing as a stepping stone to
     R3.
   - (c) Skip to R3 and stand up a two-nameserver group for `@jig` first.
2. **Does an `ack` gate admission?** Recommended: no. A subject without an `ack` is a stranger,
   never refused for it. Refusing would make the ruleset a click-through wall and would lock out
   every client that predates R2.3.
3. **The reference ruleset's numbers:** `established`, `min_age_secs`, `accrual_per_period`,
   `period_secs`, `lambda_pos` and `lambda_neg`. Proposed starting values: a day per period; 30
   periods to established; a 90-day half-life for `r` (framing 7.2) and 30 days for minor
   negatives. They are to be tuned against R1's pool metrics.
4. **Local clock for age (R2.4).** TM-01 says the server's own clock is not group time. R2.4
   uses it anyway, because the standing is the server's own and is used only by the server.
   Recommended: accept, and state it in the doc comment and the threat register.
5. **Standing feeds pools and effort only, not floors.** Recommended: yes, as rule 20 says for
   R3. A floor on R2.4's local standing would refuse subjects on unverified local evidence.
6. **One source for parameters.** When a server declares a ruleset, `[auth.pools]` shares and
   the admission effort bounds come from the document, and config that also sets them refuses
   to boot. Recommended: yes. Otherwise the server enforces something other than what it
   declared (rule 4).
7. **Operator records stay members.** Recommended: yes, and logged as operator assertions, so an
   R4 log can show them. Removing them would break every server that uses them today.
8. **A per-address cap on promotions** to the member pool (R2.4): at most `k` new members per /24
   (IPv4) or /48 (IPv6) per period. It bounds a farm behind one network, and costs a
   shared-address population (a campus, a carrier NAT). Recommended: yes, off by default, with
   the knob in the ruleset's `parameters`.
9. **Who signs the reference ruleset?** The project's DID (as for the `@jig` delegation), or each
   operator re-signing their own copy. Recommended: the project's DID signs `jig-reference`, and
   an operator who changes anything publishes their own `id`.

10. **How the welcome grows.** A welcome `v: 2` that carries the ruleset (and 5b's stamp offer),
    or separately signed objects beside a `v: 1` welcome. Recommended: a `v: 2` for the ruleset,
    which changes rarely and belongs in what the server signs at the handshake; a separate
    object for the stamp offer, which rotates every epoch.

---

## Done when

- A client can show which ruleset a server applies before acting, and acknowledges it.
- A penalty under an unacknowledged ruleset is refused in tests (GV-03).
- On a server that declares a ruleset, pool membership comes from standing the subject earned on
  that server under it, gated by time, and no longer from proof-of-work age.
- The threat register states what R2.4 does not close (the patient farm) and why R3 and R7 do.
