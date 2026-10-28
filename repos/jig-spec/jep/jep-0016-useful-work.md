+++
jep = 0016
title = "Useful Work and Auditors"
status = "Draft"
type = "Standards Track"
category = "Security"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-28"
requires = ["0004", "0008", "0009", "0010", "0014"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

Proof-of-work is a toll. It buys admission and queue priority, and never standing (D30).
Standing grows from reports, by time, and from **useful work**: mechanical checks that
established clients do for their ruleset group, each earning a flat credit (D32).

This JEP specifies:

- the three kinds of useful work:
  - log witnessing and checkpoint gossip;
  - evidence validation, the **auditor** role;
  - holding copies and answering retrievability challenges;
- who is eligible, and how a client enrols and opts out;
- **secret, self-selected assignment** from verifiable randomness over the group log, proven
  when the worker submits;
- commit-reveal among redundant workers, escalation when they disagree, and fraud proofs
  against a false verdict;
- flat credit, as ruleset events that the reference rulesets (R2.1) consume;
- who may read an evidence body (D34);
- what is checked where: members check execution in the encrypted tiers, and auditors check
  standing from commitments.

Design record: DJ's decisions D30, D32 and D34 in [`docs/ROADMAP.md`](../../../docs/ROADMAP.md).
The reference rulesets that consume this JEP are R′'s, in R2.1 (D31).

**Draft.** Parameter values are the ruleset's (JEP-0009 rule 3). R2.1 sets their reference
values.

# Motivation

D34 makes standing checkable by anyone: `R = f(ruleset, evidence log, epoch)`, recomputable from
public commitments, with a mismatch as portable proof against the server. Recomputing from
commitments checks the arithmetic. It does not check that a committed record says what its
commitment claims, that a log shows everyone the same history, or that the evidence still exists.
Someone has to look, and the protocol has to make looking cheap, honest and unattractive to
capture.

Three constraints shape the design:

- **Proof-of-work buys no standing** (D30). Hashing that earns standing prices identities
  linearly (AB-05). A client that wants standing faster than time gives it has to contribute
  checks that someone can verify.
- **Auditors are a target.** Whoever reads evidence bodies learns who did what. Whoever decides
  a verdict can be bribed or coerced. So auditors never see content, nobody can choose whose
  trail they audit or know in advance who audits it, several audit each sample, and the role pays
  the same whatever the audit finds and carries no status (D34).
- **Useful work raises detection, not flood capacity** (D32). It makes cheating visible. It does
  not let a server absorb more traffic, and it is not a second admission price.

**Non-goals:**

- the ruleset maths and parameter values (JEP-0009; R2.1);
- tribunals and content-bearing evidence such as franking openings (JEP-0010);
- the proof-of-work puzzle itself (JEP-0008), except D30's constraints in rules 1–3;
- monetary stake or payment of any kind (D31).

# Specification

All signed objects use JEP-0009 rule 1: COSE_Sign1 over deterministic CBOR. "The group" is the
ruleset group whose ruleset the work serves. "The group's nameservers" are its nameservers as
JEP-0009 defines them; after D29 they are a role of `jig-server`.

## 1. Proof-of-work is a toll

1. **Proof-of-work never converts into standing.** No ruleset event, score, pool membership or
   eligibility under this JEP MAY depend on proof-of-work a subject solved, its effort, or how
   often it solved. JEP-0008 rules 21 and 28 already take standing as an input to effort. This
   rule closes the reverse direction.
2. **The puzzle is asymmetric and memory-hard.** The algorithm that replaces `alg = 1` under
   JEP-0008 rule 8 MUST:
   - be memory-hard to solve, so that a GPU or ASIC gains less over a phone than it does on
     BLAKE3;
   - verify in time and memory small enough that verification stays the cheap step (JEP-0008
     rule 10).

   Equi-X is the candidate. The choice is registered by amendment to JEP-0008 after R1's
   measurements.
3. **The verifier checks its own work.** The verifier of a proof is the server, nameserver or
   custodian that asked for it (JEP-0008 rule 1). No other party verifies it on that verifier's
   behalf, and no party MAY present a proof to a third party as evidence of anything.

## 2. Terms

4. A **worker** is a client DID that is enrolled (rule 9) and eligible (rule 8).
5. A **task** is one unit of useful work: one log checkpoint to witness, one evidence sample to
   validate, or one retrievability challenge to answer. It has a `task_id` (rule 13).
6. An **epoch** is the ruleset's epoch, as R2.1 defines it for `f`. The **beacon** of an epoch is
   the hash of the group log's first witnessed checkpoint at or after the epoch's start
   (JEP-0009 rule 33), as for tribunal panels (JEP-0010 rule 20).
7. **Content** is anything a channel's members encrypted, and anything inside a franking opening
   (JEP-0010 rule 8). A block's CID, its signed outer fields, `ingest` records, counters, proofs
   and log records are not content.

## 3. Eligibility, enrolment and opting out

8. A DID is **eligible** in an epoch when all of these hold:
   - it is established under the group's ruleset (JEP-0009 rule 16);
   - it has an enrolment that was included in a witnessed checkpoint before the epoch's beacon
     (rule 9);
   - it has passed a retrievability challenge within the ruleset's `retrievability_window`
     (rule 28), except that a worker's first retrievability task is open to an enrolled,
     established DID without one;
   - it is not opted out (rule 10).

   An `--anon` session key is never eligible (JEP-0009 rule 22).
9. **Enrolment.** A client enrols by sending an `uw-enrol` record to any of the group's
   nameservers:

   ```
   {v, did, ruleset: hash, vrf_key, kinds: [kind], at}
   ```

   - `vrf_key` is an ECVRF-EDWARDS25519-SHA512-TAI public key (RFC 9381 §5.5). It MUST NOT be
     the DID's signing key: the DID key signs the record, and the VRF key is used for nothing
     else.
   - `kinds` lists the kinds of work the client takes: `witness`, `validate` and `retrieve`
     (sections 6–8).
   - The nameserver logs the record (JEP-0009 rule 31). A log leaf about an enrolment carries
     `subject_commit`, not the DID (JEP-0009 rule 32).
   - A new enrolment replaces the old one from the first epoch whose beacon follows its
     inclusion. A worker therefore cannot change its VRF key after it has seen a beacon and
     use the new key against that beacon.
10. **Opting out** is always allowed. An `uw-withdraw` record `{v, did, ruleset: hash, at}`
    ends the enrolment from the next epoch.
    - Opting out, failing to reveal (rule 17) and not taking a task are never ruleset events.
      They earn no credit and cost nothing.
    - A client MUST offer the holder the choice, and MUST NOT enrol a DID without the holder's
      consent.
11. **No status.** The role is not shown anywhere.
    - A client MUST NOT display that a DID is enrolled, has worked, or has audited, except to
      that DID's own holder.
    - No protocol object exposes a worker's history except the logged commitments of rule 18,
      which name no DID.
    - Credit counts as ordinary positive evidence (rule 31). The score cannot tell useful work
      from any other positive event.

## 4. Assignment

12. **Assignment is secret, self-selected and verifiable.** For each task, each eligible worker
    computes, in private:

    ```
    (out, π) = ECVRF_prove(vrf_sk, alpha)
    alpha    = labelled BLAKE3 of ("domain", "jig-uw-assign-v1"), ("beacon", beacon),
               ("task", task_id)
    ```

    The worker is **assigned** when `int(out[0..8]) < ⌊(2^64 − 1) × n / N⌋`, where `n` is the
    ruleset's expected number of workers per task for the task's kind, and `N` is the number of
    eligible workers enrolled for that kind at the beacon. The group's nameservers publish `N`
    per kind as a signed `uw-roster {v, ruleset: hash, epoch, kind, n_eligible}`, which counts
    at JEP-0009 rule 13's threshold. The roster carries no DIDs.
    - Nobody but the worker knows it is assigned until it submits. The beacon is public, but
      `out` needs the worker's VRF secret key.
    - The worker cannot grind: its VRF key was fixed before the beacon (rule 9), and the
      beacon is a witnessed checkpoint (JEP-0009 rule 33). Bias by the log's owner is a
      residual risk (Security Considerations).
    - The number assigned varies around `n`. Rule 19 says what happens when too few submit.
13. **Tasks are derived, not handed out.** Every party computes the epoch's tasks from public
    data, so no one picks a task for a particular worker. Labelled BLAKE3 throughout, with
    domain `jig-uw-task-v1`:
    - **`witness`:** one task per log that the group witnesses (JEP-0009 rule 33), per epoch.
      `task_id` = H(domain, `witness`, log origin, epoch).
    - **`validate`:** the sample is the leaves of each server's and nameserver's log whose
      index `i` satisfies `int(H(domain, beacon, log origin, i)[0..8]) < (2^64 − 1) ×
      sample_rate`. `task_id` = H(domain, `validate`, log origin, i). Only leaves included
      before the beacon are sampled.
    - **`retrieve`:** one task per stored object per epoch (section 8). `task_id` =
      H(domain, `retrieve`, object CID, epoch).
14. **Conflicts.** A worker MUST NOT submit for a task whose subject is itself, or a server or
    nameserver it operates. Skipping a task is never an
    event (rule 10).
15. **Proof at submission.** The worker proves its assignment when it submits (rule 16), by
    sending `π` and its enrolment's CID to the nameserver it submits to.
    - The nameserver MUST verify `π` against the enrolled `vrf_key`, `alpha` and the threshold,
      and MUST refuse a submission that fails.
    - The nameserver logs only a commitment to the proof (rule 18), not `π`.
    - An evidence holder that releases a body to a worker (rule 24) learns the assignment at
      that point. It does not learn the verdict.

## 5. Commit and reveal

16. **Commit.** Within `commit_secs` of the task's start, an assigned worker sends its group's
    nameservers an `uw-commit`:

    ```
    {v, task_id, assign_commit, result_commit}
    assign_commit = labelled BLAKE3 of ("domain", "jig-uw-assign-commit-v1"),
                    ("did", did), ("proof", π), ("nonce", nonce_a)
    result_commit = labelled BLAKE3 of ("domain", "jig-uw-result-commit-v1"),
                    ("task", task_id), ("result", result), ("nonce", nonce_r)
    ```

    `nonce_a` and `nonce_r` are fresh 32-byte random values.
    - The worker sends the `uw-commit`, with `π`, its enrolment's CID and `nonce_a`, over a
      connection authenticated as its DID. The nameserver checks the proof as in rule 15.
    - The nameserver logs the `uw-commit` signed by itself, not by the worker. Nothing in the
      logged record identifies the worker, or links two commits to the same worker.
17. **Reveal.** After `commit_secs`, and within `reveal_secs`, the worker sends `uw-reveal
    {v, task_id, result, nonce_r}`.
    - A reveal without a matching commit, or after `reveal_secs`, is ignored.
    - A worker that does not reveal earns no credit for the task (rule 10).
    - No worker's result is visible to any other worker before every commit for the task has
      closed, so nobody can copy a result or vote with a majority it has seen.
18. **Assignment stays committed.** The group's nameservers log the `uw-commit` with its
    `assign_commit`, and log the accepted outcome (rule 20). They do not log `π` or the DID.
    - `assign_commit` is opened, by the worker or by the nameserver that verified `π`, only in a
      dispute: a fraud proof (rule 21), or a challenge that a submission was not assigned.
    - The nameserver keeps `π` and `nonce_a` for `dispute_retention` (ruleset).
19. **Quorum.** A task's outcome is **accepted** when at least `k` revealed results agree and
    none disagrees.
    - If fewer than `k` reveal, the task carries to the next epoch under a new `task_id` (the
      same derivation with the next epoch's beacon), at most `max_carry` times. After that it
      is logged as `unresolved`.
    - If any revealed result disagrees, the task **escalates** (rule 20).
20. **Escalation.** An escalated task is redrawn with `n_escalate` workers, under
    `alpha` with label `jig-uw-escalate-v1`, excluding everyone who committed in the first
    round.
    - Its outcome is accepted when at least `k_escalate` agree.
    - The accepted outcome is logged as an `uw-result` leaf
      `{v, task_id, kind, outcome, result_commits: [CID], epoch}`.
    - If the escalated round also has a dissent, the task goes to the group's tribunal as an
      evidence-track case (JEP-0010 rule 13), since every result here is deterministic.
21. **Fraud proofs.** A revealed result that contradicts the deterministic recomputation of its
    task is a **fraud proof** against the worker who revealed it. The proof is
    `{task_id, the uw-commit, the uw-reveal, the opened assign_commit, the inputs}`.
    - It is an evidence-track case (JEP-0010 rules 13–15).
    - A verdict that sustains it is reported as `useful-work-fraud` (rule 29).
    - **Being in the minority is not fraud.** Only a result shown false by recomputation is.
      An honest worker whose input was withheld or corrupted reports that (rules 22 and 25),
      which is a result, not a dissent.

## 6. Witnessing and checkpoint gossip

22. A `witness` task's worker:
    1. fetches the log's latest checkpoint from the log's owner and from at least one other
       path: another worker's gossip, or a witness's published cosignature;
    2. checks each checkpoint's signature, and a consistency proof from the last checkpoint it
       holds for that log;
    3. returns the result `{checkpoint, consistent: bool}`.

    Two validly signed checkpoints for one log that are not consistent are a split view. The
    worker MUST send them to the group's tribunal intake (JEP-0010 rule 4) as evidence of
    equivocation (NS-02), whatever the task's outcome.
23. Workers SHOULD gossip checkpoints they hold with their own servers and with other workers
    outside tasks. Gossip outside a task earns no credit.

## 7. Evidence validation (auditors)

24. **What an auditor sees.** A `validate` task's worker is an **auditor**. It fetches the
    sampled leaf's evidence body from any holder: the log's owner, or a `retrieve` worker
    holding a copy (section 8).
    - The holder MUST release the body only to the DID the leaf concerns, or to an auditor that
      proves its assignment to that leaf (rule 15).
    - The body is the leaf's non-content evidence: signed records, `ingest` records, counters,
      proofs, reports and the verdict records that cite content.
    - An auditor never receives content (rule 7). Evidence that is content, such as a franking
      opening, stays with the tribunal that heard it (JEP-0010), and reaches `f` only as that
      tribunal's committed verdict.
25. **What an auditor checks.** The auditor's result is `{valid: bool, reason?}`. It is `valid`
    when all of these hold:
    - the body hashes to the CIDs the leaf commits to;
    - every signature in it verifies, and every record is the kind the leaf claims;
    - the event code the leaf reports is one the evidence supports under the ruleset, with the
      count it supports;
    - recomputing `f` for the leaf's subject and period from the committed inputs gives the
      committed result.

    A body that no holder releases within `commit_secs` is a result too: `{valid: false,
    reason: "withheld"}`.
26. **Execution in the encrypted tiers** is checked by members, not auditors. A server
    executes nothing under an encrypted suite (JEP-0014 rule 25), and the members' clients
    produce receipts that other members re-execute (JEP-0014 rule 34).
    - An auditor checks that the receipts a leaf cites are well-formed and signed. It cannot
      check their outcome, because it cannot read the input.
    - **Stated limit:** a dormant channel, with no member online to re-execute, gets no
      execution check. Receipts there are signed claims and nothing more (OP-07).
    - In `public` channels anyone can re-execute, auditors included.

## 8. Copies and retrievability

27. **What is stored.** A `retrieve` worker holds copies of objects the ruleset names:
    log tiles, public blocks, sealed ciphertext blocks, and evidence bodies encrypted so that
    only the DID they concern and assigned auditors can decrypt them. The scheme for that
    encryption is open question 2. Until it is registered, `retrieve` workers hold only public
    objects and ciphertext.
28. **The challenge.** A `retrieve` task names an object by CID. The worker returns, for
    `retrieve_samples` chunk indices derived from H(`jig-uw-retrieve-v1`, beacon, task_id),
    each chunk with its inclusion proof against the object's CID.
    - The result is `{held: bool}`, and any party can recompute it from the CID.
    - A worker that passes counts as having passed retrievability for rule 8.

## 9. Credit

29. **Ruleset events.** Under JEP-0009 rule 9, the group's nameservers report:
    - `useful-work`, positive, count 1, `ref` = the kind, for each well-formed, on-time reveal,
      **whatever result it revealed and whatever the task's outcome**;
    - `useful-work-fraud`, negative, citing the sustaining verdict (rule 21).

    No event rewards agreeing with the majority, and no bounty rewards finding a fault. A
    worker that reports a split view or a withheld body is credited as for any other result.
30. **Flat credit.** The weight of `useful-work` is the ruleset's `credit[kind]`. It does not
    depend on the result, the subject or the time spent.
31. **Accrual stays gated by time.** Credits count towards positive evidence `r` (JEP-0009
    rule 14), inside `accrual_per_period` (JEP-0009 rule 17). Useful work lets an established
    subject keep or regain standing. It cannot buy standing faster than time allows.
32. **What credit is not.** It is not a payment, a token or a transferable balance. It cannot be
    redeemed, and it does not raise a server's capacity (D32).

## 10. Evidence visibility

33. **Commitments are public.** Log heads, checkpoints, inclusion receipts and every leaf's
    `subject_commit` are readable by anyone (JEP-0009 rules 29–32).
34. **Bodies are not.** An evidence body is readable only by:
    - the DID it concerns;
    - an auditor assigned to it, for the task's duration (rule 24);
    - a tribunal hearing a case that cites it (JEP-0010).

    The log's owner holds its own evidence. It MUST NOT release a body to anyone else.

## 11. Ruleset parameters

35. A ruleset that uses this JEP declares a `useful_work` block in its ruleset document
    (JEP-0009 rule 3):

    | Parameter | Meaning |
    | --- | --- |
    | `kinds` | the kinds the ruleset uses |
    | `n[kind]`, `k[kind]` | expected workers per task, and agreeing reveals needed |
    | `n_escalate`, `k_escalate` | the same, for escalation |
    | `sample_rate` | the fraction of log leaves sampled per epoch for `validate` |
    | `retrieve_samples` | chunks per retrievability challenge |
    | `commit_secs`, `reveal_secs` | the commit and reveal windows |
    | `max_carry` | epochs a task may carry before it is `unresolved` |
    | `retrievability_window` | how recent a passed challenge must be for eligibility |
    | `dispute_retention` | how long a nameserver keeps `π` and `nonce_a` |
    | `credit[kind]` | the flat weight of `useful-work` |
    | `fraud_weight` | the weight of `useful-work-fraud` |

    R2.1 sets the reference values.

# Security Considerations (Zero-Trust)

**Threats addressed:**

- **AB-05, identity farming.** Proof-of-work earns no standing (rule 1). Useful work needs an
  established DID, earns flat credit and is bounded by time-gated accrual (rule 31). Farmed
  identities cannot work until they are established, and cannot earn faster once they are.
- **AB-02, botnets.** A memory-hard puzzle narrows the hardware gap (rule 2). It is still a
  toll, so a botnet that pays it gets only queue priority in the stranger pool.
- **Auditor capture.** An attacker who wants a favourable audit has to corrupt workers it
  cannot identify in advance (rule 12), several of them (rule 19), who commit before they see
  each other's results (rule 17), and whose false result is a fraud proof (rule 21). Nothing in
  the role pays more for any particular result (rules 29–30), so there is nothing to sell.
- **Auditors choosing targets.** Assignment comes from a key fixed before a beacon nobody
  controls (rules 9 and 12), and the sample from the beacon (rule 13).
- **NS-02, equivocation.** Workers witness logs from more than one path, and a split view is
  evidence (rule 22).
- **OP-07, forged receipts.** Members re-execute in the encrypted tiers and anyone can in
  `public` (rule 26). Auditors check that receipts exist and are signed.
- **OP-10.** Standing is recomputable (D34), and this JEP supplies the checks that make the
  recomputation mean something.
- **GV-02.** Workers are weighed per DID only through the k-of-n quorum, and quorum outcomes are
  deterministic checks, not votes on judgement. A party with many established DIDs gets more
  draws, in proportion. Rule 14 excludes self-audit.

**Residual risks:**

- **A holder learns its auditor** when it releases a body (rule 15). It has at most
  `commit_secs` to approach that auditor, and still has to corrupt `k` of them. Fetching from a
  `retrieve` worker's copy instead of the log's owner narrows this, once encrypted copies exist
  (open question 2).
- **A party with many established DIDs** is assigned in proportion to how many it holds. Each
  established DID costs time under JEP-0009 rule 17, and invite budgets bound the rest.
- **Beacon bias.** The owner of the group log chooses which leaves a checkpoint includes, and so
  can try several checkpoints for one that assigns workers it likes. Witnesses bound how long it
  can withhold one. Panels share this risk (JEP-0010 rule 20), and a randomness beacon that no
  log owner influences would close it for both.
- **Dormant encrypted channels** get no execution check (rule 26).
- **Liveness.** A task whose workers do not reveal carries forward and can end `unresolved`
  (rule 19). Unresolved is logged, so the gap is visible.
- **The nameserver that verifies `π`** learns who submitted for a task, at commit time and not
  before. Spreading submissions over the group's nameservers spreads that knowledge.
- **The members of a ruleset group** hold the salts of log leaves (JEP-0009 rule 32), so they can
  tell which DIDs are enrolled. They cannot tell who is assigned to what.

**Privacy:**

- Auditors never see content (rules 7 and 24).
- Public log records name enrolments by `subject_commit` and carry commits without any worker
  identity (rules 9 and 16).
- An `--anon` key is never a worker (rule 8) and is never audited as a DID (JEP-0009 rule 22).
- A worker's history is visible only to its holder (rule 11).

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- Nothing in v0.2 implements useful work. A ruleset without a `useful_work` block runs without
  it, and its standing comes from reports and time alone.
- Rule 1 constrains JEP-0008 and JEP-0009. Neither currently converts proof-of-work into
  standing, so nothing existing changes.

# Reference Implementation

None yet. It follows R2.1's reference rulesets (D31).

# Test Vectors

To be added with the reference implementation:

- an enrolment, a VRF proof and the threshold test, for one assigned and one unassigned worker;
- the task derivation of rule 13 for each kind, from a fixed beacon;
- a commit, a matching reveal, and a reveal whose nonce does not match;
- a quorum, an escalation and a fraud proof;
- a retrievability challenge and its answer.

# LLM Influence

Drafted with an LLM coding assistant from DJ's decisions D30, D32 and D34 and from JEP-0008,
JEP-0009, JEP-0010 and JEP-0014 on `main`, and reviewed by the author.

# Rejected Alternatives

- **Proof-of-work that earns standing.** It prices identities linearly, which AB-05 rules out
  (D30).
- **Public assignment, or assignment by a coordinator.** A public list is a list of whom to
  bribe, and a coordinator chooses who audits whom.
- **Bounties for faults found.** They pay auditors to find faults whether or not they exist.
- **Paying the majority.** It pays auditors to guess what others will say, not to check.
- **Auditors reading content.** It makes the role the most valuable one to capture, and breaks
  the encrypted tiers' promise (JEP-0014).
- **Reusing the DID key as the VRF key.** It uses one key for two schemes, and links every
  commit to a DID in public.

# Open Questions

1. **The epoch.** This JEP takes R2.1's epoch for `f`. If R2.1's epoch is long, `witness`
   tasks may want a shorter cadence of their own.
2. **Encrypted evidence copies.** Which scheme lets a `retrieve` worker hold an evidence body
   that only the DID it concerns and an assigned auditor can decrypt, without the holder
   learning who is assigned?
3. **Separate cap.** Whether `useful-work` credit needs its own cap per period, inside
   `accrual_per_period`.
4. **Re-execution credit.** D32 lists receipt re-execution as useful work. Here it is the
   members' check (rule 26), and it earns no credit: members are known, so their assignment
   cannot be secret, and outsiders cannot re-check an encrypted result. Should members' verified
   re-executions earn `useful-work` credit anyway, and if so, how is a false one proven?

# Copyright

This document is licensed under CC-BY-4.0.
