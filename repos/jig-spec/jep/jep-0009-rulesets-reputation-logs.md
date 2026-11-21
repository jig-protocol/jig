+++
jep = 0009
title = "Rulesets, Reputation and Transparency Logs"
status = "Draft"
type = "Standards Track"
category = "Security"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-18"
requires = ["0002", "0004", "0005", "0008"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

Reputation is one number per subject per ruleset (D21). This JEP specifies:

- the **ruleset document**, how a server declares the ruleset it applies, and how a client
  acknowledges it;
- **reputation reports**: servers report event codes with evidence, and the group's nameservers
  compute the numbers;
- **reference maths** for the number, with a cap on what any one reporter can move;
- **verifiable standing:** the number is a deterministic function of the ruleset, a log and an
  epoch, so anyone holding the evidence recomputes it, and a wrong one is a portable fraud proof
  (rules 35–52);
- **standing that compute cannot buy:** accrual gated by time, and budgeted invites whose inviter
  can be identified only after a human-confirmed verdict;
- **transparency logs** at servers and nameservers, witnessed within a ruleset group;
- when reputation becomes a protocol input (OP-10).

Design record and decisions:
[`docs/superpowers/specs/2026-10-18-reputation-pow-tribunals-framing.md`](../../../docs/superpowers/specs/2026-10-18-reputation-pow-tribunals-framing.md),
sections 6, 7, 8.1, 8.2, 9 and 17. Milestones R2, R3, R4 and R7.

**Draft.** It is held as a draft until DJ approves the framing. Parameter values are reference
defaults, to be measured.

# Motivation

Today a server's reputation is operator-seeded, nothing computes it and nothing reports it. The
nameserver prototype averages its own observations under a tier model that D21 superseded. D23
needs four things:

- servers that report;
- nameservers that compute the net change;
- logs that make equivocation and erasure detectable (NS-02);
- Sybil resistance that holds rather than prices identities linearly (AB-05).

Under the framing's question 2 the target is that **standing is sublinear in compute**: bounded by
group-observed time and by standing already held, so hashing buys none.

Non-goals:

- tribunals, abuse reports and server lists (JEP-0010);
- translating scores between ruleset groups, which comes later (D21);
- discovery (JEP-0003).

# Specification

## Encoding

1. Every signed object in this JEP is a COSE_Sign1 (RFC 9052) over a deterministic-CBOR payload
   (RFC 8949 §4.2.1):
   - `alg` is EdDSA;
   - there is no `kid`: each object's rule says whose key must verify it. A ruleset document is
     signed by one of its `authors`, an `ack` by its `subject`, and a report by its `reporter`;
     a verifier tries those keys;
   - the payload is a map with text keys, and field `v` is the object's version;
   - a verifier MUST refuse a payload that is not in deterministic encoding;
   - a verifier MUST refuse an unknown critical field. A field is critical unless its name begins
     with `x-`.

   The format is lane A's A5, extended by DJ (framing question 9).
2. Content identifiers are BLAKE3 CIDs, as for blocks.

## Rulesets

3. A **ruleset document** is a signed object
   `{v, id, version, authors: [did], maths, epoch, parameters, events, consequences, tribunal,
   useful_work, invites, binding}`.
   - `id` is a stable name.
   - `version` increases with every change. The document's CID is its **hash**.
   - `maths` names the reputation maths by id and version (rule 14).
   - `parameters` holds every value JEP-0008 and this JEP leave to a ruleset: effort bounds, pool
     shares, `established`, accrual caps, invite budgets and decay.
   - `epoch` sets how epochs close (rule 36).
   - `events` maps event codes (rule 9) to weights.
   - `consequences` is the ruleset's recommended table from standing to local action (rule 50).
   - `tribunal` holds JEP-0010's parameters, and `useful_work` JEP-0016's (JEP-0016 rule 35).
     Either is `null` when the ruleset does not use it.
   - Every parameter's unit is fixed by rule 52.
   - `invites` and `binding` declare which optional mechanisms the ruleset uses: invites,
     linked vouching (rule 27), person-binding (rule 28).
4. **Declaration.** A server that applies a ruleset MUST name it in its signed welcome and
   `server-manifest` (JEP-0002) as `{id, version, hash, url}`.
   - In the welcome, it is signed only to a hello that asks (JEP-0002 rule 2, tag 5), so a
     client from before rulesets is answered as it always was. In the manifest log, it rides
     beside the document in the `server-manifest` block, under `server_ruleset` (JEP-0002
     rule 12), for the same reason (DJ, 2026-11-21).
   - `url` is where the document is fetched. A path is on the declaring server, which
     serves it at `GET /api/v1/ruleset/{hash}` by default. A client MUST check that what it
     fetches has the canonical CID `hash` and opens to the declared `id` and `version`.
   - A server applies at most one ruleset per security context. A server MAY apply none.
   - A server that enforces anything other than what it declared has signed evidence against
     itself (OP-02).
5. **Acknowledgement.** Before a server applies a ruleset to a subject, the subject MUST have
   signed an `ack` object `{v, ruleset_hash, server, subject, at}`, where `subject` is the
   subject's DID.
   - The server MUST keep the `ack` and MUST NOT lower the subject's standing under a ruleset
     hash the subject has not acknowledged (GV-03).
   - When the ruleset changes version, the server MUST ask for a new `ack` before applying the new
     version to that subject. The subject's standing carries over unless the new version's
     `maths` differs.
   - A client MUST show the ruleset's id, version and hash before it signs an `ack`.
6. An `--anon` session key never signs an `ack`. It is unknown under every ruleset for its whole
   session (rule 22).

## Reports

7. A server in a ruleset group MUST send its group's nameservers **reports** under the data
   contract between them. A report is a signed object:

   ```
   {v, ruleset: hash, reporter: server DID, seq, prev, period: [from, to],
    entries: [{subject, code, count, evidence: [CID], ref?}]}
   ```

   - `seq` starts at 0 and increases by one per report.
   - `prev` is the CID of the reporter's previous report.
   - The chain of reports is part of the reporter's transparency log (rule 30).
8. A report entry names one subject. A report MUST NOT state or imply that two subjects have the
   same holder.
9. **Event codes, not numbers.** A server reports what happened, as a code the ruleset defines,
   and a count. The ruleset alone maps codes to weights.
   - The reference codes are `good-standing-interval`, `spam-confirmed`, `quota-breach`,
     `invalid-proof`, `signed-contradiction`, `verdict-applied` and `invite-redeemed`.
   - Any code whose weight is negative and above the ruleset's `minor` threshold MUST cite
     evidence. A nameserver MUST treat such an entry without evidence as `minor`.
10. A nameserver MUST treat a report as a claim by its reporter, not a fact. It MUST refuse a
    report with a gap or fork in `seq`/`prev`, and MUST keep both conflicting reports as
    evidence.
11. **Servers carry standing too.** A ruleset MAY define codes about servers, for example quota
    breaches by a peer or fork evidence against a sequencer. Nameservers compute servers'
    standing from them as for any subject.

## Net computation

12. Each of the group's nameservers computes every subject's **net change** per period from the
    reports it holds:
    - each reporter's positive contribution per (subject, period) is capped at
      `per_reporter_cap` evidence units, and its negative contribution at
      `per_reporter_neg_cap`. A lying reporter's reach is bounded, and one evidence-backed
      offence still outweighs a period of good standing;
    - each contribution is weighted by the reporter's own standing under the ruleset, with a
      reporter that has no standing weighted `unknown_reporter_weight` (reference: 0);
    - the subject's own reports about itself are ignored.
13. A net change is **authoritative** when a threshold of the group's nameservers (ruleset
    parameter; reference: a majority of seats, as in JEP-0010) sign the same result. Each
    nameserver logs what it signed (rule 30). Servers apply only authoritative net changes.
14. **Reference maths `jig-beta-v1`.**
    - For each subject, keep positive evidence `r` and negative evidence `s`, each the sum of
      weighted, capped contributions.
    - The score is `(r − s) / (r + s + 2)`.
    - A subject with `r = s = 0` and no reports has **no score**: it is unknown, not zero.
    - Each period, `r` decays by `λ_pos` and `s` by `λ_neg`, both ruleset parameters. Verdict
      penalties (JEP-0010) do not decay until their term ends.
    - Conformance vectors pin the maths. Implementations MUST agree to the last bit given the same
      report set, so the arithmetic is fixed-point. Rule 40 fixes the arithmetic, and a period is
      an epoch (rule 36).
15. A ruleset MAY name other maths by id and version. Global trust propagation that pools scores
    across groups (EigenTrust and similar) MUST NOT be used (D21).

## Standing

16. **Established.** A subject is established under a ruleset when its score is at or above
    `established` and its age is at least `min_age_epochs`. Age is counted in epochs from the
    epoch of the first leaf `f` applied about it (rules 36 and 41), never on any party's clock
    (TM-01).
17. **Accrual is gated by time.** A subject's positive evidence grows by at most
    `accrual_per_period` per period, whatever its activity and however many servers report it.
    Only reports by servers other than the subject count.
18. **No sums across identities.** Nothing under a ruleset adds standing across subjects:
    weights, votes and caps are each per subject.
19. Pool membership (JEP-0008 rule 21) follows standing:
    - established subjects are members;
    - subjects admitted on an invite (rule 23) are invited until established;
    - everyone else is a stranger.
20. **Reputation as a protocol input (OP-10).** From R3, a score that is authoritative under a
    declared and acknowledged ruleset is a protocol input, for pool membership and effort
    scaling (JEP-0008 rules 21 and 28) only.
    - Raw scores an operator seeded stay local policy.
    - The handshake's `reputation` field (JEP-0002) carries the server's own authoritative
      standing under its declared ruleset, with the log checkpoint it was read from.
21. A subject with no score is unknown. No floor applies to an unknown subject (JEP-0008 rule 22).
22. **`--anon` forecloses reputation.** A server MUST NOT report, score or retain standing for an
    `--anon` session key. It is a stranger for its whole session. An `--anon` key can neither
    invite nor be invited.

## Invites

23. An established subject receives `invites_per_period` **invite tokens** per period from a group
    nameserver.
    - Each token is an RSA blind signature (RFC 9474, `RSABSSA-SHA384-PSS-Deterministic`) under
      the group's invite key for the period.
    - The issuing nameserver records only how many tokens it issued to each subject.
    - Redemption is unlinkable to issuance.
    - Once a rate-limited anonymous credential scheme (ARC or ACT) is published as an RFC, a
      ruleset MAY name it instead.
24. **Redemption.** A newcomer presents a token at registration or admission, together with an
    **inviter tag**. The verifier MUST refuse a token already redeemed. The newcomer then:
    - enters the invited pool (JEP-0008 rule 21);
    - starts with `invite_start` positive evidence;
    - is reported `invite-redeemed` by the redeeming server.
25. **The inviter tag** is the inviter's DID, encrypted to the group's **seat threshold key**
    (JEP-0010), with a proof that it encrypts a DID that was issued a token for this period.
    - The tag is bound to the token by the token's message.
    - Nobody can read a tag without the seat threshold.
    - The verifiable-encryption and threshold-decryption scheme is registered by amendment to this
      JEP, and R7 selects it. Until a scheme is registered, invites carry no tag, and a ruleset
      that allows invites MUST set `invites_per_period` low enough to be its only accountability.
26. **Opening a tag** requires a tribunal verdict that a person confirmed (JEP-0010). Each seat
    releases its decryption share only by a person's act at that seat, and the release is
    logged.
    - No automated verdict or provisional measure can open a tag.
    - A seat agent MUST NOT hold a decryption share it can use alone.
    - An opened tag identifies the inviter, who takes the ruleset's inviter penalty and loses its
      budget.
27. **Linked vouching** (soul validation) is OPTIONAL. A ruleset that uses it MUST declare it in
    `binding`. A vouch is a public signed object linking two DIDs.
    - A client MUST warn the holder before signing one.
    - Vouches weigh by the voucher's standing and are capped per voucher.
    - A vouchee's losses propagate to its vouchers by the ruleset's factor.
28. **Person-binding** is OPTIONAL, and only a ruleset that declares it in `binding` may use it.
    The protocol never requires it, and no ruleset at null-sec MAY use it.

## Transparency logs

29. A log is an append-only Merkle tree in the RFC 6962 style:
    - checkpoints are C2SP `tlog-checkpoint` signed notes;
    - it is served as C2SP `tlog-tiles`;
    - witnesses sign C2SP `tlog-cosignature`s;
    - the log's origin line is its owner's DID.
30. **Server logs.** A server in a ruleset group MUST log:
    - every report it sends;
    - every enforcement it applies under the ruleset: penalties, ban decisions and verdicts
      applied;
    - every `ack` it relies on, by CID.

    A server outside any group SHOULD keep one and MAY publish it.
31. **Nameserver logs.** A nameserver MUST log:
    - every attestation, rotation statement and suffix delegation it signs (JEP-0004);
    - every net change it signs (rule 13);
    - every invite-key rotation;
    - JEP-0010's records.
32. **Personal data.** A leaf about a user subject carries
    `subject_commit = H(("domain", "jig-log-subject-v1"), ("salt", salt), ("did", did))` instead
    of the DID, with a fresh 32-byte salt per leaf.
    - The salt goes to the subject and, under the data contract, to the group's members.
    - Leaves about servers and nameservers name their DIDs.
    - No leaf links an `--anon` key to a DID.
33. **Witnessing.** In a ruleset group, every nameserver witnesses every other member's log and
    its servers' logs.
    - A checkpoint counts at the ruleset's `witness_threshold` of cosignatures.
    - A witness MUST refuse to cosign a checkpoint that is not consistent with the last one it
      cosigned for that log.
    - Group time for rules 16 and 17 is the cosigned checkpoint time.
34. **Clients.** For a name under a suffix whose delegation is `contract`-rooted (JEP-0004),
    a client MUST check that the attestation is included in a witnessed checkpoint before it pins
    the name.

## Verifiable standing

This section makes standing checkable by anyone who holds the evidence. It is milestone R2.1. It
binds R3 (rules 7–22) as well: R3's nameservers and R2.4's single server compute the same `f`.

### Epochs

35. **The epoch log.** Every computation under a ruleset reads one log, its **epoch log**:
    - for a server in a ruleset group, the group log (rule 33);
    - for a server outside any group, the server's own log (rule 30).
36. **Epochs are ranges of log positions.** Epoch 0 starts at position 0. Epoch `N + 1` starts at
    the position after epoch `N`'s **closing checkpoint**.
    - The closing checkpoint of epoch `N` is the first checkpoint of the epoch log, counted at the
      ruleset's `witness_threshold` of cosignatures, whose **epoch time** is at least `epoch_secs`
      after that of epoch `N − 1`'s closing checkpoint. For epoch 0, it is measured from the log's
      first checkpoint.
    - A checkpoint's epoch time is the `witness_threshold`-th smallest timestamp among its valid
      cosignatures. A minority of witnesses cannot move it earlier.
    - An epoch never closes inside a window it opened. The closing checkpoint is also at or after
      the end of every commit, reveal and beacon-reveal window that opened in the epoch
      (JEP-0016 rules 16, 17 and 38). A quiet epoch runs long rather than cutting a window
      short, so nobody misses a window because time ran out.
    - `f` never reads a clock. Time enters only as cosignature timestamps already in the log, so
      every recomputation finds the same boundaries.
    - Every period in this JEP, JEP-0008 and JEP-0016 is an epoch.

    Epochs do not close after a fixed number of positions. Anyone who can append leaves would
    then shorten epochs and buy accrual (rule 17) with traffic.

    On a log with no witnesses (`witness_threshold = 0`), the owner's own checkpoint time counts.
    Standing computed there is the owner's own claim, and is local policy only (rule 20).

### The function

37. **Standing is a function.** Under the ruleset with hash `H`, the standing of every subject at
    the end of epoch `N` is

    ```
    R_N = f(H, L_N, R_(N−1)),   R_(−1) = {}
    ```

    where `L_N` is the leaves of epoch `N` in the epoch log, in log order.
    - `f` is the ruleset's `maths` (rule 14).
    - `f` is deterministic. It reads only `H`'s document, `R_(N−1)` and `L_N`. It never reads a
      clock, any state outside the log, or randomness other than the epoch's beacon (JEP-0016
      rule 41).
    - `f` is published as a block (JEP-0006). Its host functions are all on the deterministic
      validator allowlist, so anyone can run the same component and check its receipt (#276). A
      native implementation is allowed when it reproduces the vectors bit for bit.
38. **What `f` reads.** `f` reads only these leaf kinds, and ignores every other kind without
    refusing it:
    - `ack` (rule 5). Until a subject's `ack` for `H` is in the epoch log, `f` ignores every leaf
      about the subject, so no leaf can lower an unacknowledged subject's standing (GV-03);
    - `event`: `{v, ruleset: H, reporter, subject_commit, code, count, covers?, ref?,
      evidence: [CID]}`, one reporter's observation under a code of rule 9. `covers` names the
      epoch a `good-standing-interval` is for (rule 45). In a group, events are the entries of
      reports (rule 7). Outside a group, they are the server's own observations;
    - `verdict` (JEP-0010 rules 21–22), applied as `verdict-applied` with the verdict's penalty;
    - `uw-result` aggregates (JEP-0016 rules 20a and 29);
    - `admit-proof`: `{v, subject_commit, proof: CID, effort}`, logged when a server accepts a
      subject's admission proof of work (JEP-0008 rule 21; rule 49);
    - `fraud-proof` (rule 44).
39. **State.** For each subject, `R` holds
    `{r, s, first_epoch, last_epoch, pinned: [{amount, until_epoch}], applied}`:
    - `r` and `s` are the fixed-point evidence of rule 40;
    - `first_epoch` is the first epoch in which `f` added evidence about the subject, and
      `last_epoch` the latest. A report that weighs nothing, such as one from an unknown reporter
      weighted 0, adds no evidence, creates no state and starts no clock;
    - `pinned` holds verdict penalties that do not decay before their term ends (rule 14);
    - `applied` is a hash chain over the positions of the leaves `f` applied to the subject,
      continued from the previous epoch's `applied`.

    A subject with no state in `R` is unknown (rule 21).
40. **Arithmetic (`jig-beta-v1`).**
    - Evidence and weights are integers in **micro-units**: one unit of evidence is 1 000 000.
    - Fractions (`λ_pos`, `λ_neg`, reporter weights, `credit_cap_per_period`) are integers in
      **parts per million**.
    - All arithmetic is exact integer arithmetic in signed 128-bit. Division rounds towards
      negative infinity. No floating point is used anywhere.
    - For each subject in each epoch, in this order:
      1. **Decay:** `r ← r − ⌊r · λ_pos / 10⁶⌋`, and `s ← s − ⌊s · λ_neg / 10⁶⌋`. Pinned amounts do
         not decay, and leave `pinned` for `s` at `until_epoch`.
      2. **Per reporter:** sum each reporter's `weight(code) × count` for the subject. Cap the
         positive part at `per_reporter_cap` and the negative part at `per_reporter_neg_cap`
         (rule 12). Multiply by
         the reporter's weight, `w = 10⁶` if the reporter was established in `R_(N−1)`, else
         `unknown_reporter_weight`, then divide by 10⁶. Reporter weight comes from the previous
         epoch, so no epoch's result depends on itself. On an epoch log outside any group, the
         log's owner is the only reporter and weighs 10⁶.
      3. **Accrual cap:** `useful-work` credit counts only for a subject established at `N − 1`.
         It keeps or regains standing and never builds it (JEP-0016 rules 8 and 31). Cap it at
         `credit_cap_per_period × accrual_per_period / 10⁶`, then all positive evidence at
         `accrual_per_period` (rule 17). Negative evidence is not capped by accrual.
      4. **Add:** `r ← r + positive`, and `s ← s + negative`.
    - **Score**, in parts per million:
      `score = ⌊(r − s) · 10⁶ / (r + s + 2 · 10⁶)⌋`, so `−10⁶ ≤ score < 10⁶`. The floor reaches
      −10⁶ once `s` exceeds about 2 · 10¹² micro-units, because negative evidence has no accrual
      cap.
41. **Age is counted in epochs:** `age = N − first_epoch + 1`. A subject is established at `N`
    when all of these hold (rule 16):
    - `score ≥ established`;
    - `age ≥ min_age_epochs`;
    - `N − last_epoch < max_idle_epochs`, unless the ruleset sets no `max_idle_epochs`.

    The idle limit stops a key that earned standing once from keeping it while dormant, to be
    used or sold later (AB-07).

### Checkpoints and fraud proofs

42. **Standing checkpoint.** After epoch `N` closes, every party that computes standing under `H`
    (each group nameserver; for its own local standing, a server) logs in its own log a signed
    `standing-checkpoint`:

    ```
    {v, ruleset: H, epoch: N, log: {origin, size, root}, standing_root, prev}
    ```

    - `log` is the epoch log's closing checkpoint for `N`.
    - `standing_root` is the RFC 6962 Merkle root over one **state leaf** per subject,
      `{standing_key, r, s, first_epoch, last_epoch, pinned, applied}`, sorted by
      `standing_key` (rule 47).
    - `prev` is the CID of the signer's checkpoint for `N − 1`.

    Checkpoints are incremental. `R_N` is checkable from `R_(N−1)`'s root and epoch `N`'s leaves
    alone, never from the log's whole history.
43. **Recomputation.** One subject's state at `N` is recomputable from:
    - its state leaf at `N − 1`, with its inclusion proof in the previous `standing_root`;
    - the leaves of epoch `N` about it, each with its opening (rule 32's salt) and its inclusion
      proof in the epoch log;
    - each reporter's state leaf at `N − 1`, for the weights.

    Who recomputes:
    - the subject, which holds its own salts (rule 32) and its `standing_key` opening;
    - auditors assigned by JEP-0016 `validate` tasks, who see bodies only for the task's duration
      (JEP-0016 rules 24 and 34);
    - spot checks by eligible clients past the retrievability gate, sampled by the epoch's beacon
      (JEP-0016 rules 8 and 41). Nobody chooses whose standing to check.
44. **Fraud proofs.** A fraud proof is a signed object
    `{v, against: checkpoint CID, standing_key, kind, proof}` that a verifier checks with no trust
    in its sender:
    - `arithmetic`: the inputs of rule 43 for one subject, and the subject's state leaf in the
      checkpoint, which differs from `f`'s output;
    - `omission`: a leaf about the subject in epoch `N`, with its opening and inclusion proof,
      that `applied` does not list; or an inclusion receipt (rule 45) whose deadline passed with
      the leaf absent;
    - `fabrication`: `applied` lists a position whose leaf is not about the subject, or is not a
      kind `f` reads;
    - `equivocation`: two standing checkpoints by one signer for the same `H` and `N` with
      different roots.

    A valid fraud proof is evidence about its signer's DID (rule 11). An observer logs it as a
    `fraud-proof` leaf in its own epoch log, and `f` applies it as `standing-fraud` under the
    observer's own ruleset. There is no global score: each observer applies the proof under its
    own named ruleset, and no other.

    Withheld data is not fraud. A party that cannot obtain an opening has a withheld-body report
    (JEP-0016 rule 29), not a fraud proof.
45. **Omission and inclusion receipts.** A log owner that accepts a leaf it did not write (a
    report entry, a verdict, a peer's evidence, an `ack`) MUST return a signed inclusion receipt
    `{v, log, leaf: CID, by}`: a promise to include the leaf at or before position `by`, at most
    `receipt_positions` past the log's size when it signed.
    - A receipt and a later checkpoint without the leaf is an `omission` fraud proof.
    - **The owner's duty.** Under a ruleset that defines `good-standing-interval`, the epoch log's
      owner MUST log one `event` with that code, `count = 1` and `covers = N` for each
      acknowledged subject it ingested at least one block from in epoch `N` and logged no
      negative leaf about in `N`.
      - It logs these after `N` closes, during epoch `N + 1`, and never before. Only then does it
        know which checkpoint closed `N` (rule 36) and whether a negative leaf arrived in `N`.
        A whole epoch of grace closes on cosigned time, so appending leaves cannot cut it short.
      - `f` applies a `good-standing-interval` in the epoch it is logged, only when its `covers`
        is the previous epoch, and at most one per subject per covered epoch. Every epoch thus
        receives exactly the previous epoch's intervals, and the accrual cap never clips one.
      - The count is 1 however many blocks the subject wrote, because accrual is capped per
        epoch (rule 17).
    - For what the owner observes itself, the subject holds receipts too: the owner-signed
      `ingest` record of each block it wrote (JEP-0002; JEP-0005 rule 12). An `ingest` record in
      epoch `N`, no negative leaf about the subject in `N`, epoch `N + 1` closed, and no
      `good-standing-interval` with `covers = N` in `N + 1` is an `omission` fraud proof against
      that duty. An owner that could not yet have complied cannot be convicted.
    - Witnessed and gossiped checkpoints (rule 33; JEP-0016 rules 22–23) make a split view
      detectable. Something the owner never received and never signed for is outside what any
      rule can prove.
46. **Encrypted tiers.** Evidence from an encrypted channel enters `f` only as a **committed
    verdict**: a tribunal's verdict on a franked report (JEP-0010), logged with its pseudonymous
    case id, outcome and penalty.
    - `f` reads the verdict. It never reads the report, the franking opening or any plaintext.
    - A public verifier checks `R` from verdict leaves. Whether the verdict was right is the
      tribunal's question (JEP-0010), checked there and not here.
    - Execution inside encrypted tiers is checked by the channel's members, who re-run receipts
      and are not credited for it (JEP-0014 rules 25 and 34; JEP-0016 rule 26). A dormant
      encrypted channel gets no execution check.
    - Zero-knowledge proofs that a verdict follows from its evidence are future work.

### Scope, cost and local policy

47. **Scope (OP-04).** A per-DID standing trail links that DID's activity across epochs. The
    default scope is **per server, unpublished**:
    - `standing_key = H(("domain", "jig-standing-key-v1"), ("log", origin), ("salt", key_salt),
      ("did", did))`, with a 32-byte `key_salt` the computing party draws once per subject;
    - `key_salt` goes to the subject and, for a task's duration, to its assigned auditors. Nobody
      else can find a DID's state leaf;
    - a subject MAY publish its `key_salt` (opt-in publication), and its standing becomes
      readable by anyone who knows its DID;
    - servers and nameservers have no `key_salt`: their `standing_key` is the same hash with an
      empty salt, so anyone can find a reporter's state leaf (rule 43), as rule 32 names them in
      leaves.

    State leaves show the distribution of standing under `H`, never who holds which.
48. **Sybil cost stays an input.** `f` MUST NOT let a subject gain standing from evidence it can
    manufacture cheaply. Under `jig-beta-v1`:
    - accrual is capped per epoch (rule 17);
    - only reporters other than the subject count (rule 17);
    - a reporter's weight comes from its own standing at `N − 1` (rule 40), so a farm of fresh
      reporters weighs `unknown_reporter_weight` (reference: 0);
    - membership by aged proof (rule 49) costs proof of work once, and then time.

    A ruleset that uses linked vouching (rule 27) MUST weight it by the vouching graph:
    - a vouch counts only after the voucher has been established for `vouch_min_epochs`;
    - a voucher's weight is shared across its active vouchees, so vouching for many dilutes each
      vouch;
    - vouched evidence per vouchee is capped at `vouch_cap`;
    - a vouchee's losses propagate to its vouchers (rule 27).
49. **Membership by aged proof.** Under a ruleset that sets `admit_age_epochs`, a subject is a
    member at `N` (JEP-0008 rule 21) when:
    - its `admit-proof` leaf is in the epoch log at least `admit_age_epochs` epochs before `N`.
      A proof logged before the subject's `ack` counts from the `ack`'s epoch (rule 38); and
    - its score is not negative, or it has none.

    This is the verifiable form of a server's proof-age membership today: the proof's position
    and its age in epochs are in the log. An `admit-proof` adds no evidence. It never moves `r`,
    `s`, the score or the age (rule 39), so proof of work never becomes standing (JEP-0016
    rule 1).

    Aged-proof membership can be farmed: one proof per DID, solved in parallel, and one wait
    for all of them. The wait does not grow with the farm. Aged-proof members therefore draw
    from their own sub-share of the member pool (JEP-0008 rule 23's `aged_share`). The bound
    protects established members only. A farm can still fill `aged_share` and crowd out honest
    newcomers who are members by aged proof. Operator `records` stay local policy, outside `R`. A
    server MAY treat a recorded DID as a member. That membership is not part of `R` and is never a
    protocol input (rule 20).
50. **Consequences are local.** `f` outputs the score and whether the subject is established,
    and nothing else. What a server does with them is local policy (JEP-0014 rule 9):
    floors, the effort multiplier within JEP-0008 rule 28's bounds, join roles.
    - The ruleset's `consequences` table is a declared recommendation, shown to the subject
      before its `ack` (rule 5).
    - A server that enforces something other than what it declared has evidence against itself
      (rule 4; OP-02). That is not a fraud proof against `R`.
    - Only "the score of this subject under ruleset `H` at epoch `N`" is verifiable.
51. **Servers' standing.** A server's standing is `R` about the server's DID under each
    observer's own ruleset, computed from the events and fraud proofs in that observer's epoch
    log. No party holds a global score for a server.
52. **Units.** Every parameter that `f` reads (the `standing`, `events` and `useful_work`
    blocks) is an integer in one of these units, which the JEP that names the parameter fixes:
    - evidence and weights: micro-units (rule 40);
    - fractions and scores: parts per million;
    - counts of epochs, of log positions or of items;
    - `epoch_secs`, the only time `f` uses, measured on epoch time (rule 36).

    No such parameter is a float or a wall-clock duration, and a ruleset document that has one
    is invalid. Parameters `f` does not read (`pow`, `pools`, `tribunal`) keep the names and
    units their own JEPs give them.

# Security Considerations (Zero-Trust)

**Threats addressed:**

- **AB-05, identity farming.** Standing is gated by time (rule 17), counted per subject
  (rule 18), and needs reports from servers other than the subject. Compute buys none of it.
- **The insider swarm.** It is bounded three ways:
  - by `k` established identities × `invites_per_period`;
  - by the invited pool's cap;
  - by the first human-confirmed verdict, which opens the tags and burns the inviters
    (rules 23–26).
- **A lying reporter.** Its contribution is capped and weighted by its own standing, and a verdict
  on false reports moves its standing (rules 11–12).
- **NS-02, NS-03.** Witnessed logs refuse split views. Net changes count only at a threshold of
  nameservers (rule 13).
- **GV-03.** A penalty is never applied under an unacknowledged ruleset (rule 5).
- **TM-01.** Age and accrual run in epochs, which close on cosigned time already in the log
  (rule 36). No computation reads a clock.
- **A server that misstates standing.** Anyone holding the evidence recomputes one subject's
  state, and a wrong state, an omitted or fabricated leaf, or two roots for one epoch is a
  portable fraud proof against the signer (rules 42–45).
- **Epoch stuffing.** Epochs close on cosigned time, not on a count of positions, so appending
  leaves does not speed accrual (rule 36).

**Residual risks:**

- **AB-07, aged-key trading.** Standing attaches to a key, and keys can be sold. This is Accepted,
  bounded: by the supply of established keys, and by the first verdict.
- **A patient attacker.** It can age many identities at once, bounded by rule 17 and by needing
  servers other than its own to report them.
- **Before a tag scheme is registered** (rule 25), inviters cannot be identified, and the budget
  is the only bound.
- **Omission of what a log never received.** A leaf nobody handed the owner, and that the owner
  never signed for, cannot be proven missing (rule 45).
- **An unwitnessed log** sets its own epoch time (rule 36). Standing computed there is the
  owner's claim and stays local policy.
- **A late witness.** When a checkpoint has exactly `witness_threshold` cosignatures, the latest
  of them sets its epoch time, so one late witness can delay an epoch's close (rule 36). That only
  slows accrual. It cannot speed it.
- **Verdict correctness** is not checked by `f` (rule 46). It is the tribunal's, until verdicts
  carry zero-knowledge proofs.

**Privacy:**

- The PV-03 carve-out is exactly one: the inviter tag, which opens only under rule 26.
- Reports never link subjects.
- Logs carry subject commitments, not user DIDs.
- State leaves are keyed by a salted `standing_key`, so standing is per server and unpublished
  unless the subject publishes its salt (rule 47).
- `--anon` keys are never reported or logged against a DID.

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- Operator-seeded admission records (`[auth.admission] records`) stay as local policy, and are not
  protocol inputs (rule 20).
- The nameserver prototype's reputation, observation and transparency routes are removed (lane
  L6), not migrated.

# Reference Implementation

None yet. Milestones R2 (rules 3–6, and R2.1's rules 35–52), R3 (rules 7–22), R4 (rules 29–34)
and R7 (rules 23–28).

# Test Vectors

To be added with each milestone:

- a ruleset document, an `ack` and a report, each as CBOR, COSE and the signer's key;
- `jig-beta-v1`: a report set with its net changes, including one capped reporter;
- the four reference rulesets (`jig-reference`, high-sec, community and null-sec), each with an
  epoch-by-epoch trace of `f` over a fixed leaf sequence, its state leaves and its
  `standing_root`;
- one fraud proof of each kind in rule 44, each with the checkpoint it is against;
- a checkpoint, a cosignature, and an inclusion and a consistency proof;
- an invite token issuance and redemption.

# Rejected Alternatives

- **Servers reporting score deltas.** One server could set any number. Event codes leave the
  magnitude to the ruleset.
- **One nameserver computing alone.** That breaks NS-03. Net changes need a threshold.
- **Global trust propagation.** It pools across groups, so an attacker inflates it everywhere at
  once (D21).
- **Social-graph Sybil defences (SybilLimit and similar) as protocol mechanisms.** They depend on
  fast mixing that later measurements dispute, and the graph links identities.
- **A nameserver that sees both inviter and invitee.** It would hold the group's invite graph. The
  threshold tag gives the same accountability with nobody holding the graph.
- **The prototype's hourly Merkle roots over JSON.** They have no inclusion or consistency proofs.
- **Epochs of a fixed number of log positions.** Appending leaves would shorten them and buy
  accrual with traffic (rule 36).
- **A standing key derived from the DID alone.** Anyone who knows a DID could read its standing
  trail on every server (rule 47).
- **Recomputing every subject from the log's start.** It grows without bound. Incremental
  checkpoints keep a check to one epoch (rule 42).

# Copyright

This document is licensed under CC-BY-4.0.
