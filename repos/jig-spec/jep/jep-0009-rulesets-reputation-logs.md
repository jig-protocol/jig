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
   - `kid` is the signer's DID as UTF-8;
   - the payload is a map with text keys, and field `v` is the object's version;
   - a verifier MUST refuse a payload that is not in deterministic encoding;
   - a verifier MUST refuse an unknown critical field. A field is critical unless its name begins
     with `x-`.

   The format is lane A's A5, extended by DJ (framing question 9).
2. Content identifiers are BLAKE3 CIDs, as for blocks.

## Rulesets

3. A **ruleset document** is a signed object
   `{v, id, version, authors: [did], maths, parameters, events, tribunal, invites, binding}`.
   - `id` is a stable name.
   - `version` increases with every change. The document's CID is its **hash**.
   - `maths` names the reputation maths by id and version (rule 14).
   - `parameters` holds every value JEP-0008 and this JEP leave to a ruleset: effort bounds, pool
     shares, `established`, accrual caps, invite budgets and decay.
   - `events` maps event codes (rule 9) to weights.
   - `tribunal` holds JEP-0010's parameters.
   - `invites` and `binding` declare which optional mechanisms the ruleset uses: invites,
     linked vouching (rule 27), person-binding (rule 28).
4. **Declaration.** A server that applies a ruleset MUST name it in its signed welcome and
   `server-manifest` (JEP-0002) as `{id, version, hash, url}`.
   - A server applies at most one ruleset per security context. A server MAY apply none.
   - A server that enforces anything other than what it declared has signed evidence against
     itself (OP-02).
5. **Acknowledgement.** Before a server applies a ruleset to a subject, the subject MUST have
   signed an `ack` object `{v, ruleset_hash, server, at}`.
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
    - each reporter's contribution per (subject, period) is capped at `per_reporter_cap` evidence
      units;
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
      report set, so the arithmetic is fixed-point at the precision the vectors set.
15. A ruleset MAY name other maths by id and version. Global trust propagation that pools scores
    across groups (EigenTrust and similar) MUST NOT be used (D21).

## Standing

16. **Established.** A subject is established under a ruleset when its score is at or above
    `established` and its age is at least `min_age`. Age is measured from the first report about
    it, on the reporting server's clock, as cosigned in the group's log (rule 33; TM-01).
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
- **TM-01.** Age and accrual run on cosigned group time (rule 33).

**Residual risks:**

- **AB-07, aged-key trading.** Standing attaches to a key, and keys can be sold. This is Accepted,
  bounded: by the supply of established keys, and by the first verdict.
- **A patient attacker.** It can age many identities at once, bounded by rule 17 and by needing
  servers other than its own to report them.
- **Before a tag scheme is registered** (rule 25), inviters cannot be identified, and the budget
  is the only bound.

**Privacy:**

- The PV-03 carve-out is exactly one: the inviter tag, which opens only under rule 26.
- Reports never link subjects.
- Logs carry subject commitments, not user DIDs.
- `--anon` keys are never reported or logged against a DID.

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- Operator-seeded admission records (`[auth.admission] records`) stay as local policy, and are not
  protocol inputs (rule 20).
- The nameserver prototype's reputation, observation and transparency routes are removed (lane
  L6), not migrated.

# Reference Implementation

None yet. Milestones R2 (rules 3–6), R3 (rules 7–22), R4 (rules 29–34) and R7 (rules 23–28).

# Test Vectors

To be added with each milestone:

- a ruleset document, an `ack` and a report, each as CBOR, COSE and the signer's key;
- `jig-beta-v1`: a report set with its net changes, including one capped reporter;
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

# Copyright

This document is licensed under CC-BY-4.0.
