+++
jep = 0010
title = "Abuse Reports, Tribunals and Server Lists"
status = "Draft"
type = "Standards Track"
category = "Security"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-18"
requires = ["0001", "0004", "0005", "0009"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

A ruleset group's nameservers hold its tribunals (D23). This JEP specifies:

- **abuse reports**, including from encrypted channels. Every encrypted message is franked: a
  commitment in the author-signed, sequenced block, with its key inside the ciphertext. A
  participant opens one message's commitment, and the tribunal verifies authorship in that
  channel without any other access (D22, AB-06);
- **tribunals that are automated first.** Each operator holds one seat, and each seat runs an
  agent:
  - an **evidence track** of deterministic adjudication, whose verdicts stand at a threshold of
    seat agents;
  - a **judgement track**, where agents may only apply provisional, expiring measures until
    people confirm them;
- human **panels** for confirmation and appeal;
- **server lists:** who may list a server as abandoned, compromised or abusive, on what evidence,
  and how a listing is appealed or cleared (lane F's F5).

Design record and decisions:
[`docs/superpowers/specs/2026-10-18-reputation-pow-tribunals-framing.md`](../../../docs/superpowers/specs/2026-10-18-reputation-pow-tribunals-framing.md),
sections 8.3–8.5, 10, 11 and 17. Milestones R5, R6 and R8.

**Draft.** It is held as a draft until DJ approves the framing.

# Motivation

Without a way to judge, shared penalties are either arbitrary or absent. Abuse in encrypted
channels has to be provable without a backdoor (D22), and that proof has to work across suites.
Tribunals must answer a concerted attack in minutes: operators cannot adjudicate full time
(framing question 8). And a server list that one nameserver controls would be the veto D19
forbids.

Non-goals:

- reputation maths and logs (JEP-0009);
- PoW (JEP-0008);
- recognising verdicts across ruleset groups, which is voluntary and unspecified.

# Specification

All signed objects use JEP-0009 rule 1: COSE_Sign1 over deterministic CBOR. Every record named
here is appended to the issuing nameserver's log (JEP-0009 rule 31).

## Seats

1. A **seat** belongs to one operator that the group's data contract has admitted. A new operator
   is admitted by a threshold of existing seats (ruleset parameter `seat_admission_threshold`).
   - An operator holds exactly one seat, however many nameservers it runs. It MUST declare all of
     them under that seat.
   - Undeclared common control, once shown by evidence, is sanctionable under the ruleset.
2. Each seat holds:
   - a **seat key**, which signs its records;
   - a share of the group's **seat threshold key**, used only for inviter tags (JEP-0009
     rule 25);
   - a **seat agent**: software that runs the ruleset's adjudication and signs its outputs with
     the seat key.
3. A seat agent MUST NOT hold the threshold share in a form it can use without a person's act at
   that seat (JEP-0009 rule 26).

## Abuse reports

4. A **report** is a signed object
   `{v, reporter, ruleset: hash, channel_id?, items: [item], context: [seq range], statement}`,
   sent to the group's tribunal intake at any of its nameservers.
   - It goes to the tribunal, never by default to the channel's owner, who may be the subject.
   - The reporter MUST be a participant in what it reports. A report about a server MAY come from
     any party that holds the evidence.
5. An item is one of:
   - a block, by CID with its bytes;
   - signed artefacts: two conflicting `ingest` records, attestations, handshake answers or
     reports;
   - a **franked message**, opened as in rule 8.
6. **Franking.** Every content message on an encrypted channel is franked. For each message, the
   sender's client:
   1. picks a fresh, uniformly random 32-byte **franking key** `k_f`;
   2. computes the **franking tag** `c` as the labelled BLAKE3 hash (JEP-0004 rule 8) of:
      - (`domain`, `jig-frank-v1`);
      - (`k_f`);
      - (`channel_id`);
      - (`sender`, the sender's DID or session key);
      - (`epoch`, as decimal ASCII);
      - (`body`, the plaintext body);
      - (`count`, the number of attachments);
      - one (`attachment`, the BLAKE3 hash of the attachment's plaintext) part per attachment,
        in order;
   3. puts `k_f` inside the encrypted plaintext, beside the body and the attachment references;
   4. puts `c` in the author-signed outer block, as the field `frank`.

   The owner's `ingest` record then sequences a block that carries `c`. A sender MUST NOT reuse
   `k_f`.
7. **The recipient's check.** After decrypting, a client MUST recompute `c` from the decrypted
   body, the attachments, `k_f`, the channel, the sender and the epoch.
   - If `c` does not match the block's `frank`, or `frank` is missing on an encrypted content
     block, the client MUST NOT display the message as valid, and MUST mark it as unverifiable.
   - A client MUST NOT display an attachment whose plaintext hash differs from the one `c`
     covers.

   This stops a sender from making a message unreportable.
8. **The report item.** For a franked message, the item is:
   - the author-signed block;
   - the owner's signed `ingest` record for it (JEP-0005 rule 12);
   - the plaintext body and attachments;
   - `k_f`.

   A tribunal accepts the item only when all of these hold:
   1. the block's author signature verifies under the accused's DID or session key;
   2. the `ingest` record verifies under the channel's sequencer of record, and names that
      block's CID;
   3. `c` recomputed from the disclosure equals the block's `frank`.

   The disclosure reveals nothing about any other message.
8a. **Suites.** Franking sits above the encryption suite. Every suite JEP MUST state that the
    suite delivers the plaintext, `k_f` included, unchanged to every member. A ruleset group that
    holds tribunals MUST NOT admit a suite that does not. The requirement belongs in JEP-0001, and
    lane S carries it.
9. **Context.** A report MAY name `seq` ranges around the reported messages.
   - The tribunal MAY ask the accused and other members to disclose their own messages in that
     range, by opening their franking tags.
   - A refusal to disclose is recorded, not inferred against anyone.
   - Several members' reports of one incident merge into one case.
10. A report about an `--anon` sender attributes to its session key only. Nothing in a report or a
    case links a session key to a DID.

## Cases

11. A case opens by a `case-open` record `{v, case_id, track, subject, ruleset: hash, trigger,
    evidence: [CID]}` signed by the seat that opened it.
    - `trigger` is either `automatic`, naming the rule that fired, or `report`, citing the reports.
    - Reports weigh by their reporters' standing (JEP-0009 rule 12). Reports from unknown subjects
      weigh zero and cannot open a case alone.
12. The subject is notified through its reachability record or custodian mailbox (JEP-0004
    rule 21), and MAY answer with a `case-response` within `response_window` (ruleset).
13. **Track.**
    - A case is on the **evidence track** when its question is decided by machine-checkable
      evidence: forks, equivocation, quota breaches, invalid proofs, flood stamps, or a signed
      contradiction of a signed answer.
    - Every other case, harassment and other content cases included, is on the **judgement
      track**.
    - The ruleset's adjudication decides which track a case is on.

## The evidence track

14. The ruleset names an **adjudication**: a deterministic function from (case, evidence, ruleset
    parameters) to an outcome. It is published by CID, with conformance vectors.
    - Until the v0.3 block ABI (JEP-0006) exists, the reference adjudication is native code pinned
      by version and vectors.
    - After that, it is a signed block that every seat agent runs.
15. Every seat agent runs the adjudication on the case and signs its output.
    - The outcome is a **verdict** once `evidence_threshold` seat agents (ruleset parameter;
      reference: a majority of seats) have signed the same output.
    - A seat whose agent signs a different output from the threshold is itself the subject of an
      automatic case.
16. An evidence-track verdict MAY apply the ruleset's full penalty range. It MUST NOT open an
    inviter tag (rule 25).

## The judgement track

17. On a judgement-track case, a seat agent MAY apply only **provisional measures**, and only the
    kinds and bounds the ruleset lists:
    - throttling;
    - demotion to the stranger pool (JEP-0008);
    - suspending the subject's invite budget.

    A measure applies when `provisional_threshold` seat agents sign it.
18. Every provisional measure:
    - MUST be reversible;
    - MUST expire after `provisional_ttl`, unless a human panel confirms it;
    - MUST NOT be permanent;
    - MUST NOT open an inviter tag.
19. A human **panel** confirms, modifies or lets the measures lapse, and decides the case.

## Panels and verdicts

20. A panel is drawn by verifiable randomness from the seats not involved in the case.
    - The seed is the hash of the group log's witnessed checkpoint at case opening (JEP-0009
      rule 33) and the `case_id`.
    - The size and the majority needed are ruleset parameters (reference: 5 seats, 4 to sustain).
    - Each seat on a panel acts through a person.
21. A **verdict** record is `{v, case_id, outcome, penalty?, measures?, term?, evidence: [CID],
    signers: [seat]}`, signed by every seat that made it.
    - `outcome` is one of `sustain`, `modify`, `overturn`, `dismiss` or `escalate`.
    - A verdict that cites no evidence is void.
22. **Enforcement.** A verdict's penalty becomes an event (`verdict-applied`) in the group's net
    computation (JEP-0009 rules 12–14). The group's servers apply it under the ruleset.
    - Nothing binds outside the group.
    - Other groups MAY read the log, and MAY recognise or ignore the verdict.
23. **Appeal.** A subject MAY appeal a verdict once, by an `appeal` record within
    `appeal_window`.
    - A panel drawn from seats that sat on neither the case nor its first panel hears it.
    - An appeal suspends only listings (rule 31), nothing else.
24. **Limits.**
    - No tribunal record, verdict or appeal can link an `--anon` session key to a DID.
    - No penalty applies under a ruleset the subject did not acknowledge (JEP-0009 rule 5).
    - Defederating a server or nameserver needs a supermajority (ruleset parameter) and published
      evidence.
25. **Opening an inviter tag.** Only a judgement-track verdict, or an appeal verdict, whose
    outcome a human panel decided can authorise opening the tags of named invitees.
    - Each seat's share is then released by a person at that seat, as a signed `share-release`
      record.
    - The tag opens at the seat threshold.

## Server lists

26. A **listing** is a signed object `{v, server_did, class, basis, evidence: [CID], case_id?,
    listed_at, expires_at}`.
    - `class` is one of `abandoned`, `compromised` or `abusive`.
    - `basis` is either `provisional` or `verdict`.
    - Lane F fixes the list format and two rules: a list is advisory, and it never moves or unseats
      the sequencer an owner names (JEP-0005 rule 14b). This section fixes who may list, on what
      evidence, and how a listing ends.
27. **Who may list.**
    - Any nameserver MAY publish listings. They are its own claims.
    - Inside a ruleset group, servers act only on listings with these bases:

      | Basis | Issued by | Effect in the group | Expiry |
      | --- | --- | --- | --- |
      | `provisional` | any one group nameserver, which MUST open a case at the same time | servers MAY refuse new shares and contract offers involving the server | `provisional_listing_ttl` (reference 72 h), unless a verdict confirms it |
      | `verdict` | the group's tribunal | servers apply the ruleset's response: refuse new shares, warn members | the verdict's term |

    - Outside its group, a listing is information only.
28. **Evidence by class.** A listing MUST cite evidence of its class:
    - `compromised`:
      - two conflicting `ingest` records under one sequencer key;
      - two conflicting attestations from one nameserver;
      - a signed handshake answer contradicted by signed behaviour;
      - or the server's own signed key-compromise statement.
    - `abandoned`:
      - signed liveness-probe failures from at least `k` seats over at least `T` (ruleset;
        reference 3 seats and 14 days), on the observers' clocks;
      - an expired DID-bound TLS binding or suffix delegation;
      - or the operator's signed retirement.
    - `abusive`: a verdict only. A provisional listing MUST NOT use this class.
29. A listing MUST NOT move, unseat or replace a sequencer. It MAY prompt the channel's owner to
    move one (JEP-0005 rule 11a).
30. **Clearing.**
    - An `abandoned` listing clears automatically when the server publishes a fresh signed welcome
      and manifest.
    - A `compromised` listing clears on evidence of a server-key rotation (lane I), or by verdict.
    - An `abusive` listing clears at the end of its term, or by verdict.
31. **Appeal.** The listed server's operator MAY appeal once, under rule 23. A `verdict` listing
    stays in force while its appeal runs. A `provisional` listing that no verdict confirms lapses
    at its expiry, appeal or not.
32. Every listing, clearing, appeal and retraction is logged. Resolvers keep the listings they act
    on, as they keep attestations (JEP-0004 rule 20), and MUST apply retractions.

# Security Considerations (Zero-Trust)

**Threats addressed:**

- **AB-06.** Encrypted abuse becomes provable by a participant alone. The proof is scoped to one
  message, with no escrow, server keys or scanning (rules 6–8a). The tag commits the sender to
  the plaintext, so the question of whether the suite's AEAD commits to its key does not arise.
  The recipient's check at decrypt (rule 7) stops a sender from making a message unreportable.
- **GV-01, capture.**
  - One seat per operator.
  - Panels are drawn at random from a witnessed checkpoint.
  - The appeal panel is disjoint from the first.
  - A disagreeing seat agent is evidence against its seat.
  - Each group is its own scope.
- **GV-02, Sybil panels.** Seats count operators, not identities. Reports from unknown reporters
  weigh zero.
- **GV-03.** Penalties apply only under an acknowledged ruleset and only inside the group.
- **Concerted attacks.** Evidence-track verdicts and provisional measures act in minutes, without
  people (rules 15 and 17).
- **Wrong automated judgement.** Content cases get only reversible, expiring measures until people
  confirm them (rule 18).
- **D19.** A listing is advisory, needs evidence of its class, and never touches a sequencer.

**Residual risks:**

- A patient party that gets several seats admitted by deceiving the seat-admission threshold.
- Members who will not disclose context. Their refusal is recorded, not inferred.
- A provisional measure can slow an innocent subject for up to `provisional_ttl`.

**Privacy:**

- Disclosures reveal only the reported messages. A franking tag reveals nothing without its
  `k_f`, so a server cannot test guesses at content.
- Franked content is not deniable, which is by design (PV-04). Because the block is author-signed,
  anyone the reporter shows an opening to can verify it, not only a platform.
- Inviter tags open only under rule 25.
- No path unmasks an `--anon` key.
- Logs carry subject commitments (JEP-0009 rule 32).

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- The nameserver prototype's tribunal case records, anomaly detector and host penalties are
  removed (lane L6). Only their outcome vocabulary carries into rule 21.

# Reference Implementation

None yet. Milestones R5 (rules 4–10), R6 (rules 1–3 and 11–25) and R8 (rules 26–32).

# Test Vectors

To be added with each milestone:

- a franked message and its opening, one opening whose `k_f` does not match, and one block whose
  `frank` does not match its plaintext;
- an evidence-track case with the adjudication's expected output;
- a provisional measure, its expiry, and a confirmation;
- each class of listing, with its evidence.

# Rejected Alternatives

- **Disclosing per-message MLS keys.** It is the strongest MLS-native proof, but openmls 0.9.1
  exposes no per-message secrets. It would need a fork that jig maintains, and the same
  internals work for every other suite.
- **An inner envelope signed by the sender inside the plaintext.** It proves authorship, but does
  not commit the delivered ciphertext to the plaintext, and it costs a signature per message.
- **Fully automated permanent verdicts on content.** Swarm reports and classifier evasion can game
  them, and they turn mistakes into permanent bans.
- **One seat per nameserver.** A party running many nameservers would get many seats (GV-02).
- **User juries.** Deferred until Sybil-resistant standing (JEP-0009) has run long enough to be
  trusted.
- **Unilateral listings that bind a group.** That would be a veto (D19).

# Copyright

This document is licensed under CC-BY-4.0.
