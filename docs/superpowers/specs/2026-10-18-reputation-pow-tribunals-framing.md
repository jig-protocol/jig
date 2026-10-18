# Reputation, proof-of-work and tribunals: framing

Date: 2026-10-18. Lane R of the
[v0.2-close and M3 plan](../plans/2026-10-18-v0.2-close-and-m3-start.md). Decisions it builds on:
D15, D19–D23 and D26 in the [roadmap](../../ROADMAP.md#decisions-log), and lane F's
[federation and naming design](2026-10-18-federation-naming-and-contract-design.md) (JEP-0004,
JEP-0005).

**Status: framing, research pass done, DJ's answers recorded (2026-10-18).** "Decided (DJ)" marks
an answer; "Recommended" marks a lane R proposal DJ has not ruled on. Section 17 lists the
questions and answers. Nothing here is normative until it lands in `jig-spec` through an
implementation PR.

Register families: AB (abuse and Sybil), NS (nameservers), GV (governance), TM (time), plus OP-10.

---

## 1. Goal

D23 makes proof-of-work, reputation, tribunals and transparency logs obligations, and requires
their known weaknesses to be closed in full. This document:

1. defines what proof-of-work is for, and designs it (section 5);
2. sets out how standing can cost more than linear compute (section 6);
3. sketches the reputation maths, report formats, logs, tribunals, server lists and anchors
   (sections 7–12) far enough to order them;
4. turns all of that into milestones with exit criteria (section 14);
5. says what to recover from the nameserver prototypes (section 15);
6. proposes spec and JEP-0003 changes (section 16).

Non-goals: the network layer (volumetric floods stay the operator's, as F 5.10 says), and any
mechanism that links an `--anon` key to a DID (D20).

## 2. What exists today (verified 2026-10-18 on `main` at `062fe91`)

| Piece | State |
| --- | --- |
| Server admission PoW | `jig-core/src/admission_pow.rs`, `jig-server/src/v0_0_2_admission.rs`. BLAKE3 over labelled parts (`jig-admission-pow-v1`, server DID, new DID, nonce ≤ 64 bytes), leading zero bits, cap 28. One-time, no challenge, no server state before the proof. Off by default (`unknown_dids = "admit"`, D26); 20 bits when on. Relayed and bridged authors are never asked. |
| Server rate limits | Token buckets per verified DID and per remote address, on by default (#92). |
| Server reputation | Operator-seeded `ruleset key → score` for admission floors. Nothing computes it, nothing is reported. The handshake's `reputation` field is signed and `null`. |
| Nameserver v0.0.2 | `/v1/challenge` then `/v1/register`, `/v1/rotate`, `/v1/renew`: no PoW, no rate limit. F1 rewrites the proof of control (JEP-0004 rule 10). |
| Nameserver legacy PoW | `pow.rs`: `blake3::keyed_hash(blake3(server_secret), …)`. Only a holder of `JIG_NS_SECRET` can solve or verify, so it gates who holds the secret, not how much work was done. D26 rules it out. |
| Nameserver legacy reputation, tribunal, transparency, anomaly, useful work | Routes and storage exist. Nothing in the workspace calls them, nothing writes the log, `penalty_delta` is stored and never applied (L6 inventory, #113). |
| MLS | The leaf signature key is the DID's Ed25519 key (`jig-mls/src/credential.rs`). Encrypted content travels as an author-signed block whose `mls_message` is an MLS `PrivateMessage` (`encryption.md`). Both matter for abuse reports (8.3). |

## 3. Prior art, and what each settles

| System | Mechanism | What it settles for jig |
| --- | --- | --- |
| **Hashcash** (Back, 1997/2002) | Partial hash preimage stamp bound to recipient and date | The stamp shape: work bound to the verifier and the action, checkable with one hash, no shared secret. jig's admission PoW is already this |
| **"Proof-of-work proves not to work"** (Laurie and Clayton, 2004) | Economics: a difficulty legitimate senders can afford is free to spammers with hijacked machines | **PoW cannot price identities against a botnet.** Any difficulty a phone tolerates is cheap to an attacker with someone else's CPUs |
| **"Proof of work can work"** (Liu and Camp, 2006) | Weight the work by reputation | Work should fall on those without standing. This is the shape adopted in 5.6 |
| **Equihash** (Biryukov and Khovratovich, 2016), **Equi-X** (tevador) | Memory-hard, asymmetric: slow to solve, microseconds to verify | Memory-hardness narrows the GPU and ASIC advantage over a CPU. It does nothing against a botnet, whose nodes are CPUs. It is a choice about GPUs, not about Sybils |
| **Tor onion-service PoW** (proposal 327, hspow-spec; proposal 362 for the controller) | Equi-X with a linear effort value; the service publishes a *suggested effort* that a controller raises under load and drops to zero when idle; requests are served from a priority queue, highest effort first; clients raise their bid on retry | **PoW as priority under load, free when idle.** It does not stop an attack; it keeps a service usable for whoever is willing to pay during one. The 60-second KPI survives because effort is zero when nobody attacks. Known issue: a forged or stale suggested effort misleads clients, so jig's must be signed |
| **Privacy Pass** (RFC 9576 architecture, RFC 9578 issuance) | An attester vouches, an issuer issues blind tokens, an origin redeems them unlinkably | **Attestation without linkage.** Standing proven on one side can be spent on the other without linking the two. Fits invites (6.3) |
| **ARC** (draft-yun-privacypass-arc, IETF privacypass) and **ACT** (draft-schlesinger-cfrg-act, draft-schlesinger-privacypass-act) | One credential presented a bounded number of times (ARC) or spent down from a balance with unlinkable change (ACT) | **Rate-limited, unlinkable vouching.** An established DID gets a per-period budget of invites it cannot exceed, and no one can link invitee to inviter. Drafts, not RFCs: track, do not depend on yet |
| **SybilGuard, SybilLimit, SybilRank** | Random walks on a trust graph; Sybils are cut off by few attack edges | Bounds hold only if the honest graph mixes fast, which later measurements dispute, and the graph must be visible, which links identities. **Rejected as a protocol mechanism.** Vouch graphs are still useful inside one ruleset, opt-in (6.4) |
| **Matrix policy lists** (Mjolnir, Draupnir; `m.policy.rule.*` events) and **policy servers** (MSC4284) | Moderation lists as rooms that bots subscribe to; a room-chosen server that gives an opinion on each event | Lists are subscribed, not imposed: each consumer picks which lists bind it. The policy server shows the risk of one party's opinion becoming a de facto gate for every room that adopts it |
| **Fediverse denylists** (FediBlock, Oliphant tiers via FediBlockHole, IFTAS DNI and abandoned-domain lists, CARIAD) | Shared domain blocklists, often by consensus of N curators; IFTAS keeps a separate abandoned/unmanaged list | Consensus thresholds are the common defence against one curator's bias; retractions must propagate; evidence is often private because of harassment. IFTAS's own guidance names overblocking and absent appeals as the main harms. **Abandoned and abusive are different lists with different evidence** |
| **Certificate Transparency** (RFC 6962/9162), CT gossip (draft-ietf-trans-gossip, expired as experimental), **C2SP tlog-checkpoint, tlog-cosignature, tlog-witness, tlog-tiles** | Merkle logs with signed tree heads; split views detected by gossip or prevented by witness cosignatures | Gossip never deployed at scale; **witness cosigning did**. A ruleset group's other nameservers are natural witnesses. Use the C2SP formats rather than invent one |
| **Message franking** (Facebook; Grubbs et al. 2017; Dodis et al. 2018 on attachment franking; asymmetric franking, Tyagi et al. 2019) | A commitment to the plaintext that the platform binds at delivery, opened by the reporter | **Adopted for encrypted reports (8.3)**, after openmls proved unable to expose per-message keys. In jig the commitment sits in the author-signed outer block, so anyone can verify it, not only the platform. Dodis et al.'s lesson carries over: the recipient must check the tag at decrypt, or a sender can make content unreportable |

Sources are in Appendix A.

## 4. What proof-of-work is for

**Decided (DJ, Q1).** PoW in jig is a **price on a stranger's use of capacity, and an ordering of
strangers under load**. It is never an identity price, never a Sybil defence and never a gate on
its own (AB-02, AB-05).

It is for:

1. **Load shedding at every ingress** (servers, nameservers, custodians, federation dials): under
   load, strangers are served in order of work done, Tor-style.
2. **Making rate-limit buckets not free to multiply.** A fresh DID is a fresh token bucket. A
   one-time admission cost makes rotating DIDs to escape a bucket cost something.
3. **Raising the price for a single host or rented cloud,** where compute costs the attacker
   money. That is most casual abuse.

It is not for:

- stopping a botnet (3, Laurie and Clayton; 5.8 below);
- making standing expensive (that is section 6);
- telling people from scripts.

Consequence: an obligation to "enforce PoW" (D23) is met by an effort controller that is zero when
idle, plus a capacity partition that protects members (5.5). A static difficulty that every new
user pays and every GPU ignores meets the letter and none of the purpose.

## 5. Proof-of-work design

### 5.1 One puzzle, three bindings

Every jig PoW is the same construction, so one solver and one verifier serve servers, nameservers
and custodians. It extends the admission PoW rather than replacing it.

- **Digest** = BLAKE3 over labelled parts (the admission PoW's and JEP-0004's labelled hashing),
  in order:
  1. (`domain`, `jig-pow-v1`);
  2. (`alg`, the puzzle algorithm id, 5.2);
  3. (`verifier`, the DID of the party that will check it);
  4. (`subject`, the DID asking, or the session key for `--anon`);
  5. (`action`, a registered action label such as `admit`, `post`, `ns-register`, `dial`,
     `kp-request`);
  6. (`binding`, bytes fixed by the action: the block CID for `post`; for `ns-register`,
     `ns-rotate` and `ns-renew`, the JEP-0004 proof hash
     `jig_core::naming::proof_hash(action, ns_did, alias, challenge)`, so the work commits to
     exactly what the proof of control signs (lane F's suggestion); the dialed server's DID for
     `dial`; empty for `admit`);
  7. (`salt`, 5.3);
  8. (`nonce`, at most 64 bytes, chosen by the solver).
- **Effort** is a linear integer `E ≥ 1`, the expected number of attempts, as in Tor, not a bit
  count. The work is valid when `u64_be(digest[0..8]) × E ≤ 2^64 − 1`. Linear effort lets a
  controller move the price by 10 % instead of doubling it. A bit count `b` is effort `2^b`, so
  the admission PoW's `bits` maps exactly.
- **No secret anywhere.** Anyone can solve from public information and anyone can verify. This is
  the D26 requirement, and the legacy keyed hash fails it.
- **Bound to the verifier, subject, action and binding,** so a solved stamp cannot be replayed
  against another server, for another DID, or for another block (AB-01).

### 5.2 Algorithm

| Option | Solve on a phone | GPU advantage | Verify | Wasm and potato | For |
| --- | --- | --- | --- | --- | --- |
| **A. BLAKE3 hashcash** (today) | ~10^6 hashes/s per core (estimate) | Large: about 10^3× a CPU core (estimate) | One hash | Trivial, already shipped | Simplest, no new dependency, deterministic |
| **B. Equi-X** (Tor) | Slower per attempt, fewer attempts | Small: designed to narrow it | Microseconds | Its HashX JIT-compiles per challenge; the interpreter fallback is slow on a potato and in Wasm | Proven at Tor's scale; narrows the GPU gap |
| **C. Argon2id stamp** | Tunable by memory | Small | As slow as one solve, so verification is not cheap | Fine | Ruled out: verification must cost far less than solving, or the verifier is the one being attacked |

**Decided (DJ, Q5): A as `alg = 1` now, with algorithm agility in the digest and the ruleset.** B
becomes `alg = 2` when a ruleset group shows it faces GPU-backed farming, after R1 measures the
gap. Rationale: the attacker that matters is a botnet, against which B buys nothing (section 3),
and B costs a JIT-shaped dependency on the platforms (potato, Wasm-hosted server) the product
constraints protect. Numbers here are estimates; R1's exit criterion includes measuring them.

### 5.3 Salt: three modes

| Mode | Salt | Used for | Replay guard | Verifier state |
| --- | --- | --- | --- | --- |
| **Admission** | empty | `admit`, once per (verifier, subject) | the binding: one admission per pair | records the DID as proven (as today) |
| **Stamp** | the verifier's current epoch salt: 32 random bytes, rotated every `epoch_secs` (ruleset; default 600), published in the signed welcome or manifest and in `/.well-known/jig` as a hint. The current and previous salts are accepted | per-action costs at servers: `post`, `kp-request`, `dial` | the binding (one stamp per block CID), plus a spent set of digests kept for two epochs | bounded: two epochs of digests |
| **Challenge** | empty: the challenge (at least 32 random bytes, at most 300 s, consumed on first use: JEP-0004 rule 10) is already inside the binding's proof hash | nameserver binding endpoints: `ns-register`, `ns-rotate`, `ns-renew`, carried in F1's optional `pow` object on the request | single use of the challenge | the challenge map, bounded by count and TTL |

The epoch salt bounds precomputation to one epoch. Admission needs no salt: precomputing an
admission does not make it cheaper, only earlier.

### 5.4 The effort controller

**Recommended (from Tor's suggested effort).**

- Each verifier runs a controller per action that sets `E_suggested` from its queue: raised while
  the stranger queue (5.5) is above its target, decayed towards **zero** when it drains. At zero,
  no work is asked (the stamp is skipped entirely, as in Tor).
- `E_suggested` is **signed**: in the welcome, in the manifest, and in every `PROOF_OF_WORK_REQUIRED`
  refusal, together with the epoch salt. Unsigned hints in `/.well-known/jig` are hints only. This
  closes the Tor analysis's forged-suggested-effort issue.
- A client bids at least `E_suggested` and doubles its bid on each refusal, up to the ruleset's
  `max_effort`, then gives up and says so.
- Within the stranger pool, the verifier serves the highest effort first. Effort above the
  required value buys priority, not admission past a quota.
- The ruleset bounds it: `min_effort`, `max_effort` per action. `max_effort` is set so the slowest
  supported client can finish within the ruleset's `max_solve_secs` (default: 2 s for `admit`,
  50 ms for per-action stamps, measured on the reference potato).

### 5.5 The stranger pool: what actually protects members

**Decided (DJ, Q3), with a 20 % reference share. This is the piece that makes identity farming
harmless to members at a server, whatever it costs the attacker.**

- A server partitions its ingest capacity (writes per second, subscriptions, handshakes) between
  **members**, subjects with standing at or above the ruleset's `established` level, and
  **strangers**: everyone else, unknown and `--anon` included.
- The stranger pool gets at most `stranger_share` of capacity (ruleset parameter; the reference
  default is 20 %). Members never compete with strangers for the rest.
- Inside the stranger pool: per-DID and per-address buckets as today, then the PoW priority queue.
- A third, **invited pool** (6.3) holds newcomers admitted on an invite until their accrual
  matures. It is capped separately (`invited_share`), so a swarm of invitees cannot spill into the
  member pool.
- `--anon` keys are always strangers. They carry no reputation at all (6.1).
- **Effect:** a flood of fresh identities, however cheaply minted, can consume only the stranger
  pool. Members are unaffected. Honest newcomers are slowed during an attack, which is the price,
  and invites (6.3) let a newcomer skip the queue on a member's budget.
- This does not make unknown "low" (whitepaper 6.1 obligation 4). No floor applies to unknown keys;
  they share a pool, they are not refused.
- The same partition applies at a nameserver (registration is by definition a stranger action;
  renew and rotate by a holder with standing are not) and at a custodian (key-package requests from
  non-contacts).

### 5.6 Scaling effort by standing, within ruleset bounds

```
E = clamp( E_suggested(action, load)
           × m_penalty(target, requester)
           × m_standing(score under the ruleset),
           min_effort(action), max_effort(action) )
```

- `m_standing` is 1 for unknown subjects and for anything below `established`. Above it, it falls
  linearly to `1 / max_standing_discount` (ruleset; reference 4) at the top of the scale. Negative
  scores raise it to at most `max_penalty_multiplier` (reference 8). Standing can only lower the
  price for subjects that already have standing, so it never makes Sybils cheaper.
- Under load, standing matters mostly through pool membership (5.5), not through the multiplier.
- `m_penalty` keys penalties on the pair **(target, requester)**, not on the target alone, which
  closes the griefing weakness in the abuse-economics note. The requester is the DID that signed
  the request (challenge requests become signed). Address-keyed penalties raise effort for that
  address (the "unpriced addresses" weakness).
- Decay remembers repeat offenders: the per-key decay interval doubles with each offence inside a
  ruleset window (reference: 300 s, then 600 s, …, capped at a day), and resets after a clean
  window. That closes "forgetful decay".

### 5.7 Where PoW applies

| Ingress | Action | Mode | Notes |
| --- | --- | --- | --- |
| Server, first contact | `admit` | admission | Once per (server, DID). Only when the controller is above zero, or the ruleset fixes a floor |
| Server, stranger writes | `post` | stamp | Only when the stranger pool is loaded |
| Server, stranger subscriptions and handshakes | `admit` covers them | — | Reads are bucketed, not stamped |
| Follower relaying to an owner (F 5.2) | none | — | The follower is the enforcement boundary for its clients; the owner sees one accountable peer with a quota |
| Nameserver | `ns-register` | challenge | Always ≥ `min_effort`: a registration creates a binding (D23) |
| Nameserver | `ns-rotate`, `ns-renew` | challenge | `min_effort` only: both are signed by a key that already holds the name |
| Nameserver challenge issuance | none | — | Rate-limited per address and per signed requester; issuing must stay cheaper than verifying |
| Custodian (F 5.4) | `kp-request` from a non-contact | stamp | Protects Alice's key-package stock |
| Server-to-server dial, open federation | `dial` | stamp | Before any work beyond the handshake's first frame (5.10) |
| Relayed and bridged authors | none | — | They never spoke to this server; the relaying peer or bridge pays at its own ingress (AB-03) |

### 5.8 Botnet economics (AB-02), stated plainly

Take a phone that does about 10^6 BLAKE3 hashes a second (estimate; R1 measures).

- A 2-second admission budget allows `E ≈ 2 × 10^6` (about 21 bits).
- A GPU at about 10^9 hashes a second (estimate) mints about 500 admissions a second at that
  effort. A 10,000-node botnet of phone-class CPUs mints about 5,000.
- Nothing a phone can afford changes that by more than a constant. **Per-identity PoW cannot price
  identities against this attacker, at any difficulty. AB-02 is closed by not relying on it:**
  1. **Capacity:** the stranger pool (5.5) caps what any number of fresh identities can take from
     a server, so farmed identities cannot hurt members.
  2. **Standing:** fresh identities start unknown and earn standing only through time and
     observation that compute cannot buy (section 6).
  3. **Attribution:** a flood relayed through a listed peer counts against that peer's quota and
     standing (F 5.10).
- What PoW still buys against a botnet: the attacker's nodes spend their time on work instead of
  requests, so the verifier's cost per attacking request is one hash, and under the priority queue
  a user who is willing to wait a few seconds still gets served.

**Proposed register wording (AB-02):** "PoW prices strangers' use of capacity and orders them under
load. It is never an identity price. Farmed identities are contained by the stranger pool and by
standing that compute cannot buy."

### 5.9 Admission PoW on by default (D26)

D26 keeps admission PoW off until a design covers (a) registration at nameservers, (b) challenges
anyone can solve, and (c) what the cost buys against identity farming. Sections 5.1–5.8 cover all
three.

| Option | Effect |
| --- | --- |
| **A. Keep off by default** | Fresh DIDs escape per-DID buckets for free. Fails D23's "servers enforce PoW" |
| **B. On, static 20 bits** | Every new user pays, every GPU ignores it, potatoes and phones pay most. The 60-second KPI pays about a second |
| **C. On, adaptive: `unknown_dids = "proof-of-work"` with the controller, effort zero when idle** | Free in normal operation; rises only under a stranger flood; meets D23 |

**Decided (DJ, Q4): C, switched on in R1 once the nameserver's binding endpoints also carry PoW**, so
D26's condition (a) is met in code, not only on paper. A ruleset MAY set a non-zero floor; the
reference ruleset does not.

### 5.10 What open federation needs (F 5.7, 5.10)

Open federation (servers that are not on each other's configured peer lists) must not ship until
all of these exist:

1. **`dial` stamps** checked before anything but the handshake's first frame, so a stranger server
   costs the dialed side one hash before the signature check.
2. **A stranger-server pool,** the server-level analogue of 5.5: unlisted peers share a capped
   slice of federation capacity, ordered by effort.
3. **Server standing under the ruleset** (whitepaper 6.1 obligation 8): servers carry numbers,
   moved by signed evidence such as quota breaches, fork evidence and broken contracts (R3).
4. **Server lists** (section 11), so a group can act on evidence about a server, advisory as F
   decided.
5. **Per-peer quotas that start small for strangers** and grow with standing, in the signed peer
   policy.

## 6. Standing beyond linear cost (AB-05)

### 6.1 The target property

D23 wants identity farming closed, not priced. **Decided (DJ, Q2):**

> **Standing is sublinear in compute.** The standing an attacker can hold under a ruleset is bounded
> by quantities compute cannot multiply: elapsed time as observed by the group, and standing the
> attacker already holds. No decision under a ruleset adds standing across identities.

Hashing cannot buy standing at all under this rule. A botnet can mint unknown keys without limit,
and unknown keys get only the stranger pool. Aged-key trading, the one class that cannot be closed
without linking keys to people, becomes a new register row, AB-07, Accepted, bounded (6.5).

Two further rules from the same answer:

- **`--anon` forecloses reputation.** A server that admits `--anon` keys (null-sec rules) cannot
  learn anything about the holder and cannot assign the key reputation. It treats every such key
  as **unknown** under every ruleset, for the whole session, and structures its policy for that.
  The spec's "reputation lasts at most for the session" becomes "an `--anon` key has none".
  Unknown, not zero: zero would mean evidence that nets out, and floors would apply to it.
- **Person-binding is a rarity, never a protocol default.** A high-sec ruleset MAY bind
  identities to persons, and MUST declare it in its ruleset document. The protocol never requires
  it: taken far, it would end the holder's ability to discard a key and start fresh, which the
  anonymity model depends on.

### 6.2 Time-gated accrual

- Positive standing accrues only from **observations by parties other than the subject** (servers'
  signed reports, R3) and is capped **per unit of group time**: at most `accrual_per_day` per
  subject, whatever the activity. Age is measured from the first signed observation by a group
  member, on the observer's clock (TM-01).
- So `n` farmed identities reach established standing no faster than one does, and only by
  behaving well for the whole period, under observation, on servers that report them.
- Many cheap identities never sum: tribunals, report weighting and vouching weigh each identity by
  its own standing, and unknown identities weigh zero (GV-02).

### 6.3 Invites: budgeted, contained, accountable on verdict

**Decided (DJ, Q6 and its follow-up).** Invites are the default acceleration, and soul validation
(6.4) is an opt-in a ruleset declares.

- An established DID gets `invites_per_period` (ruleset) **rate-limited anonymous credentials**
  from a group nameserver, ARC- or ACT-style. Presenting one at registration or admission starts
  the newcomer's accrual at `invite_start` instead of zero.
- **Containment.** An invitee sits in the **invited pool** (5.5), capped separately, until its
  accrual matures to `established`. A swarm of invitees cannot reach the member pool.
- **Escrowed inviter tag.** At redemption the invitee carries the inviter's DID, verifiably
  encrypted to the group's threshold key, which the tribunal seats hold. By default nobody can read
  it, and the presentation stays unlinkable to the inviter. A tribunal verdict on invitees opens
  the tag at the seat threshold. The inviter then takes the ruleset's inviter penalty and loses its
  invite budget.
- **Only a human-confirmed verdict opens a tag.** No automated output can open one: not an
  evidence-track threshold verdict (10.3), and not a provisional measure. Each seat's decryption
  share is released only by a person at that seat, after the human panel's verdict, and the
  release is logged. Seat agents never hold a share in a form they can use alone. Otherwise the
  machines holding the shares could de-anonymise inviters on their own. Automation still acts
  fast on the swarm itself: evidence-track verdicts and provisional measures apply to the invitees
  (demotion, throttling), which the invited pool already contains.
- **Why not a nameserver that sees both parties** (DJ's first proposal): one nameserver would hold
  the group's invite graph. That is a honeypot, and it breaks NS-03. The threshold tag gives the
  same accountability with nobody holding the graph.
- **The insider swarm** (DJ): an attacker waits out accrual on `k` identities, then invites the
  rest of a swarm. It is bounded three ways: by `k × invites_per_period`, by the invited pool's
  cap, and by the first verdict on the swarm, which opens the tags and burns the `k` inviters.
- **`--anon` keys can neither invite nor be invited.**
- **Cost: a PV-03 carve-out.** A protocol message now carries an encrypted link between two DIDs,
  which only a verdict at the seat threshold can open. PV-03's wording changes to match (16).
- **Crypto choices for R7.** ARC and ACT are drafts, so R7 starts on blind-RSA tokens (RFC 9474),
  one token per invite. The verifiable-encryption and threshold-decryption scheme is open; R7
  surveys it. It must let a verifier check that the tag encrypts a DID that holds an invite
  budget, without learning which DID.

### 6.4 Soul validation (linked vouching), opt-in per ruleset (decided, Q6)

The spec's proposal stays, scoped: a public, signed vouch that links two DIDs, boosts the
vouchee's accrual and propagates losses back. It suits high-sec work groups whose members are
known to each other. Because it links DIDs publicly, a ruleset that uses it MUST say so in its
document, and clients MUST warn before a holder vouches. Ring resistance: vouches weigh by the
voucher's standing, are capped per voucher, and a ring member's loss propagates around the ring.

### 6.5 What stays open after 6.1–6.4

- **Buying aged keys.** Standing attaches to a key, and keys can be sold. Bounded by the supply of
  established keys, and burnt by the first verdict. Not closable without linking key to person,
  which D20 and PV-03 forbid. **Accepted, bounded** as AB-07 (decided, Q2).
- **A patient attacker** who behaves well for the accrual period on many identities. Bounded by
  6.2's per-subject cap and by observation: each identity must be observed by servers that report
  it, and the attacker's own servers' reports are capped (7.3).

## 7. Reputation maths per ruleset (D21)

### 7.1 Servers report facts, nameservers compute numbers

**Recommended.** A server's report carries **event codes**, not score deltas: `spam-confirmed`,
`quota-breach`, `invalid-proof`, `verdict-applied`, `good-standing-interval`, and so on, each
citing evidence. The ruleset maps codes to weights. A server therefore cannot inflate the magnitude
of what it reports, only the count, and counts are capped (7.3). Every member computes the same
number from the same reports, which is what D21's "same maths" needs.

### 7.2 Reference ruleset maths: beta reputation with forgetting

- Per subject, keep positive evidence `r` and negative evidence `s`, each a weighted sum of event
  weights. Score `= (r − s) / (r + s + 2)`, in (−1, 1). No evidence means unknown, not zero.
- Forgetting: both decay by `λ` per period (ruleset; reference: a half-life of 90 days for `r`,
  shorter for minor negatives, none for verdicts until their expiry).
- Bounded, monotone, cheap, and well studied (Jøsang's beta reputation). It is a reference, not a
  protocol rule: a ruleset names its maths by id and version, and conformance vectors pin it.
- Rejected: global trust propagation (EigenTrust and similar), because it pools across the network
  and an attacker inflates it everywhere at once (D21).

### 7.3 Net computation that one lying server cannot move far

- Per (subject, period), each reporting server's contribution is capped at `per_reporter_cap`
  evidence units, weighted by **the reporting server's own standing** under the ruleset.
- Negative events above `minor` need evidence CIDs, or they count as minor.
- A server whose reports a verdict finds false loses standing (whitepaper 6.1 obligation 8), and
  its past reports are re-weighted.
- The net change is computed by each of the group's nameservers from the same report set, and is
  authoritative when a threshold of them sign the same result (NS-03; it rides on R4's witnessing).

### 7.4 Reputation as a protocol input (OP-10)

The rule "not a protocol gate until JEP-0003 defines it" lifts when R3 ships: a score computed
under a declared, acknowledged ruleset (R2) by this maths may feed pool membership and effort. Raw
operator-seeded scores stay local policy. The handshake's `reputation` field carries the server's
own standing under its declared ruleset, as signed evidence the client may check against the
group's log.

## 8. Report formats

### 8.1 Encoding

All of R's formats are records of named fields signed by a DID. **Decided (DJ, Q9): lane A's A5
extends to R. Every multi-field signed record of R's is deterministic CBOR (RFC 8949 §4.2.1)
signed with COSE_Sign1 (EdDSA, `kid` = signer DID).** Labelled hashing stays for flat statements
and for PoW digests. Reasons: these objects are nested (evidence bundles,
reports inside log leaves), are verified by third parties in other ruleset groups, and need
versioned optional fields. JEP-0004's labelled hashing suits flat statements; R's are not flat. The
formats below are defined as field lists so either encoding can carry them.

### 8.2 Reputation report (server → nameservers)

`{v, ruleset: {id, version, doc_hash}, reporter: server DID, seq, prev, period, entries: [{subject,
code, count, evidence: [CID], ref?}], sig}`

- `seq`/`prev` chain the reports; the chain **is** the server's transparency log of what it
  reported (section 9), so a server keeps one artefact, not two.
- `subject` is the DID or session key the server dealt with. A report never names two DIDs as the
  same holder.
- Sent under the server–nameserver data contract; a nameserver treats it as a claim (spec).

### 8.3 Abuse report from an encrypted channel (AB-06, D22)

**Decided (DJ, Q7, revisited 2026-10-18): message franking, defined above the encryption suite.**
DJ first chose per-message key disclosure. Lane S then checked openmls 0.9.1, and per-message
secrets cannot be reached:

- the secret tree is crate-private;
- processed messages expose no message key, no nonce, no sender-data key and no content
  signature;
- each generation's secret is wiped after use.

Three options were weighed:

| Option | Proves | Cost | Verdict |
| --- | --- | --- | --- |
| (a) Patch or fork openmls to return per-message keys at decrypt | The accused's ciphertext decrypts to this plaintext, under the MLS content signature | A fork jig maintains. Every other suite needs the same internals work. Values must be captured at first decrypt | Rejected |
| (b) An inner envelope `{channel, group_id, epoch, msg_id, body}`, signed by the sender's DID inside the plaintext, with `msg_id` in the outer block | The accused signed this plaintext for this channel | One extra signature per message. It does not commit the delivered ciphertext to the plaintext | Rejected |
| **(c) Message franking** | The accused committed to this plaintext in the exact block the owner sequenced | 32 bytes and one hash per message; no MLS internals | **Chosen** |

**Mechanism.**

1. For each content message, the sender's client picks a fresh 32-byte **franking key** `k_f`.
2. It computes the **franking tag**
   `c = H(("domain", "jig-frank-v1"), ("k_f", k_f), ("channel_id", …), ("sender", DID),
   ("epoch", …), ("body", plaintext body), ("attachments", the BLAKE3 hash of each attachment's
   plaintext, in order))`. `H` is labelled BLAKE3 (JEP-0004 rule 8).
3. `k_f` travels inside the encrypted plaintext. `c` goes in the author-signed outer block, so the
   owner's `ingest` record sequences it.
4. The recipient's client recomputes `c` after decrypting. If it does not match, the client MUST
   refuse to display the message as valid and MUST mark it. Otherwise a sender could make a
   message unreportable, which is the Dodis et al. attack on attachment franking.

**A report item** is:

- the author-signed block, with `c`;
- the owner's `ingest` record for it;
- the disclosed plaintext body and attachments;
- `k_f`.

**The tribunal checks:**

- the author signature over the block, which binds the accused's DID to `c`;
- the `ingest` record, which places the block in this channel at this position;
- `c` recomputed from the disclosure, which binds `c` to exactly this plaintext.

**Properties.**

- *Binding:* `c` is a collision-resistant hash over `k_f` and the content. Neither the sender nor
  a reporter can open one tag to two plaintexts. This is a committing construction, so the
  question of whether the suite's AEAD commits to its key does not arise.
- *Hiding:* without `k_f`, `c` reveals nothing. A server cannot test guesses at the content.
- *Only a recipient can report:* only holders of the group's keys, and the sender itself, learn
  `k_f`.
- *Scope:* one `k_f` opens one message, and nothing about any other.
- *Suites:* franking sits above the suite. A suite's report profile reduces to delivering the
  plaintext, `k_f` included, intact to every member. Every suite JEP still states that it does
  (lane S, JEP-0001).
- *Deniability:* none, as by design (PV-04). Because the outer block is author-signed, a franked
  message is verifiable by anyone the reporter shows it to, not only by the platform as in
  Facebook's scheme. That is what lets independent tribunals verify it.

Properties against the spec's requirements:

| Requirement | Met by |
| --- | --- |
| Only a recipient can start a report | `k_f` exists only inside the ciphertext |
| Scoped to the reported messages; no standing access | One `k_f` per message |
| No escrow, server keys or scanning | None used. The server sees only `c` |
| `--anon` sender reveals nothing more | Attribution reaches the signing key only |
| Works for every suite a group admits | Franking is suite-independent; a suite need only deliver the plaintext intact. A suite that cannot is not admitted by a group that has a tribunal |
| Context against selective disclosure | The report MAY list surrounding `seq` ranges; the tribunal MAY ask the accused and other members to disclose their own franked messages in that range; non-disclosure is recorded, not inferred |
| A channel as victim | Any member may report; several members' reports of one incident merge into one case |

Report envelope: `{v, reporter, case_ref?, channel_id, items: [above], context: [seq ranges],
statement, sig}`, sent to the group's tribunal intake, never to the channel's owner by default
(the owner may be the subject).

### 8.4 Tribunal records

`case-open`, `case-response`, `verdict`, `appeal`, `appeal-verdict`, each a signed record citing
evidence by CID, appended to the group's log (section 9). Outcome vocabulary from the prototype:
`sustain`, `modify`, `overturn`, `dismiss`, `escalate` (the only thing worth keeping from it, 15).

### 8.5 Server-list entry (F5)

F defines the list format. R adds the fields R needs: `{server_did, class: abandoned |
compromised | abusive, evidence: [CID], basis: provisional | verdict, case_ref?, listed_at,
expires_at, sig}`. Rules in section 11.

## 9. Transparency logs (NS-02)

**Recommended: one log format for servers and nameservers, the C2SP tlog family** (RFC 6962-style
Merkle tree, `tlog-checkpoint` signed notes, `tlog-tiles` for serving, `tlog-cosignature` for
witnesses). Rejected: the prototype's ad hoc Merkle root over JSON strings with hourly chained
hashes, which has no inclusion or consistency proofs.

- **Leaves** are the signed records of section 8 (or their CIDs) and, at nameservers, every
  binding, rotation, net reputation change, penalty, verdict and listing.
- **Witnesses:** in a ruleset group, every other nameserver witnesses each member's log and
  cosigns checkpoints; a checkpoint counts at the ruleset's witness threshold. Split views are then
  prevented, not merely detectable, which gossip in CT never achieved in deployment.
- **Server logs** are witnessed by the server's nameservers. A server with no nameserver keeps one
  and publishes its checkpoints; nobody is obliged to witness it.
- **Clients** check inclusion of an attestation before pinning a name, once F3 makes the log
  mandatory for a suffix. That narrows JEP-0004's first-contact residual to "the nameserver logged
  the lie", which the subject can see. Full key transparency (KEYTRANS) remains F4.
- **Personal data:** leaves about user DIDs carry `subject_commit = H(domain, salt, DID)` instead of
  the DID. Group members get the salt under the data contract, and so does the subject; the public
  can audit the log's structure, counts and consistency. Server and nameserver DIDs appear in the
  clear: servers are public infrastructure (F 5.6).
- Nothing links an `--anon` key to a DID; a penalty on a session key is logged against that key.

## 10. Tribunals (GV-01..03, D22)

**Decided (DJ, Q8 and its follow-up): one seat per operator, and every seat is automated first.**
Operators cannot watch around the clock or adjudicate full time, and a tribunal that waits for
people cannot answer a concerted attack. So each seat runs a **seat agent**, and people handle
confirmation and appeals.

1. **Seats.** Each party to the group's data contract that runs nameservers holds **one seat per
   operator**, not per nameserver or per identity (GV-02). A new party joins by a threshold
   decision of existing parties. A party that runs several nameservers declares them under one
   seat; undeclared common control, once shown, is itself sanctionable. Each seat also holds a
   share of the group's threshold key (6.3).
2. **Cases** open automatically (penalty accumulation, fork or equivocation evidence, report
   volume weighted by reporter standing) or by report (8.2, 8.3). The subject is notified through
   its reachability record or custodian mailbox (JEP-0004 rule 21) and gets a response window.
   Reports weigh by the reporter's standing; unknown reporters weigh zero, so a swarm of fresh
   identities cannot open a case or tip one.
3. **Two tracks.**

   | Track | Cases | Who decides | How fast | What it may do |
   | --- | --- | --- | --- | --- |
   | **Evidence** | Machine-checkable: forks, equivocation, quota breaches, invalid proofs, flood stamps, signed contradictions | A deterministic rule, shipped by the ruleset as a signed **adjudication block** that every seat agent runs, with conformance vectors (D21: same maths everywhere) | Minutes: the verdict stands when a threshold of seat agents sign the same output | The ruleset's full penalty range |
   | **Judgement** | Harassment and other content cases (8.3 reports) | Seat agents apply **provisional measures** automatically; a human panel confirms them | Measures in minutes; confirmation asynchronous | Only reversible, expiring measures within the ruleset's bounds: throttling, demotion to the stranger pool, suspending invites. They lapse unless people confirm them in the ruleset's window. They are never permanent |

   A seat agent that signs a different output from the threshold is evidence against that seat.
   Fully automated permanent verdicts on content were rejected: both swarm false reports and
   classifier evasion can game them, and they turn mistakes into permanent bans.
4. **Human panels** (judgement confirmations and appeals) are drawn by verifiable randomness:
   the seed is the hash of the group log checkpoint at case opening plus the case id. Parties
   involved in the case are excluded. Size and supermajority come from the ruleset (reference:
   5 seats, 4 to sustain).
5. **Verdicts** are signed by every seat agent or panelist that made them, cite evidence by CID,
   and are logged. A verdict without evidence is void (spec).
6. **Enforcement** is a net reputation change computed under the ruleset (7.3) and applied by the
   group's servers. Nothing binds outside the group. Other groups receive verdicts as information.
7. **One appeal,** to a disjoint human panel, on either track. An appeal suspends nothing except
   listings (section 11).
8. **Limits:**
   - there is no path to unmask an `--anon` key;
   - no penalty under a ruleset the subject did not acknowledge (GV-03, R2);
   - defederating a server or nameserver needs a supermajority and published evidence;
   - opening an invite tag (6.3) needs a human-confirmed verdict, with each share released by a
     person at its seat; no automated verdict or measure can open one.
9. **Residual (GV-02):** a patient party that deceives the admission threshold into granting it
   several seats. Bounded by that threshold, and by exit: a captured group loses members to groups
   that do not recognise it.
10. **Dependency.** An adjudication block is deterministic code every seat runs. Until lane A's
    v0.3 block ABI exists, the reference rule ships as native code pinned by the ruleset's version
    and vectors. It moves to a block once JEP-0006 lands.

## 11. Server lists: who may list, evidence, appeals (F5)

F fixed: a list is a signed, advisory claim; it never moves or unseats the sequencer the owner
names (D19). R owns the rest.

**Who may list.** Any nameserver may publish its own list: it is that nameserver's claim, and
forbidding it would be a veto D19 rules out. What differs is who acts on it automatically:

| Basis | Who can issue | Effect inside the group | Expiry |
| --- | --- | --- | --- |
| `provisional` | any one group nameserver, with cryptographic evidence (below), opening a case at the same time | servers MAY refuse **new** shares and offers involving the server | 72 h unless a verdict confirms it |
| `verdict` | the group's tribunal | servers apply the ruleset's response (refuse new shares; warn members) | the verdict's term |
| outside the group | anyone | information only | — |

**Evidence by class.**

| Class | Evidence that qualifies | Not enough |
| --- | --- | --- |
| `compromised` | two conflicting `ingest` records under one sequencer key (fork); two conflicting signed attestations (equivocation); a signed handshake answer contradicted by signed behaviour (OP-02); the server's own signed key-compromise statement | reports of misbehaviour without signed artefacts |
| `abandoned` | signed liveness-probe failures from at least `k` group members run by independent operators over at least `T` (ruleset; reference 3 and 14 days), on the observers' clocks; an expired DID-bound TLS binding or suffix delegation; the operator's signed retirement | one observer's failures; DNS changes alone |
| `abusive` | a tribunal verdict on participant reports, quota-breach evidence and server-level reputation (R3, R6) | provisional listing is not allowed for this class: it needs judgement |

**Appeals and clearing.**

- `abandoned` clears automatically when the server publishes a fresh signed welcome and manifest;
  no appeal is needed.
- `compromised` clears on evidence of the server-key rotation ceremony (lane I), or by verdict.
- `abusive` is appealed once to a disjoint panel. The listing stays while the appeal runs; a
  provisional listing that no verdict confirms lapses on its own.
- Every listing, retraction and appeal is logged (section 9), so retractions propagate, which the
  fediverse lists show is the usual failure.

## 12. Anchors (D19)

- An anchor publishes a **defaults document**: signed, versioned, naming a ruleset (with the PoW,
  pool, accrual, tribunal and listing parameters above), handle conventions and tribunal
  coordination. Members adopt it by hash and may diverge.
- An anchor holds one seat and counts once towards any threshold; it cannot meet one alone.
- An anchor is replaced by an ordinary threshold amendment to the group contract. It holds no state
  the group cannot rebuild, because logs are witnessed and registries replicated (F3).

## 13. Attack classes and how each closes

The whitepaper's list (6.3), with R's answer and what remains.

| Class | Register | Closed by | Residual |
| --- | --- | --- | --- |
| Identity farming | AB-05 | Standing sublinear in compute (6.1–6.3); stranger pool (5.5) | Aged-key purchase, bounded (6.5) |
| Distributed PoW solving | AB-02 | PoW is not an identity price (5.8); pool and standing | None, by construction: the attacker gains only stranger capacity |
| Challenge replay and theft | AB-01 | Work bound to verifier, subject, action and binding (5.1); single-use challenges and spent sets (5.3) | None |
| Vouching rings | — | Vouches and invites weigh by voucher standing, are capped and budgeted; ring losses propagate (6.3, 6.4) | A ring of patient, established identities; bounded by accrual caps |
| Whitewashing after a penalty | — | A fresh key starts unknown, in the stranger pool, with time-gated accrual (6.2) | By design: leaving is always possible (whitepaper 7.1 obligation 3) |
| Buying or renting aged keys | AB-07 (new) | Burnt by the first verdict; invites budgeted | **Accepted, bounded** (6.5, decided Q2) |
| Insider swarm through invites | AB-05 | Invite budget, the capped invited pool, and escrowed inviter tags opened by verdict (6.3) | `k × invites_per_period` invitees per period, contained in the invited pool until the first verdict |
| Swarm false reports | GV-02 | Reports weigh by reporter standing, unknowns weigh zero; content cases get only provisional measures (10) | Established reporters colluding; bounded by the provisional measures' expiry and human confirmation |
| Fast-forwarded clocks | TM-01, TM-02 | Accrual and age on observers' clocks; witnessed log checkpoints as group time (9) | None at the group level; a single-server deployment trusts its own clock |
| Colluding or equivocating nameservers | NS-02, NS-03 | Witnessed logs, thresholds on net changes and listings (7.3, 9) | Collusion above the threshold; bounded by operator-seat admission |
| Panel capture | GV-01, GV-02 | One seat per operator; random panels; disjoint appeal; per-group scope (10) | A patient party admitted to several seats |
| Griefing a victim's price | — | Penalties keyed on (target, requester) (5.6) | None |
| A lying reporter server | GV-03, OP-10 | Event codes, per-reporter caps weighted by reporter standing, re-weighting after a false-report verdict (7) | Bounded by the cap |
| Selective disclosure in a report | AB-06 | Context ranges and counter-disclosure (8.3) | Members who will not disclose; recorded, not inferred |

## 14. Milestones

Each lands as a JEP section or JEP plus an implementation PR by the owning lane (L6 for the
nameserver; the server and client lanes for theirs). R writes designs and JEPs only.

| Milestone | Ships in | Contents | Exit criterion | Depends on |
| --- | --- | --- | --- | --- |
| **R0: framing** | now | This document and its DJ answers | DJ has answered section 17 | F's checkpoint (met) |
| **R1: PoW that anyone can solve** | v0.2.x | JEP for 5.1–5.7: one puzzle, three modes, linear effort, signed suggested effort, stranger pool at servers and nameservers, (target, requester) penalties, decay with memory. Nameserver register, rotate and renew carry challenge-mode PoW and rate limits. Admission PoW on by default, adaptive (5.9, decided Q4). Phone, laptop, potato and GPU throughput measured and published | A third-party client solves every challenge from public information only, tested against vectors; a flood of fresh DIDs in an integration test leaves members' p99 latency within the ruleset's bound; D26's three conditions are met in code; the 60-second KPI still passes with PoW on | F1 (the register encoding is rewritten there first; R1's PoW rides on F1's challenge) |
| **R2: rulesets declared and acknowledged** | v0.2.x / v0.3 | Ruleset document format and versioning; declaration in the signed welcome and manifest (L7's); the client's signed acknowledgement block | A client can show which ruleset a server applies before acting, and a penalty under an unacknowledged ruleset is refused in tests (GV-03) | L7's welcome and manifest |
| **R3: reports and reputation maths** | v0.3 | Report format (8.2), the server's report chain as its log, event codes, the reference beta ruleset with conformance vectors, per-reporter caps; reputation becomes a protocol input (7.4); servers carry standing | Given a vector of reports, every implementation computes the same net score; one lying server moves a subject by at most its cap; OP-10 updated | R2 |
| **R4: witnessed transparency logs** | v0.3 | C2SP tlog at nameservers and servers; witnessing within a group; subject commitments; attestation inclusion checked before pinning | A split view between two group members is refused by a client in tests; a removed entry is detected (NS-02) | R3; F3's group delegation |
| **R5: abuse reports from encrypted channels** | v0.3 | Franking tags in the outer block and `k_f` in the plaintext (8.3); the recipient's check at decrypt; report envelope; tribunal intake; the suite requirement in JEP-0001 | A test report proves to a third party holding nothing else that the accused committed to the reported plaintext in the sequenced block. A message whose tag does not match is refused at decrypt. One `k_f` reveals no other message (AB-06) | F2 (`ingest` chain), lane S (suite profile) |
| **R6: tribunals, automated first** | v0.3 | Operator seats and seat agents; the two tracks (10.3); the reference adjudication rule with conformance vectors (native first, as a block after JEP-0006); provisional measures with expiry; random human panels for confirmation and appeal; enforcement as net change | An evidence-track case (a fork) runs from detection to a threshold verdict to an applied penalty across two servers of one group within minutes, with no person involved. A provisional measure on a judgement case lapses when nobody confirms it. An appeal reaches a disjoint panel (GV-01..03) | R3, R4, R5; lane A for the block form |
| **R7: standing beyond linear cost** | v0.3 / v0.4 | Time-gated accrual; invite credentials (blind-RSA first); the invited pool; escrowed inviter tags under the seats' threshold key; optional, declared soul validation and person-binding | A simulated farm of 10^5 identities with unlimited compute holds no member-pool standing after the accrual period. An insider swarm of `k` aged identities cannot place more than `k × invites_per_period` invitees, all inside the invited pool. A verdict opens their tags and burns the inviters (AB-05) | R3, R4 (group time), R6 (seats hold the threshold key), the verifiable-encryption scheme (6.3) |
| **R8: server lists and open federation** | post-MVP | Section 11 on F5's format; `dial` stamps; stranger-server pool; per-peer quotas for strangers | An unlisted server can federate under a ruleset without operator configuration, and a flood of stranger servers leaves listed peers unaffected | R1, R3, R6, F2, F5 |
| **R9: anchors and group lifecycle** | post-MVP | Defaults document, joining and leaving, anchor replacement, cross-registration with F3 | A group replaces its anchor by amendment with no loss of state | R4, F3 |

Ordering: R1 alone can ship in v0.2.x and unblocks D26. R2 and R3 are the spine; R4 and R5 can
run in parallel after R3; R6 needs both; R7 needs R4's clock. R8 and R9 follow F's post-MVP
milestones.

## 15. The deleted nameserver prototypes: what to recover

**Recommended: recover no code.** L6 may delete `pow`, `transparency`, `anomaly`, the reputation,
tribunal, useful-work, receipt and attestation route groups and their tables.

| Module | Verdict | Why |
| --- | --- | --- |
| `pow.rs` | Delete | Keyed with a server secret; R1 replaces it with the admission PoW's construction, which is already in `jig-core` |
| Difficulty formula in `server.rs` | Delete code; keep the idea | The penalty points, step and multiplier are documented in the spec and the abuse-economics note. R1 replaces them with 5.6 |
| `transparency.rs` | Delete | Ad hoc Merkle over JSON strings, no inclusion or consistency proofs; R4 uses the C2SP formats |
| `anomaly.rs` | Delete | Receipt heuristics against a receipt format lane A is replacing; cross-checking receipts becomes evidence under R3's event codes |
| Reputation routes and aggregate | Delete | Weighted mean of a nameserver's own observations, the tier model D21 superseded |
| Tribunal case records | Delete; keep the outcome vocabulary | `sustain`, `modify`, `overturn`, `dismiss`, `escalate` carries into 8.4. Git history keeps the rest |
| Useful work | Delete | Unproposed as a reputation input; nothing in R needs it. Revisit with the distributed-OS phase's compute billing |
| `runtime.rs` (L6 marked F/R) | Delete | R does not need a nameserver that executes blocks |

The spec's tables that describe these routes change in the deletion PR (L6), not here.

## 16. Proposed spec and JEP changes

To land in R1's and R3's implementation PRs (framing lanes edit no existing files).

**`identity-and-reputation.md`:**

- *Proof-of-work:* replace the challenge-flow, difficulty-formula, penalties and rate-limiting
  subsections with R1's: one puzzle (5.1), three modes (5.3), linear effort, signed suggested
  effort (5.4), the stranger pool (5.5), standing-scaled effort within ruleset bounds (5.6), and
  the table of where PoW applies (5.7). Keep the existing MUSTs on single-use challenges and
  monotone penalties with decay; add "decay remembers repeat offenders" and "penalties key on
  (target, requester)".
- *Admission PoW:* restate as the `admit` action with an empty salt; the 28-bit cap becomes a
  `max_effort` of `2^28`.
- *Sybil resistance:* replace "Before the nameserver design is complete, a ruleset group MUST have
  an admission input …" with the sublinear-standing property (6.1) and its two mechanisms
  (6.2–6.3), and move soul validation under 6.4's opt-in rule.
- *Reputation is a number:* replace the reference nameserver's weighted mean with "a ruleset names
  its maths by id and version"; add servers report event codes; add the per-reporter cap.
- *Reputation is not a protocol gate:* replace with 7.4 once R3 ships.
- *Transparency log:* name the C2SP formats, witnessing within a group and subject commitments.
- *Tribunals and Reporting abuse in encrypted channels:* the seat rule (10.1), random panels,
  message franking (8.3), and the suite requirement to deliver the plaintext and `k_f` intact.

**`threat-register.md` (decision column):**

- AB-02: the wording in 5.8.
- AB-05: "Standing under a ruleset MUST be sublinear in compute: bounded by group-observed time
  and existing standing. Fresh identities share a capped stranger pool."
- AB-01: add "proof-of-work is bound to the verifier, subject, action and its binding".
- NS-02: add witnessed checkpoints.
- GV-02: "one seat per admitted operator".
- A new row, **AB-07, aged-key trading**, status Accepted, bounded (decided, Q2).
- PV-03: "No protocol message links two DIDs in the clear. The one exception is an invite's
  inviter tag, encrypted to a ruleset group's threshold key and opened only after a
  human-confirmed tribunal verdict, by decryption shares people release at the seat threshold
  (6.3)."
- PV-03 and the `--anon` section of `identity-and-reputation.md`: "An `--anon` key has no
  reputation. It is unknown under every ruleset for its whole session, and it can neither invite
  nor be invited."
- GV-01: automated-first seats; content cases get only provisional, expiring measures until
  people confirm them.

**JEP-0003 (Server Discovery), Specification section, "Reputation and PoW" row:** the stub stays a
stub for discovery. Replace the row's question with pointers:

> Proof-of-work: JEP-00NN (R1). Reputation, rulesets and reports: JEP-00NN (R2, R3). The
> handshake's `reputation` field carries the server's own standing under its declared ruleset
> (R3). Until R3 ships, reputation is not a security input (OP-10).

and add a "Governance" pointer to R6 and R8 (server lists). **Decided (DJ, Q10): three new
JEPs**, with numbers reserved by the orchestrator:

1. **JEP-0008**, proof-of-work and admission (R1);
2. **JEP-0009**, rulesets, reputation and transparency logs (R2, R3, R4, R7). The orchestrator
   assigned the logs here rather than to F3's JEP;
3. **JEP-0010**, reports, tribunals and server lists (R5, R6, R8).

**JEP-0001:** every suite JEP defines a report profile (8.3); lane S owns the edit.

**JEP-0005:** rule 15's "admission, proof-of-work and rate limits" gains a reference to R1's
stranger pool; rule 14b's list gains R's issuer and evidence rules (section 11).

## 17. Questions for DJ, and the answers (2026-10-18)

1. ~~What PoW is for (4, 5.8)~~ **Decided:** a price on strangers' capacity and an ordering under
   load, Tor-style, never an identity price.
2. ~~What "closed in full" means for Sybils (6.1, 6.5)~~ **Decided:** standing sublinear in
   compute; aged-key trading is a new AB-07, Accepted, bounded. Added by DJ: `--anon` forecloses
   reputation, so a server admitting it treats every such key as unknown; person-binding is an
   optional high-sec ruleset mechanism, never a protocol default, because taken far it stops a
   holder discarding a key.
3. ~~The stranger pool (5.5)~~ **Decided:** capacity partitioned by standing, a 20 % reference
   share for strangers.
4. ~~Admission PoW default (5.9)~~ **Decided:** on, adaptive, zero when idle, from R1, after the
   nameserver's binding endpoints carry PoW.
5. ~~Puzzle algorithm (5.2)~~ **Decided:** BLAKE3 hashcash with linear effort, algorithm agility;
   Equi-X only if R1's measurements justify it.
6. ~~Invites (6.3, 6.4)~~ **Decided:** invites by default, soul validation opt-in. DJ raised the
   insider swarm; the answer is the capped invited pool plus inviter tags encrypted to the
   seats' threshold key and opened only by verdict, with a PV-03 carve-out. A nameserver that sees
   both parties was considered and rejected: it would hold the group's invite graph (NS-03).
7. ~~Abuse reports (8.3)~~ **Decided, then revisited:** DJ first chose per-message key
   disclosure. Lane S found that openmls 0.9.1 cannot expose those keys, and DJ then chose
   **message franking**: a commitment in the author-signed, sequenced outer block, with its key
   inside the ciphertext and a check by the recipient at decrypt. Patching openmls and an inner
   signed envelope were rejected.
8. ~~Tribunal seats (10)~~ **Decided:** one seat per admitted operator. Added by DJ: seats are
   automated first, because tribunals must be fast enough to answer a concerted attack and
   operators cannot adjudicate full time. This gives the two tracks in 10.3: deterministic
   adjudication blocks with threshold verdicts, and only provisional, expiring measures for content
   cases until people confirm them.
9. ~~Encoding (8.1)~~ **Decided:** A5's deterministic CBOR with COSE_Sign1 for R's multi-field
   signed records; labelled hashing stays for flat statements and PoW digests.
10. ~~JEP split (16)~~ **Decided:** three JEPs; JEP-0003 points at them.

Still open, for later milestones:

- the verifiable-encryption and threshold scheme for inviter tags (R7).

Answered since: openmls does not expose per-message secrets (lane S, checked against 0.9.1),
hence franking (Q7).

Settled after the questions, through the orchestrator:

- transparency logs go in JEP-0009, not F3's JEP;
- the nameserver challenge mode binds F1's proof hash (5.1);
- an inviter tag opens only on a human-confirmed verdict (6.3). This is the tight reading of
  DJ's Q6 answer, needed because Q8 made seats automated first. DJ may override it.

The plain rate limit on the nameserver's `register`, `rotate` and `renew` is not a lane R question
(it is with DJ separately). R's view, for that decision: a rate limit per address and per signed
requester is needed with or without PoW (5.7), so adding it now costs nothing R would undo.

## Appendix A: sources

**[src]** the page was read in this pass; **[search]** confirmed from search results only;
**[recall]** from memory, unverified.

- Tor proposal 327, PoW over introduction circuits [search]:
  <https://spec.torproject.org/proposals/327-pow-over-intro.html>; hspow-spec, common protocol and
  v1 Equi-X [search]: <https://spec.torproject.org/hspow-spec/>; analysis and discussion (forged
  suggested effort) [search]: <https://spec.torproject.org/hspow-spec/analysis-discussion.html>;
  proposal 362, controller update [search]:
  <https://spec.torproject.org/proposals/362-update-pow-control-loop.html>
- Laurie and Clayton, "Proof-of-Work proves not to work" (2004) [search]:
  <https://www.cl.cam.ac.uk/~rnc1/proofwork.pdf>; Liu and Camp, "Proof of Work can Work" (WEIS
  2006) [search]: <https://sites.cs.ucsb.edu/~rich/class/cs293b-cloud/papers/lui-pow.pdf>
- Hashcash (Back) [recall]; Equihash (Biryukov and Khovratovich, NDSS 2016) [recall]
- Privacy Pass architecture, RFC 9576 [search]: <https://www.rfc-editor.org/rfc/rfc9576.html>;
  issuance, RFC 9578 [recall]; blind RSA, RFC 9474 [recall]
- ARC [search]: <https://datatracker.ietf.org/doc/html/draft-yun-privacypass-arc-00>,
  draft-ietf-privacypass-arc-crypto; ACT [search]:
  <https://www.ietf.org/archive/id/draft-schlesinger-cfrg-act-00.html>,
  <https://datatracker.ietf.org/doc/html/draft-schlesinger-privacypass-act-01>
- SybilLimit [search]: <https://www.comp.nus.edu.sg/~yuhf/yuh-sybillimit.pdf>; mixing-time
  critique and design-space survey [search]:
  <https://people.mpi-sws.org/~gummadi/papers/sybil_defense.pdf>; SybilGuard, SybilRank [recall]
- Matrix policy servers, MSC4284 [search]: <https://matrix.org/blog/2025/04/introducing-policy-servers/>;
  Draupnir and policy-list rooms [search]: <https://etke.cc/help/bots/draupnir/>; MSC2313 [recall]
- IFTAS denylist guidance [search]: <https://about.iftas.org/library/denylist-resources/>;
  Oliphant tiers and FediBlockHole retractions [search]: Seirdy, "Fediverse blocklists"
- CT gossip, draft-ietf-trans-gossip-05 [search]:
  <https://datatracker.ietf.org/doc/draft-ietf-trans-gossip/>; C2SP tlog-checkpoint,
  tlog-cosignature, tlog-witness, tlog-tiles [search]: <https://github.com/C2SP/C2SP/>; RFC 6962
  and RFC 9162 [recall]
- Message franking: Grubbs et al. (2017) [search]; Dodis et al., attachment franking
  [search]: <https://eprint.iacr.org/2019/016>; Tyagi et al., asymmetric franking, cited in
  [search]: <https://eprint.iacr.org/2021/1686>
- openmls 0.9.1: the secret tree is crate-private and processed messages expose no per-message
  secrets (lane S's source check, relayed by the orchestrator)
- Jøsang and Ismail, beta reputation system (2002) [recall]
