+++
jep = 0008
title = "Proof-of-Work and Capacity Pools"
status = "Draft"
type = "Standards Track"
category = "Security"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-18"
requires = ["0002", "0004"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

Proof-of-work in jig prices a stranger's use of capacity and orders strangers under load. It is
never a price on an identity. This JEP specifies:

- one puzzle that anyone can solve and verify from public information, bound to the verifier,
  the subject, the action and what the action acts on;
- three modes: admission, per-action stamps, and nameserver challenges;
- a signed, load-driven effort that is zero when the verifier is idle;
- capacity pools that keep a flood of fresh identities away from members;
- effort scaled by penalties and standing within ruleset bounds;
- where PoW applies at servers, nameservers and custodians.

Design record, prior art (Hashcash, Tor's onion-service PoW, Laurie and Clayton) and decisions:
[`docs/superpowers/specs/2026-10-18-reputation-pow-tribunals-framing.md`](../../../docs/superpowers/specs/2026-10-18-reputation-pow-tribunals-framing.md),
sections 4–5 and 17. Milestone R1.

**Draft.** DJ decided the design (framing doc questions 1, 3, 4 and 5). The parameter defaults are
lane R's and are to be measured in R1.

# Motivation

D23 makes PoW an obligation at servers and on nameserver binding endpoints. D26 keeps admission
PoW off by default until a design covers three things: registration at nameservers, challenges
anyone can solve, and what the cost buys against identity farming. Today:

- servers have one-time admission PoW (BLAKE3, bound to the server and the DID), off by default,
  at a static 20 bits when on;
- the nameserver's `register`, `rotate` and `renew` have no PoW;
- the nameserver's legacy PoW is keyed with a server secret, so only the secret's holder can solve
  or verify it.

A static difficulty does not buy much. Any effort a phone can afford is cheap for a GPU, and a
botnet pays nothing for it. So this JEP uses PoW where it works: to order and price strangers
under load. Capacity pools keep farmed identities away from members whatever the attacker
spends. Standing that compute cannot buy is JEP-0009's.

Non-goals:

- reputation maths, rulesets and invites (JEP-0009);
- tribunals and server lists (JEP-0010);
- volumetric network floods, which stay the operator's to absorb (JEP-0005 rationale).

# Specification

## Terms

1. The **verifier** is the party that checks the work: a server, a nameserver, or a custodian
   (JEP-0005 rule 21). It is named by its DID.
2. The **subject** is the DID asking, or the session key of an `--anon` identity.
3. An **action** is a registered label (rule 11). The action's **binding** is the bytes the work
   commits to for that action.
4. **Effort** `E` is an integer, at least 1: the expected number of **attempts** a solver makes
   under its algorithm. An attempt is one digest under `alg = 1`, and one tested solution under
   `alg = 2` (rule 8c).
5. **Members**, **invited** and **strangers** are the capacity pools (rules 20–25).

## The puzzle

6. The **digest** is the labelled BLAKE3 hash of these parts, in order. Each part is fed to one
   BLAKE3 hasher as its label's bytes, the value's length as an 8-byte little-endian integer,
   then the value's bytes:
   1. (`domain`, `jig-pow-v1`);
   2. (`alg`, the algorithm id as decimal ASCII);
   3. (`verifier`, the verifier's DID);
   4. (`subject`, the subject's DID or session key);
   5. (`action`, the action label);
   6. (`binding`, the action's binding, rule 11);
   7. (`salt`, the mode's salt, rule 13);
   8. (`nonce`, chosen by the solver, at most 64 bytes).
7. Work is **valid** for effort `E` when the first 8 bytes of the output of algorithm `alg`,
   read as a big-endian unsigned integer `d`, satisfy `d ≤ ⌊(2^64 − 1) / E⌋`.
   - For `E = 2^b`, this is the same test as "at least `b` leading zero bits".
8. **Algorithms.** `alg = 1` is the digest of rule 6 itself. `alg = 2` is Equi-X (rules 8a–8d).
   Further algorithms are registered by JEP amendment.
   - A verifier MUST state each `alg` it accepts, with that algorithm's effort, in a signed offer
     (rules 8e and 16).
   - A verifier MUST refuse work under an algorithm its offer did not name.
8a. **`alg = 2`, Equi-X.** It is tevador's Equi-X, the asymmetric, memory-bound puzzle that Tor
    uses for onion-service denial-of-service defence (Tor proposal 327, `hs pow v1`), over HashX.
    - Its **challenge** `C` is the 32-byte digest of rule 6, computed with `alg` = 2. The nonce
      is inside `C`, so a solver tries a new nonce to get a new challenge.
    - Solving `C` yields zero or more **solutions**. Each solution is eight 16-bit indices,
      encoded as 16 bytes, each index little-endian, as Equi-X encodes them.
    - Each solution `S` gives an **output**: the labelled BLAKE3 hash, as in rule 6, of
      (`domain`, `jig-pow-equix-v1`), (`challenge`, `C`) and (`solution`, `S`).
8b. **Validity under `alg = 2`.** Work is valid for effort `E` when both hold:
    1. the output passes rule 7's test for `E`; and
    2. `S` is a valid Equi-X solution for `C`.
8c. **One attempt is one tested solution.** A solver tests every solution of every challenge it
    solves against rule 7, so `E` is the expected number of solutions it tests. Equi-X yields
    about two solutions per challenge, so the expected number of solves is about `E / 2`.
8d. **The proof under `alg = 2`** is `{alg, effort, nonce, salt_id, solution}`. In JSON,
    `solution` is unpadded base64url of its 16 bytes. A proof under `alg = 1` carries no
    `solution`, and a verifier MUST refuse one that does.
8e. **Offering more than one algorithm.** An offer names a **primary** algorithm and its effort
    in the fields it has today (`alg`, `effort`), and MAY add `alts: [{alg, effort}]` inside the
    same signed object.
    - A client that understands an alternative MAY solve it instead of the primary. A client
      that understands none of them solves the primary.
    - A verifier accepts a proof under any algorithm its offer named, at that algorithm's effort.
    - Old clients read only `alg` and `effort`, so `alts` changes nothing for them.
8f. **Efforts across algorithms.** The controller (rule 17), length scaling and penalties
    (rules 18 and 26) work in `alg = 1` digests. The verifier converts the result for
    `alg = 2`:

    ```
    effort(alg 2) = max(1, ⌈effort(alg 1) / digests_per_solution⌉)
    ```

    - `digests_per_solution` is the number of `alg = 1` digests that cost the slowest client the
      verifier means to serve as much as one tested Equi-X solution (rule 19). It is measured,
      not derived (#337).
    - Both efforts in one offer therefore ask a phone for about the same time, and no other
      state is kept per algorithm.
9. **No secret.** Nothing in the puzzle is keyed. A solver MUST be able to compute it from the
   verifier's DID, its own key, the action's binding and the published salt alone. A verifier
   MUST NOT key the digest with any secret.
10. **The proof** is `{alg, effort, nonce, salt_id}` where `salt_id` names the salt (rule 13). A
    verifier checks it with one evaluation of the algorithm. It MUST check the work before any
    signature verification, database read or other costly step for the same request.
    - Under `alg = 2`, the verifier checks in this order, and stops at the first failure:
      1. the proof's shape and bounds, which cost nothing;
      2. rule 7's test on the output, which costs two BLAKE3 hashes (`C`, then the output);
      3. Equi-X verification of `S` for `C`, within the budget of rule 10a;
      4. only then any signature or store read.
    - `effort` is the solver's bid, at least the effort asked (rule 20). The verifier checks the
      work against the bid.
    - In JSON, `alg`, `effort` and `salt_id` are integers and `nonce` is unpadded base64url.

## Actions and bindings

10a. **Verification budget (`alg = 2`).** Step 3 costs far more than a digest, and at the small
     efforts `alg = 2` uses, step 2 is cheap to pass with a made-up solution. A verifier
     therefore bounds how often it runs step 3:
     - **Per address.** At most `equix_verifies_per_window` proofs from one address (IPv6 per
       /64) reach step 3 per `controller_window_secs`. Over that, the verifier refuses without
       running step 3, as `RATE_LIMITED`. This costs the sender nothing beyond the refusal, and
       charges no penalty.
     - **Per challenge.** In challenge mode, a challenge whose `alg = 2` proofs have failed step 3
       `max_failed_verifies` times is consumed, and the sender asks for a new one under the
       challenge rate limits.
     - A proof that fails step 3 charges the sender's address (rule 26), as any work that does not
       verify does.

     A botnet spreads across addresses and walks past the per-address bound. It is bounded by
     how fast it obtains challenges, and for `admit` and stamps by the server's capacity to spend
     on step 3. A verifier sets `equix_verifies_per_window` so that this capacity is a small
     share of one core.
11. Actions, their modes and their bindings:

    | Action | Verifier | Mode | Binding |
    | --- | --- | --- | --- |
    | `admit` | server | admission | empty |
    | `post` | server | stamp | the block's CID |
    | `kp-request` | custodian | stamp | the labelled hash of (`did`, the requested DID) and (`channel_id`) |
    | `dial` | server | stamp | the dialing server's DID |
    | `ns-register` | nameserver | challenge | `proof_hash("register", ns_did, alias, challenge)` (JEP-0004 rule 10) |
    | `ns-renew` | nameserver | challenge | `proof_hash("renew", ns_did, alias, challenge)` |
    | `ns-rotate` | nameserver | challenge | interim, until JEP-0004 gains a rotate proof: BLAKE3 of the deterministic CBOR map `{domain: "jig-alias-rotate-pow-v1", ns_did, alias, old_did, new_did, challenge}`, every DID canonical `did:jig` |

    For `ns-rotate`, the subject is the old DID, the key that holds the name.
12. A new action MUST be registered here with its mode and binding before any verifier asks for
    it.

## Modes and salts

13. Salts:
    - **Admission:** the salt is empty. One proof admits one subject at one verifier, once.
    - **Stamp:** the salt is the verifier's current **epoch salt**, 32 random bytes that the
      verifier rotates every `epoch_secs` on its own clock (TM-01). `salt_id` is the epoch number;
      epochs start at 1.
      The verifier MUST accept the current and the previous epoch, and no other.
    - **Challenge:** the salt is empty. The nameserver's challenge is inside the binding's proof
      hash, and JEP-0004 rule 10 makes it fresh and single-use.
    - The empty salt's `salt_id` is 0.
14. **Replay.**
    - Admission: the verifier records the subject as proven (as today). A second proof for a
      proven subject is redundant, not an error.
    - Stamp: the verifier MUST keep the digests of accepted stamps for two epochs and MUST refuse
      a digest it holds.
    - Challenge: consuming the challenge (JEP-0004 rule 10) is the guard.
15. The epoch salt and its epoch number are published in the verifier's signed welcome and
    `server-manifest` (JEP-0002, JEP-0005 rule 16) and in every refusal (rule 16).
    `/.well-known/jig` MAY repeat them as a hint, never as the authority.
    - The welcome's `admit` states admission's ask as `{alg, effort, salt_id, expires_at}`,
      with `alts` as in rule 8e:
      `salt_id` is 0, and `expires_at` (Unix seconds) is when the verifier stops promising to
      accept a proof at that `effort`. The field is absent when admission asks no work. A
      `salt_id` other than 0 contradicts the welcome.

## Effort: the controller and the refusal

16. A verifier that requires work for a request refuses it with `PROOF_OF_WORK_REQUIRED`, carrying
    `{action, alg, effort, alts?, salt_id, salt, expires_at}`, signed by the verifier's DID. A
    nameserver's challenge offer carries `alts` in the same way.
    - `effort` is the effort the request needs now (rule 18).
    - A client MUST verify the signature against the DID it pinned for the verifier, and MUST
      ignore an unsigned or wrongly signed effort.
17. **The controller.** For each action, the verifier keeps a **suggested effort** driven by its
    stranger queue (rule 23):
    - it MUST NOT rise while the queue is below its target;
    - it MUST decay towards zero while the queue drains;
    - at zero, the verifier asks no work for that action. The request proceeds as if a proof were
      given, except under a ruleset floor (rule 19).

    The control algorithm is local. This JEP fixes its inputs and its bounds, not its shape.
18. **Effort for one request:**

    ```
    E = clamp( suggested(action)
               × m_penalty(target, requester)
               × m_standing(subject),
               min_effort(action), max_effort(action) )
    ```

    The terms are defined in rules 26–28. A product that rounds below 1 means no work, unless
    `min_effort ≥ 1`.
    - Where `min_effort(action) ≥ 1`, the floor is taken before the multipliers:
      `suggested(action)` above is `max(min_effort(action), suggested(action))`.
    - A name action (`ns-register`) MAY multiply by a target-dependent
      `m_length = short_name_factor ^ max(0, short_name_len − len(alias))`.
19. **Bounds.** `min_effort`, `max_effort` and `max_solve_secs` per action are ruleset
    parameters (JEP-0009). Without a ruleset they are server configuration.
    - A verifier MUST set `max_effort(action)` so that the slowest client it means to serve finishes
      within `max_solve_secs`.
    - A verifier MUST NOT ask for more than `2^28` for `admit`, or `2^28` for any challenge action,
      under `alg = 1`. Under `alg = 2`, the cap is `⌈2^28 / digests_per_solution⌉`.
    - A client SHOULD refuse an effort above those caps.
    - A verifier cannot measure its clients, so a client SHOULD also derive its own cap from its
      measured solve rate × `max_solve_secs`, by a short calibration run on the cores it will
      solve with, and refuse an effort above that cap as it would one above `2^28`.
    - A ruleset MAY set `min_effort ≥ 1` (a floor). The reference ruleset sets none.
19a. **Units.** Every parameter of this JEP is an integer, and none is a float:
     - efforts (`min_effort`, `max_effort`, the controller's start) are counts of `alg = 1`
       digests (rule 8f);
     - `digests_per_solution` is a count of `alg = 1` digests;
     - budgets (`equix_verifies_per_window`, `max_failed_verifies`, `queue_len`) are counts;
     - shares are percentages, as rule 23 states them;
     - times are seconds on the verifier's own clock, in keys ending `_secs` (TM-01).

     PoW stays on the verifier's clock: it is local admission policy, not a computation others
     check. JEP-0009 rule 52's units bind only what `f` reads.
20. **Client behaviour.** A client:
    - bids at least the signed `effort`;
    - on another refusal for the same request, doubles its bid, up to `max_effort`;
    - then stops and tells the holder the verifier is under load, instead of retrying forever.

    Effort above the required value buys priority in the queue (rule 23), not admission past a
    quota.

## Capacity pools

21. A server MUST divide the capacity it gives to clients into three pools:
    - **members:** subjects at or above the ruleset's `established` standing (JEP-0009). Until
      JEP-0009, membership is the server's local policy, such as DIDs in its admission records,
      or DIDs it has dealt with for `local_member_age` without a penalty, on its own clock;
    - **invited:** subjects admitted on an invite (JEP-0009) whose standing has not yet reached
      `established`;
    - **strangers:** everyone else.

    Capacity here means accepted writes per second, live subscriptions and handshakes.
22. Unknown subjects and every `--anon` session key are strangers. An `--anon` key has no
    standing under any ruleset and never leaves the stranger pool. Being in the stranger pool is
    not a refusal: no reputation floor applies to an unknown subject.
23. The stranger pool gets at most `stranger_share` of capacity, and the invited pool at most
    `invited_share`. Both are ruleset parameters. The reference values are 20 % and 10 %.
    - Members MUST NOT wait on the other pools.
    - **Aged-proof members** (JEP-0009 rule 49) draw from at most `aged_share` of the member pool
      (ruleset parameter; reference 25 %). Established members draw from all of it. A farm
      that solves many admission proofs at once and waits out their age once becomes members
      together, so the bound is on capacity, not on count: it cannot crowd out members who
      earned their standing.
    - Capacity a pool leaves unused MAY be lent to another pool while it is idle, and lending MUST
      stop at the owner pool's first request.
    - A pool is idle after `idle_secs` (reference: 1 s) without a request of its own, and lends
      at most what it holds above half its burst. So an owner pool that resumes has at least half
      its burst at once, and all of its rate from then on: lent capacity is spent, not recalled,
      and this reserve is what "MUST NOT wait" guarantees.
    - Within the stranger pool, requests pass per-DID and per-address rate limits first, then wait
      in a queue served highest effort first.
24. A nameserver applies rules 21–23 to its binding endpoints. `ns-register` is always a stranger
    action; `ns-renew` and `ns-rotate` by the current holder of a name are member actions.
25. A custodian applies them to key-package requests: requests from the DID's contacts are member
    requests, and all others are stranger requests.

## Penalties and standing

26. **Penalties** key on the pair (target, requester).
    - The target is what the request acts on: the name, the alias scope or the subject.
    - The requester is the DID that signed the request.
    - A refused or invalid proof adds a point to the pair, and to the requester's address bucket.
    - A failure before the requester's signature is verified charges the address bucket only.
    - `m_penalty` rises monotonically with points, up to `max_penalty_multiplier`.
27. **Decay remembers repeat offenders.** Points decay one per `decay_secs`. Each new offence
    inside the ruleset's `offence_window` doubles that key's `decay_secs`, up to
    `max_decay_secs`. A clean window resets it.
28. **Standing** scales effort only within the ruleset's bounds:
    - `m_standing = 1` for unknown subjects, for `--anon` keys, and for anything below
      `established`;
    - above `established`, it falls linearly to `1 / max_standing_discount` at the top of the
      scale;
    - for a negative standing, it is greater than 1, up to `max_penalty_multiplier`.

    Standing never lowers the price for a subject without standing.

## Where PoW applies

29. A server MUST:
    - ask `admit` of a subject it has no record of, whenever the suggested effort for `admit` is
      above zero or a floor applies;
    - ask `post` stamps of strangers while the stranger pool is loaded;
    - ask `dial` stamps of servers that are not its configured peers, once open federation
      exists. In v0.2, unlisted servers are refused (JEP-0005 rule 17).
30. A server MUST NOT ask any work of the authors of blocks a federated peer relays, or a bridge
    submits. The relaying peer or bridge pays at its own ingress, and its quotas apply (AB-03,
    JEP-0005 rule 15).
31. A nameserver MUST ask challenge-mode work on `ns-register`, `ns-renew` and `ns-rotate`. The
    proof travels in the request's `pow` object, which JEP-0004 requests carry from F1 on.
    - It MUST rate-limit challenge issuance per address and per signing requester.
    - Issuing a challenge MUST stay cheaper than verifying a proof.
32. A custodian MUST ask `kp-request` stamps of strangers while its stranger pool is loaded.

## Defaults

33. The reference server sets `[auth.admission] unknown_dids = "proof-of-work"` by default, with
    the controller of rule 17 and no floor. Admission is therefore free while the server is idle.
    This default ships only once rule 31 is implemented (D26).
    - **D26 resolved (DJ, 2026-10-25):** rule 31 is implemented, but the reference server keeps
      `unknown_dids = "admit"` by default until R2's earned standing (local earned standing,
      R2.4) lands. The controller of rule 17 ships now, used by any server that opts into
      `"proof-of-work"`; the default switches to it, with no floor, in the same release as R2.4.

# Security Considerations (Zero-Trust)

**Threats addressed:**

- **AB-01, replay and theft.** Work is bound to the verifier, subject, action and binding. Stamps
  are single-use within two epochs, and challenges are consumed.
- **AB-02, botnets.** PoW is not an identity price. A flood of fresh identities, however cheaply
  solved, reaches only the stranger pool and what idle pools lend it (rule 23). A member's first
  request stops the lending, and members keep at least half their burst; strangers are slowed.
- **Griefing.** Penalties key on (target, requester), so a third party cannot raise a victim's
  price.
- **Forged load signals.** The effort is signed and checked against the pinned DID (rule 16).
- **Precomputation.** Stamps are bounded to one epoch. An admission can be precomputed, but that
  only moves the same cost earlier.
- **Verifier exhaustion.** Under `alg = 1`, checking work costs one digest and comes before every
  costly step (rule 10). Under `alg = 2`, the target test costs two digests. The Equi-X check
  costs much more, so it is bounded per address and per challenge (rule 10a).
- **TM-01.** Epochs and decay run on the verifier's clock.

**Residual risks:**

- Honest newcomers are slowed while the stranger pool is under attack. JEP-0009's invites let a
  newcomer use the invited pool instead.
- A GPU-equipped attacker gets far more stranger-pool priority per unit of cost than a phone
  under `alg = 1`. Equi-X narrows that gap, but only where the verifier stops offering `alg = 1`.
  While both are offered, the attacker picks the one that suits its hardware (rule 8e).
- **Equi-X is memory-bound, not strongly memory-hard.** It uses about 2 MB per solve, so it fits
  in a CPU cache. Its GPU resistance comes mostly from HashX's random programs, one per challenge.
  An FPGA or ASIC for HashX is possible in principle. None is known, and no break of Equi-X has
  been published to date. A break would be met by registering a new `alg`, as rule 8 allows.
- **A shared address shares the Equi-X budget.** Everyone behind one carrier-grade NAT or one
  /64 draws on the same `equix_verifies_per_window` (rule 10a), so one flooder there can spend it
  for all of them. They are refused `RATE_LIMITED` with no penalty. While `alg = 1` is offered,
  they can fall back to it. On a verifier that has dropped `alg = 1` (migration step 3), they wait
  for the next window.
- **Clients without the HashX compiler** solve with an interpreter, which is several times slower:
  browsers and Wasm hosts, and platforms that forbid JIT code, such as iOS. They pay more under
  `alg = 2` than under `alg = 1`. Verification is cheap with or without the compiler, so small and
  Wasm-hosted verifiers are not affected.
- Before JEP-0009, membership is local policy, so a new server has few members and its stranger
  pool carries most of its traffic.

**Privacy:** a proof carries only what the request already carries (the subject, the binding) and
a nonce. No message links two DIDs.

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- Admission proofs under `jig-admission-pow-v1` stay valid for subjects a server has already
  recorded as proven. A server MAY accept new proofs in the old form until R1 ships in a release,
  where a bit count `b` is effort `2^b`.
- The nameserver's legacy keyed PoW (`/v1/challenge` POST, `/v1/claim`, `/v1/alias`) is removed
  with those routes (lane L6), not migrated.
- `admission_pow_bits` in `/.well-known/jig` is replaced by the signed effort and salt of rule 15.
- **Migration to `alg = 2`**, in three releases. Each step is a verifier default, not a protocol
  change, because rule 8e lets old and new clients share one offer:
  1. **Alternative.** Clients learn `alg = 2`. Verifiers MAY add it as an `alts` entry. The
     primary stays `alg = 1`, so every client still works.
  2. **Primary.** The reference verifiers offer `alg = 2` as primary and `alg = 1` as an
     alternative. A client solves `alg = 2` whenever it is offered, unless it has no HashX
     compiler and the `alg = 1` alternative is cheaper for it.
  3. **Sole.** The reference verifiers stop offering `alg = 1` by default. An operator MAY keep
     it, and accepts that a GPU then picks it. Without it, clients behind a shared address lose
     their fallback when a flooder there spends the Equi-X budget (rule 10a).

  Each step needs `digests_per_solution` measured on #337's set-up first.

# Reference Implementation

`jig_core::pow` (milestone R1): the digest, the effort test, the solver and the proof. The
verifiers that ask for work are built on it in R1's later tasks.

`alg = 2`: not yet implemented. The reference implementation would use the `equix` and `hashx`
crates from the Tor Project's Arti, which are pure Rust and dual MIT/Apache-2.0. The licence
needs `cargo deny` to pass when the dependency is added.

# Test Vectors

`vectors/0008/vectors.json`:

- one proof per action in rule 11, with its inputs, digest and effort;
- the boundary of rule 7 for `E = 2^20` and for an effort that is not a power of two.

`vectors/0008/ns-pow.json`: a nameserver's signed offer (`jig-ns-pow-offer-v1`), which it
returns with a challenge and restates in its `428` refusal, and the interim `ns-rotate` binding.

To add with `alg = 2`:
- one proof per action, with `C`, `S`, the output and the effort;
- a proof whose output passes rule 7 but whose solution is invalid;
- an offer with `alts`, and the conversion of rule 8f for one `digests_per_solution`.

# Rejected Alternatives

- **PoW as the price of an identity.** Any effort a phone tolerates is cheap for a GPU and free for
  a botnet (Laurie and Clayton, 2004).
- **A static default difficulty.** Every honest newcomer pays it, and attackers ignore it.
- **A keyed digest.** Only the key holder can solve or verify, so no third-party client can comply
  (D26).
- **Argon2 and other puzzles that are as slow to verify as to solve.** The verifier becomes the
  target.
- **RandomX.** Verifying it costs as much as hashing, and needs a 256 MB cache.
- **Equihash at its common parameters**, (200,9) and (144,5). ASICs exist for both. Its verification
  is cheap, but the hardware gap it was meant to close is already gone.
- **Cuckoo Cycle and Cuckatoo.** Verification is cheap (42 edges), but the larger graph sizes are
  tuned for ASICs, and the memory they need is too much for a phone. The Cuckaroo variants favour
  GPUs.
- **Argon2 with Merkle proofs (MTP).** It makes a memory-hard function verifiable, but published
  time-memory trade-offs weaken it (Dinur and Nadler, 2017), and its proofs are large.
- **Equi-X as the only algorithm, now.** It narrows the GPU gap but does nothing against botnets.
  Clients without the HashX compiler solve it slowly. It is registered as `alg = 2` beside
  `alg = 1`, and migration retires `alg = 1` only by default (Backwards Compatibility).
- **Refusing unknown subjects under load.** That makes unknown mean low, which punishes the key
  discarding that the anonymity model depends on.

# Copyright

This document is licensed under CC-BY-4.0.
