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
4. **Effort** `E` is an integer, at least 1: the expected number of digests a solver computes.
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
8. **Algorithms.** `alg = 1` is the digest of rule 6 itself. Further algorithms are registered by
   JEP amendment; Equi-X is the candidate if R1's measurements justify it.
   - A verifier MUST state the `alg` it requires with the effort (rule 16).
   - A verifier MUST refuse work under an algorithm it did not ask for.
9. **No secret.** Nothing in the puzzle is keyed. A solver MUST be able to compute it from the
   verifier's DID, its own key, the action's binding and the published salt alone. A verifier
   MUST NOT key the digest with any secret.
10. **The proof** is `{alg, effort, nonce, salt_id}` where `salt_id` names the salt (rule 13). A
    verifier checks it with one evaluation of the algorithm. It MUST check the work before any
    signature verification, database read or other costly step for the same request.
    - `effort` is the solver's bid, at least the effort asked (rule 20). The verifier checks the
      work against the bid.
    - In JSON, `alg`, `effort` and `salt_id` are integers and `nonce` is unpadded base64url.

## Actions and bindings

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
    - The welcome's `admit` states admission's ask as `{alg, effort, salt_id, expires_at}`:
      `salt_id` is 0, and `expires_at` (Unix seconds) is when the verifier stops promising to
      accept a proof at that `effort`. The field is absent when admission asks no work. A
      `salt_id` other than 0 contradicts the welcome.

## Effort: the controller and the refusal

16. A verifier that requires work for a request refuses it with `PROOF_OF_WORK_REQUIRED`, carrying
    `{action, alg, effort, salt_id, salt, expires_at}`, signed by the verifier's DID.
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
    - A verifier MUST NOT ask for more than `2^28` for `admit`, or `2^28` for any challenge action.
    - A client SHOULD refuse an effort above those caps.
    - A verifier cannot measure its clients, so a client SHOULD also derive its own cap from its
      measured solve rate × `max_solve_secs`, by a short calibration run on the cores it will
      solve with, and refuse an effort above that cap as it would one above `2^28`.
    - A ruleset MAY set `min_effort ≥ 1` (a floor). The reference ruleset sets none.
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
    - Capacity a pool leaves unused MAY be lent to another pool while it is idle, and MUST be
      returned when its owner pool has demand.
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

# Security Considerations (Zero-Trust)

**Threats addressed:**

- **AB-01, replay and theft.** Work is bound to the verifier, subject, action and binding. Stamps
  are single-use within two epochs, and challenges are consumed.
- **AB-02, botnets.** PoW is not an identity price. A flood of fresh identities, however cheaply
  solved, reaches only the stranger pool (rule 23). Members are unaffected; strangers are slowed.
- **Griefing.** Penalties key on (target, requester), so a third party cannot raise a victim's
  price.
- **Forged load signals.** The effort is signed and checked against the pinned DID (rule 16).
- **Precomputation.** Stamps are bounded to one epoch. An admission can be precomputed, but that
  only moves the same cost earlier.
- **Verifier exhaustion.** Checking work costs one digest and comes before every costly step
  (rule 10).
- **TM-01.** Epochs and decay run on the verifier's clock.

**Residual risks:**

- Honest newcomers are slowed while the stranger pool is under attack. JEP-0009's invites let a
  newcomer use the invited pool instead.
- A GPU-equipped attacker gets far more stranger-pool priority per unit of cost than a phone.
  Algorithm agility (rule 8) is the answer if R1's measurements show it matters.
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

# Reference Implementation

`jig_core::pow` (milestone R1): the digest, the effort test, the solver and the proof. The
verifiers that ask for work are built on it in R1's later tasks.

# Test Vectors

`vectors/0008/vectors.json`:

- one proof per action in rule 11, with its inputs, digest and effort;
- the boundary of rule 7 for `E = 2^20` and for an effort that is not a power of two.

`vectors/0008/ns-pow.json`: a nameserver's signed offer (`jig-ns-pow-offer-v1`), which it
returns with a challenge and restates in its `428` refusal, and the interim `ns-rotate` binding.

# Rejected Alternatives

- **PoW as the price of an identity.** Any effort a phone tolerates is cheap for a GPU and free for
  a botnet (Laurie and Clayton, 2004).
- **A static default difficulty.** Every honest newcomer pays it, and attackers ignore it.
- **A keyed digest.** Only the key holder can solve or verify, so no third-party client can comply
  (D26).
- **Argon2 and other puzzles that are as slow to verify as to solve.** The verifier becomes the
  target.
- **Equi-X as the only algorithm, now.** It narrows the GPU gap but does nothing against botnets,
  and its HashX JIT is a poor fit for potato-class and Wasm-hosted servers. It stays a candidate
  under rule 8.
- **Refusing unknown subjects under load.** That makes unknown mean low, which punishes the key
  discarding that the anonymity model depends on.

# Copyright

This document is licensed under CC-BY-4.0.
