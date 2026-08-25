# jig-server authentication and authorization Design

**Date:** 2026-08-24
**Author:** DJ + Claude
**Status:** Approved (design); implementation not yet planned
**Closes:** [`docs/RELEASE_READINESS.md`](../../RELEASE_READINESS.md) blocker #1 — the last blocker gating external release.

## Goal

Give `jig-server` a real identity and access-control model, so a server is safe on a
public address the moment it boots.

Today there is none. `Frame::Subscribe` registers any scope for any connection with no
check; `GET /api/v1/channels/:slug/blocks` returns a channel's full timeline without ever
learning who is asking; `GET /api/v1/channels` lists every channel to everyone. The only
thing protecting a deployment is network placement — `deploy/README.md` says it outright:
"the tailnet IS the authentication".

That is not merely weak, it is **incompatible with how we tell people to install jig**.
The flagship KPI is `curl -fsSL https://jig.onl/install.sh | bash` onto any $5 VPS, so the
install flow itself puts servers on public addresses. In DJ's words: *"we don't want
tailnet to be the only transport available based on our intended install flow."*

A second, quieter goal: `jig channel create --visibility restricted` advertises
"membership-gated reads" in its `--help` text and delivers nothing. A user reading `--help`
is told they got a protection they did not get. This design makes that text true.

### Out of scope

- **End-to-end encryption.** Blocks remain signed, not encrypted. Separate blocker.
- **Proof-of-work and rate limiting.** The admission gate is the natural hook — the
  reputation model ties reputation to PoW difficulty and rate limits — but neither is
  specified here.
- **Policy blocks.** Admission is *shaped* as a pure function so it can later execute as a
  sandboxed Wasm block (see Architecture). Executing it that way is not built now.
- **Timing equivalence between disclosure outcomes.** A stated limitation, not a feature.
  See Known limitations.
- **Reputation scoring itself.** This design *consumes* a reputation view; it does not
  compute, store, or exchange reputation. See
  [`QUICK_NOTE_ON_REPUTATION_COMPATIBILITY.md`](../../../repos/jig-nameserver/QUICK_NOTE_ON_REPUTATION_COMPATIBILITY.md).

---

## Locked decisions

Each of these was decided during design; they are recorded here because the reasoning
matters more than the conclusion.

**1. Identity everywhere, transport-agnostic.** Every read and write carries a verifiable
DID identity. The mechanism must not be bound to WSS specifics — the envelope is
deliberately transport-agnostic (WSS now; SSH/gRPC/IRC preserved as future transports), so
whatever authenticates a caller has to survive changing the pipe. This rules out any design
leaning on connection semantics only WebSockets provide.

**2. Readers on `open` channels authenticate too.** "Anonymous" means
pseudonymous-and-unlinkable, not unauthenticated. A throwaway DID is free and already
minted at install.

The reasoning inverts the usual framing: **authentication protects anonymity rather than
opposing it.** DJ: *"if anyone can pretend to be you by duplicating your DID face-value
with no check on whether they hold the correct key, that creates a much paler anonymization
case than 'I have these identities but no one can tell it's me unless I tell them'."* A DID
without proof-of-possession is not an anonymous identity, it is an impersonable one.

Anonymity here attaches to the **holder** — a human, an agent, whoever holds the key — never
to a machine. Keys are expendable, registerable, and enrichable *at the holder's will and
nobody else's*. Keys are expected to **ablate under deanonymization pressure**, so minting
and discarding identities must stay cheap.

**3. No server owes anyone access.** Refusal is permitted at every gate, including refusing
a caller for being unknown. Two motivating cases:

- A DID with negative reputation — earned by, say, DDoS-ing servers in the network — has no
  guarantee of access to a server that can see that score.
- A members-only server may insist on reputation > 0. DJ's example: a bank's private-wealth
  client server. *"There's no world in which they'd like reputation-zero entities to have
  any access to the system they set up, for whatever purpose, and that's ok."*

Refusing unknown parties is a **feature**. DJ: *"the economics of creating a chicken-and-egg
problem by refusing to connect with unknown parties is a feature, not a bug (and a reason
for e.g. trusted common nameservers and sharing of reputation contracts across servers)."*
Reputation only has value if it can gate both access and privilege; that scarcity is what
creates demand for nameservers and cross-server reputation contracts.

**Key ablation is therefore preserved by the *network*, not by any single server.** A
freshly-minted DID can always find a server that admits unknowns. It is not entitled to any
particular one.

**4. Two mechanisms, chosen deliberately rather than grown into.** DJ: *"C is correct
because some form of B is inevitable."* Rather than ship per-request signing and bolt a
session fast-path on later — creating exactly the seam where auth bugs live — both paths are
designed together.

**5. Errors speak common internet parlance, and disclosure is a policy.** Gates produce HTTP
status vocabulary, and the server may misreport deliberately: *"just because a server throws
a 401 doesn't mean the server has to tell the user it was a 401."* This does not have to
fully land now, but must be **compatibly-built**.

---

## Architecture

### Three gates

The primary structure is three sequential gates. The two authentication tiers are only *how*
gate 1 is satisfied — they are not the top-level axis.

| Gate | Question | Nature |
|---|---|---|
| **1. Authenticate** | Do you hold the key for this DID? | Pure crypto; identical everywhere |
| **2. Admit** | Will this server talk to you at all? | Server-local policy; reputation-aware |
| **3. Authorize** | May you do this, here? | Channel membership and visibility |

**Admission runs before authorization, and the order is a security property.** A refused
caller must receive the admission outcome, never the authorization one — "you're not a
member" confirms the channel exists.

### Two authentication tiers

**Tier 0 — untrusted (per-request).** Every request carries
`sign(canonical_bytes ‖ HLC ‖ nonce)`, verified against a replay window. Requires no
connection lifetime, which is what makes SSH/gRPC/datagram transports work at all. This is
the tier that must exist for the design to be genuinely transport-agnostic.

**Tier 1 — trusted connection (capability).** A block-shaped handshake proves possession
once; the server issues a capability bound to exactly one DID. Subsequent requests present
the capability: one verification per connection rather than one per message.

A server may decline to offer tier 1 at all, per DJ: a fallback where *"every communication
is untrusted and trusted-connections aren't permitted."*

**Neither tier is unconditional.** Admission may refuse either.

### Why the handshake earns its place

Beyond performance, the tier-1 handshake is **the ruleset-acknowledgement point**. The
reputation model requires that *"no entity should lose reputation from another without first
seeing and acknowledging the ruleset they're participating with."* The handshake is the
natural place for that exchange — the server presents its ruleset keys, the client
acknowledges. A purely per-request scheme has nowhere to put that conversation.

This is an argument for the two-tier design that has nothing to do with throughput.

### Admission as a future policy block

DJ: *"Blocks authenticating their own request or a trusted connection need to be refusable
(ideally at the worker / function layer where compatible) based on server preference."*

Admission is therefore shaped as a **pure function** with no I/O, no clock, no network:

```
admit(did, reputation_view, request_kind) -> Admit | Refuse(reason)
```

Shaped this way it can later move into `jig-runtime` as a sandboxed, fuel-metered,
deterministic policy block — which is what makes reputation contracts genuinely shareable:
two servers running the same policy block reach the same verdict, and that is checkable
rather than promised. The machinery it needs (no-imports instantiation, fuel metering,
determinism) already exists, so this becomes a matter of routing a call.

**Build the seam now; do not build policy-block execution now.**

---

## Components

New module `repos/jig-server/src/auth/`, one file per gate, each within the 100–250 LOC
guideline:

| File | Responsibility |
|---|---|
| `authenticate.rs` | Proof-of-possession: per-request signature or capability validation |
| `admission.rs` | The pure `admit(...)` policy function |
| `authorize.rs` | Membership and visibility decisions for a channel |
| `disclosure.rs` | `GateOutcome → (status, code, message)`; the single classifier |

Changes to existing crates:

- **`repos/jig-pipeline/src/envelope.rs`** — add `status: u16` to `Frame::Error`, with
  `#[serde(default)]` so existing clients keep parsing. Today the frame carries
  `{ code, ref_cid, message }` and **no numeric status**, while the REST path already
  produces `(StatusCode, code, message)`. One vocabulary across transports requires this.
- **`repos/jig-config/src/v0_0_2_server.rs`** — an `[auth]` section beside the existing
  `[identity]` section, which already has the right shape (`mode`, `trusted_nameservers`,
  and an antipattern-named fallback flag).
- **`repos/jig-server/src/v0_0_2_blocks.rs`** — `list_channels` and `get_channel_history`
  run the gates. `list_channels` currently takes only `State` — no caller identity reaches
  it at all — and returns `slug`, `visibility`, **and `owner_did`** for every channel on the
  server. It leaks not just the existence of restricted channels but who owns them.
- **Delete `repos/jig-server/src/capability/`** — see below.

### Delete the existing `capability/` module

`repos/jig-server/src/capability/` is 442 LOC of HMAC-signed capability tokens, declared
`pub mod capability` in `lib.rs`, with **zero references from anywhere outside itself**. It
is entirely unwired.

It should be deleted rather than built upon. It is symmetric-secret based, which cuts
against the DID/ed25519 model the rest of the system uses, and leaving it in place invites a
future reader to mistake it for the foundation of this design. Its name will collide
conceptually with tier-1 capabilities, which are a different thing entirely.

### Reusing what already works

Two existing patterns are extended rather than reinvented:

- **`v0_0_2_admin.rs`'s owner check** already pairs signature verification with an
  authorization decision, returning 403 `NOT_CHANNEL_OWNER`, with a test proving a validly
  signed block from a different DID is still refused. That is gate 1 → gate 3 working
  correctly in one place; this design generalizes it.
- **`v0_0_2_ingest_error.rs`** is already *"the single place `IngestError` acquires an HTTP
  status and error code"*, written because two HTTP surfaces had independently drifted into
  classifying the same variant differently. Gate errors must not repeat that: one
  classifier, all surfaces.

---

## Error model

**Separate what happened from what we say happened.** Two types, never one.

- **`GateOutcome`** — the precise internal truth. Never crosses the wire.
  `AuthSignatureInvalid`, `AuthReplayed`, `AuthCapabilityExpired`,
  `AuthCapabilitySubjectMismatch`, `AdmissionUnknownDid`, `AdmissionBelowRuleset { key }`,
  `AdmissionBanned`, `AuthzNotMember`, `AuthzNotOwner`, `AuthzChannelUnknown`.
- **`Disclosure`** — server policy mapping `GateOutcome → (status, code, message)`.

In v0.0.x the default is the **identity mapping**: truthful. An obfuscating policy — for
example `RestrictedAsNotFound`, mapping every restricted-channel refusal to 404 — is a
different mapping requiring **zero call-site changes**. That is precisely what
"compatibly-built" buys, and why the types must be split now rather than when the feature is
wanted.

**Non-negotiable: logs and audit always record the true `GateOutcome`.** Obfuscation is
client-facing only. An operator who cannot distinguish a 401 from a 404 in their own logs
cannot run the server, and that is how a feature like this gets torn out six months later.

### `unknown` and `below-threshold` are different

Because reputation is ruleset-scoped key:value and never a scalar, any config predicate is
`(ruleset_key, minimum_score)` — and **the unknown-key case is its own explicit setting**,
never a consequence of a numeric comparison.

This is the specific bug the design guards against. If `unknown` silently resolved to
"below threshold", a holder who ablated a key under deanonymization pressure would land on a
fresh DID and be refused everywhere — the system would punish exactly the behaviour the
anonymity model requires. An operator refusing unknowns must be a *choice they made*, not a
side effect of a comparison.

---

## Data flow

One pipeline, entered identically from REST, WSS, or any future transport:

```
   envelope ─→ authenticate ─→ admit ─→ authorize ─→ execute ─→ disclose
                    │             │          │                      ▲
                    └─────────────┴──────────┴──────────────────────┘
                              GateOutcome carried forward
                         (log the truth, emit the policy mapping)
```

**Failures do not return early from their gate.** Each carries a `GateOutcome` forward to
the single disclosure point. This is what keeps the timing mitigation available later —
early-returning at different depths would foreclose it permanently.

### Replay defence

Tier 0 must reject a replayed signed request, which means remembering something. The design
uses an **HLC acceptance window** — default **±30 seconds**, configurable — plus a **bounded
LRU of nonces seen within it**, so memory is bounded by `rate × window` rather than by
history.

The window length is a genuine tradeoff: wider tolerates clock skew, narrower costs less
memory. At the 10,000 msg/s KPI a ±30s window implies retaining on the order of 300,000
nonces if every request is tier 0 — which is itself an argument for tier 1 on busy servers,
since capability-authenticated requests need no nonce at all. The LRU is bounded
independently of the window so that memory is capped even under flood; eviction inside the
window degrades to rejecting a replay-window miss rather than growing without limit.

### Capability contents

```
Capability { subject_did, issuer_did, expiry, sig }
```

Conspicuously **not** IP address, TLS session id, or connection 5-tuple. Writing the struct
with nothing transport-shaped in it makes "never bound to the pipe" a structural property
rather than something review must catch every time.

The rule this enforces: **the DID is the only correlator, and nothing may be tied to the
pipe.** A session bound to exactly one DID adds no linkage that DID does not already
provide. Linkage appears only if a session spans more than one DID, or is bound to transport
identity — the latter correlating the holder with something they never chose to reveal,
which is the deanonymization pressure keys are meant to ablate under.

### Subscriptions re-check at delivery

A WSS subscription authorized once at `Frame::Subscribe` would keep delivering for the whole
connection lifetime. If membership is revoked, or a channel flips to restricted, a
long-lived connection keeps receiving.

**Authorization is re-evaluated at fanout, not only at subscribe.** Otherwise revocation
silently fails for exactly the users an operator most wants to cut off. Short capability
TTLs bound the damage but are not the fix; delivery-time checks are.

---

## Configuration

An `[auth]` section in `jig-config`, beside `[identity]`:

- Whether tier 1 (trusted connections) is offered at all — supporting DJ's fallback where
  every communication is untrusted.
- Capability TTL.
- Replay window length.
- Admission policy: ruleset-scoped reputation predicates, plus an **explicit** setting for
  the unknown-DID case.
- Disclosure policy selection (default: truthful).

Per repo convention, any carve-out that weakens a guarantee is named loudly with a
`dangerously_` / `naively_` prefix and surfaces in `unsafe_options_active` via
`GET /.well-known/jig`.

---

## Testing

**For auth, the negative cases are the product.** The passing paths are trivial; all the
value is in what gets refused.

**Core convention: every gate needs a test where the previous gate passed.** A refusal test
that fails at the wrong gate proves nothing. The template already exists —
`archive_channel_rejects_a_non_owner` uses a *validly signed* block from a different
identity, so the signature check genuinely passes and the action is still refused.

**Gate order is itself tested.** A banned DID asking about a channel it is not a member of
must receive the admission outcome, never the authorization one.

Per gate:

- **Authenticate** — bad signature; replayed nonce; HLC outside window; capability issued to
  DID A presented by DID B; expired capability.
- **Admit** — unknown DID admitted when policy admits unknowns, refused when it does not; a
  reputation floor must **not** refuse an unknown DID via numeric comparison; a banned DID
  refused **at tier 0**, pinning that tier-0 access is refusable.
- **Authorize** — non-member read of a restricted channel refused; member read allowed; open
  channel readable by any admitted DID; `list_channels` filtered.
- **Disclose** — default policy truthful; an obfuscating policy maps restricted → 404 with no
  call-site changes; the log records the true outcome even when the wire says otherwise.

Two guardrail tests worth more than they look:

1. **The capability struct's serialized keys are asserted to be exactly
   `{subject_did, issuer_did, expiry, sig}`** — not for correctness today, but to fail loudly
   the day someone adds `client_ip` for debugging convenience and silently breaks the
   linkage rule.
2. **Revocation stops delivery on a live subscription** — subscribe, confirm delivery, revoke
   membership, assert delivery stops. No test that connects, checks, and disconnects will
   ever catch this.

Placement per repo convention: unit tests inline `#[cfg(test)]` per gate module; cross-gate
ordering and revocation as integration tests in `tests/`.

---

## Implementation phasing

This design is deliberately larger than one pull request. Landing it as a single change
would mean one enormous diff across the entire security surface, reviewed all at once — the
worst possible shape for this particular kind of work. The phases below each leave the tree
green and shippable.

| Phase | Content | Behaviour change |
|---|---|---|
| **1. Plumbing** | `GateOutcome` + `Disclosure` types, single classifier, `status` on `Frame::Error`, truthful default mapping. Delete the dead `capability/` module. | None — inert |
| **2. Authenticate** | Tier 0 per-request signing, replay window, config to require it | First real change; callers must sign |
| **3. Authorize** | Membership/visibility on reads, `list_channels` filtering, delivery-time re-check at fanout | Closes blocker #1's core hole |
| **4. Admit** | The pure `admit(...)` function and its config predicates | Servers can refuse callers |
| **5. Trusted connections** | Handshake, capability issuance and validation, ruleset acknowledgement | Adds the tier-1 fast path |

Phase 1 is inert on purpose: it establishes the types and the single disclosure point
without changing a single response, so the risky phases that follow are each small diffs
against a settled shape. Deleting `capability/` belongs here because it is already unwired —
removing it before the work starts stops anyone confusing it with tier-1 capabilities
mid-implementation.

Phases 2 and 3 together are the minimum that closes blocker #1. Phases 4 and 5 add policy
and performance respectively, and can be scheduled independently once the hole is shut.

## Known limitations

**Timing distinguishes what the status code conceals.** If the forbidden path performs a
membership lookup and the not-found path returns immediately, latency separates them
regardless of the code emitted. This design does not mitigate it; it only avoids
foreclosing a mitigation, by making the disclosure decision at one point after the work.
Response shaping should be implemented when the first obfuscating policy ships. Until then
the default mapping is truthful, so nothing is being concealed for latency to reveal.

**Obfuscation is only as strong as the most talkative endpoint.** A 404 hiding a channel's
existence is theatre if any other endpoint enumerates it. Every enumerating endpoint must
run the same gates — this design covers the ones that exist today, but the constraint binds
every endpoint added later.

**Performance is measured, not assumed, and only at one point.** ed25519 verification costs
**28.3 µs** — about 35,300/sec on one core, measured in release on an aarch64 M-series
laptop. At the protocol's 10,000 msg/s KPI, per-request verification is **28% of one core**
on that hardware; a $5 VPS is several times slower at crypto. This is the concrete reason
tier 1 exists. The number must be re-measured on real target hardware before any claim that
the KPI is met.

---

## Consequences for existing behaviour

- `jig channel create --visibility restricted` becomes true rather than decorative.
- `GET /api/v1/channels` stops listing channels the caller cannot see.
- Existing unauthenticated deployments break by design. Migration is an implementation-plan
  concern, not a design one, but it must be addressed there rather than discovered.
- `deploy/README.md`'s "the tailnet IS the authentication" statement must be rewritten when
  this ships.
