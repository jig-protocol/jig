+++
jep = 0007
title = "Capabilities, block state and nesting"
status = "Draft"
type = "Standards Track"
category = "Core"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-18"
requires = ["0006", "0011"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

This JEP defines what a block may do beyond computing a value:

- one capability vocabulary, named by WIT interface, with typed scopes and an attenuation order;
- who grants a capability, and how a host enforces it;
- the `jig:host` imports and the effects a `bot` returns;
- per-install bot state, bot identities, timers;
- nesting: a block invoking declared children with attenuated authority and the parent's budget.

It builds on JEP-0006, which defines the `jig:block` worlds, the determinism profile `jig-det-1`,
run outcomes and the v0.3 receipt.

**Draft status.** The maintainer approved the design on 2026-10-18 (decisions C1–C8 in the
[design doc](../../../docs/superpowers/specs/2026-10-18-v0.3-capabilities-state-nesting-design.md),
which holds the options and rationale). Nothing here is implemented. Names marked *(L7)* or
*(F)* come from the handshake and federation JEPs and follow them if they change.

# Motivation

- Phase 2's exit criterion (`ROADMAP.md`) needs a nested block that composes with capability
  attenuation verified by tests.
- Threat-register AB-04 requires that a block holds only the capabilities its manifest names,
  attenuated at each level, with no ambient authority. Nothing enforces that today.
- Three capability vocabularies disagree, and none names fetch-by-CID or a timer.

Non-goals: network fetch and other effects that cannot be re-executed; capabilities passed in
messages (phase 6); the UI ABI; pricing; bots in encrypted channels.

# Specification

The key words MUST, MUST NOT, SHOULD and MAY are as in RFC 2119.

## 1. Vocabulary

1. A capability name is `<package>/<interface>[.<effect>]@<semver>`. An import capability names a
   WIT interface; an effect capability names an interface and an effect variant.
2. A host MUST match package and interface exactly, and the version by semver compatibility
   (same major; same minor while `0.x`). A host MUST refuse a manifest naming a capability it does
   not know.
3. Each capability has a scope schema. Every scope field has one of three types:

   | Type | `a ⊑ b` | `a ⊓ b` |
   | --- | --- | --- |
   | set | `a ⊆ b` | `a ∩ b` |
   | quota (or floor) | `a ≤ b` (`a ≥ b`) | `min` (`max`) |
   | flag | `a ⇒ b` | `a ∧ b` |

   A capability absent from a grant is bottom. A host MUST refuse a scope with a field its schema
   does not define.
4. The v0.3 vocabulary:

   | Name | Kind | Scope |
   | --- | --- | --- |
   | `jig:host/blocks@0.1.0` | import | `channels: set<channel-id>`, `cids: set<cid>`, `max_bytes: quota`, `max_calls: quota` |
   | `jig:host/compose@0.1.0` | import | `children: set<cid>`, `max_depth: quota`, `max_calls: quota` |
   | `jig:host/effects.post@0.1.0` | effect | `channels: set<channel-id>`, `per_invocation: quota`, `per_hour: quota` |
   | `jig:host/effects.state@0.1.0` | effect | `max_bytes: quota` |
   | `jig:host/effects.timer@0.1.0` | effect | `min_interval_ms: floor`, `max_horizon_ms: quota` |

   A `channel-id` is the CID of the channel's `channel-create` block *(F)*.

## 2. Authority

1. A block's **effective authority** is `request ⊓ grant ⊓ policy`:
   - *request*: the `requests` of its signed program manifest (JEP-0011);
   - *grant*: for a root bot, the `grant` of its `block-install` (§4); for a child, its parent's
     offer (§7);
   - *policy*: what the host's operator allows (JEP-0006 Q7: empty by default).
2. For a child, `effective(child) = request(child) ⊓ offer(parent → child) ⊓ effective(parent)`.
3. A manifest request alone grants nothing.
4. Execution policies (the operator's, a channel's `channel-policy` and a client's own allow and
   deny lists; JEP-0011) decide only whether code runs. They grant no authority, and none of them
   can make another party's host execute anything.

## 3. Enforcement

1. **At install and at upload,** a host MUST refuse a component whose imports are not a subset of
   the interfaces its effective authority names plus `jig:block/types`, and any `wasi:*` import
   (`jig-det-1`).
2. **At link time,** a host MUST instantiate a block with a linker that defines `jig:block/types`
   as an empty instance (it carries types only; every wit-bindgen component imports it) and
   otherwise only the interfaces in its effective authority. This applies to every world,
   `renderer` included. A host MUST NOT define missing imports as traps or stubs. A failed
   instantiation makes the run `incomplete` with reason `capability-refused`.
3. **At call time,** every `jig:host` function MUST check its arguments against the scope before
   acting. A refusal is returned to the block as an error value.
4. **At apply time,** the host MUST check each returned effect against the effective authority
   before applying it. A refused effect does not change the run's outcome; the receipt records it
   under `applied` with the reason.
5. All four points fail closed.

## 4. Installs and bot identity

1. A `block-install` is signed by the channel's owner alone, as a COSE_Sign1, and carries the
   owner's `seq` and `prev`. Nobody else can sign one. Its payload names: `block` (the bot's
   program CID, JEP-0011), `channel` (a `channel-id`), `grant`, `bot_did`, `bot_key`, `triggers`
   (what invokes the bot), and optionally `inherits_state_from` (an earlier install).
2. The hosting server approves it with a separate **`policy-approval`** (JEP-0011, the same object
   it issues for a `channel-policy`): a COSE_Sign1 of `{domain: "jig-policy-approval-v1", server,
   channel, object_cid, restrictions_cid, bot_did}`.
   - `object_cid` is the install's CID. `restrictions_cid` names the operator policy (§2.1) and
     the server's restrictions the install was checked against (JEP-0011 §5.3.3).
   - `bot_did` MUST be present in an approval of a `block-install` and absent otherwise. It states
     that the server holds the private key for `bot_did` (SC-04). A verifier MUST check that it
     equals the install's `bot_did`, and treat the approval as invalid if not.
   - The **current** approval is read from the channel's `ingest` chain: the latest
     `policy-approval` or `policy-withdrawn` for that install CID, in ingest order, wins, and a withdrawal stands until a newer approval. The approval carries no `seq` or `prev` of its own.
   - The server MUST withdraw the approval of an install that no longer passes its restrictions.
     Withdrawal and re-approval need nothing from the owner.
   - A host MUST NOT invoke a bot whose install has no current approval, and a client MUST treat
     such an install as absent.
3. The install's CID is the **instance id**. A host MUST refuse an install whose `grant` is not
   `⊑` the program's `requests`, or whose program is outside operator policy.
4. A bot's posts are blocks authored by `bot_did` and MUST go through `ingest` like any write.
   Their manifest carries `produced_by: {instance, invocation}`.
5. A host MUST NOT invoke a bot on its own posts, and MUST NOT invoke a bot from a post whose
   `produced_by` chain is 4 or more bot hops long.
6. The channel's home server *(F)* is the only server that runs its bots. Other servers receive
   their posts as ordinary blocks.

## 5. State

1. `handle(inv: invocation, state: list<u8>) -> result<handled, block-error>`, with
   `record handled { effects: list<effect>, state: option<list<u8>> }` (JEP-0006 `bot` world).
2. `state_cid = blake3(state)`. The incoming `state_cid` is part of the run's identity.
3. A returned state larger than `effects.state.max_bytes` is a refused effect. The default cap is
   64 KiB; a host MAY lower it, and MUST NOT raise it above 1 MiB.
4. A run that is `error` or `incomplete` changes no state and applies no effects. State and effects
   commit together.
5. The `exec` receipt of a bot run carries `instance`, `state_before` and, if changed,
   `state_after`. Successive receipts of one instance MUST chain: each `state_before` equals the
   previous `state_after`.
6. Invocations are ordered by their triggers' `ingest.seq` *(L7)*, and each receipt names its
   trigger's `ingest` record.

## 6. Host functions and effects

### fetch (`jig:host/blocks`)

1. `fetch(cid) -> result<payload, fetch-error>`, where `fetch-error` is `not-found`,
   `not-granted` or `too-large`.
2. A host MUST verify that the returned bytes hash to `cid`, and return `not-found` otherwise.
3. A host MUST return a block only if its CID is in scope `cids`, or it lives in a channel in
   scope `channels`. A host MUST NOT return a block from a channel whose suite is not `none`.
4. Every call and its answer is recorded in the receipt's `fetches`. A re-executor replays the
   recorded answers.

### post (`effects.post`)

`post { channel: channel-id, payload }`. Applied per §4.4.

### timer (`effects.timer`)

1. `set-timer { after_ms: u64, tag: list<u8> }` replaces the instance's pending timer;
   `cancel-timer` clears it. An instance has at most one pending timer.
2. When the timer is due, the home server authors a `timer-fire` block with its own DID and
   ingests it. Its manifest names `install`, `set_by` (the arming run's receipt), `scheduled_at`
   (`set_by`'s `ingest.ingest_hlc` plus `after_ms`) and `tag`.
3. The fire invokes `handle` with `tag` as input and the fire's `ingest.ingest_hlc` as the
   invocation clock.
4. A missed fire fires once on recovery.
5. A `timer-fire` is the home server's word alone. Clients SHOULD check it against `set_by`, the
   install's bounds and the instance's chain, and surface a mismatch.

### Invocation clock

The invocation's HLC MUST be the triggering block's `ingest.ingest_hlc` *(L7)*, never the
author's `hlc_ts`.

## 7. Nesting (`jig:host/compose`)

1. `invoke(cid, input: payload) -> result<payload, invoke-error>`, where `invoke-error` is
   `not-declared`, `failed(hash)` or `trapped`.
2. A parent's program manifest declares `children: [cid…]` (program CIDs) and `offers: {cid:
   grant}`, so the parent's program CID pins the whole tree. A host MUST refuse to invoke an
   undeclared CID, and MUST compile and validate the whole declared closure before
   the root's first run.
3. A child is a separate component instance linked per §3 with its own effective authority
   (§2.2). Children are stateless in v0.3 and return a payload, not effects. A `renderer` MAY
   import `compose` for children that are themselves renderers.
4. Children run in the root's store. Fuel comes from the root's counter, and a per-child cap MAY
   be set from it. Memory across the tree is bounded by the root's limit. Host quotas consumed by
   a child count against the root's.
5. Fuel, stack or epoch exhaustion anywhere in the tree makes the root's run `incomplete`. A
   child's `err(block-error)` and deterministic traps are returned to the parent as `failed` or
   `trapped`.
6. Depth is at most 4 below the root. A host MAY set a lower limit.
7. A host MUST reserve the tree's worst-case instance slots at admission, all or nothing, and
   refuse at upload a tree larger than its pool.
8. The root's `exec` receipt carries `children: [{cid, invocation_hash, outcome, fuel_used, host,
   children}]`, signed once.

## 8. Metering

1. Wasm fuel and host quotas are separate meters. A host MUST NOT sum them.
2. The receipt carries `engine.fuel_used` (wasm only) and a `host` object of named counters
   (`fetch_calls`, `fetch_bytes`, `compose_calls`), per tree node.

## 9. Encrypted channels

1. In a channel whose suite is not `none`, only `renderer` components and their declared children
   run, on members' devices (JEP-0006).
2. A host MUST refuse a `block-install` into such a channel.

## 10. Moving the home server

When the owner moves a channel's sequencer with `sequencer-set` *(F)*:

1. The new sequencer names freshly minted bot DIDs in its `contract-accept`, and `sequencer-set`
   carries an owner-proposed reinstall for each bot that continues, with `inherits_state_from`.
   The new home server issues fresh `policy-approval`s for the live `block-install`s and the
   channel's `channel-policy` (JEP-0005 rule 11b). An approval by the old home server does not
   carry over; until the new one approves, the install is absent (§4.2).
2. The new sequencer takes the state whose CID is the last `state_after` at or before the handover
   head, or replays the instance from its receipts. If both fail, the reinstall starts empty and
   says so.
3. The pending timer is re-derived from the instance's receipts at or before the head and keeps
   its `scheduled_at`.
4. Writes by the old sequencer past the head are not part of the chain and are not applied.

# Security Considerations (Zero-Trust)

- **No ambient authority.** An interface outside effective authority is absent from the
  instance; scopes are checked per call; effects per application.
- **Confused deputy.** `fetch` runs under the grant, never the invoking user's read rights.
- **Amplification.** Undeclared children are refused, so compilation cost is paid at install; the
  bot hop limit bounds bot-to-bot loops; fetch and compose have quotas.
- **Single writer.** The home server can withhold, reorder or invent invocations and timer fires.
  The state chain and `ingest` chain make that attributable, not impossible (OP-07).
- **Custodial bot keys.** The host can sign as any bot it hosts (SC-04). A bot DID is never a
  person's, and a moved bot gets a new key.
- **Encrypted content** is never fetched or executed by a server (SC-03).
- **Non-portable exhaustion** never changes an output, so honest hosts agree on comparable
  outcomes.

Threat-register changes: AB-04, OP-07 and SC-03 updated; new AB-07 (bot amplification) and SC-04
(custodial bot keys). Text in the design doc.

# Backwards Compatibility

No deployed block uses capabilities. Manifests with a non-empty `capabilities` array in the old
form (`scope: [pattern]`) are refused. `jig:host` starts at `0.1.0`; every `0.x` minor is
breaking, as for `jig:block`.

# Reference Implementation (if applicable)

None yet. The implementation plan is
[`docs/superpowers/plans/2026-10-18-v0.3-capabilities-state-nesting.md`](../../../docs/superpowers/plans/2026-10-18-v0.3-capabilities-state-nesting.md).

# Test Vectors

To be added with the implementation: the attenuation algebra (meet and order over each scope
type), and nested trees with their expected outcomes and `children` receipts.

# LLM Influence (if applicable)

Drafted with an AI coding agent from the approved design; reviewed by the maintainer.

# Rejected Alternatives

Dotted or URI capability names; glob scopes; the manifest as the grant; server-DID or user-signed
bot posts; shared per-block state; key-value state imports; dynamic or asynchronous child
invocation; a single fuel budget; server-run bots in encrypted channels. Rationale in the design
doc.

# Copyright

This document is licensed under CC-BY-4.0.
