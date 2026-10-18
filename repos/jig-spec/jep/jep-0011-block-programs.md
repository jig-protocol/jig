+++
jep = 0011
title = "Block programs, distribution and client execution policy"
status = "Draft"
type = "Standards Track"
category = "Core"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-18"
requires = ["0002", "0004", "0005", "0006", "0007"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

This JEP defines how block code is named, published, fetched, and chosen for execution.

- **Program manifest.** A signed object that pins a component together with what it requests and
  the children it pins. Its CID, the *program CID*, is what installs, children, operator policy and
  `render` messages name.
- **Publishing.** Programs are published through `ingest` as `block-program` blocks. A server stores
  them by CID and never executes them on ingest.
- **Read gate.** A program can be fetched only by callers who can read a channel that holds it. A
  message links a program into its channel only under its sender's read authority.
- **Execution policy.** Clients auto-run only renderers that the channel's policy allows. The
  channel owner signs that policy, and the hosting server approves it, in a separate `policy-approval`,
  against restrictions it publishes. Users can still refuse execution or allow it for themselves.

**Draft status.** The maintainer approved the design on 2026-10-18 (decisions Dv1–Dv6 in the
[design doc](../../../docs/superpowers/specs/2026-10-18-v0.3-block-dev-loop-design.md), which
holds the options and rationale). Nothing here is implemented. Terms marked *(F)* come from
JEP-0005 and change if it does.

# Motivation

- The phase-2 exit criterion (`ROADMAP.md`) asks for a third party to write, sign and ship a block in
  under 10 minutes that runs identically on client and server.
- A block's CID covers manifest, code and timestamp together, so it changes on every deployment.
  The component's hash alone pins the code but not what the code requests. Installs (JEP-0007 §4),
  children (§7) and operator policy (JEP-0006 Q7) each need one stable name that pins code,
  requested authority and children together.
- Nothing yet defines what a client executes. Clients must run third-party renderers for the exit
  criterion to hold, and in encrypted channels only members execute anything (JEP-0007 §9).

Non-goals:
- names for programs (JEP-0004 verified names, later);
- cross-server fetch by CID (a term of JEP-0005's contract, later);
- deny lists and reports by third parties (JEP-0010);
- reproducible builds.

# Specification

The key words MUST, MUST NOT, SHOULD and MAY are as in RFC 2119.

## 1. Encoding

1. Every object defined here is a deterministic CBOR payload (RFC 8949 §4.2.1, with a strict
   decoder) carrying a `domain` entry.
2. Each object is signed with protected header `{1: -8}` (EdDSA over Ed25519), an empty
   unprotected header, no external AAD, the payload attached, and the envelope untagged:
   - as a COSE_Sign1 (RFC 9052) when it has one signer;
   - as a COSE_Sign when it has several, every one of which must sign (JEP-0004 rule 0). In that
     case the signatures are in a fixed order, and a verifier checks against that exact list.
3. The envelope names no signer. A verifier MUST check each signature against a DID it learns
   elsewhere: from the payload, or, for a hosting server, from the channel's sequencer record
   *(F)*.
4. A verifier MUST refuse an envelope or payload that is not deterministically encoded, or that
   carries any other header.
5. CIDs are encoded per JEP-0004 rule 0: a CID in a payload is the binary CIDv1 as an untagged CBOR
   byte string, and CIDv0 is refused. This applies to every CID field here (`children`, `offers`
   keys, `supersedes`, `object_cid`, `restrictions_cid`, `operator_policy_cid`, `prev`, `allow` and
   `deny` program lists).
6. Every list in a payload that is a set (the `allow` and `deny` lists, `children`) MUST be
   strictly ascending by the bytes of each entry's own deterministic encoding, with no repeats. A
   verifier MUST refuse a payload that breaks this, so each object has exactly one encoding.
7. A map's keys are exactly those this JEP defines for it. A verifier MUST refuse a payload with an
   unknown or missing key, except a key this JEP marks optional.

This is the encoding layer jig uses for every new signed object (reference implementation:
`jig_core::dcbor` and `jig_core::cose`).

## 2. The program manifest

1. Payload fields:

   | Key | Type | Meaning |
   | --- | --- | --- |
   | `domain` | text | `jig-program-manifest-v1` |
   | `author` | text | The author's `did:jig`, which is also the signer. |
   | `name` | text | Display name. MUST NOT be resolved to a CID automatically. |
   | `version` | text | Semver. Lineage only. |
   | `world` | text | A JEP-0006 world with its full version, e.g. `jig:block/renderer@0.1.0`. |
   | `component` | bytes | BLAKE3-256 of the component bytes. |
   | `requests` | map | JEP-0007 §1 capability names to typed scopes. |
   | `children` | array of CID | Pinned child program CIDs (JEP-0007 §7). |
   | `offers` | map | Child program CID to grant (JEP-0007 §7). |
   | `limits` | map | `memory_max_pages`, `fuel_max`: what the author tested with. |
   | `examples` | array | Vectors: `{invocation, outcome, hash}` per JEP-0006. |
   | `supersedes` | CID, optional | An earlier program CID by the same author. |
   | `source` | map, optional | Unverified claim: `repo`, `commit`, `lock_hash`, `rustc`. |

2. The payload MUST NOT carry a timestamp. When a program was published is recorded by its `ingest`
   record.
3. **The program CID** is a CIDv1 (raw codec, BLAKE3-256 multihash) over the labelled parts
   `manifest`, which is the payload bytes (signature excluded), and `code`, which is the component
   bytes. The derivation is the block-bundle one already in use. The same payload and component
   always give the same CID.
4. A verifier MUST check, in order:
   - the CID over the bytes;
   - `component` against the component bytes;
   - the author's signature;
   - JEP-0006's `jig-det-1` profile against `world`;
   - that `requests` uses only known capability names and scope fields (JEP-0007 §1);
   - that every child is present and itself verifies.
5. A host SHOULD run `examples` at publish and at install, and MUST surface any example whose
   comparable outcome differs.

## 3. Block kinds

1. **`block-program`** carries a signed manifest and the component. A server MUST verify it (§2.4),
   store it by program CID, and issue an `accepted` receipt (JEP-0006). A server MUST NOT execute
   a program on ingest. Re-publishing a CID the server already holds is a no-op for storage, and
   the channel gains the program (§4).
2. **`render`** names a `program` (program CID) and carries an `input` payload.
   - A server executes it only if its `operator-policy` (§5.1) allows the program, and then
     issues an `exec` receipt carrying `component`, `program` and `operator_policy_cid`
     (the `operator-policy` that authorised the run). Otherwise it issues
     `accepted`.
   - Operator policy allowing an author MUST NOT extend to children by other authors.
   - A server MUST NOT execute a `render` in a channel whose suite is not `none`.
3. **`program-yank`**, signed by a program's author, names a program CID and a reason. It is
   advisory: pinned uses keep working, and clients SHOULD warn.
4. **`server-restrictions`**, **`channel-policy`**, **`policy-approval`** and **`policy-withdrawn`**
   are defined in §5.

## 4. Read gate

1. A server MUST NOT serve a program, or any CID, to a caller who cannot read some channel that
   holds it.
2. A channel holds a program when:
   - the program was published into it; or
   - a message ingested into it linked the program (§4.3).
3. When a server ingests a message into channel Y that names program P:
   - it MUST add P to Y's holdings if the message's sender can read a channel that already holds
     P, or the message attaches P's bytes;
   - otherwise it MUST refuse the message with `program-unavailable`;
   - the server's own holdings MUST NOT count.
4. In a channel whose suite is not `none`, the server cannot see which program a message names.
   There, members fetch P from a channel that holds it, or from a `block-program` carried inside
   the encrypted channel, and verify it by CID after decrypting.

## 5. Client execution policy

### 5.1 Server rules

A server publishes two rule sets, each a COSE_Sign1 signed by the server, versioned by `seq` and
named by CID. A server that issues any `policy-approval` MUST publish both, even if one is empty,
so that every approval names the exact rules it was checked against.

1. **`server-restrictions`**:
   `{domain: "jig-server-restrictions-v1", server, seq, deny: {programs: [cid…], authors: [did…]}}`.
   - It limits which channel policies and installs the server will approve (§5.3).
   - It does not limit what clients run.
2. **`operator-policy`**:
   `{domain: "jig-operator-policy-v1", server, seq, allow: {programs: [cid…], authors: [did…], components: [hash…]}}`.
   - It is the operator policy of JEP-0006 Q7 and JEP-0007 §2: which programs this server will
     execute at all.
   - `components` allows a program by the hash of its component (§2.1 `component`), whoever
     authored the manifest. A `components` entry MUST match only a program whose `world` is a
     `renderer` world, whose `requests` is empty, and whose `children` is empty. Such a manifest
     can add nothing to the code it wraps.
   - Any other program, including every `bot`-world install, MUST be allowed by `programs` or
     `authors`.
   - A server's default `operator-policy` lists in `components` exactly the renderer components it
     ships, and nothing else: today, text-block's component hash. Clients therefore see everything
     the server will run, and built-ins get no implicit exception. "Empty by default" means empty
     of third-party entries.
   - **Why components, not program CIDs, for built-ins.** A built-in published as a program by each
     server's own DID would have a different program CID on every server. A `render` composed on
     server X would name X's program CID, and server Y's default policy would refuse it, so plain
     rendered messages would stop federating. The component hash is the same everywhere.
   - **Cross-server comparison keys on the component.** Two executors agree on a run when they
     agree on the component hash, world and invocation (JEP-0006 Q3). The program CID may differ
     between servers for the same component.
   - Allowing an author does not extend to children by other authors.

### 5.2 Channel policy

1. A `channel-policy` is a COSE_Sign1 signed by the channel's owner:
   `{domain: "jig-channel-policy-v1", channel, owner, seq, prev, allow: {programs: [cid…], authors: [did…]}}`.
2. The owner sets one when creating the channel, and MAY amend it with a new `channel-policy` whose
   `seq` is one higher and whose `prev` is the previous policy's CID. The CID of a policy is the
   CID of its signed envelope.
3. A host MUST refuse a `channel-policy` that is not signed by the channel's owner.
4. A `channel-policy` is a plaintext control block in every channel, including encrypted ones
   (§6.3).
5. A `channel-policy` gates client execution only. It grants no capability, is not a
   `block-install`, and MUST NOT cause a server to execute anything.

### 5.3 Approval and withdrawal by the hosting server

The hosting server signs off on owner-signed channel objects with one object kind, used for
`channel-policy` here and for `block-install` (JEP-0007 §4).

1. A **`policy-approval`** is a COSE_Sign1 signed by the channel's home server *(F)*:
   `{domain: "jig-policy-approval-v1", server, channel, object_cid, restrictions_cid, operator_policy_cid?, bot_did?}`.
   - `object_cid` is the CID of the approved `channel-policy` or `block-install`.
   - `restrictions_cid` is REQUIRED for both kinds: the `server-restrictions` the object was
     checked against.
   - `operator_policy_cid` MUST be present when the approved object is a `block-install`, and MUST
     be absent otherwise. It names the `operator-policy` the install's program was checked
     against.
   - `bot_did` MUST be present when the approved object is a `block-install`, and MUST be absent
     otherwise. It states that this server holds the private key for `bot_did`, as custodian
     (JEP-0007 §4, SC-04). A verifier MUST check that it equals the install's `bot_did`.
2. A **`policy-withdrawn`** is a COSE_Sign1 signed by the home server:
   `{domain: "jig-policy-withdrawn-v1", server, channel, object_cid, restrictions_cid, operator_policy_cid?, conflicts}`.
   - The rule CIDs are the versions that the object now fails. `operator_policy_cid` appears under
     the same condition as in an approval.
   - For a `channel-policy`, `conflicts` lists the entries the current restrictions deny.
   - For a `block-install`, it means the server will no longer run the bot.
3. **Approving a policy.** The home server checks each `channel-policy` against its current
   restrictions.
   - If the policy allows nothing the restrictions deny, it issues a `policy-approval`.
   - Otherwise it MUST refuse the policy, naming the conflicting entries.

   For a `block-install`, the server approves only if the installed program is in its
   `operator-policy` and not denied by its `server-restrictions`.
4. **When either rule set changes**, the server MUST re-check every object it has approved.
   - For each object that still passes, it issues a new `policy-approval` naming the new rule
     CIDs.
   - For each object that now fails, it issues a `policy-withdrawn`.
   - A server cannot change an owner's object. It can only approve or withdraw.
5. **Ordering.** Approvals and withdrawals are control blocks, so the channel's `ingest` chain
   (JEP-0002) orders them, in encrypted channels too.
   - For a given object CID, the latest `policy-approval` or `policy-withdrawn` in the chain is the
     current one.
   - A withdrawal is final for that object CID until a newer `policy-approval` for it appears later
     in the chain.
   - Approvals carry no counter of their own, so their order cannot disagree with the chain's.
6. **Sequencer moves.** When the sequencer moves, the new home server issues a `policy-approval` as
   part of its `contract-accept`, as JEP-0005 rule 11b (#173) requires. It does this for the
   current `channel-policy` and for every live `block-install`. The owner does not need to be
   online.
   - An object whose current approval is not from the current home server counts as absent:
     no policy, no install.

### 5.4 What a client runs

1. A client MUST treat a channel as having an **effective policy** only when all of these hold:
   - the latest `channel-policy` is signed by the owner;
   - its `seq`/`prev` chain is unbroken;
   - its current entry in the ingest chain (§5.3.5) is a `policy-approval` from the current home
     server.

   Otherwise the channel has no policy.
2. A client MAY auto-run a renderer only if its program CID, or its author's DID, is in the
   effective policy's `allow`. Everything else MUST be click-to-run.
3. **Closure.**
   - Allowing a program by CID covers exactly the tree its manifest pins.
   - Allowing an author does not cover children by other authors.
   - If any node of a tree is not allowed, the whole tree is click-to-run. A client MUST NOT render
     part of a tree.
4. **User restrictions win.** A client keeps a per-user deny list and per-user allows ("always run
   this program", "always run this author") as local state.
   - A deny entry overrides any channel or user allow.
   - Before executing, a client MUST warn about any conflict between the effective policy and the
     user's restrictions.
5. **Rotation.** An allow by DID, whether in a `channel-policy` or a per-user allow, lapses when that
   DID rotates (JEP-0004 AliasLink). It returns only when whoever granted it (the owner, or the
   user) confirms the verified link.
6. **Compile cap.** A client SHOULD cap the number of distinct, uncached programs it compiles per
   channel per minute. Past the cap, it shows fallback text and offers click-to-run.
7. **Comparison.** In an encrypted channel, the in-group `output_hash` comparison (JEP-0006)
   covers only the members who executed.

# Security Considerations (Zero-Trust)

## 6.1 What each mechanism establishes

- **Program CID:** integrity. Any server may serve the bytes.
- **Author signature:** who published the program. It says nothing about the source or the build.
- **Pinning by CID, with no automatic upgrades:** a compromised author key cannot change anything
  already pinned.
- **Operator policy:** whether this server executes the program.
- **Channel policy approved by the hosting server:** what members auto-run.
- **`jig-det-1` and the sandbox:** bound execution. They do not protect against a runtime zero-day
  (SC-03).

## 6.2 Builds are not reproducible

A component cannot be checked against its source, so trusting a program means trusting its author.
`source` is a claim, not evidence.

## 6.3 Cost: channel policies are plaintext in encrypted channels

The hosting server must read a policy to approve it. So in a channel whose suite is not `none`,
the `channel-policy` and its `policy-approval` are visible to the server, and to anyone who can read the
channel's control stream. They reveal which program CIDs and author DIDs the channel allows. That
says something about what the channel is for, even though no message content leaks. The
maintainer accepted this cost (Dv5d) so that a server can refuse policies it will not host, and
so that a channel owner who is not the server operator still answers to the host.

Hiding the allow list while proving compliance (zero-knowledge set membership against the
restrictions) is possible in principle, but out of proportion for v0.3. Owners who need the allow
list hidden can leave the policy empty, so every renderer is click-to-run.

## 6.4 Confused deputy

The read-gate rule (§4) exists so that a CID is never a capability. If a server linked programs on
its own authority, anyone who learned a CID from a restricted channel could make the program
readable in an open one.

## 6.5 Compile amplification

Compiling a component costs host CPU that fuel does not meter. The compile cap (§5.4.6) and the
whole-tree rule bound what a flood of distinct program CIDs can cost a client (AB-07).

## 6.6 Threat register (edits land with the implementation)

- **SC-01** widens to all third-party programs.
- **SC-02** gains a block-toolchain clause.
- **AB-07** gains client-side compile amplification.
- **New PV row:** the channel-policy allow list is visible to the hosting server in encrypted
  channels (§6.3).

# Backwards Compatibility

All of this is new. No existing block uses a program, a `render` kind or a channel policy. Blocks
already stored keep their CIDs and receipts.

# Reference Implementation

Not yet written. The plan is
[`2026-10-18-v0.3-block-dev-loop.md`](../../../docs/superpowers/plans/2026-10-18-v0.3-block-dev-loop.md),
slices 4–8.

# Test Vectors

To come with slice 4 and slice 6:
- program manifests, with their program CIDs;
- tampered variants of each;
- **federation:** a `render` composed on server X, naming X's program CID for text-block, is
  executed by server Y under Y's default `operator-policy` (allowed by component), and both
  servers' `exec` receipts carry the same outcome hash;
- programs whose component hash is in `components`, but whose program and author are not allowed,
  are refused in each of these cases:
  - a `bot`-world program, at install;
  - a renderer whose manifest requests any capability;
  - a renderer whose manifest pins any child;
- a `channel-policy` chain with host approvals and a withdrawal.

# Rejected Alternatives

- **Policy keyed by component hash alone, for every program.** It would approve the code under any
  manifest, including one that requests capabilities or pins children. Component matching is kept
  only for renderers with no requests and no children (§5.1), where the manifest adds nothing.
- **Signature inside the program CID.** Every later attestation would then need a second name.
- **A registry service, or programs on nameservers.** This adds a second write path and a second
  trust root.
- **Linking programs on the server's own authority.** This is the confused-deputy case (§6.4).
- **Clients auto-run any renderer.** Exposure would extend to anyone who can post.
- **A two-signer COSE_Sign (owner first, host second) over the policy.** It is one object instead
  of two, but it records no restrictions version. And because Ed25519 signatures are
  deterministic, a server re-approving a policy after withdrawing it would produce the very same
  bytes as before. That re-approval could not be told apart from the original, so the owner would
  have to amend the policy. A separate `policy-approval` keeps the owner's object fixed and the
  host's judgement current and ordered.
- **A counter on each approval.** The `ingest` chain is already the server-signed order, so a
  second counter would be redundant and could disagree with it.

# Copyright

This document is licensed under CC-BY-4.0.
