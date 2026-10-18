+++
jep = 0011
title = "Block programs, distribution and client execution policy"
status = "Draft"
type = "Standards Track"
category = "Core"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-18"
requires = ["0004", "0005", "0006", "0007"]
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
  channel owner signs that policy, and the hosting server countersigns it against restrictions it
  publishes. Users can still refuse execution or allow it for themselves.

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
   - A server executes it only if operator policy allows the program (JEP-0006 Q7), and then
     issues an `exec` receipt carrying both `component` and `program`. Otherwise it issues
     `accepted`.
   - Operator policy allowing an author MUST NOT extend to children by other authors.
   - A server MUST NOT execute a `render` in a channel whose suite is not `none`.
3. **`program-yank`**, signed by a program's author, names a program CID and a reason. It is
   advisory: pinned uses keep working, and clients SHOULD warn.
4. **`server-restrictions`**, **`channel-policy`** and **`policy-withdrawn`**
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

### 5.1 Server restrictions

1. An operator MAY publish a `server-restrictions` object:
   `{domain: "jig-server-restrictions-v1", server, seq, deny: {programs: [cid…], authors: [did…]}}`,
   signed by the server.
2. Restrictions limit which channel policies the server will countersign (§5.3). They do not limit
   what clients run, and they do not affect server execution, which operator policy alone governs
   (JEP-0007 §2).

### 5.2 Channel policy

1. A `channel-policy` payload is
   `{domain: "jig-channel-policy-v1", channel, owner, seq, prev, allow: {programs: [cid…], authors: [did…]}}`.
   It is a COSE_Sign with two signatures, in this order:
   - the channel's owner (`owner`);
   - the channel's hosting (home) server *(F)*.

   The payload does not name the server, so a new home server can countersign the same payload.
2. The owner sets one when creating the channel, and MAY amend it with a new `channel-policy` whose
   `seq` is one higher and whose `prev` is the previous policy's CID. The CID of a policy is the
   CID of its payload.
3. A host MUST refuse a `channel-policy` whose first signature is not the channel owner's.
4. A `channel-policy` is a plaintext control block in every channel, including encrypted ones
   (§6.3).
5. A `channel-policy` gates client execution only. It grants no capability, is not a
   `block-install`, and MUST NOT cause a server to execute anything.

### 5.3 Countersignature by the hosting server

1. The home server checks each owner-signed `channel-policy` against its current restrictions.
   - If the policy allows nothing the restrictions deny, the server adds its signature.
   - Otherwise it MUST refuse to countersign, naming the conflicting entries.
2. When its restrictions change, the server MUST re-check every policy it countersigned.
   - A policy that still passes needs nothing further.
   - For a policy that now fails, the server issues a `policy-withdrawn`, signed by the server:
     `{domain: "jig-policy-withdrawn-v1", server, channel, policy: cid, restrictions: cid, conflicts}`.
   - A withdrawn policy stays withdrawn. The owner restores a policy by amending it (§5.2.2), and
     the server countersigns the amendment.
3. A server cannot change a policy. It can only countersign, or withdraw.
4. **Sequencer moves.** When a channel's sequencer moves, the new home server countersigns the
   current `channel-policy` as part of its `contract-accept`, as JEP-0005 rule 11b (#173) requires.
   Until it does, the policy carries no signature from the server that hosts the channel, and
   clients treat the channel as having no policy. Rule 11b applies the same requirement to every
   live `block-install` (JEP-0007 §4).

### 5.4 What a client runs

1. A client MUST treat a channel as having an **effective policy** only when all of these hold:
   - the latest `channel-policy` carries both signatures, the owner's and then the current home
     server's;
   - the `seq`/`prev` chain is unbroken;
   - the current home server has not issued a `policy-withdrawn` for it.

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
- **Channel policy countersigned by the hosting server:** what members auto-run.
- **`jig-det-1` and the sandbox:** bound execution. They do not protect against a runtime zero-day
  (SC-03).

## 6.2 Builds are not reproducible

A component cannot be checked against its source, so trusting a program means trusting its author.
`source` is a claim, not evidence.

## 6.3 Cost: channel policies are plaintext in encrypted channels

The hosting server must read a policy to countersign it. So in a channel whose suite is not `none`,
the `channel-policy` and its countersignature are visible to the server, and to anyone who can read the
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

To come with slice 4:
- program manifests, with their program CIDs;
- tampered variants of each;
- a `channel-policy` chain with countersignatures and a withdrawal.

# Rejected Alternatives

- **Policy and receipts keyed by component hash.** This approves the code under any manifest,
  including one that requests more.
- **Signature inside the program CID.** Every later attestation would then need a second name.
- **A registry service, or programs on nameservers.** This adds a second write path and a second
  trust root.
- **Linking programs on the server's own authority.** This is the confused-deputy case (§6.4).
- **Clients auto-run any renderer.** Exposure would extend to anyone who can post.
- **A separate server approval object** naming the policy and the restrictions version. It would
  let the server re-approve against each version of its restrictions, but it adds a third object
  kind, and it breaks the single "owner first, host second" COSE_Sign pattern that
  `block-install` and JEP-0005 rule 11b use. Withdrawal alone covers the case that matters.

# Copyright

This document is licensed under CC-BY-4.0.
