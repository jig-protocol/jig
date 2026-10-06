+++
jep = 0001
title = "Pluggable Encryption Suites"
status = "Draft"
type = "Standards Track"
category = "Security"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-05"
requires = ["0002"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

Encryption in jig is a negotiated, operator-chosen **suite**, not a fixed scheme. MLS
(RFC 9420) is the default. An operator can run another registered suite without a wire
change. This stub records what v0.1 already fixes and the questions the v0.2 crypto design
must answer.

# Motivation

- Operators own their encryption. Some will need a scheme other than the default, for
  example a post-quantum one, and nothing in the protocol should stop them.
- Clients must be able to tell a weak or absent suite from a strong one, so a hostile
  operator cannot downgrade silently (threat register OP-03).
- One scheme for every conversation: a DM is a channel with locked membership, so growing
  a conversation never changes scheme.

Non-goals: metadata privacy (OP-04); choosing the post-quantum approach, which is decision
D13 for the v0.2 crypto design.

# Specification

Fixed in v0.1 (normative text in `src/encryption.md` and `src/versioning.md`):

- The suite identifier and its registry: `none` (implemented), `mls` (reserved).
- Carriage: envelope `suite`, manifest `privacy.encryption`, the channel's creation block.
- Unregistered and unimplemented suites are refused, never treated as `none`.
- A channel's suite is fixed at creation; posting under another suite is refused.

Proposed for v0.2:

- **Advertisement.** A server lists the suites it implements in its signed handshake
  answer (JEP-0002). `/.well-known/jig` MAY repeat the list as a discovery hint; the
  handshake is authoritative.
- **Negotiation is per channel, not per connection.** The creator picks the suite from
  those the server advertises. Joining members and federated servers either implement it
  or are refused.
- **Downgrade protection.** A client pins the suites a server DID advertised. A later
  handshake from the same DID advertising fewer or weaker suites is surfaced to the user,
  and a channel created under an encrypted suite never accepts `none`.
- **MLS mapping.** One channel is one MLS group; membership blocks drive MLS commits.
- **One `mls` registry entry.** The MLS cipher suite (RFC 9420 §17.1) is negotiated
  inside the group, not named in the jig registry. Per-cipher-suite entries (for example
  a PQ-hybrid MLS suite) MAY be added later as new registry entries, the same way any
  pluggable suite is: a registry row, a JEP and conformance vectors, with no wire
  change.

# Open questions

1. ~~Identifier granularity.~~ Resolved: a single `mls` entry for now; see
   Specification.
2. D13: does a non-MLS scheme such as Signal's post-quantum protocol fit as a suite with
   its own group semantics, or only as PQ-hybrid MLS?
3. Key-package distribution: nameserver, home server, or both?
4. Multi-device membership and key rotation.
5. Who may sign a membership change on a locked channel with no owner (a DM)?
6. Can a channel move to a new suite, or is that always a new channel?
7. Execution: a server cannot run Wasm over ciphertext. Which block kinds execute
   client-side under an encrypted suite, and what does a receipt then attest?
8. A conformance test suite per registered suite.

# Security Considerations (Zero-Trust)

Threat register entries: OP-03 (downgrade), OP-05 (content disclosure), OP-02 (false
suite claims). The operator is assumed hostile: it may advertise only `none`, strip suites
from the handshake, or claim suites it does not implement.

# Backwards Compatibility

v0.x makes no compatibility guarantee. Frames without `suite` are read as `none`.

# Reference Implementation

`jig_core::EncryptionSuite` (registry and refusals), `jig_pipeline::envelope` (envelope
gate), `BlockManifest::check_gates` (manifest gate).

# Rejected Alternatives

- **HPKE or `age` sealing for DMs, MLS for groups.** Two schemes, and turning a DM into a
  group would mean migrating it. Rejected in D2.
- **Ignoring unknown suites.** Lets an attacker inject a suite a receiver silently treats
  as plaintext.

# Copyright

This document is licensed under CC-BY-4.0.
