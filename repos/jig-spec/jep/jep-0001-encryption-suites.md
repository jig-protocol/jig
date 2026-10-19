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

## Suite properties

A gate treats a suite by its properties, not by name:

- **Encrypted.** Content under the suite is ciphertext: every suite but `none`. A server
  refuses a plaintext `body` beside it (`SUITE_MISMATCH`), stores and relays it, and does not
  execute it: its receipt says `"content": "sealed"`. A client that cannot read an encrypted
  suite shows the block as sealed, never as plaintext.
- **Payload field.** The block-metadata key that carries an encrypted suite's ciphertext
  (`mls_message`; `test_ciphertext`). A content block without it is refused
  (`MISSING_METADATA`).
- **Operator-confidential.** The server's operator cannot read content under the suite:
  `mls` only. `none` is not encrypted, and `test-aead` is encrypted under a published key.
  A restricted channel's suite MUST be operator-confidential (decision D25), and a server and
  a client apply the same property. The refusal code stays `RESTRICTED_REQUIRES_MLS`. A
  new suite's JEP states whether the suite is operator-confidential. A DM is always `mls`,
  because it relies on MLS group membership.

## Reporting

Encrypted abuse reports use message franking, which sits above the suite
([JEP-0010](jep-0010-reports-tribunals-lists.md), rules 6–8a). A suite contributes one
property, and every suite JEP MUST state it:

- **Faithful delivery.** The suite delivers the plaintext, franking key `k_f` included,
  unchanged to every member of the channel. A ruleset group that holds tribunals MUST NOT
  admit a suite that does not ([JEP-0010](jep-0010-reports-tribunals-lists.md) rule 8a).

`none` and `mls` both have this property: every member receives the same plaintext, and
for `mls` it is authenticated by the sender's MLS content signature. `test-aead` has it too:
there is one key and one payload, and every member opens it to the same bytes.

## Conformance vectors

Every registered suite ships one file, `vectors/suites/<id>.json` in this repository
(CC-BY-4.0). A suite without one is not registered. The vectors pin jig's mapping of the
suite onto channels and blocks, not the cryptography beneath it, which has its own vectors
(RFC 9420; RFC 8439).

```json
{
  "format": 1,
  "suite": "<id>",
  "description": "…",
  "suite_params": { "…": "…" },
  "cases": [
    { "name": "…",
      "steps": [
        { "submit": { "sender": "<did:jig>", "manifest": { "…": "…" },
                      "expect": "accept" } },
        { "submit": { "sender": "…", "manifest": { "…": "…" },
                      "expect": { "refuse": "<error code>" } } },
        { "read": { "step": 1, "expect": { "plaintext": "…" } } },
        { "read": { "step": 1, "expect": "unreadable" } }
      ] }
  ]
}
```

- Each case starts from a server with no state and is one channel's history. Steps run in
  order.
- `submit` hands the server a block manifest from `sender`. The server either accepts it or
  refuses it with the named error code from the spec.
- `read` says what a member reads from the content block submitted at index `step`: its
  plaintext, or `unreadable`. A suite whose reading depends on member secrets (`mls`) has
  no read steps.
- Manifests are unsigned and timestamps are not checked. Signatures and freshness do not
  depend on the suite and are tested elsewhere.
- `suite_params` holds whatever the suite needs to run its read steps (the `test-aead` key).
- The `mls` file's leaves carry a lifetime, which MLS checks against the clock. Its
  `description` gives the expiry. The file is regenerated before that date.

Every suite's file covers: creating a channel under it; a restricted creation (refused
unless the suite may serve restricted channels); content without the payload field, with a
plaintext `body`, and under another suite (all refused); and a control block that declares
the suite (refused). The reference implementation checks every file in CI
(`jig-server/tests/suite_vectors.rs`), and fails if a registered suite has none.

## The test suite

`test-aead` is the second suite. It is reserved for conformance testing and is not for
deployment. It shows that a suite plugs into the registry, the manifest, the gates and the
sealed receipt without MLS.

- **Construction.** ChaCha20-Poly1305 (RFC 8439). The key is the 32 bytes `00 01 … 1f`,
  published in this JEP and in the suite's vectors. Its payload field `test_ciphertext` is
  the base64 of a 12-byte nonce followed by the AEAD output. The AAD is the UTF-8 of
  `jig-test-aead-v1|<channel slug>|<sender DID>`, so a payload reads only in its own channel
  under its own author.
- **No group state.** Membership blocks on a `test-aead` channel are plain control blocks.
- **Faithful delivery** (see Reporting): every member opens the one payload to the same
  plaintext, so the suite meets [JEP-0010](jep-0010-reports-tribunals-lists.md) rule 8a.
- **Open channels only.** Anyone can read it, so it may not serve a restricted channel or a
  DM.
- **Never in a production build.** The `test-` prefix is reserved: a production
  implementation refuses every `test-` identifier as unregistered, and no server advertises
  one. In the reference implementation the suite exists only behind a Cargo feature that only
  dev-dependencies enable, and CI fails if any crate's normal dependency graph enables it.

# Open questions

Answers marked *v0.2* are the defaults the implementation ships with
([M2 design](../../../docs/superpowers/specs/2026-10-11-m2-mls-and-channel-dynamics-design.md));
each says what would change it.

1. ~~Identifier granularity.~~ Resolved: a single `mls` entry for now; see
   Specification.
2. D13, *deferred* (2026-10-18): does a non-MLS scheme such as Signal's post-quantum
   protocol fit as a suite with its own group semantics, or only as PQ-hybrid MLS? v0.2
   shows suites are pluggable with the test suite and conformance vectors instead. A
   production second suite is a stretch goal.
3. ~~Key-package distribution~~ *v0.2*: the home server, which validates each package's
   binding to its DID. Nameserver distribution is deferred.
4. Multi-device membership and key rotation. *v0.2*: one DID is one MLS client, and the
   DID's key is the MLS signature key, so rotating it means rejoining.
5. ~~Who signs membership changes on a DM?~~ *v0.2*: there is no ownerless DM; whoever
   opens it owns it.
6. ~~Suite migration~~ *v0.2*: a new suite is a new channel.
7. Execution: *v0.2*: a server executes nothing under an encrypted suite, and its receipt
   says `"content": "sealed"`. Client-side execution of decrypted content is open.
8. ~~A conformance test suite per registered suite.~~ Resolved: every registered suite
   ships conformance vectors; see Specification.

# Security Considerations (Zero-Trust)

Threat register entries: OP-03 (downgrade), OP-05 (content disclosure), OP-02 (false
suite claims). The operator is assumed hostile: it may advertise only `none`, strip suites
from the handshake, or claim suites it does not implement.

# Backwards Compatibility

v0.x makes no compatibility guarantee. Frames without `suite` are read as `none`.

# Reference Implementation

`jig_core::EncryptionSuite` (registry and refusals), `jig_pipeline::envelope` (envelope
gate), `BlockManifest::check_gates` (manifest gate), `jig_pipeline::mls_gate` (per-channel
suite and MLS validation), `jig_mls` (delivery service and member), `jig_client::secure`
(client state), `jig_core::suite::test_aead` (the test suite),
`jig-server/tests/suite_vectors.rs` (the conformance-vector check and generator).

# Rejected Alternatives

- **HPKE or `age` sealing for DMs, MLS for groups.** Two schemes, and turning a DM into a
  group would mean migrating it. Rejected in D2.
- **Ignoring unknown suites.** Lets an attacker inject a suite a receiver silently treats
  as plaintext.

# Copyright

This document is licensed under CC-BY-4.0.
