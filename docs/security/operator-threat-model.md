# Operator threat model

The reasoning behind the spec's
[threat register](../../repos/jig-spec/src/threat-register.md). The register holds the
decisions; this document holds the model, the alternatives and the evidence for each
status. Update both together. This document covers the OP entries; the other families are
analysed in the [trust, federation and identity whitepaper](../whitepaper/trust-federation-identity.md#14-threat-analysis-beyond-operators).

Last reviewed 2026-10-05, against `main` at the v0.1 groundwork branch.

## Why operators are in scope

jig is federated: anyone can run a server, and users choose one. "Only use good servers"
cannot be enforced by a protocol, and an honest operator can be compromised, coerced or
sold. So every decision assumes the server a client talks to may be hostile, and asks
what the client can still rely on.

## The attacker

A hostile operator controls everything on their side of the wire:

- the server binary, which may be modified jig or not jig at all;
- its database, logs and backups, including all stored blocks and receipts;
- its keys, including the server DID key;
- its network position: it sees every client connection and every federation link;
- its configuration, including the nameserver it points clients at.

It **cannot**:

- forge a signature by a user key it does not hold;
- make two different blocks hash to one CID;
- read content encrypted to a group it is not a member of (from v0.2).

A hostile federated **peer** is the same attacker, one hop further away.

## What the client must still be able to rely on

1. A block it accepts was signed by the DID it claims (signatures, today).
2. The protocol version and suite it is speaking are the ones it agreed to (gates today,
   handshake next).
3. A lie by the server leaves evidence (signed handshake, JEP-0002).
4. Content in an encrypted channel stays unreadable to the server (MLS, v0.2).

Everything else (delivery, ordering, completeness, metadata) is something a hostile
operator can degrade. The register says so plainly rather than implying otherwise.

## Entries

### OP-01: handshake stripped or disabled

**Attack.** The operator skips the handshake, so the client never learns, and never
checks, what the server claims to support.

**Decision rationale.** Make the handshake mandatory *on the client side*. A server-side
"MUST send" binds only honest servers; a client that refuses to proceed without one binds
every server. **Alternative rejected:** an optional handshake, because the attacker
chooses to omit it.

**Status evidence.** `jig-server` answers `hello` with a signed `welcome` and
refuses any earlier frame. `jig-client` closes when that welcome is missing or
malformed. Version and suite refusals leave the socket open.

### OP-02: false handshake answers

**Attack.** The operator claims capabilities, suites, a version or a reputation it does
not have, for example claiming execution while serving synthetic receipts.

**Decision rationale.** A protocol cannot stop a lie, but it can make one attributable.
The server signs its answer, and the client treats contradicting behaviour as a failure.
A signed false claim is evidence a user or a reputation system can act on. **Alternative
rejected:** unsigned answers, which leave nothing to show anyone.

**Status evidence.** The welcome is signed over version, suites, capabilities,
reputation (`null`), and the client's nonce. The client keeps the frame when
the signature fails or the welcome contradicts itself. Checking a later frame
against that signature is still open.

### OP-03: suite downgrade

**Attack.** The operator advertises only weak suites or `none`, strips suites from an
offer, or relabels encrypted content as plaintext.

**Decision rationale.**

- Unknown and unimplemented suites are **refused, never ignored**. Ignoring an unknown
  suite risks a receiver treating a payload it did not understand as plaintext, which is
  the downgrade.
- The suite is fixed per **channel**, at creation, in a signed block. A per-connection
  negotiation would let the operator pick the weakest common suite on every connection.
  A channel-level choice is made once by the creator, and every later post is checked
  against it.
- Offered lists still skip unknown entries, as TLS does, because otherwise no new suite
  could ever be offered to an old peer.

**Status evidence.** `jig_core::EncryptionSuite` has no catch-all variant, so an
unregistered identifier does not deserialize. `Envelope` refuses `v != 1` and any frame
suite except `none` at deserialization, on every path (WebSocket handler, federation,
client). `BlockManifest::check_gates` refuses an unsupported schema or suite in `ingest`
and on federation inbound. Since v0.2 a channel records its suite at creation
(`channels.suite`) and `jig_pipeline::mls_gate` refuses any post under another suite,
including plaintext on an `mls` channel (`SUITE_MISMATCH`). Pinning the suites a server
advertised is still JEP-0001.

The relabel half of this attack also works against the client, which learns a channel's
suite from the server's unsigned listing. Until the fix below, `jig send` and `jig chat`
encrypted only when the listing said `mls` and otherwise sent a plaintext `text-render`, so
an operator could flip a channel to `none` in its own store and receive the next message in
the clear (the server's own gate agreed, having been relabelled too). A client now decides
from its own MLS state first (`jig-cli` `must_encrypt`): holding the group means `mls`,
whatever the listing says, and a contradiction is printed as a warning. A channel the device
has no group for is still taken on the listing's word, which is what suite pinning closes.

Suite pinning: the listing now names each channel's creation block (`id`), and
`GET /api/v1/blocks/{cid}` serves it with its author's signature. `jig-client`'s
`pins::prove_channel` checks the block hashes to that id, is a `channel-create` for the
slug and is signed by its author, and the CLI reads the suite from it, never from the
listing. The block is pinned in `~/.jig/pins.json` on first sight; a different creation
block under the same slug is refused (`ChannelReplaced`). The welcome's advertised suites
are pinned per server too, and a welcome that drops one is refused (`SuiteDropped`). What
remains: a device's very first look at a channel can be answered with a channel the server
made up and signed under its own key; the pin turns that into one lie that is then caught,
not one that is silently repeated.

### OP-04: metadata harvesting

**Attack.** The operator records who talks to whom, when, how often and how much.

**Decision rationale.** Routing needs sender, channel and timing. MLS hides content, not
routing. Hiding routing needs mixnets or private information retrieval, which conflict
with "runs on a potato". So the spec makes no metadata-privacy claim, rather than a weak
one. Revisit after v0.2.

### OP-05: content disclosure

**Attack.** The operator reads messages.

**Decision rationale.** Only end-to-end encryption answers this. See
[encryption.md](encryption.md).

**Status evidence.** v0.2 channels created under `mls` store only MLS ciphertext; the
server holds no group secret (`jig_mls::delivery` tracks public state only).
`integration-tests/tests/h12_encrypted_channels.rs` searches every file the server wrote
after a conversation and finds none of it. Channels created without a suite remain
plaintext, and encrypted channels do not federate.

### OP-06: dropping, reordering, delaying, replaying, selective censorship

**Attack.** The operator withholds some blocks from some members, reorders history, or
replays old blocks.

**Decision rationale.** Replay is cheap to stop and is stopped. Omission and reordering
are not detectable by a single client talking to a single server. Detecting them needs
either signed per-channel sequence or hash chains from authors, or comparison across
servers and members. Both are design work, so the register says Open for those parts.

**Status evidence.** `IngestError::DuplicateBlock` refuses a CID seen before, which also
stops replay of control-plane blocks. Read proofs go through a
`ReplayGuard` (`jig-server/src/auth/`). The manifest's `hlc_ts` is set by the ingesting
server, so it does not help a client detect reordering by that server.

### OP-07: forged or withheld receipts; lying about fuel or execution

**Attack.** The operator issues receipts for executions it did not perform, inflates
fuel, or withholds receipts.

**Decision rationale.** A receipt is a signed claim by one server, so a false one is
attributable but not prevented. Cross-server `render_hash` parity is the only independent
check today. Making divergence a refusal rather than a warning needs deterministic,
portable fuel (see `docs/investigations/2026-08-11-fuel-portability.md`).

**Status evidence.** Receipts are server-signed. `integration-tests/tests/h4_parity_warning.rs`
covers the warning.

### OP-08: key substitution

**Attack.** The operator (or its nameserver) maps a name to the wrong DID, so a user
talks to the attacker thinking it is someone else.

**Decision rationale.** A `did:jig` *is* its public key, so a DID cannot be substituted;
the mapping from a human name to a DID can. Today's TOFU pin lives on the server, in the
identity resolver, which protects users from each other but not from the operator who
controls it. The decision moves pinning to clients. A key-transparency log would turn
pins into something verifiable; that is future work.

**Status evidence.** The CLI pins each server's DID on its first signed welcome
(`jig_client::pins`, `~/.jig/pins.json`). A later welcome signed by another key fails
closed with an explanation, for every WebSocket connection and once per process before
`Secure`'s first REST request (REST has no handshake of its own). `jig server forget`
drops a server's pins. Name→DID mappings are not yet pinned client-side, and a REST
response is tied to the pinned server only once TLS binds the two.

### OP-09: federation abuse

**Attack.** A peer relays junk, relays blocks claiming other authors, or impersonates a
peer.

**Decision rationale.** A relayed block is ingested like a submitted one; a peer is a
transport, not a source of authority. Listing a peer is what trusts it: the server dials
it, pins its DID, and lets only listed DIDs read its federation stream. v0.2 still
federates only open, unencrypted channels, because an MLS group spanning two servers needs
the federation contract (D12).

**Status evidence.** `ingest_peer_block` runs every relayed block through `ingest` with
`IngestSource::FederatedPeer`: signature, manifest gates, admission, the kind allowlist,
archived channels, the write gate, the suite gate, effects, and the server's own execution
and receipt. Relayed receipts are not kept. Only a federated `text-render` may name a
channel the server has no row for; a relayed member-add, member-remove, promote or archive
for an unknown channel is refused, since there is no owner to authorize it against. The
dialer pins each peer's `expected_did` in the handshake, and a federation-scope subscribe
must come from a listed peer's DID, authenticated even where reads are not. A `ws://`
peer is a boot error, and is never dialed, unless `dangerously_allow_plaintext_federation`
is set (advertised in `unsafe_options_active`): the pin covers the handshake, not what
follows it on an unprotected link. The
`naively_trust_peer_authored_blocks` flag is gone. The relay still drops blocks for local
channels that do not federate, and `DeliveryPolicy::federates` keeps restricted and
encrypted channels' blocks off outbound links. Peers actually receive a server's blocks
through the federation-scope subscription they hold on their connection to it, not through
the server's own dial (whose block frames the peer ignores); until the fix below that
subscription was filtered by `permits` alone, so an open encrypted channel's commits,
welcomes and ciphertext reached every peer. `federates` now gates both paths. It derives block CIDs the way `ingest` does
(before v0.2 it used a different scheme, so one block had two identities).

### OP-10: discovery and reputation gaming

**Attack.** Sybil servers, fake activity and purchased reputation steer users towards
hostile servers.

**Decision rationale.** No reputation input exists that an attacker cannot mint, so
reputation must not gate anything until the discovery project (JEP-0003) designs one with
PoW and governance. The handshake carries a reputation field as a placeholder so the wire
does not need to change later.

## Adding an entry

1. Add the row to the spec register: ID, threat, decision (normative, one or two
   sentences), status.
2. Add a section here: attack, decision rationale, alternatives rejected, status
   evidence with file paths.
3. Reference the ID from the JEP that changes it.
