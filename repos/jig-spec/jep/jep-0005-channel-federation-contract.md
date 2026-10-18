+++
jep = 0005
title = "Channel Federation Contract"
status = "Draft"
type = "Standards Track"
category = "Federation"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-18"
requires = ["0001", "0002", "0004"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

A cross-server channel has exactly one owning server (D24). The owner orders every block
and is the MLS delivery service. Servers the channel is shared with are followers, each
under a grant (read, write or member). A client reads and writes through whichever server
it is authenticated to, without knowing the owner. Followers relay writes to the owner
within their grant and deliver the owner's ordered stream. The contract is three things:

- the creator-signed `channel-create` block, which fixes the suite, the membership rule
  and the owner (D12);
- a server-signed accept or refuse from each follower;
- the owner-signed `ingest` record on every block (JEP-0002), which makes forks and
  omissions detectable.

Design record, alternatives and prior art (XMPP MUC, IRC, Matrix, ActivityPub groups,
IETF MIMI):
[`docs/superpowers/specs/2026-10-18-federation-naming-and-contract-design.md`](../../../docs/superpowers/specs/2026-10-18-federation-naming-and-contract-design.md),
sections 5–7.

**Draft. Choices marked (pending DJ) are recommendations, not decisions.** The
server-to-server handshake is lane L7's JEP-0002 work. This JEP assumes a mutually
authenticated, bidirectional server connection and specifies only what runs over it.

# Motivation

Phase 1 exit criterion: "a channel's federation data contract is specified and two jig
servers federate an encrypted channel through it". Today:

- only open, unencrypted channels federate;
- channels are identified by slug and are first-come per server;
- nothing records an owner;
- only the server that hosts a channel can validate its MLS commits.

Non-goals for v0.2:

- open federation with unconfigured servers;
- moving ownership;
- nameserver-led contract templates;
- servers built differently from jig.

# Specification

## Roles and addressing

1. A channel is identified by `(owner_server, channel_id)`.
   - `owner_server` is the owning server's DID.
   - `channel_id` is the CID of the `channel-create` block.
   - A slug is a display name, unique only per owner.
   - A server MUST key remote channels by this pair, never by slug.
2. The **owner** holds the channel's authoritative state, orders all blocks and validates
   all MLS commits.
3. A **follower** is a server the channel has been shared with: it has accepted the
   channel's contract under a grant (7a).
4. A user is a DID with no home server. A channel does have one: its owner, the only
   server that signs its `ingest` records. A client reads and writes a shared channel
   through any server it is authenticated to that carries the channel, and need not know
   the owner. The servers where a DID can be reached come from its reachability record
   (JEP-0004).

## Terms

5. A `channel-create` block for a federable channel MUST carry `owner_server`.
6. The terms of the contract are the creation block's fields: `owner_server`, `suite`,
   visibility and lock (the membership rule), and protocol version. The suite is fixed for
   the channel's life.

## Offer, accept, refuse, end

7. A share starts with a `channel-share` block naming the target server and a grant. The
   block MUST be signed by the channel's owner or by a DID holding the `share` right at
   that point in the `ingest` chain (7b). The owning server MUST then check that the
   target is on its configured peer list, and sends the target a `contract-offer`, signed
   by the owner. Only the owning server sends offers. The offer carries:
   - the grant (7a);
   - the creation block;
   - the current `ingest` head (12);
   - the hash of the owner's signed peer policy (16).
7a. A grant is one of:
    - `read`: the follower relays only protocol traffic (`seen` acknowledgements, MLS
      self-updates, self-leave) and no content;
    - `write`: the follower also relays content blocks from channel members;
    - `member`: the follower also relays the membership blocks the channel's rule allows.

    The owner MUST enforce the grant on every relayed block. A follower SHOULD refuse
    early. A client that wants to write past a follower's grant connects to the owner
    directly, under the owner's admission.
7b. Authority is role-based.
    - Role assignments are `role-assign` and `role-unassign` blocks, ordered in the
      `ingest` chain.
    - The owning server MUST check the signer's rights as of the block's position in the
      chain for every `channel-share`, membership block and commit.
    - The creator holds the root `owner` role, which carries every right and cannot be
      removed.
    - v0.2 defines one more role, `admin`, with the rights `share` and `membership`. Only
      the owner assigns roles (pending DJ).
8. The offered server MUST answer, signed by its DID, with exactly one of:
   - `contract-accept {channel_id, owner_server, policy_hash}`, stating that it
     implements the suite and will enforce the membership rule;
   - `contract-refuse {channel_id, code}`, where `code` is one of `UNSUPPORTED_SUITE`,
     `UNSUPPORTED_VERSION`, `POLICY_REFUSED`, `NOT_A_PEER` or `SUFFIX_CONFLICT` (the two
     servers claim one name suffix under different authorities, JEP-0004).
9. A server MUST refuse when it does not implement the suite. It MUST NOT fall back to
   another suite or relay plaintext.
10. The owner MUST append each accept to the channel's log as a block, so members can see
    which servers carry the channel.
11. Either side ends a share with a signed `contract-end`. Members then commit removals
    for any leaves reachable only through that follower. A grant changes by a new offer
    and accept.

## Ordering

12. The owner MUST attach to each block it accepts the `ingest` record of JEP-0002:
    `{channel_id, seq, ingest_hlc, block_cid, prev}`, signed by the owner.
    - Followers MUST relay the record unchanged and MUST NOT re-sign it.
13. Followers MUST keep the chain and MUST deliver blocks to their users in `seq` order.
14. A follower MUST stop delivering the channel when it sees any of these, and SHOULD
    surface the conflicting records as evidence:
    - a gap in `seq`;
    - two records with the same `seq` and different content;
    - a block whose `seen` cites a record the follower does not hold and cannot obtain
      from the owner.

## Writes through followers

15. A client submits to the server it is authenticated to. If that server is a follower,
    it relays the block to the owner within its grant.
    - The follower MUST apply its own admission, proof-of-work and rate limits to the
      client before relaying.
    - The owner MUST run its full write gate on the relayed block, as for a local
      submission (OP-09).
    - A relayed block MUST stay attributable to its author, and the owner SHOULD record
      the relaying server's DID.

## Peer policy

16. A server MUST publish a policy document signed by its DID, listing:
    - protocol versions;
    - hosted suites;
    - block kinds it relays;
    - per-peer quotas;
    - the DIDs of the peers it federates with;
    - the name suffixes it attests and their roots (JEP-0004).

    Contract messages cite its hash.
17. (pending DJ) In v0.2 a server MUST refuse an offer from a server that is not on its
    configured peer list (`NOT_A_PEER`).

## MLS

18. The owner MUST apply the delivery-service rules of the Encryption chapter: exact
    epoch, a commit that does exactly what its block says, one linear history.
19. Followers MUST track the group's public state from the stream and MUST NOT deliver a
    commit that does not validate.
20. Only clients commit. The group has no external senders in v0.2.
21. (pending DJ) Key packages are fetched through the owner: the requester's server → owner
    → a follower (holding a `member` grant) where the target's reachability record says
    the target can be reached. The owner may also serve one itself.
    - The request MUST be signed by the requester's DID and MUST name the channel.
    - The serving server MUST apply the target's consent policy before releasing a key
      package.
    - Key packages are self-signed by the target's DID, so relays can withhold but cannot
      substitute.

## Unchanged

22. Every receiving server re-verifies author signatures and runs its gates on relayed
    blocks (federation.md, Relayed Blocks).
23. Encrypted content is never executed. Its receipts are `sealed`.

# Security Considerations (Zero-Trust)

**What a hostile owner can and cannot do:**

- It cannot read content (MLS) or forge blocks (author signatures).
- It cannot show followers different histories without detection (12–14).
- It can censor and can stop the channel. Both are accepted (OP-06).
- It can collude with the channel-owner DID to add members. This is the same trust as a
  single-server channel.

**Other threats:**

- **A hostile follower** can censor its own users, which it can already do. It cannot
  wedge others (19).
- **Metadata.** The owner and every follower see routing metadata for the channel. There
  is no metadata-privacy claim (OP-04, PV-01).

**Threat register rows:** OP-06, OP-09, AB-03 and PV-01 are updated in implementation PRs.

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- Open, unencrypted channels keep today's relay until F2 replaces it.
- Slug-keyed channels without `owner_server` stay local.

# Reference Implementation

None yet. Milestone F2 of the design.

# Test Vectors

To be added with F2:

- a `contract-offer`, a `contract-accept`, a `contract-refuse`;
- a three-entry sequence chain;
- a signed peer policy.

# Rejected Alternatives

- **Multi-homed channels with state resolution** (Matrix, IRC). Merge rules become the
  attack surface (Matrix's 2025 state-reset CVEs), and MLS needs one linear epoch history.
- **Requiring clients to find and connect to the owner.** That defeats sharing. A client
  connects to the owner directly only to write past a follower's grant.
- **Fetching key packages follower to follower.** Every pair of servers would need to
  peer.

# Copyright

This document is licensed under CC-BY-4.0.
