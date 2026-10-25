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

**Draft.** The decisions behind it are recorded in the design document, section 11. The
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
- transferring channel ownership (the `owner` role, held by DIDs), beyond co-owners named
  at creation. Moving the sequencer, the server that orders the channel, is in scope
  (11a) and does not change who owns the channel;
- nameserver-led contract templates;
- servers built differently from jig.

# Specification

## Encoding

0. Every message this JEP defines and signs (`contract-offer`, `contract-accept`,
   `contract-refuse`, `contract-end`, a custodian release policy and a key-package
   request) is a `COSE_Sign1` over deterministic CBOR, exactly as JEP-0004 rule 0 states,
   with `domain` `jig-contract-offer-v1`, `jig-contract-accept-v1`,
   `jig-contract-refuse-v1`, `jig-contract-end-v1`, `jig-kp-release-policy-v1` and
   `jig-kp-request-v1` respectively. Blocks (`channel-share`, `role-assign`,
   `sequencer-set` and the rest) and the `ingest` record are signed as JEP-0002 defines.

## Roles and addressing

1. A channel is identified by `channel_id`, the CID of its `channel-create` block.
   - The channel's current **sequencer** (the owner) is a hint, not part of the identity,
     because it can move (11a).
   - A slug is a display name, unique only per sequencer.
   - A server MUST key channels by `channel_id`, never by slug.
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

5. A `channel-create` block for a federable channel MUST carry `sequencer`, the first
   owning server's DID.
6. The terms of the contract are the creation block's fields: `sequencer`, `suite`,
   visibility and lock (the membership rule), and protocol version. The suite is fixed for
   the channel's life.

## Offer, accept, refuse, end

7. A share starts with a `channel-share` block naming the target server and a grant: its
   metadata is `{to, grant}`, where `to` is the target's DID in canonical form and `grant`
   is `read`, `write` or `member` (7a). The
   block MUST be signed by the channel's owner or by a DID holding the `share` right at
   that point in the `ingest` chain (7b). The owning server MUST then check that the
   target is on its configured peer list, and sends the target a `contract-offer`, signed
   by the owner. Only the owning server sends offers. The offer carries:
   - `offer_id`, unique per offer: the BLAKE3 hash of the deterministic encoding of the
     offer's payload, without `offer_id` itself;
   - the grant (7a);
   - the creation block;
   - the current `ingest` head (12);
   - the owner's current `server-manifest`, by CID and `seq` (16);
   - the name suffixes the owner attests, each with its authority (7c). A `config`-rooted
     one is never published, and appears only in contract messages (JEP-0004 rule 7).

   Its payload is `{domain, owner, to, channel_id, grant, creation_block, ingest_head,
   manifest: {cid, seq}, attested_suffixes, offer_id}`. `owner` is the signing server and
   `to` the offered one, so an offer cannot be replayed to a third server. `channel_id` and
   `manifest.cid` are CIDs as rule 0 states. `creation_block` and `ingest_head` are byte
   strings carrying the block and the record as they travel, and the receiver checks that
   the block's CID is `channel_id`.
7a. A grant is one of:
    - `read`: the follower relays only protocol traffic (MLS self-updates, self-leave) and
      no content;
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
      owners assign roles, and admins cannot create admins. Co-owners may be listed in the
      `channel-create` block only.
    - **Roles follow a channel-scoped key-link** (lane I's identity design). A `key-link`
      block, authored by the new DID and carrying a link whose audience is this channel,
      is ordered in the `ingest` chain. From its `seq`, the owning server reads the old
      DID's roles and membership as the new DID's. The creator rule carries across the
      link. A link scoped to another channel, alias or contact moves nothing here.
7c. `attested_suffixes` lists every name suffix the signing server attests, each once, as one
    of:
    - `{suffix, root: "config", authorities}`: `authorities` is the delegation's DIDs, in
      canonical form, sorted ascending and distinct, and never empty;
    - `{suffix, root: "dns", domain}`: `domain` is the DNS name whose zone roots the suffix.

    `suffix` and `domain` are normalised suffixes (JEP-0004 rule 1). There is no other root
    in v0.2: a `contract` root comes in v0.3, and an entry in any other shape is refused.
    Two entries name the same claim when their suffix, root and authority are equal. Each
    side compares the other's list with its own, so it decides a conflict from the contract
    messages alone, without fetching the other's manifest.
8. The offered server MUST answer, signed by its DID, with exactly one of:
   - `contract-accept {server, channel_id, offer_id, sequencer, manifest, attested_suffixes,
     bot_dids}`, where `server` is the signing server and `bot_dids` is empty except on a
     sequencer move (11a).
     - `offer_id` names the exact offer accepted, under the follower's signature. An
       accept binds only the grant in that offer.
     - `manifest` names its current `server-manifest`.
     - `attested_suffixes` lists the suffixes it attests, each with its authority (7c).
     - The accept states that the server implements the suite and will enforce the
       membership rule.
   - `contract-refuse {server, channel_id, offer_id, code}`, where `code` is one of `UNSUPPORTED_SUITE`,
     `UNSUPPORTED_VERSION`, `POLICY_REFUSED`, `NOT_A_PEER` or `SUFFIX_CONFLICT`.
     - `SUFFIX_CONFLICT`: the two servers claim one suffix under different authorities
       (JEP-0004 rule 7): the same `suffix` with a different root, a different
       `authorities` set or a different `domain`. The same suffix under the same
       authority is one claim, and no conflict. The owner checks the accept's list the
       same way, and refuses the contract on a conflict it finds.
9. A server MUST refuse when it does not implement the suite. It MUST NOT fall back to
   another suite or relay plaintext.
10. The owner MUST append each accept to the channel's log as a block, so members can see
    which servers carry the channel.
    - A `contract-accept` block carries `{to, offer, accept}`: the follower's DID, and the
      signed offer and accept, each base64. A member checks that the sequencer signed the
      offer to `to`, and that `to` signed an accept of it.
    - The owner records a refusal the same way, as a `contract-refuse` block carrying
      `{to, code, offer, refuse}`. When the owner refuses a share itself, because the
      target is not a configured peer (17), no offer was sent, and the block carries only
      `{to, code}`.
    - Only the channel's sequencer writes `contract-accept`, `contract-refuse` and
      `contract-end` blocks. A server MUST refuse one signed by anyone else.
11. Either side ends a share with a signed `contract-end {server, channel_id, offer_id}`,
    naming the accepted offer it ends. On the owner's side, a `channel-unshare {to}` block,
    signed as a `channel-share` must be (7), asks the owner to end its share with `to`. The
    owner records each end, its own or the follower's, as a `contract-end` block carrying
    `{to, end}`: the follower's DID and the signed `contract-end`, base64. Members then commit removals
    for any leaves reachable only through that follower. A grant changes by a new offer
    and accept.

11a. The owner moves the sequencer with a `sequencer-set` block. In v0.2 only
     the `owner` role holds that right.
     - The new sequencer MUST have accepted the contract before its first record.
     - The record for the `sequencer-set` block itself MUST be signed by the new
       sequencer, with `seq` = cited head + 1 and `prev` = the cited head's hash, whether
       or not the old sequencer is reachable.
     - Carriers MUST refuse records from the previous sequencer once they hold the
       `sequencer-set`.
     - **An owner's `sequencer-set` always wins over a server's own `sequencer-rekey`**
       (lane I's server-key ceremony).
       - A `sequencer-rekey` moves sequencing only to the rekeyed server's new DID, under a
         public link signed by the old and new server keys.
       - It is void from the first `sequencer-set` that follows it in the chain.
       - A carrier holding both for overlapping positions follows the `sequencer-set`.
       - So a thief with a leaked server key cannot keep a channel the owner has moved.
     - A member whose client merged a commit past the cited head rejoins by external
       commit.
     - A `sequencer-set` MAY carry owner-signed bot reinstalls (lane C's install format,
       with new bot DIDs and `inherits_state_from`). By default it carries one per current
       bot. The new sequencer MUST name the new bot DIDs in its `contract-accept`.

11b. When the sequencer moves (11a), the new sequencer issues, as part of its
     `contract-accept`, a `policy-approval` for the channel's current `channel-policy`
     and for every live `block-install`.
     - A `policy-approval` is a `COSE_Sign1` by the hosting server (JEP-0004 rule 0). It
       names the server, the channel, the CID of the policy or install it approves, and
       the CID of the server's restrictions. An approval of a `block-install` also
       carries the required `operator_policy_cid`, naming the operator policy the
       install's program was checked against, and the required `bot_did`, stating that the
       server holds that bot's key.
       The owner's `channel-policy` and `block-install` stay `COSE_Sign1`s by the owner.
     - Which approval is current is decided by the channel's `ingest` order: the latest
       `policy-approval` or `policy-withdrawn` for an object CID wins.
     - Clients MUST treat a policy or install without a current approval from the hosting
       server as absent. A move without these approvals therefore leaves the channel with
       no policy.
     - Because the approval is separate from the owner's object, a server can re-approve
       or withdraw one when its restrictions change, and a new sequencer can approve on a
       move, without the owner signing again.

     JEP-0011 defines `channel-policy`, `block-install`, `policy-approval` and
     `policy-withdrawn`.

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

14a. Clients report the latest sequencer record they verified to their server, which
     forwards heads to other carriers with no reader DID attached. Fork evidence is two
     conflicting sequencer signatures.
14b. A nameserver's list of abandoned or compromised servers (post-MVP) is advisory. A
     server MAY refuse new shares involving a listed server, and MUST NOT treat a listing
     as moving or unseating the sequencer the owner names.

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

16. A server's peer policy is its `server-manifest` block (JEP-0002), in its manifest
    log. Beyond JEP-0002's fields it MUST list:
    - the block kinds it relays;
    - per-peer quotas;
    - the DIDs of the peers it federates with that it chooses to publish;
    - the `dns`- and `contract`-rooted name suffixes it attests (JEP-0004). `config`-rooted
      suffixes are never published; they travel only in contract messages.

    Contract messages cite the current manifest by CID and `seq`.
17. In v0.2 a server MUST refuse an offer from a server that is not on its
    configured peer list (`NOT_A_PEER`).

## MLS

18. The owner MUST apply the delivery-service rules of the Encryption chapter: exact
    epoch, a commit that does exactly what its block says, one linear history.
19. Followers MUST track the group's public state from the stream and MUST NOT deliver a
    commit that does not validate.
20. Only clients commit. The group has no external senders in v0.2.
21. Key packages are held by **custodians**: servers or nameservers the DID
    names in its reachability record (JEP-0004). Each holds a release policy the DID
    signed.
    - A custodian MUST release a key package only to a request inside the policy's
      scopes. It holds any other request for the DID's approval.
    - Requests MUST be signed by the requester's DID and MUST name the channel.
    - A custodian MUST log every release. It MAY hold MLS Welcomes for the DID as a
      mailbox.
    - Key packages are self-signed by the DID, so a custodian can withhold one but cannot
      substitute one. Each carries a fresh leaf key certified by the DID (lane I).
    - A custodian MUST release **one key package per device** for a request, so the adder
      can add every device the DID has stocked packages for.
    - A custodian MUST stop releasing a DID's key packages once it holds that DID's
      revocation (lane I).
    - The sequencer takes no part in fetching key packages.

## Unchanged

22. **Client writes relayed to the owner.** For a client's block relayed by a follower,
    the owner re-verifies the author signature and runs its full write gate, including
    grants and roles (7a, 7b, 15), as for a local submission (federation.md, Relayed
    Blocks).
22a. **The owner's stream delivered to a follower.** For a block arriving in the owner's
     sequenced stream, a follower verifies:
     - the author signature;
     - the owner's `ingest` record, signed by the expected sequencer;
     - the `channel_id`, and the `seq`/`prev` chain (12–14);
     - the MLS state (19).

     A follower does not apply a local ownership write gate to such a block. The channel's
     authority is the owner's chain, not a local channel row.
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
- **Shares are visible to the servers.** `channel-share`, `channel-unshare` and the
  `contract-accept`, `contract-refuse` and `contract-end` records are control blocks in
  clear on every suite, a restricted MLS channel's included: the owning server must read a
  share to make its offer, and members check the records. The owning server's operator, and
  every server that carries the channel, therefore learn which servers the channel is
  shared with, under which grant, who asked, and when. They learn nothing of the channel's
  content, which stays MLS ciphertext. A share sent encrypted is refused, not carried
  unread (PV-05).

**Threat register rows:** OP-06, OP-09, AB-03, PV-01 and PV-05 are updated in implementation
PRs.

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- Open, unencrypted channels keep today's relay until F2 replaces it.
- Slug-keyed channels without `sequencer` stay local.

# Reference Implementation

In progress (milestone F2): the contract messages are `jig_core::contract`.

# Test Vectors

`vectors/0005/vectors.json`: a `contract-offer` with its `offer_id`, and the
`contract-accept`, `contract-refuse` and `contract-end` answering it, each as its
deterministic payload and its `COSE_Sign1`, in hex, under fixed test keys. The offer's
`creation_block` and `ingest_head` are placeholder bytes. The offer lists one
`config`-rooted suffix under the owner's DID, and the accept one `dns`-rooted suffix.

To be added with F2:

- a three-entry sequence chain;
- a `server-manifest` carrying peer policy.

# Rejected Alternatives

- **Multi-homed channels with state resolution** (Matrix, IRC). Merge rules become the
  attack surface (Matrix's 2025 state-reset CVEs), and MLS needs one linear epoch history.
- **Requiring clients to find and connect to the owner.** That defeats sharing. A client
  connects to the owner directly only to write past a follower's grant.
- **Routing key-package requests through the sequencer.** The sequencer gains nothing
  from them, and the DID's custodian is what has to enforce its policy.

# Copyright

This document is licensed under CC-BY-4.0.
