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
   `contract-refuse`, `contract-end`, a custodian release policy, a key-package request
   and a decision on a held request) is a `COSE_Sign1` over deterministic CBOR, exactly
   as JEP-0004 rule 0 states, with `domain` `jig-contract-offer-v1`,
   `jig-contract-accept-v1`, `jig-contract-refuse-v1`, `jig-contract-end-v1`,
   `jig-kp-release-policy-v1`, `jig-kp-request-v1` and `jig-kp-decision-v1` respectively. Blocks (`channel-share`, `role-assign`,
   `sequencer-set` and the rest) and the `ingest` record are signed as JEP-0002 defines.

## Roles and addressing

1. A channel is identified by `channel_id`, the CID of its `channel-create` block.
   - The channel's current **sequencer** (the owner) is a hint, not part of the identity,
     because it can move (11a).
   - A slug is a display name, unique only per sequencer.
   - A server MUST key channels by `channel_id`, never by slug.
   - *Non-normative.* A link to a channel is written
     `jig:<channel_id>[?sequencer=<did>&slug=<slug>]`. The `channel_id` is in its one
     canonical text spelling (base32 lowercase with the `b` prefix, as JEP-0004 rule 0
     gives a CID in text), and the query values are percent-encoded. The query carries
     hints only: a reader ignores keys it does not know, and never takes the channel from
     a hint. The reference CLI accepts links of at most 512 bytes.
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

   *Note (D37, #375):* when the owner's key has rotated since the creation block named it,
   the owner sends its key-link chain, from the DID the creation block names to the offer's
   signer, in its own peer frame beside the `contract-offer`, not inside the offer. A server
   MUST ignore a peer frame kind it does not know, so this frame is additive; a receiver
   that does not verify the chain refuses the offer as it does today.
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
      - Its metadata is `{channel_id, link}`: `link` is the JEP-0012 link, base64
        COSE_Sign. The kind name has no `opt-` prefix, so the block is critical (14c).
      - The sequencer MUST refuse it unless:
        - the link verifies under both its keys;
        - its audience is `{kind: "channel", channel_id}` for this channel;
        - its `new` DID is the block's author;
        - its `old` DID holds membership or a role at the block's position;
        - no earlier `key-link` in the chain leaves the same `old` DID (JEP-0012,
          ordered logs);
        - `new` holds no membership or role in the channel.
      - From the block's `seq` on, `old` holds nothing in the channel, and `new` holds
        what `old` held. A root owner (the creator or a co-owner) stays a root owner
        under `new`.
      - On an MLS channel the link moves the roster and the roles, not the leaf. It
        carries no commit. The new DID then joins by its own external commit, which
        the owner's gate admits because the roster lists it. The old DID's leaf is
        removed by an ordinary member commit (the tidy-up `member-remove`: the old
        DID is no longer a member). The new DID's client sends that commit right
        after its join, before any application message, and any member's client
        whose tree still holds the old leaf may send it. Whichever lands first
        removes the leaf; the others are refused as stale. Until it is removed, the
        old leaf can read every epoch it is still in. A member that has not yet seen
        the link may still commit (an add, or the removal of someone else), and the
        old leaf holds that epoch too. Clients that hold the link send nothing, and
        commit only the new DID's join and the old leaf's removal, so the window ends
        with the first such client to act.
      - A client that has verified a `key-link` MUST NOT encrypt to a group whose
        tree still holds the old DID's leaf, and MUST NOT commit anything to it but
        the old leaf's removal, or, as the new DID, its own external join.
      - The atomic form, one external commit by the new DID that also removes the
        old leaf, is valid MLS: RFC 9420 leaves it to the application which
        identities a joiner may remove. The openmls version we use can't build an
        external commit that removes a leaf with a different key, so the old leaf is
        removed by an ordinary member commit right after the join.
      - A refusal is `KEY_LINK_REFUSED`.
      - The sequencer MUST judge a block's rights and give it its `seq` as one step
        with respect to the channel's `key-link`s. No link may land between the check
        of a block signed by `old` and that block's `seq`.
      - **Root owners, for every reader.** The channel's root owners are the creator
        and the co-owners its `channel-create` lists, each carried along the
        `key-link`s that follow it, in chain order. A link from a DID that is not a
        root owner at that point moves no root, and a root owner linked away is no
        longer one. Servers and clients MUST use this one reading wherever they ask
        who is an owner, including who may sign a `sequencer-set` (11a). A client
        keeps each `key-link` it verifies in the chain for this purpose.
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
     - A **move accept** (11a) names `server` itself as `sequencer`, and also carries
       `policy_approvals`, a list of byte strings (11b). No other accept carries that
       key, so an ordinary accept's bytes are what they were before moves existed.
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
      `{to, code, offer, refuse}`. When the owner refuses a share itself, the block
      carries only `{to, code}`, and `code` is the owner's own reason: `NOT_A_PEER` when
      the target is not a configured peer (17), so no offer was sent, or `SUFFIX_CONFLICT`
      when the target's accept claims one of the owner's suffixes under another authority
      (8). A refusal with any other code carries the target's signed message.
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
     - **Metadata:** `{channel_id, sequencer, head: {seq, hash}, accept, reinstalls}`.
       - `sequencer` is the new sequencer's DID in canonical form.
       - `head` is the cited head: the `seq` of the last record the old sequencer
         signed, and that record's hash as the next record's `prev` names it (64
         lowercase hex digits).
       - `accept` is the new sequencer's **move accept**, base64: a `contract-accept`
         (8) for the offer of this channel it accepted as a follower, naming itself as
         `sequencer`. It carries `bot_dids` and `policy_approvals` (11b), and travels
         only inside this block, so a move needs nothing from the old sequencer.
       - `reinstalls` holds one owner-signed bot reinstall per entry of the accept's
         `bot_dids`, base64.
       - The block carries no `mls_` key and is sent in clear on every suite, like
         `channel-share`. The kind name has no `opt-` prefix, so the block is critical
         (14c). Its `seen` (JEP-0002) MUST be the cited head's record.
     - **Who checks what.** Every carrier and client MUST check, before acting on the
       block:
       - the author held the `owner` right at the block's position;
       - the move accept verifies, is signed by `sequencer`, names `sequencer` as the
         channel's sequencer, and is for this channel;
       - the block's own record is signed by `sequencer`, with `seq` = `head.seq` + 1
         and `prev` = `head.hash`.

       Because `head` sits inside the owner's signature, the new sequencer cannot
       choose where the move cuts the chain.
     - **One slug per sequencer.** A slug names one channel per sequencer (1). A server
       MUST NOT issue a move accept for a channel whose slug it already holds, including
       an archived one; it refuses with `SLUG_TAKEN`. A follower that would hold two
       channels of one slug under one sequencer stops the channel, with the evidence
       kept. The owner renames the channel before moving it.
     - **The expected sequencer.** A reader keeps, per channel, a schedule of who signs
       each range of `seq`:
       - from `seq` 0, the server the `channel-create` names, along its public key
         links (JEP-0012);
       - from the `seq` of each `sequencer-set` record on, the DID that block names.

       A record MUST be signed by the sequencer of the range its `seq` falls in. Inside
       one range, the JEP-0012 link order holds. A record with `seq` above a cited head,
       signed by a DID of an earlier range, MUST be refused. This holds whatever key
       links that DID serves later, so a later rotation of the old sequencer never
       extends its range. Such a refusal is a break, kept as evidence. It is not a
       signed proof against either server, since it is two keys' words. Backfill is
       positional: a record at or below a cited head is checked against the range it
       falls in, whenever it arrives.
     - **Where the follower stands.** A follower may receive the `sequencer-set` from
       the new sequencer before it holds any share with it, because the re-offer comes
       after the move. It MUST take the set only from a configured peer, and only under
       a live share with the sequencer the set moves from. It MUST charge the peer's
       quota before it checks any signature.
       - **Behind the cited head.** The follower keeps the set. It takes the records up
         to the cited head from the new sequencer, which serves them, and checks each
         against the range of the schedule it falls in: the old sequencer's, whoever
         serves it. It lands the set once it holds the cited head exactly. A dead old
         sequencer therefore cannot strand it.
       - **Past the cited head.** The follower already holds records past the cited head,
         signed by the old sequencer. Those records have applied their effects (members,
         roles, the MLS group). A follower that holds records past the cited head MUST
         stop the channel as for a fork, unless it can rebuild the carried state to the
         cited head and set them aside. Records set aside are kept as evidence and never
         delivered. Their writes are lost, as the bullets below say.
       - Two valid `sequencer-set` blocks at one `seq` are the owner's own
         contradiction: the channel stops at that `seq`, and both are kept.
     - **Taking over.** Once the new sequencer has sequenced the block, it sequences the
       channel. It sends each server that holds a live share (a `contract-accept` in the
       chain without a later `contract-end`) a new `contract-offer` at the grant that
       server had. Such a re-offer cites the channel's `sequencer-set`. A follower that
       already carries the channel accepts it automatically when the new sequencer is a
       configured peer and the grant is the same as before, or narrower. It holds a
       wider grant for its operator (DJ 2026-11-26, revising the 2026-10-19 default).
       An old sequencer that learns of the move refuses writes to the channel with
       `SEQUENCER_MOVED`, naming the new sequencer.
     - **Readers that predate the move.** A reader that does not implement
       `sequencer-set` cannot verify the block's record, because a key it does not
       expect signs it. The 14c stop therefore never reaches it. Servers say it for
       14c instead, for every kind added since `v0.2.0`:
       - A client MUST declare every block kind it implements: in its hello's
         `capabilities.block_kinds` on a connection, and in the `jig-capabilities`
         header on a request, which carries no hello. A welcome's `block_kinds` stays
         the server's allow-list.
       - Let a channel's **gate** for a client be the first block in its chain whose kind
         is critical (14c), is not one of the kinds `v0.2.0` implements, and is not one
         the client declares. A non-critical (`opt-`) kind never gates.
       - A server serves the client the channel's records before the gate as usual. It
         MUST NOT deliver the gate's record or any record after it. A history or records
         read that reaches the gate is cut there. A read that starts at or past it, a
         live subscription when the gate lands, and a subscription made once the gate is
         in the chain are answered with `CHANNEL_NEEDS_UPGRADE`, naming the kind and the
         gate's `seq`.
       - A `v0.2.0` client declares no kinds, so it is served each channel up to its
         first `sequencer-set`.
       - A `v0.2.0` follower cannot accept the new sequencer's re-offer, because the
         creation block names another server. It keeps the channel at the cited head
         and shows nothing; the release notes say so (DJ 2026-11-26).
       - A `v0.2.0` old sequencer never learns of the move, and goes on signing past
         the cited head: the partitioned case below. A client SHOULD refuse to sign a
         `sequencer-set` while the old sequencer is reachable and its welcome does not
         list `sequencer-set`, unless its user states the old sequencer is unreachable
         (DJ 2026-11-26).
     - *Note (D38):* a `v0.2.0` node does not implement this rule. It MUST fail closed on a
       channel whose chain holds a `sequencer-set`, rather than accept records from either
       sequencer. The expected-sequencer rule arrives in v0.2.x.
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
    - A block the follower already holds in another channel of its own, whose chain names it
      too, is kept in both chains, each under its own record. The follower MUST NOT move it or
      re-sign either record (#427).
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
14c. **Block kinds a reader does not implement.** A follower or client meets blocks of
     kinds added after it was built. Such a block is **critical** unless its kind name
     starts with `opt-`. A block whose metadata carries any key that starts with `mls_`,
     other than `mls_message` and `mls_epoch`, is critical whatever its name. The v0.2
     keys this covers are `mls_commit`, `mls_welcome`, `mls_group_info` and
     `mls_ratchet_tree`, and any `mls_` key added later is covered too. The kind name is
     in the manifest, so the author's signature covers it, and no relay can add or remove
     the marker. Kind names that start with `opt-` are reserved for non-critical kinds,
     and no kind defined in v0.2 uses the prefix.
     - A reader MUST verify the author's signature and the owner's record before it acts
       on a block's criticality.
     - A follower MUST store a non-critical block of an unknown kind as the next link of
       the chain, without executing it or applying any effect, and MUST deliver it like
       any other block. Clients MUST skip its content. The chain stays continuous.
     - On a critical block of an unknown kind, a follower or client MUST stop that channel
       at that `seq`. It MUST NOT apply the block, read past it, or request it again
       while it cannot implement the kind. It MUST surface that the channel needs an
       upgrade, and MUST NOT stop any other channel. A follower answers its clients'
       subscriptions and history reads of the channel with the error code
       `CHANNEL_NEEDS_UPGRADE`, naming the kind and the `seq`. It sends that error once
       to a subscription already open when the channel stops.
     - Once upgraded to implement the kind, a reader takes the channel up again from the
       block it stopped at.
     - A server still refuses a block of a kind it does not implement when the block is
       submitted to it as the channel's sequencer. This rule covers only blocks a reader
       receives already sequenced.

## Writes through followers

15. A client submits to the server it is authenticated to. If that server is a follower,
    it relays the block to the owner within its grant.
    - The follower MUST apply its own admission, proof-of-work and rate limits to the
      client before relaying.
    - The owner MUST run its full write gate on the relayed block, as for a local
      submission (OP-09).
    - A relayed block MUST stay attributable to its author, and the owner SHOULD record
      the relaying server's DID.
    - Admission is delegated to the follower. The owner MUST NOT ask a relayed author for
      proof of work: any the author did answered the follower's challenge, not the
      owner's. The owner MUST still refuse an author it bans or that falls below its
      ruleset floors, and MUST check the author's signature and the grant (7a) on every
      relayed block. The follower answers for what it relays: the owner records its DID
      with each block, limits what it relays into each channel, and can end its share
      (11) (AB-07).
    - A relayed block MUST be for the channel the follower's share covers. A
      `channel-create` is outside every share.
    - The owner MUST take a relayed block it already holds as accepted, before any effect,
      so a client that did not learn a relay's outcome can submit the same signed block
      again.

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
21a. A **key-package request** is a `COSE_Sign1` by `requester` (rule 0, domain
     `jig-kp-request-v1`) over
     `{domain, requester, did, channel_id, custodian, nonce, issued_at}`: `channel_id` is
     the binary CID of the channel the package is for, `custodian` the custodian's server
     DID, `nonce` 16 fresh bytes and `issued_at` Unix seconds on the requester's clock.
     Vectors are in `vectors/0005/kp-request.json`.
     - A requester finds custodians in the DID's reachability record: from the nameserver
       that verified its name, or from a server the requester is told the DID uses. It
       holds each to the record's `server_did` by its signed welcome before asking.
     - A custodian MUST refuse a request not signed by its `requester`, naming another
       custodian, or with `issued_at` outside its acceptance window. It answers `404
       NO_CUSTODY` for a DID whose record it does not keep, or of which it holds no
       package.
     - The same request, or the same requester asking again for the same DID and channel
       within a short window, gets the package already released: a lost answer costs the
       DID no second package.
     - A custodian MUST bound releases per DID and per requester (`429 RATE_LIMITED`). A
       last-resort package is released but never consumed, so a drained stock leaves the
       DID reachable. The bounds and the log cover every way a package leaves the server,
       including its own channels' adds.
     - A record that leaves the custodian out, with a higher `seq` than the one it holds,
       withdraws custody: the custodian keeps it so no older record restores custody, and
       answers `NO_CUSTODY` from then on. Withdrawal ends releases to other servers'
       requesters only: the server's own channels can still add the DID from its stock.
       Ending those adds, or erasing the DID's data, are separate requests, not yet
       defined (#449).
     - The requester MUST check that a released package verifies and is the DID's before
       it commits.
21b. A **release policy** is a `COSE_Sign1` by `did` (rule 0, domain
     `jig-kp-release-policy-v1`) over
     `{domain, did, custodian, seq, issued_at, release_to, release_any}`:
     - `custodian` is the server DID it is for;
     - `seq` is an unsigned integer: a custodian keeps only the policy with the highest
       `seq` it has seen for `(did, custodian)`;
     - `release_to` is an array of the requester DIDs it releases to, each a canonical
       did:jig key, at most 256, sorted by their deterministic encoding and without
       repeats;
     - `release_any` is a boolean: release to any requester. `release_to` MUST then be
       empty.

     A verifier MUST refuse any other form, so that each policy has one encoding. A
     custodian MUST refuse a policy that names another custodian. A request from a
     requester the policy releases to is released as 21a says. Any other request is held
     (21c). A DID that has stored no policy with a custodian falls back to that server's
     own configured policy: `open`, within the limits of 21a, or `closed`
     (DJ 2026-11-26), so that DIDs whose clients predate policies keep the release they
     had. Vectors are in `vectors/0005/kp-custody.json`.
21c. **Held requests.** A custodian answers a request it holds with `409 HELD` and the
     request's `request_id`: BLAKE3-256 over the request's deterministic payload. It is a
     refusal, not a release, so a requester that does not know holds reports it as one.
     - The DID reads its held requests with a read proof of its own (JEP-0002), addressed
       to the custodian. Nobody else may read them: they say who is trying to add the
       DID, and to which channel.
     - The DID answers a held request with a **decision**: a `COSE_Sign1` by `did`
       (rule 0, domain `jig-kp-decision-v1`) over
       `{domain, did, custodian, request_id, approve, issued_at}`, where `approve` is a
       boolean. A custodian MUST refuse a decision that names another custodian, or a
       `request_id` that is not a request it holds for that same DID. A request is decided
       once.
     - An approval lets the requester's next request for the same DID and channel be
       released as the policy would have released it, once, within 24 hours. The limits
       of 21a still apply. No package is set aside, and nothing new is sent: the
       requester asks again with a fresh signed request.
     - A refusal is final for that request. The requester may still ask again; a new
       request is held again.
     - Every hold, decision and release is logged, as in 21a.

     The Welcome mailbox and one package per device are not yet defined.

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
- **Delegated admission.** A follower admits the authors whose writes it relays, and the
  owner does not ask them for its own proof of work (15). A hostile follower can relay
  authors the owner would have charged, but not one the owner bans or rates below its
  floors. It can relay only into the channels it shares, only the kinds its grant
  carries, and only as fast as the owner's limit for it. Each block names it, and ending
  its share stops it (AB-07).
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

- **Key-package custody** (21–21c). A custodian can withhold a DID's packages, and can
  log who asked for them; it cannot substitute one, since each is signed by the DID and
  checked by the adder. Under a server's own `open` policy, anyone it admits can ask,
  within its limits, so many identities that each pass admission can draw a DID's
  ordinary stock down to its last-resort package. The DID stays reachable, but adds that
  reuse the last-resort package share its init key until the DID updates its leaf. A
  release policy the DID signed (21b) closes this: a requester it does not name is held
  until the DID approves (21c), so only those the DID names, or approves, draw its stock.
  A DID that stores no policy keeps the server's. The held list shows who is trying to
  add the DID, so only the DID reads it.

- **Unknown block kinds** (14c). A hostile owner can sequence a critical block of an
  invented kind to stop a channel at readers that do not implement it. That is no more
  than it can already do (it can stop the channel). It cannot make a reader skip a block
  that changes the group, because any group key makes a block critical. No one else can
  turn a critical block into a skippable one, because the marker is part of the signed
  kind name.

**Threat register rows:** OP-06, OP-09, AB-03, AB-07, PV-01 and PV-05 are updated in
implementation PRs.

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- Open, unencrypted channels keep today's relay until F2 replaces it.
- Slug-keyed channels without `sequencer` stay local.
- Rule 14c lets later releases add block kinds without stalling v0.2 readers. A new kind
  is skippable by them only if it is named `opt-*` from the start. Changing a kind's
  criticality means naming a new kind.

# Reference Implementation

In progress (milestone F2): the contract messages are `jig_core::contract`.

# Test Vectors

`vectors/0005/vectors.json`: a `contract-offer` with its `offer_id`, and the
`contract-accept`, `contract-refuse` and `contract-end` answering it, each as its
deterministic payload and its `COSE_Sign1`, in hex, under fixed test keys. The offer's
`creation_block` and `ingest_head` are placeholder bytes. The offer lists one
`config`-rooted suffix under the owner's DID, and the accept one `dns`-rooted suffix.

`vectors/0005/kp-request.json`: a `jig-kp-request-v1` (21a) under fixed test keys, as its
deterministic payload and its `COSE_Sign1`, in hex.

`vectors/0005/kp-custody.json`: a `jig-kp-release-policy-v1` (21b) releasing to two
requesters, the `request_id` of the request in `kp-request.json`, and a
`jig-kp-decision-v1` (21c) approving that request, each as its deterministic payload and
its `COSE_Sign1`, in hex, under fixed test keys. Under `refused`, the same policy and
decision signed for another custodian: valid objects that the custodian above MUST refuse.

`vectors/0005/unknown-kinds.json` (14c): manifests of kinds that no v0.2 build implements,
each signed under a fixed test key. For each it gives whether the block is critical and
whether the author's signature verifies. The cases are: no marker; the `opt-` prefix; the
prefix with `mls_commit`; the prefix with only `mls_message` and `mls_epoch`; the prefix
with an `mls_` key not yet named; and the prefix added after signing.

`vectors/0005/sequencer-move.json` (7b, 11a): under fixed test keys, a `sequencer-set`'s
metadata and its record's `seq`, `prev` and signer; the move accept it carries, with no bot
and with one, as its deterministic payload and its `COSE_Sign1`, in hex; and a `key-link`'s
metadata and author.

To be added with F2:

- a sequence chain across a `sequencer-set`: three records by the old sequencer, the set's
  record by the new one, a record after it, and a record by the old sequencer past the
  cited head, which is refused;
- a hello that lists the block kinds its client implements (11a);
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
