+++
jep = 0014
title = "Channel Tiers: Visibility, Joining and Encryption"
status = "Draft"
type = "Standards Track"
category = "Core"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-25"
requires = ["0001", "0002", "0005", "0006", "0007", "0008", "0010"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

Every channel belongs to one of four **tiers**, fixed when it is created:

| Tier | Who joins | Encrypted |
| --- | --- | --- |
| `private` | added by a member or admin | yes, MLS |
| `server` | anyone holding the required server role joins themselves | yes, MLS |
| `shared` | as `server`, across servers under a federation contract | yes, MLS |
| `public` | anyone | **no**: signed, readable by anyone, the server operator included |

Three tiers are encrypted, and the operator cannot read them. `public` is the only plaintext
tier. Choosing it is explicit, it is labelled wherever it is shown, and no existing channel can
be switched into it.

This JEP settles the question D25 left open: whether every channel is encrypted by default
after the v0.2 tag. It is, except a channel created as `public`. The JEP also specifies:
- the server roles a join rule can name;
- what a joiner can read;
- how a 1:1 grows into a group;
- how today's plaintext open channels migrate;
- what moves from the server to clients as a result.

It amends JEP-0001 and JEP-0005 where noted.

# Motivation

- **Operators are untrusted** (D11). Under D25 today, restricted channels and DMs are always
  MLS, but an open channel is plaintext unless its creator asks for `--encrypted`, and the
  operator reads it. Product constraint 4 is "secure and E2EE by default".
- **Joining should not need the server to read content.** An open channel is open because
  anyone the server admits can join. MLS external commits (RFC 9420 §12.4.3.2) let a joiner
  add itself, and `jig-mls` already supports them (`Member::join_external`,
  `delivery::Intent::Join`). The server can gate the join on who the joiner is, without ever
  holding a group secret.
- **Plaintext should be a decision, not a default.** Announcements, a server's own system
  channels and public archives need content that anyone can verify and read. That is the
  `public` tier, and it says so.

**Non-goals:**
- metadata privacy (OP-04 is accepted);
- changing a channel's tier in place;
- the agent capability model itself (JEP-0007) and enclave attestation (section 7.4's
  research track).

# Specification

The key words MUST, MUST NOT, SHOULD and MAY are as in RFC 2119.

## 1. Tiers

1. A `channel-create` block MUST carry `tier`: one of `private`, `server`, `shared` or
   `public`. A server MUST refuse an unknown `tier` (`UNKNOWN_TIER`). Channels created before
   this JEP are read as section 6 says.
   - A new `channel-create` without `tier`, from a client that predates this JEP, is mapped as
     section 6's table maps stored channels: `restricted` with `mls` is `private`, and `open`
     with `mls` is `server` with `join = guest`.
   - A new `channel-create` without `tier` that would be `open` with `none` MUST be refused
     (`UNKNOWN_TIER`). Otherwise an old client would create a `public` channel without the label
     or the confirmation that rule 5 requires.
   - A server that implements this JEP advertises the `tiers` feature in its `welcome`
     capabilities (JEP-0002). A client MUST NOT send a `channel-create` with `tier` `server` or
     `shared` to a server that does not advertise it: such a server ignores `tier`, reads the
     channel as `open`, and admits any authenticated joiner.
2. **The tier is fixed for the channel's life**, like its suite (JEP-0001). Changing a tier
   means creating a new channel. A server MUST refuse any block that would change a
   channel's tier, `channel-promote` included.
3. **Suites by tier:**
   - `private`, `server` and `shared` MUST use an operator-confidential suite (JEP-0001); today
     that is `mls`.
   - `public` MUST use `none`. A server MUST refuse a `public` channel under any other suite,
     and an encrypted tier under `none` (`TIER_SUITE_MISMATCH`).
4. **`public` is never a destination.** No block, migration or successor (section 6) turns an
   encrypted channel, or its history, into a `public` one. A `public` channel's successor MAY be
   encrypted; the reverse is not allowed.
5. **The `public` label.** A client MUST show a `public` channel's tier wherever it shows the
   channel, with words to the effect of "anyone, including the server operator, can read
   this". A client MUST ask the creator to confirm before it signs a `public`
   `channel-create`. A server MAY refuse `public` channels by policy.
   - A client that implements this JEP requests the `tiers` capability in its `hello`
     (JEP-0002). A server MUST refuse a content block in a `public` channel from a connection
     that did not request it (`TIER_UNSUPPORTED`). An older client cannot show the label, so it
     may read a `public` channel but not post to it.
6. **System channels are `public`.** The server's own channels under the reserved `#jig/`
   prefix carry what anyone must be able to verify. Today that is the manifest log
   (`#jig/manifest`). Key links stay where they are, at `/.well-known/jig` and in the welcome.
   A `#jig/keys` channel is deferred until key links need an append-only history that anyone
   can follow, for example JEP-0009's transparency logs.
7. **DMs are `private`.** A DM is a `private` channel whose `#dm/` slug is derived from the
   pair of DIDs (`jig_core::dm`). Today's `restricted` channels are `private`.

## 2. Server roles

8. **Every authenticated caller has one server role** on a given server:
   - **`member`**: a DID the server's admission policy records as a member. Until JEP-0009,
     that is local policy: admission `records`, or JEP-0008 rule 21's member pool.
   - **`guest`**: a DID that has proven possession of its key (JEP-0002 request proofs) and
     that admission lets through, but that is not a member.
   - **`stranger`**: everyone else, including every `--anon` session key (D20).
9. **The role is the server's local judgement,** made on its own clock and records, at the
   moment the join is checked. It is not carried to other servers.
10. **Join roles are not capacity pools.** JEP-0008 rule 21's pools (members, invited and
    strangers) decide how much capacity a caller gets. The roles here decide who may join a
    channel. A `member` is in JEP-0008's member pool. A `guest` is in whichever other pool
    JEP-0008 puts it: the invited pool if it was admitted on an invite, the stranger pool
    otherwise (JEP-0008 rules 21 and 22). Either way it is a `guest` for joining. A server MUST
    NOT admit to a join a DID its capacity pools refuse at that moment.

## 3. Joining

11. **`private`:** members join only when a DID holding the `membership` right adds them
    (JEP-0005 rule 7b): the owner or an admin. Self-join is refused. This is today's
    `restricted`.
12. **`server`:** the `channel-create` block carries `join`, either `member` (the default) or
    `guest`, the lowest server role that may join. A joiner joins itself with an MLS external
    commit, carried in a `member-add` block it signs for itself. The role check stands in for
    JEP-0005 rule 7b's `membership` right, which a self-join does not need (rule 37). The server,
    acting as delivery service:
    - MUST check the joiner's server role (section 2) against `join` before it accepts the
      commit;
    - MUST validate the external commit against the group's public state, as it does today
      (`delivery::Intent::Join`);
    - holds no group secret and reads no content.

    A `stranger` never self-joins a `server` channel. A DID with the `membership` right MAY
    still add anyone, as in `private`.
13. **`shared`:** as `server`, across servers under a JEP-0005 contract. The `channel-create`
    block carries `join` as in rule 12, plus `join_servers`: either `owner` (only the owning
    server's roles count) or `granted` (a follower's roles count too).
    - A self-join through a follower is relayed only under a `member` grant (JEP-0005 rule
      7a).
    - The follower MUST check the joiner's role on the follower (rule 9) before it relays the
      self-join. The owner cannot check that role: it is the follower's local judgement.
    - The owner MUST check that the follower holds the grant and that `join_servers` is
      `granted`, and MUST refuse a relayed self-join that fails either. It also validates the
      external commit, as in rule 12.
    - The owner trusts the follower's role decision. That trust is what the `member` grant
      means, as JEP-0005 rule 15 already delegates admission of relayed writes to the
      follower; an owner that stops trusting a follower withdraws the grant.
    - The servers whose members may self-join are exactly those holding a `member` grant. The
      grant is signed by the owner per channel and per follower, and changes with a new offer,
      so the creation block lists no servers.
14. **`public`:** anyone the server admits reads it. Who may post is the existing write gate
    (membership and roles); nothing is encrypted.
15. **Leaving and removal** are unchanged: a `member-remove` block, by the member or by a DID
    with the `membership` right. In the encrypted tiers it carries an MLS commit. In `public`
    there is no group, so membership blocks carry no commit: membership there decides who may
    post (rule 14), not who reads, and removal stops only posting.

## 4. History

16. **In the encrypted tiers, by default, a joiner reads from the epoch it joins.** MLS gives a
    new member no key for earlier epochs, and jig adds nothing that would. A `public` channel's
    whole history is readable by anyone the server admits.
17. **Re-sharing history is reserved,** for the encrypted tiers only; `public` needs none. A
    later JEP MAY specify a `history-share` mechanism,
    within these constraints, which this JEP fixes now:
    - Only a client re-shares: a member's device, or an agent the owner runs as a member of
      the channel with its own DID. The server MUST NOT re-share, and holds nothing it could
      re-share with.
    - Re-shared content keeps every original author's signature and franking tag (JEP-0010
      rule 6), so the joiner can check who said what and can report it.
    - The channel's creation block states whether re-sharing is allowed (`history`: `none`, the
      default, or `members-may-share`). A client MUST NOT re-share history from a channel whose
      creation block says `none`.
    - Re-sharing travels encrypted to the joiner alone, in a `private` channel whose members
      are the re-sharing client and the joiner, such as their 1:1. It MUST NOT be sent in the
      channel itself, where every member at that epoch would receive it.

    The block kind `history-share` and the creation field `history` are reserved.

## 5. Group conversations from a DM

18. **A 1:1 stays a pair.** Its `#dm/` slug is derived from the two DIDs, so a third member
    cannot be added to it. A server MUST refuse a `member-add` to a `#dm/` channel of any DID
    that is not one of the two the slug is derived from. Adding the other side of the pair, as
    `jig dm` does after creating the channel, is allowed.
19. **Adding someone to a 1:1 creates a new `private` channel** with all three members. Its
    `channel-create` carries `from_dm`, the 1:1's `channel_id`, so clients can link the two
    conversations. The 1:1 continues unchanged.
20. **Later adds** to the group are ordinary `member-add` blocks with MLS commits. A group never
    turns back into a 1:1.

## 6. Migration

21. **Legacy channels.** A channel created before this JEP has no `tier`. Its tier is read from
    its stored `visibility` and `suite`:

    | `visibility` | `suite` | Tier |
    | --- | --- | --- |
    | any channel under the reserved `#jig/` prefix | `none` | `public` (rule 6) |
    | `restricted` | `mls` | `private` |
    | `open` | `mls` | `server`, with `join = guest`, which matches today's rule that any caller the server admits may join an open channel |
    | `open` | `none` | **frozen** |
    | `restricted` | `none` | **frozen**, as D25 already does |

    The first row is checked first: a server's own system channels, such as `#jig/manifest`, are
    `open` with `none` and would otherwise be frozen, which would stop the manifest log.
22. **Frozen channels.** A frozen channel keeps its history readable to whoever could read it
    before. A server MUST refuse every new content or membership block in it (`CHANNEL_FROZEN`),
    except an archive by its owner.
23. **Successors.** The owner of a frozen channel MAY create an encrypted successor: a new
    channel whose `channel-create` carries `successor_of`, the frozen channel's `channel_id`.
    - Clients SHOULD follow the link and show the two channels as one conversation.
    - No history moves into the successor, except by section 4's re-sharing, done by a client.
24. **"No plaintext is stored" is forward-looking.** From this JEP on, a server stores no
    plaintext except in `public` channels. Frozen history stays where it is. An operator MAY
    delete it, and the release notes for the change say both things.

## 7. Consequences

25. **Block execution moves to clients and agents.** A server executes nothing under an
    encrypted suite, and its receipt for such a block is `sealed` (JEP-0001 open question 7;
    JEP-0005 rule 23). Work that must run on a server runs as an agent (section 7.4).
    Clients run blocks on the plaintext they decrypt, and already check a server's `exec`
    receipt by running the same component (JEP-0006, #276). In `public` channels the server
    still executes, and clients still check it.
26. **Search moves to clients.** A server cannot search content it cannot read. Search runs on
    the client, over its own decrypted store, or in an agent the channel admits (section 7.4). That store is sealed at rest, like the MLS
    plaintext cache.
27. **Bridges are visible members.** A bridge that carries content in or out of an encrypted
    channel is a member of the group under its own DID. Clients MUST show it as a bridge in the
    member list, so every member knows that content leaves through it. A bridge never reads a
    channel it is not a member of. The email bridge's inbound path depends on this.
28. **Moderation uses reports and franking.** Abuse in an encrypted channel reaches a tribunal
    through a member's report of a franked message (JEP-0010 rules 6 to 8a). It never relies on
    the server reading content, on escrow or on scanning (D22).

### 7.4 Server-side execution: agents now, enclaves later

Decided by DJ, 2026-10-25. The model is that of an operating system: the kernel cannot read
process memory, and each process holds keys only for its own scope.

29. **The server is the kernel.** It delivers, stores ciphertext and schedules. It MUST NOT hold
    content keys for a `private`, `server` or `shared` channel.
30. **Server-side work on encrypted content runs as agents.** Block execution, search
    indexing, bridging and bots are all agents. An agent:
    - is an ordinary MLS member with its own DID and its own sealed key;
    - is added to a channel by someone the channel's join rules allow (section 3);
    - is listed in the roster, and clients show it as an agent;
    - is removable. After an MLS Remove it reads nothing from that epoch on.
31. **Membership gives read; capabilities give act.** What an agent may do beyond reading is
    bounded by the capability grants of JEP-0007. Its outputs are signed by its own DID, and
    every receipt it produces names it as executor.
32. **An agent may run on the server's machines.** Its key MUST be separate from the server's
    DID key and MUST be sealed at rest on its own. The operator who runs an agent can read what
    that agent reads. The roster makes that visible to every member.
33. **`public` channels need no agent.** The server MAY execute blocks of a `public` channel
    directly, as it does today.
34. **Clients do the rest.** They run blocks deterministically and produce receipts that members
    can compare (JEP-0006, #276), and they search their own decrypted store (rules 25 and 26).
35. **Research track, not normative:** binding an agent's key to an attested enclave
    measurement. Members could then check, before admitting the agent, that even the operator
    cannot read through it.

**Rejected:** the server holding a channel's key on opt-in. That access would be invisible to
members, unlike an agent in the roster, and it breaks the tier model's promise that the server
reads no encrypted tier.

## 8. Amendments

36. **JEP-0001:**
    - "Restricted channels are always MLS" becomes rule 3 above: every non-`public` tier uses an
      operator-confidential suite.
    - JEP-0001's Specification, which states that only `restricted` channels require an
      operator-confidential suite, follows this JEP's tier rules.
37. **JEP-0005:**
    - Rule 6, the terms of the contract, adds `tier`, `join`, `join_servers`, `history`,
      `from_dm` and `successor_of` to the creation block's fields, fixed for the channel's life.
      `history`, `from_dm` and `successor_of` are reserved by this JEP.
    - Rule 7b: a `member-add` whose signer is the DID it adds, carrying an MLS external commit,
      to a `server` or `shared` channel, is authorized by the role check of rule 12 or 13
      instead of the `membership` right. Every other membership block still needs the right.
    - Rule 7a's `member` grant also covers relayed self-joins (rule 13).
    - An owner MUST NOT offer a `shared` channel to a follower whose manifest does not
      advertise the `tiers` feature (rule 1). Such a follower would read the channel as `open`
      and relay self-joins without a role check.
    - `shared` and `public` channels may be offered under a contract; `private` and `server`
      channels may not.
    - **`public` channels federate under contracts** (DJ, 2026-10-25), once F2's first phase has
      landed. The defaults:
      - the owner offers a `public` channel to every server on its peer list;
      - followers receive a `write` grant;
      - a server accepts an offer for a `public` channel automatically, even when its peer
        policy is `offers = "hold"`.

      Until then, the legacy relay carries `public` channels to listed peers, with catch-up
      after an outage (#340).
    - **A channel is carried by the relay or by a contract, never both** (#344). Relayed, a
      channel gets a second sequencer on the receiving server, and that server then refuses
      the owner's records. So a channel is relayed until it is shared with a peer, and the
      contract carries it from the accept on.

# Security Considerations (Zero-Trust)

Threat-register rows: OP-05 (content disclosure), OP-03 (suite downgrade), OP-09 (federation
abuse), PV-04 (non-deniability), AB-06 (abuse in encrypted channels), AB-07 (delegated
admission).

- **The server learns who joins, not what is said.** Checking a role on a self-join reveals the
  joiner's DID and time to the operator, as membership blocks already do. It reveals no
  content (OP-04, accepted).
- **A follower decides its own members' roles.** Under a `member` grant, the owner accepts a
  follower's self-joins on the follower's word (rule 13). A hostile follower can admit anyone
  to a `shared` channel with `join_servers = granted`. The owner limits this by granting
  `member` only to followers it trusts, and members see each join as below. This is the
  delegation of AB-07, extended from writes to joins.
- **A hostile server can refuse a join, or admit one it should have refused.** Admitting a DID
  that does not hold the role exposes future content to that DID. Members see every join as a
  signed `member-add` with its MLS commit, so a member's client SHOULD surface joins and MAY
  leave the channel. This is the same trust a channel puts in an admin.
- **Downgrade.** The tier and the suite are fixed by the signed creation block, which clients
  pin (JEP-0002). An operator cannot turn a channel `public`. It can only refuse to host
  encrypted ones, and that is visible.
- **The `public` label is a safety property.** A client that hides it lets users write to the
  operator believing they are writing privately.
- **History re-sharing is a disclosure decision** made by a member, not the server. The
  creation block's `history` field makes it a channel policy that every member can see before
  joining.
- **Bridges carry content out.** A bridge's DID in the member list is the only signal members
  get, and rule 27 makes it mandatory.

# Backwards Compatibility

- **Legacy channels** map to tiers or are frozen, as section 6 sets out. Clients that do not
  know `tier` see the new channels' `visibility` and `suite` fields unchanged:
  - `private` is written `restricted`;
  - `server` and `shared` are written `open` with `suite = mls`;
  - `public` is written `open` with `suite = none`.
- **Old clients creating channels.** A `channel-create` without `tier` is mapped as rule 1
  says. An old client asking for a plaintext open channel is refused with `UNKNOWN_TIER`, so its
  user must upgrade before creating one, and then confirms the `public` label.
- **Two CLI paths go away.** Growing a DM into a group with `jig channel add`, and opening it
  with `jig channel promote`, are both refused: the tier is fixed (rule 2), and a 1:1 stays a
  pair (rule 18). The replacement is rule 19's new linked group. A legacy `#dm/` channel that
  already has three or more members stays `private`, and rule 18 refuses any further add to it.
- **Old clients cannot tell the tiers apart.** In particular they do not show the `public`
  label, so a server refuses their posts to `public` channels (rule 5) and they can only read
  them.
- **Old servers ignore `tier`** and fall back to `visibility`, so a `server` or `shared`
  channel on one would admit any authenticated joiner. Clients and owners therefore create or
  offer those tiers only to servers that advertise `tiers` (rules 1 and 37).

# Reference Implementation

None yet. The pieces that exist:
- external-commit self-join (`jig_mls::Member::join_external`, `delivery::Intent::Join`);
- the MLS gate (`jig-pipeline/src/mls_gate.rs`);
- frozen plaintext restricted channels;
- client re-execution of receipts (#276).

# Test Vectors

To be added with the implementation:
- `channel-create` blocks for each tier;
- refused tier and suite combinations;
- a legacy-channel mapping table, including `#jig/manifest` mapped to `public`;
- a `member-add` to a `#dm/` channel: the pair's other DID accepted, a third DID refused;
- a self-join refused for a role below `join`.
- a post to a `public` channel refused on a connection without the `tiers` capability.

# LLM Influence

Drafted with an LLM coding assistant from DJ's decisions of 2026-10-25 and the code on `main`
(a740fa8), and reviewed by the author.

# Rejected Alternatives

- **Encrypted by default, with an opt-out flag on any channel.** A flag can be flipped. A
  fixed `public` tier, chosen at creation and labelled, cannot be confused with an encrypted
  channel.
- **The server re-shares history to joiners.** It would have to hold the plaintext, which is
  what the encrypted tiers exist to prevent.
- **Adding a third member to a 1:1.** The `#dm/` slug names the pair, and growing it would
  change what the slug means. A new linked group keeps the 1:1's meaning.
- **Converting plaintext open channels in place.** Their history is already readable by the
  operator. Encrypting new content in the same channel would suggest otherwise. A frozen
  channel and an encrypted successor say exactly what is true.

# Open Questions

1. ~~Roles and capacity pools.~~ Decided (DJ, 2026-10-25): they stay separate, and a `guest`
   counts as a stranger for capacity (rule 10).
2. ~~`join_servers` for `shared`.~~ Decided (DJ, 2026-10-26): the follower's `member` grant is
   enough, and the creation block names no servers (rule 13).
3. ~~A `#jig/keys` system channel.~~ Deferred (DJ, 2026-10-25) until key links need an
   append-only, followable history (rule 6).

# Copyright

This document is licensed under CC-BY-4.0.
