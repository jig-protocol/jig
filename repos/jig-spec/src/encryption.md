# Encryption

> **v0.2 implements `mls` for single-server channels.** A channel created under `mls` is
> one MLS group: its content is end-to-end encrypted and the server stores ciphertext it
> cannot read. Channels created without a suite are `none`, as before. Encrypted channels
> do not federate in v0.2. Design record:
> [M2 design](https://github.com/jig-protocol/jig/blob/main/docs/superpowers/specs/2026-10-11-m2-mls-and-channel-dynamics-design.md);
> rationale: [`docs/security/encryption.md`](https://github.com/jig-protocol/jig/blob/main/docs/security/encryption.md);
> open questions: [JEP-0001](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0001-encryption-suites.md).

## Suites

An **encryption suite** names the scheme that protects a payload. Suites are pluggable:
a channel created without one is `none` (signed, not encrypted), and MLS is selected per
channel at creation. An operator MAY run another registered suite. Adding a suite is a
registry entry plus a JEP and conformance vectors. It MUST NOT need a wire-format change.

### Registry

| Identifier | Scheme | Status |
| --- | --- | --- |
| `none` | No encryption. Signatures still apply. | Implemented |
| `mls` | MLS, [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420), cipher suite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | Implemented in v0.2 for single-server channels |

Identifiers are lowercase ASCII and compared byte for byte.

### Where the suite is carried

- The wire envelope: `suite` on every frame ([Versioning](versioning.md#envelope)). An
  absent `suite` means `none`. A frame is never encrypted as a unit — it carries blocks,
  and an encrypted block is encrypted inside its manifest — so the only frame suite is
  `none`, and a frame declaring `mls` is refused. The handshake's `suites` list names the
  content suites a server can host.
- The block manifest: `privacy.encryption`. An absent `privacy` means `none`.
- The channel: the suite fixed when the channel is created (see [Channels](#channels)).

### Rejection rules

An implementation MUST refuse a frame or manifest whose suite is:

1. not in the registry (`UNSUPPORTED_SUITE`), or
2. registered but not implemented by it (`UNSUPPORTED_SUITE`).

It MUST NOT ignore an unknown suite, treat it as `none`, or forward the payload as if it
had been understood. A list of suites *offered* during negotiation is different: entries
the receiver does not know are skipped, and negotiation fails if nothing remains.

## Channels

Every conversation is a channel. An encrypted channel is one MLS group.

- A channel's suite is chosen by its creator and recorded in the signed channel-creation
  block. It is fixed at creation.
- A **DM** is a channel with two members and **locked membership**. A group DM is a
  locked channel with more members. There is no separate DM scheme.
- A DM's slug is derived from the pair's DIDs (`#dm/` and a hash of both), so either side
  finds it. A server MUST refuse to create a `#dm/` slug unless the creator and the
  `dm_peer` it names derive it, and the channel is locked and `mls`. A client MUST NOT
  treat a channel as a DM with a peer while the channel's MLS group holds anyone else.
- **Locked membership** means nobody joins on their own: the member set changes only
  through an explicit, signed membership block.
- Growing a conversation (DM → group DM → channel) is a membership change on the same
  channel: adding members, or unlocking membership. It is never a migration to another
  scheme.
- A client MUST NOT post to a channel under a suite other than the channel's. A client
  that holds a channel's MLS group MUST treat the channel as `mls` whatever a server says
  about it.

## MLS mapping

One channel is one MLS group. Membership blocks carry the MLS handshake; content blocks
carry application messages.

### Identity

A leaf's credential is an MLS basic credential whose identity is the member's canonical
`did:jig` string, and its signature key MUST be that DID's Ed25519 key. A leaf where the
two disagree MUST be refused by the server and by every member.

### Blocks

| Block | Metadata on an `mls` channel |
| --- | --- |
| `channel-create` | `suite: "mls"`; `mls_group_info` and `mls_ratchet_tree` for epoch 0, holding only the creator |
| `member-add` (owner adds `member_did`) | `mls_commit` adding exactly `member_did`; `mls_welcome`; `mls_group_info` for the new epoch |
| `member-add` (self-join, open channel) | `mls_commit`, an external commit whose new leaf is the sender; `mls_group_info` |
| `member-remove` (removing `member_did`) | `mls_commit` removing exactly `member_did`'s leaf; `mls_group_info` |
| `member-remove` (leaving) | none: a member cannot commit its own removal |
| content (`text-render`, …) | `privacy.encryption = "mls"`; `mls_message`, an MLS application `PrivateMessage`; no `body` |

All MLS values are standard base64 of their TLS encoding. Commit-carrying blocks also name
`mls_epoch`, the epoch the commit was built on. Commits MUST be MLS `PublicMessage`s
(wire-format policy *mixed plaintext*), so a server can validate them; application messages
are always `PrivateMessage`s.

### Server obligations

A server hosting an `mls` channel is a validating delivery service. It MUST:

1. track the group's public state from the creation block;
2. accept a commit-carrying block only if the commit is valid for the current epoch and
   does exactly what the block says (the add, external join or removal it names, and no
   other proposals); otherwise refuse with `STALE_EPOCH` (wrong epoch, `409`) or
   `MLS_REJECTED` (`400`);
3. apply accepted commits in order, so the channel has one linear history;
4. refuse content whose suite is not the channel's (`SUITE_MISMATCH`), plaintext `body` on
   an `mls` channel, and application messages for another group or more than a few epochs
   old;
5. not execute encrypted content. Its receipt for such a block is marked
   `"content": "sealed"` and carries no `render_hash`.

A server SHOULD serve published key packages (`/api/v1/mls/key-packages`) and the newest
group info of a channel (`/api/v1/channels/{slug}/mls/group-info`) to callers who may read
the channel.

### Leaving

A member leaves with a `member-remove` naming itself and carrying no commit. The server
removes the membership at once. Any remaining member then sends a `member-remove` with the
commit removing the departed leaf. Until it does, a departed member that obtained new
ciphertext by other means could still decrypt it; a server does not deliver it to them.

## What the server sees

Under an encrypted suite the server stores and relays ciphertext. It sees routing
metadata: sender DID, channel, timestamps, sizes and membership changes — including, from
the commits it validates, who was added and removed and when. This chapter makes no
metadata-privacy claim. See the [threat register](threat-register.md) (OP-04).

## Federation

A cross-server channel's suite is part of its federation contract, fixed at setup. A
server that cannot speak the suite cannot join the channel, the same way a TLS handshake
with no common cipher suite fails.

v0.2 does not federate encrypted channels: channel and membership state does not replicate
between servers, so only the home server can validate a channel's commits. A server MUST
NOT relay an `mls` channel's blocks to peers, and MUST refuse a relayed block for a local
`mls` channel.
