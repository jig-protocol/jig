# Encryption

> **Not implemented in v0.1.** v0.1 implements only the `none` suite: content is signed,
> not encrypted, and the server operator can read it. This chapter fixes the wire hooks
> v0.1 ships and the model v0.2 implements. Design rationale:
> [`docs/security/encryption.md`](https://github.com/jig-protocol/jig/blob/main/docs/security/encryption.md).
> Open design: [JEP-0001](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0001-encryption-suites.md).

## Suites

An **encryption suite** names the scheme that protects a payload. Suites are pluggable:
the default is MLS, and an operator MAY run another registered suite. Adding a suite is a
registry entry plus a JEP and conformance vectors. It MUST NOT need a wire-format change.

### Registry

| Identifier | Scheme | Status |
| --- | --- | --- |
| `none` | No encryption. Signatures still apply. | v0.1: the only implemented suite |
| `mls` | MLS, [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) | Reserved. v0.2 default. Not implemented in v0.1 |

Identifiers are lowercase ASCII and compared byte for byte.

### Where the suite is carried

- The wire envelope: `suite` on every frame ([Versioning](versioning.md#envelope)). An
  absent `suite` means `none`.
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
- **Locked membership** means nobody joins on their own: the member set changes only
  through an explicit, signed membership block.
- Growing a conversation (DM → group DM → channel) is a membership change on the same
  channel: adding members, or unlocking membership. It is never a migration to another
  scheme.
- A client MUST NOT post to a channel under a suite other than the channel's.

## What the server sees

Under an encrypted suite the server stores and relays ciphertext. It sees routing
metadata: sender DID, channel, timestamps, sizes and membership changes. This chapter
makes no metadata-privacy claim. See the [threat register](threat-register.md) (OP-04).

## Federation

A cross-server channel's suite is part of its federation contract, fixed at setup. A
server that cannot speak the suite cannot join the channel, the same way a TLS handshake
with no common cipher suite fails.
