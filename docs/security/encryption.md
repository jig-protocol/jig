# Encryption: rationale for the v0.1 groundwork

Why the spec's [Encryption](../../repos/jig-spec/src/encryption.md) and
[Versioning](../../repos/jig-spec/src/versioning.md) chapters say what they say. The open
design is [JEP-0001](../../repos/jig-spec/jep/jep-0001-encryption-suites.md).

## Why reserve the field before encryption exists

v0.1 ships unencrypted (D1). Adding a suite field later would be a wire change made at the
worst moment: while turning encryption on, when an old peer that silently ignores the new
field is exactly the downgrade we must not allow. Shipping the field now, with `none` as
the only value and refusals for everything else, means v0.2 changes a value, not the
format.

## Why refuse unknown suites instead of ignoring them

The tempting rule, "ignore what you don't understand", is right for optional metadata and
wrong for security parameters. A receiver that ignores an unknown suite has to treat the
payload as *something*, and the only thing it can treat it as is plaintext. Refusing makes
the failure loud and keeps the decision with the sender.

Offered *lists* are different. A client offering `[mls, future-suite]` to an old server
should still get `mls`, so unknown entries in an offer are skipped.

## Why an absent `suite` means `none`

Every frame on the wire before this change had no `suite` and was unencrypted, so reading
absence as `none` is accurate, and keeps v0.1 servers and older clients on a tailnet
talking during the upgrade. It does not weaken OP-03: absence can only ever mean `none`,
and a channel created under an encrypted suite refuses `none` regardless of how it was
spelled.

## Why gate the manifest before the signature

The schema defines what the signature covers. Verifying a signature under a schema you do
not implement means guessing at the preimage. A gate failure therefore comes before
signature verification, and is reported with its own code (`UNSUPPORTED_SCHEMA`) so a
client can tell "upgrade" from "forgery".

## Why MLS, and for everything

- MLS (RFC 9420) is a standard group protocol with forward secrecy and post-compromise
  security, efficient for large groups, and has a maintained Rust implementation
  (`openmls`).
- One scheme for every conversation size avoids the migration a separate DM scheme would
  force when a DM becomes a group (D2). HPKE or `age` sealing per DM was the earlier
  recommendation and is rejected for that reason.
- "Pluggable" keeps the operator's choice open (D1): a server can run another registered
  suite. Whether a non-MLS protocol such as Signal's post-quantum one fits as a suite, or
  only PQ-hybrid MLS does, is D13, left to the v0.2 crypto design.

## Why a DM is a locked channel

A DM, a group DM and a channel differ only in who may join. Modelling that as a
membership property means:

- the same code path, the same authorization and the same MLS group handle all three;
- DM → group DM → channel is a membership change, never a re-encryption or a new
  conversation;
- there is no DM-specific wire type for an operator to treat differently.

Who may sign a membership change in a DM with no owner is an open question in JEP-0001.

## Why the suite is fixed per channel

Per-connection negotiation lets a hostile operator steer every connection to the weakest
common suite. A suite chosen once, by the channel's creator, recorded in a signed block,
gives every member and every federated server one thing to check every post against. It
also matches federation as a data contract (D12): the channel's suite is part of the
contract, and a server that cannot speak it is refused.

## Execution under encryption

A server cannot execute Wasm over ciphertext. Today `text-render` executes server-side to
produce the `render_hash` a receipt signs. Under MLS, execution of content blocks has to
move to clients, and what a server receipt attests changes. This is the largest design
consequence of encryption for jig, and it is open in JEP-0001.
