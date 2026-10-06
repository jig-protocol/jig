# Versioning

## No compatibility guarantee in v0.x

v0.x makes **no compatibility guarantee**. Any v0.x release MAY change the wire format,
the manifest, receipts or this specification without a migration path. Stability
commitments start at v1.0.

What v0.x does guarantee is that a mismatch is **refused, not misread**: the gates below
fail closed.

## Envelope

Every wire frame is a JSON object with:

| Field | Type | v0.1 value |
| --- | --- | --- |
| `v` | integer | `1` |
| `suite` | string | `none` (absent means `none`); see [Encryption](encryption.md#registry) |
| `op` | string | the frame type |

A receiver MUST refuse a frame whose `v` it does not implement (`UNSUPPORTED_VERSION`) or
whose `suite` fails the [rejection rules](encryption.md#rejection-rules)
(`UNSUPPORTED_SUITE`), before acting on any other field. Both refusals are distinct from
a malformed frame (`BAD_JSON`). Schema:
[`schemas/wire-envelope.json`](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/schemas/wire-envelope.json).

## Manifest

A block manifest's `schema` names its format. v0.1 accepts exactly
`https://jig.dev/schema/block-manifest/v0.1`.

A receiver MUST refuse a manifest whose `schema` it does not implement
(`UNSUPPORTED_SCHEMA`) or whose `privacy.encryption` fails the rejection rules
(`UNSUPPORTED_SUITE`). It MUST do so before verifying the signature, because the schema
defines what the signature covers.

## Refusal codes

| Code | Meaning |
| --- | --- |
| `UNSUPPORTED_VERSION` | Envelope `v` not implemented |
| `UNSUPPORTED_SUITE` | Suite unregistered or not implemented |
| `UNSUPPORTED_SCHEMA` | Manifest `schema` not implemented |

On the WebSocket transport a server replies with an `error` frame carrying the code and
`status: 400`. Over REST, which carries no envelope, manifest refusals come back as HTTP
`400` with the same codes.
