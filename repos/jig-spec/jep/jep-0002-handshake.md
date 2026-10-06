+++
jep = 0002
title = "Mandatory Client–Server Handshake"
status = "Draft"
type = "Standards Track"
category = "Core"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-05"
requires = []
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

Every connection begins with a handshake that states the protocol version, capabilities,
encryption suites and reputation claims. The server signs its answer. Clients fail closed
when the handshake is missing, malformed, or contradicted by later behaviour. The
handshake is the client's main defence against a hostile operator (threat register
OP-01, OP-02).

# Motivation

Operators are untrusted (D11). Without a mandatory, signed handshake a client cannot tell
"this server does not support encryption" from "this server is hiding it", and a lie
leaves no evidence. Today no handshake exists: the first frame may be anything. The
`src/handshake.md` chapter predates this JEP and is not implemented.

# Specification

Draft. Field names are provisional.

1. After the transport opens, the client's first frame is `hello`:
   envelope versions it speaks, suites it implements, capabilities it wants, and a fresh
   random `nonce`.
2. The server's first frame is `welcome`, signed by the server's DID key over its
   canonical bytes, including the client's `nonce`:

   | Field | Content | Threats |
   | --- | --- | --- |
   | `server_did` | The signing key | OP-08 |
   | `v` | Chosen envelope version | OP-02 |
   | `suites` | Suites the server implements | OP-02, OP-03 |
   | `capabilities` | Allowed block kinds, limits, features (execution, federation) | OP-02 |
   | `reputation` | Placeholder object; `null` until JEP-0003 | OP-10 |
   | `nonce` | Echo of the client's nonce | replayed `welcome` |
   | `sig` | ed25519 over the above | OP-02 |

3. A server MUST refuse any frame before `hello` with `HANDSHAKE_REQUIRED`.
4. A client MUST close the connection, without sending anything else, if:
   - the first frame is not a `welcome`;
   - the signature does not verify, or `nonce` does not match;
   - `server_did` differs from the DID the client pinned for this server;
   - a required field is missing, or `v` or every suite is outside what the client offered.
5. A client MUST treat behaviour that contradicts the signed `welcome` as a handshake
   failure. Examples: refusing an advertised capability, or sending a frame at an
   unadvertised version or suite. It SHOULD keep the `welcome` as evidence.
6. Server-to-server connections use the same exchange in both directions.

v0.1 scope (roadmap P1): version, capabilities and suite (`none`) in `jig-server` and
`jig-client`; the client refuses to proceed without a valid `welcome`. Reputation and real
suites follow in v0.2.

# Open questions

1. REST is stateless. Does each request carry a reference to a signed `welcome`, or does
   REST fetch a signed capabilities document?
2. Re-handshake on reconnect, and whether a cached `welcome` may be reused.
3. Signed mid-session capability updates.
4. Binding the handshake transcript into MLS group joins.
5. How a client reports a contradiction to the user, and to anyone else.

# Security Considerations (Zero-Trust)

The handshake cannot stop an operator from lying. It makes a lie **attributable**: a
signed false answer is evidence. Detecting the lie still depends on the client checking
behaviour against the answer. Threat register entries: OP-01, OP-02, OP-03, OP-08, OP-10.

# Backwards Compatibility

None. Clients and servers without the handshake cannot talk to those with it. v0.x makes
no compatibility guarantee.

# Rejected Alternatives

- **Optional handshake.** A hostile operator would simply omit it (OP-01).
- **Unsigned answers.** A lie would leave no evidence (OP-02).

# Copyright

This document is licensed under CC-BY-4.0.
