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
leaves no evidence. Before this JEP no handshake existed: the first frame could be
anything. The `src/handshake.md` chapter predates this JEP and is not implemented. The
reference implementation now implements a subset of this JEP; the threat register's OP-01
and OP-02 rows say which.

# Specification

Draft. Field names are provisional. The design behind this revision is
[`docs/superpowers/specs/2026-10-18-d11-handshake-completion-design.md`](https://github.com/jig-protocol/jig/blob/main/docs/superpowers/specs/2026-10-18-d11-handshake-completion-design.md).

## Messages

1. After the transport opens, the client's first frame is `hello`:
   envelope versions it speaks, suites it implements, capabilities it wants, and a fresh
   random `nonce`. A server that dials another server adds `peer_did`, its own DID.
2. The server's first frame is `welcome`, signed by the server's DID key over its
   canonical bytes (domain `jig-handshake-welcome-v2`; v1 had no `server_nonce` or
   `tls_exporter`):

   | Field | Content | Threats |
   | --- | --- | --- |
   | `server_did` | The signing key | OP-08 |
   | `v` | Chosen envelope version | OP-02 |
   | `suites` | Suites the server implements | OP-02, OP-03 |
   | `capabilities` | Allowed block kinds, limits (including `max_future_skew_ms`), features (execution, federation) | OP-02, TM-01 |
   | `reputation` | Placeholder object; `null` until JEP-0003 | OP-10 |
   | `manifest` | CID and `seq` of the server's current `server-manifest` block | OP-02, OP-03 |
   | `key_link` | During a key change: the public key link (JEP-0012) from the server's old DID to `server_did`, signed by both keys; absent otherwise | OP-08 |
   | `nonce` | Echo of the client's nonce | replayed `welcome` |
   | `server_nonce` | A fresh random value from the server | replayed `peer_proof` |
   | `tls_exporter` | 32 bytes exported from the TLS session (RFC 9266, label `EXPORTER-jig-handshake`); empty over plaintext | relayed handshake |
   | `sig` | ed25519 over the above | OP-02 |

3. If the server shares no version or suite with the `hello`, it sends a `refusal`
   instead of a `welcome`: a COSE_Sign1 (EdDSA) by `server_did` over a deterministic
   CBOR map with `domain` = `jig-handshake-refusal-v2`, the client's `nonce`, the
   refusal code (`UNSUPPORTED_VERSION` or `UNSUPPORTED_SUITE`), and the versions and
   suites it supports. It then closes the connection. The frame's `format` field
   names the signature format (`jig-handshake-refusal-v2`); a client
   MUST treat a refusal in a format it does not verify as a handshake failure, by
   that name, not by trying to parse it.
4. When the `hello` carried `peer_did`, the dialer's next frame is `peer_proof`: an
   ed25519 signature by `peer_did`, under domain `jig-handshake-peer-v1`, over the
   transcript hash. The transcript hash is BLAKE3 over the domain tag and the
   length-prefixed bytes of the `hello` frame, the `welcome` frame and `tls_exporter`.
   Server-to-server connections MUST carry a `peer_did` and a valid `peer_proof`. Client
   connections carry neither; a client proves its DID per subscription.
   Either side MUST refuse a `welcome` whose `tls_exporter` is not its own connection's
   value: one signed for another TLS session was relayed by whatever terminated TLS in
   between. A dialed server closes (4001) if the proof is missing, late (`WELCOME_WAIT`)
   or does not verify, or if any other frame comes first.
5. After the handshake, a server-to-server connection is symmetric: either side MAY
   subscribe and push, within what the federation contract (JEP-0005) grants the
   authenticated peer DID.
6. A connection carries exactly one `hello`. Every connection runs the full handshake;
   no earlier `welcome` is reused. A capability change applies to new connections, and
   is published in the manifest log (rule 12).

## Closing

7. Every failure is in one of four classes, or is an ordinary error. The side named
   closes the connection with the code given, and sends nothing else first except where
   stated.

   | Class | Failure | Closes | Code |
   | --- | --- | --- | --- |
   | Handshake failure | The `welcome` is missing, malformed or late (`WELCOME_WAIT`), its signature does not verify, `nonce` does not match, `server_did` is not the pinned DID, it contradicts itself or the offer, it no longer advertises a pinned suite, its skew bound is outside the protocol's range, or `tls_exporter` is empty on a TLS connection; a required `peer_proof` is missing or does not verify | The side that detects it | 4001 |
   | Incompatible | No version or suite in common | The server, after its signed `refusal` | 4002 |
   | Contradiction | Behaviour that contradicts the signed `welcome` (rule 8), or a broken `ingest` chain (rule 9) | The client | 4003 |
   | Protocol violation | A frame before `hello`; a second `hello`; a client frame outside the version or suite it offered | The server, after an error frame | 4004 |
   | Ordinary error | Authorization refused, not a member, duplicate or invalid block, rate limit, `CLOCK_SKEW`, a malformed frame after the handshake | Nobody: an error frame, the connection stays open | — |

   A client MUST treat a signed `refusal` that omits a suite it pinned for that server
   as a contradiction, not as an incompatibility.

## Checking behaviour against the welcome

8. A client MUST treat each of these as a contradiction:
   - a frame at an envelope version or suite the `welcome` did not advertise;
   - an error refusing a capability the `welcome` advertised;
   - a receipt produced by the connected server whose `server_did` is not the
     `welcome`'s;
   - a block whose `hlc_ts` is ahead of its `ingest_hlc` by more than the advertised
     `max_future_skew_ms`;
   - a `welcome` whose suites, capabilities or skew bound differ from the manifest it
     cites;
   - a second `welcome` on the connection.

   A client MUST check the server only against what the server signed. Its own
   expectations beyond its offer are never a contradiction.

## Channel history

9. Every block in a channel has an `ingest` record, signed by the channel's sequencer
   as a COSE_Sign1 (EdDSA) over a deterministic CBOR map with `domain` =
   `jig-ingest-v2`, which its `format` field names (a client MUST refuse a record in
   a format it does not verify by that name; CIDs in the payload are binary CIDv1
   byte strings, per JEP-0004 rule 0): `channel_id` (the CID of the channel's
   `channel-create` block), `seq` (0 for that block, then +1 per accepted block),
   `ingest_hlc`, `block_cid`, `prev` (BLAKE3 of the previous record's COSE_Sign1 envelope;
   zero at `seq` 0) and `sequencer`. The sequencer is the channel's owning server from
   `seq` 0. An owner-signed `sequencer-set` block names a new sequencer and the last
   record the old one signed (the cited head); its own record is always signed by the
   new sequencer, at the cited head's `seq` + 1 with `prev` = the cited head's hash, and
   the new sequencer signs every record from there on. A block is delivered
   with its record; a block the reader may not read is delivered as its record alone. A
   client MUST check, per channel, the signer, `seq` continuity, the `prev` chain,
   `channel_id`, `block_cid`, that `ingest_hlc` never decreases, and on live delivery
   that `ingest_hlc` is within its own skew tolerance of its clock. A failure is a
   contradiction. History is ordered by `seq`. A block's `hlc_ts` is its author's
   claim.
10. Every block a member authors into a channel, except the `channel-create`, carries
    `seen`: the latest `ingest` record its author verified for that channel. A client,
    including a member that only reads, SHOULD send its server a `head` frame holding the
    latest record it verified, with no
    identity attached; servers verify heads and forward them toward the sequencer and
    other carriers. Two records signed by one sequencer for the same `channel_id` and
    `seq` with different contents are proof of a fork.
11. A `member-remove` block, including a self-leave, carries `ends`: the CID of the
    `member-add` it ends. A server MUST refuse a remove whose `ends` is not the member's
    current membership.

## Manifest log

12. A server MUST keep a manifest log: a reserved channel whose only writer is the
    server's DID and which accepts only `server-manifest`, `sequencer-set` and handover
    notices. Anyone may read it. The server MUST publish a new `server-manifest` block
    whenever its versions, suites, capabilities, skew bound or signed peer policy
    (JEP-0005) change, and every `welcome` and federation contract message cites the
    current one. A public manifest log exposes the server's peer graph; a server MAY
    publish only the peers it wants known. A server MAY keep an optional handshake-transcript
    channel; if it does, its manifest MUST advertise it, and a client MUST agree to it
    before posting, as part of the ruleset it consents to.

## Time

13. A server MUST refuse, with `CLOCK_SKEW` and its own time, a block whose `hlc_ts` is
    more than `max_future_skew_ms` ahead of its clock. The value is between 30 s and
    15 min, defaulting to 5 min; a ruleset group MAY narrow it. A server MUST NOT adopt
    a block's time beyond that bound. A block's past is unbounded.

## Pins and evidence

14. A client SHOULD pin, on its first verified `welcome` from a server, the
    `server_did`, the suites it advertised and its manifest-log chain. It MUST then
    close on a `welcome` from another `server_did` (rule 7), unless the `welcome`
    carries a `key_link` with audience `public` from exactly the pinned DID to exactly
    that `server_did`, which it MUST verify under both keys; it then moves its pin.
    The server serves the same link at `/.well-known/jig`. It MUST treat a `welcome`
    that no longer advertises a pinned suite as a downgrade and refuse it. A server
    adding a suite is not a downgrade.
15. A pinned name moves to a new DID automatically only with a rotation signed by the
    old key. A client MUST refuse any other change until its holder accepts it.
16. On a contradiction a client MUST keep an evidence bundle (`jig-evidence-v1`): the
    signed `welcome` or `refusal`, every signed item that contradicts it, with the
    records on both sides of any gap, and the class and code. The bundle holds no
    decrypted content, and is not signed by the user's key by default. It stays with the
    user. A client MUST refuse later connections to that server until the user accepts
    it again. Only items the server signed, and that show the contradiction on their own,
    may cause that refusal: two `ingest` records that cannot both hold, or a signed
    `refusal` that drops a suite a signed `welcome` advertised. Frames are not signed, so
    a frame the welcome did not allow is kept as evidence but does not cause it. Timeouts,
    closed connections and malformed frames never do, and neither does evidence imported
    from others.
17. A nameserver's list of abandoned or compromised servers is advisory. It MUST NOT
    override the sequencer an owner names in `sequencer-set`.

v0.1 scope (roadmap P1): version, capabilities and suite (`none`) in `jig-server` and
`jig-client`; the client refuses to proceed without a valid `welcome`. Reputation and real
suites follow in v0.2. *(Done in v0.2: the welcome advertises `none` and `mls`, and the CLI
pins the server's DID and advertised suites; reputation is still `null`.)*

v0.2 scope (D11): rules 1–17, except the optional handshake-transcript channel in rule 12.
Reputation stays `null`.

# Open questions

1. ~~REST is stateless.~~ Plaintext REST is refused by the CLI, except to loopback.
   History REST responses carry `ingest` records, so they are checkable on any
   transport. Binding REST to the handshake through TLS and the DID is still open.
2. ~~Re-handshake on reconnect.~~ Settled: every connection handshakes in full (rule 6).
3. ~~Signed mid-session capability updates.~~ Settled: none. A change applies to new
   connections and is published in the manifest log (rules 6, 12).
4. Binding the handshake transcript into MLS group joins. The transcript hash of rule 4
   is the input; the design is open.
5. ~~How a client reports a contradiction.~~ Settled for v0.2: a local evidence bundle
   (rule 16). Submitting it to a tribunal waits for JEP-0003 and the tribunal design.
6. ~~When to close the connection.~~ Settled: rule 7.
7. Fork detection depends on records crossing by paths the sequencer does not control.
   High-sec federation could use carriers co-signing heads, and Merkle logs with gossip
   would close the gap generally. Both are open.

# Security Considerations (Zero-Trust)

The handshake cannot stop an operator from lying. It makes a lie **attributable**: a
signed false answer is evidence. Detecting the lie still depends on the client checking
behaviour against the answer, and on records reaching members by more than one path.

Known limits:

- A first contact is trusted on first use; pins catch later lies, not the first.
- The sequencer orders history. It can delay a block within the skew bound and choose
  the order of concurrent writes.
- Withholding from a whole carrier is detected only once a member on another carrier
  posts. A channel with a single poster has no detection against its sequencer.
- `timer-fire` blocks are the sequencer's word, bounded by the install's grant.

Threat register entries: OP-01, OP-02, OP-03, OP-06, OP-08, OP-09, OP-10, TM-01, TM-02.

# Backwards Compatibility

None. Clients and servers without the handshake cannot talk to those with it, and the
v0.2 revision changes the wire again. v0.x makes no compatibility guarantee.

# Rejected Alternatives

- **Optional handshake.** A hostile operator would simply omit it (OP-01).
- **Unsigned answers.** A lie would leave no evidence (OP-02).
- **Close on any failure.** It makes ordinary errors indistinguishable from attacks. The
  failure class, and what was signed, tell them apart.
- **Leaving the socket open after a version or suite refusal.** With one `hello` per
  connection the open socket has no use, and an unsigned refusal leaves no evidence of
  a downgrade.
- **Unsigned sequence numbers with periodic signed heads.** A gap is proven only at the
  next head, and a block has no signed time of its own.
- **Two one-way handshakes on one socket** for server-to-server links. The transcripts
  are not bound to each other.
- **Mutual TLS alone.** It authenticates, but leaves nothing signed to show anyone.
- **Logging every handshake.** It records who connected and when.

# Copyright

This document is licensed under CC-BY-4.0.
