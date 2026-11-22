+++
jep = 0015
title = "Authenticated Writes: A Write Is Bound to the Session That Makes It"
status = "Draft"
type = "Standards Track"
category = "Core"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-26"
requires = ["0002", "0005", "0008"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

A block's signature says who wrote it. This JEP adds a second, separate fact: who is
submitting it, on this connection or in this request. For every local submission, a server
MUST know the submitter's DID from a proof bound to the session, and MUST refuse a block
whose signer is not that DID.

The JEP amends JEP-0002 in three ways:
- a client proves its DID once per WebSocket connection, bound to the handshake transcript;
- a REST write carries a request proof by the signer, as REST reads already do;
- the exemptions are named: relayed and carried blocks, and server-originated blocks,
  in-process bridges among them, which may sign only as the DIDs they have registered.

It also sets the rollout.

# Motivation

**Writes should be bound to the session that makes them.** jig already binds reads this
way. A subscription carries a proof by the reader's DID (JEP-0002 rule 4), and a REST read
carries a request proof (`jig-request-auth-v1`) over its method, path, body, time and nonce.
Writes carry only the block's own signature. That signature is a fact about the block, not
about the submission: it holds whoever holds the bytes and wherever they are sent.

Binding writes to the session makes three things true:

- **Admission and limits apply to the party that acts.** A server's admission gate, its
  per-DID rate limits and proof-of-work (JEP-0008), and the penalties rulesets will charge
  (JEP-0009, R2.4) all key on a DID. They are meant to key on the DID that made the
  submission. Once penalties exist, an author must never be charged for a submission it did
  not make. That is why this JEP is built before R2.4.
- **An author decides where its blocks go.** A signed block reaches a server because its
  author submitted it there, or because a rule this protocol names carried it there: a
  federation contract, a follower's relay, or the server itself. Nothing else.
- **Reads and writes have one model.** A session has a proven DID, and what the session
  does is attributed to it.

**Non-goals:**
- **Key theft.** Whoever holds a DID's key can write as it, here as everywhere.
- **Metadata privacy.** The server already learns the signer's DID from the block.
- **Changing what a relayed or carried block proves.** JEP-0005 governs those.

# Specification

The key words MUST, MUST NOT, SHOULD and MAY are as in RFC 2119.

## 1. Terms

1. A **local submission** is a block a server receives from a client:
   - a WebSocket `submit` frame;
   - `POST /api/v1/blocks`;
   - a REST channel operation (`POST /api/v1/channels`, `…/members`, `…/archive`).

   In the reference implementation these are `IngestSource::LocalClient` and
   `IngestSource::AdminEndpoint`.
2. A block's **signer** is the DID whose key verifies the block's signature: today the
   first entry of `authors` (`jig_pipeline::ingest::verify_sig`).
3. A connection's or request's **submitter** is the DID proven by rule 7 (WebSocket) or
   rule 10 (REST). It is never taken from a claim the client makes: only a verified
   signature establishes it.

## 2. The rule

4. **For every local submission, the server MUST establish the submitter and MUST refuse
   the block unless its signer is the submitter.**
   - A submission with no submitter is refused with `AUTH_REQUIRED`: an error frame on
     WebSocket, or HTTP 401 on REST.
   - A signer that differs from the submitter is refused with `SIGNER_MISMATCH`: an error
     frame, or HTTP 403.

   Both checks run before admission, so a refused submission is never charged to anyone.
4a. **Rule 4 runs before the held-block answer.** A server answers a resubmitted block it
   already holds in its channel with that block's CID, before admission (ingest step 1a).
   For a local submission, the rule 4 checks run first, straight after the block's
   signature is verified.
   - A local submission of a held block with no submitter is refused with `AUTH_REQUIRED`,
     and one whose signer is not the submitter with `SIGNER_MISMATCH`. Neither learns the
     block's CID or that the server holds it.
   - The signer resubmitting its own held block gets the CID, and spends no rate, pool share
     or relay slot, as before.
   - Relayed writes (rule 12) are not local submissions. A relayed copy of a held block is
     answered with its CID as before.

   This is a choice. The other order, the held-block answer first, would spend nothing
   either way. But it would tell a caller with no proven DID that this server holds a
   given block in a given channel. The caller already holds the bytes, so that is a small
   leak. The choice is still made here so that implementations agree and the vectors can
   test it.
5. **Admission, rate limits, proof-of-work and ruleset penalties for a local submission
   apply to the submitter.** By rule 4 that is also the signer.
   - **Per-address limits still apply.** A DID costs nothing to make (OP-10, AB-05), so a
     limit keyed only on the submitter is no bound on one client minting DIDs. A server
     keeps its per-address limits on local submissions as well.
   - **Relay slots.** A follower's slots for writes waiting on the owner (JEP-0005
     rule 15) are counted per submitter once the submitter is proven. They are bounded
     per client address too.
     - Today REST writes have no submitter, so their slots are keyed by client address
       alone (#396).
     - WebSocket slots are per connection. Under rule 7 that is also per submitter.
   - **The client address** is the one per-address limits use: the connection's address.
     Behind a proxy that passes TLS through, that is the proxy's address, so clients
     behind it share one key, unless the operator lists the proxy in
     `[server.proxy_protocol]` (#423).
     - A connection from a listed proxy MUST open with a PROXY protocol v2 header. Its
       client address is the one the header reports.
     - This fails closed. A connection from a listed proxy without a valid v2 header is
       closed, never served under the proxy's address.
     - A valid `LOCAL` header, such as a proxy's own health check, keeps the proxy's
       address.
     - A connection from any other address keeps its own address, and its PROXY header is
       not read. The server trusts no forwarded HTTP header.
     - The nameserver keeps its own `proxy_ip_header` setting and does not read PROXY
       protocol yet (#419).

## 3. WebSocket

6. A client's `hello` MAY carry `client_did`. When it does, the client's next frame after
   the `welcome` is `client_proof`.
   - `client_proof` is an ed25519 signature by `client_did`, under domain
     `jig-handshake-client-v1`, over the transcript hash of rule 4 of JEP-0002: BLAKE3 over
     the domain tag and the length-prefixed `hello`, `welcome` and `tls_exporter`.
   - The server MUST verify it before any other frame from the client. If it does not
     verify, the server closes with 4001, as for a failed `peer_proof`.
   - Binding the proof to `tls_exporter` keeps a proof from being relayed into another TLS
     session. Over plaintext the exporter is empty and the binding is to the transcript
     alone, so a client SHOULD NOT submit over plaintext except to loopback.
   - `client_did` is optional. A connection that only reads stays anonymous until it signs
     a subscription, as today (PV-03).
7. A verified `client_proof` makes `client_did` the connection's submitter, for the life of
   the connection.
   - A connection has one submitter. Writing as another DID means opening another
     connection.
   - After a key link (JEP-0012), a client writes as the new DID on a new connection proven
     by the new DID.
8. A `submit` on a connection without a submitter is refused under rule 4.
9. JEP-0002 rule 4's sentence "Client connections carry neither; a client proves its DID per
   subscription" becomes: "A client connection MAY carry `client_did` and `client_proof`
   (JEP-0015). A client proves its DID per subscription, and once per connection to submit."
   Subscriptions keep their per-subscription proof. A later JEP MAY let a proven connection
   stand in for it.

## 4. REST

10. `POST /api/v1/blocks` and the REST channel operations MUST carry a request proof (the
    `jig-request-auth-v1` headers, as reads use).
    - The proof covers the request's method, path and body. The body holds the block, so
      the proof is bound to this block.
    - The proof's DID is the submitter. The replay guard and freshness window are those of
      reads.
    - This applies whatever `require_authenticated_reads` says.
11. REST routes that already require a request proof by the DID they act for, such as
    key-package publication, are unchanged.

## 5. Exemptions

12. **Relayed and carried blocks** arrive under their own rules and are not local
    submissions:
    - a write a follower relays to the owner (JEP-0005 rule 15, `IngestSource::Relayed`);
    - a block a follower takes on the follower stream (JEP-0005 rule 22a).

    The connection carrying them is proven by `peer_proof`, and the share answers for them
    (AB-07, OP-09). A block a listed peer relayed on legacy peering was a third case until
    servers stopped taking them (JEP-0014 rule 37). The owner records a relayed write against the
    follower's proven DID as well as its author (`IngestSource::Relayed`'s `via`).
13. **A follower applies this JEP before it relays.** It MUST apply rules 4 to 10 to the
    client that submitted to it, and MUST NOT relay a block whose signer is not that
    client's submitter. The owner relies on this, as it relies on the follower's admission
    (JEP-0005 rule 15).
    - This covers the REST channel operations as well as `submit` and `POST /api/v1/blocks`.
      On a follower, a member-add for a channel it carries is relayed to the owner under
      the follower's share (#396). A share with a `read` or `write` grant refuses it with
      `GRANT_REFUSED`.
    - The follower applies rules 4 to 10 before either outcome.
14. **Server-originated blocks** are signed in-process by the server's own DID and are not
    local submissions. These are the manifest log, the server's own contract and share
    blocks, and its system channels.

## 6. Bridges

15. **An in-process bridge is part of the server.** Every bridge today runs in the server's
    process and submits through its `BridgeContext` (`IngestSource::Bridge`). Its
    submissions are not local submissions, for the same reason as the server's own blocks
    (rule 14): no client session carries them.
    - The server MUST refuse a bridge submission whose signer is not a DID that bridge has
      registered as its own (`ManagedDidRegistrar`). This is the declared delegation the
      server already keeps, so it routes those DIDs' deliveries to the bridge.
    - Per-sender shadow DIDs, such as the email bridge's, keep working, and so does
      per-sender attribution.
16. **An out-of-process bridge uses a declared delegation.** A bridge that connects to a
    server as a client proves its own DID like any client (rules 6 and 10). It MAY submit
    blocks signed by another DID only if the server's config lists that bridge DID as
    allowed to submit for the DIDs it custodies (open question 1). The submitter is then
    the bridge DID, and rule 4 is met when the signer is the submitter or a DID in its
    custody. Admission and limits for such a block apply to both the signer and the bridge.
17. Clients show every DID a bridge signs as, its own and those in its custody, as a
    bridge's wherever it carries content in or out of an encrypted channel (JEP-0014
    rule 27).

## 7. Compatibility and rollout

18. A client that implements this JEP requests the `authenticated-writes` feature in its
    `hello` capabilities. A server that implements it includes the feature in its signed
    `welcome` only when the `hello` requested it, and the client then sends `client_did`
    and `client_proof`, and request proofs on REST writes.
    - The server MUST NOT add the feature to a `welcome` the `hello` did not ask for. An old
      client checks the `welcome` signature over bytes it rebuilds from the fields it knows,
      so any unrecognised field in a signed `welcome` makes the signature fail for it.
    - The feature is advertised only in the `welcome`, never in the server manifest
      (JEP-0002 rule 12). The manifest decoder refuses unknown keys and any document that
      does not re-encode to its own bytes, and a client that cannot decode the manifest a
      `welcome` cites treats it as a contradiction. A new manifest key would therefore make
      every older client refuse the server for good. Advertising anything there needs a
      manifest format bump.
19. Rollout has three steps, each in a release note:
    1. **Report.** Servers verify `client_proof` and REST write proofs when present, and
       count local submissions that would fail rule 4. They refuse nothing new. Clients
       send the proofs.
    2. **Enforce by default.** `[auth] require_authenticated_writes` defaults to `true`. An
       operator MAY set it to `false` for one release, to give old clients time.
    3. **Always.** The option is removed.
20. **Timing (DJ, 2026-10-26):** designed now; built after F2 phase 1 and before R2.4.
21. Operators of servers that are not open to the public SHOULD meanwhile set
    `[auth.admission] unknown_dids` to `"proof-of-work"` or `"refuse"`.

# Security Considerations (Zero-Trust)

Threat-register rows: AB-03 (relay and bridge quota abuse), AB-07 (delegated admission),
OP-09 (federation abuse), GV-03 (penalty propagation without consent or evidence), PV-03
(identity cross-linking).

- **What it binds.** A local submission is attributed to the DID that made it, by a proof
  the server verifies, so admission, limits and penalties fall on that DID (rule 5).
- **What it does not bind.**
  - Blocks that arrive by contract or relay are attributed to the relaying server as well
    as to their author (JEP-0005 rule 15, rule 12 here). Their author's session is the
    follower's business, under rule 13.
- **Held blocks.** A caller with no proven DID cannot use a resubmission to learn whether a
  server holds a block (rule 4a).
- **Shared addresses.** Per-address limits stay, because DIDs are free (rule 5). Clients
  behind one proxy share them unless the operator lists it in `[server.proxy_protocol]` and
  it sends a PROXY protocol v2 header, which fails closed (rule 5, #423).
  - A hostile follower can still relay what it should not. It answers for that through its
    share (AB-07).
- **Transcript binding.** `client_proof` signs over `tls_exporter`, so a TLS terminator in
  the middle cannot replay one client's proof on another session (the same reasoning as
  `peer_proof`).
- **Ruleset penalties.** GV-03 requires evidence for a penalty. A penalty for a local
  submission can now cite a submission the penalized DID provably made.
- **Bridges.** An in-process bridge may sign only as DIDs it has registered with the server
  (rule 15), and an out-of-process bridge only as itself or as DIDs its declared delegation
  names (rule 16). Abuse that arrives through a bridge is charged to the bridge and its
  operator as well as to the signer.

# Backwards Compatibility

- **Old clients** submit without `client_proof` or REST write proofs. They keep working
  through rollout step 1. From step 2 they are refused with `AUTH_REQUIRED` unless the
  operator turns enforcement off, and from step 3 they must upgrade.
- **Old clients and the `welcome`.** A server adds `authenticated-writes` to its `welcome`
  only when the `hello` asks for it (rule 18), so an old client never sees a field it would
  drop before checking the signature.
- **Old servers** do not know `client_proof`, and do not echo the feature. A client MUST
  NOT send `client_did` or `client_proof` to a server whose `welcome` does not include
  `authenticated-writes` (rule 18). It submits to such a server as it does today.
- **Bridges** are unchanged. The email bridge runs in-process, and its shadow DIDs are
  already registered with the server (rule 15).
- **Subscriptions** are unchanged (rule 9).

# Reference Implementation

None yet. The pieces that exist:
- request proofs (`jig_core::request_auth`, `jig-server/src/auth/authenticate.rs`);
- the transcript hash and `peer_proof` (`jig-pipeline/src/handshake.rs`);
- `IngestSource`, which already tells local, relayed, peer, bridge and server submissions
  apart (`jig-pipeline/src/ingest.rs`).

# Test Vectors

To be added with the implementation:
- a `client_proof` over a known transcript;
- a REST write proof over a known request;
- a `submit` refused for no submitter, and one refused for a signer mismatch;
- a relayed block accepted without a client proof at the owner;
- the held-block order of rule 4a, over one block already held in its channel:
  - submitted with no submitter: `AUTH_REQUIRED`, and no CID in the answer;
  - submitted by a proven submitter that is not its signer: `SIGNER_MISMATCH`, and no CID;
  - submitted by its signer: its CID, with no rate, pool share or relay slot spent;
  - relayed to the owner again: its CID.

# LLM Influence

Drafted with an LLM coding assistant from DJ's decisions of 2026-10-26 and the code on
`main` (873bfd4), and reviewed by the author. Revised against `main` (c2ceeaa) after #396:
rules 4a and 5, rule 12's `via`, rule 13's REST channel operations, and open question 5.

# Rejected Alternatives

- **Rely on the block signature alone.** It proves authorship, not submission. Admission,
  limits and penalties need the second fact.
- **A per-block nonce or audience in the signed block.** It would bind a block to one
  server, but blocks must stay valid on every server that carries them under a contract.
  The binding belongs to the session, not the block.
- **Prove per submit frame instead of per connection.** One proof per connection, bound to
  the transcript, does the same work with one signature.
- **Make every bridge sign as itself.** Per-sender shadow DIDs would give way to one bridge
  DID, and bridged content would lose its per-sender attribution, which per-sender
  admission, limits and reports rely on. A declared delegation (rules 15 and 16) binds the
  bridge just as well and keeps attribution.

# Open Questions

1. **The custody rule for an out-of-process bridge.** How a server's config states which
   DIDs a bridge custodies (an explicit list, or a derivation such as the email bridge's
   shadow DIDs), and whether the delegation is also published so other servers can see it.
   It cannot go in the server manifest as that stands (rule 18): it would need a separate
   signed object, or a manifest format bump.
2. **Subscriptions on a proven connection.** Whether a proven connection can drop the
   per-subscription proof (rule 9).
3. **Multi-author blocks.** Whether a co-authored block needs every author's session or
   only the signer's. Rule 4 requires only the signer's.
4. **Verifying the `welcome` over its received bytes.** Rule 18's request-then-sign step is
   needed only because a client checks the `welcome` signature over bytes rebuilt from the
   fields it parsed. If JEP-0002 instead had a client verify the signature over the
   canonical bytes it received, a server could add fields that old clients ignore while
   still checking the signature. Later features would not need this step. That is a change
   to JEP-0002 rule 2 and its implementation, outside this JEP.
5. **Limits per in-process bridge.** Rule 15 bounds which DIDs an in-process bridge may sign
   as, not how much it submits.
   - Per-DID limits apply to each of its DIDs separately. A bridge with many shadow DIDs
     therefore has no limit across all of them (AB-03: no limit is kept per bridge).
   - Rule 16 charges an out-of-process bridge as well as the signer, but that does not
     cover in-process bridges.
   - Open: whether a server keeps a limit per bridge, and how it relates to rule 16.

# Copyright

This document is licensed under CC-BY-4.0.
