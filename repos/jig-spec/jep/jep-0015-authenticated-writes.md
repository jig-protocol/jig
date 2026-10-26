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
5. **Admission, rate limits, proof-of-work and ruleset penalties for a local submission
   apply to the submitter.** By rule 4 that is also the signer.

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
    - a block a follower takes on the follower stream (JEP-0005 rule 22a);
    - a block a listed peer relays on legacy peering (`IngestSource::FederatedPeer`).

    The connection carrying them is proven by `peer_proof`, and the share or peer listing
    answers for them (AB-07, OP-09).
13. **A follower applies this JEP before it relays.** It MUST apply rules 4 to 10 to the
    client that submitted to it, and MUST NOT relay a block whose signer is not that
    client's submitter. The owner relies on this, as it relies on the follower's admission
    (JEP-0005 rule 15).
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
    as to their author (JEP-0005 rule 15). Their author's session is the follower's
    business, under rule 13.
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
- a relayed block accepted without a client proof at the owner.

# LLM Influence

Drafted with an LLM coding assistant from DJ's decisions of 2026-10-26 and the code on
`main` (873bfd4), and reviewed by the author.

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
   shadow DIDs), and whether the delegation is also published, for example in the server's
   manifest, so other servers can see it.
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

# Copyright

This document is licensed under CC-BY-4.0.
