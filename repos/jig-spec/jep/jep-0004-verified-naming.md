+++
jep = 0004
title = "Verified Naming: Suffix Authority, Attestations and Client Pins"
status = "Draft"
type = "Standards Track"
category = "Security"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-18"
requires = ["0002", "0003"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

A name `alias@suffix` maps to a `did:jig` through an attestation signed by a nameserver
authoritative for the suffix. This JEP specifies:

- how a resolver learns which nameservers are authoritative for a suffix;
- the canonical form of attestations and registration proofs;
- how whoever acts on a binding verifies it;
- how clients pin names and accept changes;
- what resolvers keep as evidence;
- the DID-signed reachability record that says where a DID can be reached.

Design record, alternatives and prior art:
[`docs/superpowers/specs/2026-10-18-federation-naming-and-contract-design.md`](../../../docs/superpowers/specs/2026-10-18-federation-naming-and-contract-design.md),
section 4.

**Draft.** The decisions behind it are recorded in the design document, section 11.

# Motivation

A DID is its own key, so key substitution happens where a name maps to a DID (OP-08).
Today:

- the server's resolver verifies no signature and binds no suffix to a nameserver;
- it takes the first answer and caches past validity (NS-01);
- nothing retains attestations (NS-02);
- registration proofs bind no action (AB-01);
- clients accept only DIDs and local contacts, which is what keeps nameserver lies away
  from E2EE.

This JEP lets clients use names without losing that property.

Non-goals:

- ruleset-group delegation with thresholds, cross-registration and transparency logs
  (v0.3, with lane R);
- multi-device (lane I).

# Specification

## Names

1. A name is `alias@suffix`.
   - The alias is 1–24 characters from `[A-Za-z0-9_-]`, compared case-insensitively and
     stored lowercase.
   - The suffix is a domain name, compared case-insensitively.
2. A name says nothing about which server its holder uses.

## Suffix authority

3. A **suffix delegation** is
   `{suffix, authorities: [did], root, root_id, valid_until, sigs: [{did, sig}]}`.
   - An authority is a nameserver, or a server attesting names under its own suffix.
   - `root` says what makes the delegation authoritative:
     - `config`: the resolver's own configuration;
     - `dns`: served at `https://<suffix>/.well-known/jig-ns-delegation` under a CA-valid
       certificate;
     - `contract`: signed by a threshold of the parties to a shared data contract (v0.3).
   - `root_id` names the specific root:
     - for `config`, a local identifier the resolver chooses, never sent to anyone;
     - for `dns`, the suffix's domain name, lowercased;
     - for `contract`, the contract's CID.
   - Every listed authority MUST sign. Each `sig` is by that authority over the labelled
     hash (rule 8) of these parts, in order:
     - (`domain`, `jig-suffix-delegation-v1`);
     - (`suffix`);
     - (`root`);
     - (`root_id`);
     - (`count`, the number of authorities as decimal ASCII);
     - one (`authority`, did) part per authority, in bytewise ascending order;
     - (`valid_until`).
4. A resolver MUST determine a suffix's delegation before it accepts an attestation under
   it, with precedence `config` > `contract` > `dns`.
   - A resolver MUST refuse a delegation where any listed DID's signature is missing or
     invalid.
   - It MUST surface, not silently resolve, a `contract` delegation that disagrees with
     `dns` for the same suffix.
   - A party MUST NOT assert a `config` delegation to anyone else.
5. A resolver MUST NOT accept an attestation signed by a DID outside the suffix's
   authorities.
6. A name means (alias, suffix, root, root_id), and a client pin is keyed by all four
   (rule 17). A client MUST NOT display a name as verified unless its own resolver
   verified it. A name received from elsewhere is a hint, re-verified by the receiver.
7. A server's `server-manifest` (JEP-0005) declares the `dns`- and `contract`-rooted
   suffixes it attests. A `config`-rooted suffix is never published. A server declares it
   only to the other party of a contract, inside its signed `contract-offer` or
   `contract-accept`. A contract MUST be refused (`SUFFIX_CONFLICT`) when two parties claim
   one suffix under different authorities, whatever the roots.

## Attestations

8. An attestation is `{did, alias, ns_did, valid_from, valid_until, sig}`.
   - `alias` is the full name.
   - Times are Unix seconds.
   - `sig` is the Ed25519 signature by `ns_did` over the labelled BLAKE3 hash of
     (`domain`, `jig-alias-attestation-v1`), (`did`), (`alias`), (`ns_did`),
     (`valid_from`), (`valid_until`). Times and counts are encoded as decimal ASCII.
   - **Labelled hashing**, as in the admission proof-of-work: for each part, the label's
     UTF-8 bytes, then the value's length as a little-endian u64, then the value's bytes.
     Every signature in this JEP uses it.
9. A **rotation statement** is `{alias, ns_did, old_did, new_did, at, sig_old, sig_new}`.
   - `ns_did` is the nameserver that accepted the rotation. It MUST equal the `ns_did` of
     the attestation the rotation produced.
   - Both keys sign over (`domain`, `jig-alias-rotate-v1`), (`alias`), (`ns_did`),
     (`old_did`), (`new_did`), (`at`).
   - A nameserver MUST keep every rotation statement it accepted, and MUST serve the chain
     of them with the attestation that resulted.

## Registration

10. Proof of control for register, renew and rotate MUST be a signature by the DID over
    (`domain`, `jig-alias-<action>-v1`), (`ns_did`), (`alias`), (`challenge`). A
    nameserver MUST refuse a proof over the bare challenge.
    - A challenge MUST be fresh: at least 32 random bytes, issued by the nameserver, and
      valid for a short window it sets (at most 300 s).
    - A nameserver MUST consume a challenge atomically, on the first proof that verifies.
      It MUST refuse a challenge that is expired, unknown or already consumed, for any
      action.
11. Registration is a binding endpoint. It MUST carry proof-of-work and rate limits
    (identity-and-reputation.md; D23, D26). This JEP does not set the parameters.
12. A nameserver MUST serve TLS: CA-issued, or bound to its DID as for servers. Plaintext
    is allowed only behind an antipattern flag that the nameserver advertises.

## Verification

13. Whoever acts on a binding MUST verify it. A client MUST verify before it encrypts to,
    adds, or opens a DM with a name, and MUST NOT rely on a server's check. Verification
    means all of the following:
    1. the signer is authoritative for the suffix (rules 3–5);
    2. `sig` verifies;
    3. `valid_from ≤ now < valid_until` on the verifier's clock;
    4. `alias` equals the requested name after normalisation.
14. A resolver MUST NOT cache a binding past `valid_until` and MUST re-check validity on
    every use of a cached binding.
15. A resolver that obtains two valid attestations for one name with different DIDs and
    overlapping windows MUST refuse the name, MUST keep both, and SHOULD surface them as
    evidence of equivocation.
16. A resolver MAY fetch through its own server or directly from a nameserver. The fetch
    path does not affect verification.

## Client pins

17. A client MUST pin `(name → did, attestation, ns_did)` on first verified use of a name
    in any E2EE operation, keyed as in rule 6, and SHOULD pin on any other first verified
    use. When it pins, it shows the DID's fingerprint and the vouching nameserver.
18. A client MUST NOT act on a binding that differs from its pin unless one of these
    holds:
    1. a chain of valid rotation statements leads from the pinned DID to the new DID; or
    2. the holder explicitly accepts the change.

    That covers expiry followed by re-registration to another DID, a change of
    nameserver, and any other differing answer.
19. A client MUST accept names for E2EE operations only through rules 13, 17 and 18.
    Local contacts written by the holder count as pins.

## Evidence

20. A resolver SHOULD keep every attestation and rotation statement it acted on until at
    least its `valid_until` plus 30 days, and SHOULD let the holder export them.

## Reachability records

21. A reachability record is `{did, servers: [{server_did, url}], seq, sig}`.
    - `sig` is by `did` over the labelled hash of these parts, in order:
      - (`domain`, `jig-reach-v1`);
      - (`did`);
      - (`seq`);
      - (`count`, the number of servers);
      - for each server in the order listed, (`server_did`) then (`url`).
    - A DID has no home server. The record lists the servers where the DID wants to be
      found, in no order of preference. The DID MAY leave servers out, or publish no
      record at all.
    - A nameserver whose data contract requires a contact point MAY require a record at
      registration (`POST /v1/register` then carries it).
    - The record with the highest valid `seq` wins.
    - A server SHOULD serve the records of DIDs that list it.
    - A nameserver MAY serve one beside an attestation.
    - Nobody but the DID can produce one.

# Security Considerations (Zero-Trust)

**Threats addressed:**

- **OP-08:** pins, with a change accepted only by a rotation signed by the old key or by
  the holder.
- **NS-01:** suffix authority, verification and bounded caching.
- **NS-02:** retention, and conflicting answers as proof.
- **AB-01:** proofs bound to the action, alias and nameserver.

**Residual risks:**

- **First contact.** A nameserver, or the controller of a suffix's domain under
  discovery, can bind a name to its own key before the client first pins it. A signature
  makes the lie provable, not impossible. Closing first contact needs transparency
  (v0.3) or out-of-band comparison.
- **NS-03** is unchanged until ruleset-group delegation.
- **Domain seizure** under discovery redirects a suffix for names nobody has pinned yet.
- **Reachability records** misroute only to denial of service, because key packages are
  self-signed.

**Privacy:**

- Lookups through the server hide the client's address from the nameserver.
- Direct lookups hide them from the server.
- No message links two user DIDs except a rotation statement, which both keys sign
  (PV-03). Service links are by design: an attestation links a user's DID to the
  nameserver's, and a reachability record links it to the servers the user chose to list.

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- Attestations signed under the old JSON encoding are refused once a resolver implements
  this JEP. Nameservers re-issue them on renew.
- `/v1/resolve/{alias}` keeps its path and adds the rotation chain and an optional
  reachability record.

# Reference Implementation

None yet. Milestone F1 of the design.

# Test Vectors

To be added with F1:

- an attestation;
- a rotation statement;
- a delegation document;
- a reachability record;

each as inputs, hash and signature, under a fixed test key.

# Rejected Alternatives

- **Trusting the user's server to resolve.** That is today's model. The server becomes
  able to substitute keys (D11).
- **Failover between nameservers.** A second nameserver that is asked only when the first
  fails adds availability and hides disagreement. Disagreement must refuse.
- **The nameserver asserting where a DID is reached.** It couples routing to naming and lets the
  nameserver misdirect.
- **Names as `user@server`.** That ties identity to a server, which DIDs exist to avoid.

# Copyright

This document is licensed under CC-BY-4.0.
