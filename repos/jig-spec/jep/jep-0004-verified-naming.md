+++
jep = 0004
title = "Verified Naming: Suffix Authority, Attestations and Client Pins"
status = "Review"
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
- the encoding of attestations, delegations, reachability records and registration
  proofs: COSE_Sign1 over deterministic CBOR;
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

## Encoding

0. Every object this JEP signs is a `COSE_Sign1` (RFC 9052) whose payload is a CBOR map
   with text keys, encoded under the core deterministic encoding of RFC 8949
   section 4.2.1.
   - The protected header is exactly `{1: -8}` (alg EdDSA, Ed25519). The unprotected
     header is empty. The envelope itself is deterministically encoded.
   - Every payload has a `domain` entry naming the object, listed with each object below.
   - Times and sequence numbers are CBOR unsigned or negative integers (Unix seconds for
     times). Floating-point values and tags MUST NOT appear.
   - A CID is an untagged CBOR byte string (major type 2) holding a binary CIDv1 with
     codec `raw` (0x55) and multihash `blake3-256` (0x1e, 32-byte digest), the one way
     jig computes CIDs. No tag 42, no multibase text. A receiver MUST refuse any other
     version, codec or hash. The schema says which fields are CIDs, so one CID has one
     encoding. Admitting another codec is an explicit change to this rule.
   - **One exception:** a suffix delegation's `root_id` (rule 3) is text under every root,
     so a `contract` root's CID appears there as text. Only the canonical form is allowed:
     base32 lowercase with the `b` prefix, of a CID this rule admits. A receiver MUST
     refuse any other spelling, so that CID still has exactly one encoding. Every other
     CID in a payload is binary.
   - A receiver MUST refuse an envelope or payload that is not in deterministic form,
     that carries an unknown key, or whose `domain` is not the one expected.
   - The signer is named inside the payload, not in the envelope, and the receiver
     verifies against that DID.
   - Anything hashed is hashed over the deterministic encoding, never over a re-encoding.
   - The envelope bytes are what travels and what a resolver keeps as evidence (rule 20).

## Names

1. A name is `alias@suffix`.
   - The alias is 1–24 characters from `[A-Za-z0-9_-]`, compared case-insensitively and
     stored lowercase.
   - The suffix is a domain name, compared case-insensitively.
2. A name says nothing about which server its holder uses.

## Suffix authority

3. A **suffix delegation** is the payload
   `{domain: "jig-suffix-delegation-v1", suffix, authorities: [did], root, root_id, valid_until}`,
   with `authorities` in bytewise ascending order, and one `COSE_Sign1` over that same
   payload per authority.
   - An authority is a nameserver, or a server attesting names under its own suffix.
   - `root` says what makes the delegation authoritative:
     - `config`: the resolver's own configuration;
     - `dns`: served at `https://<suffix>/.well-known/jig-ns-delegation` under a CA-valid
       certificate;
     - `contract`: signed by a threshold of the parties to a shared data contract (v0.3).
   - `root_id` names the specific root:
     - for `config`, a local identifier the resolver chooses, never sent to anyone;
     - for `dns`, the suffix's domain name, lowercased;
     - for `contract`, the contract's CID, as the canonical text form (base32 lowercase,
       `b` prefix) of a CID that rule 0 admits, because `root_id` is text under every root. A resolver
       MUST refuse any other spelling.
   - Every listed authority MUST sign. An envelope over other bytes, or signed by a DID
     outside `authorities`, counts for nothing.
4. A resolver MUST determine a suffix's delegation before it accepts an attestation under
   it, with precedence `config` > `contract` > `dns`.
   - A resolver MUST refuse a delegation where any listed DID's signature is missing or
     invalid.
   - It MUST surface, not silently resolve, a `contract` delegation that disagrees with
     `dns` for the same suffix.
   - A party MUST NOT assert a `config` delegation to anyone else.
   - A suffix of a single label (no `.`, such as `jig`) MUST NOT be `dns`-rooted. A resolver
     MUST NOT run `dns` discovery for it, and MUST refuse a `dns` delegation for it. Such a
     name is resolved through local DNS search domains, so `https://<suffix>/` would reach
     whatever host the local network gives that name, under a certificate a local CA can
     issue. A single-label suffix is `config`- or `contract`-rooted only.
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

8. An attestation is a `COSE_Sign1` by `ns_did` over the payload
   `{domain: "jig-alias-attestation-v1", did, alias, ns_did, valid_from, valid_until}`.
   - `alias` is the full name.
   - Times are Unix seconds.
9. A **rotation** is a link as defined by the identity-lifecycle design (lane I): from
   `old` to `new`, signed by both keys, COSE over deterministic CBOR, with its audience set
   to one nameserver DID and one alias.
   - The audience's nameserver MUST equal the `ns_did` of the attestation the rotation
     produced, and its alias MUST equal that attestation's `alias`. A link with any other
     audience moves no alias.
   - `/v1/rotate` takes the link, in place of two challenge signatures.
   - A nameserver MUST keep every link it accepted, and MUST serve the chain of them with
     the attestation that resulted.
   - Until links exist (lane I's milestone I3), no alias can be rotated, and every change
     of DID behind a pinned name needs the holder's acceptance (rule 18).

## Registration

10. Proof of control for register and renew MUST be a `COSE_Sign1` by the DID over the
    payload `{domain: "jig-alias-<action>-v1", ns_did, alias, challenge}`, with the
    challenge as the text the nameserver issued. A nameserver MUST refuse a proof over
    any other payload, the bare challenge included.
    - `proof_hash` is the BLAKE3 hash of that payload's deterministic encoding. An
      admission proof-of-work on registration binds to it.
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
    1. a chain of valid rotation links (rule 9) leads from the pinned DID to the new DID; or
    2. the holder explicitly accepts the change.

    That covers expiry followed by re-registration to another DID, a change of
    nameserver, and any other differing answer.
19. A client MUST accept names for E2EE operations only through rules 13, 17 and 18.
    Local contacts written by the holder count as pins.

## Evidence

20. A resolver SHOULD keep every attestation and rotation link it acted on until at
    least its `valid_until` plus 30 days, and SHOULD let the holder export them.

## Reachability records

21. A reachability record is a `COSE_Sign1` by `did` over the payload
    `{domain: "jig-reach-v1", did, servers: [{server_did, url}], seq}`. The array keeps
    the order the DID signed.
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
- No message links two user DIDs except a rotation link, which both keys sign
  (PV-03). Service links are by design: an attestation links a user's DID to the
  nameserver's, and a reachability record links it to the servers the user chose to list.

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- Attestations signed under the old JSON encoding are refused once a resolver implements
  this JEP. Nameservers re-issue them on renew.
- `/v1/resolve/{alias}` keeps its path and adds the rotation chain and an optional
  reachability record.

# Reference Implementation

Milestone F1, in the reference implementation:

- `jig_core::naming` (#147), on the shared `jig_core::dcbor` and `jig_core::cose` (#175):
  every object, its signed bytes and its verification.
- The nameserver issues COSE attestations and takes action-bound register and renew proofs
  (#210), for several suffixes with their own policies (#224).
- Servers resolve through `[identity.delegations]` (#200); clients through
  `[naming.delegations]` or `dns` discovery (#201).
- Client name pins (#213), used by `jig dm`, `jig channel add` and `jig channel kick`
  (#215).
- The default `@jig` delegation, in the CLI (#214) and the server (#218).
- `integration-tests/tests/h13_verified_names.rs` runs rules 5, 13, 15, 17 and 18 end to
  end, against real nameservers and a lying one.

Not yet implemented:

- rotation by link (rule 9), which waits on lane I's I3;
- TLS on the nameserver (rule 12);
- proof-of-work on registration (rule 11);
- the `contract` root (v0.3).

# Test Vectors

`vectors/0004/vectors.json` (added by #147): an attestation, a delegation, a
reachability record and a register proof, each as its deterministic payload and its
`COSE_Sign1`, in hex, under fixed test keys. The proof also gives its `proof_hash`.
Rotation links use lane I's vectors.

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
