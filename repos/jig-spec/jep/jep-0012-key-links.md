+++
jep = 0012
title = "Key Links: Moving a DID's Standing to a New Key"
status = "Draft"
type = "Standards Track"
category = "Security"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-19"
requires = ["0004"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

A `did:jig` is its Ed25519 key and does not outlive it, so a new key is a new DID. A
**key link** is the statement, signed by both keys, that the old DID hands what it held
over to the new one, for exactly one audience: a channel, one alias at one nameserver, one
contact, or the public (a server's own key change). This JEP specifies:

- the link's payload and its COSE encoding;
- how a verifier checks a link;
- the fork rule: two links from one DID to different DIDs are evidence of a stolen key;
- what a server's own public link moves: its channels and its sequencer role, and how a
  client checks a channel's history across the change.

Which records carry a link (the `key-link` and `server-rekey` blocks, `/v1/rotate`, the
welcome) and what each other audience then moves are specified where those records are.
Revocation (`jig-key-revoke-v1`) is a later JEP.

Design record, alternatives and prior art:
[`docs/superpowers/specs/2026-10-18-identity-lifecycle-design.md`](../../../docs/superpowers/specs/2026-10-18-identity-lifecycle-design.md),
section Q2.

# Motivation

- Rotating a key must not need a log that ties keys to a DID. Such a log would be an online
  record of every key behind a DID, and would undo key ablation.
- Whoever relied on the old DID (a channel's roles, a name's pin, a contact, a server's
  peers) needs a statement they can verify alone, without a trusted third party, that
  the new DID speaks for the old one.
- The holder chooses who learns that two DIDs share a holder: a link names one audience
  and moves nothing outside it.

Non-goals: deniable links, which are v0.3; revocation; the records that carry a link.

# Specification

The key words MUST, MUST NOT, SHOULD and MAY are as in RFC 2119.

## Payload

The payload is a map in RFC 8949 section 4.2 deterministic CBOR, with text keys:

| Key | CBOR type | Value |
| --- | --- | --- |
| `domain` | text | `jig-key-link-v1` |
| `old` | text | The DID being left, `did:jig:z…` |
| `new` | text | The DID taking over, `did:jig:z…`. MUST differ from `old` |
| `audience` | map | One of the four forms below |
| `issued_at` | integer | When it was signed, in Unix seconds |

`audience` is a map with a text `kind` and the keys that kind takes, and no others:

| `kind` | Other keys | Audience |
| --- | --- | --- |
| `channel` | `channel_id`: bytes. The channel's binary CIDv1 in canonical form: raw codec (0x55), BLAKE3-256, as ingest records carry it | One channel |
| `alias` | `ns_did`: text, a `did:jig`. `alias`: text, the full name `local@suffix` in its canonical lowercase spelling (JEP-0004) | One alias at one nameserver |
| `contact` | `did`: text, a `did:jig` | One contact |
| `public` | none | Anyone. In practice, a server's own key change |

The field names and the `domain` entry follow the signed objects of JEP-0004.

## Envelope

A link is a COSE_Sign (RFC 9052 section 4.1):

- the body's protected header is empty, and its unprotected header is an empty map;
- the payload is the bytes above;
- there are exactly two signatures, in this order: the first by `old`'s key, the second by
  `new`'s key;
- each signature's protected header is `{1: -8}` (EdDSA), its unprotected header is an
  empty map, and it carries no `kid`, since the payload names both signers;
- each signature is Ed25519 over the `Sig_structure` with context `"Signature"`, the empty
  body protected header, the signature's protected header, empty external AAD and the
  payload.

The envelope is untagged and MUST itself be deterministic CBOR. Its bytes are what travels and what a
verifier keeps as evidence.

## Verifying a link

A verifier MUST refuse a link unless all of these hold:

1. The envelope parses as the COSE_Sign above, with no other headers or shape.
2. The payload decodes, and `domain` is `jig-key-link-v1`.
3. `old`, `new`, and any `ns_did` or `did`, are `did:jig` Ed25519 keys in their canonical
   lowercase spelling, the one the key encodes to; `old` ≠ `new`. A key spelled another way
   would decode to the same key but compare unequal, so a fork or an audience match could
   be missed.
4. `audience.kind` is one of the four above. A `channel_id` is a canonical CIDv1 in its
   canonical binary encoding; an `alias` is a full name in its canonical spelling.
5. Re-encoding the decoded fields gives exactly the payload bytes. This refuses unknown
   keys and any non-canonical encoding.
6. The first signature verifies under `old` and the second under `new`.

A verifier MUST act on a link only for the audience it names. A link for one channel does
not move roles in another; a link for an alias at one nameserver does not move that alias
elsewhere, nor any channel role.

Where JEP-0004 follows a chain of links for an alias (rule 18), each link MUST have an
`alias` audience naming that nameserver and alias. A link with any other audience breaks
the chain.

## Following a chain

A server that changed its key more than once serves its links as a chain, oldest first:
each link leaves the DID the one before it moved to, and the last moves to the DID it
signs as now (JEP-0002 `prior_key_links` and `key_link`). A verifier holding an earlier
DID follows the chain hop by hop. It MUST refuse the chain unless all of these hold:

1. It has at most 16 links.
2. Every link verifies as above and has audience `public`.
3. Each link's `old` is exactly the `new` of the link before it.
4. No two links have the same `old`: that is a fork (below), never followed.
5. The last link's `new` is exactly the DID presented.
6. One link's `old` is the DID the verifier holds. It follows from that link on.

Every hop is checked against the links the verifier already kept, as below: a link it is
offered that forks one it followed before is evidence, wherever in the chain it is.

A server MUST NOT serve a chain that breaks these rules. When one of its stored earlier
links is unreadable, does not verify, or leaves a gap, it serves the longest chain that
ends at its DID and is still whole, and tells its operator which file it left out:
verifiers holding a DID behind the break are refused, as with no chain. Only a newest
link that cannot be served stops it from starting. A server keeps every link it ever
signed, and once its chain holds 16 links it stops serving the oldest before it adds
another, so the verifiers still holding that oldest DID are refused and must pin anew.

## A server's standing

A server's public link moves everything the server held as the old DID. That includes
the channels it owns, such as its manifest log (JEP-0002 rule 12), and the sequencer role
of every channel it sequences (JEP-0005). A server that changed its key:

1. MUST treat a channel owned by a DID in its own verified chain (the links it serves, as
   above) as its own, and go on writing into it as its current DID. It MUST NOT move such
   a channel aside, or create another at its slug, as it would for a channel a stranger
   holds.
2. MUST sequence, as its current DID, every channel that a DID in its own verified chain
   sequenced. It continues each channel's chain from the last record: the first record it
   signs has the next `seq`, and its `prev` is the hash of the last record the earlier DID
   signed. Records already signed MUST NOT be signed again.
3. MUST treat a channel owned or sequenced by a DID outside its verified chain exactly as
   before the change: not its own.
4. MUST publish its manifest again, as its current DID, if the newest entry in its log was
   written by an earlier DID, so that every welcome cites an entry signed by the DID that
   signed the welcome.

A server that leaves a DID out of the chain it serves (a broken or pruned link) also
loses that DID's standing: its channels are no longer the server's.

How a server that follows another server's channel follows that sequencer's key change
is not specified yet. Until it is, a follower holds the sequencer it agreed terms with.

### Checking a chain across a key change

A channel's chain from a server that changed its key holds records signed by each of its
DIDs in turn. A client checks it against the DIDs of the server's chain that it holds:
the hops its pin followed, and the links the server serves that lead to the DID it pins,
each verified as above. It takes them in link order, oldest first:

1. A record MUST be signed by one of these DIDs. A record signed by any other DID is a
   break, as before.
2. Once the chain holds a record signed by one DID, a later record (a higher `seq`) signed
   by a DID earlier in the link order MUST be refused as a break. The earlier key handed
   its standing on, so it adds nothing after that. This is the ordered-log rule of
   [Forks](#forks), applied to sequencing.
3. A record before the client's head is history. It MAY be signed by any of these DIDs up
   to the one that signed the head.
4. Two records that contradict each other prove something against the sequencer only
   when one DID signed both. Across a key change the two halves are two keys' words,
   tied only by the link, so a client MUST treat them as a break and MUST NOT offer them
   as a signed proof.

A client that holds no link to an earlier DID (it first pinned the server after the
change and was served no chain) cannot check that DID's records, and refuses them as in
rule 1.

## Forks

Two verified links with the same `old` and different `new` are a **fork**. The old key
signed both, so someone other than its holder has it. Every verifier that holds both
SHOULD keep both envelopes as evidence and SHOULD tell the person it acts for. What else
it does depends on whether the links come in an order:

- **In an ordered log**, such as a channel's chain, where a link takes effect at its
  position: the first link from `old` takes effect, and what it moved stays moved, so
  that what a DID held has one answer at each position. A later link from the same `old`
  to a different `new` MUST be refused, because `old` holds nothing any more. Undoing the
  first move is the log owner's call: in a channel, the owner can unassign the moved
  roles by hand.
- **With no order**, such as a pin or a server's `expected_did` that has seen both links:
  the verifier MUST NOT follow either automatically.

Two links with the same `old` and the same `new` (for two audiences, or signed twice) are
not a fork.

A holder MUST NOT link one `old` DID to two different `new` DIDs, even for different
audiences: splitting a rotation per audience cannot be told apart from theft. Clients MUST
refuse to sign a second link from an `old` to a different `new`.

# Security Considerations (Zero-Trust)

- **Both keys sign.** The new key alone cannot claim the old DID's standing, and the old
  key alone cannot hand it to a DID that did not agree.
- **A stolen old key.** A thief can sign a link to its own key. If the holder also links,
  the two links fork and verifiers that see both follow neither. A verifier that sees only
  the thief's link follows it: revocation, a later JEP, is the defense.
- **A disclosed link is permanent and can be forwarded.** A signature proves the link to
  anyone the recipient shows it to, so the holder's choice of audience holds only as far as
  each recipient keeps the link to itself. Clients MUST say so before sending one.
- **A retired server key.** Clients take records from a server's earlier DIDs only in link
  order, so whoever holds a key the server rotated away from cannot add to a channel's
  history after the newer key has signed in it. Before that point, on a channel a client
  has not read past the change, it can: the same exposure the old key had before the
  change. A client whose channel head was kept without its record (a pin written before
  heads were kept whole) cannot tell which DID signed the head, so it applies the rule
  only from the next record it accepts: until then an earlier key, given a path to that
  client, can still append past the head.
- **Replay.** A link is a statement of fact with no expiry. Showing it again changes
  nothing a verifier has not already acted on. `issued_at` orders links and lets a verifier
  apply its own age policy; it is not a validity window.
- **Audience confusion** is closed by rule 4, the canonical forms, and the audience rule
  above. A verifier that compares an alias or channel id it did not canonicalize may still
  miss a match, but cannot be made to accept a link for another audience.
- **Metadata.** A link ties two DIDs. It is the only message in jig that does, and the
  holder decides who sees it.

# Backwards Compatibility

There are no earlier links. `jig keys rotate` today signs a bare challenge with both keys
at `/v1/rotate`. Moving it onto links is a change to that endpoint, specified with it.

# Reference Implementation

`jig_core::key_link` (`repos/jig-core/src/key_link.rs`): `KeyLink`, `Audience`,
`SignedKeyLink::sign`, `SignedKeyLink::from_envelope` and `fork`. `SignedKeyLink`
implements `jig_core::naming::AliasLink`, so `verify_rotation_chain` follows alias links.
A server's chain: `jig_pipeline::handshake::chain_moves` follows it, and
`jig_client::server_key::key_chain` builds what a server serves from its stored links;
`jig-server keys rotate` signs and keeps them. A server's standing: at boot
`jig_pipeline::persist::SqliteStore::adopt_predecessor_sequencers` moves the channels its
earlier DIDs sequenced, and `jig_server::v0_0_2_manifest_log::publish` keeps the log they
own. A client checks a chain across the change with `jig_client::chain::ChannelChain::across`,
fed the DIDs `jig_client::pins::ServerPin::sequencers` gives.

# Test Vectors

`repos/jig-spec/jep/vectors/0012/vectors.json` holds one link per audience kind, made with
fixed keys (Ed25519 seeds of one repeated byte: old `0x01`, new `0x02`, nameserver
`0x07`, contact `0x03`) at `issued_at` 1800000000. The channel's id is the canonical CIDv1
of the bytes `#general`. For each audience the file gives `old`, `new`, `payload_hex` and
`cose_sign_hex`. `jig_core::key_link`'s tests rebuild every entry and open every envelope.

# LLM Influence

Drafted with Claude Code (lane I). The encoding follows JEP-0004's conventions, and the
reference implementation's tests pin it to the vectors.

# Rejected Alternatives

- **An identity log**, one DID for life with its keys listed under it: it would undo key
  ablation. Rejected by DJ, 2026-10-18.
- **A COSE_Sign1 by the old key alone:** it would let a stolen old key move standing to
  any DID with no agreement from the new one, and would not show the new key's holder
  accepted.
- **Short field names** (`t`, `aud`, `iat`): they would differ from every other signed
  object in jig.
- **A `kid` on each signature:** the payload names both signers, so a `kid` would only be
  one more thing to keep consistent.

# Copyright

This document is licensed under CC-BY-4.0.
