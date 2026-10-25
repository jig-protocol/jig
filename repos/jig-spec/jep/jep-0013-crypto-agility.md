+++
jep = 0013
title = "Crypto Agility and a Post-Quantum Path"
status = "Draft"
type = "Standards Track"
category = "Security"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-25"
requires = ["0001", "0002", "0004", "0005", "0008", "0012"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

Every signature in jig today is ed25519, and every encrypted channel uses one MLS
ciphersuite, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001). Neither choice is
named anywhere a verifier reads it. The algorithm is implied by the DID's form, the
signature's length and a constant in `jig-mls`.

This JEP is jig's side of the plan for moving to other algorithms, ML-DSA and ML-KEM
included, without a flag day. It specifies:

1. **A signature-algorithm registry.** A DID's form names its algorithm, and a verifier
   takes the algorithm from the DID and never from the signed object.
2. **A new DID form** for keys other than ed25519, including a hybrid ed25519 + ML-DSA key.
   The existing form stays valid for ed25519 forever.
3. **How each signed artefact moves.** This covers DIDs, key links, receipts, attestations,
   the handshake, request proofs, block signatures and the proof-of-work binding. The
   COSE-based artefacts need no new format; the rest get versioned successors.
4. **How a post-quantum or hybrid MLS ciphersuite is registered and allowed per channel.**
   It goes through the existing suite registry (JEP-0001, D13), and the #303 ciphersuite
   gate is generalised from "jig's suite" to "this channel's suite".
5. **Adoption criteria.** jig builds no suite and no primitive of its own. It adopts a vetted,
   pluggable suite when one exists, after general availability (GA).

# Motivation

- **Harvest now, decrypt later.** MLS ciphertext recorded today can be decrypted by anyone
  who later breaks X25519. That threat needs only a post-quantum KEM, and it is the reason
  the KEM can move before signatures do.
- **Forgery later.** Once ed25519 can be broken, anyone can sign as any `did:jig` whose
  public key they know, and every DID's public key is its name. A DID has to move to a new
  key before that day, and the move has to be verifiable without a trusted party. That
  is a key link (JEP-0012).
- **Algorithm choices are hard-wired today.** The survey in the next section lists eleven
  places. Some carry no domain string, and some check the signature in non-strict mode.
  Fixing them once, with a rule, costs less than fixing them algorithm by algorithm.
- **Operators own their encryption** (JEP-0001). A post-quantum suite is one more registered
  suite, chosen per channel at creation. It is not a protocol version.

**Goals.**
- An identity can move from ed25519 to a post-quantum or hybrid key while keeping its
  channels, names, contacts and server standing.
- A channel can be created under a post-quantum or hybrid MLS ciphersuite.
- Neither move needs every server or client to upgrade at once.

**Non-goals.**
- Choosing the post-quantum algorithms. This JEP names candidates and sets the bar for
  adopting them.
- Building a suite, a KEM, a signature scheme or an MLS implementation.
- Migrating an existing channel to a new suite in place. A new suite is a new channel
  (JEP-0001 open question 6).
- Hash-function agility. BLAKE3 is not affected by the quantum threats above; CIDs already
  carry a multihash code.

**Position (DJ, 2026-10-25).** The work is post-GA. jig does not build its own suite. It
adopts a vetted, pluggable suite when one exists, and this JEP is the plan on jig's side.

## Where the algorithm is fixed today

| Artefact | Encoding today | Algorithm named? |
| --- | --- | --- |
| DID (`jig-core/src/did.rs`) | `did:jig:z` + lowercase unpadded base32 of the 32-byte ed25519 key | Implied by the `z` sigil and the length |
| COSE objects (`jig-core/src/cose.rs`): receipts `jig-block-receipt-v1`, key links `jig-key-link-v1`, naming objects, contract messages, `ingest` records `jig-ingest-v2`, operator and program policies, evidence bundles, the handshake refusal | COSE_Sign1 or COSE_Sign over deterministic CBOR, protected header `{1: -8}` | Yes, but the parser accepts only `-8` |
| Handshake welcome `jig-handshake-welcome-v2` (`jig-pipeline/src/handshake.rs`) | Raw ed25519 over length-prefixed canonical bytes | No |
| Peer proof `jig-handshake-peer-v1` | Raw ed25519 over a BLAKE3 digest | No |
| TLS binding `jig-tls-binding-v1` (`jig-core/src/tls_binding.rs`) | Raw ed25519 over a BLAKE3 digest | No |
| Request proof `jig-request-auth-v1` (`jig-core/src/request_auth.rs`) | Raw ed25519 over a BLAKE3 digest that does not include the DID | No |
| Block signature (`jig-pipeline/src/ingest.rs`) | Raw ed25519 over a JSON array of the manifest and code bytes, with **no domain string** | No |
| Admission proof `jig-admission-v2` (`jig-core/src/admission_pow.rs`) | Raw ed25519 | No |
| Proof-of-work `jig-pow-v1` (`jig-core/src/pow.rs`) | BLAKE3 over the verifier and subject **DID strings** | Not a signature; no algorithm depends on the key |
| MLS credential (`jig-mls/src/credential.rs`) | `BasicCredential` with the DID; the leaf's signature key **is** the DID's ed25519 key | Implied by the ciphersuite |
| MLS ciphersuite (`jig-mls/src/lib.rs`, `delivery.rs`) | One constant, `CIPHERSUITE` (0x0001), enforced by `require_ciphersuite` (#303) | In MLS, yes; in the jig registry, no: `mls` names no ciphersuite |

The spec's [Crypto Primitives](../src/crypto.md) chapter sketches agility as `ed25519:v1:`
key strings. No code implements that sketch, and this JEP replaces it.

# Specification

The key words MUST, MUST NOT, SHOULD and MAY are as in RFC 2119.

## 1. The signature-algorithm registry

The spec keeps a registry of signature algorithms, alongside the suite registry. Each entry
has:

- an identifier;
- a 16-bit `alg` code;
- its COSE algorithm value;
- its public-key and signature sizes;
- a status: `active`, `verify-only` or `refused`;
- the JEP that added it.

| Identifier | `alg` | COSE | Status | DID form |
| --- | --- | --- | --- | --- |
| `ed25519` | 1 | -8 (EdDSA) | active | `z` (section 2.1) |
| `ed25519+ml-dsa-65` | reserved | composite, per the IETF LAMPS composite-signature work once it has a code point | not registered | `k` (section 2.2) |
| `ml-dsa-65` | reserved | the COSE registry's ML-DSA-65 value | not registered | `k` |

Rules:

1. **A verifier MUST take the algorithm from the signer's DID.** It MUST check that the
   object's own algorithm field, where it has one (the COSE `alg`), names the same
   algorithm, and refuse the object if not. An algorithm field is never a reason to try
   another algorithm.
2. **An unregistered, reserved or `refused` algorithm is refused** (fail closed), the same
   way an unregistered suite is.
3. **A `verify-only` algorithm** still verifies objects already signed. A server MUST NOT
   accept a new block, link or attestation from a DID whose algorithm is `verify-only`,
   except a key link away from that DID (section 3.2). Moving an algorithm to `verify-only`
   takes a JEP and a release note; it is never a flag day for reading history.
4. **Strict verification.** Every algorithm's verification MUST be its strict form. For
   ed25519 that means refusing non-canonical points and S values (`verify_strict` in
   ed25519-dalek). Today the welcome, block, TLS-binding and request-proof checks use
   the non-strict form, and they move to strict when their successors land (section 3).
5. **Composite keys verify every component.** A composite signature verifies only if every
   component signature verifies over the same message (AND, never OR).

Adding an algorithm takes a JEP that gives its entry, its test vectors and the adoption
evidence in section 6.

## 2. DID forms

### 2.1 The ed25519 form (unchanged)

`did:jig:z` followed by 52 characters of lowercase unpadded base32 (RFC 4648) of the 32-byte
public key. This form means `ed25519` and nothing else, now and later. The `z` is a jig
sigil, not a multibase prefix.

### 2.2 The key-hash form

For every algorithm other than ed25519:

```text
did:jig:k<base32-lowercase-nopad( alg (u16, big-endian) || BLAKE3-256( "jig-did-key-v1" || alg || public_key ) )>
```

- The identifier is 55 characters after `did:jig:k`, whatever the key's size. An ML-DSA-65
  public key is 1,952 bytes, and a DID that spelled it out would be about 3,100 characters.
- The algorithm is readable from the DID without fetching anything.
- A verifier needs the public key itself. Every signed object from such a DID carries it
  (section 3.1), and the verifier MUST recompute the hash and compare it with the DID before
  verifying the signature.
- An implementation that does not know the `k` sigil refuses the DID. Today's
  `did.rs` already refuses any sigil but `z`, so old clients fail closed.

The domain string and the `alg` inside the hash keep two algorithms from ever sharing a
DID, even if their key encodings collide.

## 3. How each artefact moves

### 3.1 COSE objects: no new format

Receipts, key links, naming objects, contract messages, `ingest` records, policies,
evidence bundles and refusals are already COSE.

- **Algorithm.** Each signature's protected header carries the registry's COSE `alg` for the
  signer's algorithm, in place of the fixed `{1: -8}`.
- **Public key.** For a `k` DID, the protected header also carries the public key, under a
  jig header label this JEP reserves in the private-use range (`jig-pk`). The value is
  fixed with the test vectors. The key is in the protected header, so the signature covers it.
- **Domain strings do not change.** A domain names what an object means, not how it is
  signed, so `jig-block-receipt-v1` signed with ML-DSA is still `jig-block-receipt-v1`.
- **Parsing.** `cose.rs` stops refusing every `alg` but `-8`. It accepts any registered
  algorithm that matches the signer's DID (section 1, rule 1).

### 3.2 Key links: the migration mechanism

A key link (JEP-0012) is how a DID moves to another algorithm. The old key signs first and
the new key signs second, each with its own algorithm in its own COSE_Signature. The link's
payload is unchanged: `old` and `new` are DID strings of any registered form.

- **Order of migration.** A holder SHOULD link its ed25519 DID to a composite
  `ed25519+ml-dsa-65` DID while ed25519 is still sound. A link signed only by a key that can
  no longer be trusted proves nothing.
- **After a migration.** A verifier that has pinned the new DID MUST NOT follow a later link
  away from the old DID. JEP-0012's fork rule already keeps such a link as evidence of a
  stolen key, and after migration it is exactly what a quantum forger would produce.
- **Each audience moves through its own link**, as JEP-0012 specifies:
  - a channel's roles and membership: a `key-link` block;
  - a name at a nameserver: `/v1/rotate` with an alias link;
  - a contact;
  - a server's own identity: the `public` audience, served as the chain in the welcome and at
    `/.well-known/jig`.

  None of these needs a new record kind. The chain limit of 16 links is unchanged.

### 3.3 Signatures outside COSE: versioned successors

Each of these gets a successor that is a COSE_Sign1 over deterministic CBOR, with a new
domain string. A `z` DID MAY use either version while the old one is accepted. A `k` DID MUST
use the successor.

| Today | Successor | Also fixes |
| --- | --- | --- |
| Welcome `jig-handshake-welcome-v2` | `jig-handshake-welcome-v3`, the same fields as a CBOR map | strict verification |
| Peer proof `jig-handshake-peer-v1` | `jig-handshake-peer-v2` | — |
| TLS binding `jig-tls-binding-v1` | `jig-tls-binding-v2` | strict verification |
| Request proof `jig-request-auth-v1` | `jig-request-auth-v2`, with the DID inside the signed hash | binds the proof to its claimed signer, and does not rely on the header alone |
| Block signature (no domain) | `jig-block-sig-v1`, signing the bundle's CID | domain separation; strict verification |
| Admission proof `jig-admission-v2` | `jig-admission-v3` | — |

The handshake advertises which successors a server accepts, in its capabilities
(JEP-0002), and a client uses the newest version both sides support. A server MUST NOT
accept an old version from a `k` DID. Each old version is retired, and becomes refused, by a
later JEP, never by this one.

Larger signatures need room:
- A request proof travels in an HTTP header, and an ML-DSA-65 signature is 3,309 bytes before
  base64. Request proofs from `k` DIDs MAY travel in the request body instead, and the
  successor fixes where.
- `MAX_BUNDLE_BYTES` and `MAX_ENVELOPE_BYTES` keep their meaning. The envelope overhead
  constant grows to fit the largest registered signature and public key.

### 3.4 Proof-of-work

The puzzle binds the verifier and subject **DID strings** and their actions (JEP-0008). It
signs nothing and depends on no key algorithm, so it does not change. The only rule: a
`k` DID is hashed as its full DID string, like any other.

### 3.5 Attestations by nameservers and servers

A nameserver's attestation binds an alias to a DID and is signed by the nameserver's DID. Each
side moves independently:
- **The subject moves** by an alias link (section 3.2), and the nameserver re-attests under
  the new DID.
- **The nameserver moves** by a `public` key link, which clients follow like a server's.
  Clients follow nameservers' links once nameservers serve them; today they serve none.

Attestations signed before a move stay verifiable for as long as their algorithm is not
`refused`.

## 4. MLS ciphersuites

### 4.1 Registration

A post-quantum or hybrid MLS ciphersuite is registered as **its own suite entry**, as
JEP-0001 already allows. Each entry names exactly one RFC 9420 ciphersuite code point.

| Suite | MLS ciphersuite | Status |
| --- | --- | --- |
| `mls` | 0x0001, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | implemented |
| `mls-pq-…` | a code point that draft-ietf-mls-pq-ciphersuites assigns, once it does | reserved, not registered |

`mls` keeps meaning 0x0001. It never comes to mean a set of ciphersuites, because a channel
pinned on `mls` must not later accept another one. The registration JEP for a new entry
gives what JEP-0001 asks of every suite:
- operator confidentiality and faithful delivery;
- conformance vectors in `repos/jig-spec/vectors/suites/`;
- the evidence in section 6.

### 4.2 Allowing a suite per channel

Nothing about choosing a suite changes:
- A channel's suite is fixed by its creation block (JEP-0001).
- The creator chooses from the suites the server advertises in its signed welcome.
- Restricted channels and DMs MUST use an operator-confidential suite (D25). Any registered
  MLS entry qualifies.
- A federation contract fixes the channel's suite, and a server that cannot speak it is
  refused (JEP-0005, D12).

What changes in the implementation:

1. **The ciphersuite gate takes the channel's ciphersuite.** `require_ciphersuite` (#303)
   compares against the channel's registered ciphersuite instead of the `CIPHERSUITE`
   constant. It still refuses every other ciphersuite **before** running any of its crypto,
   for group infos, key packages and welcomes alike. The one ungated path #303 documents (an
   inline Add verified in its own ciphersuite) MUST be closed before a second ciphersuite is
   registered, because it would then run crypto the channel never chose.
2. **Key packages are per ciphersuite.** A client publishes key packages for each
   ciphersuite it supports, and the key-package route takes the ciphersuite as a parameter.
3. **The server's delivery service** validates commits in the channel's ciphersuite. It needs
   only public-state operations in that ciphersuite, so it never holds the new KEM's secret
   keys.
4. **The suite registry's properties** (`jig-core/src/suite.rs`) are per entry, as they are
   today. The test-only `test-aead` suite already exercises a second entry through the
   registry (#165).

### 4.3 Signatures inside MLS

An MLS ciphersuite fixes its signature scheme, and in jig the leaf's signature key **is** the
DID's key. Two cases follow.

- **A post-quantum KEM with ed25519 signatures.** The X25519 + ML-KEM hybrid suites with
  Ed25519 signatures change nothing about identity. OpenMLS's experimental X-Wing suite is one
  (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`). This is the first step, and it answers
  harvest-now-decrypt-later on its own.
- **Post-quantum signatures.** draft-ietf-mls-pq-ciphersuites pairs its ML-DSA suites with
  post-quantum KEMs only. Using them needs the leaf key to be an ML-DSA key. That requires one
  of two things:
  - the member's DID has moved to a `k` DID whose algorithm the ciphersuite uses; or
  - the MLS leaf key is separated from the DID key, with a DID-signed binding in the
    credential.

  Separating the leaf key also answers JEP-0001 open question 4 (multi-device, and rotation
  without rejoining). This JEP requires that one of the two is specified before a
  post-quantum-signature ciphersuite is registered. It leaves the choice to the identity
  lifecycle design.

## 5. Order of work

None of these steps is a flag day. Each one adds something, and old forms keep working until
a later JEP retires them.

| Step | What | Gate |
| --- | --- | --- |
| A | The registry (section 1), strict verification, the successors in section 3.3, and parsers that take the algorithm from the DID. Nothing changes algorithm yet | May land before GA if DJ chooses; it hardens ed25519 too |
| B | Register a hybrid post-quantum-KEM MLS suite with ed25519 signatures (section 4.3, first case) | After GA, once a candidate meets section 6 |
| C | Register `ed25519+ml-dsa-65` and the `k` DID form; holders migrate by key link | After GA, once an ML-DSA implementation meets section 6 |
| D | Separate the MLS leaf key from the DID key, or require `k` DIDs for post-quantum-signature suites; then register one | After C |
| E | Move `ed25519` to `verify-only` for new registrations, by ruleset or server policy first, by JEP last | When the threat is concrete |

## 6. Adoption criteria

jig adopts a suite, an algorithm or an implementation only when all of these hold:

1. **A stable identifier.** An IANA code point from a published RFC, or from an IETF
   working-group draft on the Standards Track whose code points the working group has fixed.
   Private-use or expired-draft code points are only for test builds.
2. **A released implementation in the library jig already uses.** The suite ships as a
   supported feature of openmls, or of whatever library replaces it by then, and not as an
   experimental flag.
3. **A vetted crypto provider.** The primitives come from a provider that is formally
   verified or has had a published audit, with constant-time claims for the operations that
   touch secrets.
4. **Interoperability.** Vectors from the specification or another implementation pass,
   alongside jig's own conformance vectors.
5. **jig wrote none of the cryptography.** jig's code is the glue: the registry entry, the
   gate, the suite properties and the vectors.

Where the candidates stand on 2026-10-25:

| Candidate | What it is | Meets the bar? |
| --- | --- | --- |
| draft-ietf-mls-pq-ciphersuites-06 (July 2026) | MLS working-group draft, now Standards Track. ML-KEM suites, X25519 and NIST-curve hybrids, and ML-DSA-signature suites paired with post-quantum KEMs | Not yet: a draft, not an RFC. The target for steps B and D |
| OpenMLS X-Wing suite | Experimental suite on libcrux's ML-KEM and X25519, at non-IANA code point 0x004D, from an expired individual draft | No: not IANA-registered, and it will be superseded by the working group's suites. Useful to test step B's plumbing |
| liboqs (Open Quantum Safe) | C library of post-quantum algorithms for prototyping | No, as a production provider. Usable for test vectors and experiments |
| saorsa-labs/saorsa-mls | "MLS-inspired" library with post-quantum primitives | No: it describes itself as not for production use, and it is not RFC 9420 |

# Security Considerations (Zero-Trust)

Threat-register rows: OP-03 (downgrade), OP-05 (content disclosure), OP-08 (key
substitution), OP-02 (false handshake answers), ID-04 (keys at rest).

- **Downgrade.**
  - Algorithms: the algorithm comes from the DID, and a pinned DID cannot change algorithm,
    so a server cannot downgrade one. Only a key link can, and that link is signed by the
    holder.
  - Suites: the suite comes from the channel's creation block, which the client pins. An
    operator who advertises only `mls` keeps channels from being created under a post-quantum
    suite, but cannot move an existing one. That is visible, as OP-03 already states.
- **Algorithm confusion.** No verifier tries an algorithm because an object names it.
  Section 1 rule 1 closes the class of attacks where a signature made for one algorithm is
  verified under another.
- **Migration timing.** A key link is only as strong as its weaker key at the moment it is
  checked. A holder who migrates after ed25519 falls can be raced by a forger. The fork rule
  makes the race visible but does not settle it. Step C has to happen early.
- **Composite rather than pure post-quantum first.** `ed25519+ml-dsa-65` is at least as
  strong as the stronger of the two, so adopting it cannot make an identity weaker than it is
  today, even if ML-DSA or its implementation has a flaw.
- **Size limits as denial of service.** Larger keys and signatures make bundles, receipts and
  records bigger. Size caps are checked before parsing, as `jig-core/src/bundle.rs` already
  does, and they rise only by the registered maxima.
- **Keys at rest.** The `.jigkey` envelope seals a seed of any length. A composite key is
  sealed as one seed from which both component keys are derived, or as two seeds in one
  envelope. The registration JEP says which.
- **Metadata.** A `k` DID carries the algorithm in the clear, so a holder's choice is
  visible. That is accepted, as the DID itself already is.

# Backwards Compatibility

- **`z` DIDs, `mls` channels and every existing signed object stay valid.** Nothing in this
  JEP changes how they are verified, except strict verification on the successors.
- **An old client meeting a `k` DID refuses it** (fail closed). In a channel with members on
  both forms, old clients cannot verify blocks from `k` members. So:
  - a client SHOULD be upgraded before its contacts migrate;
  - a server MAY refuse `k` DIDs until its ruleset says otherwise;
  - the handshake capability (section 3.3) tells a client in advance.
- **Old servers refuse channels created under a new suite** (JEP-0001: unknown suites are
  refused), and a federation contract under a new suite is refused by servers that cannot
  speak it.
- **The `ed25519:v1:` sketch in `src/crypto.md` is superseded.** That chapter is updated when
  this JEP is accepted.

# Reference Implementation

None yet. Step A touches `jig-core` (`did.rs`, `cose.rs`, `crypto.rs`, `request_auth.rs`,
`tls_binding.rs`, `admission_pow.rs`), `jig-pipeline` (`handshake.rs`, `ingest.rs`) and
`jig-mls` (`delivery.rs`, `member.rs`, `credential.rs`). Key generation in
`jig_core::crypto` is already the one sanctioned keygen path, and its comment says algorithm
changes belong there.

# Test Vectors

To be added with each step, under `jep/vectors/0013/`:
- `k` DIDs for each registered algorithm;
- COSE objects signed by each algorithm, including mismatched-`alg` cases that MUST be
  refused;
- a key link from a `z` DID to a composite `k` DID;
- the successors in section 3.3.

Suite vectors for a new MLS entry go in `repos/jig-spec/vectors/suites/`.

# LLM Influence

Drafted with an LLM coding assistant from a survey of the code on `main` (a740fa8) and the
public status of the candidate suites. It was reviewed by the author.

# Rejected Alternatives

- **Building a post-quantum suite or primitive in jig.** jig's crypto stays glue (section 6,
  criterion 5).
- **Putting the full public key in the DID.** An ML-DSA DID would run to thousands of
  characters, in every block, header, pin and name.
- **An algorithm prefix on key strings (`ed25519:v1:...`), as `crypto.md` sketched.** A key
  string is not what a verifier pins; the DID is. The algorithm belongs there.
- **Letting `mls` mean "any MLS ciphersuite the group chose".** A pinned channel could then be
  moved to a weaker ciphersuite, and the gate from #303 would have nothing fixed to check.
- **A protocol-version bump for post-quantum.** It would be a flag day. Registry entries and
  versioned successors let old and new coexist.
- **Adopting X-Wing at 0x004D now.** It is non-IANA and experimental, and it is
  expected to be superseded by the working group's suites. Channels pinned on it would then
  need a migration of their own.

# Copyright

This document is licensed under CC-BY-4.0.
