# Federation: verified naming and the channel contract

**Date:** 2026-10-18
**Author:** DJ + Claude (lane F of the
[v0.2-close plan](../plans/2026-10-18-v0.2-close-and-m3-start.md))
**Status:** Research pass done. Every choice marked **Proposed** waits for DJ. Nothing here
is built, and no implementation starts until DJ approves.
**Decisions it rests on:** D11, D12, D15, D19–D25 in the
[roadmap](../../ROADMAP.md#decisions-log), and phase 1's exit criterion: "a channel's
federation data contract is specified and two jig servers federate an encrypted channel
through it".
**JEP drafts:** [JEP-0004 Verified naming](../../../repos/jig-spec/jep/jep-0004-verified-naming.md)
and [JEP-0005 Channel federation contract](../../../repos/jig-spec/jep/jep-0005-channel-federation-contract.md).

## 1. Goal

Two things, so that v0.2 can meet exit criterion 5 without weakening criteria 1–3:

1. **Verified, pinned name lookups.** `jig dm alice@example.org` works, and neither a
   nameserver nor the user's own server can swap in another key without the client
   noticing (OP-08, NS-01, NS-02).
2. **A contract between two jig servers** under which a restricted MLS channel owned by
   server A has members whose home is server B, with no plaintext anywhere but the
   members' clients (D12, D24, D25).

Out of scope for v0.2, and placed in [section 9](#9-milestones): ruleset groups and
cross-registration, nameserver-led shared contracts, transparency logs, open federation
with servers nobody configured, moving a channel's ownership, and federating with servers
built differently from jig.

## 2. What exists today (verified 2026-10-18)

Paths are relative to `repos/`. Each line was checked against the code on `main` at
`d16f26a`.

### Server-to-server

- **Relayed blocks run the full write gate.** `ingest_peer_block`
  (`jig-server/src/v0_0_2_federation.rs:395`) calls `ingest` with
  `IngestSource::FederatedPeer`. That runs the author signature, admission (proof-of-work
  excepted), the kind allowlist, the channel checks, `authorize_block`, CID dedupe, the MLS
  gate and the server's own receipt. A peer's receipts are discarded.
- **Peers are listed and pinned.** `FederationPeer { url, expected_did, alias }`
  (`jig-config/src/v0_0_2_server.rs:311`). The dialer requires the JEP-0002 welcome to be
  signed by `expected_did`. The dialed side accepts a federation subscription only from a
  DID on its peer list (`v0_0_2_ws.rs:539`, `NOT_A_PEER`).
- **`ws://` peers are refused** at boot, at spawn and at every dial
  (`check_peer_transport`, `v0_0_2_federation.rs:55`), unless an antipattern flag is set.
- **Peer TLS is trusted through the peer's DID.** The dialer probes `/.well-known/jig`,
  accepts a CA-valid certificate or one whose BLAKE3 hash the DID signed (`tls_binding`,
  `jig-core/src/tls_binding.rs`). This pins the whole certificate, not the SPKI.
- **Encrypted and restricted channels do not federate,** in either direction
  (`DeliveryPolicy::federates`, `jig-pipeline/src/fanout.rs:74`;
  `v0_0_2_federation.rs:411-426`).
- **The link is pull-only, and each side must list the other.** A dials B, completes the
  handshake, then sends a federation `Subscribe` signed by A's server key. B streams its
  blocks to A. Blocks A pushes back over that socket are ignored (`v0_0_2_ws.rs:745`), and
  the `fed-hello` block it submits is refused unless an operator allows that kind. So A
  receives B's blocks only over A's own dial. The dialed side never authenticates the
  dialer in the handshake itself, only in the signed subscription.
- **Channels are identified by slug alone.** There is no owning server in the channel
  record. A peer's `channel-create` for a slug new to this server creates a local row owned
  by the peer's author. If the slug exists locally, the block is refused
  (`ChannelExists`). Each server is first-come per slug.
- **Replay and liveness.** A subscription carries a nonce and a ±30 s window. Relayed
  blocks have neither and are deduped by CID only. Reconnects wait a constant 5 s, with no
  exponential backoff. There is no per-peer quota; relayed blocks charge the author's
  token bucket.

**Two gaps the plan's fact list missed:**

1. **Orphan relayed posts.** A relayed `text-render` may name a channel this server has
   no row for (`requires_existing_channel` exempts it, `jig-pipeline/src/ingest.rs:731`).
   `authorize_block` then passes it, because no channel means no check
   (`authorize_write.rs:122`). It is stored with no gate a member could rely on.
2. **No policy means federate.** In fanout, a block with no channel policy is relayed to
   peers (`policy.is_none_or(|p| p.federates)`, `fanout.rs:281`).

Both fail open. Neither leaks restricted or encrypted content today, because those
channels always have a row. Both should fail closed before the contract work starts. That
is a small fix PR, not part of this design.

### Naming

- **The nameserver issues signed attestations.** `POST /v1/register` returns
  `{did, alias, ns_did, valid_from, valid_until, profile_ttl_seconds, sig}`
  (`jig-nameserver/src/v0_0_2_register.rs:29`). Validity is 90 days. The signature covers
  `serde_json::to_vec` of a `json!` map: no specified canonical encoding and no domain
  separator.
- **Proof of control is weak.** The DID signs the raw challenge hex string, with no domain
  separation and no binding to the alias or the nameserver (`register.rs:82`). A signature
  made for any other purpose over the same 64 hex characters would pass. This is AB-01's
  "proofs are not bound to an action or DID".
- **One suffix per nameserver.** `alias_suffix` is a config string, default `gigue.jig`.
  `.jig` is not a DNS top-level domain. There is no delegation of any kind.
- **The nameserver serves plaintext HTTP** (`server.rs:1572`).
- **The server's resolver verifies nothing** (`jig-pipeline/src/identity.rs:168-205`). It
  reads only `json["did"]`, asks every configured nameserver in order whatever the
  suffix, takes the first 2xx answer, and caches it for a fixed 300 s, ignoring
  `valid_until`. The alias is put into the URL path unescaped. Its only caller is the
  ingest check on blocks carrying a `nickname`, and first-party clients never set one. So
  today the resolver guards nothing anyone uses.
- **Clients take only DIDs and local contacts.** `resolve_who`
  (`jig-cli/src/cmd/channel.rs:301`) accepts a `did:jig:` or a unique `[contacts]` name.
  `jig dm` and `jig channel add` use it. `jig ns resolve` and `jig init --request-alias`
  call the nameserver without checking the signature. The client pins server DIDs, suites
  and creation blocks (`jig-client/src/pins.rs`), but no names. **This is the only reason
  a lying nameserver cannot reach E2EE today.** The design keeps that property until
  verified, pinned lookups replace it.

### MLS (what the contract has to carry)

- The server is a validating delivery service: an openmls `PublicGroup` per channel,
  commits as `PublicMessage`, exact epoch match, and the commit must do exactly what the
  block says (`jig-mls/src/delivery.rs:125`). Ordering is a compare-and-swap on the epoch,
  atomic with the membership change (`jig-pipeline/src/persist.rs:888`).
- Key packages live on the DID's home server: `POST`/`GET /api/v1/mls/key-packages`,
  validated as self-signed and bound to the DID (`jig-server/src/v0_0_2_mls.rs`).
- Only clients commit. The owner adds; anyone may external-join an open channel.

## 3. Prior art

Sources and how each fact was checked are in [Appendix A](#appendix-a-sources).

### 3.1 Who owns a multi-server room

| System | Owner | How remote members write | Who orders | If the owner is down or hostile | Lesson for jig |
| --- | --- | --- | --- | --- | --- |
| **XMPP MUC** (XEP-0045) | The room's MUC service, one domain | The member's server carries its stanzas to the room over s2s | The room service | The room is gone; there is no replica. A hostile service can censor and read (no E2EE by default) | One owner is simple and well understood. Liveness is the price |
| **XMPP MIX** (XEP-0369, experimental since 2020) | The channel's service | The member's own server subscribes on its behalf (PubSub) | The channel service | Same as MUC | Relaying through the home server is a known pattern. MIX has stalled for six years |
| **IRC** | Nobody: every server on a spanning tree holds the full state | Any server | Nobody: a message crosses each link once | Netsplits. On rejoin, merged modes allowed "split riding" takeovers, and nick collisions killed both users | Without an owner, merge rules become the attack surface |
| **Matrix** | Nobody: every participating homeserver keeps the event graph | Any participating server | Converges by state resolution v2 | The 2025 "state reset" CVEs (CVE-2025-49090 and one other) let a malicious server roll back power levels and membership. Fixed in room v12 (Aug 2025) with state-res v2.1, creators with infinite power, and the room ID as the create event's hash | Multi-homing costs a decade of state-resolution bugs and room upgrades. MLS on Matrix is still unshipped research |
| **ActivityPub groups** (FEP-1b12) | The Group actor's server | Members send activities to the group's inbox | The group's server, which re-broadcasts them wrapped in a signed `Announce` | Down: no distribution. Hostile: can censor, cannot forge (receivers can re-fetch originals) | Owner relay plus author signatures gives "can censor, cannot forge", which is what jig wants |
| **IETF MIMI** (draft-ietf-mimi-protocol-06, Apr 2026; no RFC) | One **hub** per room; every other provider is a **follower** | Clients submit to their own provider, which forwards to the hub (`/update`, `/submitMessage`) | The hub is the MLS delivery service. It refuses stale epochs (`wrongEpoch`) and fans out to followers (`/notify`) in order | Not specified. Moving the hub is listed as future work | The closest match to jig: MLS, one owner, follower relay, the hub validating commits |

**What MIMI does that jig should copy, and what it lacks:**

- **Hub as validating DS.** "The Hub is the arbiter that decides if a state change is
  valid." Only clients commit. Room state (participants, roles, policy) rides in MLS so
  that clients agree on it through the group context. jig already puts membership in
  signed blocks that the server checks against the MLS commit, which is the same idea.
- **Key packages are fetched through the hub.** `POST /keyMaterial/{user}` goes to the
  hub, which routes it to the target's provider and remembers where each key package came
  from, so the Welcome goes back the right way. The target's provider releases key
  packages only under the target's **consent** (request, grant, revoke, cancel), and that
  consent exchange runs provider to provider, never through the hub.
- **Addressing.** `mimi://provider/u/alice`, `/r/room`, `/d/device`. The provider domain
  is the authority.
- **What MIMI lacks.** Provider-to-provider authentication is mTLS against WebPKI domain
  names. The credential model is still a TODO. Identity binding is X.509 or SD-JWT in an
  individual draft. Nothing in MIMI protects a user from their own provider substituting
  keys; it trusts providers, while jig does not (D11). MIMI says nothing about a hostile
  hub beyond what MLS itself gives.

### 3.2 Who says which key a name has

| System | Authority for a name | What it detects | Lesson for jig |
| --- | --- | --- | --- |
| **DNSSEC** | Hierarchical delegation: the parent signs the child's key | Forgery by anyone outside the chain. **Not** equivocation: a parent can silently sign an alternative | Delegation answers "who is authoritative for this suffix". It does nothing against the authority lying |
| **Certificate Transparency** | CAs, with append-only public logs | Misissuance, after the fact. Gossip between clients was never standardised; split views are resisted by multiple logs and witnesses | Detection, not prevention, is achievable and useful. Requiring evidence (an SCT) at use time is what makes logs matter |
| **Key Transparency** (draft-ietf-keytrans-protocol-04, Apr 2026; deployed at WhatsApp with a Cloudflare co-signing auditor, and in Apple's Contact Key Verification) | The provider, with a verifiable map and auditors | The provider showing different keys to different users | The target state for a ruleset group (v0.3+). Too heavy for v0.2 |
| **CONIKS** (2015) | Each provider, with signed tree roots chained per epoch | Non-equivocation; users monitor their own bindings | KEYTRANS descends from it |
| **Keybase** | Per-user signed sigchains, a global Merkle root anchored externally | Forks of a user's history | A user-signed chain of changes makes rotation self-authenticating. jig's `rotate` is already signed by both keys |
| **ATProto handles** | DNS TXT `_atproto.<handle>` or `https://<handle>/.well-known/atproto-did` gives the DID, **and** the DID document must list the handle back | A handle claimed without the DID's agreement | Bidirectional binding: the name's authority says "this DID", and the DID says "this name" |
| **Signal / WhatsApp safety numbers** | The provider | Nothing automatically; the user compares numbers | Trust on first use plus loud change warnings is the floor everyone ships |

### 3.3 What the survey settles

1. **One owner per channel is the mainstream answer and fits D24.** Every system with E2EE
   group state (MIMI, and Matrix's own move to creator privilege in v12) is moving toward
   a single arbiter. Multi-homing is rejected (section 6).
2. **Followers relay for their own users.** MIMI, MIX and ActivityPub all route a remote
   member's write through the member's own server.
3. **The owner is the MLS delivery service.** That is jig's single-server rule, extended.
4. **Fetch key packages through the owner, under the target's consent.**
5. **Names: delegation tells you whom to ask, transparency tells you whether they lied.**
   v0.2 needs the first, plus client pinning and retained evidence. The second is v0.3+.
6. **Nothing in the prior art protects against a hostile owner's censorship.** MLS
   protects confidentiality and signatures protect authenticity. Censorship and liveness
   are accepted costs everywhere (OP-06).

## 4. Naming design (JEP-0004)

### 4.1 What a name is

**Proposed.** A name is `alias@suffix`.

- The alias is 1–24 characters from `[A-Za-z0-9_-]`, as today, compared case-insensitively
  and stored lowercase.
- The **suffix** is a domain name a nameserver is authoritative for. A suffix is **not**
  a server: `alice@example.org` says nothing about which server Alice uses. The current
  federation chapter's `user@server` model is dropped.

A name maps to exactly one DID at a time, through an **attestation** signed by a
nameserver authoritative for the suffix. The DID is the identity. The name is a claim
about it (OP-08).

### 4.2 Who is authoritative for a suffix

This is the real question. A signed attestation verifies the same whoever fetches it, so
"who resolves" matters less than "whose signature counts for this suffix".

| Option | How a resolver learns the nameserver DIDs for `example.org` | For | Against |
| --- | --- | --- | --- |
| **A. DNS-anchored delegation** | `https://example.org/.well-known/jig-ns-delegation`, served under a CA-valid certificate, lists the nameserver DIDs (and optionally a DNS TXT record `_jig-ns.example.org`) | Works on day one with no new root. Whoever controls the domain controls the suffix, which is what users expect. Same shape as ATProto | Trusts DNS and the WebPKI. A domain owner, or whoever seizes the domain, can switch nameservers silently. Pinning and retention (4.4, 4.5) catch the switch only for names already pinned |
| **B. Local configuration only** | The client's and server's config maps suffix → nameserver DIDs | No outside trust at all. Fits small and private deployments | Does not scale. Every client must be configured before first use |
| **C. Ruleset-group delegation** | The ruleset group's nameservers sign a delegation, at a threshold the ruleset fixes, and an anchor publishes the initial one (D19, D21) | No single party, domain registrar included, can redirect a suffix. Fits high-sec groups and NS-03 | Needs ruleset groups, which do not exist yet. It is the v0.3 work |

**Decided (DJ, 2026-10-18): A, with B as an override.** Configuration always wins over
discovery, so a private deployment never needs DNS.

**A and C are one mechanism (DJ).** A ruleset group is not a separate entity. It is what
forms when nameservers and servers share data contracts. So both A and C produce the same
artefact, a **suffix delegation**: a signed statement that a set of authority DIDs speaks
for a suffix. They differ only in what roots the claim:

| Root | Who can redirect the suffix | Visible to |
| --- | --- | --- |
| `config` (B) | The configuring party, locally | Only that party. A config override MUST NOT be asserted to anyone else |
| `dns` (A) | One controller: the domain owner, or whoever controls the registrar, DNS or CA | Everyone |
| `contract` (C) | Only a threshold of the contract's parties; no single party | Parties to the contract |

The shared format holds, but the security does not: `dns` imports one controller, and
`contract` has none. A "domain claim" therefore costs DNS trust; it is not free.

**Precedence: `config` > `contract` > `dns`.** A party to a contract that claims a suffix
uses the contract. Everyone else sees DNS. A disagreement between a contract's delegation
and DNS for the same suffix is surfaced, never silently resolved.

**A server with no nameserver is its own authority.** Nameservers are opt-in, so a server
MAY attest names under its own suffix with its own DID. It is then simply the delegation's
only authority. Under A the suffix is a domain the server controls; under B it is whatever
its operator configures.

**Duplicates and impersonation (DJ's question).** Where no shared root exists, uniqueness
cannot be enforced, only scoped and detected. This is Zooko's triangle: a name cannot be
global, secure and human-meaningful without an anchor. DNS or a contract is that anchor.

1. **Across isolated servers.** Two servers can each configure the suffix `acme`, and
   nothing global stops them. No protocol rule can prevent that without a central
   registry, which D19 rules out. Instead, **a name means (alias, suffix, root)**:
   - `alice@acme` resolved under my config is a different name from `alice@acme` under
     yours.
   - A client shows a name bare only when its own resolver verifies it under its own root.
   - Otherwise the client shows the name marked as unverified, with the DID's
     fingerprint.

   DNS-rooted suffixes cannot collide, because DNS is unique. Only config-rooted suffixes
   can, and they are local by definition.
2. **Within one server.** The server is the only authority for its suffix, so it can bind
   a name to its own key. Nobody can **prevent** a lone authority from lying. It can be
   **detected**: the attestation is signed, clients pin (4.4), and retained evidence
   (4.5) makes two conflicting bindings a proof. Prevention needs a second, independent
   signer, which is the threshold of a `contract` root.
3. **Across a federation link.** Here a data contract can prevent the collision:
   - **Each server's signed peer policy (5.6) declares the suffixes it attests and their
     root.**
   - A `contract-offer` is refused with `SUFFIX_CONFLICT` when two parties claim one
     suffix under different authorities.
   - A name never crosses a link as identity. Blocks carry DIDs, and a name is a hint the
     receiver re-verifies under its own root (rule 1).

   So a federated isolated server cannot impersonate a peer's names. At worst its names
   show as unverified on the peer.

**`gigue.jig`.** `.jig` is not a DNS name, so it can only be config-rooted (B) or
contract-rooted. **Open:** pick a real domain as the reference default, or keep `gigue.jig`
and accept that it is local.

The delegation document is signed by every authority DID it lists. A CA or web host that
serves a forged list without those keys produces an unsigned or wrongly signed document.
That does not stop the domain owner from listing a new nameserver, which is why 4.4 pins.

### 4.3 Who resolves and who verifies

**Proposed.**

- **Anyone may fetch; whoever acts on a binding verifies it.** A client that is about to
  encrypt to a name (`jig dm`, `jig channel add`) verifies the attestation itself. It
  never acts on its server's word. A server verifies before it uses a binding, for
  example in the `nickname` check.
- **Verification** means all of the following:
  1. The suffix's delegation, from config or discovery, lists the signing nameserver's
     DID.
  2. The signature verifies under that DID over the canonical encoding (4.6).
  3. `valid_from ≤ now < valid_until` on the verifier's clock (TM-01).
  4. The alias in the attestation equals the name asked for, after normalisation.
- **Fetching goes through the client's own server or directly to the nameserver.** Either
  way the result is the same, because the attestation verifies on its own. Going through
  the server hides the client's address from the nameserver. Going direct hides the lookup
  from the server.
- **Caches never outlive `valid_until`,** and a resolver re-verifies on every cache hit.
- **More than one nameserver for a suffix means cross-checking, not failover.** A resolver
  that asks two nameservers and gets two different DIDs refuses and keeps both
  attestations, which together prove that one of the nameservers lied. In v0.2 asking one
  is enough. A ruleset group's threshold rule (v0.3) makes asking several mandatory.

### 4.4 Pinning names on the client (OP-08)

**Proposed.** The client keeps a name pin store beside its server pins, holding for each
name the DID, the attestation and the nameserver DID.

- **First use.** The client shows the DID's fingerprint and the nameserver that vouched
  for it, then pins. A non-interactive `jig dm alice@example.org` pins and prints the
  fingerprint.
- **A change is accepted automatically only with proof from the old key.** The nameserver
  already requires both keys to sign a rotation (`/v1/rotate`). The nameserver keeps that
  rotation statement and serves it with the new attestation. A client that holds the old
  pin and sees a valid rotation signed by the old DID moves the pin and says so.
- **Any other change is refused until the holder accepts it.** That covers expiry
  followed by re-registration to another DID, a different nameserver, and a nameserver
  that simply answers differently. It is surfaced the way a changed server DID is, with
  both fingerprints. How the holder accepts it is `jig trust`'s job, which lane L7 owns.
  F names the cases and L7 owns the command.
- **`jig dm` and `jig channel add` accept a name only through this path.** `[contacts]`
  stays: a contact is a pin the holder wrote themselves.

**Push-back on a likely assumption:** "the nameserver signs it, so it is safe". A signed
attestation proves which nameserver lied, not that it did not. Without client pins, a
nameserver (or whoever controls the suffix's domain) can bind `alice@example.org` to its
own key at the moment Bob first types it, and Bob's client would encrypt to that key. Pins
narrow this to first contact. Retained evidence (4.5) makes the lie provable. Only
transparency or out-of-band comparison (v0.3) closes first contact.

### 4.5 Retaining evidence (NS-02)

**Proposed.** Every resolver, client or server, keeps the attestations it acted on, for at
least their validity window plus a grace period. Two valid attestations binding one alias
to different DIDs with overlapping windows are a complete proof of equivocation. In v0.2
the evidence is local and exportable (`jig ns evidence`, a name to settle later). Feeding
it to a tribunal or a transparency log is v0.3 (lane R).

### 4.6 Attestation and registration wire changes

**Proposed**, so that 4.3 and 4.5 can work at all:

- **Canonical, domain-separated signatures.** An attestation is signed over the labelled
  BLAKE3 hash jig uses elsewhere (`hash_labeled_parts`): (`domain`,
  `jig-alias-attestation-v1`), then `did`, `alias`, `ns_did`, `valid_from`, `valid_until`,
  in that order. `profile_ttl_seconds` either joins that list or leaves the signed body.
  JSON map order stops mattering.
- **Proof of control binds the action.** The DID signs (`domain`,
  `jig-alias-register-v1`), (`ns_did`), (`alias`), (`challenge`). The same applies to
  renew and rotate, each with its own domain. This closes AB-01 for this flow.
- **Rotation statements are kept and served** with the attestation that resulted from
  them (4.4).
- **The nameserver serves TLS**, CA-issued or DID-bound like the server (#95). Plaintext
  HTTP stays only behind an antipattern flag. The attestation's signature does not depend
  on the transport, but discovery under option A does.

### 4.7 Where a DID lives: the home record

The contract needs to know which server hosts a DID's key packages and inbox. A DID is a
key and carries no location.

| Option | Who asserts "Alice's home is server B" | Against |
| --- | --- | --- |
| **A. The attestation carries it** | The nameserver | The nameserver can misdirect. Key packages are self-signed, so the harm is denial of service, but it couples naming to routing |
| **B. A home record signed by the DID** | Alice's own key: `{did, homes: [{server_did, url}], seq, sig}` | Alice's client must publish it. A stale record misroutes until it is replaced |
| **C. Ask around** | Nobody in particular | Leaks who is looking for whom, and there is no answer when nobody knows |

**Recommendation: B.** The record is self-certifying, so it can be served by Alice's
server, by any nameserver next to her attestation, or embedded in a `member-add` block.
The highest `seq` wins. It also keeps routing out of the nameserver's power. **Open for
DJ:** whether one DID may name several home servers in v0.2. The recommendation is that
the type allows a list and v0.2 uses the first entry.

## 5. The channel contract (JEP-0005)

### 5.1 Topology: owner plus followers

**Proposed (D24 made concrete).**

- The **owning server** (MIMI's hub) holds the channel's authoritative state: the creation
  block, membership, and the MLS public group. It orders every block, validates every
  commit, and fans accepted blocks out to followers.
- A **follower** is a server with at least one member of the channel among its users. It
  relays its users' writes to the owner and delivers the owner's ordered stream to its
  users.
- Every server, owner or follower, re-verifies each block's author signature and runs its
  own gates (OP-09 as today). A follower also tracks the MLS public group from the stream
  and refuses to deliver a commit that does not validate. It does not have to trust the
  owner to be correct, only to be live.

### 5.2 How a remote member writes

| Option | Path | For | Against |
| --- | --- | --- | --- |
| **A. Relay through the home server** (MIMI, MIX, ActivityPub) | client → home → owner | The home server stays the enforcement boundary for its own users: admission, proof-of-work, rate limits, reputation reports (D23). It queues for offline clients. The owner sees one accountable peer per server, not every client (AB-03). The client's address stays hidden from the owner | Two hops. The home server sees channel metadata. The home server can censor its own users, which it can already do to everything they send |
| **B. The client connects to the owner directly** | client → owner | DIDs are server-independent, so a jig client could simply authenticate to the owner. No server-to-server write path at all | The owner must admit and rate-limit strangers. Every client needs a link to every owner. Offline delivery and reputation reporting have no home. It is not federation in D23's sense |
| **C. Multi-homed** (Matrix, IRC) | client → any participating server | No single point of failure | Rejected: it needs a state-resolution algorithm, and the MLS delivery service needs one linear epoch history. This is the Matrix state-reset class, plus MLS forks |

**Recommendation: A**, with B allowed later as a client fallback when the home server is
down. **Open for DJ.**

### 5.3 The MLS delivery service across servers

**Proposed.**

- **The owner is the delivery service.** It applies the current single-server rules
  unchanged: an exact epoch match, a commit that does exactly what its block says, and a
  compare-and-swap on the epoch. Only clients commit.
- **The owner signs the order, using L7's `ingest` record (decided by DJ, 2026-10-18).**
  - Every block gets a record signed by the channel's home server:
    `{channel_id, seq, ingest_hlc, block_cid, prev}`. Here the home server is the owner.
  - The record travels with the block. Relaying servers pass it through unchanged and
    never re-sign it.
  - Authored blocks carry `seen`, the hash of the latest record their author verified.
  - JEP-0002 (L7) defines the record. This design only relies on it.
  - Followers keep the chain. Two followers that compare heads detect an owner showing them
    different histories, and a gap in `seq` shows an omission. `seen` adds detection by
    authors: a block citing a record the follower never received shows withholding (OP-06:
    detection, not prevention).
- **Followers validate too** (5.1), so a buggy or hostile owner cannot wedge remote
  members with a commit that will not apply.
- **The owner's server key goes into the group's `external_senders`** only if the owner
  needs to propose removals (for example, of a member whose home server left the
  contract). The recommendation for v0.2 is no external senders: members commit
  everything, as today.

### 5.4 Fetching key packages across servers

**Proposed.** Bob's client, adding Alice (home: server B) to channel X (owner: A),
fetches a key package **through the owner**: Bob's client → Bob's home server → A → B.

- **Through the owner,** because A must be a peer of every follower anyway. Routing
  direct from home to home would need every pair of servers to peer (n² links).
- **B releases a key package only under Alice's consent policy.** In v0.2 the policy is
  coarse: anyone, members of servers I share a channel with, or contacts only. MIMI's
  per-requester consent exchange is v0.3.
- **The request is signed by the requester's DID** and names the channel, so B can apply
  the policy and log the request.
- **The key package is self-signed by Alice's DID,** so A and the relays cannot
  substitute one (D2 / decision 1 of M2). They can only withhold.

### 5.5 Offer, accept and refuse on the wire

**Proposed.**

1. **The channel-create block names its owner.** New field `owner_server`, the owning
   server's DID. The suite, the membership rule and the protocol version are already in
   it. The creation block is the contract's terms, and the suite is fixed there for the
   channel's life (D12).
2. **A follower joins when a `member-add` names a DID whose home is a server not yet
   party.** The owner sends that server a `contract-offer`, signed by the owner, carrying
   the creation block, the current sequence head and the owner's signed peer policy
   (5.6).
3. **The server answers with a `contract-accept` or a `contract-refuse`, signed by its
   DID.**
   - An accept cites the creation block's CID and its own policy's hash, and states that
     it implements the suite and will enforce the membership rule.
   - A refusal carries a code: `UNSUPPORTED_SUITE`, `UNSUPPORTED_VERSION`,
     `POLICY_REFUSED`, `NOT_A_PEER` or `SUFFIX_CONFLICT` (4.2). There is no fallback
     suite and no plaintext relay.
4. **The accept is a block in the channel's log,** so every member can see which servers
   carry the channel, and a server that breaks the contract has signed the evidence
   (whitepaper 9.1.5).
5. **Leaving.** When a follower's last member leaves, the follower sends a signed
   `contract-end`, or the owner ends it. Members commit the removal of any leaves that
   remain.

### 5.6 Signed peer policy

**Proposed.** A server publishes, signed by its DID, a policy document: the protocol
versions, the suites it hosts, the block kinds it relays, the per-peer quotas it applies,
the peers it federates with (DIDs, not URLs), and the name suffixes it attests with their
roots (4.2). `/.well-known/jig` already carries most
of these fields unsigned. Contract messages cite the policy's hash, so a server that
changes its policy mid-contract leaves evidence. This is the roadmap's "signed peer
policy" item.

### 5.7 Who may federate (v0.2)

**Proposed: configured peers only.** Today both sides must list each other, and the
contract keeps that: an offer from a server that is not on the list is refused with
`NOT_A_PEER`. Open federation, meaning accepting an offer from a stranger, waits for
reputation and proof-of-work between servers (lane R, D26).

### 5.8 The owner fails or turns hostile

| Owner behaviour | Effect | v0.2 answer |
| --- | --- | --- |
| Down | No new blocks; followers serve history they hold | Accepted, like an XMPP MUC. Clients say the channel is unreachable |
| Censors a member | That member's writes vanish | Detectable only by the member. Accepted (OP-06) |
| Shows followers different histories | Fork | Detected by comparing signed sequence heads (5.3) |
| Reads content | Cannot: MLS | Exit criterion 2 holds |
| Forges a block | Cannot: author signatures | OP-09 |
| Adds a key the owner controls | Cannot unilaterally: only the channel owner's DID may add, and the add is a client-made commit naming the DID | Holds while the channel owner (a DID) and the owning server are different parties. **The channel-owner DID and the owning server can collude**, which is the same trust the single-server channel already has |

**Open for DJ:** whether members can move a channel to a new owner. The recommendation is
not in v0.2: members create a new channel. A signed handover by the channel-owner DID is
v0.3.

## 6. Addressing

**Proposed.**

| Thing | Identifier | Hints (not identity) |
| --- | --- | --- |
| Server | its DID | URL, from config, a home record or `/.well-known/jig` |
| User | their DID | name (`alias@suffix`), home record |
| Channel | `(owner_server DID, channel id)`, where the id is the CID of the `channel-create` block | slug, unique only per owner |
| Device | out of scope: one DID, one device, until lane I | |

A URI form for links: `jig:<owner-server-did>/<channel-cid>`, with the slug as an optional
display parameter. **Consequence:** today's tables are keyed by slug and are first-come
per server. A follower that has its own `#ops` and joins A's `#ops` must keep both, so
remote channels are keyed by owner and CID. That is a schema change in the server, and the
largest single piece of build work in F2.

## 7. `federation.md`: keep, rewrite or drop

**Proposed disposition.** The rewrite lands in F2's implementation PR. Until then the
chapter needs a status banner saying that most of it is unbuilt. Banners belong to lane
L1, so F asks L1 to add one now.

| Requirement today | Disposition |
| --- | --- |
| DNS SRV `_jig._tcp` discovery, MUST | **Drop to MAY.** Peers are configured by DID plus URL, and URLs come from config, home records or `/.well-known/jig` |
| `/.well-known/jig` "HTTP, not HTTPS" | **Drop.** It is served over TLS, and the DID-bound TLS binding lives there (#95) |
| mTLS with X.509 client certificates | **Rewrite:** DID-bound TLS, plus a mutual JEP-0002 handshake in both directions (lane L7 owns the handshake) |
| Server signs every federation payload in a `from_server`/`to_server`/nonce envelope | **Rewrite.** Blocks are author-signed and CID-addressed. Contract messages and `ingest` records are server-signed. The handshake binds the connection. No second envelope |
| Relayed blocks: full gate, no persisting on a peer's word, receipts are evidence, configured pinned peers only | **Keep** (built, #90) |
| Nonce and ±10 min window on every message | **Rewrite:** the nonce and window apply to the handshake and subscription (built, ±30 s). Blocks are deduped by CID |
| Explicit version negotiation, no silent downgrade | **Keep** |
| `user@server` routing | **Drop.** Users are DIDs; names are `alias@suffix` and say nothing about servers |
| Exponential backoff with jitter, circuit breaker, MUST | **Keep as SHOULD** without the fixed numbers or library advice (today: a constant 5 s) |
| Rate limiting at ingress | **Rewrite:** per-peer quotas in the signed peer policy, plus the author's own bucket (built) |
| Receipt exchange for billing | **Rewrite:** receipts are evidence about a peer, verified by replay where possible. Encrypted blocks have sealed receipts and nothing to replay. No billing |
| Reputation tiers (`verified`, `high_sec`, …) | **Drop:** superseded by D21. Reputation is one number per ruleset, and lane R owns it |
| Metadata minimisation, fail closed on unknown critical fields, minimal logging | **Keep** |
| Examples (`did:jig:server-b.com`, Python) | **Drop:** `did:jig` is a key |

## 8. Threat register rows this touches

Updated in the implementation PRs, not here.

| Row | Change |
| --- | --- |
| OP-06 | Owner-signed sequence chain: omissions and forks across followers become detectable |
| OP-08 | Client name pins, and change acceptance only with a rotation signed by the old key |
| OP-09 | Contract accept and refuse; channels keyed by owner and CID; the orphan-post and no-policy gaps closed |
| NS-01 | Suffix delegation, verification by whoever acts, caching bounded by validity |
| NS-02 | Resolvers retain attestations, and conflicting answers become proof |
| NS-03 | Unchanged in v0.2; ruleset-group threshold delegation in v0.3 |
| AB-01 | Domain-separated, alias-bound proof of control |
| AB-03 | Per-peer quotas; relayed writes attributable to the relaying server |
| PV-01, OP-04 | Unchanged claim (none). Follower relay adds the home server as an observer of channel metadata, which is stated |

## 9. Milestones

| Milestone | Ships in | Contents | Depends on |
| --- | --- | --- | --- |
| **F0** | now | This design and the two JEP drafts. L1 adds a banner to `federation.md`. A small PR makes the orphan-post and no-policy paths fail closed | nothing |
| **F1: verified names** | v0.2.x | Canonical attestation and proof encodings (4.6); nameserver TLS; suffix delegation by config and `.well-known` (4.2 A+B); verification in the client and the server's resolver (4.3); client name pins and the change rule (4.4); retained attestations (4.5); `jig dm`/`channel add` accept names; home records (4.7) | L7 for `jig trust` UX; L6 for nameserver code |
| **F2: the contract between two jig servers** | v0.2.x, gate G3 | Channels keyed by owner and CID (6); `owner_server` in the creation block; offer, accept, refuse and end (5.5); signed peer policy (5.6); relay through the home server (5.2); owner sequencing with a signed chain, and follower validation (5.3); key packages through the owner under consent (5.4); restricted MLS channels federate between configured peers; the `federation.md` rewrite | **L7's mutual server-to-server handshake**; F1's home records |
| **F3** | v0.3+ | Ruleset-group delegation with thresholds (4.2 C); replicated registry and transparency log (NS-02, NS-03, with lane R); nameserver-led contract templates (D12); MIMI-style consent; ownership handover; open federation with reputation; interop with other implementations by contract | lane R; ruleset groups |

**Exit criterion 5 is met at the end of F2.**

## 10. Coordination

- **L7 (handshake, D11).** L7 owns the server-to-server handshake. F needs three things
  from it:
  1. The dialed side authenticates the dialer's DID in the handshake, not only in a later
     subscription.
  2. One authenticated connection carries traffic both ways, so the owner can push to a
     follower and the follower can submit to the owner.
  3. `jig trust` handles name-pin changes as well as server-pin changes.

  F owns every frame above the handshake (contract messages, relay-submit, key-package
  requests). The `ingest` record is L7's.
- **L6 (nameserver sweep).** F claims **only the `v0_0_2_*` alias flow** (register,
  resolve, renew, rotate), which F1 changes in place. F claims **none** of the legacy
  modules. In particular:
  - legacy `federation` and `discovery` resolve remote handles through SRV with no
    verification, which is the NS-01 hazard itself;
  - `pow` prices identities linearly (AB-05), and D26 wants a new design;
  - `transparency` is a single-nameserver log that the v0.3 group log will not reuse
    as is.

  Lane R may want `pow` or `transparency` as reference, and git history keeps them. The
  debug `/v1/handles` route is L6's call.
- **R (reputation, PoW, tribunals).** R builds on 4.5 (retained evidence), 4.2 C
  (ruleset-group delegation) and 5.7 (open federation).
- **I (identity lifecycle).** Home records (4.7) and rotation statements (4.4) are inputs
  to multi-device and key rotation.

## 11. Questions for DJ, in the order they will be asked

1. ~~Suffix authority (4.2)~~ **Decided:** A with a B override; A and C are one delegation
   mechanism with different roots; servers without a nameserver are their own authority;
   suffix conflicts across a federation link refuse the contract. Still open: the
   reference default suffix.
2. Remote writes (5.2): relay through the home server?
3. Name-pin changes (4.4): automatic only with a rotation signed by the old key, and
   refused otherwise?
4. Home records (4.7): signed by the DID, not the nameserver?
5. Key packages (5.4): through the owner, under a coarse consent policy in v0.2?
6. Owner failure and handover (5.8): accept liveness loss in v0.2, no handover?
7. Who may federate (5.7): configured peers only in v0.2?
8. `federation.md` (7): this disposition?

## Appendix A: sources

How each was checked: **[src]** means the source file was read; **[search]** means it was
confirmed from search results only; **[recall]** means it is from memory and unverified.

- MIMI protocol, editor's copy and draft-ietf-mimi-protocol-06 (25 Apr 2026) [src]:
  <https://www.ietf.org/archive/id/draft-ietf-mimi-protocol-06.html>
- MIMI architecture, draft-ietf-mimi-arch-02 (expired) [src]:
  <https://datatracker.ietf.org/doc/draft-ietf-mimi-arch/>
- MIMI room policy, draft-ietf-mimi-room-policy-04 (Jul 2026) [src]
- MIMI identity, draft-mahy-mimi-identity-05 (individual draft) [search]:
  <https://www.ietf.org/archive/id/draft-mahy-mimi-identity-05.html>
- Matrix room version 12 [src]:
  <https://github.com/matrix-org/matrix-spec/blob/main/content/rooms/v12.md>.
  CVE-2025-49090 [search]: <https://security-tracker.debian.org/tracker/CVE-2025-49090>
- XEP-0045, XEP-0369, XEP-0384, XEP-0220, XEP-0178 [src, from the xsf/xeps repository]
- FEP-1b12 [search]: <https://socialhub.activitypub.rocks/t/fep-1b12-group-federation/2724>
- KEYTRANS, draft-ietf-keytrans-protocol-04 [search]:
  <https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/>.
  WhatsApp and Cloudflare: <https://blog.cloudflare.com/key-transparency>. Apple:
  <https://security.apple.com/blog/imessage-contact-key-verification/>
- ATProto handles [search]: <https://atproto.com/specs/handle>
- DNSSEC, CONIKS, Keybase, IRC [recall]
