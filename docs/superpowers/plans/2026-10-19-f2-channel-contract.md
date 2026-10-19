# F2: The Channel Contract Between Two jig Servers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** phase 1's exit criterion 5: "a channel's federation data contract is specified and two
jig servers federate an encrypted channel through it." A restricted MLS channel that server A
sequences is shared with server B under a grant. B's clients read and write it through B. Both
servers check everything, and no plaintext exists anywhere except on the members' clients.

**Architecture:**
- **Channels are keyed by `channel_id`**, the CID of their `channel-create` block. A slug is a
  display name, unique only per sequencer (JEP-0005 rule 1). This is the largest piece of work,
  and it goes first.
- **The creation block carries the terms:** `sequencer`, the suite, the membership rule and
  co-owners. **Authority is role-based:** `role-assign` and `role-unassign` blocks, checked at
  the block's position in the `ingest` chain (rule 7b).
- **`jig_core::contract` holds the signed contract messages**: offer, accept, refuse and end,
  as COSE_Sign1 objects over deterministic CBOR (rule 0). It is pure code, as `jig_core::naming`
  is for F1.
- **The owner is the delivery service.** It orders blocks, signs L7's `ingest` records and
  validates commits. Followers verify the author, the record, the chain and the MLS state
  (rule 22a). They relay their clients' writes to the owner within their grant, and the owner
  runs its full gate on each one (rule 15).
- **Key packages come from custodians** under a release policy the DID signed (rule 21). The
  sequencer takes no part.
- **Every server-to-server frame runs over L7's mutual handshake** (D11 slice 8): one
  authenticated connection, carrying traffic both ways.

**Spec:**
- [JEP-0005](../../../repos/jig-spec/jep/jep-0005-channel-federation-contract.md); rule numbers
  below are JEP-0005's.
- Design: [federation naming and contract](../specs/2026-10-18-federation-naming-and-contract-design.md),
  sections 5, 6, 7 and 9.
- **Aligned with L7's build plan** (`2026-10-18-d11-handshake-completion.md`). F2 relies on
  these L7 slices and does not rebuild them:
  - 4a/4b, `ingest` records: the chain, `seq`/`prev`, the sequencer's signature;
  - 5, `seen` and head gossip: fork and withholding detection;
  - 7, the manifest log: `server-manifest`, which F2 extends into the peer policy;
  - 8, the mutual server-to-server handshake;
  - 10, `sequencer-set`: the kind and the expected-sequencer rule. F2 builds the contract half
    of a move.
- JEP-0011 (lane C) defines `channel-policy`, `block-install`, `policy-approval` and
  `policy-withdrawn`. F2 issues approvals on a sequencer move (rule 11b) and does not redefine
  them.

**What exists today (main, 2026-10-19):**
- `channels.id` is already the creation block's CID, and `memberships` are keyed by it.
- Everything else is keyed by slug:
  - `blocks.channel_id` stores the slug;
  - `mls_groups` is keyed by slug;
  - the fanout scope is `Channel(slug)`;
  - every store lookup is by slug;
  - every REST and WSS route takes `{slug}`.

  That is about 780 `slug` hits outside tests.
- Federation is WSS push between configured peers. The dialer pins the peer's welcome DID. The
  dialed side authenticates the dialer only through a signed federation subscribe and the peer
  list.
- Only open, unencrypted channels federate (`DeliveryPolicy.federates`).
- Roles are the strings `owner` and `member`, and `require_owner` hard-codes "only the owner
  adds".
- There is no sequencer, contract, share, grant or role-block code, and no
  `subscription_cursors` reader.

**Compatibility:**
- Slice 0 migrates existing databases in place (`blocks.channel_id` and `mls_groups`, slug →
  CID). Routes keep accepting a slug for channels this server sequences, so the CLI keeps working
  through the change.
- Federation between a server before slice 4 and one after it is not supported: v0.x makes no
  compatibility guarantee. The release notes say so.

**Tech stack:** Rust 2024, axum, serde, `jig_core::{dcbor, cose}`, `cargo nextest`,
`cargo clippy`.

**Working directory:** all `cargo` commands run from `repos/`. Build with `CARGO_INCREMENTAL=0`,
and run `scripts/clean-build-artifacts.sh --here --yes` when a slice is done (`AGENTS.md`).

---

## Ownership and order

Most of F2 touches files other lanes own. Each slice is one PR. Where F does not own a file, the
owning lane builds the slice, or agrees in writing (through the orchestrator) that F may.

| Slice | What | Files | Owner | Depends on |
| --- | --- | --- | --- | --- |
| 0a | Channels keyed by CID, store and pipeline: `blocks.channel_id`, `mls_groups` and the fanout scope move to CID, with an in-place migration; one `channel_id_of` resolver replaces `channel_slug_of` | `jig-pipeline/src/{persist,ingest,fanout,effect,mls_gate,authorize_write}.rs` | F builds; L7 agrees for `persist.rs` | nothing. **Lands in a quiet window** (see slice 0a) |
| 0b | Routes and frames take `channel_id`; a slug resolves only among channels this server sequences | `jig-server/src/v0_0_2_{blocks,admin,mls,ws}.rs`, `auth/authorize.rs`, `jig-pipeline/src/envelope.rs` | L3 for the routes, F for the frames | 0a |
| 0c | Client and CLI address channels by `channel_id`, with the slug as a hint | `jig-client/src/{secure,pins,blocks}.rs`, `jig-cli/src/cmd/{channel,secure}.rs` | L3 (CLI), L7 (`pins.rs`), F (`secure.rs`, agreed with its owner) | 0b |
| 1 | Terms and roles: `sequencer` and `co_owners` in `channel-create`; `role-assign` and `role-unassign`; a role-at-position check replaces `require_owner` and the MLS gate's owner rule | `jig-core` manifest fields, `jig-pipeline/src/{effect,authorize_write,mls_gate}.rs` | F | 0a; L7 4a for chain positions |
| 2 | `jig_core::contract`: offer, accept, refuse and end, with `offer_id`, refusal codes, grants and vectors | `jig-core/src/contract.rs` (new), `jig-core/src/lib.rs`, `jig-spec/jep/vectors/0005/` (new) | F | nothing; **can start now** |
| 3 | Peer policy: the `server-manifest` gains relayed kinds, per-peer quotas, published peers and attested suffixes (rule 16) | the manifest module L7's slice 7 creates | F, agreed with L7 | L7 7 |
| 4 | Share flow: a `channel-share` block triggers an offer over the mutual connection. The target answers. The owner appends a `contract-accept` block or surfaces the refusal. `contract-end` | `jig-pipeline` (kinds, effects), `jig-server/src/v0_0_2_federation.rs` (contract frames) | F | 1, 2, 3; L7 8 |
| 5 | Follower stream: a follower carries a shared channel by CID, verifies records and the chain (rules 12–14, 22a), stops on a gap or fork, and applies no local ownership gate | `jig-pipeline/src/ingest.rs` (`IngestSource::Sequenced`), `jig-server/src/v0_0_2_federation.rs` | F | 0a, 4; L7 4a/4b |
| 6 | Relayed writes under grants: a `relay-submit` frame. The follower applies its own admission. The owner runs its full gate plus grant enforcement and records the relaying server | `jig-pipeline/src/{ingest,authorize_write}.rs`, `envelope.rs`, `jig-server/src/v0_0_2_federation.rs` | F | 5 |
| 7 | MLS across servers: restricted MLS channels federate between configured peers. Followers track the public group and refuse commits that don't validate (rule 19). `contract-end` leads to removals | `jig-pipeline/src/{fanout,mls_gate}.rs`, `jig-mls/src/delivery.rs` (follower-side apply), `v0_0_2_federation.rs` | F | 6 |
| 8 | Custodians: key-package release policy, signed requests, one package per device, held-for-approval queue, release log, Welcome mailbox (rule 21) | `jig-core/src/contract.rs` (policy and request objects), `jig-server/src/v0_0_2_mls.rs`, `persist.rs` (custody tables), `jig-client` | F; L3 for routes, L7 for `persist.rs` | 2; L6's F1 slice 2 (reachability records); lane I (per-device leaves, revocation) |
| 9 | The contract half of a sequencer move: the new sequencer's accept names fresh bot DIDs and carries `policy-approval`s (rule 11b). Roles follow a channel-scoped `key-link` | `jig-pipeline` (effects), `jig-server` (accept builder) | F, with L7 (slice 10), lane C (approvals), lane I (`key-link`) | 4, 7; L7 10; lane C's JEP-0011 objects; lane I's link encoding |
| 10 | Layered abuse defences on federation links (design 5.10): cheap checks first, per-peer quotas from the manifest, a cap on writes queued while the sequencer is down, rate-limited and deduplicated head gossip | `jig-server/src/v0_0_2_federation.rs`, `jig-pipeline/src/ingest.rs` (check order) | F | 3, 6 |
| 11 | End to end, `federation.md` rewrite and threat register | `integration-tests/tests/h14_channel_contract.rs` (new), `jig-spec/src/federation.md`, `threat-register.md` | F | 0–7 and 10 |

Slices 2 and 0a can start at once. Slice 2 is pure code with no dependencies, so it goes first.
Slices 1, 3 and 4 follow as L7's 4a, 7 and 8 land. Slices 8 and 9 trail the core path, and the
exit criterion does not need them:
- the exit criterion needs an encrypted channel shared between two servers, which slices 0–7
  give;
- slice 8 needs lane I's per-device leaves;
- slice 9 needs L7's slice 10 and lane C.

---

### Task 0a: Channels keyed by CID, store and pipeline

**Why first:** every later slice addresses a channel that may have the same slug as a local
one. A follower that has its own `#ops` and carries A's `#ops` must keep both (design 6).

**Today's facts:**
- `blocks.channel_id` stores the slug (`ingest.rs:549`).
- `mls_groups` is keyed by slug (`persist.rs:407`).
- `land_mls_commit` does its compare-and-swap `WHERE slug=?` (`persist.rs:888`).
- `channels.slug` is `UNIQUE`.
- `ingest::channel_slug_of` (`ingest.rs:733`) reads metadata `slug` on create and `channel`
  elsewhere.

**Files:** `jig-pipeline/src/{persist,ingest,fanout,effect,mls_gate,authorize_write}.rs`.

- [ ] **Step 1: Failing tests.**
  - Two channels with the same slug and different sequencers coexist, and each block lands
    under its own CID.
  - A database with slug-keyed rows migrates in place: every `blocks.channel_id` and
    `mls_groups` row ends up keyed by the CID of the matching `channels` row.
  - A block naming an unknown `channel_id` is refused as today's unknown-slug block is.
  - The MLS compare-and-swap is keyed by CID.
- [ ] **Step 2: Implement.**
  - Content blocks carry `channel_id` in metadata. `channel` (a slug) is still read for
    channels this server sequences, until slice 0c moves the clients. One resolver,
    `channel_id_of`, returns the CID.
  - `channels.slug` uniqueness becomes `UNIQUE(sequencer_did, slug)`.
  - The migration runs in `SqliteStore::migrate`, guarded so it runs once.
  - `SubscriptionScope::Channel` carries the CID.
- [ ] **Step 3:** the whole workspace test suite. Every slug-keyed test either moves to CID or
  goes through the sequencer-local slug lookup.
- [ ] **Step 4:** commit `refactor(pipeline): key channels by channel_id (JEP-0005 rule 1)`.

**L7's conditions (agreed 2026-10-19).** Once L7's #161 is on main, this slice also moves L7's
sequencing code to the CID: `backfill_ingest_records`, `is_sequenced`, `sequenced_history_sql`
and `sequence_on`. The migration runs before the boot backfill, in one transaction, and is
idempotent. A test starts from a pre-migration store with records and shows that the chain
survives byte for byte: same `seq`s, same hashes, no re-signing. L7's
`backfill_sequences_a_store_once` and `backfill_re_signs_a_chain_in_an_older_format` stay green.
Slug wrappers resolve only channels this server sequences. L7's client (#169) relies on that, so
a relayed channel's history gets its own route, with its sequencer in the response.

**Coordination:** this touches files several open PRs edit. The orchestrator picks a window
with few in-flight `jig-pipeline` PRs. The slice keeps every public function signature that
takes a slug, as a thin wrapper over a sequencer-local lookup, so callers in other lanes'
branches keep compiling.

---

### Task 0b: Routes and frames take `channel_id`

- [ ] Routes accept either a `channel_id` (canonical CID text, checked with
  `jig_core::canonical_cid`) or a slug. A slug resolves only among channels this server
  sequences. A slug that matches nothing there is a 404, and a slug is never resolved across
  sequencers.
- [ ] `Scope::Channel` on the WSS subscribe carries `channel_id`.
- [ ] Read authorization (`auth/authorize.rs`) looks up by CID.
- [ ] Tests: a route reached by CID and by slug returns the same channel. A carried channel
  whose slug collides with a local one is reachable only by its CID.
- [ ] Commit `feat(server): address channels by channel_id`.

### Task 0c: Clients address channels by `channel_id`

- [ ] `jig-client` stores the `channel_id` with each channel it knows of. Channel pins are
  keyed by `(server, channel_id)`.
- [ ] The CLI shows the slug, with a short CID prefix when two channels it knows share a slug.
  It accepts `jig:<channel-cid>` (design 6).
- [ ] Commit `feat(client): channels by channel_id, slug as a hint`.

---

### Task 1: Terms and roles

**Files:** `jig-core` manifest fields; `jig-pipeline/src/{effect,authorize_write,mls_gate}.rs`.

- [ ] **Step 1: Failing tests.**
  - A `channel-create` without `sequencer` is refused for a federable channel (rule 5).
  - An admin's `channel-share` and `member-add` pass, and an admin's `role-assign` is refused.
  - A DID that was admin when it signed, and is unassigned later in the chain, still has its
    earlier block valid. The same DID's later block is refused.
  - The creator and listed co-owners cannot be unassigned.
  - Today's "owner adds" tests pass, now through the role check.
- [ ] **Step 2: Implement.**
  - `rights_at(channel_id, did, position)` folds the role blocks up to `position`. Before
    L7's 4a lands, `position` is local ingest order. Once 4a lands, it is the record's `seq`.
  - `require_owner` and the MLS gate's owner rule call it.
  - v0.2 has two roles: `owner` holds every right; `admin` holds `share` and `membership`.
- [ ] **Step 3:** commit `feat(pipeline): channel terms and role-based authority (JEP-0005 rules 5–7b)`.

---

### Task 2: `jig_core::contract`

Pure code, like `jig_core::naming`. Every object is a COSE_Sign1 over deterministic CBOR with
the domains rule 0 lists.

- [ ] **Step 1: Types and signed bytes.**
  - `Grant` is `read`, `write` or `member`.
  - `ContractOffer`:
    - `offer_id`;
    - the grant;
    - the creation block's bytes;
    - the `ingest` head;
    - the owner manifest's CID and `seq`;
    - `private_suffixes`.
  - `ContractAccept`:
    - `channel_id`;
    - `offer_id`;
    - `sequencer`;
    - the manifest's CID and `seq`;
    - `private_suffixes`;
    - `bot_dids`, empty except on a sequencer move.
  - `ContractRefuse`: `channel_id`, `offer_id`, and one of five codes.
  - `ContractEnd`: `channel_id`, the ending server, and a reason.
  - `offer_id` is BLAKE3 over the payload's deterministic encoding without `offer_id`.
    `from_envelope` recomputes it and refuses a mismatch.
- [ ] **Step 2: Failing tests.**
  - Each object round-trips.
  - Any field changed after signing fails.
  - An accept citing another offer's `offer_id` is detected by `ContractAccept::answers(&offer)`.
  - An unknown refusal code does not parse.
  - The `ingest` head is carried as opaque bytes until L7's 4a type exists. After that, it is
    the record type.
- [ ] **Step 3: Vectors** in `jig-spec/jep/vectors/0005/vectors.json`, generated by an ignored
  test as for 0004.
- [ ] **Step 4:** commit `feat(core): signed contract messages (JEP-0005 rules 0, 7–11)`.

---

### Task 3: Peer policy in the server manifest

- [ ] Extend L7's `server-manifest` with the fields below. The shape was agreed with L7 on
  2026-10-19, so its slice 7 reserves the keys from the start.
  - **Every key is always present.** An empty list is an empty array, never an absent key.
  - **Every list is sorted** bytewise by each element's deterministic CBOR encoding, with no
    duplicates. A verifier refuses any other order or a repeat, so each state has exactly one
    encoding.
  - `uint` is CBOR major type 0.

  | Key | CBOR type | Notes |
  | --- | --- | --- |
  | `relayed_kinds` | array of text | one entry per block kind |
  | `default_peer_quota` | map `{blocks_per_min: uint, bytes_per_min: uint}` | applies to every listed peer without its own entry, so no peer is unquoted |
  | `peer_quotas` | array of map `{peer: text, blocks_per_min: uint, bytes_per_min: uint}` | `peer` is a did:jig, unique across entries |
  | `peers` | array of text | did:jig; only the peers the server chooses to publish |
  | `attested_suffixes` | array of map `{suffix: text, root: text, root_id: text}` | `root` is `dns` or `contract`, never `config`; for `dns`, `root_id` is the lowercased suffix; for `contract`, canonical CID text (JEP-0004 rule 3); `(suffix, root)` unique |
- [ ] `/.well-known/jig` serves the same fields unsigned.
- [ ] Contract messages cite the manifest by CID and `seq`.
- [ ] Commit `feat(server): peer policy in the server manifest (JEP-0005 rule 16)`.

---

### Task 4: Offer, accept, refuse, end

**Wire:** contract frames ride the mutual server-to-server connection (L7's slice 8):
`contract-offer`, `contract-answer` and `contract-end`, each carrying one envelope from slice 2.

- [ ] **Step 1: Failing tests,** with two in-process servers.
  - A `channel-share` naming a configured peer produces an offer. The peer accepts, and the
    owner appends a `contract-accept` block that both servers hold.
  - A `channel-share` naming an unlisted server produces a visible refusal block in the
    channel log (`NOT_A_PEER`, design 5.7). No offer is sent.
  - An offer from a server not on the receiver's peer list is refused with `NOT_A_PEER`
    (rule 17).
  - An offer for a suite the receiver lacks is refused with `UNSUPPORTED_SUITE`. There is no
    fallback (rule 9).
  - Two servers that attest one suffix under different authorities refuse with
    `SUFFIX_CONFLICT`.
  - A `contract-end` from either side stops the stream, and the owner stops relaying to that
    follower.
  - A new offer with a different grant, once accepted, replaces the old grant.
- [ ] **Step 2: Implement.**
  - The owning server alone sends offers, and only on a `channel-share` block it has
    accepted.
  - Each follower's acceptance policy is configured per peer: auto-accept, or hold for the
    operator. The default is to hold.
- [ ] **Step 3:** commit `feat(federation): contract offer, accept, refuse and end (JEP-0005 rules 7–11, 17)`.

---

### Task 5: The follower's stream

- [ ] **Step 1: Failing tests.**
  - The follower delivers in `seq` order.
  - A gap in `seq`, two records with the same `seq` and different content, or a record signed by
    anyone but the expected sequencer each stops delivery and is surfaced as evidence
    (rule 14).
  - A block whose `seen` cites an unknown record stops delivery once the follower fails to
    obtain that record from the owner.
  - The follower applies no local ownership write gate to the owner's stream (rule 22a), but
    still verifies the author's signature.
- [ ] **Step 2: Implement.**
  - A new `IngestSource::Sequenced { sequencer }` path.
  - The follower keeps the chain head per `channel_id`.
  - Catch-up after a reconnect uses the owner's records from the follower's head. This is the
    reader `subscription_cursors` never had.
- [ ] **Step 3:** commit `feat(federation): followers verify the owner's chain (JEP-0005 rules 12–14, 22a)`.

---

### Task 6: Writes relayed under grants

- [ ] **Step 1: Failing tests.**
  - A member's post through a `write` follower lands at the owner and comes back through the
    stream.
  - Through a `read` follower, a post is refused at the follower and again at the owner, if
    the follower is forced to relay it. A self-update still relays.
  - A membership block through a `write` follower is refused. Through a `member` follower, it
    passes whatever the channel's rule allows.
  - The owner records the relaying server's DID.
  - A relayed block with a bad author signature is refused whatever the grant.
- [ ] **Step 2: Implement.**
  - A `relay-submit` frame.
  - The follower runs admission, proof-of-work and rate limits on its client before relaying.
  - The owner runs its full gate, plus `grant_allows(grant, kind)` (rules 7a and 15).
- [ ] **Step 3:** commit `feat(federation): relayed writes under share grants (JEP-0005 rules 7a, 15)`.

---

### Task 7: Encrypted channels across servers

- [ ] **Step 1: Failing tests.**
  - A restricted MLS channel on A is shared with B. A client on B is added by Welcome and posts
    through B, and a client on A decrypts the post. Neither server holds plaintext. The
    integration test greps both stores for the plaintext.
  - A commit that does not apply to the follower's public group state is not delivered by the
    follower (rule 19).
  - After a `contract-end`, members commit removals for leaves reachable only through that
    follower.
- [ ] **Step 2: Implement.**
  - `DeliveryPolicy.federates` becomes "this channel has an accepted contract with this
    peer", replacing "open and unencrypted".
  - The follower applies commits to a public group mirror, using `jig-mls`'s delivery checks
    without the private state.
  - There are no external senders (rule 20).
- [ ] **Step 3:** commit `feat(federation): restricted MLS channels federate under contract (JEP-0005 rules 18–20)`.

---

### Task 8: Custodians

- [ ] Release policy and request objects in `jig_core::contract` (`jig-kp-release-policy-v1`,
  `jig-kp-request-v1`).
- [ ] The custodian's routes, which L3 owns:
  - upload stock and a last-resort package;
  - set the policy;
  - request, signed and naming a channel;
  - list held requests, approve or refuse;
  - read the release log.
- [ ] Releases are one package per stocked device. A DID whose revocation the custodian holds
  gets no releases.
- [ ] The Welcome mailbox is for DIDs no carrying server reaches.
- [ ] Tests:
  - a contact gets a package automatically;
  - a stranger's request is held, then released on approval;
  - an unsigned request, or one naming no channel, is refused;
  - a revoked DID gets nothing;
  - the last-resort package is never consumed.
- [ ] Commit `feat(mls): key-package custodians under a signed release policy (JEP-0005 rule 21)`.

---

### Task 9: The contract half of a sequencer move

- [ ] The new sequencer's `contract-accept` names fresh bot DIDs and carries a
  `policy-approval` for the current `channel-policy` and for every live `block-install`
  (rule 11b).
- [ ] A `key-link` block moves roles and membership from its `seq` onward (rule 7b).
- [ ] Test: once a `sequencer-set` is in force, an approval-less policy reads as absent. A
  `key-link` scoped to another channel moves nothing.
- [ ] Commit `feat(federation): sequencer move approvals and key-link roles (JEP-0005 rules 7b, 11a, 11b)`.

---

### Task 10: Abuse defences on federation links

- [ ] Ingest from a peer checks in this order:
  1. frame size;
  2. the per-peer quota from the manifest;
  3. CID dedupe;
  4. the author's signature;
  5. MLS.

  A test asserts the order by counting signature verifications on a flood of oversize and
  duplicate frames.
- [ ] Handshake attempts are limited per source address, and no block processing happens
  before the mutual handshake.
- [ ] Writes queued while the sequencer is down are capped. Head gossip is rate-limited and
  deduplicated.
- [ ] Commit `feat(federation): layered abuse defences on peer links`.

---

### Task 11: End to end, spec and threat register

**Files:** `integration-tests/tests/h14_channel_contract.rs` (new).

| Case | Expected |
| --- | --- |
| Share an encrypted channel A → B, post from both sides | Both decrypt; neither store holds plaintext |
| Same slug on both servers | Both channels live, distinct by `channel_id` |
| Unlisted target | Refusal visible in the channel log |
| Grant `read`, B's client posts | Refused at B and at A; self-update still relays |
| A shows B a forked chain | B stops delivering and keeps both records |
| Contract ended | B stops; removals committed |

- [ ] Rewrite `federation.md` per design section 7. The rewrite lands in this PR (DJ, 2026-10-18).
- [ ] Threat-register rows OP-06, OP-09, AB-03, PV-01 and OP-04, per design section 8.
- [ ] Commit `test(federation): the channel contract end to end`.

---

## Questions for DJ

1. **The F2 milestone row says "key packages through the owner under consent"**, but section
   5.4 and rule 21 settle custodians, with the sequencer taking no part. This plan follows 5.4
   and rule 21. The row should be corrected in the design doc.
2. **The follower's default for incoming offers:** this plan holds every offer for the
   operator unless that peer is configured to auto-accept. Auto-accepting from configured peers
   is the alternative. The trade-off is a manual step per share against a configured peer
   committing the operator to carry any channel.
3. **The cap on writes queued while a sequencer is down.** The plan proposes two caps,
   configured per server:
   - per channel: 1000 blocks or 10 MiB;
   - per server, across all channels: 100 MiB, so that many carried channels cannot add up to
     an unbounded total (orchestrator, 2026-10-19).

## Done when

- `h14_channel_contract` passes in CI. Its first case is exit criterion 5.
- No route, table or frame keys a channel by slug, except the sequencer-local slug lookup.
- JEP-0005 moves from Draft to Review. The `federation.md` rewrite and the threat-register rows
  are merged.
