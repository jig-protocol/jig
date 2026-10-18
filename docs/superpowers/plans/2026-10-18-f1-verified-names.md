# F1: Verified, Pinned Name Lookups — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `jig dm alice@example.org` works, and neither a nameserver nor the user's own server
can swap in another key without the client noticing. Names reach E2EE only through a verified,
pinned lookup.

**Architecture:**
- **One shared module, `jig_core::naming`, holds every signed naming object** with its exact
  signed bytes: attestation, suffix delegation and reachability record, plus the rotation-chain
  check over lane I's links. It is
  pure code, with no I/O.
- **The nameserver issues and stores** these objects.
- **The server's resolver verifies them** for the `nickname` gate.
- **A client-side resolver (`jig_client::naming`) verifies before every E2EE use.** The pin store
  records what it accepted.

Nothing trusts a binding because of which party fetched it.

**Spec:**
- [JEP-0004](../../../repos/jig-spec/jep/jep-0004-verified-naming.md); rule numbers below are
  JEP-0004's.
- Design: [federation naming and contract](../specs/2026-10-18-federation-naming-and-contract-design.md),
  sections 4.1–4.8.
- Name pins and `jig trust accept-name`:
  [D11 design item 11](../specs/2026-10-18-d11-handshake-completion-design.md) (lane L7).
- **Aligned with L7's build plan** (`2026-10-18-d11-handshake-completion.md`):
  - L7's slice 9 (name pinning) is the pin half of F1's slice 5.
  - L7's slice 6 (evidence) is where F1's name evidence goes. F1 adds no evidence store or
    command of its own.

**Compatibility, stated precisely:**
- Attestations signed under the old JSON encoding stop verifying once a resolver implements this
  plan. Nameservers re-issue on renew (JEP-0004, Backwards Compatibility).
- Registration proofs over the bare challenge are refused once slice 2 lands. Every client must
  move to action-bound proofs in the same release (slice 6 ships the CLI side).
- v0.x makes no compatibility guarantee. The release notes must name both breaks.

**Tech stack:** Rust 2024, axum 0.7, serde, reqwest (rustls), `cargo nextest`, `cargo clippy`.

**Working directory:** all `cargo` commands run from `repos/`. Build with `CARGO_INCREMENTAL=0`,
and run `scripts/clean-build-artifacts.sh --here --yes` when a slice is done (`AGENTS.md`).

**Toolchain:** `cargo +stable` for clippy, matching CI.

---

## Ownership and order

F1 touches files that other lanes own. Each slice is one PR. Where F does not own a file, the
owning lane builds the slice, or agrees in writing (through the orchestrator) that F may.

| Slice | What | Files | Owner | Depends on |
| --- | --- | --- | --- | --- |
| 0 | Fail closed on orphan relayed posts and on fanout with no policy | `jig-pipeline/src/ingest.rs`, `jig-pipeline/src/fanout.rs` | To be confirmed by the orchestrator (asked 2026-10-18) | nothing |
| 1 | `jig_core::naming`: types, signed bytes, verification, test vectors | `jig-core/src/naming.rs` (new), `jig-core/src/lib.rs`, `jig-spec/jep/vectors/0004/` (new) | F | nothing |
| 2 | The nameserver issues the new objects and takes action-bound proofs for register and renew. Rotate stays as it is until lane I's I3 moves `/v1/rotate` onto links | `jig-nameserver/src/v0_0_2*.rs`, alias storage in `jig-pipeline/src/persist.rs` | L6 (nameserver); persistence change agreed with whoever owns `persist.rs` | 1 |
| 3 | TLS on the nameserver | `jig-nameserver/src/server.rs` | L6 | nothing |
| 4 | The server's resolver verifies, binds suffixes, caches within validity and keeps evidence | `jig-pipeline/src/identity.rs`, `jig-config/src/v0_0_2_server.rs` | F for `identity.rs`; L3 for the config field | 1 |
| 5 | Client resolver (F) and name pins (L7's slice 9) | `jig-client/src/naming.rs` (new, F); `jig-client/src/pins.rs` `names` map and `jig trust accept-name` plus expiry warning (L7's slice 9) | F + L7 | 1; L7's slice 9 also needs F1 slice 1 (`verify_rotation_chain`, the pin key) |
| 6 | CLI: names in `dm`/`channel add`, verified `init`/`ns`, reachability | `jig-cli/src/cmd/{channel,dm,init,ns}.rs`, `jig-cli/src/config.rs` | L3 | 2, 5; L7's slices 6 and 9 |
| 7 | End-to-end test against a lying nameserver | `integration-tests/tests/h13_verified_names.rs` (new) | F | 2, 4, 6 |
| 8 | Spec pages and threat-register rows | `jig-spec/src/identity-and-reputation.md`, `threat-register.md` | F, in the implementation PR, after L1 has merged its banners | 7 |

Slices 1 and 3 can start at once. Slices 2, 4 and 5 can run in parallel after slice 1. Ship 2
and 6 in the same release (see Compatibility).

**Lane I (identity, decided 2026-10-18):** a DID is bound to its key, and a rotation is a
new DID plus a dual-signed link (COSE over deterministic CBOR), scoped to one audience. For
F1 this means:
- an alias moves only by a link scoped to that nameserver and alias;
- `/v1/rotate` switches to links in lane I's I3;
- F1 ships with no automatic rotation, so every change of DID behind a pinned name needs
  the holder's acceptance until I3;
- `jig_core::naming::verify_rotation_chain` is generic over lane I's link type
  (`AliasLink`).

Roles across a channel `key-link`, and one key package per device at custodians, are F2
work (JEP-0005 items 7b and 21).

**Open decision carried into the build:** the reference default suffix (`gigue.jig`) is not a DNS
name. Until DJ decides, it works only through a `config` delegation, and every test uses an
explicit config delegation.

---

### Task 0: Fail closed on orphan posts and policy-less fanout

Two fail-open paths found in the research pass (design, section 2). Neither leaks restricted or
encrypted content today, but both will matter once channels are keyed by CID in F2.

**Files:**
- Modify: `repos/jig-pipeline/src/ingest.rs` (`requires_existing_channel`, around line 731)
- Modify: `repos/jig-pipeline/src/fanout.rs` (the federation-scope filter, around line 281)
- Test: the existing `ingest.rs` and `fanout.rs` test modules

- [ ] **Step 1: A failing test for the orphan.** Ingest a `text-render` from
  `IngestSource::FederatedPeer` naming a slug with no channel row. Expect a refusal (the typed
  unknown-channel error that local submissions get). It passes today, so the test fails first.
- [ ] **Step 2: A failing test for fanout.** Fan out a block with `policy = None` to a federation
  subscriber. Expect no delivery.
- [ ] **Step 3: Fix.**
  - Drop the `FederatedPeer` exemption in `requires_existing_channel`.
  - Change the federation filter to `policy.is_some_and(|p| p.federates)`.
- [ ] **Step 4:** run `cargo nextest run -p jig-pipeline -p jig-server` and
  `cargo nextest run -p integration-tests --test h3_federation`. `h3_federation` relays posts
  into channels both peers created, so it must stay green. If it relies on orphan relay, stop and
  report: that test encodes the bug.
- [ ] **Step 5:** commit `fix(federation): refuse relayed posts for unknown channels; no policy means no federation`.

---

### Task 1: `jig_core::naming`

Pure types and signed bytes, so the nameserver, the server and the client all compute the same
signature input.

**Files:**
- Create: `repos/jig-core/src/naming.rs`
- Modify: `repos/jig-core/src/lib.rs` (`pub mod naming;`)
- Create: `repos/jig-spec/jep/vectors/0004/{attestation,rotation,delegation,reachability}.json`

**Interface:**

```rust
pub struct Name { pub alias: String, pub suffix: String }           // parsed, normalised
pub enum Root { Config, Dns, Contract }
pub struct RootId(pub String);                                      // rule 3
pub struct Attestation { did, alias, ns_did, valid_from: i64, valid_until: i64, sig: String }
pub struct RotationStatement { alias, ns_did, old_did, new_did, at: i64, sig_old, sig_new }
pub struct SuffixDelegation { suffix, authorities: Vec<String>, root: Root, root_id: RootId,
                              valid_until: i64, sigs: Vec<(String, String)> }
pub struct ReachabilityRecord { did, servers: Vec<(String /*server_did*/, String /*url*/)>,
                                seq: u64, sig: String }

impl Attestation        { pub fn signed_hash(&self) -> Hash; pub fn verify(&self) -> Result<(), NamingError>; }
impl RotationStatement  { pub fn signed_hash(&self) -> Hash; pub fn verify(&self) -> Result<(), NamingError>; }
impl SuffixDelegation   { pub fn signed_hash(&self) -> Hash; pub fn verify(&self) -> Result<(), NamingError>; }
impl ReachabilityRecord { pub fn signed_hash(&self) -> Hash; pub fn verify(&self) -> Result<(), NamingError>; }

pub fn proof_hash(action: Action, ns_did: &str, alias: &str, challenge: &str) -> Hash; // rule 10
pub fn verify_binding(att: &Attestation, deleg: &SuffixDelegation, name: &Name, now: i64)
    -> Result<(), NamingError>;                                                         // rule 13
pub fn verify_rotation_chain(pinned: &str, chain: &[RotationStatement], new: &str)
    -> Result<(), NamingError>;                                                         // rule 18
```

Every hash is `jig_core::crypto::hash_labeled_parts` with the labels and order JEP-0004 lists.
Times, counts and `seq` are decimal ASCII. Authorities are sorted bytewise before hashing.

- [ ] **Step 1: Name parsing tests.**
  - The alias is 1–24 characters of `[A-Za-z0-9_-]`, and is lowercased.
  - The suffix is lowercased.
  - Refuse an empty part, a second `@`, and a suffix with whitespace or a trailing dot.
- [ ] **Step 2: Signed-bytes tests against fixed vectors.**
  - Use a fixed seed `[7u8; 32]` for the nameserver key and `[9u8; 32]` and `[11u8; 32]` for
    user keys.
  - Write each vector as JSON: inputs, the hex hash and the base64 signature. Commit the vectors
    under `jig-spec/jep/vectors/0004/`. The test loads them with `include_str!`, so a change to
    the encoding fails CI.
- [ ] **Step 3: Verification tests.** Each must fail for exactly one reason:
  - the signature is from the wrong key;
  - the signer is not in the delegation's authorities;
  - one delegation signature is missing;
  - the attestation is expired (`now == valid_until`);
  - the attestation is not yet valid;
  - the alias differs from the requested name;
  - the rotation chain breaks (a gap, a link scoped to another alias or nameserver, an
    unsigned link). The link type is lane I's; slice 1 tests against a stand-in through the
    `AliasLink` trait;
  - a rotation's `ns_did` differs from the attestation's;
  - a reachability record's servers are reordered after signing.
- [ ] **Step 4: Implement** until the tests pass. `NamingError` variants name the exact failure;
  slices 4–6 show those names to users.
- [ ] **Step 5:** `cargo nextest run -p jig-core naming`; `cargo +stable clippy -p jig-core --all-targets -- -D warnings`.
- [ ] **Step 6:** commit `feat(core): naming objects with domain-separated signed bytes (JEP-0004)`.

---

### Task 2: The nameserver issues verifiable objects

**Files:**
- Modify: `repos/jig-nameserver/src/v0_0_2_register.rs`
  - `Attestation` now uses `jig_core::naming::Attestation`.
  - `verify_proof_of_control` takes an `Action` and checks `proof_hash`.
- Modify: `repos/jig-nameserver/src/v0_0_2_rotate_renew.rs` (action-bound proofs; store the
  `RotationStatement`)
- Modify: `repos/jig-nameserver/src/v0_0_2_resolve.rs` (serve `{attestation, rotations: [...],
  reachability?}`)
- Modify: `repos/jig-nameserver/src/v0_0_2.rs`
  - `take_challenge` runs only after the proof verifies;
  - serve the nameserver's own signed `SuffixDelegation` at `/.well-known/jig-ns-delegation`.
- Modify: `repos/jig-pipeline/src/persist.rs` (rotation-statement table; optional reachability
  record beside each attestation)

Today's facts this task changes:
- The proof signs the raw challenge hex (`register.rs:118`).
- The challenge is consumed before the proofs are checked (`rotate_renew.rs:43`), so a bad proof
  burns a good challenge.
- `profile_ttl_seconds` is inside the signed JSON. It leaves the signed body and stays as an
  unsigned hint. First check its readers (`grep -rn profile_ttl_seconds`). If a client acts on
  it, stop and report.

- [ ] **Step 1: Failing tests.**
  - A proof over the bare challenge is refused.
  - A register proof replayed as renew is refused.
  - A renew whose proof is bad leaves the challenge usable for one more attempt.
  - A consumed challenge is refused for every action.
  - A challenge older than its TTL is refused.
  - `/v1/resolve/{alias}` after a rotation returns both the statement and the new attestation.
  - Every returned attestation passes `naming::Attestation::verify`.
- [ ] **Step 2: Implement.**
  - The TTL stays 60 s, within rule 10's 300 s cap.
  - Challenges stay 32 random bytes.
  - Consumption becomes `verify → take_challenge`. A `false` from `take_challenge` is a refusal,
    so two racing proofs cannot both win.
- [ ] **Step 3: Delegation endpoint.**
  - The nameserver signs a single-authority `SuffixDelegation` for its configured `alias_suffix`,
    with `root: dns` and `root_id` = the suffix.
  - Serving it at the domain is how `dns` discovery finds it when the suffix's host points at the
    nameserver. A test fetches and verifies it.
- [ ] **Step 3b: Reserve the proof-of-work field (for lane R's R1, draft #152).**
  - `RegisterReq`, `RenewReq` and `RotateReq` gain an optional `pow` field: an opaque JSON
    object that F1 neither defines nor checks.
  - F1 accepts requests with or without it.
  - R1 defines its contents and makes it required. Its stamp should commit to
    `naming::proof_hash(action, ns_did, alias, challenge)`, so the work is bound to the same
    action, alias, nameserver and challenge as the proof (AB-01), with no second binding to
    design.
  - Test: a request carrying an arbitrary `pow` object is accepted and the object is ignored.
    This pins the reservation so R1 is a pure addition.
- [ ] **Step 4: Reachability.**
  - `POST /v1/register` accepts an optional `reachability` field. Verify it and store it.
  - `resolve` returns it.
  - Refuse a record whose `did` differs from the registrant's.
- [ ] **Step 5:** `cargo nextest run -p jig-nameserver -p integration-tests --test h6_nameserver_mode --test h10_nameserver_binary_surface`.
  `h6` will fail until slice 4 lands, if it asserts on the old encoding. Update its expectations
  in this PR, and say so in the PR body.
- [ ] **Step 6:** commit `feat(nameserver): verifiable attestations, action-bound proofs (JEP-0004)`.

---

### Task 3: TLS on the nameserver

**Files:** modify `repos/jig-nameserver/src/server.rs` (the `TcpListener` + `axum::serve` path
around line 1572).

- [ ] **Step 1: Reuse jig-server's TLS setup.** That is a CA-issued certificate, or a self-signed
  one bound to the nameserver's DID through `jig_core::tls_binding` and published in
  `/.well-known/jig-ns`. Do not write a second TLS stack: if the jig-server helper is not
  reachable from the nameserver crate, move it to `jig-core` or `jig-config`, agreed with its
  owner.
- [ ] **Step 2: Plaintext only behind a flag.** Add `dangerously_allow_plaintext_nameserver`,
  advertised in `/.well-known/jig-ns` under `unsafe_options_active` (rule 12).
- [ ] **Step 3: Tests.** A TLS client that pins the nameserver's DID connects. A client that pins
  a different DID is refused. Plaintext without the flag refuses to start.
- [ ] **Step 4:** commit `feat(nameserver): TLS by default, bound to the nameserver DID`.

---

### Task 4: The server's resolver verifies

**Files:**
- Modify: `repos/jig-pipeline/src/identity.rs` (`NameserverResolver`, lines 141–230)
- Modify: `repos/jig-config/src/v0_0_2_server.rs`: add `[identity] delegations`, a map from
  suffix to `{ authorities = [did], nameservers = [url] }`. L3 owns this file.
- Create: an evidence table in the server's store: `(name, root_id, attestation_bytes,
  first_seen)`.

Today's facts:
- It reads only `json["did"]`.
- It asks every nameserver whatever the suffix, and takes the first 2xx.
- It caches for 300 s, ignoring `valid_until`.
- It puts the alias into the URL path unescaped.

- [ ] **Step 1: Failing tests.** Each runs against a stub nameserver:
  - a valid attestation from a DID outside the suffix's authorities is refused;
  - a forged signature is refused;
  - an expired attestation is refused;
  - a cached entry past `valid_until` is refetched;
  - two configured nameservers answering different DIDs refuse the block, and both attestations
    land in the evidence table;
  - an alias containing `/` or `%` is refused before any request.
- [ ] **Step 2: Implement.**
  - A suffix with no delegation in config refuses: there is no discovery on the server side in
    F1.
  - Keep `naively_allow_unknown_handles_fallback`. It still only downgrades refusal to a warning,
    and stays listed in `unsafe_options_active`.
- [ ] **Step 3:** `cargo nextest run -p jig-pipeline identity` and `--test h6_nameserver_mode`.
- [ ] **Step 4:** commit `fix(identity): the server's resolver verifies attestations and suffix authority (NS-01)`.

---

### Task 5: Client resolver and name pins

**Files:**
- Create: `repos/jig-client/src/naming.rs` (F)
- Modify: `repos/jig-client/src/pins.rs`, adding the `names` map (L7, per D11 item 11)

**`jig_client::naming::resolve(name, &Delegations, &Pins) -> Result<Verified, ResolveError>`:**
1. Find the delegation:
   - first `config` (the client's `[naming.delegations]`);
   - else `dns`: `GET https://<suffix>/.well-known/jig-ns-delegation` with CA validation only,
     no DID-bound fallback.
2. Fetch `/v1/resolve/{alias}` from a listed nameserver, directly or through the connected
   server.
3. Run `naming::verify_binding`.
4. Compare with the pin, keyed by `(alias, suffix, root, root_id)` (rule 6):
   - no pin: return `Verified::New`, and the caller must pin before any E2EE use (rule 17);
   - same DID: `Verified::Pinned`;
   - different DID with a valid chain of rotation links (lane I's I3; until then this branch
     never fires): `Verified::Rotated`, and the caller moves the pin
     and says so;
   - anything else: `ResolveError::PinMismatch { reason, old, new }`, where `reason` is one of
     `ReRegistered`, `OtherNameserver` or `NoRotationProof`.
5. Hand every attestation and rotation chain acted on to L7's evidence writer
   (`jig-client/src/evidence.rs`, `jig-evidence-v1`, L7's slice 6) as a name-evidence bundle
   (rule 20). An equivocation, meaning two valid attestations with different DIDs, is written as
   one bundle holding both. F1 keeps no separate evidence file.

- [ ] **Step 1:** tests for each branch of step 4, using a stub nameserver and an in-memory pin
  store.
- [ ] **Step 2:** a test that a `dns` delegation served over a self-signed certificate is
  refused.
- [ ] **Step 3: Pin store.** This is L7's slice 9. It adds `names` to `PinFile`:
  - keyed by `(alias, suffix, root, root_id)`;
  - with `check_name(key, did, attestation, rotations)`, which calls
    `jig_core::naming::verify_rotation_chain`;
  - using the same atomic write as server pins.

  F's resolver calls it. Until L7's slice 9 lands, F's PR stubs the call behind a trait, so the
  two can merge in either order. L7's slice 9 needs F1's slice 1 merged first.
- [ ] **Step 4:** commit `feat(client): verified name resolution against pinned bindings (OP-08)`.

---

### Task 6: CLI

**Files:** `repos/jig-cli/src/cmd/channel.rs` (`resolve_who`, line 323), `dm.rs`, `init.rs`,
`ns.rs`, `config.rs`. L3 owns them; `jig trust accept-name` is L7's.

- [ ] **Step 1: `resolve_who`.** Its order becomes:
  1. a `did:jig:` DID;
  2. a `[contacts]` name;
  3. an `alias@suffix`, through `jig_client::naming::resolve`.

  On `Verified::New` it pins, and prints the DID fingerprint and the vouching nameserver. On
  `PinMismatch` it refuses, printing the reason, both fingerprints and the
  `jig trust accept-name` hint. It never falls back to an unverified answer.
- [ ] **Step 2: `jig init --request-alias`.**
  - Sign the action-bound register proof (`naming::proof_hash`).
  - Verify the returned attestation before saving it.
  - Optionally send a reachability record listing the server in `cli.toml`.
- [ ] **Step 3: `jig ns resolve`.** Print `verified`, `pinned`, `rotated` or the exact refusal,
  never a bare DID.
- [ ] **Step 4: Evidence and expiry.** No new commands. Name evidence is listed and exported by
  L7's `jig trust evidence`, and the expiry warning is L7's slice 9.
- [ ] **Step 5: Tests.** `resolve_who` against a stub nameserver covers the new-pin, pinned,
  rotated and mismatch cases. A test confirms `jig dm` with a mismatched name sends nothing.
- [ ] **Step 6:** commit `feat(cli): verified, pinned names in dm and channel add`.

---

### Task 7: End to end against a lying nameserver

**Files:** create `repos/integration-tests/tests/h13_verified_names.rs`.

One nameserver, one jig server and two CLI identities, Alice and Bob. Each case asserts what
Bob's client does:

| Case | Setup | Expected |
| --- | --- | --- |
| Honest | Alice registers; Bob runs `jig dm alice@<suffix>` | Pins Alice's DID; the DM opens |
| Substitution after pin | The nameserver re-binds the alias to Mallory without a rotation | `PinMismatch(NoRotationProof)`; nothing sent |
| Rotation | Alice rotates with both keys | Pin moves; Bob is told; the DM goes to the new DID |
| Unauthorised signer | A second nameserver, not in the delegation, answers | Refused: signer not authoritative |
| Equivocation | Two delegated nameservers answer different DIDs | Refused; one evidence bundle holding both attestations (`jig trust evidence show`) |
| Expired | Clock moved past `valid_until` | Refused; refetch attempted |
| Server lies | Bob's server serves a forged attestation | Refused: the client verifies itself |

- [ ] **Step 1:** write the cases.
- [ ] **Step 2:** they pass once slices 2, 4, 5 and 6 are in.
- [ ] **Step 3:** commit `test(naming): lying nameserver and server cases end to end`.

---

### Task 8: Spec and threat register

After L1's banners merge, in the PR that lands slice 7.

- [ ] Rewrite `identity-and-reputation.md`:
  - "Aliases": signed bytes, action-bound proofs, rotation by link (lane I), delegation,
    reachability;
  - "Resolution by servers": verification, suffix binding, caching within validity, evidence.

  Point both at JEP-0004 for the details.
- [ ] Update the threat-register rows:
  - OP-08: name pins → Partial, server pins plus name pins.
  - NS-01: verified, suffix-bound, cached within validity → Mitigated for configured and DNS
    roots.
  - NS-02: client and server evidence retained → Partial; no transparency log until F3.
  - AB-01: alias proofs bound to the action, alias and nameserver → Partial; PoW binding is
    lane R's.
- [ ] The release notes name both compatibility breaks and the four rows.

---

## Done when

- `h13_verified_names` passes in CI.
- `jig dm alice@<suffix>` pins on first use and refuses a substituted key.
- No code path hands an unverified name→DID answer to E2EE.
- The four threat-register rows are updated, and JEP-0004 moves from Draft to Review.
