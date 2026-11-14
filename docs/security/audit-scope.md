# External security audit: scope (D27)

**Status:** the split is decided (DJ, 2026-10-25): **Option A**, one firm in two phases, with
Phase 1 starting before G3 (section 4). This settles [ROADMAP](../ROADMAP.md) still-open
question 5. Budget, timing, the formal model and publication (section 7) are still open.

**Decision it builds on (D27):** the audit reviews code that will not be replaced soon, and it
does not block development. As decided on 2026-10-25, Phase 1 covers the code already complete
and starts before gate G3; Phase 2 follows once v0.2 is code-complete (section 4).

This document is written to be sent to audit firms as it stands. It names code paths, spec
chapters and threat-register rows. It describes no deployment: the audit covers the
open-source reference implementation in this repository and nothing else.

---

## 1. What jig is, for an auditor

jig is an open protocol and reference implementation for federated, signed messages that may
carry sandboxed WebAssembly. It is written in Rust, in one Cargo workspace under
[`repos/`](../../repos/), dual-licensed MIT OR Apache-2.0.

- **Identity is a key.** A `did:jig` is an ed25519 public key. Every block, receipt, record and
  attestation is signed by a DID and checked against the DID itself.
- **_All_ operators are untrusted** (D11). Malicious operators are in the threat model: clients,
  servers, and nameservers alike. 
- **Encryption is per-channel.** MLS (RFC 9420, via openmls) is the one real suite, with additional
  pluggable suites planned. Restricted channels and DMs always use it (D25), and the server acts as
  a validating delivery service that holds no group secret.
- **Federation is a signed contract between servers** ([JEP-0005](../../repos/jig-spec/jep/jep-0005-channel-federation-contract.md)).
  Each channel has one sequencing server, and followers carry its signed, hash-chained record.
- **Blocks may carry a Wasm component** that the server runs in a deterministic sandbox and
  receipts. Clients check a receipt by re-running the component.

The normative spec is the mdBook in [`repos/jig-spec/src/`](../../repos/jig-spec/src/), and the
protocol changes are the JEPs in [`repos/jig-spec/jep/`](../../repos/jig-spec/jep/). The
[threat register](../../repos/jig-spec/src/threat-register.md) has 34 rows in eight families. Its
status column says, row by row, what the code on `main` mitigates. The reasoning behind the
operator rows is in [`operator-threat-model.md`](operator-threat-model.md), and the encryption
design is in [`encryption.md`](encryption.md).

## 2. Ground rules for the engagement

- **A fixed commit.** The audit runs against one tagged commit on `main`, named in the
  engagement letter. Findings cite that commit. Fixes land as ordinary pull requests and are
  re-tested against a later tag.
- **The threat model is the threat register.** A finding that breaks a row's MUST is in scope
  whatever the row's status. A finding against a row marked **Accepted** (OP-04, SC-01, PV-01)
  or **By design** (PV-04) is out of scope unless the row's stated limits are wrong. Rows marked
  **Open** describe known gaps: we want confirmation and severity, not rediscovery.
- **Malicious operators, malicious peers and malicious nameservers are all attackers,** as are
  network attackers and other users. The member's own device is trusted while the member uses
  it; key theft at rest (ID-04) is in scope.
- **Reporting.** Critical and high findings are reported as they are found, through GitHub
  private vulnerability reporting or security@jig.onl, as [`SECURITY.md`](../../SECURITY.md) sets
  out, and are held under its 90-day coordinated disclosure.
- **Publication.** We intend to publish the final report, or a summary of it the firm agrees
  to, once fixes ship.

## 3. Scope, by priority

Line counts are approximate and include in-file unit tests.

| # | Area | Why this rank | Size | Code-complete now? |
| --- | --- | --- | --- | --- |
| 1 | MLS integration and the ciphersuite gate | Confidentiality of every encrypted channel and DM rests on it, and it is the only place the server touches group state | ~2.5k lines | Single-server, yes. Across servers, no (F2 Task 7) |
| 2 | The handshake and the TLS DID binding | The client's main defence against a hostile operator; custom signed transcript bound to the TLS exporter | ~9k lines | Mostly. Slices 5 and 10 of the D11 plan remain |
| 3 | Key links and chains | A wrong link check hands one server's standing to an attacker's key | ~4k lines | Yes |
| 4 | Keys at rest | Identity seeds, MLS secrets and the plaintext cache on disk | ~6k lines | Yes |
| 5 | Proof-of-work and admission | Abuse cost at nameservers and servers; request authentication | ~6k lines | Yes, except capacity pools at servers |
| 6 | The federation contract and the follower stream | Cross-server trust: a follower carries what the owner sequenced | ~9k lines | No: F2 Tasks 0c and 7 to 11 remain |
| 7 | The Wasm sandbox and receipts | Executes sender-supplied code on the server | ~6k lines | Yes, for the one world that runs (`renderer`) |

### 3.1 MLS integration and the ciphersuite gate

**Questions for the auditor.**
- Can the server, or any non-member, learn plaintext?
- Can a member be made to accept a commit, welcome or application message that the group's
  public state should refuse?
- Can anyone make a client or the server run crypto in a ciphersuite other than jig's?
- Does the binding between a leaf's credential and its DID hold?

**Threat-register rows:** OP-05 (content disclosure), OP-03 (suite downgrade), PV-04
(non-deniability, by design), SC-03 (no execution of encrypted content), ID-04 (MLS state at
rest).

**Entry points.**

- [`jig-mls/src/lib.rs`](../../repos/jig-mls/src/lib.rs): `CIPHERSUITE`
  (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) and the group configuration.
- [`delivery.rs`](../../repos/jig-mls/src/delivery.rs), the server's delivery service on openmls
  `PublicGroup`: `genesis`, `apply_commit`, `check_application`, `validate_key_package`,
  `decode_group_info`, `decode_key_package`, `require_ciphersuite`, `check_proposals`.
- [`member.rs`](../../repos/jig-mls/src/member.rs), the client member: `join_external`,
  `join_welcome`, `apply_commit`, `encrypt`, `decrypt`.
- [`credential.rs`](../../repos/jig-mls/src/credential.rs): `bound_did`, `leaf_did`. The MLS
  signature key is the DID's ed25519 key.
- [`jig-pipeline/src/mls_gate.rs`](../../repos/jig-pipeline/src/mls_gate.rs): the server-side
  gate. The suite is fixed at channel creation and plaintext into an encrypted channel is
  refused.
- [`jig-server/src/v0_0_2_mls.rs`](../../repos/jig-server/src/v0_0_2_mls.rs): the key-package
  and group-info routes.
- [`jig-core/src/suite.rs`](../../repos/jig-core/src/suite.rs): the suite registry.
- The client's plaintext cache: [`jig-client/src/secure.rs`](../../repos/jig-client/src/secure.rs)
  (shared with 3.4).

**Spec:** [Encryption](../../repos/jig-spec/src/encryption.md),
[JEP-0001](../../repos/jig-spec/jep/jep-0001-encryption-suites.md).

**Existing tests:**
- `jig-mls/tests/ciphersuite.rs`, which drives every entry point with real P-256 MLS;
- `jig-mls/tests/flow.rs`;
- `jig-server/tests/suite_vectors.rs`;
- `integration-tests/tests/h12_encrypted_channels.rs`, which searches the server's files for
  plaintext after a conversation.

**Known and stated:**
- One path stays ungated: a member's signed commit carrying an inline Add with a P-256 key
  package, which openmls verifies over public values only. The `v0.2.0-alpha.2` release notes and
  `deny.toml` (RUSTSEC-2026-0387) explain it.
- One device per DID.
- Restricted channels created as plaintext before D25 are frozen, and their history stays
  readable by the operator.

**Out of scope:**
- openmls itself, the RustCrypto primitives and RFC 9420. We want the integration reviewed, not
  the library.
- The `test-aead` suite, which is compiled only for conformance tests. CI checks that no
  release binary enables it.

**Must be code-complete first:** MLS channels across servers (F2 Task 7) and key-package
custodians (Task 8), if this area is to cover federation. Single-server MLS can be reviewed now.

### 3.2 The handshake and the TLS DID binding

**Questions for the auditor.**
- Can an operator or a network attacker strip, replay or forge the welcome?
- Can either of them move a signed welcome onto another TLS session?
- Can a server present answers that contradict the welcome without the client noticing?
- Can a self-signed certificate be accepted without the DID vouching for it?
- Do the client's pins and its `ingest` record chain checks hold against a server that forks or
  rewrites a channel's history?

**Threat-register rows:** OP-01, OP-02, OP-03, OP-06, OP-08, NS-01, TM-01, TM-02.

**Entry points.**

- [`jig-pipeline/src/handshake.rs`](../../repos/jig-pipeline/src/handshake.rs). The welcome
  (`jig-handshake-welcome-v2`, exporter label `EXPORTER-jig-handshake`) is handled by `begin`,
  `negotiate`, `seal`, `interpret_on`, `verify_signature` and `verify_offline`. The peer proof
  between servers (`jig-handshake-peer-v1`) is `peer_proof` and `verify_peer_proof`. It also holds
  the refusal envelope, close classes and skew bounds.
- [`jig-pipeline/src/ingest_record.rs`](../../repos/jig-pipeline/src/ingest_record.rs): the
  signed, hash-chained per-channel record (`jig-ingest-v2`).
- [`jig-server/src/v0_0_2_ws.rs`](../../repos/jig-server/src/v0_0_2_ws.rs) (`complete_hello`),
  [`server.rs`](../../repos/jig-server/src/server.rs) (TLS and exporter extraction),
  [`v0_0_2_federation.rs`](../../repos/jig-server/src/v0_0_2_federation.rs) and
  [`v0_0_2_federation_tls.rs`](../../repos/jig-server/src/v0_0_2_federation_tls.rs) (server to
  server).
- [`jig-core/src/tls_binding.rs`](../../repos/jig-core/src/tls_binding.rs): the certificate's
  binding to the server DID (`jig-tls-binding-v1`), served at `/.well-known/jig`. The nameserver's
  equivalent is at `/.well-known/jig-ns`.
- Client side, in [`jig-client/src/`](../../repos/jig-client/src/):
  - `tls.rs`: certificate checks, and following the key chain;
  - `pins.rs`: server, channel and name pins;
  - `chain.rs`: record-chain checks;
  - `evidence.rs`: kept contradictions;
  - `connection.rs`.

**Spec:** [JEP-0002](../../repos/jig-spec/jep/jep-0002-handshake.md),
[Handshake](../../repos/jig-spec/src/handshake.md) (its banner says which parts are current).
Design: [`2026-10-18-d11-handshake-completion-design.md`](../superpowers/specs/2026-10-18-d11-handshake-completion-design.md).

**Existing tests:** in `integration-tests/tests/`:
- `h_tls_did_binding.rs`, `h_tls_verifier.rs`, `h_nameserver_tls.rs`;
- `h_manifest_log.rs`, `h5_tofu_mismatch.rs`, `h7_unsafe_advertised.rs`, `h13_verified_names.rs`.

**Known and stated:**
- The first contact is trust on first use.
- Reputation in the welcome is always `null`.
- Members do not yet compare chains with each other (slice 5), so a server that shows different
  members different histories is caught only by a member who sees both.
- A gap seen on a live stream is not filled until the next history read.
- `dangerously_allow_plaintext_nameservers` exists as an explicit opt-out.

**Out of scope:**
- rustls and TLS 1.3 themselves.
- REST bound to the handshake, which is an open question in JEP-0002.

**Must be code-complete first:** D11 slices 5 (`seen` and head gossip) and 10 (`sequencer-set`).
Without them the review covers detection by one client, but not detection across members.

**Formal analysis (optional):** the welcome, the peer proof and the exporter binding are small
enough for a symbolic model (Tamarin or ProVerif). We would welcome a quote for it as a separate
line item.

### 3.3 Key links and chains

**Questions for the auditor.**
- Can a key link be forged, replayed onto another audience, or chained so that a client moves
  its pin to a key the old key never endorsed?
- Is a fork (two links from one key) always detected and kept?

**Threat-register rows:** OP-08, OP-02 (a fork is kept as evidence), AB-01 (rotation's proof of
control).

**Entry points.**

- [`jig-core/src/key_link.rs`](../../repos/jig-core/src/key_link.rs): the payload
  (`jig-key-link-v1`; `old`, `new`, `audience`, `issued_at`), a COSE_Sign signed by the old key
  then the new, `fork`.
- [`jig-core/src/cose.rs`](../../repos/jig-core/src/cose.rs) and
  [`dcbor.rs`](../../repos/jig-core/src/dcbor.rs): the COSE and deterministic-CBOR layer every
  newer signed object uses. Review it here once.
- [`jig-pipeline/src/handshake.rs`](../../repos/jig-pipeline/src/handshake.rs): `chain_moves`
  and `MAX_KEY_LINK_HOPS` (16).
- [`jig-client/src/server_key.rs`](../../repos/jig-client/src/server_key.rs): `rotate`, `link`,
  `refuse_relink`, behind `jig-server keys rotate` and `keys link`.
- [`jig-client/src/tls.rs`](../../repos/jig-client/src/tls.rs): following the chain.
- [`jig-client/src/evidence.rs`](../../repos/jig-client/src/evidence.rs): fork evidence.

**Spec:** [JEP-0012](../../repos/jig-spec/jep/jep-0012-key-links.md). Vectors are in
[`jep/vectors/0012/`](../../repos/jig-spec/jep/vectors/0012/).

**Existing tests:**
- `h_tls_did_binding.rs`, the case where a pinned server is followed to a new key only along its
  link;
- `jig-cli/tests/keys_smoke.rs`;
- a unit test that refuses a chain longer than 16 links.

**Known and stated:**
- A client pinned further back than the chain reaches must re-pin.
- Nameservers serve no key links yet.
- Rotation at a nameserver still signs the bare challenge (AB-01).

**Out of scope:** multi-device, which is not built.

**Must be code-complete first:** nothing.

### 3.4 Keys at rest

**Questions for the auditor.**
- Does the `.jigkey` envelope protect the seed against offline attack at the stated cost?
- Can a slot be added, removed or downgraded without the existing secret?
- Do the plaintext opt-outs stay opt-outs: never a fallback, and always loudly signposted?

**Threat-register row:** ID-04.

**Entry points.**

- [`jig-core/src/keystore.rs`](../../repos/jig-core/src/keystore.rs): the envelope, a random
  data key wrapped per slot, with the seed sealed under it. Passphrase slots use Argon2id. Look at
  `KdfParams`, `derive_file_key`, `seal`, `open`, `with_slot`, `without_slot`, and
  `MIN_SECRET_LEN` for secret slots.
- [`jig-client/src/identity.rs`](../../repos/jig-client/src/identity.rs) (the CLI identity and
  `JIG_KEYS_STORAGE`), [`keychain.rs`](../../repos/jig-client/src/keychain.rs) (OS keychain
  slots), [`secure.rs`](../../repos/jig-client/src/secure.rs) (sealed MLS state and the
  per-line sealed plaintext cache).
- [`jig-client/src/server_key.rs`](../../repos/jig-client/src/server_key.rs): the server and
  nameserver keys (`[keys] unlock`, `load_or_create`, `add_slot`).
- [`deploy/setup-server-key.sh`](../../deploy/setup-server-key.sh): seals a server key
  under a systemd credential.
- [`jig-cli/src/cmd/passphrase.rs`](../../repos/jig-cli/src/cmd/passphrase.rs) and the
  `jig keys protect` and recovery-kit commands.

**Spec:** [Crypto Primitives](../../repos/jig-spec/src/crypto.md). Design:
[`2026-10-18-identity-lifecycle-design.md`](../superpowers/specs/2026-10-18-identity-lifecycle-design.md).

**Existing tests:** `jig-cli/tests/keys_smoke.rs`, `jig-server/tests/boot_config.rs`,
`scripts/test-setup-server-key.sh` (run in CI).

**Known and stated:**
- Plaintext storage exists as an explicit opt-out (`JIG_KEYS_STORAGE=plaintext`,
  `[keys] storage = "plaintext"`).
- There is no defence against code running as the same user, or against keys in memory.

**Out of scope:** the OS keychains and systemd-creds themselves.

**Must be code-complete first:** nothing.

### 3.5 Proof-of-work, admission and request authentication

**Questions for the auditor.**
- Can a proof be reused across servers, subjects, actions or time?
- Can a solver pay less than the stated effort?
- Can the pricing be gamed to lock others out?
- Can a read be made without proof of possession, or replayed?
- Does any surface reach data before the three gates (authenticate, admit, authorize) have run?

**Threat-register rows:** AB-01, AB-02, AB-03, AB-05 (open: identity farming), TM-01, PV-03.

**Entry points.**

- [`jig-core/src/pow.rs`](../../repos/jig-core/src/pow.rs): the puzzle (`jig-pow-v1`; BLAKE3
  over verifier, subject, action, binding, salt and nonce), with `check`, `solve` and `meets`.
- [`admission_pow.rs`](../../repos/jig-core/src/admission_pow.rs): the server's admission form,
  plus a legacy form still accepted.
- [`jig-server/src/auth/`](../../repos/jig-server/src/auth/):
  - `authenticate.rs`: per-request proofs, and the WebSocket subscribe;
  - `replay.rs`: the replay guard;
  - `admission.rs`: bans, ruleset floors and the unknown-DID policy;
  - `rate.rs`: per-DID and per-address token buckets;
  - `authorize.rs`: `authorize_read`;
  - `disclosure.rs`: what a refusal reveals.
- [`jig-server/src/v0_0_2_admission.rs`](../../repos/jig-server/src/v0_0_2_admission.rs): the
  admission challenge route.
- [`jig-core/src/request_auth.rs`](../../repos/jig-core/src/request_auth.rs): the signed request
  hash (`jig-request-auth-v1`).
- [`jig-pipeline/src/authorize_write.rs`](../../repos/jig-pipeline/src/authorize_write.rs): the
  write gate, run inside `ingest` for every surface.
- [`jig-nameserver/src/v0_0_2_pow_policy.rs`](../../repos/jig-nameserver/src/v0_0_2_pow_policy.rs)
  (load-based pricing and the registration pool),
  [`v0_0_2_register.rs`](../../repos/jig-nameserver/src/v0_0_2_register.rs) and
  [`v0_0_2_rate_limit.rs`](../../repos/jig-nameserver/src/v0_0_2_rate_limit.rs).

**Spec:** [JEP-0008](../../repos/jig-spec/jep/jep-0008-proof-of-work.md), [Identity and
Reputation](../../repos/jig-spec/src/identity-and-reputation.md). Rationale:
[`nameserver-abuse-economics.md`](nameserver-abuse-economics.md). Vectors:
[`jep/vectors/0008/`](../../repos/jig-spec/jep/vectors/0008/).

**Existing tests:**
- `integration-tests/tests/h14_registration_pow.rs` and `h11_signed_reads.rs`;
- in `jig-server/tests/`: `admission.rs`, `admission_pow.rs`, `rate_limits.rs`,
  `authenticated_reads.rs`, `restricted_reads.rs`, `ws_delivery_authz.rs`.

**Known and stated:**
- Admission proof-of-work is off by default (D26).
- Blocks relayed by a peer or submitted by a bridge are not asked for it.
- Proof-of-work is a rate cost, not a Sybil defence (AB-05 is Open).

**Out of scope:**
- The economics of the chosen prices, which is a design question for JEP-0008 and not a code
  finding. Comments on it are welcome.
- Reputation, tribunals and transparency logs, which are not built (JEP-0009, JEP-0010).

**Must be code-complete first:** capacity pools at servers (R1 Task 5), if the review is to
cover them.

### 3.6 The federation contract and the follower stream

**Questions for the auditor.**
- Can a server take a share of a channel it was not granted, or keep one after it ended?
- Can an owner, a follower or a third party make a follower store a block or record the owner
  did not sequence?
- Is a fork in the owner's chain always detected, and is the evidence bounded?
- Can a peer exhaust another server through the stream?
- Can a follower relay a write the owner should refuse: into a channel it does not share, past
  its grant, from a banned author, or faster than the owner's limit for it?

**Threat-register rows:** OP-09, OP-06, PV-05, AB-03, AB-07, PV-01 (accepted).

**Entry points.**

- [`jig-core/src/contract.rs`](../../repos/jig-core/src/contract.rs): the signed offer, accept,
  refuse and end messages.
- In [`jig-pipeline/src/`](../../repos/jig-pipeline/src/):
  - `contracts.rs`: share and record checks;
  - `roles.rs`: rights at a chain position;
  - `follow.rs`: `ingest_sequenced`. By design it runs no admission and no write gate (JEP-0005
    rule 22a), so its checks carry all the weight;
  - `server_manifest.rs`: the peer policy.
- In [`jig-server/src/`](../../repos/jig-server/src/):
  - `v0_0_2_contract.rs`: offers and answers;
  - `v0_0_2_peer.rs`: peer frames after the peer proof;
  - `v0_0_2_stream.rs`: the follower stream and its per-peer limits;
  - `v0_0_2_relay.rs`: writes a follower relays to the owner (JEP-0005 rule 15), and their
    per-follower, per-channel limit;
  - `v0_0_2_federation.rs`: the older relay of open channels to listed peers.

**Spec:** [JEP-0005](../../repos/jig-spec/jep/jep-0005-channel-federation-contract.md),
[Federation](../../repos/jig-spec/src/federation.md). Design:
[`2026-10-18-federation-naming-and-contract-design.md`](../superpowers/specs/2026-10-18-federation-naming-and-contract-design.md).
Build plan:
[`2026-10-19-f2-channel-contract.md`](../superpowers/plans/2026-10-19-f2-channel-contract.md).

**Existing tests:**
- Unit tests in `follow.rs` and `contracts.rs`, and vectors in `jep/vectors/0005/`.
- `integration-tests/tests/h3_federation.rs`, which covers the older relay only.
- No end-to-end test of the contract yet; that is F2 Task 11.

**Out of scope:** federation with an implementation other than jig's. That comes after the MVP.

**Must be code-complete first.** F2 Tasks 7 to 11 must be merged before this area is audited
(relayed writes, Task 6, are merged, #316):
- MLS channels across servers;
- custodians;
- the contract half of a sequencer move;
- abuse defences;
- the end-to-end test.

Of all seven areas, this one is furthest from ready.

### 3.7 The Wasm sandbox and receipts

**Questions for the auditor.**
- Can a component reach anything outside its grant, or run past its fuel, deadline or memory
  cap?
- Can a component that fails the `jig-det-1` profile reach the compiler?
- Can a receipt be forged, replayed onto another block, or made to compare equal when outcomes
  differ?

**Threat-register rows:** SC-03, OP-07, OP-11, AB-04, PV-02.

**Entry points.**

- [`jig-runtime/src/component.rs`](../../repos/jig-runtime/src/component.rs): `compile_renderer`
  and `render`, with the per-store limits.
- [`engine.rs`](../../repos/jig-runtime/src/engine.rs): the deterministic engine configuration,
  fuel, epoch deadline and pooling allocator.
- [`grant_linker.rs`](../../repos/jig-runtime/src/grant_linker.rs): only granted imports are
  linked, and there is no WASI.
- [`jig-core/src/component_validation.rs`](../../repos/jig-core/src/component_validation.rs) and
  [`wasm_validation.rs`](../../repos/jig-core/src/wasm_validation.rs): the `jig-det-1` profile and
  the feature allowlist.
- [`jig-core/src/operator_policy.rs`](../../repos/jig-core/src/operator_policy.rs): what an
  operator authorises to run.
- [`jig-core/src/block_receipt.rs`](../../repos/jig-core/src/block_receipt.rs): `exec`, `sealed`
  and `accepted` receipts (`jig-block-receipt-v1`), `compare`, `SignedReceipt::open`.
- [`jig-pipeline/src/executor.rs`](../../repos/jig-pipeline/src/executor.rs),
  [`receipts.rs`](../../repos/jig-pipeline/src/receipts.rs) (legacy receipts, read only), and
  [`jig-client/src/verify.rs`](../../repos/jig-client/src/verify.rs) (re-execution).

**Spec:** [JEP-0006](../../repos/jig-spec/jep/jep-0006-block-abi.md),
[JEP-0011](../../repos/jig-spec/jep/jep-0011-block-programs.md),
[Receipts](../../repos/jig-spec/src/receipts.md),
[Block Execution](../../repos/jig-spec/src/block-execution.md). WIT is in
[`repos/jig-spec/wit/`](../../repos/jig-spec/wit/).

**Existing tests:**
- `jig-runtime/tests/`: `block_abi_vectors.rs`, `component_outcomes.rs`, `epoch_ticker.rs`,
  `text_block_component.rs`;
- `integration-tests/tests/client_verifies_render.rs` and `federated_render_agrees.rs`;
- `block-abi-vectors.yml`, which runs the vectors on aarch64, native and Pulley.

**Known and stated:**
- Only the `renderer` world runs. No host interface has a provider yet.
- A divergence is marked, not recorded or reported.
- A withheld receipt cannot be told from a late one.

**Out of scope:** wasmtime and Cranelift themselves. We track their advisories, and `deny.toml`
suppresses none of them.

**Must be code-complete first:** nothing for the `renderer` world. Host interfaces (lane C) will
need a second, smaller review when they land.

## 4. How to split it

Three options, from cheapest in coordination to cheapest in calendar time.

**Option A: one firm, two phases (decided).**
- **Phase 1, as soon as a firm is engaged:** areas 3, 4, 5 and 7, plus single-server MLS (area 1
  without federation). This code is complete and unlikely to be replaced, which is D27's test.
- **Phase 2, at G3:** area 6, the federated half of area 1, and area 2 once slices 5 and 10 have
  landed. Phase 2 also re-tests the fixes from Phase 1.

One firm keeps one picture of the system, and the COSE and deterministic-CBOR layer is reviewed
once. Phase 1 starts before G3, which reads D27 as "review code that is done" rather than "wait
until everything is done". DJ confirmed that reading on 2026-10-25.

**Option B: two firms, split by expertise.**
- **A cryptographic-protocol firm:** areas 1, 2, 3 and 4. They share the identity, COSE and TLS
  layers, and it can quote the formal model in 3.2.
- **An application-security firm:** areas 5, 6 and 7. These are abuse resistance, distributed
  state and sandboxing.

This gives deeper specialist coverage, but costs two onboardings, and the seam between the
handshake (2) and federation (6) has to be reviewed twice or deliberately assigned to one firm.
Either option can be phased as in A.

**Option C: one firm, one engagement at G3.** This is the plainest reading of D27. It is the
simplest contract, but it is the latest and largest, and it leaves the finished areas unreviewed
until federation is done.

## 5. Deliverables we ask for

1. **A report per phase.** For each finding:
   - severity, on a scale the firm states (CVSS or its own);
   - the affected commit and code path;
   - a reproduction or proof of concept;
   - the threat-register rows it breaks, or a proposed new row;
   - a recommended fix.
2. **Coverage notes.** What was reviewed, at what depth, and what was not. A clean area with no
   coverage notes is not a clean area.
3. **Comments on the threat register.** Rows whose MUST is wrong or missing, and rows whose
   status cell overstates what the code does.
4. **A fix review.** A re-test of every fix at a later tag, with each finding's status updated.
5. **A publishable summary.** We publish it under [`docs/security/`](./) once fixes ship.
6. **Optional:** the symbolic model of the handshake (3.2), with its sources.

## 6. Before the first engagement

Things on our side, in order:

1. **Freeze a commit.** Tag it, and keep it buildable from a clean checkout with
   `rust-toolchain.toml` and `repos/Cargo.lock`.
2. **Make the threat register's status cells true at that commit.** AB-02, which said the
   nameserver asks for no proof-of-work, is corrected in #324.
3. ~~**Fix or remove the jig-runtime fuzz crate.**~~ Done (#331). The broken crate is gone,
   and [`repos/fuzz`](../../repos/fuzz/) has eight cargo-fuzz targets over what jig decodes
   from the network: COSE, dCBOR, the WebSocket envelope, `ingest` records, MLS delivery and
   group messages, the follower stream's peer frames, and a block's Wasm component. The
   `Fuzz` workflow runs each briefly on a pull request that touches them, and longer once a
   week. `SignedReceipt::open` has no target yet.
4. **Write a reviewer's quick start:** how to build, run the integration tests, and start two
   servers and a nameserver on loopback. The `integration-tests` harness does this already; it
   needs a short README.
5. **Name a contact** for questions during the engagement, with an agreed response time.
6. **For Phase 2:** F2 Tasks 0c and 7 to 11, and D11 slices 5 and 10, merged; JEP-0005 and
   JEP-0002 updated to match.

## 7. Questions for DJ

1. ~~Option A, B or C?~~ Decided: Option A.
2. ~~Does Phase 1 starting before G3 fit D27?~~ Decided: yes.
3. Budget and timing, which decide how deep each area goes.
4. Is the formal model in 3.2 wanted?
5. Is publishing the report, or a summary, the default?
