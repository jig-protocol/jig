# Architecture tour

A map of the code for someone starting on jig. It names the crates, follows one block through
the server, and points at the spec for each part. It describes `main` as of 2026-10-25; for what
works and what does not, read [`RELEASE_READINESS.md`](RELEASE_READINESS.md) and the
[threat register](../repos/jig-spec/src/threat-register.md). For where it is going, read
[`ROADMAP.md`](ROADMAP.md).

Paths are relative to [`repos/`](../repos/), the Cargo workspace. The repository root holds
docs, scripts, the installer and CI.

## The model in five lines

- **Everything is a block:** a signed manifest, optionally with a Wasm component, addressed by a
  BLAKE3 CID.
- **An identity is a key.** A `did:jig` is an ed25519 public key, and every signature is checked
  against the DID itself. No registry is needed to verify one.
- **Servers are untrusted.** Clients pin what a server signed and fail closed on contradictions
  (D11).
- **Channels are encrypted per channel.** The suite is fixed at creation; `mls` is the one real
  suite, and restricted channels and DMs always use it (D25).
- **Federation is a contract between servers,** not shared semantics (D12, JEP-0005).

## Crates

| Crate | Role | Depends on (jig crates) |
| --- | --- | --- |
| [`jig-core`](../repos/jig-core/) | Protocol primitives, pure code: DIDs, signing, COSE and deterministic CBOR, manifests and bundles, request auth, key links, the key store, TLS binding, the suite registry, receipts, naming objects, proof-of-work, contract messages, Wasm and component validation | none |
| [`jig-pipeline`](../repos/jig-pipeline/) | The write path shared by server and nameserver: `ingest`, the write gate, the MLS gate, effects, SQLite persistence, fanout, `ingest` records, the follower stream, the handshake | jig-core, jig-mls, text-block; jig-runtime behind the `executor` feature |
| [`jig-server`](../repos/jig-server/) | The reference server, binary `jig-server`: HTTP and WebSocket surfaces, the three auth gates, federation, contracts, the manifest log | most of the workspace |
| [`jig-client`](../repos/jig-client/) | Client library: connection and handshake checks, pins, identity and keychain, chain and evidence checks, proof-of-work, re-execution of receipts | jig-core, jig-pipeline, jig-mls |
| [`jig-cli`](../repos/jig-cli/) | The `jig` binary: `init`, `keys`, `channel`, `chat`, `send`, `tail`, `dm`, `ns`, `block`, `trust`, `receipt` | jig-core, jig-client, jig-mls; jig-runtime optionally |
| [`jig-config`](../repos/jig-config/) | The server's config types; every table denies unknown keys | none |
| [`jig-mls`](../repos/jig-mls/) | MLS (RFC 9420) on openmls: the server's validating delivery service and the client's group member | jig-core |
| [`jig-nameserver`](../repos/jig-nameserver/) | Verified names: registration with proof-of-work, resolution, rotation; links no Wasm engine | jig-core, jig-config, jig-pipeline, jig-client |
| [`jig-runtime`](../repos/jig-runtime/) | Runs `jig:block` components on wasmtime under the `jig-det-1` determinism profile | jig-core |
| [`text-block`](../repos/text-block/) | The canonical text-render block, built as a `jig:block/renderer` component and committed under `artifacts/` | none |
| [`bridges/core`](../repos/bridges/core/), [`bridges/email`](../repos/bridges/email/) | The bridge trait, and the in-process email bridge | core: none; email: bridges/core, jig-core, jig-client |
| [`integration-tests`](../repos/integration-tests/) | Starts real servers and nameservers on loopback; the `h*` tests are end-to-end scenarios | everything |
| [`jig-spec`](../repos/jig-spec/) | The specification (mdBook), JEPs, schemas, vectors and WIT. Not a workspace member | — |

## One block through the server

Every way a block gets into a server ends in one function,
[`jig_pipeline::ingest`](../repos/jig-pipeline/src/ingest.rs), with an `IngestSource` saying where
it came from: a local client, a federated peer, a channel-ops endpoint, or a bridge. The stages
are:

```text
ingest ─▶ authorize ─▶ effect ─▶ persist ─▶ fanout
```

1. **Ingest.** Verify the author's signature (step 1). Run **admission** on the DID it
   established: bans, ruleset floors, the unknown-DID policy, proof-of-work and the per-DID rate
   limit (step 1b, through the `Admission` trait; the server's implementation is in
   [`jig-server/src/auth/`](../repos/jig-server/src/auth/)). Resolve identity, check the block
   kind and that its channel exists.
2. **Authorize.** The write gate,
   [`authorize_write.rs`](../repos/jig-pipeline/src/authorize_write.rs), decides whether this
   author may post to or change this channel: visibility, membership, ownership and roles. Then
   the clock-skew bound, execution of the block's component when it has one, and the **MLS
   gate** ([`mls_gate.rs`](../repos/jig-pipeline/src/mls_gate.rs)): the channel's suite is fixed
   at creation, plaintext into an encrypted channel is refused, and every MLS commit is validated
   against the group's public state.
3. **Effect.** [`effect.rs`](../repos/jig-pipeline/src/effect.rs) applies what the block means:
   a channel created, a member added or removed, a channel promoted or archived. Roles keep no
   row of their own: they are read back from the channel's chain.
4. **Persist.** [`persist.rs`](../repos/jig-pipeline/src/persist.rs) stores the block together
   with the next link of the channel's signed, hash-chained `ingest` record (JEP-0002 rule 9) in
   one transaction, and the block's receipt.
5. **Fanout.** [`fanout.rs`](../repos/jig-pipeline/src/fanout.rs) delivers to subscribers. A
   block a peer relayed goes to local subscribers only.

The surfaces that call it: `POST /api/v1/blocks`
([`v0_0_2_blocks.rs`](../repos/jig-server/src/v0_0_2_blocks.rs)), the WebSocket `submit` frame
([`v0_0_2_ws.rs`](../repos/jig-server/src/v0_0_2_ws.rs)), channel ops under
`/api/v1/channels` ([`v0_0_2_admin.rs`](../repos/jig-server/src/v0_0_2_admin.rs); user-signed
bundles, no operator credential), bridges
([`v0_0_2_bridges.rs`](../repos/jig-server/src/v0_0_2_bridges.rs)) and blocks relayed by a
listed peer ([`v0_0_2_federation.rs`](../repos/jig-server/src/v0_0_2_federation.rs)).

**The one exception, by design:** a channel another server sequences arrives on the follower
stream ([`v0_0_2_stream.rs`](../repos/jig-server/src/v0_0_2_stream.rs) →
[`follow::ingest_sequenced`](../repos/jig-pipeline/src/follow.rs)). The follower checks the
author's signature and the owner's record chain, applies the effect and fans out locally, but
runs no admission and no write gate: the owner gated the block before it sequenced it
(JEP-0005 rule 22a).

Reads go through the same three gates, in the order authenticate, admit, authorize. A read
carries a per-request ed25519 proof over the request
([`jig-core/src/request_auth.rs`](../repos/jig-core/src/request_auth.rs)), checked with a
replay guard ([`auth/authenticate.rs`](../repos/jig-server/src/auth/authenticate.rs),
[`auth/replay.rs`](../repos/jig-server/src/auth/replay.rs)), then admission, then
`authorize_read` ([`auth/authorize.rs`](../repos/jig-server/src/auth/authorize.rs)). Per-address
rate limits sit in front of all of it.

## Identity and keys

- **DIDs.** `did:jig:z` followed by the lowercase, unpadded base32 of the 32-byte ed25519 public
  key ([`jig-core/src/did.rs`](../repos/jig-core/src/did.rs)). Spec: [Crypto
  Primitives](../repos/jig-spec/src/crypto.md) and [Identity and
  Reputation](../repos/jig-spec/src/identity-and-reputation.md).
- **Signed objects.** Newer objects are COSE_Sign1 over deterministic CBOR, each with its own
  `domain` string ([`cose.rs`](../repos/jig-core/src/cose.rs),
  [`dcbor.rs`](../repos/jig-core/src/dcbor.rs)): receipts, key links, naming attestations,
  contract messages, `ingest` records.
- **Key links** ([JEP-0012](../repos/jig-spec/jep/jep-0012-key-links.md),
  [`key_link.rs`](../repos/jig-core/src/key_link.rs)) move a DID's standing to a new key; the old
  and new keys both sign. A server serves its links as a chain at `/.well-known/jig`, and
  clients follow it hop by hop, up to 16 links.
- **Keys at rest** ([`keystore.rs`](../repos/jig-core/src/keystore.rs)): a `.jigkey` file holds
  the seed sealed under a data key, wrapped by one or more slots (a passphrase, the OS keychain, a
  systemd credential). The CLI's identity, its MLS state and plaintext cache, and the server's and
  nameserver's own keys are all sealed this way.
- **The server's TLS certificate** is vouched for by its DID
  ([`tls_binding.rs`](../repos/jig-core/src/tls_binding.rs)), published at `/.well-known/jig`.
  Clients and peers accept a self-signed certificate only through that binding.

## The handshake

Every WebSocket connection starts with `hello` and a signed `welcome`
([JEP-0002](../repos/jig-spec/jep/jep-0002-handshake.md),
[`jig-pipeline/src/handshake.rs`](../repos/jig-pipeline/src/handshake.rs)). The welcome signs the
protocol version, suites, capabilities, the server manifest's CID, the admission price and the
connection's TLS exporter, so it cannot be replayed onto another TLS session. The client pins the
server's DID and each channel's suite and creation block
([`jig-client/src/pins.rs`](../repos/jig-client/src/pins.rs)), checks the `ingest` record chain,
and keeps contradictions as evidence ([`evidence.rs`](../repos/jig-client/src/evidence.rs)).
Servers handshake with each other the same way, both sides proving their DID.

## MLS

An encrypted channel is one MLS group ([`jig-mls`](../repos/jig-mls/), openmls 0.9). jig speaks
one ciphersuite, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, because the MLS signature key is
the DID's ed25519 key ([`credential.rs`](../repos/jig-mls/src/credential.rs) binds them).

- **Server:** a delivery service that holds no group secret.
  [`delivery.rs`](../repos/jig-mls/src/delivery.rs) keeps each group's public state and validates
  every commit and application message against it. It refuses group infos, key packages and
  welcomes in any other ciphersuite before running their crypto (#303).
- **Client:** [`member.rs`](../repos/jig-mls/src/member.rs) holds the group secrets, sealed at
  rest.
- **Suites:** the registry is [`jig-core/src/suite.rs`](../repos/jig-core/src/suite.rs)
  (`none`, `mls`, and `test-aead`, which is compiled only for the conformance tests).
  [JEP-0001](../repos/jig-spec/jep/jep-0001-encryption-suites.md) says how a suite is added, and
  [`jig-spec/vectors/suites/`](../repos/jig-spec/vectors/suites/) holds the conformance vectors.
  Design rationale: [`security/encryption.md`](security/encryption.md).

## Federation

- **Peers** are listed in config with the DID each must present, and dialled over the mutual
  handshake ([`v0_0_2_federation.rs`](../repos/jig-server/src/v0_0_2_federation.rs)). A relayed
  block runs through `ingest` like a local one.
- **The channel contract** ([JEP-0005](../repos/jig-spec/jep/jep-0005-channel-federation-contract.md)):
  each channel has one sequencing server. Another server asks for a share of it with a signed
  offer, and the owner accepts or refuses
  ([`jig-core/src/contract.rs`](../repos/jig-core/src/contract.rs),
  [`v0_0_2_contract.rs`](../repos/jig-server/src/v0_0_2_contract.rs)). A follower then takes the
  owner's blocks and records on the follower stream described above. The peer policy is published
  in the signed server manifest ([`server_manifest.rs`](../repos/jig-pipeline/src/server_manifest.rs)).
- **Writes through a follower** ([`v0_0_2_relay.rs`](../repos/jig-server/src/v0_0_2_relay.rs)): a
  client writing to a channel its server carries for the owner has the write relayed to the owner,
  if the share's grant covers it. The owner runs it through `ingest` as a relayed write, and the
  block comes back on the follower stream with the owner's record.
- **Not built yet:** MLS channels across servers. The follower
  stream refuses MLS channels. The build plan is
  [`2026-10-19-f2-channel-contract.md`](superpowers/plans/2026-10-19-f2-channel-contract.md).

## Blocks and the runtime

A block may carry a `jig:block` component
([JEP-0006](../repos/jig-spec/jep/jep-0006-block-abi.md), WIT in
[`jig-spec/wit/`](../repos/jig-spec/wit/)). [`jig-runtime`](../repos/jig-runtime/) checks it
against the `jig-det-1` profile, links only the imports its grant names (no WASI), and runs it
with fuel, a wall-clock deadline and a memory cap
([`component.rs`](../repos/jig-runtime/src/component.rs),
[`engine.rs`](../repos/jig-runtime/src/engine.rs)). Today the server runs one component, the
text renderer in [`text-block`](../repos/text-block/).

A run produces a signed receipt ([`jig-core/src/block_receipt.rs`](../repos/jig-core/src/block_receipt.rs),
[Receipts](../repos/jig-spec/src/receipts.md)). A receipt claims an outcome, not a cost: a client
checks it by running the same component on the same input and comparing outcome hashes. Fuel is
recorded as telemetry and never compared.

## Nameserver

[`jig-nameserver`](../repos/jig-nameserver/) maps names such as `alice@example.org` to DIDs
([JEP-0004](../repos/jig-spec/jep/jep-0004-verified-naming.md)). A registration proves control
of the DID and pays proof-of-work priced by load
([JEP-0008](../repos/jig-spec/jep/jep-0008-proof-of-work.md),
[`jig-core/src/pow.rs`](../repos/jig-core/src/pow.rs)). The nameserver signs a COSE attestation
([`jig-core/src/naming.rs`](../repos/jig-core/src/naming.rs)), and clients check it against the
suffix's delegation and pin the result. A nameserver serves TLS bound to its own DID.
Operating one: [`jig-nameserver/OPERATOR_GUIDE.md`](../repos/jig-nameserver/OPERATOR_GUIDE.md).

## Where the specs and decisions live

| What | Where |
| --- | --- |
| Normative spec, by chapter | [`repos/jig-spec/src/`](../repos/jig-spec/src/) (mdBook; [`SUMMARY.md`](../repos/jig-spec/src/SUMMARY.md) is the table of contents). Each chapter opens with a banner saying what `main` implements |
| JEPs: one per protocol change, written before code | [`repos/jig-spec/jep/`](../repos/jig-spec/jep/), from the [template](../repos/jig-spec/jep/JEP-TEMPLATE.md); test vectors in [`jep/vectors/`](../repos/jig-spec/jep/vectors/) |
| Security status, row by row | [Threat register](../repos/jig-spec/src/threat-register.md) |
| JSON schemas, WIT, suite and block-ABI vectors | [`schemas/`](../repos/jig-spec/schemas/), [`wit/`](../repos/jig-spec/wit/), [`vectors/`](../repos/jig-spec/vectors/) |
| Decisions (D1–D28) and open questions | [`ROADMAP.md`](ROADMAP.md) |
| Why something was built the way it was | [`docs/superpowers/specs/`](superpowers/specs/) (designs) and [`plans/`](superpowers/plans/) (build plans) |
| Rationale behind the spec | [`docs/security/`](security/), the [whitepaper](whitepaper/trust-federation-identity.md) |

## Starting out

[`scripts/dev-setup.sh`](../scripts/dev-setup.sh) checks for the toolchain and tools CI uses;
`--install` installs what is missing. [`CONTRIBUTING.md`](../CONTRIBUTING.md) has the build and
pull-request rules, [`OWNERSHIP.md`](OWNERSHIP.md) says who reviews what, and
[`GOOD_FIRST_CONTRIBUTIONS.md`](GOOD_FIRST_CONTRIBUTIONS.md) lists places to start.
