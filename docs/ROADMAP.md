# jig roadmap

Where jig is going, in phases from a public alpha (`v0.1`) to a distributed OS (`v1+`), and the
decisions that shape the path. Last updated 2026-10-13.

**Status in one line:** v0.1 groundwork is tagged (`v0.1.0-alpha.1`, no published release yet),
and v0.2's per-channel MLS encryption is merged on `main`. For what works today, gate by gate, see
[`RELEASE_READINESS.md`](RELEASE_READINESS.md). This doc is the direction, not the status page.

Each phase lands as JEPs in [`repos/jig-spec/jep/`](../repos/jig-spec/jep/) before code. Milestone
names in PRs map to phases: **M1** = phase 0 (`v0.1`), **M2** = phase 1 (`v0.2`), and so on.

---

## Goals

jig is an open protocol and reference implementation for federated, signed messages that can carry
sandboxed Wasm code. The aim is to climb from message passing to an **executable web** (blocks
rendered instead of HTML) and then to a **distributed OS**, where blocks are processes and the
network is the machine: Alan Kay's "objects all the way down".

### Product constraints

1. **curl to hello world in under 60 seconds** on the default path, Linux and macOS.
2. **Runs on a potato, scales to the data center.** The same server family runs on a Pi-class
   device, as a Wasm component, and on a large cluster.
3. **One spectrum, message passing to distributed OS.** Every layer is built so the next can sit
   on it.
4. **Secure and E2EE by default.** Until it is the default, releases say plainly what is not
   encrypted.
5. **Open and implementable by others.** The spec comes first, and conformance tests make a second
   implementation possible.

### Architectural principles

- **Everything is a block.** A signed manifest (optionally carrying Wasm) addressed by a BLAKE3 CID.
  Identities are self-certifying `did:jig` keys.
- **One write path.** Every surface goes through `ingest → authorize → effect → persist → fanout`.
- **Encryption is composable and chosen by the server operator.** The envelope carries a
  cipher-suite identifier ([JEP-0001](../repos/jig-spec/jep/jep-0001-encryption-suites.md)). The
  default is MLS, and nothing in the protocol stops an operator running another scheme.
- **MLS for everything by default.** There is no separate DM scheme. A DM is a channel with locked
  membership, so a conversation grows from DM to group DM to channel without changing schemes.
- **Server operators are untrusted.** Every connection starts with a mandatory handshake
  ([JEP-0002](../repos/jig-spec/jep/jep-0002-handshake.md)), and clients fail closed when it is
  missing or contradicted. The [threat register](../repos/jig-spec/src/threat-register.md) tracks
  operator attacks.
- **Federation is a data contract, not shared semantics.** A cross-server channel is specified by a
  contract over the transmission between servers, including its encryption suite. Servers own
  their encryption; one that can't speak a channel's suite is refused, like a failed TLS handshake.
  Clients and use cases are not typed at this layer, so a chat server and an industrial
  orchestrator can federate a channel without knowing what the other is.
- **`jig-server` is both a Wasm-block host and a Wasm program.** It runs Wasm blocks, and it
  compiles to and runs on Wasm itself.
- **Block nesting is a first-class ABI concern.** Blocks embed or invoke other blocks, with
  capabilities attenuated at each level.
- **Servers are findable from inside the protocol.** Discovery runs through nameservers, with
  proof-of-work and reputation designed in rather than bolted on
  ([JEP-0003](../repos/jig-spec/jep/jep-0003-server-discovery.md)).
- **Keep the spec small.** `jig-spec` holds final decisions, normative and terse. Modelling,
  alternatives and justifications go in `docs/` and link to the spec.

---

## Phases

Each phase has an exit criterion. Phases 2 and 3 can overlap.

| Phase | Theme | Exit criterion |
| --- | --- | --- |
| **0. Public alpha** (`v0.1`, M1) | Honest, installable, green | A stranger goes `curl` → `#hello` in under 60s on Linux and macOS, measured in CI |
| **1. Secure by default** (`v0.2`, M2) | E2EE, hostile-operator resistance, abuse resistance | The spec's privacy claims are true; the operator cannot read restricted content; a hostile operator's downgrade or false handshake is detected; a second suite plugs in without wire changes; two unlike servers federate a channel through the contract alone; an external audit report is published |
| **2. Executable blocks** (`v0.3`) | From pure functions to capability-bearing programs | A third party writes, signs and ships a block in under 10 minutes that runs identically on client and server; a nested block composes with capability attenuation verified by tests |
| **3. The executable web client** | "Not HTML", made visible | A "page" (a live doc, a poll, a game) authored as blocks and browsable with no developer-authored HTML |
| **4. Potato → data center** | Scale both ways | The same server runs natively on a Pi Zero 2, as a Wasm component on a Wasm host, and on a 50-node cluster; a deployment holds 1M members; benchmarks are published |
| **5. Enterprise / industrial** | Operate it like infrastructure | A production enterprise deployment runs unmodified OSS jig |
| **6. Distributed OS** (`v1+`) | Blocks as processes, the network as the machine | A multi-node app whose processes migrate across nodes with no central coordinator, every effect capability-checked and receipted |

### Phase 0: public alpha (`v0.1`)

Positioning: federated, signed, Wasm-sandboxed messaging; not yet encrypted. The wire and spec
reserve the hooks for encryption so that turning it on in v0.2 changes a value, not the format.

| # | Item | Status |
| --- | --- | --- |
| 1 | Green `main`: patch advisories, pinned toolchain (`rust-toolchain.toml`), daily advisory check | Done |
| 2 | Release pipeline: static musl x86_64/aarch64 + Apple Silicon, checksums, signatures | Pipeline built and dry-run green; **`v0.1.0-alpha.1` release runs failed, no release published** |
| 3 | 60-second default path: working `install.sh`, channel ops out of `[debug]`, CI smoke test | Done (`install-smoke.yml`, Linux + macOS) |
| 4 | Security communication: root `SECURITY.md`, private vulnerability reporting, "not implemented" banners on the spec | Done |
| 5 | Scrub history, go public with full history, archive the pre-monorepo repos | Done |
| 6 | Clear reachable `deny.toml` suppressions | See [`RELEASE_READINESS.md`](RELEASE_READINESS.md) §1.7 |
| 7 | Encryption hooks: suite field in envelope and manifest, version gates, typed config, JEP | Done ([JEP-0001](../repos/jig-spec/jep/jep-0001-encryption-suites.md)) |
| 8 | Spec licence to CC-BY-4.0 | Done |
| 9 | Threat register: malicious operators in scope | Done ([threat register](../repos/jig-spec/src/threat-register.md)) |
| 10 | Mandatory handshake: spec | Done ([JEP-0002](../repos/jig-spec/jep/jep-0002-handshake.md)) |
| 11 | Mandatory handshake: version + capabilities + suite in server and client | Done |
| 12 | Public server trial: an experimental, unencrypted server as an optional hello-world target | Open |
| 13 | `CONTRIBUTING.md` (with the dependency rule below), `CODE_OF_CONDUCT.md`, templates, `CODEOWNERS` | Done |
| 14 | CLI papercuts: `jig read`, `jig --version`, client reconnect with backoff, `block` stubs | `read` and `--version` done; reconnect and `block` stubs open |
| 15 | `publish = false` on crates not meant for crates.io | Open |
| 16 | CI: macOS job, clippy on every crate, federation and bridge counters in `/metrics`, scope jobs by changed paths (note below) | Partial (macOS covered by the install smoke test only); path scoping open |
| 17 | Collapse the hybrid server config into one struct with `deny_unknown_fields` | Open |
| 18 | Run federated blocks through the write gate; "trusted peer" becomes explicit config | Open (since v0.2 only open, unencrypted channels federate) |
| 19 | Discovery JEP stub | Done ([JEP-0003](../repos/jig-spec/jep/jep-0003-server-discovery.md)) |
| 20 | Reserve `jig-*` package names (crates.io, npm, Homebrew, container registries) | Open, low priority |
| 21 | Move the Riverdance GUI out of the protocol monorepo | Done (it now lives in its own repository) |

Explicitly not required for v0.1: E2EE itself, a GUI, more bridges, reputation scoring, discovery
beyond the JEP stub, the reputation part of the handshake, and Windows.

**Note on item 16: scope CI by changed paths.** Every pull request runs the full `workspace` job
(fmt, clippy and nextest across the workspace) and `wasm-build`, even when it only touches docs.
What to watch when scoping it:

- `workspace`, `wasm-build` and `dependency-policy` are required checks. A workflow-level `paths:`
  filter leaves a required check unreported, which blocks the merge. Decide per job instead: a
  first job lists the changed files (`git diff --name-only` against the merge base, since the
  allowed actions exclude third-party path filters), and later jobs skip with a job-level `if:`.
  A skipped job reports success.
- Count `repos/Cargo.lock`, `rust-toolchain.toml`, `deny.toml` and `.github/workflows/**` as code.
  `fuel-portability.yml` already filters on `repos/jig-runtime/**` alone, so a lockfile-only
  wasmtime bump, the change most likely to move fuel, skips it today.
- Keep `dependency-policy` unconditional. It is quick, and the advisory database changes whatever
  the diff touches.

### Phase 1: secure by default (`v0.2`)

Merged so far (M2, [design](superpowers/specs/2026-10-11-m2-mls-and-channel-dynamics-design.md)):
MLS (RFC 9420, `openmls`) per channel, with the server as a validating delivery service that holds
no group secret; DMs as locked encrypted channels; `member-remove` (kick and leave); channel
dynamics in the CLI.

Still to do in this phase:

- **Crypto design (D13):** how a non-MLS scheme (for example Signal's post-quantum protocol) plugs
  in, versus PQ-hybrid MLS suites, with a conformance test per suite.
- **Full handshake (D11):** reputation and real suites; clients detect false answers and
  downgrades, mitigating each threat-register entry.
- **Federation as a data contract (D12):** encrypted channels across servers, with the suite fixed
  in the channel's initial contract, and nameserver-led shared contracts for trusted subnets.
- Multi-device and key rotation; a server-key rotation ceremony.
- TLS on by default (self-signed + TOFU, or ACME); rate limiting and proof-of-work at admission.
- Federation through the write gate, with signed peer policy.
- An external security audit of `jig-core`, `jig-runtime`, the crypto and the handshake.

### Phase 2: executable blocks (`v0.3`)

- The **Wasm Component Model + WIT** as the block ABI.
- Host functions granted strictly through manifest capabilities (the existing `capability_dsl`):
  storage, fetch-block-by-CID, post-message, timer.
- Per-block persistent state, CID-addressed.
- The client runs the same runtime (`jig-client` embeds `jig-runtime`).
- `jig block new/lint/sign/run` work; block templates; a block registry by CID.
- **Block nesting:** a block embeds or invokes others by CID, with capabilities attenuated and fuel
  accounted to the parent. This is the prerequisite for servers serving servers.

### Phase 3: the executable web client

A real client that renders blocks through a **UI ABI** (a declarative view tree or canvas surface
the block exports, not DOM/HTML). Links are CIDs plus DIDs; navigation is fetching and running
blocks. A web build runs through a Wasm-in-browser shell for reach.

### Phase 4: potato → data center

- **Potato:** musl/aarch64/armv7/riscv64 builds; wasmtime's Pulley interpreter as a no-JIT mode;
  memory budget (for example under 32 MB RSS idle) and binary budget (≤ 25 MB) enforced in CI.
- **Wasm-hosted server (D8):** `jig-server` compiles to and runs as a WASI 0.2 component, with
  storage, sockets and clocks behind host traits.
- **Big iron:** a pluggable storage trait (SQLite → Postgres / FoundationDB / object store for
  blobs); stateless front ends plus a sharded fanout tier; a NATS- or QUIC-based inter-node bus;
  OpenTelemetry; real Helm/Terraform.
- A million-member deployment (mostly inactive members) as the scale proof.
- Published benchmarks: 10k msg/s on a $5 VPS, then N-node linear scaling.

### Phase 5: enterprise / industrial

SSO → DID binding, org policy blocks, audit-log export, retention and legal hold over E2EE (key
escrow only as opt-in org policy, never the default), a FIPS crypto mode (which pluggable suites
make possible), multi-region federation, an HA nameserver, offline / intermittent-link mode for
industrial sites, and LTS releases.

### Phase 6: distributed OS (`v1+`)

- An actor model: long-lived block instances addressed by DID+CID, exchanging messages.
- Object-capability security: capability references passed in messages, so you can only call what
  you were handed.
- A scheduler with fuel as the currency and receipts as the accounting.
- Migration of instances between nodes; a durable replicated object store; supervision trees.
- A governance layer as blocks.
- **Research: servers serving servers.** A server transmits blocks that are themselves servers.
  This ships only after a published threat model covering self-replication, resource
  amplification, capability escalation across levels, the signing chain, and kill switches.

---

## Cross-cutting tracks

- **Spec first, with conformance tests**, so a second implementation is possible.
- **Fuel as a protocol quantity:** settle
  [`investigations/2026-08-11-fuel-portability.md`](investigations/2026-08-11-fuel-portability.md).
  If receipts carry cost across nodes, the pricing schedule must be versioned and enforced.
- **Encryption-suite registry:** suites are spec-level identifiers with their own JEP and
  conformance vectors. Adding a suite never needs a wire-format change.
- **Threat register:** every JEP adds or updates its entries, and each release notes which entries
  it mitigates.
- **Discovery design project (D15):** discovery, exposure, activation, search, reputation and
  proof-of-work, and nameserver governance (delisting bad actors without central control). It runs
  alongside phases 1–4 with its own milestones.
- **Bridges as onboarding:** email first, then IRC, then ActivityPub/ATProto.
- **The dependency rule:** jig never depends on downstream or proprietary code. Products built on
  jig depend on it, never the reverse ([`CONTRIBUTING.md`](../CONTRIBUTING.md)).

---

## Decisions log

Settled on 2026-10-05 unless noted. Open items follow the table.

| # | Question | Decision |
| --- | --- | --- |
| D1 | E2EE in v0.1 or v0.2? | v0.2. v0.1 reserves the wire and spec hooks for operator-chosen encryption. |
| D2 | HPKE / `age` sealing, or MLS? | MLS for everything. A DM is a channel with locked membership, so DM → group DM → channel is a membership change. |
| D4 | A public jig server as a hello-world target? | Try one in v0.1, experimental and unencrypted, kept off the critical 60-second path. |
| D5 | Go public with history, or squash? | Public with full history after a secrets scrub; archive the pre-monorepo repos. Done 2026-10-06. |
| D6 | Publish crates, or binaries only? | Reserve names now (low priority). Publish `jig-core` + `jig-client` once v0.2 stabilizes the wire. |
| D7 | Spec licence? | CC-BY-4.0. |
| D8 | Does `jig-server` compile to Wasm, or host Wasm blocks? | Both. Servers serving servers is v1+ research, gated on a danger analysis. |
| D9 | Who owns triage, the security inbox and release cadence? | The maintainer in [`CODEOWNERS`](../.github/CODEOWNERS). Response, triage and released-fix targets of 1 / 7 / 28 days, 90-day coordinated disclosure ([`SECURITY.md`](../SECURITY.md)). |
| D10 | Should deployed servers track `main` or tags? | Both: a canary on tagged releases and a bleeding-edge deployment on `main`. |
| D11 | How far does the protocol trust server operators? | Not at all. Malicious operators are in scope; every connection starts with a mandatory handshake, and clients fail closed. |
| D12 | Mixed encryption suites across federated servers? | Cross-server channels are a data contract over the transmission. The contract fixes the channel's suite; a server that can't speak it is refused. Trusted subnets may share a nameserver-led contract. |
| D13 | Signal's post-quantum protocol vs MLS as the plug-in shape? | **Open:** settled in the v0.2 crypto design. |
| D15 | Discovery design? | A design project of its own, with proof-of-work and reputation built in. Only the JEP stub is in v0.1. |
| D18 | Where does the threat register live? | Decisions in `jig-spec`, normative and terse; analysis in `docs/`. |

D3, D14, D16 and D17 concern the Riverdance GUI's licence and internal hosting and are tracked
outside this repo.

### Still open

1. Where the public trial server runs, and whether it tracks the canary or `main` (D4).
2. Signal post-quantum vs MLS as the plug-in shape (D13).
3. Publishing the `v0.1.0-alpha.1` release: both release runs for the tag failed.
