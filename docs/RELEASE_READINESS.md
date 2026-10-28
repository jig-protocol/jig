# Release readiness: internal → external

The gate between "jig runs on private deployments" and "we tell strangers to
run `curl -fsSL https://jig.onl/install.sh | bash`".

jig is MIT OR Apache-2.0 source in a public repository, and it publishes signed
alpha prereleases, but it has never been announced, never been deployed to a
public address, and has never had a user outside the team. This document is the
checklist for changing that. Every "current state" row below was checked against
the code at merge commit `1fa5681`; §1.3, §1.5, §1.8 and §4 were re-checked
against `d16f26a` on 2026-10-18; §1.1, §1.6, §1.7, the binary install row, §3,
§6 and the verdict were re-checked against `a740fa8` on 2026-10-25. Where a claim
could not be verified from the tree it says so.

**Verdict vocabulary**

| Verdict | Meaning |
| --- | --- |
| READY | Shipped, verified, safe to point a stranger at |
| GAP | Missing or incomplete; embarrassing but not dangerous |
| BLOCKER | Must be closed before external exposure, or a user gets hurt |

---

## 1. Security

This is the heaviest section and the honest reason the answer at the bottom is
"no". Until 2026-09 jig's security model was *network placement*: it assumed the
listener was only reachable by people you already trust, and
`deploy/README.md` said so outright — "the tailnet IS the authentication". The
authn/authz work (`docs/superpowers/specs/2026-08-24-jig-server-authn-authz-design.md`,
phases 1–3) moved identity into the server; the tailnet is now defence in depth.

### 1.1 Authentication and authorization

| | |
| --- | --- |
| **Current state** | Three gates, in order: authenticate, admit, authorize ([`jig-server/src/auth/`](../repos/jig-server/src/auth/)). **Authenticate** holds: every REST read and every WSS subscribe carries a per-request ed25519 proof over a canonical hash of the request (`jig-core::request_auth`), verified against the caller's DID, with a fail-closed replay guard; `[auth] require_authenticated_reads` defaults to `true`, and the documented escape hatch restores the old behaviour only when set explicitly. **Authorize** holds for channels: history, the listing, live WSS delivery (re-checked per block) and posting all run `authorize_read`/`authorize_block` against `visibility`, `owner_did` and the memberships table; membership changes and `channel-promote` are owner-signed. Refusals go through one disclosure point per surface (`GateOutcome` → `DisclosurePolicy`), truthful by default. **Admit** holds: `[auth.admission]` (`banned_dids`, ruleset-scoped `floors`, an explicit `unknown_dids` choice, operator-seeded `records`) runs on every read and every write — inside `ingest` for writes, so REST, WSS, admin and bridge paths agree — after gate 1 and before any channel lookup, as a pure function (`auth/admission.rs`) shaped to later run as a policy block. |
| **Ready means** | A caller's identity is established per request, reads/writes are checked against channel membership before data leaves the process, and a server can refuse callers it does not want (reputation, bans, rate limits). |
| **Gap** | Reputation is consumed, not computed: the view is what the operator wrote in config, there is no ledger and no exchange of scores. Per-DID and per-address rate limits (`[auth.rate_limit]`) sit in front of the gates, and `unknown_dids = "proof-of-work"` makes each new DID pay once before it is served; the work is a speed bump, not Sybil resistance, and it is off by default. Tier-1 trusted connections (phase 5) are not built. Blocks relayed by a federated peer run through `ingest` like local ones, and peers are pinned and listed. Under the federation contract (JEP-0005), a server can now accept a share of a channel another server sequences and follow it, checking the owner's signed record chain (#309), but the follower stream refuses MLS channels, and writes relayed under a grant are not built: an encrypted group cannot yet span two servers. Legacy peering, which relays open channels to listed peers, catches up after an outage (#340): after it subscribes, the dialing server asks the peer for every federating block it took since the newest one the dialer holds from it, paged and held to the peer quota, and a catch-up cut short resumes from its saved place after a restart. Before #340 it was live only, and a restart soak (#338) lost one or two posts per peer restart. The catch-up judges whether a channel federates as it stands now, not as it stood when each block landed. Legacy peering also merges same-named open channels by name: a post to `#general` on one server appears in `#general` on every peered server that has a channel of that name, re-sequenced and signed by each receiver. Author signatures still hold, but which server a post was made on is lost, and the copies can diverge. It is the pre-contract federation model (the F2 design spec: "channels are identified by slug alone"). Public channels move onto contracts after F2 phase 1 (DJ's decision), which ends it for new posts; #357 tracks posts that have already crossed. Contract shares do replay missed records across restarts: in the same soak, with both sides restarting in turn, a follower lost nothing, pulling the owner's records from its own head after each reconnect. But between peers that are both up, the legacy relay delivers a new open channel first, the follower takes it as a channel of its own, and the share then delivers nothing; a fix is pending. On a follower, a followed channel is read by its id (`jig read <channel-id>`): reading or subscribing by slug is refused with `CARRIED_CHANNEL`, naming the channel's id and owner (#353), until clients address channels by id (F2 Task 0c). Its records are held to the owner, proven by the owner's signed offer to the follower (#353). Revocation is a signed `member-remove` block (owner kick or self-leave) since v0.2. |

**Verdict: GAP** (was BLOCKER). The part that let strangers read and write every
channel is closed and proven by fault injection at each gate, and an operator can
now refuse and rate-limit callers; what remains is scoring and the tier-1
fast path, not the absence of a model.

**Hardening:** operators should set `[auth.admission] unknown_dids = "proof-of-work"` (or
`"refuse"`) on servers that are not open to the public.

### 1.2 `visibility = "restricted"` is enforced

| | |
| --- | --- |
| **Current state** | `restricted` gates history (`403 NOT_A_MEMBER`), the listing (restricted channels and their `owner_did` are not shown to non-members), live WSS delivery (per block, so removing a membership stops an open subscription) and posting (`403 NOT_A_MEMBER` at ingest, on every surface). Self-join works on open channels only; on restricted ones only the owner adds members. Unknown visibility strings and store errors fail closed. |
| **Ready means** | `restricted` gates reads (history, WSS delivery) and writes to non-members. |
| **Gap** | Restricted channels do not federate yet: a relayed block runs the same posting gate, but there is no way to carry membership across servers (see §1.1). Timing still distinguishes a refused read from an unknown channel under a concealing disclosure policy — a stated limitation of the design, and the default policy conceals nothing. |

The CLI's `restricted` help text (members only, always end-to-end encrypted) is true, and
`jig channel join` says which channels it can join.

**Verdict: READY.**

### 1.3 End-to-end encryption

| | |
| --- | --- |
| **Current state** | **Per channel, since v0.2.** A channel created with `suite = "mls"` (`jig channel create --encrypted`, and every `jig dm`) is one MLS group ([`jig-mls`](../repos/jig-mls/), `openmls` 0.9): content is an MLS `PrivateMessage`, the server validates every commit through a public-state `PublicGroup` and holds no group secret, and plaintext into such a channel is refused (`SUITE_MISMATCH`). `integration-tests/tests/h12_encrypted_channels.rs` searches the server's files after a conversation and finds none of it. Channels created without a suite are still signed-not-encrypted and stored in cleartext. |
| **Ready means** | Message bodies are encrypted to recipient keys; the server stores ciphertext it cannot read. |
| **Gap** | Restricted channels are always MLS (D25), but encryption is opt-in for open channels; restricted channels created plaintext before D25 are frozen, their history still readable to the operator. Encrypted channels do not federate. One device per DID. The client's plaintext cache (`~/.jig/mls/`) is as sensitive as the identity key; it is sealed at rest with the identity (#177), and kept in clear only under `JIG_KEYS_STORAGE=plaintext`. No independent review of the MLS integration. |

`repos/jig-spec/` used to document `age+x25519` E2EE in the present tense. Since
2026-10-05 it specifies MLS, suite-pluggable, in `src/encryption.md`, whose banner now
states what v0.2 implements: `mls` for single-server channels.

**Verdict: GAP** (was BLOCKER). Encrypted channels and DMs are real for
single-server use; "private by default" is not yet a true claim, and nothing
here has had an outside review.

### 1.4 Channel-ops endpoints

| | |
| --- | --- |
| **Current state** | Channel ops live on `POST /api/v1/channels`, `/api/v1/channels/:channel/members` and `/api/v1/channels/:channel/archive` (`:channel` is the channel's id or `#slug`, #274), mounted unconditionally ([`v0_0_2_admin.rs`](../repos/jig-server/src/v0_0_2_admin.rs)). The legacy `/_admin_v0_0_2/*` aliases and their `[debug] admin_endpoints` switch were removed (#146); a config that still sets the key refuses to boot until the key is deleted (#199). `jig channel create` posts to `/api/v1/channels`, and the member and archive commands post to its `/:slug/members` and `/:slug/archive` subroutes ([`jig-cli/src/cmd/channel.rs`](../repos/jig-cli/src/cmd/channel.rs)). |
| **Authentication** | Every route runs the bundle through `jig_pipeline::ingest`, which verifies the ed25519 signature and rejects `INVALID_SIG`. The *author DID is authenticated* — you cannot forge someone else's DID here. |
| **Authorization** | Owner checks on channel mutation run inside `ingest` (`jig-pipeline/src/authorize_write.rs`), so they hold on these routes, the public `POST /api/v1/blocks`, WSS `Submit` and the bridge path alike: `member-add` of anyone but yourself, or onto a restricted channel, `member-remove` of anyone but yourself (unless tidying up a member who already left), and `channel-promote` must be signed by the channel owner (`403 NOT_CHANNEL_OWNER`); `channel-archive` keeps its own owner check. Any self-minted keypair can still *create* channels, which is by design. |
| **Ready means** | Ownership/role checks on channel mutation, and a channel-ops path that does not live behind a `[debug]` flag. |

**Verdict: READY** (was GAP). Both conditions hold: mutation is authorized at
ingest, and the working path needs no `[debug]` flag.

### 1.5 v0.0.1 unsigned REST ingest

| | |
| --- | --- |
| **Current state** | Removed (D28, #107). `/blocks` (GET+POST), `/blocks/:cid` and `/receipts/:cid` are no longer routes, and a test pins that they answer `404` ([`handler.rs`](../repos/jig-server/src/handler.rs)). The `dangerously_enable_v0_0_1_rest` flag is gone with them; a config that still sets it refuses to boot (#199). The routes it gated accepted an attacker-chosen author DID with no signature, executed the supplied Wasm and signed a receipt for it. |

**Verdict: READY** (was READY as defaulted off). The hole no longer exists to re-open.

### 1.6 Wasm sandbox

| | |
| --- | --- |
| **Current state** | Tighter than the rest of the system. Blocks are `jig:block` components (JEP-0006), and there is one execution path, [`jig-runtime/src/component.rs`](../repos/jig-runtime/src/component.rs); the byte-payload ABI and the WASI path were deleted (#291, #299). A component is checked against jig-core's `jig-det-1` profile before it is compiled, and the linker defines only the imports its grant names; no host interface has a provider yet, so a component that imports anything is refused at link time. There is no WASI: no stdio, filesystem, sockets or clocks. Every run is bounded by fuel, a wall-clock epoch deadline and a memory cap, on a pooling allocator with one memory per module ([`engine.rs`](../repos/jig-runtime/src/engine.rs)). Server defaults: 5,000,000 fuel, 64 MB, 250 ms ([`jig-server/src/config.rs`](../repos/jig-server/src/config.rs)). wasmtime is 49.0.4 (#280), with no wasmtime advisory suppressed in `deny.toml`, including RUSTSEC-2026-0096 (aarch64 Cranelift guest-heap miscompile → sandbox escape). |
| **Gap** | None material for external use. This is the strongest part of the security story, and it has had no outside review. |

**Verdict: READY.**

### 1.7 Advisory suppressions (`deny.toml`)

Two RustSec ignores, and `yanked = "deny"`.

| Category | IDs | Matters to an external user? |
| --- | --- | --- |
| Build-time only (proc macro) | RUSTSEC-2026-0173 (`proc-macro-error2`, unmaintained, no vulnerability), reached through `jig-mls` → `openmls_rust_crypto` → `hpke-rs` → `libcrux-sha3` → `hax-lib` | No. Never linked into a shipped binary. |
| Linked, unreachable secret (#303) | RUSTSEC-2026-0387 (`crypto-bigint` 0.5, secret-dependent branches), reached through `openmls_rust_crypto` 0.6 → `elliptic-curve` 0.13; no compatible bump exists | No secret reaches it: jig holds no elliptic-curve secret, and `jig-mls` refuses group infos, key packages and welcomes in any other ciphersuite before running their crypto. One path verifies a P-256 signature over public values only. `deny.toml` says when the ignore goes. |

The twelve other ignores this section used to list are gone, resolved rather than
re-annotated: the `time`, `tracing-subscriber` and `rand` fixes arrived with later
lockfile changes; `paste` left with ratatui 0.30, `atty` with an unused `jig-cli`
dependency, and the yanked `core2` with `cid` 0.11; and unifying on rustls 0.23 removed both `rustls-pemfile` and the
`rustls-webpki` 0.102 copy behind the four name-constraint and CRL advisories. The
file records each removal.

**Verdict: READY** (was GAP).

### 1.8 Responsible disclosure

| | |
| --- | --- |
| **Current state** | A root [`SECURITY.md`](../SECURITY.md) written for an outside reporter: GitHub private vulnerability reporting or security@jig.onl, 1-day acknowledgement, 7-day triage, 28-day fix, 90-day coordinated disclosure, safe harbour, and malicious operators in scope. The per-crate `SECURITY.md` files (`repos/jig-{cli,config,core,nameserver,runtime,server,spec}/`) now only point to it. |
| **Ready means** | One root `SECURITY.md` written for an outside reporter: what's in scope, how to report, expected acknowledgement window, disclosure timeline, and whether GitHub private vulnerability reporting is enabled. |
| **Gap** | None in the repository. |

**Verdict: READY** (was BLOCKER).

---

## 2. Operations

| Item | Current state (verified) | Ready means | Verdict |
| --- | --- | --- | --- |
| Install (source) | `install.sh` detects a source checkout and runs `cargo build --release` for `jig-server`, `jig-cli`, and `text-block` (wasm32-wasip1). Works. | Same. | READY |
| Install (binary) | `install.sh` downloads the tarball and `SHA256SUMS` from the GitHub Release (or a `JIG_RELEASES_BASE` mirror), verifies the checksum, and verifies `SHA256SUMS.sig` with `ssh-keygen -Y` against a pinned release key. A missing signature file, a bad signature or a missing `ssh-keygen` is refused; only an explicit `JIG_VERIFY_SIGNATURE=0` installs on the checksum alone. `install-smoke.yml` runs the `curl \| bash` path on every PR that touches the installer, against that PR's build signed with a throwaway key, and after each release against the published tag on Linux and macOS. `v0.2.0-alpha.1` (2026-10-19) and `v0.2.0-alpha.2` (2026-10-25) are published, signed and installable this way; each release run passed the install smoke against its published release on Ubuntu and macOS. The `v0.1.0-alpha.1` prerelease page has no assets and cannot be installed. | URL points where artifacts actually are; paths match the tarball layout; checksum and signature verified before extraction. | READY |
| Upgrade path | None. No `jig upgrade`, no version pinning, no store migration story. `install.sh` overwrites `$JIG_HOME/bin` in place. | A documented upgrade that states what happens to `jig_v002.db`, and to the `jig.db` an older release left behind (no longer opened since #196; `deploy/README.md` says the operator may delete it). | GAP |
| Backup | `deploy/jig-backup.sh` + systemd timer. Genuinely good: `VACUUM INTO` (not `cp`) for the block store `jig_v002.db` and the nameserver's `nameserver.db` and `nameserver_v002.db`, the sealed `server.jigkey` and `nameserver_v002.jigkey` included (a nameserver store without its key is refused; a key still in clear is copied with a warning), `umask 077`, partial snapshots removed on failure, retention pruning with `DRY_RUN`. | Same, plus offsite. | READY |
| Restore | Documented in `deploy/README.md` ("Restore"), including the `chmod 600` on the `.jigkey` files, adding a slot on another machine, and a post-restore `server_did` check. | Same. | READY |
| Observability | `/healthz` (static 200, deliberately does not touch the store) and `/metrics` (Prometheus text). Both mounted unconditionally and unauthenticated. Counters are hand-rolled atomics. `jig_blocks_ingested_total{source}` counts every block `ingest` accepts, by source: `local` (WebSocket and REST clients), `federation`, `admin` and `bridge` ([`jig-pipeline/src/metrics.rs`](../repos/jig-pipeline/src/metrics.rs), #121). The `jig_ws_*` counters still cover the WebSocket path only. | Metrics cover every ingest path, not just WSS. | READY |
| Server key loss | `deploy/README.md` opens with a red-flagged section: losing `/var/lib/jig/server.jigkey`, or every way to open it, changes the server DID and breaks TOFU pinning for every client that ever connected. Clients follow a server's key link (JEP-0012) from its old DID to a new one (#241), and `jig-server keys rotate` writes one (#298), but a link is signed by the old key, so a lost key still means "restore the key from backup". | A documented rotation ceremony, or an identity that survives key change. | GAP |
| Public exposure | `[tls]` is on by default: with no certificate configured the server makes a self-signed one on first start, and its DID vouches for it at `/.well-known/jig` (`tls_binding`). The CLI and federation peers accept that certificate only when the DID they pinned or were configured with vouches for it, or a certificate a CA issued; the first contact is trust on first use. The signed welcome carries the TLS exporter (#234), so the server must terminate TLS itself: anything in front of it passes TLS through. `bind_address` defaults to loopback, and `deploy/README.md` says never set `0.0.0.0`. The nameserver (`:7070`) serves TLS by default under a certificate its DID vouches for, and the CLI and servers refuse `http://` nameservers unless `dangerously_allow_plaintext_nameservers` is set (#262, #263). | n/a — see §1. | See §1 |

---

## 3. Protocol stability

| Layer | Versioned? | Enforced? |
| --- | --- | --- |
| WSS envelope | Yes — `Envelope { v: u8 }`, always `1`, plus `suite` ([`envelope.rs`](../repos/jig-pipeline/src/envelope.rs)) | **Yes.** A frame with any other `v` is refused `UNSUPPORTED_VERSION`, and any frame suite other than `none` `UNSUPPORTED_SUITE` (content suites, `mls` included, are per block), before the frame is read. |
| Block manifest | Yes — `BlockManifest.schema`, default `https://jig.dev/schema/block-manifest/v0.1` ([`manifest.rs`](../repos/jig-core/src/manifest.rs)) | **Yes.** `ingest` runs `BlockManifest::check_gates`, which refuses any schema outside `SUPPORTED_SCHEMAS` and any unimplemented encryption suite. The URI still says `jig.dev`, which is not our domain. |
| Receipt | Yes — every receipt is a COSE_Sign1 over deterministic CBOR whose payload carries `domain: "jig-block-receipt-v1"` and a `kind` (`exec`, `sealed`, `accepted`) ([`block_receipt.rs`](../repos/jig-core/src/block_receipt.rs), JEP-0006 A5). Receipts stored before v0.3 are JSON objects tagged `"v"` (`0.3-render`, `0.3-sealed`, `0.2-synthetic`), read by [`receipts.rs`](../repos/jig-pipeline/src/receipts.rs). The spec's [Receipts](../repos/jig-spec/src/receipts.md) chapter describes both | **Yes.** `SignedReceipt::open` refuses any other `domain`; legacy receipts are read and checked, never written. |
| Fuel schedule | Yes — `FUEL_SCHEDULE_VERSION`, `"0.2.0"`, a constant in [`jig-runtime/src/identity.rs`](../repos/jig-runtime/src/identity.rs); an operator can no longer set it | Not needed. An `exec` receipt reports fuel as engine telemetry, and fuel is never compared (JEP-0006). |

**Will receipts issued today validate tomorrow?** A receipt's *signature* will
still verify: it is ed25519 over bytes. What a receipt claims is an outcome:
two `exec` receipts for the same component, world and invocation that both
reached `ok` or `error` must agree on the class, trap code and outcome hash
([`compare`](../repos/jig-core/src/block_receipt.rs)). A client checks a
server's claim by re-running the component and comparing
(`integration-tests/tests/client_verifies_render.rs`). Fuel, limits and engine
details ride along as telemetry, so a cost-table change between wasmtime
versions (wasmtime 47 began billing `memory.copy` and `memory.fill` per byte)
no longer changes what a receipt asserts. Two servers whose render receipts
disagree are surfaced to the reader as a warning, not refused
(`h4_parity_warning`).

**Verdict: READY, because we promise nothing.** The envelope version, the
encryption suite, the manifest schema and the receipt domain are gates. The
README (*"v0.x makes no compatibility guarantee"*) and every release's notes
say that pre-1.0 releases make no wire, receipt or storage compatibility
guarantee, and `release.yml` publishes every tag as a prerelease. A
compatibility promise is still a BLOCKER for the day one is made.

---

## 4. Documentation

| Artifact | Exists? | Notes |
| --- | --- | --- |
| Root `README.md` | Yes | The front door: what jig is, install, quick start, crate map. `scripts/package-release.sh` copies it and the licence pair into every release tarball. |
| `repos/README.md` | Yes | Workspace-level architecture. Accurate on crate roles. Not a front door. |
| `CONTRIBUTING.md` (root) | Yes | Build, test and pull-request rules, including the DAG rule. `repos/jig-spec/CONTRIBUTING.md` covers the spec book. |
| `CODE_OF_CONDUCT.md` | Yes | At the repo root. |
| `SECURITY.md` (root) | Yes | See §1.8. |
| Deployment docs | Yes, strong | `deploy/README.md` (426 lines: install, tailnet security model, TLS via `tailscale cert`, teammate onboarding, backups, restore, gotchas), `docs/deployment/gcp-vps-runbook.md` (940 lines), plus dogfood runbooks and an install benchmark. |
| Per-crate rustdoc | Partial | Module- and item-level doc comments are dense and unusually good (the `//!` headers carry real rationale). But **no crate sets `#![warn(missing_docs)]`** and none carries `[package.metadata.docs.rs]`, so there is no rendered API reference anywhere. Only `integration-tests` sets `publish = false`; the rest are publishable-by-accident. |
| `jig-spec` book | Yes | mdbook under `repos/jig-spec/`. Describes much unshipped behaviour. Each chapter's banner, and the threat register's status column, say what the reference implementation does (re-checked 2026-10-18); `message-format.md` is bannered as historical, not the wire format. |
| Riverdance | Not in this repo | The unfinished GUI is not part of this repository. Its licence is undecided, and it is not a working client. |

**Verdict: GAP.** The front-door files exist and the spec is bannered; what
remains is a rendered API reference and `publish = false` on crates not meant for
crates.io.

---

## 5. Legal / licensing

**RESOLVED.** The protocol is dual-licensed **MIT OR Apache-2.0**, the customary Rust
pair, decided 2026-08-06. Rationale, in DJ's words: *"the protocol doesn't work if most of
it isn't reusable by everyone for everything."*

| Item | State |
| --- | --- |
| Root licence files | `LICENSE-MIT` and `LICENSE-APACHE` at the repo root, full texts. GitHub now detects the licence. |
| Per-crate SPDX | Every protocol crate declares `MIT OR Apache-2.0`, including the workspace default, `integration-tests`, and the `repos/fuzz` crate (#331). No crate declares AGPL any more, so the earlier MIT-linking-AGPL incoherence is gone. |
| Superseded files | The AGPL notice stubs under `jig-core`/`jig-server` and the standalone MIT under `jig-cli` are deleted; the root pair covers them. |
| `deny.toml` | The `AGPL-3.0-only` allowance is removed — no dependency needed it, and cargo-deny reported it as an unmatched allowance. |
| Contribution terms | The standard Apache-2.0 §5 inbound=outbound paragraph is in the README. No CLA. |

### Carve-outs

**Riverdance is not in this repository.** A client application is not protocol surface,
and the reusability argument does not transfer to it. Its licence is undecided, and the
client is not functional. It lives outside this tree, so its status cannot contaminate
the protocol crates.

**`repos/jig-spec/` — CC-BY-4.0 (decided 2026-10-05).** It was CC BY-SA 4.0. Share-alike
on a written specification impedes exactly the independent implementations the permissive
code licence exists to encourage, because a derived implementation guide inherits the
share-alike obligation. Attribution-only matches what most widely adopted protocol specs use.

**Verdict: resolved.**

### The DAG rule (external contributors must know this)

**gigue may depend on jig. jig must never depend on gigue.** gigue is the
closed-source sibling product; jig is the open protocol. The boundary is not
stylistic — it exists so that no jig contributor's work can be pulled into a
closed product by an import, and so that no one can claim jig is a funnel for
gigue. Practically: no `gigue` crate, package, path dependency, private
registry, or copied code may appear anywhere under `repos/`. This belongs in
`CONTRIBUTING.md` and ideally in a CI check, neither of which exists today.

---

## 6. Community readiness

`.github/` holds the workflows (`ci.yml`, `release.yml`, `install-smoke.yml`,
`block-abi-vectors.yml`), issue templates, a PR template, `CODEOWNERS` and
`dependabot.yml`.

| Item | State | Verdict |
| --- | --- | --- |
| Issue templates | Bug report, feature request and JEP proposal; blank issues are off, and the chooser links private vulnerability reporting and dev@jig.onl | READY |
| PR template | `.github/pull_request_template.md`: what changed, test plan, spec/JEP impact, the DAG rule | READY |
| `CODEOWNERS` | DJ owns everything, repeated on sensitive paths | READY |
| Discussion / support channel | dev@jig.onl and issues; security reports go to security@jig.onl or GitHub private reporting. No public chat. | GAP |
| Triage owner | DJ, named in `SECURITY.md` for vulnerability reports. No rotation or SLA for ordinary issues. | GAP |
| Release cadence | Two signed prereleases so far, `v0.2.0-alpha.1` (2026-10-19) and `v0.2.0-alpha.2` (2026-10-25), each with notes in [`.github/release/notes/`](../.github/release/notes/). `release.yml` is tag-triggered, waits for a maintainer's approval in the `release` environment, refuses notes that do not list the threat-register entries mitigated, and publishes every tag as a prerelease. No cadence is promised. | GAP |
| CI coverage | `changes`, `workspace` (fmt, clippy and nextest on every workspace crate), `wasm-build` and `dependency-policy` (also daily at 07:17 UTC against `main`). A `nightly` job on the same schedule runs doc tests, skips nights when nothing under `repos/` (Markdown aside) and not `rust-toolchain.toml` changed, and does not gate merges. Drafts and docs-only PRs skip the build jobs; the merge queue runs everything. Linux only for the workspace job; macOS runs in the install smoke test inside `release.yml` and after each release, and in `block-abi-vectors.yml` on manual dispatch only. | GAP |

**Test counts, measured at `1fa5681`** (`cargo nextest list`, stable 1.97.1): 1,054 tests in
the CI-gated package set, plus 87 in `jig-runtime` + `hello-wasm` = **1,141**. (`hello-wasm` was
deleted in #134, and `jig-runtime` is now CI-gated, so the split no longer applies.)
Reports of 1,143 are within rounding of this but do not reproduce exactly; if a
precise number goes in a README, re-measure it there.

---

## Verdict

**No. jig is not ready for external users today.**

The sentence that used to decide it, *a jig server has no authentication and
no authorization*, is no longer true: reads require proof of possession,
restricted channels are membership-gated on every surface, membership changes
are owner-signed, and rate limits are on by default. Nor are the next four: DMs,
restricted channels and `--encrypted` open channels are end-to-end encrypted with
MLS; `SECURITY.md` gives a disclosure path; and two signed releases are published
and install through the verified `curl | bash` path. What decides it now:

- Encryption is not the default for open channels (restricted channels are always MLS
  since D25), and the email bridge refuses inbound mail until it can join MLS groups.
- Encrypted channels do not federate yet: a server can follow an open channel
  another server sequences (#309) and relay its users' writes to the owner (#316), but MLS
  across servers and the rest of F2 (Tasks 7 to 11) are still to build.
- Nothing has had an outside review yet. The audit is scoped (D27, decided 2026-10-25):
  Phase 1 before G3, Phase 2 after code-complete.
- Admission rests on operator-written config, not earned reputation.

### Minimum credible blocker set, ordered

| # | Blocker | Why it is in this position |
| --- | --- | --- |
| ~~1~~ | ~~**Authn + authz on `jig-server`**~~ | **Phases 1–4 DONE 2026-09-11** — per-request proof of possession on reads, `visibility`/membership enforced on history, listing, live delivery and posting, owner-signed membership changes, and an admission policy (bans, ruleset floors, explicit unknown-DID choice) on every read and write. Rate limits (#92) and optional admission proof-of-work (#94) followed. Still open from the same design: trusted connections (phase 5); see §1.1. |
| ~~2~~ | ~~**Root `SECURITY.md` with an external reporting path**~~ | **DONE 2026-10-05** — `SECURITY.md`: security@jig.onl, 1/7/28-day targets, 90-day disclosure, malicious operators in scope. |
| ~~3~~ | ~~**Root `LICENSE` + consistent per-crate SPDX ids**~~ | **DONE 2026-08-06** — dual-licensed MIT OR Apache-2.0, root licence pair added, every protocol crate aligned. `jig-spec` moved to CC-BY-4.0 on 2026-10-05. |
| ~~4~~ | ~~**Publish a release the installer can install**~~ | **DONE 2026-10-19** — `v0.2.0-alpha.1`, then `v0.2.0-alpha.2` on 2026-10-25: built, signed and published by `release.yml`, and installed by `install.sh` against the published release on Ubuntu and macOS in the same run. |
| ~~5~~ | ~~**Say plainly that v0.x has no compatibility guarantee**~~ | **DONE** — README and spec 2026-10-05; every release's notes since `v0.2.0-alpha.1` ([`.github/release/notes/`](../.github/release/notes/)). `Envelope.v`, the manifest `schema`, the encryption suite and the receipt domain are gates (§3). |
| ~~6~~ | ~~**Implementation-status banner on `jig-spec`**~~ | **DONE 2026-10-05**, re-checked 2026-10-18 — every chapter's banner and the threat register's status column match `main`. |
| ~~7~~ | ~~**Clear the reachable advisory suppressions**~~ | **DONE** — two ignores left: one build-time only, one linked where no secret reaches it (§1.7). |
| 8 | **Publish a support channel** | DJ is the named triage owner for security reports, and dev@jig.onl takes everything else. No public discussion channel, and no SLA for ordinary issues. |

Until blocker 8 lands, along with the encryption, federation and review items above, the honest
external posture is still: **source-available for reading and auditing, not for
running on a public address.** That is a defensible thing to announce — "here is
a protocol implementation, here is what works, here is the security model, do
not put it on the internet yet" — and it is far better than shipping an install
script that implies otherwise.
