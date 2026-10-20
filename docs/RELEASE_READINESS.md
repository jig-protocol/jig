# Release readiness: internal → external

The gate between "we dogfood jig on our own tailnet" and "we tell strangers to
run `curl -fsSL https://jig.onl/install.sh | bash`".

jig is MIT OR Apache-2.0 source in a public-shaped repo, but it has never been
announced, never been deployed to a public address, and has never had a user
outside the team. This document is the checklist for changing that. Every
"current state" row below was checked against the code at merge commit
`1fa5681`; §1.3, §1.5 to §1.8, the binary install row, §3, §4, §6 and the verdict
were re-checked against `d16f26a` on 2026-10-18. Where a claim could not be
verified from the tree it says so.

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
| **Gap** | Reputation is consumed, not computed: the view is what the operator wrote in config, there is no ledger and no exchange of scores. Per-DID and per-address rate limits (`[auth.rate_limit]`) sit in front of the gates, and `unknown_dids = "proof-of-work"` makes each new DID pay once before it is served; the work is a speed bump, not Sybil resistance, and it is off by default. Tier-1 trusted connections (phase 5) are not built. Blocks relayed by a federated peer run through `ingest` like local ones, and peers are pinned and listed, but only open, unencrypted channels federate until the federation contract (D12) says how an encrypted group spans two servers. Revocation is a signed `member-remove` block (owner kick or self-leave) since v0.2. |

**Verdict: GAP** (was BLOCKER). The part that let strangers read and write every
channel is closed and proven by fault injection at each gate, and an operator can
now refuse and rate-limit callers; what remains is scoring and the tier-1
fast path, not the absence of a model.

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
| **Gap** | Restricted channels are always MLS (D25), but encryption is opt-in for open channels; restricted channels created plaintext before D25 are frozen, their history still readable to the operator. Encrypted channels do not federate. One device per DID. The client's plaintext cache (`~/.jig/mls/`) is as sensitive as the identity key and is not encrypted at rest. No independent review of the MLS integration. |

`repos/jig-spec/` used to document `age+x25519` E2EE in the present tense. Since
2026-10-05 it specifies MLS, suite-pluggable, in `src/encryption.md`, whose banner now
states what v0.2 implements: `mls` for single-server channels.

**Verdict: GAP** (was BLOCKER). Encrypted channels and DMs are real for
single-server use; "private by default" is not yet a true claim, and nothing
here has had an outside review.

### 1.4 Channel-ops endpoints

| | |
| --- | --- |
| **Current state** | Channel ops live on `POST /api/v1/channels`, `/api/v1/channels/:slug/members` and `/api/v1/channels/:slug/archive`, mounted unconditionally ([`v0_0_2_admin.rs`](../repos/jig-server/src/v0_0_2_admin.rs)). The legacy `/_admin_v0_0_2/*` aliases and their `[debug] admin_endpoints` switch were removed (#146); a config that still sets the key refuses to boot until the key is deleted (#199). `jig channel create` posts to `/api/v1/channels`, and the member and archive commands post to its `/:slug/members` and `/:slug/archive` subroutes ([`jig-cli/src/cmd/channel.rs`](../repos/jig-cli/src/cmd/channel.rs)). |
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
| **Current state** | Tighter than the rest of the system. `build_wasi_context` ([`jig-runtime/src/engine.rs:458`](../repos/jig-runtime/src/engine.rs)) grants an empty stdin pipe and an in-memory stdout buffer — no host stdio, no preopened directories, no sockets. Store limits pin one instance, one memory, 10 tables, 10k table elements; fuel and an epoch deadline bound runtime. Server defaults: 5,000,000 fuel, 64 MB, plus a timeout ([`jig-server/src/config.rs:446-452`](../repos/jig-server/src/config.rs)). wasmtime is 49.0.3, with no wasmtime advisory suppressed in `deny.toml` — including RUSTSEC-2026-0096 (aarch64 Cranelift guest-heap miscompile → sandbox escape). |
| **Gap** | None material for external use. This is the strongest part of the security story. |

**Verdict: READY.**

### 1.7 Advisory suppressions (`deny.toml`)

One RustSec ignore, and `yanked = "deny"`.

| Category | IDs | Matters to an external user? |
| --- | --- | --- |
| Build-time only (proc macro) | RUSTSEC-2026-0173 (`proc-macro-error2`, unmaintained, no vulnerability), reached through `jig-mls` → `openmls_rust_crypto` → `hpke-rs` → `libcrux-sha3` → `hax-lib` | No. Never linked into a shipped binary. |

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
| Install (binary) | `install.sh` downloads the tarball and `SHA256SUMS` from the GitHub Release (or a `JIG_RELEASES_BASE` mirror), verifies the checksum, and verifies `SHA256SUMS.sig` with `ssh-keygen -Y` against a pinned release key. A missing signature file, a bad signature or a missing `ssh-keygen` is refused; only an explicit `JIG_VERIFY_SIGNATURE=0` installs on the checksum alone. `install-smoke.yml` runs the `curl \| bash` path on every PR that touches the installer, against that PR's build signed with a throwaway key, and after each release against the published tag on Linux and macOS. No release has been published yet. | URL points where artifacts actually are; paths match the tarball layout; checksum and signature verified before extraction. | GAP: no published release |
| Upgrade path | None. No `jig upgrade`, no version pinning, no store migration story. `install.sh` overwrites `$JIG_HOME/bin` in place. | A documented upgrade that states what happens to `jig_v002.db`, and to the `jig.db` an older release left behind (no longer opened since #196; `deploy/README.md` says the operator may delete it). | GAP |
| Backup | `deploy/jig-backup.sh` + systemd timer. Genuinely good: `VACUUM INTO` (not `cp`) for the block store `jig_v002.db` and the nameserver's `nameserver.db` and `nameserver_v002.db`, `server.key` and `nameserver_v002.key` included (a nameserver store without its key is refused), `umask 077`, partial snapshots removed on failure, retention pruning with `DRY_RUN`. | Same, plus offsite. | READY |
| Restore | Documented in `deploy/README.md` ("Restore"), including the `chmod 600` on `server.key` and a post-restore `server_did` check. | Same. | READY |
| Observability | `/healthz` (static 200, deliberately does not touch the store) and `/metrics` (Prometheus text). Both mounted unconditionally and unauthenticated. Counters are hand-rolled atomics. `jig_blocks_ingested_total{source}` counts every block `ingest` accepts, by source: `local` (WebSocket and REST clients), `federation`, `admin` and `bridge` ([`jig-pipeline/src/metrics.rs`](../repos/jig-pipeline/src/metrics.rs), #121). The `jig_ws_*` counters still cover the WebSocket path only. | Metrics cover every ingest path, not just WSS. | READY |
| Server key loss | `deploy/README.md` opens with a red-flagged section: losing `/var/lib/jig/server.key` changes the server DID and breaks TOFU pinning for every client that ever connected. There is no key-rotation or re-pin flow — recovery is "restore the key from backup". | A documented rotation ceremony, or an identity that survives key change. | GAP |
| Public exposure | `[tls]` is on by default: with no certificate configured the server makes a self-signed one on first start, and its DID vouches for it at `/.well-known/jig` (`tls_binding`). The CLI and federation peers accept that certificate only when the DID they pinned or were configured with vouches for it, or a certificate a CA issued; the first contact is trust on first use. `bind_address` defaults to loopback, and `deploy/README.md` says never set `0.0.0.0`. The nameserver (`:7070`) still serves plaintext. | n/a — see §1. | See §1 |

---

## 3. Protocol stability

| Layer | Versioned? | Enforced? |
| --- | --- | --- |
| WSS envelope | Yes — `Envelope { v: u8 }`, always `1`, plus `suite` ([`envelope.rs`](../repos/jig-pipeline/src/envelope.rs)) | **Yes.** A frame with any other `v` is refused `UNSUPPORTED_VERSION`, and any frame suite other than `none` `UNSUPPORTED_SUITE` (content suites, `mls` included, are per block), before the frame is read. |
| Block manifest | Yes — `BlockManifest.schema`, default `https://jig.dev/schema/block-manifest/v0.1` ([`manifest.rs`](../repos/jig-core/src/manifest.rs)) | **Yes.** `ingest` runs `BlockManifest::check_gates`, which refuses any schema outside `SUPPORTED_SCHEMAS` and any unimplemented encryption suite. The URI still says `jig.dev`, which is not our domain. |
| Receipt | Partly. `RECEIPT_SCHEMA_VERSION = "0.2"` ([`receipt.rs`](../repos/jig-core/src/receipt.rs)) stamps `jig-core` receipts, but the receipt the server signs for a rendered block is a separate JSON object tagged `"v": "0.3-render"` ([`ingest.rs`](../repos/jig-pipeline/src/ingest.rs)), which the spec's [Receipts](../repos/jig-spec/src/receipts.md) chapter does not describe | No consumer branches on either value. |
| Fuel pricing | Yes — `PricingConfig::schedule_version`, now `"0.2.0"` ([`jig-runtime/src/config.rs:215`](../repos/jig-runtime/src/config.rs)) | Advisory. Carried into receipts and into `runtime/mod.rs` metadata; nothing rejects a mismatch. |

The `0.1.0 → 0.2.0` pricing bump is the clearest example of why external users
cannot yet assume stability: wasmtime 47 bills bulk memory ops (`memory.copy`,
`memory.fill`) **per byte** where 24.x charged flat. The same block costs
materially more fuel — the WASI reference fixture went from 1,713 to 18,098,
almost all of it a 16 KiB memcpy in `_start`. Per-operator costs for ordinary
compute are unchanged.

**Will receipts issued today validate tomorrow?** A receipt's *signature* will
still verify — that is just ed25519 over bytes. But a receipt is a claim about
determinism and cost, and both halves are unstable:

- **Cost** is not comparable across `schedule_version` values. A `0.1.0`
  receipt and a `0.2.0` receipt for the same block disagree by an order of
  magnitude on a memcpy-heavy workload. The version string is the *only*
  signal a consumer gets, and nothing enforces that they check it.
- **Render-hash parity** across servers depends on both running the same
  wasmtime. Integration test `h4_parity_warning` covers the divergence case;
  the outcome is a warning, not a rejection.

**Verdict: BLOCKER for any compatibility promise; READY if we promise nothing.**
The envelope version, the encryption suite and the manifest schema are now gates; the
receipt and pricing versions are still labels. External users
must be told, in the README and on the release page, that v0.0.x makes no wire
or receipt compatibility guarantee and that breaking changes ship without a
migration. Crate versions already say this (`0.0.1`–`0.0.3`) and
`release.yml` marks every `v0.0.*` tag `prerelease: true` — the docs need to
match.

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
| Per-crate SPDX | Every protocol crate declares `MIT OR Apache-2.0`, including the workspace default, `integration-tests`, and the fuzz target. No crate declares AGPL any more, so the earlier MIT-linking-AGPL incoherence is gone. |
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
`fuel-portability.yml`), issue templates, a PR template, `CODEOWNERS` and
`dependabot.yml`.

| Item | State | Verdict |
| --- | --- | --- |
| Issue templates | Bug report, feature request and JEP proposal; blank issues are off, and the chooser links private vulnerability reporting and dev@jig.onl | READY |
| PR template | `.github/pull_request_template.md`: what changed, test plan, spec/JEP impact, the DAG rule | READY |
| `CODEOWNERS` | DJ owns everything, repeated on sensitive paths | READY |
| Discussion / support channel | dev@jig.onl and issues; security reports go to security@jig.onl or GitHub private reporting. No public chat. | GAP |
| Triage owner | DJ, named in `SECURITY.md` for vulnerability reports. No rotation or SLA for ordinary issues. | GAP |
| Release cadence | Undefined. `release.yml` is tag-triggered and marks every v0.x tag a prerelease; no release has been published. | GAP |
| CI coverage | `changes`, `workspace` (fmt, clippy and nextest on every workspace crate), `wasm-build` and `dependency-policy` (also daily at 07:17 UTC against `main`). A `nightly` job on the same schedule runs doc tests and clippy on `jig-runtime --features tracing`, skips nights when nothing under `repos/` (Markdown aside) and not `rust-toolchain.toml` changed, and does not gate merges. Drafts and docs-only PRs skip the build jobs; the merge queue runs everything. Linux only for the workspace job; macOS runs in the install smoke test inside `release.yml` and after each release, and in `fuel-portability.yml` on manual dispatch only. | GAP |

**Test counts, measured at `1fa5681`** (`cargo nextest list`, stable 1.97.1): 1,054 tests in
the CI-gated package set, plus 87 in `jig-runtime` + `hello-wasm` = **1,141**. (`hello-wasm` was
deleted in #134, and `jig-runtime` is now CI-gated, so the split no longer applies.)
Reports of 1,143 are within rounding of this but do not reproduce exactly; if a
precise number goes in a README, re-measure it there.

---

## Verdict

**No. jig is not ready for external users today.**

The sentence that used to decide it — *a jig server has no authentication and
no authorization* — is no longer true: reads require proof of possession,
restricted channels are membership-gated on every surface, membership changes
are owner-signed, and rate limits are on by default. Nor are the next three: DMs
restricted channels and `--encrypted` open channels are end-to-end encrypted with MLS, the binary
installer verifies a signed checksum, and `SECURITY.md` gives a disclosure path.
What decides it now:

- Encryption is not the default for open channels (restricted channels are always MLS
  since D25), and the email bridge refuses inbound mail until it can join MLS groups.
- Encrypted channels do not federate, and nothing has had an outside review (the
  audit, D27, runs once v0.2 is code-complete).
- Admission rests on operator-written config, not earned reputation; the
  nameserver serves plaintext.
- No real release has been published; the `curl | bash` path has run only against
  CI builds and a throwaway prerelease (`v0.0.0-relpipe.1`).

### Minimum credible blocker set, ordered

| # | Blocker | Why it is in this position |
| --- | --- | --- |
| ~~1~~ | ~~**Authn + authz on `jig-server`**~~ | **Phases 1–4 DONE 2026-09-11** — per-request proof of possession on reads, `visibility`/membership enforced on history, listing, live delivery and posting, owner-signed membership changes, and an admission policy (bans, ruleset floors, explicit unknown-DID choice) on every read and write. Rate limits (#92) and optional admission proof-of-work (#94) followed. Still open from the same design: trusted connections (phase 5); see §1.1. |
| ~~2~~ | ~~**Root `SECURITY.md` with an external reporting path**~~ | **DONE 2026-10-05** — `SECURITY.md`: security@jig.onl, 1/7/28-day targets, 90-day disclosure, malicious operators in scope. |
| ~~3~~ | ~~**Root `LICENSE` + consistent per-crate SPDX ids**~~ | **DONE 2026-08-06** — dual-licensed MIT OR Apache-2.0, root licence pair added, every protocol crate aligned. `jig-spec` moved to CC-BY-4.0 on 2026-10-05. |
| 4 | **Publish a release the installer can install** | The installer is fixed: it fetches from GitHub Releases, verifies `SHA256SUMS` and its signature, and `install-smoke.yml` tests it on PRs. What is missing is a published release; every `v0.1.0-alpha.1` attempt failed (see the roadmap). |
| 5 | **Say plainly that v0.x has no compatibility guarantee** | README and spec done 2026-10-05; release notes still to do. `Envelope.v`, the manifest `schema` and the encryption suite are gates; receipt and pricing versions are labels (§3). |
| ~~6~~ | ~~**Implementation-status banner on `jig-spec`**~~ | **DONE 2026-10-05**, re-checked 2026-10-18 — every chapter's banner and the threat register's status column match `main`. |
| ~~7~~ | ~~**Clear the reachable advisory suppressions**~~ | **DONE** — one build-time-only ignore left (§1.7). |
| 8 | **Publish a support channel** | DJ is the named triage owner for security reports, and dev@jig.onl takes everything else. No public discussion channel, and no SLA for ordinary issues. |

Until those land, along with the encryption and review items above, the honest
external posture is still: **source-available for reading and auditing, not for
running on a public address.** That is a defensible thing to announce — "here is
a protocol implementation, here is what works, here is the security model, do
not put it on the internet yet" — and it is far better than shipping an install
script that implies otherwise.
