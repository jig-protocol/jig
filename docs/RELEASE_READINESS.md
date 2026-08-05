# Release readiness: internal → external

The gate between "we dogfood jig on our own tailnet" and "we tell strangers to
run `curl -fsSL https://jig.onl/install.sh | bash`".

jig is AGPL-licensed source in a public-shaped repo, but it has never been
announced, never been deployed to a public address, and has never had a user
outside the team. This document is the checklist for changing that. Every
"current state" row below was checked against the code at merge commit
`1fa5681`; where a claim could not be verified from the tree it says so.

**Verdict vocabulary**

| Verdict | Meaning |
| --- | --- |
| READY | Shipped, verified, safe to point a stranger at |
| GAP | Missing or incomplete; embarrassing but not dangerous |
| BLOCKER | Must be closed before external exposure, or a user gets hurt |

---

## 1. Security

This is the heaviest section and the honest reason the answer at the bottom is
"no". jig's current security model is *network placement*: it assumes the
listener is only reachable by people you already trust.
`deploy/README.md` states this outright — "the tailnet IS the authentication".

### 1.1 Authentication and authorization

| | |
| --- | --- |
| **Current state** | There is no authn and no authz anywhere in `jig-server`. No token, no session, no capability check, no per-request identity. the `Frame::Subscribe` arm of `handle_client_frame` ([`v0_0_2_ws.rs`](../repos/jig-server/src/v0_0_2_ws.rs)) registers any scope for any connection with no check; `Scope::Federation { block_kinds: [] }` matches every block on the server. `GET /api/v1/channels/:slug/blocks` ([`v0_0_2_blocks.rs:329`](../repos/jig-server/src/v0_0_2_blocks.rs)) returns a channel's full timeline with no caller identity involved at all. |
| **Ready means** | A caller's identity is established per connection, and reads/writes are checked against channel membership before data leaves the process. |
| **Gap** | Total. Anyone who can open a TCP connection to the port reads and writes every channel on the server. |

**Verdict: BLOCKER.**

### 1.2 `visibility = "restricted"` is stored, not enforced

| | |
| --- | --- |
| **Current state** | `channel-create` persists a `visibility` string and an `owner_did`, and `member-add` persists rows into a `memberships` table ([`effect.rs:73-121`](../repos/jig-pipeline/src/effect.rs), schema at [`persist.rs:242`](../repos/jig-pipeline/src/persist.rs)). Nothing reads either one for an access decision. `grep` for `visibility` across `jig-server/src` returns only the field definition, the JSON serializer for `GET /api/v1/channels`, and tests. Memberships are read only for bridge-sink dispatch. |
| **Ready means** | `restricted` gates reads (history, WSS delivery) and writes to non-members. |
| **Gap** | The flag is decorative. A restricted channel is exactly as readable as an open one. |

This is worse than merely missing, because the CLI advertises the feature.
`jig channel create --visibility restricted` has help text reading
`restricted (membership-gated reads)`
([`jig-cli/src/main.rs:161`](../repos/jig-cli/src/main.rs)). A user reading
`--help` is told they got a protection they did not get.

**Verdict: BLOCKER.** Enforce it or delete the flag and the help text.

### 1.3 No end-to-end encryption

| | |
| --- | --- |
| **Current state** | Blocks are **signed, not encrypted**. Signing is ed25519 over canonical bundle bytes; hashing is BLAKE3/SHA-256. `BlockManifest.privacy.encryption` ([`manifest.rs:117`](../repos/jig-core/src/manifest.rs)) is a free-form `String` with no crypto behind it — no crate in the workspace performs any AEAD or key agreement. `x25519-dalek` is declared in `repos/Cargo.toml` but no crate depends on it and no source file calls it. Block bodies are cleartext in the SQLite store and cleartext on the wire unless TLS terminates the hop. |
| **Ready means** | Message bodies are encrypted to recipient keys; the server stores ciphertext it cannot read. |
| **Gap** | Everything. The `[tls]` section ([`config.rs:41`](../repos/jig-server/src/config.rs), off by default) gives transport confidentiality only; the server operator reads every message. |

`repos/jig-spec/` documents `age+x25519` E2EE in detail
(`src/crypto.md`, `src/blocks.md`, `src/zero-trust.md`). None of it is
implemented. Publishing that spec next to the code without a prominent
"not implemented" banner is itself a security-communication problem.

**Verdict: BLOCKER** for any claim of privacy. Not a blocker for a
narrowly-scoped "federated IRC with signed messages" pitch — *if* the
positioning and the spec say so plainly.

### 1.4 Admin endpoints are required and unauthorized

| | |
| --- | --- |
| **Current state** | `/_admin_v0_0_2/channels` and `/_admin_v0_0_2/channels/:slug/members` mount only when `[debug] admin_endpoints = true` (`build_v0_0_2_router` in [`v0_0_2_ws.rs`](../repos/jig-server/src/v0_0_2_ws.rs)). `JigServerConfig::default()` has it `false`, but the config template `jig-server` writes sets it `true` with a comment explaining it is not optional: `jig channel create` and `jig channel join` POST to exactly these routes ([`config.rs:273-279`](../repos/jig-server/src/config.rs), [`jig-cli/src/cmd/channel.rs`](../repos/jig-cli/src/cmd/channel.rs)). |
| **Authentication** | Partial. Both handlers run the bundle through `jig_pipeline::ingest`, which verifies the ed25519 signature and rejects `INVALID_SIG`. So the *author DID is authenticated* — you cannot forge someone else's DID here. |
| **Authorization** | None. `apply_member_add` does not check that the signer owns or belongs to the channel. `apply_channel_promote` does not check ownership before flipping a channel's `visibility` to `open`. Any self-minted keypair — and minting one is free and unlogged — can create channels and add arbitrary DIDs to arbitrary channels. |
| **Ready means** | Ownership/role checks on channel mutation, and a channel-ops path that does not live behind a `[debug]` flag. |

**Verdict: BLOCKER.** The shape of the problem is that the only working
channel-management path is explicitly labelled debug-only in the code and is
unauthorized by design.

### 1.5 v0.0.1 unsigned REST ingest

| | |
| --- | --- |
| **Current state** | Gated off by default. `ServerConfig::dangerously_enable_v0_0_1_rest` is `#[serde(default)]` `bool` = `false` ([`config.rs:30`](../repos/jig-server/src/config.rs)); a unit test pins the default. When false, `/blocks` (GET+POST), `/blocks/:cid` and `/receipts/:cid` are not mounted and 404 ([`handler.rs:44-61`](../repos/jig-server/src/handler.rs)). `/.well-known/jig`, `/healthz` and `/metrics` stay mounted either way. |
| **What enabling it re-opens** | `POST /blocks` accepts an attacker-chosen author DID with **no signature anywhere in the request**, executes the supplied Wasm, and signs a server receipt attesting to the result. It bypasses the v0.0.2 signature check and the `allowed_block_kinds` allowlist entirely. Net effect: anonymous Wasm execution on your host, plus a server-signed receipt laundering it as authentic. |

**Verdict: READY** as shipped (correctly defaulted off, loudly named,
documented in the handler). Keep it off; never document it as a workaround.

### 1.6 Wasm sandbox

| | |
| --- | --- |
| **Current state** | Tighter than the rest of the system. `build_wasi_context` ([`jig-runtime/src/engine.rs:293`](../repos/jig-runtime/src/engine.rs)) grants an empty stdin pipe and an in-memory stdout buffer — no host stdio, no preopened directories, no sockets. Store limits pin one instance, one memory, 10 tables, 10k table elements; fuel and an epoch deadline bound runtime. Server defaults: 5,000,000 fuel, 64 MB, plus a timeout ([`jig-server/src/config.rs:296-304`](../repos/jig-server/src/config.rs)). wasmtime is 47.0.3, which closed every wasmtime advisory previously carved out — including RUSTSEC-2026-0096 (aarch64 Cranelift guest-heap miscompile → sandbox escape). |
| **Gap** | None material for external use. This is the strongest part of the security story. |

**Verdict: READY.**

### 1.7 Advisory suppressions (`deny.toml`)

13 individually-pinned RustSec ignores, plus `yanked = "warn"`.
`cargo deny --manifest-path repos/Cargo.toml check` was run and reports
`advisories ok, bans ok, licenses ok, sources ok` — i.e. clean *given* these
suppressions.

| Category | IDs | Matters to an external user? |
| --- | --- | --- |
| Build-time only (proc macros) | RUSTSEC-2024-0370 (`proc-macro-error`), RUSTSEC-2024-0436 (`paste`) | No. Never linked into a shipped binary. |
| CLI-local, non-network | RUSTSEC-2021-0145, RUSTSEC-2024-0375 (`atty`) | No. Windows-only, and only under a custom global allocator we do not install. |
| Unmaintained, no upgrade published | RUSTSEC-2025-0134 (`rustls-pemfile`), RUSTSEC-2026-0105 (`core2`, all versions yanked) | Indirectly. Unmaintained crypto-adjacent code in the TLS cert-loading path is a supply-chain smell an external auditor will flag. |
| Fixable by a lockfile bump | RUSTSEC-2026-0009 (`time` RFC-2822 stack exhaustion), RUSTSEC-2025-0055 (`tracing-subscriber` ANSI injection into logs), RUSTSEC-2026-0097 (`rand` ThreadRng unsoundness) | **Yes — two of them.** The `time` parse path is reachable from `hickory-resolver`; the premise "we do not parse attacker-supplied RFC 2822 dates" holds only while the email bridge does not. The `tracing-subscriber` one is log poisoning by a remote party, which is exactly what an unauthenticated public listener invites. All three are a `Cargo.lock` bump away. |
| `rustls-webpki` (0.102.8 via rustls 0.22 + 0.103.4 via rustls 0.23) | RUSTSEC-2026-0049, -0098, -0099, -0104 | **Yes.** Two are name-constraint bypasses and one is a reachable panic parsing a CRL. The stated mitigation ("we use no CRLs and no name-constrained CAs") is true of *our* config today and is not a property an external operator's PKI will preserve. Blocked on retiring the rustls 0.22 branch, i.e. the `tokio-tungstenite` 0.21 bump already tracked as a follow-up. |

**Verdict: GAP.** Three lockfile bumps and one rustls dedup would take this to
zero-or-near-zero suppressions. The current list is well-documented and
individually justified — the file's own invariant comment is better discipline
than most projects have — but "13 ignores" is a bad first impression and two
categories are genuinely reachable once the listener is public.

### 1.8 Responsible disclosure

| | |
| --- | --- |
| **Current state** | No `SECURITY.md` at the repo root. GitHub only surfaces a policy from the root, `.github/`, or `docs/` — so today the repo shows no security policy at all. Seven per-crate `SECURITY.md` files exist (`repos/jig-{cli,config,core,gui,nameserver,runtime,server}/SECURITY.md`, 17 lines each, plus a 30-line one in `jig-spec`). Their contents are **internal-facing**: they route reporters to `security@gigue.ai // #alert-security`, tell them not to DM engineers because it hurts SLAs, and tell them not to open tickets without coordinating with security engineering first. |
| **Ready means** | One root `SECURITY.md` written for an outside reporter: what's in scope, how to report, expected acknowledgement window, disclosure timeline, and whether GitHub private vulnerability reporting is enabled. |
| **Gap** | The file is missing where it counts, and the text that does exist reads as an internal runbook. "#alert-security" is a channel a stranger cannot join. |

**Verdict: BLOCKER.** Cheap to fix, and going public without a disclosure path
means the first finding arrives as a tweet.

---

## 2. Operations

| Item | Current state (verified) | Ready means | Verdict |
| --- | --- | --- | --- |
| Install (source) | `install.sh` detects a source checkout and runs `cargo build --release` for `jig-server`, `jig-cli`, and `text-block` (wasm32-wasip1). Works. | Same. | READY |
| Install (binary) | **Broken, and unverifiable.** `install_from_release` fetches `${JIG_RELEASES_BASE}/${JIG_VERSION}/jig-<os>-<arch>.tar.gz` — default base `https://releases.jig.onl`, default version `v0.0.2` — but `release.yml` publishes to **GitHub Releases**, not to that host. It also extracts to `$tmp` and then copies `$tmp/bin/jig-server`, while the release tarball's root is `jig-<platform>/bin/…`. And no checksum is verified, despite `release.yml` publishing a `.sha256` alongside every tarball. | URL points where artifacts actually are; paths match the tarball layout; `.sha256` verified before extraction. | BLOCKER |
| Upgrade path | None. No `jig upgrade`, no version pinning, no store migration story. `install.sh` overwrites `$JIG_HOME/bin` in place. | A documented upgrade that states what happens to `jig.db` / `jig_v002.db`. | GAP |
| Backup | `deploy/jig-backup.sh` + systemd timer. Genuinely good: `VACUUM INTO` (not `cp`) for both `jig.db` and the derived `jig_v002.db`, `server.key` included, `umask 077`, partial snapshots removed on failure, retention pruning with `DRY_RUN`. | Same, plus offsite. | READY |
| Restore | Documented in `deploy/README.md` ("Restore"), including the `chmod 600` on `server.key` and a post-restore `server_did` check. | Same. | READY |
| Observability | `/healthz` (static 200, deliberately does not touch the store) and `/metrics` (Prometheus text). Both mounted unconditionally, outside the v0.0.1 gate. Counters are hand-rolled atomics in `v0_0_2_ws::metrics`; **federation and bridge ingest are not counted**. | Metrics cover every ingest path, not just WSS. | GAP |
| Server key loss | `deploy/README.md` opens with a red-flagged section: losing `/var/lib/jig/server.key` changes the server DID and breaks TOFU pinning for every client that ever connected. There is no key-rotation or re-pin flow — recovery is "restore the key from backup". | A documented rotation ceremony, or an identity that survives key change. | GAP |
| Public exposure | `[tls]` exists but defaults off; `bind_address` defaults to loopback. `deploy/README.md` says never set `0.0.0.0`. | n/a — see §1. | See §1 |

---

## 3. Protocol stability

| Layer | Versioned? | Enforced? |
| --- | --- | --- |
| WSS envelope | Yes — `Envelope { v: u8 }`, always `1` ([`envelope.rs:27`](../repos/jig-pipeline/src/envelope.rs)) | **No.** No code path reads `env.v`. A `v: 99` frame is processed identically to `v: 1`. |
| Block manifest | Yes — `BlockManifest.schema`, default `https://jig.dev/schema/block-manifest/v0.1` ([`manifest.rs:22`](../repos/jig-core/src/manifest.rs)) | **No.** The field is never compared, validated, or dispatched on outside of test fixtures. Also note the URI says `jig.dev`, which is not our domain. |
| Receipt | Yes — `RECEIPT_SCHEMA_VERSION = "0.2"` ([`receipt.rs:38`](../repos/jig-core/src/receipt.rs)), stamped on every receipt | Structurally, yes: the field must be non-empty. No consumer branches on its value. |
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
Every version field in the system is a *label*, not a *gate*. External users
must be told, in the README and on the release page, that v0.0.x makes no wire
or receipt compatibility guarantee and that breaking changes ship without a
migration. Crate versions already say this (`0.0.1`–`0.0.3`) and
`release.yml` marks every `v0.0.*` tag `prerelease: true` — the docs need to
match.

---

## 4. Documentation

| Artifact | Exists? | Notes |
| --- | --- | --- |
| Root `README.md` | No | Landing in this same batch (a sibling lane owns it). `release.yml` already tries to `cp install.sh README.md LICENSE "$STAGE/"` with `2>/dev/null \|\| true` — so today it silently ships a tarball with neither. |
| `repos/README.md` | Yes | Workspace-level architecture. Accurate on crate roles. Not a front door. |
| `CONTRIBUTING.md` (root) | No | One exists at `repos/jig-spec/CONTRIBUTING.md`, scoped to the spec book only. |
| `CODE_OF_CONDUCT.md` | No | Nowhere in the tree. |
| `SECURITY.md` (root) | No | See §1.8. |
| Deployment docs | Yes, strong | `deploy/README.md` (426 lines: install, tailnet security model, TLS via `tailscale cert`, teammate onboarding, backups, restore, gotchas), `docs/deployment/gcp-vps-runbook.md` (940 lines), plus dogfood runbooks and an install benchmark. |
| Per-crate rustdoc | Partial | Module- and item-level doc comments are dense and unusually good (the `//!` headers carry real rationale). But **no crate sets `#![warn(missing_docs)]`** and none carries `[package.metadata.docs.rs]`, so there is no rendered API reference anywhere. Only `integration-tests` sets `publish = false`; the rest are publishable-by-accident, including five `jig-gui/riverdance` crates named `ui`, `api`, `web`, `desktop`, and `mobile`. |
| `jig-spec` book | Yes | mdbook under `repos/jig-spec/`. **Describes unshipped behaviour in the present tense** — E2EE (`age+x25519`), crypto-suite negotiation, SSH/gRPC transports. Needs an implementation-status banner before anyone outside reads it. |
| `jig-gui` (riverdance) | Scaffold | `repos/jig-gui/riverdance/README.md` is verbatim Dioxus template boilerplate ("your_project"). It is a design mock, not a working client, and nothing in the repo says so where a newcomer would look. |

**Verdict: GAP**, trending to READY once the README lands — with the caveat
that `jig-spec` shipping unimplemented crypto in the present tense is closer to
a security-communication BLOCKER than a docs gap (see §1.3).

---

## 5. Legal / licensing

The intent is AGPL-3.0. The tree does not consistently say so.

| Finding | Detail |
| --- | --- |
| No root `LICENSE` | There is no `LICENSE` file at the repository root. GitHub therefore shows the repo as unlicensed. `release.yml` tries to copy one into every tarball and silently skips it. |
| Workspace declares a deprecated SPDX id | `repos/Cargo.toml` sets `[workspace.package] license = "AGPL-3.0"`. The current SPDX id is `AGPL-3.0-only` (or `-or-later`). `deny.toml`'s allowlist contains only `AGPL-3.0-only`; this passes solely because `[licenses.private] ignore = true` exempts workspace members. |
| Crate licenses are split, not uniform | AGPL-3.0-only: `jig-core`, `jig-server`, `jig-config`, `jig-pipeline`, `jig-runtime`, `jig-nameserver`, `jig-bridge-core`. **MIT**: `jig-cli`, `jig-client`, `text-block`, `hello-wasm`, `jig-bridge-email`. **None declared**: `integration-tests`, and all five `jig-gui/riverdance/*` crates. |
| `LICENSE` files are notice stubs, not license text | `repos/jig-core/LICENSE` and `repos/jig-server/LICENSE` are 18 lines: the AGPL §14-style notice followed by `[Full AGPL-3.0 license text available at https://www.gnu.org/licenses/agpl-3.0.txt]`. AGPL requires the full text accompany the work. `repos/jig-cli/LICENSE` is genuine MIT text; `repos/jig-spec/LICENSE` is CC-BY-SA-4.0 (reasonable for a spec, but a third licence nobody has written down). |
| Copyright line | "Jig Protocol Contributors", 2024. Fine, but there is no CLA/DCO and no `.github` contribution config to attach one to. |

**Ready means**: a root `LICENSE` with full AGPL-3.0 text; every crate
declaring an intentional SPDX id; the MIT/AGPL split documented as a decision
(MIT for the client and the blocks is defensible — say so) rather than looking
like drift; `jig-spec`'s CC-BY-SA noted in the README.

**Verdict: BLOCKER.** Not because the risk is high, but because "the licence
file is missing and five crates disagree about the licence" is the first thing
a serious external adopter checks, and the cost to fix is an afternoon.

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

`.github/` contains exactly two files: `workflows/ci.yml` and
`workflows/release.yml`. Nothing else.

| Item | State | Verdict |
| --- | --- | --- |
| Issue templates | None | GAP |
| PR template | None | GAP |
| `CODEOWNERS` | None | GAP |
| Discussion / support channel | None public. Per-crate `SECURITY.md` points at `#alert-security`, an internal channel. | GAP |
| Triage owner | Undefined. No rotation, no SLA, nothing written down. | BLOCKER-adjacent — an unowned inbox is how a project acquires a reputation for ignoring people. |
| Release cadence | Undefined. `release.yml` is tag-triggered and marks `v0.0.*` as prerelease; no schedule or policy exists. | GAP |
| CI coverage | 3 jobs: `workspace`, `wasm-build`, `dependency-policy` (the last also runs daily at 07:17 UTC against `main` so advisory-DB drift is not blamed on a contributor's PR — good practice). **Caveats an external contributor will hit:** clippy runs on 7 crates only — `jig-server`, `jig-nameserver`, and `jig-cli` are formatted and tested but **not linted**; `jig-runtime`, `hello-wasm`, and all `jig-gui/*` crates are neither built nor tested; the matrix is `ubuntu-latest` only, so macOS and Windows are untested despite `release.yml` shipping darwin binaries. | GAP |

**Test counts, measured** (`cargo nextest list`, stable 1.97.1): 1,054 tests in
the CI-gated package set, plus 87 in `jig-runtime` + `hello-wasm` = **1,141**.
Reports of 1,143 are within rounding of this but do not reproduce exactly; if a
precise number goes in a README, re-measure it there.

---

## Verdict

**No. jig is not ready for external users today.** Not close.

The single sentence that decides it: **a jig server has no authentication and
no authorization, so anyone who can reach the port can read and write every
channel on it, including the ones the CLI told the user were "membership-gated".**
Every current deployment is safe only because it is bound to a tailnet address.
Publishing an install script that stands up that server on a public address
would be handing strangers a footgun with our name on it.

### Minimum credible blocker set, ordered

| # | Blocker | Why it is in this position |
| --- | --- | --- |
| 1 | **Authn + authz on `jig-server`** | Everything else is cosmetic while the port is open to the world. Includes enforcing `visibility`/membership on reads, or removing the flag and its `--help` text. |
| 2 | **Root `SECURITY.md` with an external reporting path** | Cheap, and blocker #1 guarantees findings. Without it the first report is public. |
| 3 | **Root `LICENSE` (full AGPL-3.0 text) + consistent per-crate SPDX ids** | An afternoon. First thing an adopter checks; currently the repo reads as unlicensed. |
| 4 | **Fix the binary install path** | `install.sh` points at a host that serves nothing, unpacks the wrong paths, and verifies no checksum — while `release.yml` already publishes the `.sha256`. A `curl \| sh` KPI that does not work is worse than not having one. |
| 5 | **Say plainly that v0.0.x has no compatibility guarantee** | README + release notes. Every version field in the system is a label, not a gate; users must not infer stability from their presence. |
| 6 | **Implementation-status banner on `jig-spec`** | It documents E2EE we have not written, in the present tense. Shipping that unqualified is a claim about privacy we cannot back. |
| 7 | **Clear the reachable advisory suppressions** | Three lockfile bumps (`time`, `tracing-subscriber`, `rand`) plus the rustls 0.22 → 0.23 dedup that retires the four `rustls-webpki` ignores. |
| 8 | **Name a triage owner and publish a support channel** | Not technical. Determines whether the first outside contributor comes back. |

Items 2–8 are days of work. Item 1 is the real project.

Until item 1 lands, the honest external posture is: **source-available for
reading and auditing, not for running.** That is a defensible thing to announce —
"here is a protocol implementation, here is what works, here is the security
model, do not put it on the internet yet" — and it is far better than shipping
an install script that implies otherwise.
