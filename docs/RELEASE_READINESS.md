# Release readiness: internal → external

The gate between "we dogfood jig on our own tailnet" and "we tell strangers to
run `curl -fsSL https://jig.onl/install.sh | bash`".

jig is MIT OR Apache-2.0 source in a public-shaped repo, but it has never been
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
| **Gap** | Reputation is consumed, not computed: the view is what the operator wrote in config, there is no ledger and no exchange of scores. No rate limiting or proof-of-work in front of the gates. Tier-1 trusted connections (phase 5) are not built. Blocks relayed by a federated peer are persisted and delivered without running the write gate (`v0_0_2_federation.rs` does not go through `ingest`), so federation is trust-on-peer. There is no `member-remove` block yet; revocation is a store operation. |

**Verdict: GAP** (was BLOCKER). The part that let strangers read and write every
channel is closed and proven by fault injection at each gate, and an operator can
now refuse callers outright; what remains is scoring, throttling and the tier-1
fast path, not the absence of a model.

### 1.2 `visibility = "restricted"` is enforced

| | |
| --- | --- |
| **Current state** | `restricted` gates history (`403 NOT_A_MEMBER`), the listing (restricted channels and their `owner_did` are not shown to non-members), live WSS delivery (per block, so removing a membership stops an open subscription) and posting (`403 NOT_A_MEMBER` at ingest, on every surface). Self-join works on open channels only; on restricted ones only the owner adds members. Unknown visibility strings and store errors fail closed. |
| **Ready means** | `restricted` gates reads (history, WSS delivery) and writes to non-members. |
| **Gap** | Peer-relayed blocks bypass the posting gate (see §1.1). Timing still distinguishes a refused read from an unknown channel under a concealing disclosure policy — a stated limitation of the design, and the default policy conceals nothing. |

The CLI's `restricted (membership-gated reads)` help text is now true, and
`jig channel join` says which channels it can join.

**Verdict: READY.**

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
| **Authentication** | Both handlers run the bundle through `jig_pipeline::ingest`, which verifies the ed25519 signature and rejects `INVALID_SIG`. The *author DID is authenticated* — you cannot forge someone else's DID here. |
| **Authorization** | Owner checks on channel mutation now run inside `ingest` (`jig-pipeline/src/authorize_write.rs`), so they hold on the admin routes, the public `POST /api/v1/blocks`, WSS `Submit` and the bridge path alike: `member-add` of anyone but yourself, or onto a restricted channel, and `channel-promote` must be signed by the channel owner (`403 NOT_CHANNEL_OWNER`); `channel-archive` keeps its own owner check. Any self-minted keypair can still *create* channels, which is by design. |
| **Ready means** | Ownership/role checks on channel mutation, and a channel-ops path that does not live behind a `[debug]` flag. |

**Verdict: GAP** (was BLOCKER). The mutation is authorized; the remaining
problem is the label — the only working channel-management path is still
mounted by a `[debug]` flag, and "debug" reads as "harmless" to an operator.

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
| **Current state** | Tighter than the rest of the system. `build_wasi_context` ([`jig-runtime/src/engine.rs:293`](../repos/jig-runtime/src/engine.rs)) grants an empty stdin pipe and an in-memory stdout buffer — no host stdio, no preopened directories, no sockets. Store limits pin one instance, one memory, 10 tables, 10k table elements; fuel and an epoch deadline bound runtime. Server defaults: 5,000,000 fuel, 64 MB, plus a timeout ([`jig-server/src/config.rs:296-304`](../repos/jig-server/src/config.rs)). wasmtime is 47.0.4 (RUSTSEC-2026-0268/0269 closed by the patch bump, not suppressed; jig never enables WASI, so neither was reachable) — including RUSTSEC-2026-0096 (aarch64 Cranelift guest-heap miscompile → sandbox escape). |
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

### Two deliberate carve-outs

**`repos/jig-gui/` (Riverdance) — no licence granted.** A client application is not
protocol surface, and the reusability argument does not transfer to it. AGPL or BSL may be
correct; that decision is open. Until then default copyright applies, all five crates are
`publish = false`, and [`repos/jig-gui/NOTICE.md`](../repos/jig-gui/NOTICE.md) states this
explicitly so the silence is not read as an oversight. Nothing in the protocol crates
depends on this subtree, so its status cannot contaminate them.

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

The sentence that used to decide it — *a jig server has no authentication and
no authorization* — is no longer true: reads require proof of possession,
restricted channels are membership-gated on every surface, and membership
changes are owner-signed. What decides it now is the rest of this document:
no admission policy or rate limiting in front of those gates, federation on
trust, no E2EE, a broken install path, and no disclosure channel. Publishing an
install script that stands up a server on a public address is still handing
strangers a footgun — a smaller one, with the safety on.

### Minimum credible blocker set, ordered

| # | Blocker | Why it is in this position |
| --- | --- | --- |
| ~~1~~ | ~~**Authn + authz on `jig-server`**~~ | **Phases 1–4 DONE 2026-09-11** — per-request proof of possession on reads, `visibility`/membership enforced on history, listing, live delivery and posting, owner-signed membership changes, and an admission policy (bans, ruleset floors, explicit unknown-DID choice) on every read and write. Still open from the same design: trusted connections (phase 5); see §1.1. |
| 2 | **Root `SECURITY.md` with an external reporting path** | Cheap, and blocker #1 guarantees findings. Without it the first report is public. |
| ~~3~~ | ~~**Root `LICENSE` + consistent per-crate SPDX ids**~~ | **DONE 2026-08-06** — dual-licensed MIT OR Apache-2.0, root licence pair added, every protocol crate aligned. `jig-spec` moved to CC-BY-4.0 on 2026-10-05. |
| 4 | **Fix the binary install path** | `install.sh` points at a host that serves nothing, unpacks the wrong paths, and verifies no checksum — while `release.yml` already publishes the `.sha256`. A `curl \| sh` KPI that does not work is worse than not having one. |
| 5 | **Say plainly that v0.0.x has no compatibility guarantee** | README + release notes. Every version field in the system is a label, not a gate; users must not infer stability from their presence. |
| 6 | **Implementation-status banner on `jig-spec`** | It documents E2EE we have not written, in the present tense. Shipping that unqualified is a claim about privacy we cannot back. |
| 7 | **Clear the reachable advisory suppressions** | Three lockfile bumps (`time`, `tracing-subscriber`, `rand`) plus the rustls 0.22 → 0.23 dedup that retires the four `rustls-webpki` ignores. |
| 8 | **Name a triage owner and publish a support channel** | Not technical. Determines whether the first outside contributor comes back. |

Items 2–8 are days of work. Item 1 was the real project; its first three
phases have landed, and what remains of it (admission, trusted connections) is
policy on top of a model rather than the absence of one.

Until the rest lands, the honest external posture is still: **source-available
for reading and auditing, not for running on a public address.** That is a
defensible thing to announce — "here is a protocol implementation, here is what
works, here is the security model, do not put it on the internet yet" — and it
is far better than shipping an install script that implies otherwise.
