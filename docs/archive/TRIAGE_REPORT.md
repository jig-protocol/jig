> **HISTORICAL — archived.** A snapshot of the workspace on 2026-03-26. Its test count
> ("658/658"), its per-crate table, and its file paths (e.g. `repos/jig-core/install.sh`,
> the `jig-email-bridge` crate) no longer match the tree — `install.sh` is at the repo
> root and the bridges are `repos/bridges/{core,email}`. Retained for its triage
> narrative and its blocker analysis, not as a status page. For current state see
> [`docs/README.md`](../README.md) and the deployment docs it indexes.

# Jig Protocol — Triage Report

**Generated:** 2026-03-26  
**Triage scope:** `~/repos/jig-protocol/repos/` (workspace root)  
**Status after triage:** Build fixed, 658/658 tests pass ✅

---

## 1. Build Status

### What Was Broken

Two separate bugs prevented tests from compiling cleanly:

**Bug 1 — `jig-cli/src/cmd/block_run.rs`** (original reported issue)  
`block_run.rs` was written against a stale `Receipt` API that no longer existed. Specifically:
- `receipt.error_message` → field doesn't exist; error lives in `receipt.error: Option<ReceiptError>` → `err.message`
- `receipt.error_code` → ditto, lives in `receipt.error.code`
- `receipt.is_success()` → method was removed; replacement is `receipt.outcome != ExecutionOutcome::Success`
- `receipt.block_id` → now `receipt.block.block_id` (CID, not `Option<String>`)
- `receipt.host` → now `receipt.block.host`
- `receipt.executed_at` → now `receipt.block.executed_at`
- `receipt.fuel_used` → now `receipt.fuel_used()` (method)
- `receipt.limits.fuel_max` → now `receipt.block.limits.as_ref().map(|l| l.fuel_max)`
- `receipt.memory_peak_mb` → now `receipt.block.memory_peak_mb`
- `receipt.module_hash` → now `Option<ModuleHash>` struct with `.value` field (not a plain String)

**Fix applied:** Rewrote all field/method accesses in `block_run.rs` to match the current `jig-runtime::Receipt` and `jig-core::BlockReceipt` API.

**Bug 2 — `jig-server/src/handler.rs`** (test compilation only)  
Two tests (`parse_time_range_custom_ok` and `list_blocks_clamps_limit_to_200`) were accidentally pasted inside the `parse_time_range` function body rather than in the `mod tests` block. This caused:
- The function's return type to change to `()` instead of `Result<TimeRange, ApiError>`
- `tempdir()` to be out of scope (import was in `mod tests`)
- `semver::Version::new(1, 0, i)` to fail because loop variable `i` was `u32` but `Version::new` takes `u64`

**Fix applied:** Moved both tests to `mod tests`, added local `use tempfile::tempdir;`, changed loop to `0..205u64`.

**Bug 3 — `integration-tests/tests/runtime_workspace_integration.rs`** (test compilation only)  
Integration tests used `Receipt::new(...)`, `receipt.is_success()`, and `receipt.fuel_used` (field, not method) — all removed in the Receipt v0.2 refactor.

**Fix applied:** Replaced stale `Receipt::new()` test with an `ExecutionOutcome` enum check; replaced `receipt.is_success()` with `matches!(receipt.outcome, ExecutionOutcome::Success)`; replaced `receipt.fuel_used` with `receipt.fuel_used()`; replaced `ExecutionContext { ..Default::default() }` struct init (which errors due to `pub(crate) capability_meter` field) with `ExecutionContext::default()` + field assignment.

**Bug 4 — `jig-cli/Cargo.toml`** (test compilation only)  
`jig-cli/src/receipt/v0_2.rs` test module uses `time::OffsetDateTime` but `time` was not in jig-cli's dependencies.

**Fix applied:** Added `time = { version = "0.3", features = ["serde"] }` to `[dev-dependencies]`.

### Final Build Result

```
cargo build --workspace → Finished (0 errors, warnings only)
cargo nextest run --workspace → 658 tests run: 658 passed, 2 skipped
```

---

## 2. Per-Crate Status

| Crate | Builds | Tests Pass | Functional | Description | OSS-Ready? |
|-------|--------|------------|------------|-------------|-----------|
| **jig-core** | ✅ | ✅ | ✅ Functional | Core protocol types: BlockManifest, BlockBundle, BlockReceipt v0.2, CID, DID, capability scopes, canonical JSON. Well-tested. | 🟡 Minor: WASM validation utils (`wasmparser`) still TODO in IMPL_PLAN |
| **jig-runtime** | ✅ | ✅ | ✅ Functional | Wasmtime-backed WASM execution runtime with fuel metering, WASI preview1, capability sandbox, deterministic execution, pricing. Solid foundation. | 🟡 Minor: capability symmetry tests and cross-binary parity pending |
| **jig-server** | ✅ | ✅ | ✅ Functional | Axum HTTP server; block ingestion/retrieval via SQLite; receipt storage; analytics endpoints. Runs on port 7117. `/.well-known/jig`, `/blocks`, `/receipts/:cid` all working. | 🟡 Moderate: full Wasm execution in server, analytics ClickHouse sink, federation not yet done |
| **jig-cli** | ✅ | ✅ | 🟡 Partial | CLI client (`jig` binary); messaging, receipt inspection, block init scaffolding, local WASM execution (feature-gated). Many stubs. `jig block run` planned but incomplete. | 🔴 Significant: many commands are stubs; lacks end-to-end block send workflow |
| **jig-nameserver** | ✅ | ✅ | 🟡 Partial | Nameserver for DID registry, anomaly detection, PoW penalty ledger, analytics backend. Data structures and anomaly detector are real; tribunal/governance hooks are stubs. | 🔴 Significant: adaptive PoW enforcement, tribunal, transparency log not done |
| **jig-email-bridge** | ✅ | ✅ (minimal) | 🟡 Stub | Email↔Jig bridge: SMTP/IMAP scaffolding, email-to-block message type mapping, DNS discovery stub. Many `pub` items are dead code (warnings). | 🔴 Significant: DNS discovery, bi-directional relay, MX integration all unimplemented |
| **jig-config** | ✅ | ✅ | ✅ Functional | Unified config types for server, CLI, runtime, receipts, pricing profiles. Profile inheritance, TOML load/save, env overrides. | 🟡 Minor: profile-driven analytics backend config still TODO |
| **jig-spec** | N/A | N/A | 📖 Docs only | Not a Rust crate — contains mdBook-based spec (`book.toml`), JSON schemas, JEP (Jig Enhancement Proposals) directory. | 🔴 Needs publishing setup; content exists but not yet rendered/hosted |
| **jig-docs** | N/A | N/A | 📖 Docs only | Additional documentation directory; no Cargo.toml. Contains spec drafts. | 🔴 No build/render pipeline |
| **jig-gui (Riverdance)** | ✅ (ui, api) | ✅ (ui) | 🟡 Scaffold | Dioxus-based cross-platform GUI (desktop, mobile, web). `ui` and `api` crates build; mostly scaffold/skeleton with mock data. Desktop/mobile/web crates compile but are largely empty. | 🔴 MVP not built; depends on features not yet in jig-server |

### Notes

- `jig-spec` directory exists but has no `Cargo.toml` — it's an mdBook project, not in the workspace
- `jig-docs` similarly has no `Cargo.toml`
- `hello-wasm` and `integration-tests` are workspace members that support testing, not published crates

---

## 3. curl-to-hello-world Path

### KPI Goal: `curl -L https://jig.onl | sh` → working server in ~60s

### Current Status: **BLOCKED — no hosted binaries at releases.jig.onl**

#### What Exists

An install script lives at `repos/jig-core/install.sh` and is intended to be served at `https://jig.onl/install.sh`. It:
- Detects OS/arch
- Downloads binary from `https://releases.jig.onl/$VERSION/jig-$os-$arch`
- Creates `~/.jig/` directory structure with default TOML config
- Optionally installs systemd service, email bridge, adds to PATH
- Has `--minimal`, `--with-email`, `--with-systemd`, `--dir`, `--version` flags

However: **`releases.jig.onl` does not exist** — no CI/CD pipeline produces binaries, no release infrastructure is set up. The script would fail at the download step.

#### What Actually Works Right Now

A developer who clones the repo and has Rust installed can:
```bash
git clone <repo>
cd repos
cargo build --release -p jig-server
./target/release/jig-server  # starts on localhost:7117
```

The server:
- Responds on port 7117 (default, configurable)
- Returns JSON at `GET /blocks`
- Returns server info JSON at `GET /.well-known/jig`
- Accepts block ingestion at `POST /blocks`
- Stores data in `nameserver.db` (SQLite, auto-created)

#### Minimum for a Stranger to Run a Server

1. Install Rust (rustup)
2. `git clone <repo> && cd repos`  
3. `cargo run -p jig-server`
4. Server up at `http://localhost:7117`

**No `--irc` flag exists** — that flag was in the task description but is not in the binary. IRC bridge is referenced in code but not exposed as a CLI flag.

#### Gaps to Fix the KPI

1. **Set up CI to produce release binaries** (GitHub Actions → `releases.jig.onl`)
2. **Point `jig.onl` to serve the install script** (or redirect to GitHub raw)
3. **Add `jig server start` command to CLI** so the install script can run `jig server start` rather than running `jig-server` binary directly
4. **Smoke-test the install path** (the quickstart shell script in `integration-tests/user-flows/01-quickstart.sh` is close but assumes local binary)

---

## 4. Documentation Summary

### `executable-internet-master-plan/00-README.md`

The master plan index. Establishes four core pillars: executable-by-default blocks (Wasm), E2EE reputation/governance, curl-to-hello-world in 60s, and federated + integration-first architecture. Directs readers through five tiers of docs (vision → architecture → security → implementation → ecosystem). Working agreements require updating Tier docs before architecture-impacting code changes. **Status: Well-written, authoritative, current.**

### `vision/EXECUTABLE_INTERNET_OVERVIEW.md`

The manifesto. Argues browsers ossified around HTML/HTTP, AI-native workflows need provenance + deterministic replay, and Jig's innovation is "executable-by-default blocks" — Wasm modules carrying their own manifest, code, data, and proofs. Key open questions: which capability primitives ship in v1, how to encode privacy-preserving provenance for AI-generated blocks, what minimum tribunal interface is needed. **Status: Strategy is clear; open questions unresolved and not tracked elsewhere.**

### `vision/GO_TO_MARKET_AND_DISTRIBUTION.md`

Four growth loops: (1) domain onboarding Trojan Horse ("professional email" → DNS autoconfig → Jig block-backed mail), (2) CLI/hacker channels, (3) integration hub embedding (Linear, GitHub, PagerDuty connectors as blocks), (4) bridge-led expansion (email viral signature "Secured by Jig Block"). Rollout plan has five phases ending at AI/LLM lineage tracking. **Status: Strategy is sound; all dependencies are un-built (email bridge, DNS discovery, capability marketplace).**

### `vision/PRODUCT_PILLARS_AND_METRICS.md`

Five measurable pillars with specific KPIs: ≥90% block traffic share, ≥99.9% deterministic render rate, 95% curl-install success, bridge latency <200ms p95, <10min block authoring time. Instrumentation requirements call for anonymized telemetry schema across server/CLI/bridges feeding ClickHouse/Parquet. **Status: Good KPI spec; none of the measurement infrastructure exists yet.**

### `vision/INTEGRATION_AND_PARTNERSHIPS.md`

Priority integration categories: incident/DevOps (PagerDuty, Linear, GitHub), messaging bridges (IRC, Matrix, ActivityPub, ATProto), productivity (Cal, Notion, Slack migrator), email providers (Resend, Postmark, SendGrid). Roadmap: foundational alliances → developer toolchain → federated protocols → enterprise security. **Status: Aspirational; no connectors implemented.**

### `executable-internet-master-plan/implementation/IMPL_PLAN.md`

Repo-by-repo program plan. M0-M5 milestones (workspace reset through agent/GUI enablement). Per-crate checklists with ✅/☐ status. `jig-core` block schema ✅; Wasm validation utilities ☐. `jig-server` Wasmtime scaffold ✅, full execution/capability enforcement ☐, integration bus ☐, analytics ClickHouse sink PARTIAL. **Status: Useful tracking document; M1 mostly done, M2-M5 largely unstarted.**

### `IMPLEMENTATION_PLAN.md` (repo root)

Cross-binary protocol alignment plan dated 2025-11-09. 50-task matrix covering Receipt v0.2 integration, analytics layer (ClickHouse + DuckDB/Parquet), server integration, pricing/metering, CLI parity, runtime symmetry, config alignment, nameserver integration, federation, testing. **All 50 tasks are "Not Started."** This is the clearest picture of the work queue; it's comprehensive but completely unexecuted.

### What Are NORAD Chats?

**NORAD** stands for **Network Operations Redaction And Deletion** — a zero-trust cryptographic redaction protocol specified in `ADR-005` (archived under `executable-internet-master-plan/archive/legacy-block-plan/`). 

NORAD chats are messages that carry a built-in cryptographic deletion capability: when all parties agree to redact a message, a threshold ceremony (requiring M-of-N participant signatures) reconstructs the encryption key, performs cryptographic deletion, and produces a verifiable proof of destruction. The protocol uses Shamir secret sharing, zero-knowledge proofs, and optionally hardware attestation (Intel SGX). 

**Current status: NORAD is an ADR/design document only.** The `jig-gui/README.md` lists "NORAD redaction protocol" as a planned feature. No implementation exists in any crate. It's architecturally sound and well-specified but purely aspirational at this stage.

---

## 5. Top 3 Blockers for OSS Publish

### Blocker 1: No Release Infrastructure (Severity: CRITICAL)
The curl-to-hello-world KPI is the protocol's #1 stated requirement and it is completely blocked. There are no GitHub Actions workflows, no CI pipeline, no release binary hosting at `releases.jig.onl`, and no mechanism to actually serve `https://jig.onl/install.sh`. A stranger cannot install Jig today without a full Rust toolchain and git clone. Until this exists, the protocol cannot onboard any external users.

**Fix:** Set up GitHub Actions to build release binaries for linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64 on tag push; host at GitHub Releases or a CDN; serve the install script.

### Blocker 2: Core User Workflows Are Stubs (Severity: HIGH)
The CLI (`jig`) is the primary user interface but many commands are unimplemented stubs. There is no end-to-end workflow where a user can: (1) run a server, (2) send a block, (3) have another user receive and execute it. `jig block run` is planned but incomplete. The server has no WASM execution in the hot path (Wasmtime is embedded but block execution returns a receipt from runtime without full capability enforcement). Federation (server-to-server block relay) is unimplemented.

**Fix:** Before OSS publish, define a narrow "happy path" demo scenario (e.g., Alice sends a hello.wasm block to Bob via a shared server), implement it end-to-end, and gate the release on that demo working.

### Blocker 3: Identity/Nameserver Is Non-Functional (Severity: HIGH)
The nameserver holds DID registration, PoW enforcement, tribunal governance, and the reputation system — all of which are described as essential to the security model ("E2EE Reputation" is Pillar 2). Currently the nameserver has data structures and an anomaly detector but no PoW enforcement, no tribunal, no transparency log, no cross-server identity validation. This means the security model described in the docs doesn't exist in the code. Publishing as OSS with this gap would invite criticism that Jig's security claims are vaporware.

**Fix:** Either (a) implement a minimal PoW + DID registration flow before publish, or (b) be explicit in the README that identity/governance are not yet implemented and the current release is "protocol skeleton + runtime + server prototype."

---

## 6. Recommended Next Steps

### Immediate (This Week)

1. **Set up CI/CD** — GitHub Actions: `cargo build --release` on tag, upload artifacts to GitHub Releases. Update install.sh to point to GitHub Releases. This unblocks the curl-to-hello-world KPI.

2. **Define and implement the demo path** — Pick the narrowest possible E2E: server starts → CLI sends a text block → another CLI reads it. Wire it up with `cargo run -p jig-server` + `cargo run -p jig-cli`. Write a shell script that demos it in <60s. This becomes the README quick start.

3. **Write an honest README** — The current README is sparse. It should say clearly: what works (server, runtime, block manifests, receipts), what's planned (identity, federation, email bridge, GUI), and how to run the demo. Honesty about scope is better than implied completeness for OSS launch.

### Near-Term (Next 2-4 Weeks)

4. **Implement `IMPLEMENTATION_PLAN.md` Phase E (CLI Parity)** — Tasks 22-26: `jig block run` command with `--receipt` flag and parity verification. This is the most visible developer-facing feature and unlocks the block authoring KPI.

5. **Minimum viable nameserver** — Implement DID registration and basic PoW challenge/response in `jig-nameserver`. Even a simplified version is better than publishing with zero identity infrastructure.

6. **Wire up the integration-tests user-flows** — The shell scripts in `integration-tests/user-flows/` are nearly complete quickstart flows. Fix them to work against the actual binaries and add them to CI. They serve as both regression tests and documentation.

### Medium-Term (Next Month)

7. **Analytics tier** — ClickHouse is overkill for potato-tier; the DuckDB/Parquet path is the right default. Implement the potato analytics sink (Tasks 5-9 in IMPLEMENTATION_PLAN.md) so server operators have visibility into block execution.

8. **Email bridge** — DNS discovery + basic SMTP ingest is the minimum for the "domain Trojan Horse" GTM loop. The scaffold is there; needs the missing pieces (DNS SRV/TXT lookup, actual SMTP handling).

9. **jig-spec mdBook** — Set up mdBook CI to publish the spec as a hosted docs site. The JEP directory and schemas are valuable for external contributors but invisible without a build pipeline.

---

## Appendix: Files Changed During Triage

| File | Change |
|------|--------|
| `jig-cli/src/cmd/block_run.rs` | Fixed stale Receipt API usage (error_message, is_success, field paths) |
| `jig-server/src/handler.rs` | Moved two stray tests from inside function body to `mod tests`; fixed `u32`→`u64` type |
| `integration-tests/tests/runtime_workspace_integration.rs` | Replaced `Receipt::new()`, `is_success()`, `fuel_used` field with current API |
| `jig-cli/Cargo.toml` | Added `time` to dev-dependencies |
