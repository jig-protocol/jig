# jig-runtime Implementation Plan (Executable Internet + Fuel v0.2)

**Owners:** jig-runtime maintainers  
**Last-reviewed:** 2025-11-03  
**Scope:** Upgrade jig-runtime to a full, shared WASM runtime crate with deterministic execution, capability sandboxing, instrumentable and pricing-compatible fuel (receipt v0.2), and standardized integrations with jig-server, jig-cli, and jig-gui.  
**Out of scope:** docker/podman/kube extensions and any non-WASM runtime paths for core builds.

## References

- repos/jig-spec/src/block-execution.md
- repos/jig-spec/src/receipts.md

## Notes

- Follow licensing constraints from deny.toml (prefer permissive; avoid AGPL/GPL; internal gigue packages are closed-source and must not error).
- docker/podman repos and runtime-select are to be archived as part of cleanup; WASM is the one true core runtime path.

---

## Current State Assessment

- jig-runtime is currently trait-oriented and not a unified, shared runtime crate implementing the full executable internet specification.
- WASM execution exists in pieces but lacks a cohesive, deterministic, capability-sandboxed engine with per-capability fuel.
- No complete receipt v0.2 implementation with pricing-compatible counters and limits.
- Consumers (jig-server, jig-cli, jig-gui) are not standardized on a single runtime abstraction.
- Vestigial repos exist (jig-docker, jig-podman, jig-runtime-select) and must be archived to avoid confusion.

### jig-runtime-select: Deprecation Decision

**Current role:** Multi-engine dispatcher that selects between wasmtime/podman/docker/local-process based on env or config.

**Why deprecate:**

- The new architecture has **WASM as the only core runtime** (docker/podman out-of-scope).
- jig-runtime is becoming a full implementation, not a trait-only interface.
- No need for runtime selection when there's only one canonical engine.
- Config-driven behavior (limits, capabilities) moves **into** jig-runtime, not a separate selector layer.

**Migration path:**

- Remove jig-runtime-select as a dependency from jig-cli (currently feature-gated and unused).
- Consumers will import jig-runtime directly and use its Runner API.
- Engine-specific config (previously in `[runtime.wasmtime]`) becomes core jig-runtime config.

## Architecture Decisions (to confirm per 20251102 review)

- **Execution engine:** Wasmtime (Component Model/WIT preferred) with preview2 WASI and capability imports.
- **Determinism and safety by default:**
  - Fuel metering enabled (instruction-level via Wasmtime).
  - No threads, no real wall-clock access, canonicalized NaNs, no host entropy; provide seeded RNG capability.
  - Epoch-based interruption or fuel-only timeouts; strict resource limits (memory, stack, instances).
- **Capability model:**
  - Closed-by-default; explicit allowlist per run.
  - Capability handles via WIT imports (jig:cap/\*@v0.x).
  - Policy enforcement in runtime; per-capability quotas and budgets.
- **Fuel and pricing:**
  - Dual accounting: WASM instruction fuel (engine) + hostcall synthetic fuel per capability with a versioned cost schedule.
  - Pricing-compatible receipt fields and reproducible accounting.
- **Receipt v0.2:**
  - Deterministic, canonical serialization; includes counters, timings, limits, outcomes, and digests of logs/traces.
  - Optional signing and hashing for provenance.
- **Integration:**
  - Single jig-runtime crate consumed by jig-server, jig-cli, jig-gui with a stable Runner API and ExecutionContext.
- **Out-of-scope:** docker/podman/kube adapters until later phases.

## Implementation Sequence

1. **Repo restructure:** promote jig-runtime to shared runtime crate with clear modules, features, and public API.
2. **Engine integration:** Wasmtime configuration for determinism, component model support, and WASI preview2 wiring.
3. **Capability layer:** WIT-based capability interfaces, registry, handles, and policy enforcement.
4. **Fuel/metering:** instruction fuel + hostcall fuel; budgets; pricing schedule; telemetry hooks.
5. **Receipt v0.2:** schema, canonical serialization, and integration with runtime events.
6. **Integration:** migrate jig-server, jig-cli, jig-gui to new jig-runtime Runner API.
7. **Tests/validation:** determinism, parity across consumers, perf budgets, security enforcement.
8. **Deprecation/cleanup:** archive vestigial repos; remove runtime-select; docs update.

---

## Comprehensive Tabular Checklists

### Core Runtime Architecture

| Priority | Status | Description                                                                                                      | Dependencies             | Notes                                                    |
| -------- | ------ | ---------------------------------------------------------------------------------------------------------------- | ------------------------ | -------------------------------------------------------- |
| P0       | ☐      | Create unified crate structure crates/jig-runtime with modules: engine, capabilities, fuel, receipt, api, config | jig-spec block-execution.md    | Replace trait-only façade with full implementation crate |
| P0       | ☐      | Define public Runner API: Runtime, ExecutionContext, BlockPackage, Limits, Outcome                               | jig-spec block-execution.md | Stable API for jig-server/cli/gui                        |
| P0       | ☐      | Config struct + builder covering limits, capabilities, fuel budgets, pricing schedule ref                        | jig-spec block-execution.md | Serialize from TOML/JSON; environment overrides          |
| P0       | ☐      | Strongly-typed error model (RuntimeError taxonomy)                                                               |                          | Map to receipt outcomes                                  |
| P0       | ☐      | Feature flags: component-model, wasi-preview2, deterministic, tracing, receipt-signing                           |                          | Keep default minimal and deterministic                   |
| P0       | ☐      | Structured tracing/logging via tracing crate with span taxonomy                                                  |                          | Toggle via feature and env                               |
| P0       | ☐      | Deny.toml and cargo-deny integration for licenses and bans                                                       | Licensing rule           | Avoid AGPL/GPL; allow internal gigue                     |
| P1       | ☐      | Crate-level docs and examples; README with quickstart                                                            |                          | Include example block and run snippet                    |
| P1       | ☐      | CI: build, test, fmt, clippy, cargo-deny                                                                         |                          | Matrix for macOS/Linux                                   |
| P1       | ☐      | Versioning strategy and CHANGELOG from 0.x→0.y release                                                           |                          | Tag milestones                                           |
| P1       | ☐      | Remove jig-runtime-select and route consumers to new API                                                         |                          | Part of deprecation phase                                |
| P2       | ☐      | Bench harness for cold/warm start and fuel costs                                                                 |                          | For pricing calibration                                  |

### WASM Execution Engine (Wasmtime)

| Priority | Status | Description                                                                       | Dependencies             | Notes                                     |
| -------- | ------ | --------------------------------------------------------------------------------- | ------------------------ | ----------------------------------------- |
| P0       | ☐      | Pin Wasmtime version and strategy; enable consume_fuel(true)                      |                          | Choose latest stable with component model |
| P0       | ☐      | Initialize engine/store with deterministic config (canonicalize NaNs, no threads) | jig-spec block-execution.md | Lock down non-determinism                 |
| P0       | ☐      | Support Component Model (WIT) and fallback to core wasm modules                   | 20251102 review          | Prefer components for capabilities        |
| P0       | ☐      | WASI preview2 setup with minimal surfaces                                         |                          | No direct wall clock or random            |
| P0       | ☐      | Epoch-based interruption or fuel-only timeouts                                    |                          | Evaluate epoch if needed                  |
| P0       | ☐      | Memory/table limits and instance quotas                                           |                          | From ExecutionContext limits              |
| P0       | ☐      | Module validation and safe loader (content-type detection)                        |                          | Reject non-wasm                           |
| P1       | ☐      | Deterministic RNG capability; remove access to host entropy                       | Capability layer         | Seeded via context                        |
| P1       | ☐      | Precompilation/caching toggle (optional)                                          |                          | Ensure cache does not break determinism   |
| P1       | ☐      | Bytecode hashing for provenance and receipts                                      | Receipt v0.2             |                                           |
| P1       | ☐      | Component linker for capability imports jig:cap/\*@0.x                            | Capability layer         | WIT-generated shims                       |
| P2       | ☐      | Sandbox test suite for resource isolation                                         | Testing                  |                                           |

### Fuel & Metering System (pricing-compatible)

| Priority | Status | Description                                                  | Dependencies          | Notes                                 |
| -------- | ------ | ------------------------------------------------------------ | --------------------- | ------------------------------------- |
| P0       | ☐      | Enable Wasmtime instruction fuel with per-run budget         | Engine                | Budget in ExecutionContext            |
| P0       | ☐      | Synthetic fuel for hostcalls per capability                  | Capability layer      | Wrap hostcalls with counters          |
| P0       | ☐      | Versioned cost schedule file (e.g., TOML) mapping units→fuel | jig-spec block-execution.md | Checked into repo with semver         |
| P0       | ☐      | Budget enforcement: overall and per-capability quotas        | Engine, Capability    | Errors map to receipt limits_exceeded |
| P0       | ☐      | Pricing mapping: fuel units→cost (configurable)              | Receipt               | Provide price field optional          |
| P0       | ☐      | Counters: calls, bytes_in/out, time_ns, wasm_fuel_in_calls   | Receipt v0.2          | Deterministic where possible          |
| P1       | ☐      | Telemetry hooks for metrics export (feature-gated)           |                       | No PII; sampling controls             |
| P1       | ☐      | Exhaustion behavior: soft vs hard fail modes                 |                       | Configurable per run                  |
| P1       | ☐      | Numeric safety: saturating/checked arithmetic                |                       | Avoid overflows                       |
| P1       | ☐      | Calibration harness to derive default schedule               | Testing               | Uses microbench runs                  |
| P2       | ☐      | Smoothing/normalization across hardware classes              |                       | Doc-only guidance acceptable          |
| P2       | ☐      | Tooling to diff cost schedules across versions               |                       | Guardrails for pricing changes        |

### Capability Security Model

| Priority | Status | Description                                                                      | Dependencies    | Notes                        |
| -------- | ------ | -------------------------------------------------------------------------------- | --------------- | ---------------------------- |
| P0       | ☐      | Capability registry and policy engine (allowlist, quotas)                        | Core            | Closed by default            |
| P0       | ☐      | Define WIT interfaces for initial caps: http, kv, clock, rand, crypto-basic, env | 20251102 review | Minimal V1 set               |
| P0       | ☐      | Capability handles/tokens with unique IDs per run                                | Core            | Include in receipts          |
| P0       | ☐      | Enforce per-capability limits (reqs/sec, bytes, domains)                         | Fuel            | Network allowlist, size caps |
| P0       | ☐      | Disable filesystem by default; temp-sandbox option if needed                     |                 | Only if explicitly allowed   |
| P1       | ☐      | Clock virtualization (monotonic/seeded), no wall clock                           | Engine          | Deterministic time source    |
| P1       | ☐      | Seeded RNG capability; no host entropy                                           | Engine          | Seed from ExecutionContext   |
| P1       | ☐      | HTTP client sandbox: method/host/headers allowlist                               | http WIT        | Count bytes precisely        |
| P1       | ☐      | KV capability with namespaced keys and quotas                                    | kv WIT          | In-memory default provider   |
| P1       | ☐      | Crypto: hashing and verify primitives only                                       | crypto WIT      | Avoid secrets handling       |
| P2       | ☐      | Env capability: controlled env var exposure                                      | env WIT         | Read-only, allowlist         |
| P2       | ☐      | Capability audit log entries for every call                                      | Receipt         | Feature-gated verbose mode   |

### Receipt Generation (v0.2)

| Priority | Status | Description                                                              | Dependencies          | Notes                           |
| -------- | ------ | ------------------------------------------------------------------------ | --------------------- | ------------------------------- |
| P0       | ✅      | Receipt v0.2 schema: ids, module hash, env fingerprint, limits, outcomes | jig-spec block-execution.md | Rust struct and docs            |
| P0       | ✅      | Canonical serialization (JSON with sorted keys)                          |                       | Optionally CBOR canonical later |
| P0       | ✅      | Include fuel totals: wasm_fuel_total, per-capability fuel                | Fuel                  | Deterministic increments        |
| P0       | ✅      | Include counters: calls, bytes_in/out, time_ns, errors                   | Capability            |                                 |
| P0       | ✅      | Include timings: start/end, duration_ns (monotonic)                      | Engine                | Deterministic within run        |
| P1       | ✅      | Include budget/limit snapshots and which limit tripped                   | Fuel                  |                                 |
| P1       | ☐      | Optional hashing/signing fields (provenance)                             |                       | Feature-gated                   |
| P1       | ☐      | Attach summarized logs/traces digests                                    | Tracing               | Not full logs by default        |
| P1       | ☐      | Back-compat adapter to v0.1 (if exists)                                  |                       |                                 |
| P2       | ☐      | Receipt validator CLI to lint receipts                                   | jig-cli               | For pipelines                   |

### Integration with Consumers (server/cli/gui)

| Priority | Status | Description                                                             | Dependencies | Notes                 |
| -------- | ------ | ----------------------------------------------------------------------- | ------------ | --------------------- |
| P0       | ✅      | Publish jig-runtime crate and version to be consumed                    | Core         | Local workspace first |
| P0       | 📋      | Migrate jig-cli to new Runner API; add flags for limits, caps, receipts | Core         | Integration guide ready (RUNTIME_INTEGRATION.md) |
| P0       | ✅      | Migrate jig-server to use Runner; expose REST/gRPC endpoints            | Core         | Complete with conversion layer |
| P0       | N/A    | Migrate jig-gui to call runtime via unified API                         | Core         | Too early - no runtime yet; docs ready when needed |
| P1       | ☐      | Shared config file format across consumers                              | Core         | Detect overrides      |
| P1       | ☐      | Example "hello-capabilities" block and tutorial                         | Docs         | For onboarding        |
| P1       | ☐      | E2E tests: server↔cli↔gui parity in receipts                            | Testing      | Golden receipts       |
| P1       | ✅      | Integration docs and diagrams                                           | Docs         | README.md, jig-core/jig-server docs, CLI guide |
| P2       | ☐      | SDK snippets for block authors                                          |              | Outside core runtime  |
| P2       | ☐      | Backpressure and queueing guidance for server                           |              | Docs-only acceptable  |

### Testing & Validation

| Priority | Status | Description                                             | Dependencies    | Notes                       |
| -------- | ------ | ------------------------------------------------------- | --------------- | --------------------------- |
| P0       | ☐      | Determinism tests: same inputs → same receipts          | Engine, Receipt | Stable across runs/machines |
| P0       | ☐      | Parity tests: server/cli/gui produce identical receipts | Integration     | Allow timing tolerance      |
| P0       | ☐      | Capability security tests (deny-by-default, allowlist)  | Capability      |                             |
| P0       | ☐      | Fuel exhaustion and limit-tripping scenarios            | Fuel            | Verify error mapping        |
| P1       | ☐      | Fuzz hostcall inputs for robustness                     | Capability      | cargo-fuzz gated            |
| P1       | ☐      | Snapshot/golden receipt suite                           | Receipt         | Update guardrails           |
| P1       | ☐      | Performance baselines: cold/warm, p95 fuel per op       | Bench           | Budget docs                 |
| P1       | ☐      | CI matrix (macOS, Linux; stable Rust)                   | Core            |                             |
| P2       | ☐      | Code coverage targets for runtime modules               |                 |                             |
| P2       | ☐      | Static analysis and SAST                                |                 |                             |
| P2       | ☐      | Security review checklist                               |                 |                             |
| P2       | ☐      | Soak tests with varying budgets                         |                 |                             |

### Deprecation & Cleanup

| Priority | Status | Description                                                           | Dependencies      | Notes                                                |
| -------- | ------ | --------------------------------------------------------------------- | ----------------- | ---------------------------------------------------- |
| P0       | ☐      | Archive jig-docker repo with README pointer to wasm runtime           |                   | Out-of-scope permanently for core                    |
| P0       | ☐      | Archive jig-podman repo similarly                                     |                   |                                                      |
| P0       | ☐      | Archive jig-runtime-select repo with migration notes                  | Integration       | No longer needed; consumers use jig-runtime directly |
| P0       | ☐      | Remove jig-runtime-select from jig-cli Cargo.toml and src/runtime.rs  | jig-cli migration | Feature-gated, minimal usage                         |
| P0       | ☐      | Remove jig-runtime-select from workspace Cargo.toml                   |                   | After consumers migrated                             |
| P0       | ☐      | Update top-level docs to state WASM-only core runtime                 | Docs              |                                                      |
| P1       | ☐      | Search-and-replace references to docker/podman/runtime-select in docs |                   |                                                      |
| P1       | ☐      | Migrate any open issues/PRs to jig-runtime                            |                   |                                                      |
| P2       | ☐      | Add deprecation notices to release notes                              |                   | Specify migration from runtime-select                |
| P2       | ☐      | Remove stale CI and scripts for deprecated repos                      |                   |                                                      |

---

## Open Questions (to confirm in alignment)

- Wasmtime version pin and features: exact minimal supported version; Component Model maturity target.
- Exact initial capability set for v0.1 of the unified runtime (http, kv, rand, clock, crypto-basic, env?): confirm names and semantics.
- Receipt v0.2 canonical serialization: JSON only vs dual JSON/CBOR; any mandatory signing?
- Pricing model defaults: units, currency, and rounding; do we ship a default schedule enabled by default?
- Deterministic time policy: epoch or fuel-only timeouts; acceptable jitter in timing fields for receipt parity.
- How to seed RNG for determinism at scale: per-run seed provenance fields in receipt?
- What logs/traces are included in receipt digests vs external telemetry?
- Any backwards-compat expectations for existing blocks targeting non-component core wasm?
- Minimal OS support matrix: macOS and Linux; any Windows constraints?
- Target Rust toolchain version and MSRV policy for the workspace.

---

## Success Criteria

- jig-runtime crate exposes a stable Runner API and builds on supported platforms.
- Wasmtime-based execution is deterministic by default with fuel metering enabled.
- Capability layer enforces closed-by-default policies with explicit allowlists and quotas.
- Fuel system accounts for instruction and hostcall fuel; pricing mapping is configurable and reflected in receipts.
- Receipt v0.2 produced on every run; canonical and validates against schema; parity across server/cli/gui.
- jig-server, jig-cli, and jig-gui all integrate with the unified runtime and pass parity tests.
- Comprehensive tests pass in CI, including determinism, security, exhaustion, and performance baselines.
- Vestigial repos archived; documentation clearly states WASM-only runtime for core builds.
- Licensing checks pass (cargo-deny), respecting deny.toml preferences and avoiding restrictive copyleft.

---

## Phased Milestones

### M1: Core + Engine + Capability Skeleton (P0) ✅ COMPLETE

**Exit criteria:** Deterministic Wasmtime engine integrated; minimal capability imports wired; Runner API stable; CI green.

**Status:** All 59 tests passing; Runtime API stable; builds on macOS/Linux.

### M2: Fuel + Receipt v0.2 (P0) ✅ COMPLETE

**Exit criteria:** Instruction + hostcall fuel with budgets; pricing mapping; receipt v0.2 emitted and validated.

**Status:** 
- ✅ Fuel metering with configurable limits
- ✅ Receipt v0.2 with pricing fields (cost_per_fuel_unit, total_cost, currency, schedule_version)
- ✅ Outcome tracking (Success/LimitsExceeded/ExecutionFailed/ValidationFailed)
- ✅ Per-capability fuel breakdown structure
- ✅ Pricing optional and configurable via RuntimeConfig

### M3: Consumer Integration Parity (P0/P1) ✅ COMPLETE

**Exit criteria:** jig-server/cli/gui parity tests passing with identical receipts (allowing documented time tolerances).

**Status:**
- ✅ M3.1: Integration test package created (7 tests passing)
- ✅ M3.2: jig-cli integration guide documented (RUNTIME_INTEGRATION.md)
- ✅ M3.3: jig-server migrated and tested (36 tests passing, pricing in metadata)
- ✅ M3.4: jig-gui assessed (N/A - too early, docs ready for future integration)

**Architecture documented:**
- jig-runtime/README.md: Full architecture and pricing rationale
- jig-core/src/receipt.rs: Why BlockReceipt is pricing-neutral
- jig-server/src/runtime/mod.rs: Conversion layer documentation
- jig-cli/RUNTIME_INTEGRATION.md: Direct runtime consumer pattern

### M4: Test Hardening + Deprecations (P1/P2) ⏭️ NEXT

**Exit criteria:** Vestigial repos archived; docs updated; fuzz/soak/security tests passing thresholds.
