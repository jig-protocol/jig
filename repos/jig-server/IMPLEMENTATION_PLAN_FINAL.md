# jig-server Runtime Spine Implementation Plan — FINAL

**Status**: ✅ **APPROVED — CLEAR TO EXECUTE**  
**Date**: 2025-11-02  
**Updated**: 2025-11-09  
**Phase 0.0**: ✅ Complete (Feature flags + licensing)  
**Phase 0.1**: ✅ Complete (jig-core receipt v0.2 live)  
**Phase 1.0**: ✅ Complete (Outcome model)  
**Phase 1.1**: ✅ Complete (Capability enforcement)  
**Phase 1.2**: ✅ Complete (Fuel tracker foundation)  
**Phase 1.3**: ✅ Complete (consume jig-runtime Receipt.block; pricing/timings/renders_match mapping)  
**Next**: Finalize E2E receipt path checks (Phase 2 readiness). Phase 3.3 (Analytics Dispatcher) is COMPLETE and wired with config knobs; continue Phase 3.2 (ClickHouse) hardening. Proceed to Phase 4.0 (Profile-Driven Config). Transport trait remains deferred.

---

## Executive Summary

Integrates original gap analysis + 20251102_REVIEW.md to deliver:

1. Capability enforcement with fuel-by-capability pricing
2. Receipt v0.2 with outcome-based metering
3. Transport upgrades with deterministic receipts
4. **Profile-driven analytics**: SQLite (potato) → DuckDB (standard) → ClickHouse (hyperscale)

### Analytics DB Architecture (CLARIFIED)

| Profile        | Truth Store | Analytics Sink       | Notes                                                                  |
| -------------- | ----------- | -------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------- |
| **potato**     | SQLite      | **SQLite** (same DB) | Zero extra services                                                    |
| **standard**   | SQLite      | **DuckDB/Parquet**   | Separate analytics DB                                                  | _Could use Postgres at this tier, but not a priority_ |
| **hyperscale** | SQLite\*    | **ClickHouse**       | Federated analytics; _can upgrade to Postgres/Cockroach/Scylla/S2/etc_ |

**Key**: potato = SQLite for everything; DuckDB only at standard+; ClickHouse only at hyperscale.
**Note**: three standard profiles in jig-config, customization available via flag, "potato" is default, mix-and-match should be viable (e.g. SQLite + Scylla + Parquet for some reason? Sure? composable to the greatest extent possible).

---

## Phase 0.1 Status: ✅ COMPLETE

**jig-core receipt v0.2 types are LIVE** in `repos/jig-core/src/receipt.rs`

Available for jig-server:

- `BlockReceipt` with optional v0.2 fields (backwards compatible)
- `Outcome { status: OutcomeStatus, affordances: Vec<String>, reason: Option<String> }`
- `OutcomeStatus` enum: `Ok | SoftFail | HardFail`
- `Counters { fuel_total, fuel_by_capability, bytes_tx, bytes_rx, syscalls }`
- `Timings { queue_wait, init, exec, total }` (u32 milliseconds)
- `Limits { fuel_max, memory_max_mb, execution_timeout_ms }`

**Server is unblocked** — can import and use immediately. No feature flag needed (v0.2 fields are optional).

---

## Implementation Phases

### Phase 0: Preflight (1 day)

**Feature flags + deny.toml**

```toml
# jig-server/Cargo.toml
[features]
default = ["sqlite"]
sqlite = []
telemetry_v0_2 = []
analytics_duckdb = ["dep:duckdb"]  # standard tier
analytics_clickhouse = ["dep:clickhouse"]  # hyperscale only
transports_irc = []
transports_ssh = []
transports_ws = []

[dependencies]
duckdb = { version = "0.10", optional = true }
clickhouse = { version = "0.11", optional = true }
hdrhistogram = "7.5"
hmac = "0.12"
sha2 = "0.10"
```

```toml
# deny.toml (workspace root)
[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"]
deny = ["AGPL-3.0", "GPL-2.0", "GPL-3.0"]

[licenses.private]
ignore = true
registries = ["gigue-internal"]
```

**Validation**: `cargo check --all-features && cargo deny check`

---

### Phase 1: Capability Enforcement & Fuel Tracking (4-5 days)

**1.0: Outcome Model** ✅ COMPLETE (~145 LOC)

- Files: `src/runtime/outcome.rs`, `tests/outcome_tests.rs`
- Content: `OutcomeStatus` enum, `Outcome` struct with affordances
- Maps to `jig_core::Outcome` for receipt emission
- Status: All tests passing, integrated with runtime module

**1.1: Capability Enforcement** ✅ COMPLETE (~195 LOC)

- Files: `src/capability/token.rs`, `src/capability/registry.rs`, `src/capability/mod.rs`, `tests/capability_enforcement.rs`
- Content: CapabilityToken with HMAC signatures, CapabilityRegistry with deny-by-default enforcement
- Features: Expiry validation, scope matching, usage counters for telemetry
- Status: 12 tests passing, clean clippy

**1.2: Fuel-by-Capability Tracker** ✅ COMPLETE (~125 LOC foundation)

- Files: `src/capability/fuel_tracker.rs`, `tests/fuel_tracker_tests.rs`
- Content: `FuelTracker` with per-capability accumulation, `FuelSnapshot` for immutable views
- API: `consume_direct()` for manual attribution, `begin()` guard for future Wasmtime integration
- Status: 8 tests passing, clean clippy
- **NOTE**: FuelGuard drop logic remains stubbed; plan is to replace it with `jig_runtime` telemetry instead of expanding the legacy shim
- **Follow-up**: Remove or re-home this module once runtime exposes per-capability counters to the server crate

**1.3: Runtime Wiring** 🚧 PARTIAL (~300 LOC across crates)

- Files: `src/runtime/mod.rs`, `src/lib.rs`, new `jig-runtime` crate integration
- Content: `BlockRuntime` now delegates to `jig_runtime::Runtime` for Wasmtime execution, resource limits, and pricing hooks
- Status: Integration present but still uses legacy `Receipt` field access in places; refactor needed to the new `jig_runtime::Receipt { block: BlockReceipt, pricing, duration_ns, ... }` API
- ✅ Replace server-side reconstruction with augmentation of `jig_runtime::Receipt.block`:
  - set `timings_ms` (exec/total) from `duration_ns`
  - set `renders_match` by comparing `module_hash.value` with `manifest.render.expected_hash`
  - copy `pricing.*` into `BlockReceipt.metadata`
  - rely on runtime-provided `counters`/`limits` already in `block`
- Tests: update runtime tests to construct via `Receipt::builder()` or by executing `Runtime`; remove usages of `JigReceipt::new` and legacy fields
- **TODO**: Surface capability allowlists, wire runtime-provided per-capability telemetry, and retire the legacy `FuelTracker` shim once upstream APIs land
- **Spec sync**: Coordinate with `jig-core`/`jig-runtime` on canonical receipt bytes, reason-code taxonomy, deterministic host policies, and signed field lists so server-side changes stay aligned with repo-wide contracts

**Validation each step**: `cargo nextest -p jig-server && cargo clippy -p jig-server -D warnings`

---

### Phase 2: Receipt Path Finalization (4-5 days)

**2.0: E2E Receipt Path** (~150–200 LOC)

- Files: `src/runtime/mod.rs` (refactor), `tests/receipt_e2e.rs`, `src/storage.rs` (no schema change)
- Content: Persist `jig_runtime::Receipt.block` (with server augmentations above) to SQLite; remove legacy conversion path; assert v0.2 fields present; verify pricing metadata persisted; validate against manifest

**2.1: Transports (deferred)**

- Reuse existing `irc/` and `websocket/` modules; no new `Transport` trait now
- Keep feature flags (`transports_irc`, `transports_ssh`, `transports_ws`) for later adapters as needed

**2.2: Server-side receipt augmentation** (~100 LOC)

- No separate emitter module; augmentation happens in runtime wiring
- Tests ensure `timings_ms`, `renders_match`, `pricing.*` are set correctly

**2.3: SQLite Migration**

- Not required for v0.2: existing `receipts (receipt TEXT)` stores `BlockReceipt` JSON with optional v0.2 fields
- Revisit schema for analytics-only projections in Phase 3

---

### Phase 3: Analytics & Observability (5-6 days)

**3.0: Timings & Histograms** (~200 LOC) — ✅ COMPLETE

- Files: `src/telemetry/timings.rs` (feature = `telemetry_v0_2`), `tests/timings_histograms.rs`
- Content: `TimingsRecorder` with phase markers, HDR histograms for p50/p95/p99
- Status: Implemented and wired from `BlockRuntime`; unit tests pass; clippy clean under feature

**3.1: SQLite Analytics (potato) + DuckDB (standard)** (~250 LOC) — ✅ COMPLETE (potato + standard)

- Files: `src/analytics/mod.rs` (potato), `src/analytics/duckdb.rs` (feature = `analytics_duckdb`), `tests/analytics_sqlite.rs`, `tests/analytics_duckdb.rs`
- **Potato**: Reuse existing SQLite DB for v0.2 receipts table; added HTTP endpoint `GET /analytics/receipt-stats` with unit tests
- **Standard**: Separate DuckDB file with receipts/counters/blocks tables
- Parquet exporter CLI shipped (feature = `analytics_parquet`), documented in README and covered by tests
- Notes: feature-gated backends verify clean builds; dependency versions pinned (DuckDB 1.2.x, chrono 0.4.39); no conflicts observed under feature gates

**3.2: ClickHouse Sink (hyperscale only)** (~250 LOC) — 🚧 PARTIAL

- Files: `src/analytics/clickhouse.rs` (feature = `analytics_clickhouse`), `tests/analytics_clickhouse.rs`
- DDL: receipts (MergeTree, partition by date), receipt_capability_counters, blocks mirror
- Batched inserts with backpressure

**3.3: Analytics Dispatcher** (~200 LOC) — ✅ COMPLETE

- Files: `src/analytics/mod.rs`, `src/analytics/dispatcher.rs`, unit test in module
- Trait `AnalyticsSink` implemented by ClickHouse (feature); future: SQLite/DuckDB if needed
- Fan-out from ingest path to configured analytics sink (optional)
- Bounded queue with drop policy, batch-size flush, and interval-based flush
- Config knobs exposed under `[analytics.dispatcher]` (capacity, batch_size, flush_interval_ms)

**3.4: Metrics HTTP Endpoint** (~200 LOC)

- Files: `src/http/metrics.rs`, `tests/metrics_endpoint.rs`
- Expose: p50/p95/p99 for queue_wait/init/exec/total; recent fuel/bytes/syscalls totals
- JSON format (optional Prometheus later)
 - Status: timings endpoint implemented under feature `telemetry_v0_2`; fuel/bytes/syscalls totals pending

---

### Phase 4: Integration & Rollout (3-4 days)

**4.0: Profile-Driven Config** (~200 LOC)

- Files: `src/config/profile.rs`, update `src/main.rs`, `tests/profile_selection.rs`
- Profile selection from `jig-config.toml`:
  - `potato` → SQLite truth + SQLite analytics
  - `standard` → Postgres truth + DuckDB analytics
  - `hyperscale` → CockroachDB truth + ScyllaDB hot + ClickHouse analytics
- Runtime validation; feature-disabled fallback warnings
- Only `potato` comes by default; others require feature flags / config / addl download (curl-to-hello-world is only tested against potato build with just SQLite as sole DB)

**4.1: E2E Receipt Emission** (~150 LOC touch)

- Files: Update `src/runtime.rs`, `tests/e2e_receipt_v02.rs`
- Flow: Collect timings/counters/limits/outcome → build receipt → persist SQLite → dispatch analytics

**4.2: Determinism Validation** (~150 LOC)

- Files: `src/runtime/render_hash.rs`, `tests/renders_match.rs`
- Content: `compute_render_hash(output)` → blake3, compare with manifest.render.expected_hash

**4.3: Documentation**

- Files: `docs/jig-server/{receipts_v02,telemetry_and_pricing,profiles}.md`
- Content: Receipt v0.2 schema, fuel-based pricing, profile selection, analytics backends

**4.4: Rollout Plan**

- Staging: Enable `--features "telemetry_v0_2 analytics_duckdb"` (standard profile)
- Hyperscale: Enable `--features "analytics_clickhouse"`
- SLO checks: p95 exec < 200ms, receipt error rate < 0.1%
- Backout: Disable features to revert

---

## Timeline (Updated)

| Phase                   | Duration   | Dependencies    |
| ----------------------- | ---------- | --------------- |
| ~~Phase 0.1: jig-core~~ | ~~2 days~~ | ✅ **COMPLETE** |
| Phase 0: Preflight      | 1 day      | None            |
| Phase 1: Capabilities   | 4-5 days   | Phase 0         |
| Phase 2: Transports     | 4-5 days   | Phase 1         |
| Phase 3: Analytics      | 5-6 days   | Phase 2         |
| Phase 4: Integration    | 3-4 days   | Phase 3         |

**Total**: 17-21 days (single developer) — Phase 0.1 already complete  
**Critical path**: Phase 0 → Phase 1 → Phase 2 → Phase 4

---

## File Size Budget

| Component             | Files        | Total LOC      |
| --------------------- | ------------ | -------------- |
| Phase 1: Capabilities | 4            | 850            |
| Phase 2: Transports   | 7            | 1,350          |
| Phase 3: Analytics    | 6            | 1,300          |
| Phase 4: Integration  | 3            | 500            |
| **Total**             | **20 files** | **~4,000 LOC** |

All files under 250 LOC per ROE.

---

## Dependencies & Licensing

| Crate        | Version | License        | Profile    |
| ------------ | ------- | -------------- | ---------- |
| hmac         | 0.12    | MIT/Apache-2   | All        |
| sha2         | 0.10    | MIT/Apache-2   | All        |
| hdrhistogram | 7.5     | BSD-2/Apache-2 | All        |
| duckdb       | 0.10    | MIT            | standard+  |
| clickhouse   | 0.11    | MIT/Apache-2   | hyperscale |

**Validation**: `cargo deny check` enforces no AGPL/GPL; internal gigue crates allowed.

---

## Success Criteria

### Phase 0.1 ✅ COMPLETE

- [x] Receipt v0.2 types live in jig-core
- [x] jig-server can import immediately

### Phase 1 (Partial)

- [x] **Phase 1.0**: Outcome model with OutcomeStatus enum
- [x] **Phase 1.1**: Capability enforcement with CapabilityToken + CapabilityRegistry
- [x] **Phase 1.2**: FuelTracker foundation (API ready, Wasmtime integration stubbed)
- [x] **Phase 1.3**: Refactor to consume `jig_runtime::Receipt.block`; set `timings_ms`/`renders_match`; copy pricing metadata; update tests

### Phase 2-4

- [ ] Capability enforcement with fuel-by-capability tracking (guard integration pending)
- [ ] Receipt v0.2 emitted with all fields
- [x] SQLite analytics (potato)
- [x] DuckDB analytics (standard)
- [ ] ClickHouse analytics (hyperscale)
- [ ] p95/p99 latency < SLO targets
- [ ] Profile-driven config without recompilation
- [x] Timings endpoint exposed under `telemetry_v0_2`

---

## Next Steps

1. ✅ **Phase 0.0 complete** — Feature flags + deny.toml configured
2. ✅ **Phase 0.1 complete** — jig-core receipt v0.2 types live
3. ✅ **Phase 1.0 complete** — Outcome model implemented
4. ✅ **Phase 1.1 complete** — Capability enforcement implemented
5. ✅ **Phase 1.2 complete** — FuelTracker foundation ready

---

## References

- **Gap Analysis**: Original issue
- **Review**: `executable-internet-master-plan/20251102_REVIEW.md`
- **Architecture**: `executable-internet-master-plan/architecture/EXECUTION_ENVIRONMENT.md`
- **ROE**: `.claude/CLAUDE.md`
- **Guidelines**: `repos/jig-server/AGENTS.md`

---

**Owner**: Runtime team  
**Clear to execute**: ✅ YES
