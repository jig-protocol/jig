# jig-config Implementation Plan

## Bringing Configuration to Executable Internet Spec

**Purpose**
Transform `jig-config` into the cross-binary contract for deployment profiles, execution guardrails, and outcome-based pricing that supports jig-core, jig-server, jig-cli, jig-nameserver, jig-bridge-email, and jig-gui.

**Status**
✅ **READY TO PROCEED** - All upstream blockers resolved (2025-11-04)
Owner: config + runtime teams

**References**

- `executable-internet-master-plan/20251102_REVIEW.md` - Receipt v0.2 and pricing requirements
- `executable-internet-master-plan/architecture/CONFIGURATION.md` - Canonical config spec
- `executable-internet-master-plan/architecture/EXECUTION_ENVIRONMENT.md` - Runtime constraints
- `executable-internet-master-plan/architecture/DATA_FLOW_AND_STORAGE.md` - Storage tier architecture
- `executable-internet-master-plan/architecture/IDENTITY_AND_REPUTATION.md` - Reputation tiers and governance
- `repos/jig-core/IMPLEMENTATION_PLAN.md` - Core types status (Receipt v0.2, Capability DSL complete)

---

## Executive Summary

### 🎯 Mission
Build the configuration foundation that enables:
1. **Symmetric execution** across server/CLI/GUI (same limits, same behavior)
2. **Outcome-based pricing** with per-capability fuel metering
3. **Profile-driven deployment** from potato (SQLite, 60s setup) to hyperscale (multi-tier storage)
4. **Deterministic validation** enforcing Wasm constraints from config

### 🚦 Current State: UNBLOCKED
- ✅ `jig-core` Receipt v0.2 types **complete** (verified 2025-11-03)
- ✅ `jig-core` Capability DSL **complete** (verified 2025-11-03)
- ✅ `jig-core` Determinism validation **complete** (verified 2025-11-03)
- ✅ Canonical JSON (JCS) serialization **complete** (verified 2025-11-03)
- ✅ All design decisions **resolved** (see Resolved Design Decisions section)

### 📋 What We're Building
10-week phased implementation adding:
- Profile system (potato/standard/hyperscale) with override mechanism
- Execution constraints (fuel/memory/timeout) per profile
- Storage tier separation (truth/speed/intelligence/archive)
- Receipt v0.2 configuration (schema version, canonicalization rules)
- Pricing configuration (fuel bands per capability type)
- Governance integration (nameserver, tribunals, reputation tiers)
- Analytics backend selection (DuckDB → ClickHouse per profile)
- Bridge-specific settings (email relay quotas, DNS discovery)
- Template generation & validation tooling

### 🎯 Success Metrics
- Config parsing < 10ms, validation < 5ms
- 100% test coverage on config parsing & profile merging
- Zero breaking changes to existing `jig-config` API
- Server/CLI/Runtime all consume config successfully
- Potato profile remains one-line deployable

### 📅 Timeline
- **Week 1**: Foundation & profiles (Phase 0)
- **Weeks 2-3**: Execution & storage (Phases 1-2)
- **Weeks 4-5**: Receipts & pricing (Phases 3-4)
- **Weeks 6-7**: Governance & analytics (Phases 5-6)
- **Weeks 8-9**: Bridges, overrides, validation (Phases 7-9)
- **Week 10**: Documentation & integration (Phase 10)
- **Target Release**: v0.2.0 by end of Week 10

---

## Current State Assessment

### ✅ What We Have

| Component               | Status         | Notes                                           |
| ----------------------- | -------------- | ----------------------------------------------- |
| Basic runtime config    | ✅ Implemented | Engine selection (Wasmtime/Podman/Docker/Local) |
| Engine-specific options | ✅ Implemented | Wasmtime fuel, preopens; Podman/Docker mounts   |
| Deployment modes        | ✅ Implemented | QuickStart/Development/Production/Custom        |
| Storage backend enum    | ✅ Implemented | SQLite/Postgres/Memory                          |
| Feature flags           | ✅ Implemented | IRC, SSH, WebSocket, email, federation, etc.    |
| Network configuration   | ✅ Implemented | Bind addresses, ports, TLS config               |

### ❌ What's Missing for Executable Internet

| Gap                                                 | Priority | Blocks                    |
| --------------------------------------------------- | -------- | ------------------------- |
| Profile-based configuration system                  | **P0**   | Server, CLI, all repos    |
| Execution constraints (fuel/memory/timeout)         | **P0**   | Runtime, server, CLI      |
| Receipt v0.2 schema configuration                   | **P0**   | Core, server, CLI         |
| Analytics backend per profile                       | **P0**   | Server analytics, pricing |
| Storage tier separation (truth/speed/intel/archive) | **P0**   | Server storage at scale   |
| Capability DSL configuration                        | **P0**   | Runtime enforcement       |
| Determinism enforcement settings                    | **P0**   | Runtime validation        |
| Per-capability fuel bands                           | **P1**   | Outcome-based pricing     |
| Governance/tribunal configuration                   | **P1**   | Nameserver integration    |
| Bridge-specific settings                            | **P1**   | Email bridge, IRC bridge  |
| Telemetry and observability                         | **P1**   | Metrics, logging, tracing |
| Profile override mechanism                          | **P0**   | All deployments           |

---

## Gap Analysis: Receipt v0.2 & Outcome-Based Pricing

### What Receipt v0.2 Requires from Config

| Receipt Field                                           | Config Support Needed                        | Current State |
| ------------------------------------------------------- | -------------------------------------------- | ------------- |
| `receipt_schema_version`                                | Config specifies version for compatibility   | ❌ Missing    |
| `limits{fuel_max, memory_max_mb, execution_timeout_ms}` | Runtime constraint configuration per profile | ❌ Missing    |
| `counters.fuel_by_capability{}`                         | Per-capability fuel metering config          | ❌ Missing    |
| `outcome{status, affordances, reason}`                  | Outcome taxonomy and reason codes            | ❌ Missing    |
| `timings_ms{}`                                          | Monotonic timing configuration               | ❌ Missing    |
| `renders_match`                                         | Determinism validation settings              | ❌ Missing    |
| Canonical JSON serialization                            | Canonicalization rules config                | ❌ Missing    |

### What Pricing Requires from Config

| Pricing Primitive              | Config Support Needed                               | Current State |
| ------------------------------ | --------------------------------------------------- | ------------- |
| Fuel bands per capability type | `[pricing.fuel_bands]` for CPU/bandwidth/crypto     | ❌ Missing    |
| Profile-based limits           | Different `fuel_max` for potato/standard/hyperscale | ❌ Missing    |
| Useful work credit discounts   | Integration with nameserver reputation tiers        | ❌ Missing    |
| Analytics sink configuration   | DuckDB (potato) vs ClickHouse (hyperscale)          | ❌ Missing    |
| Replay proof settings          | Deterministic render validation config              | ❌ Missing    |

---

## Implementation Plan: Detailed Task Breakdown

### Phase 0: Foundation & Types (Week 1)

**Goal:** Establish profile system and core runtime constraint types without breaking existing code.

| Task | File(s)             | Description                                       | Acceptance Criteria                                                                              |
| ---- | ------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| 0.1  | `src/profiles.rs`   | Create profile enum and override mechanism        | Enum with Potato/Standard/Hyperscale/Custom variants                                             |
| 0.2  | `src/profiles.rs`   | Implement profile merge logic for overrides       | `Profile::merge(&self, overrides: &ProfileOverride)` returns merged config                       |
| 0.3  | `src/execution.rs`  | Define `ExecutionConstraints` struct              | Fields: `fuel_max`, `memory_max_mb`, `execution_timeout_ms`, `deterministic`, `import_allowlist` |
| 0.4  | `src/execution.rs`  | Add `ExecutionConstraints::default_for_profile()` | Returns appropriate limits for each profile tier                                                 |
| 0.5  | `src/lib.rs`        | Wire `profiles` and `execution` modules           | Add to public API with docs                                                                      |
| 0.6  | `tests/profiles.rs` | Profile merge unit tests                          | Test override precedence and validation                                                          |
| 0.7  | `README.md`         | Update with profile examples                      | Show potato/standard/hyperscale TOML snippets                                                    |

**Exit Criteria:** Profile system compiles, tests pass, no breaking changes to existing API.

---

### Phase 1: Execution & Runtime Configuration (Week 1-2)

**Goal:** Support symmetric execution constraints across server/CLI/GUI per the EXECUTION_ENVIRONMENT spec.

| Task | File(s)                   | Description                             | Acceptance Criteria                                                     |
| ---- | ------------------------- | --------------------------------------- | ----------------------------------------------------------------------- |
| 1.1  | `src/execution.rs`        | Add `DeterminismConfig` struct          | Fields: `float_policy`, `prng_seed_source`, `forbidden_imports`         |
| 1.2  | `src/execution.rs`        | Add `CapabilityConfig` struct           | Fields: `default_grants`, `scope_patterns`, `rate_limits`               |
| 1.3  | `src/execution.rs`        | Implement `RuntimeConfig` aggregator    | Bundles `ExecutionConstraints`, `DeterminismConfig`, `CapabilityConfig` |
| 1.4  | `src/lib.rs`              | Add `[runtime]` TOML section parser     | Parse `fuel_max`, `memory_max_mb`, `timeout_ms`, `deterministic`        |
| 1.5  | `src/lib.rs`              | Add `[runtime.determinism]` subsection  | Parse float policy, import allowlist                                    |
| 1.6  | `src/lib.rs`              | Add `[runtime.capabilities]` subsection | Parse capability grants and scopes                                      |
| 1.7  | `tests/runtime_config.rs` | Test runtime constraint parsing         | Load sample TOML, assert values                                         |
| 1.8  | `tests/runtime_config.rs` | Test per-profile constraint overrides   | Potato has lower limits than hyperscale                                 |
| 1.9  | Example TOML              | Add `examples/potato.toml`              | Full potato profile with runtime settings                               |
| 1.10 | Example TOML              | Add `examples/hyperscale.toml`          | Full hyperscale profile with all tiers                                  |

**Exit Criteria:** Runtime constraints configurable per profile; TOML examples validate; tests pass.

---

### Phase 2: Storage Tier Separation (Week 2-3)

**Goal:** Support layered storage architecture (truth/speed/intelligence/archive) per DATA_FLOW_AND_STORAGE spec.

| Task | File(s)                   | Description                                                  | Acceptance Criteria                                                                       |
| ---- | ------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| 2.1  | `src/storage.rs`          | Refactor `StorageConfig` to `StorageTier` struct             | Fields: `backend`, `connection_string`, `options`                                         |
| 2.2  | `src/storage.rs`          | Create `StorageLayerConfig` struct                           | Fields: `truth`, `speed`, `intelligence`, `archive` (all `Option<StorageTier>`)           |
| 2.3  | `src/storage.rs`          | Expand `Backend` enum                                        | Add variants: `CockroachDB`, `ScyllaDB`, `ClickHouse`, `DuckDB`, `Parquet`, `S3`, `Redis` |
| 2.4  | `src/storage.rs`          | Implement profile-specific storage defaults                  | Potato: SQLite only; Standard: Postgres + Redis; Hyperscale: all four layers              |
| 2.5  | `src/lib.rs`              | Add `[storage.truth]`, `[storage.speed]`, etc. TOML sections | Parse layered config with fallbacks                                                       |
| 2.6  | `src/lib.rs`              | Add `[analytics]` section                                    | Configure intelligence backend (duckdb vs clickhouse)                                     |
| 2.7  | `tests/storage_layers.rs` | Test single-tier potato config                               | Only truth layer defined                                                                  |
| 2.8  | `tests/storage_layers.rs` | Test full hyperscale config                                  | All four layers defined                                                                   |
| 2.9  | Example TOML              | Update `examples/hyperscale.toml`                            | Show CockroachDB + ScyllaDB + ClickHouse + S3                                             |
| 2.10 | Docs                      | Update README storage section                                | Explain tier separation and profile mapping                                               |

**Exit Criteria:** Storage layers configurable per profile; single and multi-tier configs validate.

---

### Phase 3: Receipt & Canonicalization Configuration (Week 3-4)

**Goal:** Support receipt v0.2 schema and deterministic serialization settings.

| Task | File(s)                   | Description                                       | Acceptance Criteria                                              |
| ---- | ------------------------- | ------------------------------------------------- | ---------------------------------------------------------------- |
| 3.1  | `src/receipts.rs`         | Create `ReceiptConfig` struct                     | Fields: `schema_version`, `signed_fields`, `canonical_format`    |
| 3.2  | `src/receipts.rs`         | Add `CanonicalizationRules` struct                | Fields: `algorithm` (JCS/CBOR), `field_order`, `float_precision` |
| 3.3  | `src/receipts.rs`         | Define `OutcomeTaxonomy` enum                     | Variants: `Ok`, `SoftFail`, `HardFail` with reason codes         |
| 3.4  | `src/receipts.rs`         | Create `ReasonCode` enum                          | Standard codes: `NET_TIMEOUT`, `CAPABILITY_DENIED`, etc.         |
| 3.5  | `src/lib.rs`              | Add `[receipts]` TOML section                     | Parse schema version and canonicalization settings               |
| 3.6  | `src/lib.rs`              | Add `[receipts.outcome_taxonomy]` subsection      | Configure reason codes and affordances catalog                   |
| 3.7  | `tests/receipt_config.rs` | Test receipt schema version parsing               | Default to v0.2                                                  |
| 3.8  | `tests/receipt_config.rs` | Test canonicalization rules                       | JCS with stable field order                                      |
| 3.9  | Example TOML              | Add receipt configuration to all profile examples | Show v0.2 settings                                               |
| 3.10 | Docs                      | Document receipt configuration in README          | Link to BLOCK_RUNTIME_SPEC                                       |

**Exit Criteria:** Receipt v0.2 config types defined; canonicalization rules configurable; examples complete.

---

**ReasonCode Alignment (2025-11-03)** – `OutcomeConfig::default` now ships the canonical list shared with `jig-core`:

```
NET_TIMEOUT
UPSTREAM_5XX
CAPABILITY_DENIED
MANIFEST_INVALID
NONDETERMINISM_DETECTED
RENDER_MISMATCH
RUNTIME_TIMEOUT
RUNTIME_TRAP
FUEL_EXHAUSTED
MEMORY_LIMIT_EXCEEDED
TABLE_LIMIT_EXCEEDED
HOST_PANIC
UNKNOWN
```

Runtime/server/CLI teams should map host errors onto these codes until spec docs are updated.

---

### Phase 4: Pricing & Fuel Band Configuration (Week 4-5)

**Goal:** Enable outcome-based pricing with per-capability fuel bands and useful work integration.

| Task | File(s)                   | Description                                 | Acceptance Criteria                                                                |
| ---- | ------------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------- |
| 4.1  | `src/pricing.rs`          | Create `PricingConfig` struct               | Fields: `fuel_bands`, `useful_work_discounts`, `outcome_adjustments`               |
| 4.2  | `src/pricing.rs`          | Define `FuelBand` struct                    | Fields: `capability_type`, `cost_per_unit`, `metering_mode` (CPU/bandwidth/crypto) |
| 4.3  | `src/pricing.rs`          | Add `UsefulWorkDiscount` struct             | Fields: `reputation_tier`, `discount_pct`, `min_streak_days`                       |
| 4.4  | `src/pricing.rs`          | Implement profile-specific pricing defaults | Free tier (potato), dev tier (standard), paid tier (hyperscale)                    |
| 4.5  | `src/lib.rs`              | Add `[pricing]` TOML section                | Parse fuel bands and discount rules                                                |
| 4.6  | `src/lib.rs`              | Add `[pricing.fuel_bands]` subsection       | Per-capability cost configuration                                                  |
| 4.7  | `src/lib.rs`              | Add `[pricing.discounts]` subsection        | Useful work credit configuration                                                   |
| 4.8  | `tests/pricing_config.rs` | Test fuel band parsing                      | CPU vs bandwidth vs crypto bands                                                   |
| 4.9  | `tests/pricing_config.rs` | Test useful work discount application       | High-sec tier gets discount                                                        |
| 4.10 | Example TOML              | Add pricing to hyperscale example           | Show per-capability fuel bands                                                     |
| 4.11 | Docs                      | Document pricing model in README            | Link to outcome-based pricing doc                                                  |

**Exit Criteria:** Pricing configuration types complete; fuel bands configurable; discount rules validated.

---

### Phase 5: Governance & Identity Integration (Week 5-6)

**Goal:** Wire nameserver, tribunal, and reputation tier configuration per IDENTITY_AND_REPUTATION spec.

| Task | File(s)                      | Description                                    | Acceptance Criteria                                                |
| ---- | ---------------------------- | ---------------------------------------------- | ------------------------------------------------------------------ |
| 5.1  | `src/governance.rs`          | Create `GovernanceConfig` struct               | Fields: `nameserver_url`, `tribunal_endpoints`, `transparency_log` |
| 5.2  | `src/governance.rs`          | Define `ReputationTier` enum                   | Variants: `NullSec`, `LowSec`, `HighSec` matching identity spec    |
| 5.3  | `src/governance.rs`          | Add `TribunalConfig` struct                    | Fields: `panel_size`, `quorum_threshold`, `appeal_window_hrs`      |
| 5.4  | `src/governance.rs`          | Create `ProgressiveCostConfig` struct          | PoW difficulty per reputation tier                                 |
| 5.5  | `src/lib.rs`                 | Add `[governance]` TOML section                | Parse nameserver and tribunal settings                             |
| 5.6  | `src/lib.rs`                 | Add `[governance.reputation_tiers]` subsection | Configure tier transition requirements                             |
| 5.7  | `src/lib.rs`                 | Add `[governance.progressive_cost]` subsection | PoW difficulty per tier                                            |
| 5.8  | `tests/governance_config.rs` | Test reputation tier parsing                   | NullSec/LowSec/HighSec configs                                     |
| 5.9  | `tests/governance_config.rs` | Test progressive cost function                 | Higher tier = lower PoW                                            |
| 5.10 | Example TOML                 | Add governance config to all profiles          | Nameserver URLs and tribunal settings                              |
| 5.11 | Docs                         | Document governance integration                | Link to IDENTITY_AND_REPUTATION doc                                |

**Exit Criteria:** Governance config types complete; reputation tiers map to costs; tribunal settings validated.

---

### Phase 6: Analytics & Telemetry Configuration (Week 6-7)

**Goal:** Configure analytics sinks (DuckDB/Parquet vs ClickHouse) and telemetry per profile.

| Task | File(s)                     | Description                                   | Acceptance Criteria                                                |
| ---- | --------------------------- | --------------------------------------------- | ------------------------------------------------------------------ |
| 6.1  | `src/analytics.rs`          | Create `AnalyticsConfig` struct               | Fields: `backend`, `retention_days`, `sample_rate`, `privacy_mode` |
| 6.2  | `src/analytics.rs`          | Define `AnalyticsBackend` enum                | Variants: `DuckDB`, `Parquet`, `ClickHouse`, `Disabled`            |
| 6.3  | `src/analytics.rs`          | Add `TelemetryConfig` struct                  | Fields: `metrics_endpoint`, `trace_sampling`, `log_level`          |
| 6.4  | `src/analytics.rs`          | Implement profile-specific analytics defaults | Potato: DuckDB; Hyperscale: ClickHouse                             |
| 6.5  | `src/lib.rs`                | Add `[analytics]` TOML section                | Parse backend and retention settings                               |
| 6.6  | `src/lib.rs`                | Add `[telemetry]` TOML section                | Parse metrics and tracing configuration                            |
| 6.7  | `tests/analytics_config.rs` | Test analytics backend selection              | Profile determines backend                                         |
| 6.8  | `tests/analytics_config.rs` | Test telemetry sampling rates                 | Different per profile                                              |
| 6.9  | Example TOML                | Add analytics config to all profiles          | DuckDB (potato), ClickHouse (hyperscale)                           |
| 6.10 | Docs                        | Document analytics pipeline in README         | Link to DATA_FLOW_AND_STORAGE doc                                  |

**Exit Criteria:** Analytics backend configurable per profile; telemetry settings validated; examples complete.

---

### Phase 7: Bridge & Transport Configuration (Week 7)

**Goal:** Add bridge-specific configuration (email relay quotas, DNS discovery, IRC settings).

| Task | File(s)                   | Description                                       | Acceptance Criteria                                                        |
| ---- | ------------------------- | ------------------------------------------------- | -------------------------------------------------------------------------- |
| 7.1  | `src/bridges.rs`          | Create `BridgeConfig` struct                      | Fields: `email`, `irc`, `ssh`, `websocket`                                 |
| 7.2  | `src/bridges.rs`          | Add `EmailBridgeConfig` struct                    | Fields: `relay_quota_per_day`, `dns_discovery`, `deliverability_analytics` |
| 7.3  | `src/bridges.rs`          | Add `IrcBridgeConfig` struct                      | Fields: `server`, `channels`, `nick_prefix`, `block_wrapper`               |
| 7.4  | `src/bridges.rs`          | Enhance existing transport settings               | Integrate with features and network config                                 |
| 7.5  | `src/lib.rs`              | Add `[bridges]` TOML section                      | Parse bridge-specific settings                                             |
| 7.6  | `src/lib.rs`              | Add `[bridges.email]` subsection                  | Email relay and DNS discovery config                                       |
| 7.7  | `tests/bridges_config.rs` | Test email bridge settings                        | Relay quotas and DNS discovery                                             |
| 7.8  | `tests/bridges_config.rs` | Test IRC bridge settings                          | Block wrapper configuration                                                |
| 7.9  | Example TOML              | Add bridge config to standard/hyperscale profiles | Email and IRC settings                                                     |
| 7.10 | Docs                      | Document bridge configuration                     | Link to TRANSPORTS_AND_BRIDGES doc                                         |

**Exit Criteria:** Bridge-specific settings configurable; email relay quotas defined; tests pass.

---

### Phase 8: Profile Override System Implementation (Week 8)

**Goal:** Implement full profile override mechanism with merge semantics and validation.

| Task | File(s)                      | Description                             | Acceptance Criteria                                         |
| ---- | ---------------------------- | --------------------------------------- | ----------------------------------------------------------- |
| 8.1  | `src/profiles.rs`            | Implement `ProfileOverride` struct      | Fields match all config sections with `Option<T>`           |
| 8.2  | `src/profiles.rs`            | Add `Profile::apply_overrides()` method | Deep merge with precedence rules                            |
| 8.3  | `src/profiles.rs`            | Add profile validation                  | Ensure compatibility (e.g., federation requires encryption) |
| 8.4  | `src/lib.rs`                 | Add `[[profile.override]]` TOML parsing | Support multiple override blocks                            |
| 8.5  | `src/lib.rs`                 | Implement profile selection logic       | ENV var > CLI flag > file `profile` field > default         |
| 8.6  | `tests/profile_overrides.rs` | Test simple override                    | Standard overrides potato storage                           |
| 8.7  | `tests/profile_overrides.rs` | Test deep override                      | Nested field merge (storage.truth.backend)                  |
| 8.8  | `tests/profile_overrides.rs` | Test multiple overrides                 | Last override wins                                          |
| 8.9  | `tests/profile_overrides.rs` | Test validation failures                | Invalid combinations rejected                               |
| 8.10 | Example TOML                 | Create `examples/custom-override.toml`  | Show custom profile with overrides                          |
| 8.11 | Docs                         | Document override system in README      | Precedence and merge rules                                  |

**Exit Criteria:** Profile override system complete; deep merge working; validation enforced.

---

### Phase 9: Template Generation & Validation (Week 9)

**Goal:** Implement config template generation (`--init-config`) and validation tooling.

| Task | File(s)                        | Description                                 | Acceptance Criteria                                 |
| ---- | ------------------------------ | ------------------------------------------- | --------------------------------------------------- |
| 9.1  | `src/templates.rs`             | Create template generator                   | Generates commented TOML for each profile           |
| 9.2  | `src/templates.rs`             | Add profile-specific templates              | Potato, standard, hyperscale templates              |
| 9.3  | `src/validation.rs`            | Implement config validator                  | Returns `Result<(), ValidationError>`               |
| 9.4  | `src/validation.rs`            | Add validation rules                        | Required fields, compatibility checks, range limits |
| 9.5  | `src/lib.rs`                   | Add `JigConfig::generate_template()` method | Returns TOML string with comments                   |
| 9.6  | `src/lib.rs`                   | Add `JigConfig::validate()` method          | Validates entire config                             |
| 9.7  | `tests/template_generation.rs` | Test template generation                    | All profiles generate valid TOML                    |
| 9.8  | `tests/validation.rs`          | Test validation rules                       | Invalid configs rejected with clear errors          |
| 9.9  | Example binary                 | Create `examples/config_gen.rs`             | CLI tool to generate templates                      |
| 9.10 | Docs                           | Document template generation                | Usage instructions for `--init-config`              |

**Exit Criteria:** Template generation works; validation catches errors; clear error messages.

---

### Phase 10: Documentation & Integration (Week 10)

**Goal:** Complete documentation, integration examples, and migration guides.

| Task  | File(s)                         | Description                  | Acceptance Criteria                     |
| ----- | ------------------------------- | ---------------------------- | --------------------------------------- |
| 10.1  | `README.md`                     | Comprehensive rewrite        | Cover all config sections with examples |
| 10.2  | `MIGRATION.md`                  | Create migration guide       | Map old config to new profiles          |
| 10.3  | `examples/README.md`            | Document all examples        | Explain each TOML example               |
| 10.4  | `docs/PROFILES.md`              | Profile deep-dive            | When to use each profile                |
| 10.5  | `docs/EXECUTION_CONSTRAINTS.md` | Runtime limits guide         | Fuel, memory, timeout tuning            |
| 10.6  | `docs/PRICING.md`               | Pricing configuration guide  | Fuel bands and outcome-based pricing    |
| 10.7  | `docs/GOVERNANCE.md`            | Governance integration guide | Nameserver and tribunal setup           |
| 10.8  | `Cargo.toml`                    | Update metadata              | Version bump, keywords, categories      |
| 10.9  | `CHANGELOG.md`                  | Document all changes         | Complete changelog for v0.2.0           |
| 10.10 | Integration tests               | Cross-repo integration tests | Test with jig-server, jig-cli stubs     |

**Exit Criteria:** Documentation complete; examples work; migration guide ready; integration tests pass.

---

## Configuration Schema Summary

### Complete `jig-config.toml` Structure

```toml
# jig-config.toml v0.2 - Complete Schema

[meta]
version = "0.2"
profile = "potato"  # potato | standard | hyperscale | custom

[network]
bind_address = "127.0.0.1"
public_address = "jig.example.com"
federation_port = 7117
irc_port = 6667
ssh_port = 2222
websocket_port = 8080
smtp_port = 2525

[network.tls]
cert_path = "/etc/jig/cert.pem"
key_path = "/etc/jig/key.pem"
federation_tls = true
websocket_tls = true

[storage]
# Single-tier (potato)
backend = "sqlite"
connection_string = "~/.jig/jig.db"
max_connections = 10
sqlite_wal = true
cache_size_mb = 100

# OR Multi-tier (hyperscale)
[storage.truth]
backend = "cockroachdb"
connection_string = "postgres://..."

[storage.speed]
backend = "scylladb"
contact_points = ["10.0.0.1:9042"]

[storage.intelligence]
backend = "clickhouse"
connection_string = "tcp://..."

[storage.archive]
backend = "s3"
bucket = "jig-blocks"
region = "us-east-1"

[runtime]
# Execution constraints
fuel_max = 5_000_000
memory_max_mb = 32
execution_timeout_ms = 250

[runtime.determinism]
float_policy = "deterministic"  # deterministic | deny | allow
prng_seed_source = "manifest"   # manifest | host | mixed
forbidden_imports = [
  "wasi_snapshot_preview1::random_get",
  "wasi_snapshot_preview1::clock_time_get",
]

[runtime.capabilities]
default_grants = []  # No ambient authority
scope_pattern_syntax = "glob"  # glob | regex
rate_limit_global = 1000  # requests/sec

[[runtime.capabilities.grant]]
name = "net.fetch"
scope = ["https://api.example.com/*"]
fuel_budget = 1_000_000

[runtime.engine]
type = "wasmtime"
target = "./server.wasm"
inherit_stdio = true
args = ["--port", "8080"]

[runtime.engine.wasmtime]
fuel = 5_000_000
[[runtime.engine.wasmtime.preopened]]
host = "/var/jig/data"
guest = "/data"
directory_permissions = "readwrite"
file_permissions = "readwrite"

[receipts]
schema_version = "0.2"
canonical_format = "jcs"  # JCS (JSON Canonicalization Scheme)
signed_fields = ["block_id", "render_hash", "fuel_used", "counters", "timings_ms", "limits", "outcome"]

[receipts.canonicalization]
algorithm = "jcs"
field_order = "sorted"
float_precision = 15

[receipts.outcome_taxonomy]
statuses = ["ok", "soft_fail", "hard_fail"]
reason_codes = [
  "NET_TIMEOUT",
  "CAPABILITY_DENIED",
  "MANIFEST_MISMATCH",
  "RUNTIME_OOM",
  "NONDETERMINISM_DETECTED",
]
affordances_catalog = [
  "email.delivered",
  "bridge.forwarded",
  "net.http_2xx",
  "queue.enqueued",
]

[pricing]
model = "outcome_based"  # outcome_based | fixed | free

[[pricing.fuel_bands]]
capability_type = "cpu"
cost_per_million = 0.001  # USD
metering_mode = "fuel_used"

[[pricing.fuel_bands]]
capability_type = "bandwidth"
cost_per_gb = 0.05
metering_mode = "bytes_tx_rx"

[[pricing.fuel_bands]]
capability_type = "crypto"
cost_per_operation = 0.0001
metering_mode = "operation_count"

[pricing.useful_work_discounts]
enabled = true
null_sec_discount_pct = 0
low_sec_discount_pct = 10
high_sec_discount_pct = 25
min_streak_days = 30

[governance]
nameserver_url = "https://ns.jig.dev"
transparency_log_url = "https://transparency.jig.dev"

[governance.reputation_tiers]
null_sec_pow_difficulty = 24
low_sec_pow_difficulty = 16
high_sec_pow_difficulty = 8
verified_pow_difficulty = 0

[governance.tribunal]
panel_size = 5
quorum_threshold = 3
appeal_window_hrs = 168  # 7 days
evidence_retention_days = 90

[governance.progressive_cost]
suspicious_pow_multiplier = 2.0
blocked_pow_multiplier = 999.0
penalty_decay_half_life_days = 30

[analytics]
backend = "duckdb"  # duckdb | parquet | clickhouse | disabled
retention_days = 90
sample_rate = 1.0  # 100%
privacy_mode = "anonymized"  # anonymized | aggregated | full

[analytics.duckdb]
path = "~/.jig/analytics.duckdb"

[analytics.clickhouse]
dsn = "tcp://clickhouse.internal:9000"
database = "jig_analytics"
batch_size = 1000
flush_interval_sec = 60

[telemetry]
metrics_enabled = true
metrics_endpoint = "http://localhost:9090/metrics"
trace_sampling = 0.01  # 1%
log_level = "info"
structured_logging = true

[telemetry.opentelemetry]
enabled = false
endpoint = "http://localhost:4317"
service_name = "jig-server"

[bridges]
enabled = ["irc", "websocket"]  # irc | ssh | websocket | email

[bridges.email]
enabled = true
relay_quota_per_day = 1000
dns_discovery = true
spf_dkim_enforcement = "strict"  # strict | lenient | disabled

[bridges.email.deliverability]
analytics_backend = "clickhouse"
track_opens = false  # privacy-first default
track_bounces = true

[bridges.irc]
enabled = true
server = "irc.libera.chat:6697"
channels = ["#jig"]
nick_prefix = "jig_"
block_wrapper = true  # Wrap IRC messages as blocks

[bridges.ssh]
enabled = false
bind_port = 2222
authorized_keys_path = "~/.jig/authorized_keys"

[bridges.websocket]
enabled = true
bind_port = 8080
max_connections = 10000
ping_interval_sec = 30

[features]
core = true
federation = false
irc = true
ssh = false
websocket = true
email = false
web_ui = false
metrics = true
anonymous = true
encryption = true

# Profile Override Example
[[profile.override]]
name = "standard"
[profile.override.storage]
backend = "postgres"
connection_string = "postgres://jig@localhost/jig"
[profile.override.runtime]
fuel_max = 10_000_000
[profile.override.analytics]
backend = "parquet"

[[profile.override]]
name = "hyperscale"
[profile.override.storage.truth]
backend = "cockroachdb"
[profile.override.storage.speed]
backend = "scylladb"
[profile.override.storage.intelligence]
backend = "clickhouse"
[profile.override.storage.archive]
backend = "s3"
[profile.override.runtime]
fuel_max = 50_000_000
memory_max_mb = 128
[profile.override.analytics]
backend = "clickhouse"
```

---

## Testing Strategy

### Unit Tests

- Config parsing for each section
- Profile merge logic
- Validation rules
- Template generation

### Integration Tests

- Load complete configs for each profile
- Override precedence
- Cross-section dependencies (e.g., federation requires encryption)
- Invalid config rejection

### Property Tests

- Config serialization round-trips
- Profile overrides are associative
- Validation is deterministic

### Cross-Repo Integration

- `jig-server` reads config correctly
- `jig-cli` uses profile overrides
- `jig-runtime` applies execution constraints

---

## Migration Path

### For Existing Deployments

1. **Detect old config format**: Check for legacy field names
2. **Generate migration report**: Show old → new field mappings
3. **Auto-migrate where possible**: Convert to profile-based config
4. **Warn on breaking changes**: Flag manual intervention needed
5. **Provide rollback**: Keep backup of old config

### Backward Compatibility

- Keep old field names as deprecated aliases (one release cycle)
- Emit warnings when old fields detected
- Provide `jig-config migrate` CLI tool
- Document all breaking changes in MIGRATION.md

---

## Success Criteria

### Functional

- ✅ All config sections parse correctly
- ✅ Profile override system works end-to-end
- ✅ Execution constraints applied by runtime
- ✅ Storage tier separation supported
- ✅ Receipt v0.2 configuration complete
- ✅ Pricing fuel bands configurable
- ✅ Governance integration wired
- ✅ Analytics backend selectable per profile

### Quality

- ✅ 100% unit test coverage on config parsing
- ✅ Integration tests pass with all profiles
- ✅ Documentation complete and accurate
- ✅ Examples validate and run
- ✅ Migration guide tested on real configs

### Performance

- ✅ Config parsing < 10ms (cold)
- ✅ Profile merge < 1ms
- ✅ Validation < 5ms
- ✅ Template generation < 50ms

### Adoption

- ✅ `jig-server` uses new config
- ✅ `jig-cli` uses new config
- ✅ `jig-runtime` reads execution constraints
- ✅ `jig-nameserver` reads governance config
- ✅ `jig-bridge-email` reads bridge config

---

## Dependencies & Blockers

### Upstream Status - ✅ UNBLOCKED

**`jig-core` - Receipt v0.2 & Capability DSL COMPLETE** (as of 2025-11-03)

Implementation verified in `repos/jig-core/src/`:

- ✅ **receipt.rs** - `BlockReceipt` with v0.2 fields:
  - `receipt_schema_version`, `renders_match`, `counters` (with `fuel_by_capability`), `timings_ms`, `limits`, `outcome`
  - `OutcomeStatus` enum (Ok, SoftFail, HardFail), `ReasonCode` support
  - `HashAlgorithms` for block_id and render_hash
- ✅ **capability_scope.rs** - `CapabilityScopePattern` with:
  - Canonical scope parsing and formatting
  - `covers()` method for `requested ⊆ granted` validation
  - Wildcard support, serialization
- ✅ **wasm_validation.rs** - `verify_determinism()` with:
  - Float instruction detection, import allowlist/forbid list
  - Memory/table limit checking, `DeterminismReport` and `DeterminismViolation`
- ✅ **serde_helpers.rs** - `to_canonical_json_bytes()` for JCS-style canonicalization
- ✅ **capability_validation.rs** & **capability_registry.rs** - Validation and registry infrastructure

**Spec Status:**

- ⚠️ `jig-spec` - BLOCK_RUNTIME_SPEC docs in progress (code complete, docs following)

### Downstream (Blocked by This Work)

These repos can proceed once `jig-config` Phase 0-3 complete:

- 🔄 `jig-server` - Needs execution constraint config to emit v0.2 receipts with correct limits
- 🔄 `jig-cli` - Needs runtime config to run local blocks with correct fuel/memory/timeout
- 🔄 `jig-runtime` - Needs determinism config to enforce validation rules from config
- 🔄 `jig-nameserver` - Needs governance config to apply progressive cost function

### Parallel (Can Develop Concurrently)

- ✅ `jig-gui` - Can start config integration in parallel (Phase 3+)
- ✅ `jig-bridge-email` - Can define bridge config independently (Phase 7)
- ✅ Testing infrastructure - Can develop test harness alongside all phases

---

## Risk Assessment

| Risk                                         | Likelihood | Impact | Status / Mitigation                                       |
| -------------------------------------------- | ---------- | ------ | --------------------------------------------------------- |
| ~~Receipt v0.2 types change~~                | ~~Medium~~ | ~~High~~ | ✅ **RESOLVED** - jig-core types finalized 2025-11-03     |
| ~~Capability DSL unstable~~                  | ~~Medium~~ | ~~High~~ | ✅ **RESOLVED** - jig-core DSL complete 2025-11-03        |
| Breaking existing deployments                | Medium     | High   | ⚠️ Backward compat layer + migration tool + version bump |
| Config complexity overwhelms users           | Medium     | High   | ⚠️ Good defaults + potato profile as default; doc focus  |
| Profile override merge semantics unclear     | Low        | Medium | ⚠️ Comprehensive tests + clear docs                      |
| Storage tier config too complex for potato   | Low        | Low    | ✅ Single-tier fallback always available                 |
| Pricing model changes invalidate fuel bands  | Low        | Medium | ⚠️ Extensible fuel bands; version pricing config         |
| Hot reload implementation complexity         | Medium     | Medium | ⚠️ Phase 2 feature; mark MVP fields restart-required     |

---

## Next Steps - ✅ READY TO START

### Immediate Actions (This Week)
1. ✅ **Plan Review Complete** - Upstream blockers resolved, design decisions finalized
2. 🚀 **Begin Phase 0** (Foundation & Types) - Start immediately
   - Create `src/profiles.rs` with enum and merge logic
   - Create `src/execution.rs` with `ExecutionConstraints` struct
   - Wire modules and add tests
   - Target: Complete by end of Week 1

### Sequenced Rollout
- **Week 1**: Phase 0 (Foundation & Types)
- **Weeks 2-3**: Phases 1-2 (Execution & Storage)
- **Weeks 4-5**: Phases 3-4 (Receipts & Pricing)
- **Weeks 6-7**: Phases 5-6 (Governance & Analytics)
- **Weeks 8-9**: Phases 7-9 (Bridges, Overrides, Validation)
- **Week 10**: Phase 10 (Documentation & Integration)
- **Week 11** (buffer): Testing, refinement, cross-repo integration
- **Week 12**: Release v0.2.0 and coordinate downstream adoption

### Coordination Points
- **After Phase 2**: Notify `jig-server` and `jig-runtime` teams (execution constraints ready)
- **After Phase 3**: Notify `jig-core` integration team (receipt config ready)
- **After Phase 5**: Notify `jig-nameserver` team (governance config ready)
- **After Phase 7**: Notify `jig-bridge-email` team (bridge config ready)
- **After Phase 10**: Full downstream rollout coordination meeting

---

## Resolved Design Decisions

### 1. Canonicalization Algorithm

**Decision:** JCS (JSON Canonicalization Scheme) as primary

- **Rationale:** Determinism is non-negotiable; JCS provides stable ordering and formatting
- **Implementation:** `jig-core` already uses `to_canonical_json_bytes()` with sorted keys
- **CBOR:** Consider as optional optimization later, but not at expense of determinism

### 2. Float Policy

**Decision:** Deny floats by default (strict determinism)

- **Rationale:** Aligns with `jig-core` strict-determinism-by-default approach
- **Implementation:** Feature-flag allow mode but don't wire initially; `wasm_validation.rs` already detects float instructions
- **Escape Hatch:** Explicit config opt-in required to relax policy (with warnings)

### 3. Fuel Band Extensibility

**Decision:** Yes, with registry for custom capability types

- **Core Bands:** CPU, bandwidth, crypto (MVP)
- **Extended Bands:** GPU, LPU (linear processing unit), storage I/O, etc.
- **Custom Bands:** Registry-based extension; expect <10% of deployments to use custom types
- **Implementation:** Extensible enum in `src/pricing.rs` with `Custom(String)` variant

### 4. Profile Inheritance

**Decision:** Simple inheritance with dead-simple defaults

- **Implementation:** Standard/Hyperscale profiles overlay Potato base
- **User Model:** Users only specify overrides; system merges with profile defaults
- **Default Profile:** Potato is the implicit default (potato-friendly principle)
- **No Deep Hierarchy:** Keep to 3 built-in profiles; custom profiles via overrides
- **P4 Feature:** User-defined profile parent-child relationships (not now)

### 5. Hot Reload

**Decision:** Context-dependent, prefer hot-reload where safe

- **Restart Required:** Execution limits (fuel/memory/timeout), runtime engine, storage backends, capability grants
- **Hot-Reloadable:** Log levels, metrics endpoints, sampling rates, rate limits, non-security config
- **Heuristic:** Avoid server/nameserver restarts when possible; minimize user irritation
- **UI Constraints:** CLI/GUI boundaries may force restarts; document clearly
- **Implementation:** Mark fields with `#[hot_reloadable]` attribute; provide `--watch-config` flag

### 6. Multi-Instance Config

**Decision:** Federated config expected; design for multi-tenancy from start

- **Core Feature:** Not optional—vanilla IRC doesn't do this, we do
- **Sharing Mechanism:** Nameserver + discovery protocol + config overlays
- **Tenant Model:** Parent tenant config → child tenant with overrides
- **Auth/Ownership:** Identity + capability inheritance across tenant boundaries
- **Implementation:** Phase 1 includes config structure; full federation in Phase 2
- **Cross-Instance Sync:** Config distribution via discovery protocol + signed config blocks

---

## Changelog

### v0.2.0 - 2025-11-04 - Ready to Proceed
**Status Change:** Draft → **✅ READY TO START**

**Blockers Resolved:**
- ✅ `jig-core` Receipt v0.2 types complete (2025-11-03)
- ✅ `jig-core` Capability DSL complete (2025-11-03)
- ✅ `jig-core` Determinism validation complete (2025-11-03)
- ✅ All 6 open questions resolved with team consensus

**Design Decisions Finalized:**
1. **Canonicalization:** JCS (JSON Canonicalization Scheme) primary
2. **Float Policy:** Deny by default (strict determinism)
3. **Fuel Bands:** Extensible with registry (CPU/bandwidth/crypto core + custom)
4. **Profile Inheritance:** Simple overlay model (Standard/Hyperscale extend Potato)
5. **Hot Reload:** Context-dependent; security-critical fields require restart
6. **Multi-Instance:** Federated config via nameserver + discovery protocol

**Plan Updates:**
- Added Executive Summary with mission, status, metrics, timeline
- Updated Dependencies & Blockers: marked jig-core complete
- Updated Risk Assessment: resolved upstream risks, downgraded others
- Updated Next Steps: immediate start with coordination points
- Clarified LPU as "language processing unit" (not "linear")

### v0.1.0 - 2025-11-04 - Initial Draft
- Gap analysis against executable internet requirements
- 10-phase implementation plan with detailed task breakdown
- Complete TOML schema preview for v0.2
- Testing strategy and success criteria
- Migration path and backward compatibility

---

**End of Implementation Plan**

_Last Updated: 2025-11-04_
_Version: 0.2.0_
_Status: ✅ **APPROVED - READY TO PROCEED**_
_Next Action: Begin Phase 0 (Foundation & Types)_
