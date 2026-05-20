# Migration Guide: jig-config v0.2.0

This guide helps you migrate to jig-config v0.2.0 from earlier versions or hand-written configurations.

---

## Table of Contents

1. [Quick Start for New Users](#quick-start-for-new-users)
2. [Migrating from Manual Config](#migrating-from-manual-config)
3. [Migrating from v0.1](#migrating-from-v01)
4. [Profile Selection](#profile-selection)
5. [Breaking Changes](#breaking-changes)
6. [Feature Additions](#feature-additions)
7. [Configuration Validation](#configuration-validation)
8. [Hot-Reload Migration](#hot-reload-migration)

---

## Quick Start for New Users

If you're starting fresh with jig-config v0.2.0, use the template generator:

```bash
# Generate minimal potato config (default, zero-config)
cargo run --example config_generator -- --profile potato > ~/.jig/config.toml

# Generate full standard config with comments
cargo run --example config_generator -- --profile standard --full > ~/.jig/config.toml

# Generate hyperscale config for production
cargo run --example config_generator -- --profile hyperscale --full > ~/.jig/config.toml
```

**That's it!** The generated config includes all required sections with sensible defaults.

---

## Migrating from Manual Config

If you've been manually writing jig-server configurations, here's how to migrate:

### Step 1: Identify Your Profile

Choose the profile that best matches your deployment:

| Your Current Setup | Recommended Profile |
|--------------------|---------------------|
| Single SQLite database, <100 users | **Potato** (default) |
| PostgreSQL + Redis, 1K-10K users | **Standard** |
| Multi-database (Cockroach, Scylla, ClickHouse), 100K+ users | **Hyperscale** |
| Highly custom configuration | **Custom** |

### Step 2: Generate Template

```bash
# Generate template for your chosen profile
cargo run --example config_generator -- --profile standard --full > new-config.toml
```

### Step 3: Port Custom Settings

Compare your old config with the generated template and port custom settings:

```bash
# Side-by-side comparison
diff old-config.toml new-config.toml
```

**Common Custom Settings to Port:**
- Database connection strings
- Network bind addresses and ports
- TLS certificates
- API keys and secrets
- Custom fuel limits
- Bridge configurations

### Step 4: Validate

Run the validator to catch misconfigurations:

```rust
use jig_config::validation::ConfigValidator;

let mut validator = ConfigValidator::new();

// Validate your specific sections
validator.validate_runtime_constraints(fuel_max, memory_max_mb, timeout_ms);
validator.validate_storage(backend, path, connection_string);
validator.validate_federation_requires_encryption(federation_enabled, encryption_enabled);

if validator.has_errors() {
    for error in validator.errors() {
        eprintln!("{}", error);
    }
    std::process::exit(1);
}
```

### Step 5: Test

1. Start jig-server with the new config
2. Send a test message
3. Verify receipt generation
4. Check audit logs
5. Monitor analytics

---

## Migrating from v0.1

### Breaking Changes

1. **Receipt Schema Updated to v0.2**
   - **Old**: `render_hash`, `fuel_used`, `memory_peak_mb`
   - **New**: `renders_match`, `counters`, `timings_ms`, `limits`, `outcome`
   - **Migration**: Set `require_v2_fields = true` in `[receipts]`

2. **Storage Tiers Renamed**
   - **Old**: `[storage]` (single backend)
   - **New**: `[storage.truth]`, `[storage.speed]`, `[storage.intelligence]`, `[storage.archive]`
   - **Migration**: Move your single storage backend to `[storage.truth]`

3. **Pricing Model Required**
   - **Old**: No explicit pricing configuration
   - **New**: Must specify `model = "free"` or `"outcome_based"`
   - **Migration**: Add `[pricing] model = "free"` for potato, `"outcome_based"` for standard/hyperscale

4. **Profile System Introduced**
   - **Old**: No profile concept
   - **New**: Must specify profile or defaults to potato
   - **Migration**: Add `[meta] profile = "potato"` (or omit for default)

### Configuration Mapping

#### Old v0.1 Config

```toml
[runtime]
fuel_max = 1000000
memory_max_mb = 32
execution_timeout_ms = 250

[storage]
backend = "sqlite"
connection_string = "~/.jig/jig.db"
```

#### New v0.2 Config

```toml
[meta]
profile = "potato"  # Or omit for default

[runtime.constraints]
fuel_max = 1000000
memory_max_mb = 32
execution_timeout_ms = 250
deterministic = true

[runtime.determinism]
float_policy = "deny"
prng_seed_source = "manifest"

[storage.truth]
backend = "sqlite"
connection_string = "~/.jig/jig.db"
max_connections = 10
sqlite_wal = true
```

### Step-by-Step Migration

1. **Add Profile Section**
   ```toml
   [meta]
   profile = "potato"  # Choose: potato, standard, hyperscale
   ```

2. **Split Runtime Config**
   ```toml
   # Old: [runtime]
   # New: [runtime.constraints]
   [runtime.constraints]
   fuel_max = 1000000
   memory_max_mb = 32
   execution_timeout_ms = 250
   deterministic = true

   # New: [runtime.determinism]
   [runtime.determinism]
   float_policy = "deny"
   prng_seed_source = "manifest"
   ```

3. **Tier Your Storage**
   ```toml
   # Old: [storage]
   # New: [storage.truth]
   [storage.truth]
   backend = "sqlite"
   connection_string = "~/.jig/jig.db"
   max_connections = 10
   sqlite_wal = true
   ```

4. **Add Receipt Configuration**
   ```toml
   [receipts]
   require_v2_fields = true
   require_renders_match = false  # Set true for hyperscale
   require_fuel_breakdown = true

   [receipts.canonicalization]
   block_id_algorithm = "blake3-256"
   render_hash_algorithm = "sha256"

   [receipts.outcome]
   require_outcome = true

   [receipts.retention]
   persist = true
   retention_days = 30  # 30 for potato, 90 for standard, 365 for hyperscale
   compress = true
   storage_tier = "intelligence"
   ```

5. **Add Pricing Configuration**
   ```toml
   [pricing]
   model = "free"  # For potato profile

   [pricing.free_tier]
   fuel_per_month = 1_000_000_000
   bandwidth_per_month = 10737418240  # 10 GB
   operations_per_month = 10_000

   [pricing.useful_work_discounts]
   enabled = false

   [pricing.outcome_adjustments]
   charge_on_success = true
   charge_on_soft_fail = false
   charge_on_hard_fail = false
   ```

6. **Add Analytics Configuration**
   ```toml
   [analytics]
   backend = "duckdb"  # duckdb for potato, parquet for standard, clickhouse for hyperscale
   retention_days = 30
   sample_rate = 0.1  # 10% for potato
   privacy_mode = "anonymized"

   [telemetry]
   metrics_enabled = true
   trace_sampling = 0.01
   log_level = "info"
   ```

7. **Add Audit Configuration**
   ```toml
   [audit]
   compliance_standard = "none"  # none for potato, soc2 for standard, enterprise for hyperscale
   enabled_categories = ["security", "execution"]
   min_severity = "warn"
   log_payloads = false
   anonymize_pii = false
   sign_audit_logs = false
   tamper_evident = false

   [audit.retention]
   enabled = true
   retention_days = 7  # 7 for potato, 365 for standard, 2555 for hyperscale
   compress = true
   storage_tier = "truth"
   ```

### Automated Migration Tool

We provide a migration script that converts v0.1 configs to v0.2:

```bash
# Migrate old config to new format
cargo run --example migrate_config -- --input old-config.toml --output new-config.toml --profile potato

# Validate migrated config
cargo run --example config_generator -- --validate new-config.toml
```

---

## Profile Selection

### Decision Tree

```
Start here
├─ Do you need federation?
│  ├─ Yes → Hyperscale
│  └─ No → Continue
├─ Do you have >10K users?
│  ├─ Yes → Hyperscale
│  └─ No → Continue
├─ Do you need SOC2/HIPAA/GDPR compliance?
│  ├─ Yes → Standard or Hyperscale
│  └─ No → Continue
├─ Do you want PostgreSQL or Redis?
│  ├─ Yes → Standard or Hyperscale
│  └─ No → Continue
└─ Are you running on a "potato" (<$10/month VPS)?
   ├─ Yes → Potato
   └─ No → Standard
```

### Profile Comparison

| Metric | Potato | Standard | Hyperscale |
|--------|--------|----------|------------|
| **Setup Time** | <60 seconds | ~10 minutes | ~1 hour |
| **Monthly Cost** | $5-10 | $50-500 | $500+ |
| **Max Users** | ~100 | ~10K | 100K+ |
| **Fuel Limit** | 1M | 5M | 50M |
| **Storage** | SQLite | Postgres + Redis | Multi-tier |
| **Analytics** | DuckDB | Parquet | ClickHouse |
| **Federation** | No | Opt-in | Yes |
| **Compliance** | None | SOC2 | Enterprise |
| **Support** | Community | Community | Commercial |

---

## Breaking Changes

### 1. Receipt Schema (v0.1 → v0.2)

**Impact**: All receipt consumers must handle new fields

**Migration**:
```rust
// Old v0.1
struct Receipt {
    render_hash: String,
    fuel_used: u64,
    memory_peak_mb: u32,
}

// New v0.2 (backwards compatible)
struct Receipt {
    // v0.1 fields (preserved)
    render_hash: String,
    fuel_used: u64,
    memory_peak_mb: u32,

    // v0.2 additions
    renders_match: Option<bool>,
    counters: Option<Counters>,
    timings_ms: Option<Timings>,
    limits: Option<Limits>,
    outcome: Option<Outcome>,
}
```

**Config**:
```toml
[receipts]
require_v2_fields = true  # Enforce v0.2 fields
```

### 2. Storage Tier Separation

**Impact**: Single `[storage]` section split into four tiers

**Migration**:
```toml
# Old v0.1
[storage]
backend = "sqlite"
connection_string = "~/.jig/jig.db"

# New v0.2
[storage.truth]  # Required
backend = "sqlite"
connection_string = "~/.jig/jig.db"

[storage.speed]  # Optional
# Omit if not needed

[storage.intelligence]  # Optional
backend = "duckdb"
path = "~/.jig/analytics.duckdb"

[storage.archive]  # Optional
# Omit if not needed
```

### 3. Pricing Model Required

**Impact**: Must explicitly specify pricing model

**Migration**:
```toml
# Add to all configs
[pricing]
model = "free"  # Or "outcome_based", "time_based", "custom"
```

### 4. Profile System

**Impact**: Profile determines defaults; must specify profile or accept potato

**Migration**:
```toml
# Add to beginning of config
[meta]
profile = "potato"  # Or "standard", "hyperscale", "custom"
```

### 5. Execution Config Nesting

**Impact**: `[runtime]` split into `[runtime.constraints]` and `[runtime.determinism]`

**Migration**:
```toml
# Old
[runtime]
fuel_max = 1000000

# New
[runtime.constraints]
fuel_max = 1000000

[runtime.determinism]
float_policy = "deny"
```

---

## Feature Additions

### New Features in v0.2.0

1. **Profile System** (Phase 0)
   - Potato, Standard, Hyperscale, Custom
   - Inheritance and overrides
   - Dead-simple defaults

2. **Storage Tiers** (Phase 1)
   - Truth, Speed, Intelligence, Archive
   - 10 supported backends
   - Profile-scaled connection limits

3. **Receipt v0.2** (Phase 2)
   - Outcome-based execution status
   - Fuel breakdown by capability
   - Canonicalization for signatures

4. **Outcome-Based Pricing** (Phase 3)
   - Fuel bands (CPU, bandwidth, crypto, storage)
   - Useful work discounts
   - Outcome adjustments (refunds on failure)

5. **Nameserver & Federation** (Phase 4)
   - Three federation modes
   - Proof-of-work (Blake3 Hashcash)
   - Reputation system
   - Tribunal adjudication

6. **Analytics & Telemetry** (Phase 5)
   - DuckDB, Parquet, ClickHouse backends
   - Privacy modes (anonymized, aggregated, full)
   - OpenTelemetry support

7. **Audit & Compliance** (Phase 6)
   - SOC2, HIPAA, GDPR, Enterprise standards
   - 7 event categories
   - Tamper-evident logging

8. **Export & Interop** (Phase 7)
   - JCS (canonical), JSON, YAML, ActivityPub, ATProto
   - Provenance preservation

9. **Bridge Configuration** (Phase 8)
   - IRC, Email, WebSocket, Federation
   - ATProto, ActivityPub
   - Transform pipelines

10. **Template Generation & Validation** (Phase 9)
    - CLI tool for config generation
    - Cross-config validator
    - Compliance enforcement

---

## Configuration Validation

### Running the Validator

```rust
use jig_config::validation::{ConfigValidator, Severity};

let mut validator = ConfigValidator::new();

// Validate all sections
validator.validate_runtime_constraints(fuel_max, memory_max_mb, timeout_ms);
validator.validate_storage(backend, path, connection_string);
validator.validate_analytics(backend, retention_days, sample_rate);
validator.validate_telemetry(trace_sampling, log_level);
validator.validate_federation_requires_encryption(federation_enabled, encryption_enabled);
validator.validate_bridges_storage(&enabled_bridges, storage_backend);
validator.validate_hyperscale_requirements(profile, analytics_backend, storage_backend);
validator.validate_useful_work_requires_nameserver(useful_work_enabled, nameserver_url);
validator.validate_audit_compliance(compliance_standard, retention_days, anonymize_pii);

// Get results
match validator.result() {
    Ok(()) => println!("Configuration is valid"),
    Err(errors) => {
        for error in errors {
            match error.severity {
                Severity::Critical => eprintln!("CRITICAL: {}", error),
                Severity::Error => eprintln!("ERROR: {}", error),
                Severity::Warning => eprintln!("WARNING: {}", error),
            }
        }
        std::process::exit(1);
    }
}
```

### Common Validation Errors

| Error | Severity | Cause | Fix |
|-------|----------|-------|-----|
| Federation requires encryption | Critical | Federation enabled without encryption | Enable encryption or disable federation |
| SQLite backend requires 'path' | Error | Missing path field | Add `path = "~/.jig/jig.db"` |
| Sample rate must be 0.0-1.0 | Error | Invalid sample rate | Set sample_rate between 0.0 and 1.0 |
| HIPAA requires PII anonymization | Critical | HIPAA without anonymize_pii | Set `anonymize_pii = true` |
| High-throughput bridges with SQLite | Warning | WebSocket/federation with SQLite | Consider PostgreSQL or accept performance hit |

---

## Hot-Reload Migration

v0.2.0 supports hot-reloading certain configuration sections without restart.

### Hot-Reload Compatible

These sections can be reloaded at runtime:

- **Rate limits**: `[pricing.rate_limits]`, `[bridges.*.limits]`
- **Penalties**: `[nameserver.penalties]`
- **Useful work discounts**: `[pricing.useful_work_discounts]`
- **Anomaly detection thresholds**: `[nameserver.anomaly_detection]`
- **Reputation decay**: `[nameserver.reputation.decay_halflife_days]`
- **Analytics sampling**: `[analytics.sample_rate]`, `[telemetry.trace_sampling]`

### Requires Restart

These sections require full restart:

- **Network configuration**: Listen addresses, ports, TLS
- **Storage backends**: Connection strings, backend changes
- **PoW secret**: `[nameserver.pow.secret_key]`
- **Federation mode**: `[federation.mode]`
- **Execution constraints**: Fuel/memory/timeout limits
- **Compliance standard**: `[audit.compliance_standard]`

### Implementing Hot-Reload

```rust
use std::sync::{Arc, RwLock};
use jig_config::pricing::PricingConfig;

// Wrap config in Arc<RwLock<T>>
let config = Arc::new(RwLock::new(PricingConfig::default()));

// Hot-reload
fn reload_pricing(config: Arc<RwLock<PricingConfig>>, new_config: PricingConfig) {
    let mut guard = config.write().unwrap();
    *guard = new_config;
}

// Usage
let config_clone = Arc::clone(&config);
std::thread::spawn(move || {
    // Watch config file for changes
    // On change, reload compatible sections
    reload_pricing(config_clone, new_pricing_config);
});
```

---

## Troubleshooting

### Error: "Profile 'potato' not found"

**Cause**: Typo in profile name
**Fix**: Use lowercase: `profile = "potato"` (not "Potato")

### Error: "Truth storage backend required"

**Cause**: Missing `[storage.truth]` section
**Fix**: Add truth storage backend:
```toml
[storage.truth]
backend = "sqlite"
connection_string = "~/.jig/jig.db"
```

### Warning: "Fuel max is very high (>1B)"

**Cause**: Fuel limit set too high
**Fix**: Reduce fuel limit or accept warning:
```toml
[runtime.constraints]
fuel_max = 1000000  # 1M for potato, 5M for standard, 50M for hyperscale
```

### Error: "Federation requires encryption"

**Cause**: Federation enabled without encryption
**Fix**: Enable encryption or disable federation:
```toml
[federation]
mode = "isolated"  # Or enable encryption in [security]
```

### Error: "HIPAA requires 7-year retention"

**Cause**: HIPAA compliance with <2555 day retention
**Fix**: Increase retention:
```toml
[audit.retention]
retention_days = 2555  # 7 years
```

---

## Getting Help

- **Documentation**: See README.md and PHASES.md
- **Examples**: Check `examples/` directory for complete configs
- **Validation**: Run validator to catch misconfigurations early
- **Templates**: Generate templates to see expected structure
- **Community**: Ask in #jig-config on Discord

---

## Changelog Summary

### v0.2.0 (2025-11-05)

**Added**:
- Profile system (Potato, Standard, Hyperscale, Custom)
- Storage tier separation (Truth, Speed, Intelligence, Archive)
- Receipt v0.2 with outcome-based execution
- Outcome-based pricing with fuel bands
- Nameserver & Federation configuration
- Analytics & Telemetry configuration
- Audit & Compliance logging (SOC2, HIPAA, GDPR)
- Export format configuration (JCS, JSON, YAML, ActivityPub, ATProto)
- Bridge configuration (IRC, Email, WebSocket, Federation, ATProto, ActivityPub)
- Template generator CLI tool
- Cross-config validator
- 323 tests, zero clippy warnings

**Changed**:
- `[runtime]` → `[runtime.constraints]` and `[runtime.determinism]`
- `[storage]` → `[storage.truth]`, `[storage.speed]`, `[storage.intelligence]`, `[storage.archive]`
- Receipt schema from v0.1 to v0.2 (backwards compatible)

**Removed**:
- None (backwards compatible where possible)

---

## Next Steps

1. **Migrate your config** using the steps above
2. **Run the validator** to catch issues
3. **Test in development** before deploying to production
4. **Monitor hot-reload** behavior for supported sections
5. **Review profile defaults** to ensure they match your needs
6. **Update documentation** to reference new config structure
7. **Train your team** on new profile system and validator

**Questions?** Check README.md, PHASES.md, or ask in #jig-config on Discord.
