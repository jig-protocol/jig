Jig Config
===========

**Cross-binary contract for deployment profiles, execution guardrails, and outcome-based pricing.**

Version: 0.2.0 (✅ All 10 Phases Complete)

## Overview

`jig-config` provides the configuration foundation that enables:
1. **Symmetric execution** across server/CLI/GUI (same limits, same behavior)
2. **Outcome-based pricing** with per-capability fuel metering
3. **Profile-driven deployment** from potato (SQLite, 60s setup) to hyperscale (multi-tier storage)
4. **Deterministic validation** enforcing Wasm constraints from config

## Deployment Profiles

Profiles provide opinionated defaults for different deployment scenarios. Users only specify overrides; the system merges with profile defaults (dead-simple defaults principle).

### Available Profiles

| Profile | Use Case | Storage | Execution Limits | Auto-start |
|---------|----------|---------|------------------|------------|
| **Potato** (default) | <100 users, single-node | SQLite | 1M fuel, 32MB, 250ms | ✅ Yes |
| **Standard** | 1K-10K users, small team | PostgreSQL + Redis | 5M fuel, 64MB, 500ms | ✅ Yes |
| **Hyperscale** | 100K+ users, federation | Multi-tier (Cockroach+Scylla+ClickHouse+S3) | 50M fuel, 256MB, 2000ms | ❌ No |
| **Custom** | User-defined | Explicit config required | Conservative defaults | ❌ No |

### Profile Inheritance

- **Potato** is the base (potato-friendly principle)
- **Standard** extends Potato with increased limits
- **Hyperscale** extends Standard with further increases
- **Custom** has no base; requires explicit configuration

### Example: Potato Profile (Default)

```toml
# jig-config.toml - Minimal configuration
# Potato profile applied implicitly

[meta]
# profile = "potato"  # Optional; potato is default

# No other config needed! Potato provides:
# - SQLite storage (truth layer only)
# - 1M fuel, 32MB memory, 250ms timeout
# - DuckDB analytics (local)
# - IRC + Core features only
# - Localhost binding (127.0.0.1)
```

### Example: Standard Profile

```toml
[meta]
profile = "standard"

# Standard extends Potato with:
# - PostgreSQL storage (truth) + optional Redis (speed)
# - 5M fuel, 64MB memory, 500ms timeout
# - Parquet analytics (local files)
# - IRC + WebSocket + Core features
# - Public binding (0.0.0.0)
```

### Example: Hyperscale Profile

```toml
[meta]
profile = "hyperscale"

# Hyperscale extends Standard with:
# - Multi-tier storage (CockroachDB, ScyllaDB, ClickHouse, S3)
# - 50M fuel, 256MB memory, 2000ms timeout
# - ClickHouse analytics (federated)
# - All features enabled
# - Public binding with TLS

# Hyperscale requires explicit storage configuration:
[storage.truth]
backend = "cockroachdb"
connection_string = "postgres://jig@cluster/jig"

[storage.speed]
backend = "scylladb"
contact_points = ["10.0.0.1:9042"]

[storage.intelligence]
backend = "clickhouse"
connection_string = "tcp://analytics:9000"

[storage.archive]
backend = "s3"
bucket = "jig-blocks"
region = "us-east-1"
```

### Example: Profile Override

Apply specific settings from one profile over another:

```toml
[meta]
profile = "potato"  # Start with potato defaults

[[profile.override]]
name = "standard"

# Apply only Standard's storage config
[profile.override.storage]
backend = "postgres"
connection_string = "postgres://localhost/jig"

# Result: Potato limits + Standard storage
```

## Execution Constraints

Execution constraints ensure symmetric runtime behavior across server, CLI, and GUI. These limits are snapshotted into receipts for audit verification.

### Default Execution Constraints by Profile

| Constraint | Potato | Standard | Hyperscale |
|------------|--------|----------|------------|
| **Fuel Max** | 1,000,000 | 5,000,000 | 50,000,000 |
| **Memory Max** | 32 MB | 64 MB | 256 MB |
| **Timeout** | 250 ms | 500 ms | 2000 ms |
| **Deterministic** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Import Allowlist** | `jig_host::*` | `jig_host::*` | `jig_host::*` |

### Determinism Enforcement

All profiles enforce deterministic execution by default (strict-determinism-by-default principle):
- ❌ Float instructions denied
- ❌ Non-allowlisted imports rejected (clock, random, sockets)
- ❌ Unbounded memory/table growth prevented
- ✅ Explicit opt-in required to relax validation (for testing only)

## Runtime Configuration

The `RuntimeConfig` aggregator bundles all execution settings consumed by jig-server, jig-cli, and jig-runtime.

### Structure

```rust
RuntimeConfig {
    constraints: ExecutionConstraints,      // Fuel/memory/timeout limits
    determinism: DeterminismConfig,         // Float policy, PRNG, forbidden imports
    capabilities: CapabilityConfig,         // Grants, scopes, rate limits
}
```

### Determinism Configuration

Controls how strictly the runtime enforces deterministic behavior:

**Float Policy:**
- `deny` (default): Reject modules with float instructions
- `deterministic`: Allow floats with Wasmtime deterministic mode
- `allow`: Permit non-deterministic floats (testing only)

**PRNG Seed Source:**
- `manifest` (default): Seed derived from block manifest (block_id, author, timestamp)
- `host`: Seed provided by host at execution time
- `mixed`: Combined manifest + host entropy

**Forbidden Imports:**
Always denied regardless of allowlist:
- `wasi_snapshot_preview1::random_get`
- `wasi_snapshot_preview1::clock_time_get`
- `wasi_snapshot_preview1::sock_*`

### Capability Configuration

Controls which capabilities blocks can request:

**Zero Ambient Authority:**
- `default_grants` is empty by default
- Blocks must explicitly request capabilities in manifest

**Rate Limits (by profile):**
- Potato: 100 req/s global
- Standard: 1,000 req/s global
- Hyperscale: 10,000 req/s global

**Scope Pattern Syntax:**
- `glob` (default): Unix-style wildcards (`jig_host::*`, `https://*.example.com/*`)
- `regex`: Full regex (use sparingly for audit-ability)

### Example: Runtime Config in TOML

```toml
[runtime.constraints]
fuel_max = 5_000_000
memory_max_mb = 64
execution_timeout_ms = 500
deterministic = true

import_allowlist = [
    "jig_host::*",
    "env::get"
]

[runtime.determinism]
float_policy = "deny"
prng_seed_source = "manifest"

[runtime.capabilities]
default_grants = []  # Zero ambient authority
scope_pattern_syntax = "glob"
rate_limit_global = 1000

[runtime.capabilities.rate_limits]
"net.fetch" = 500
"crypto.sign" = 2000
```

## Storage Tier Architecture

jig-config supports a **layered storage architecture** with four distinct tiers, each optimized for different access patterns and durability requirements. This enables flexible deployment from single-node SQLite to federated multi-database architectures.

### Storage Tiers

| Tier | Purpose | Typical Backends | Required |
|------|---------|------------------|----------|
| **Truth** | ACID-compliant source of truth | SQLite, PostgreSQL, CockroachDB | ✅ Yes |
| **Speed** | High-throughput real-time operations | Redis, ScyllaDB | ❌ Optional |
| **Intelligence** | Analytics and aggregations | DuckDB, Parquet, ClickHouse | ❌ Optional |
| **Archive** | Long-term cold storage | S3, filesystem | ❌ Optional |

### Supported Backends

| Backend | Use Case | Profiles |
|---------|----------|----------|
| **SQLite** | Single-node, zero-config | Potato |
| **PostgreSQL** | Standard RDBMS | Standard |
| **CockroachDB** | Distributed SQL | Hyperscale |
| **Redis** | In-memory cache | Standard, Hyperscale |
| **ScyllaDB** | Cassandra-compatible, high-throughput | Hyperscale |
| **DuckDB** | Embedded analytics | Potato |
| **Parquet** | Columnar file format | Standard |
| **ClickHouse** | Columnar analytics | Hyperscale |
| **S3** | Object storage | Hyperscale |
| **Memory** | Testing only | N/A |

### Storage Configuration by Profile

**Potato Profile (Default):**
```toml
# Two-tier: Truth (SQLite) + Intelligence (DuckDB)
[storage.truth]
backend = "sqlite"
connection_string = "~/.jig/jig.db"
max_connections = 10
sqlite_wal = true
cache_size_mb = 100

[storage.intelligence]
backend = "duckdb"
path = "~/.jig/analytics.duckdb"
batch_size = 1000
```

**Standard Profile:**
```toml
# Three-tier: Truth (Postgres) + Speed (Redis) + Intelligence (Parquet)
[storage.truth]
backend = "postgres"
connection_string = "postgres://localhost/jig"
max_connections = 50
cache_size_mb = 512

[storage.speed]
backend = "redis"
connection_string = "redis://localhost:6379"
max_connections = 50

[storage.intelligence]
backend = "parquet"
path = "~/.jig/parquet/"
compression = "snappy"
```

**Hyperscale Profile:**
```toml
# Four-tier: All layers enabled
[storage.truth]
backend = "cockroachdb"
connection_string = "postgres://jig@cluster/jig?sslmode=verify-full"
max_connections = 100
cache_size_mb = 1024

[storage.speed]
backend = "scylladb"
contact_points = ["10.0.1.1:9042", "10.0.1.2:9042", "10.0.1.3:9042"]
keyspace = "jig_speed"
replication_factor = 3
consistency_level = "QUORUM"

[storage.intelligence]
backend = "clickhouse"
connection_string = "tcp://analytics-cluster:9000/jig_analytics"
batch_size = 10_000
flush_interval_sec = 30
compression = "lz4"

[storage.archive]
backend = "s3"
bucket = "jig-blocks-prod"
region = "us-east-1"
access_key_id = "${JIG_S3_ACCESS_KEY}"
secret_access_key = "${JIG_S3_SECRET_KEY}"
```

### Backend-Specific Configuration

**SQLite:**
- `connection_string` (required): Path to database file
- `sqlite_wal` (optional, default `true`): Enable Write-Ahead Logging
- `max_connections` (optional, default `10`): Connection pool size
- `cache_size_mb` (optional, profile-scaled): In-memory cache size

**PostgreSQL / CockroachDB:**
- `connection_string` (required): Postgres-compatible connection string
- `max_connections` (optional, profile-scaled): Connection pool size
- `cache_size_mb` (optional, profile-scaled): Query cache size

**ScyllaDB:**
- `contact_points` (required): Array of host:port cluster endpoints
- `keyspace` (required): Keyspace name
- `replication_factor` (optional, profile-scaled): Replication factor (1/2/3)
- `consistency_level` (optional, default `"QUORUM"`): Read/write consistency

**ClickHouse:**
- `connection_string` (required): TCP connection string
- `batch_size` (optional, profile-scaled): Bulk insert batch size
- `flush_interval_sec` (optional, default `30`): Buffer flush interval
- `compression` (optional, default `"lz4"`): Compression algorithm

**DuckDB / Parquet:**
- `path` (required): File or directory path
- `batch_size` (optional): Bulk operation batch size
- `compression` (optional): Compression algorithm (`snappy`, `gzip`, `zstd`)

**S3:**
- `bucket` (required): S3 bucket name
- `region` (required): AWS region
- `endpoint` (optional): Custom endpoint for S3-compatible storage
- `access_key_id` (optional): AWS access key (supports `${ENV_VAR}` substitution)
- `secret_access_key` (optional): AWS secret key (supports `${ENV_VAR}` substitution)

**Redis:**
- `connection_string` (required): Redis connection string (e.g., `redis://localhost:6379`)
- `max_connections` (optional, profile-scaled): Connection pool size

### Validation Rules

1. **Truth layer is required** - All configurations must define `[storage.truth]`
2. **Backend-specific fields validated** - Missing required fields (e.g., SQLite without `connection_string`) cause validation errors
3. **Profile-scaled defaults** - Cache sizes, connection limits, and replication factors scale automatically with profile selection
4. **Optional tiers** - Speed, Intelligence, and Archive layers are optional; omit sections to disable

## Receipt Configuration

Receipt configuration controls execution attestation, outcome-based pricing, and audit policies. Receipts align with the **jig-core BlockReceipt v0.2** schema, providing deterministic proof of execution for federation, pricing, and compliance.

### Receipt Structure

Receipts contain:
- **v0.1 fields**: `render_hash`, `fuel_used`, `memory_peak_mb` (backwards compatible)
- **v0.2 additions**: `renders_match`, `counters`, `timings_ms`, `limits`, `outcome`
- **Canonicalization**: Deterministic JSON serialization with stable field ordering
- **Signature**: Optional host signature over canonical bytes (excludes `signature` and `metadata` fields)

### Receipt Configuration Sections

#### 1. Receipt Requirements

```toml
[receipts]
require_v2_fields = true          # Require v0.2 fields (counters, timings, limits, outcome)
require_renders_match = false     # Require renders_match field
require_fuel_breakdown = true     # Require fuel_by_capability in counters
```

#### 2. Canonicalization Rules

Deterministic serialization for signatures and federation:

```toml
[receipts.canonicalization]
block_id_algorithm = "blake3-256"      # Hash algorithm for block IDs
render_hash_algorithm = "sha256"       # Hash algorithm for render hashes
strict_field_order = true              # Enforce JSON key ordering (always true)
compact_json = true                    # No whitespace in canonical bytes
```

#### 3. Outcome Configuration

Standardized success/failure outcomes with reason codes:

```toml
[receipts.outcome]
require_outcome = true                 # Require outcome field in all receipts
default_affordances = []               # Affordances granted on success

# Built-in reason codes:
# - FUEL_EXHAUSTED (hard_fail, not retryable)
# - TIMEOUT (hard_fail, retryable)
# - MEMORY_EXHAUSTED (hard_fail, not retryable)
# - CAPABILITY_DENIED (hard_fail, not retryable)
# - VALIDATION_FAILED (hard_fail, not retryable)
# - RENDER_MISMATCH (soft_fail, retryable)
# - NETWORK_ERROR (soft_fail, retryable)
```

#### 4. Retention Policies

```toml
[receipts.retention]
persist = true                         # Store receipts to persistent storage
retention_days = 90                    # Retention period (0 = infinite)
archive_after_days = 30                # Archive to cold storage after N days
compress = true                        # Compress receipts before storage
storage_tier = "intelligence"          # Storage tier (truth/speed/intelligence/archive)
```

### Profile-Specific Defaults

| Setting | Potato | Standard | Hyperscale |
|---------|--------|----------|------------|
| **require_v2_fields** | ✅ Yes | ✅ Yes | ✅ Yes |
| **require_renders_match** | ❌ No | ❌ No | ✅ Yes |
| **retention_days** | 30 | 90 | 365 |
| **archive_after_days** | None | 30 | 90 |

### Outcome Status Enum

Receipts report one of three outcome statuses:

- **`ok`**: Execution completed successfully
- **`soft_fail`**: Partial success or transient failure (may retry)
- **`hard_fail`**: Permanent failure (do not retry)

### Example: Potato Profile

```toml
[receipts]
require_v2_fields = true
require_renders_match = false
require_fuel_breakdown = true

[receipts.canonicalization]
block_id_algorithm = "blake3-256"
render_hash_algorithm = "sha256"

[receipts.outcome]
require_outcome = true

[receipts.retention]
persist = true
retention_days = 30
compress = true
storage_tier = "intelligence"
```

### Example: Hyperscale Profile

```toml
[receipts]
require_v2_fields = true
require_renders_match = true  # Strict render verification
require_fuel_breakdown = true

[receipts.canonicalization]
block_id_algorithm = "blake3-256"
render_hash_algorithm = "sha256"

[receipts.outcome]
require_outcome = true

[receipts.retention]
persist = true
retention_days = 365           # 1 year retention (compliance)
archive_after_days = 90        # Archive to S3 after 90 days
compress = true
storage_tier = "intelligence"
```

## Pricing Configuration

Pricing configuration enables outcome-based metering with per-capability fuel bands, reputation-based useful work discounts, and flexible billing policies.

### Pricing Models

| Model | Description | Use Case |
|-------|-------------|----------|
| **Free** | No billing, fixed monthly limits | Development, hobby projects |
| **OutcomeBased** | Pay per execution outcome | Production usage |
| **TimeBased** | Pay per compute time | Predictable workloads |
| **Custom** | User-defined pricing | Enterprise contracts |

### Fuel Bands

Fuel bands define per-capability pricing with different metering modes:

| Capability | Metering Mode | Cost Field | Example Cost |
|------------|---------------|------------|--------------|
| **CPU** | Fuel | `cost_per_million` | $0.001 / 1M fuel |
| **Bandwidth** | Bandwidth | `cost_per_gb` | $0.05 / GB |
| **Crypto** | Operations | `cost_per_operation` | $0.0001 / op |
| **Storage** | Storage | `cost_per_gb_hour` | $0.0001 / GB-hour |

### Useful Work Discounts

Reputation-based discounts incentivize consistent, high-quality contributions:

| Tier | Description | Discount (Hyperscale) |
|------|-------------|----------------------|
| **NullSec** | Unverified, new users | 0% |
| **LowSec** | Some reputation history | 10% |
| **HighSec** | High reputation score | 25% |
| **Verified** | KYC-verified identity | 40% |

**Requirements:**
- Minimum streak days (configurable, default: 30 for hyperscale)
- Maximum discount cap (default: 50%)

### Outcome Adjustments

Control billing based on execution outcomes:

- **Success**: Charge by default (`charge_on_success = true`)
- **Soft Fail**: No charge by default, 100% refund (`charge_on_soft_fail = false`, `soft_fail_refund_pct = 100`)
- **Hard Fail**: No charge by default, 100% refund (`charge_on_hard_fail = false`, `hard_fail_refund_pct = 100`)

### Profile-Specific Defaults

| Setting | Potato | Standard | Hyperscale |
|---------|--------|----------|------------|
| **Model** | Free | OutcomeBased | OutcomeBased |
| **Fuel Bands** | None (free) | 2 (CPU, bandwidth) | 4 (CPU, bandwidth, crypto, storage) |
| **Discounts Enabled** | ❌ No | ✅ Yes | ✅ Yes |
| **Free Tier** | 1B fuel/month | None | None |

### Example: Potato (Free Tier)

```toml
[pricing]
model = "free"

[pricing.free_tier]
fuel_per_month = 1_000_000_000      # 1B fuel/month
bandwidth_per_month = 10737418240   # 10 GB/month
operations_per_month = 10_000       # 10K operations/month

[pricing.useful_work_discounts]
enabled = false

[pricing.outcome_adjustments]
charge_on_success = true
charge_on_soft_fail = false
charge_on_hard_fail = false
```

### Example: Standard (Outcome-Based)

```toml
[pricing]
model = "outcome_based"

[[pricing.fuel_bands]]
capability_type = "cpu"
cost_per_million = 0.001
metering_mode = "fuel"

[[pricing.fuel_bands]]
capability_type = "bandwidth"
cost_per_gb = 0.05
metering_mode = "bandwidth"

[pricing.useful_work_discounts]
enabled = true
verified_discount_pct = 25
min_streak_days = 7
max_discount_pct = 50
```

### Example: Hyperscale (Full Pricing)

```toml
[pricing]
model = "outcome_based"

# Four fuel bands (CPU, bandwidth, crypto, storage)
[[pricing.fuel_bands]]
capability_type = "cpu"
cost_per_million = 0.001
metering_mode = "fuel"

[[pricing.fuel_bands]]
capability_type = "bandwidth"
cost_per_gb = 0.05
metering_mode = "bandwidth"

[[pricing.fuel_bands]]
capability_type = "crypto"
cost_per_operation = 0.0001
metering_mode = "operations"

[[pricing.fuel_bands]]
capability_type = "storage"
cost_per_gb_hour = 0.0001
metering_mode = "storage"

# Reputation-based discounts
[pricing.useful_work_discounts]
enabled = true
null_sec_discount_pct = 0
low_sec_discount_pct = 10
high_sec_discount_pct = 25
verified_discount_pct = 40
min_streak_days = 30
max_discount_pct = 50

# Outcome adjustments
[pricing.outcome_adjustments]
charge_on_success = true
charge_on_soft_fail = false
charge_on_hard_fail = false
soft_fail_refund_pct = 100
hard_fail_refund_pct = 100
```

## Audit Configuration

Audit configuration enables compliance logging for security, access, execution, storage, and billing events, with support for SOC2, HIPAA, GDPR, and enterprise compliance standards.

### Compliance Standards

| Standard | Description | Retention Minimum | PII Anonymization |
|----------|-------------|-------------------|-------------------|
| **None** | No compliance requirements | 7 days | Optional |
| **SOC2** | SOC2 Type II compliance | 365 days | Optional |
| **HIPAA** | Healthcare data compliance | 2555 days (7 years) | Required |
| **GDPR** | EU data protection | 730 days (2 years) | Required |
| **Enterprise** | All standards combined | 2555 days (7 years) | Required |

### Audit Event Categories

| Category | Description | Required For |
|----------|-------------|--------------|
| **Security** | Authentication and authorization events | SOC2, HIPAA, GDPR, Enterprise |
| **Access** | User access and permission changes | SOC2, HIPAA, GDPR, Enterprise |
| **Execution** | Block execution events | SOC2, Enterprise |
| **Storage** | Storage operations | HIPAA, GDPR |
| **Billing** | Billing and pricing events | Enterprise |
| **Config** | Configuration changes | Optional |
| **System** | System health and performance | Optional |

### Audit Severity Levels

Audit events are filtered by minimum severity:

- **info**: Informational events (normal operations)
- **warn**: Warning events (potential issues)
- **error**: Error events (failures)
- **critical**: Critical security events

### Audit Retention

Audit logs can be:
- Retained for a configurable period (or infinite with `retention_days = 0`)
- Archived to cold storage after a threshold
- Compressed to save space
- Streamed to external SIEM systems in real-time

### Profile-Specific Defaults

| Setting | Potato | Standard | Hyperscale |
|---------|--------|----------|------------|
| **Compliance Standard** | None | SOC2 | Enterprise |
| **Enabled Categories** | 2 (Security, Execution) | 4 (Security, Access, Execution, Billing) | 7 (All) |
| **Min Severity** | Warn | Info | Info |
| **Log Payloads** | ❌ No | ❌ No | ✅ Yes |
| **Anonymize PII** | ❌ No | ✅ Yes | ✅ Yes |
| **Retention Days** | 7 | 365 | 2555 (7 years) |
| **Sign Logs** | ❌ No | ✅ Yes | ✅ Yes |
| **Tamper Evident** | ❌ No | ✅ Yes | ✅ Yes |
| **Stream to SIEM** | ❌ No | ❌ No | ✅ Yes |

### Example: Potato (Minimal Audit)

```toml
[audit]
compliance_standard = "none"
enabled_categories = ["security", "execution"]
min_severity = "warn"
log_payloads = false
anonymize_pii = false
include_stack_traces = false
sign_audit_logs = false
tamper_evident = false

[audit.retention]
enabled = true
retention_days = 7
compress = true
storage_tier = "truth"
stream_to_siem = false
```

### Example: Standard (SOC2 Compliance)

```toml
[audit]
compliance_standard = "soc2"
enabled_categories = ["security", "access", "execution", "billing"]
min_severity = "info"
log_payloads = false
anonymize_pii = true
include_stack_traces = true
sign_audit_logs = true
tamper_evident = true

[audit.retention]
enabled = true
retention_days = 365  # SOC2 requires 1 year
archive_after_days = 90
compress = true
storage_tier = "truth"
stream_to_siem = false
```

### Example: Hyperscale (Enterprise Compliance)

```toml
[audit]
compliance_standard = "enterprise"
enabled_categories = [
    "security",
    "access",
    "execution",
    "storage",
    "billing",
    "config",
    "system",
]
min_severity = "info"
log_payloads = true
anonymize_pii = true
include_stack_traces = true
sign_audit_logs = true
tamper_evident = true

[audit.retention]
enabled = true
retention_days = 2555  # 7 years (HIPAA/enterprise requirement)
archive_after_days = 365
compress = true
storage_tier = "truth"
stream_to_siem = true
siem_endpoint = "https://siem.example.com/ingest"
```

## Bridge & Interoperability Configuration

Bridge configuration enables bidirectional communication between Jig's deterministic Wasm block execution and third-party systems (email, IRC, Slack, ActivityPub, ATProto, etc.) while maintaining security, fuel accounting, provenance, and determinism.

### The Bridge Sandwich Pattern

Every bridge follows a three-layer architecture:

```
┌─────────────────────────────────────┐
│ INGEST: External → Jig Block        │
│ - Schema validation                 │
│ - Content sanitization              │
│ - Transform pipeline                │
│ - Capability mapping                │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ BLOCK: Deterministic Core           │
│ - Wrap as block manifest            │
│ - Fuel budgeting                    │
│ - Receipt generation                │
│ - Enforce capabilities              │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ EXPORT: Jig Block → External        │
│ - Transform pipeline                │
│ - Render to target format           │
│ - Add provenance metadata           │
│ - Privacy constraints               │
└─────────────────────────────────────┘
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Validation Mode** | `strict` (reject non-conforming), `lenient` (accept with warnings), `disabled` (trust all) |
| **Sanitization** | `aggressive` (strip all dangerous content), `moderate` (safe subset), `minimal` (obvious threats only) |
| **Transform Pipeline** | Chain of Wasm blocks that transform content (e.g., audio→text→structured data) |
| **Fuel Budgeting** | Each transform step has allocated fuel budget, metered and priced |
| **Capability Mapping** | External actions mapped to Jig capabilities with explicit grants |
| **Zero Ambient Authority** | Bridges start with no capabilities, must explicitly grant |

### Transform Types

Bridges support Wasm-based content transformations:

| Transform | Input | Output | Example Use Case |
|-----------|-------|--------|------------------|
| **text_to_structured** | Plain text | JSON/data structures | Parse tasks from emails |
| **structured_to_text** | Data structures | Plain text | Generate summaries |
| **audio_to_text** | Audio | Transcribed text | Voice message → text |
| **text_to_audio** | Text | Audio | TTS for accessibility |
| **image_to_text** | Image | OCR + description | Receipt scanning |
| **text_to_image** | Text | Generated image | Diagrams from descriptions |
| **format_conversion** | Format A | Format B | Markdown → HTML |
| **custom** | Any | Any | User-defined Wasm blocks |

### Profile-Specific Defaults

| Setting | Potato | Standard | Hyperscale |
|---------|--------|----------|------------|
| **Bridges Enabled** | ❌ No | ✅ Yes | ✅ Yes |
| **Validation Mode** | Strict | Strict | Lenient |
| **Max Content Size** | 5 MB | 10 MB | 50 MB |
| **Sanitization** | Aggressive | Moderate | Moderate |
| **Fuel Budget (default)** | 50K | 100K | 500K |
| **Rate Limit (per user)** | 10/hour | 100/hour | 1000/hour |
| **Min Reputation** | null_sec | null_sec | low_sec |

### Example: Potato (Bridges Disabled)

```toml
[bridges.generic]
enabled = false                    # Disabled for resource-constrained potato
bridge_version = "1.0"

[bridges.generic.ingest]
schema_validation = "strict"
max_content_size_mb = 5
sanitization_mode = "aggressive"

[bridges.generic.block]
fuel_budget_default = 50_000
fuel_budget_max = 500_000

[bridges.generic.limits]
rate_limit_per_user = 10
rate_limit_global = 100
```

### Example: Hyperscale (Full Transforms)

```toml
[bridges.generic]
enabled = true
bridge_version = "1.0"

# Ingest with transform pipeline
[bridges.generic.ingest]
schema_validation = "lenient"
max_content_size_mb = 50
sanitization_mode = "moderate"

# Transform: Audio → Text → Structured Data
[[bridges.generic.ingest.transform_pipeline]]
transform_type = "audio_to_text"
fuel_budget = 200_000
fuel_max = 2_000_000
required_capabilities = ["audio.decode", "ml.stt"]
validate_determinism = true
preserve_provenance = true

[[bridges.generic.ingest.transform_pipeline]]
transform_type = "text_to_structured"
fuel_budget = 100_000
fuel_max = 1_000_000
required_capabilities = ["nlp.parse"]
validate_determinism = true
preserve_provenance = true

# Block layer with capability mapping
[bridges.generic.block]
fuel_budget_default = 500_000
fuel_budget_max = 5_000_000

[bridges.generic.block.capability_mapping]
send_email = ["net.smtp", "net.dns"]
upload_file = ["storage.write", "net.http"]
fetch_url = ["net.http", "net.dns"]

# Export with transform pipeline
[[bridges.generic.export.transform_pipeline]]
transform_type = "structured_to_text"
fuel_budget = 80_000
fuel_max = 800_000
required_capabilities = ["nlp.generate"]

[[bridges.generic.export.transform_pipeline]]
transform_type = "text_to_audio"
fuel_budget = 150_000
fuel_max = 1_500_000
required_capabilities = ["audio.encode", "ml.tts"]

# Rate limiting with reputation gating
[bridges.generic.limits]
rate_limit_per_user = 1000
rate_limit_global = 100_000
min_reputation_tier = "low_sec"
require_verified_for_outbound = true
```

## Export Format Configuration

Jig blocks can be exported to multiple formats for interoperability. **TOML is the source of truth** - all other formats are generated artifacts.

### Supported Formats

| Format | Canonical? | MIME Type | Use Case |
|--------|------------|-----------|----------|
| **JCS** | ✅ Yes | `application/json` | Deterministic, verifiable exports |
| **YAML** | ❌ No | `application/yaml` | Human-readable config |
| **JSON** | ❌ No | `application/json` | API interop (use JCS for canonical) |
| **ActivityPub** | ❌ No | `application/activity+json` | Fediverse integration |
| **ATProto** | ❌ No | `application/json` | Bluesky integration |
| **Text** | ❌ No | `text/plain` | Plain text fallback |
| **HTML** | ❌ No | `text/html` | Web rendering |
| **Markdown** | ❌ No | `text/markdown` | Documentation |

**Key Principle:** Only JCS (JSON Canonicalization Scheme) is canonical. All other formats are for interoperability, not as configuration sources.

### Example: Export Configuration

```toml
# YAML export (interop only, not canonical)
[export.yaml]
enabled = true
canonical_format = false
include_comments = true
include_provenance = true
pretty_print = true

# JSON export (interop only, not canonical)
[export.json]
enabled = true
canonical_format = false
include_provenance = true
pretty_print = true

# JCS export (THE canonical format)
[export.jcs]
enabled = true
canonical_format = true            # Deterministic, verifiable
include_provenance = true
pretty_print = false

# ActivityPub export (optional, for fediverse)
[export.activitypub]
enabled = true
canonical_format = false
include_provenance = true

# AT Protocol export (optional, for Bluesky)
[export.atproto]
enabled = true
canonical_format = false
include_provenance = true
```

### Security Principles

1. **Zero Trust:** Bridges start with zero capabilities, must explicitly grant
2. **Sanitize Aggressively:** All external content validated/sanitized before ingestion
3. **Fail Secure:** Invalid content rejected, not coerced
4. **Audit Everything:** All bridge operations logged for compliance
5. **Reputation Gates:** High-risk operations require verified identity
6. **Fuel Accounting:** All bridge operations and transforms metered
7. **Provenance Always:** Block IDs and signatures preserved across bridges
8. **Privacy First:** PII anonymization enforced for compliant exports

## Bridge-Specific Configuration

In addition to the generic bridge configuration above, jig-config provides explicit configuration for named bridges and template configurations for bridge categories.

### Named Bridges

These bridges have explicit, first-class configuration support:

#### IRC Bridge (Native)

IRC is a native protocol in jig-server (RFC 1459 compliant). Maps IRC commands to Jig blocks.

```toml
[bridges.irc]
enabled = true
server_name = "jig.irc.network"
port = 6667
bind_address = "0.0.0.0"
auto_join_channels = ["#jig", "#jig-dev"]

[bridges.irc.nick_validation]
max_length = 30
require_unique = true

[bridges.irc.block_wrapper]
enabled = true
fuel_budget = 10_000
preserve_metadata = true
```

**Key Features:**
- Native TCP connection (no transforms needed)
- Channels map to Jig channels
- PRIVMSG → JigMessage with routing
- Full RFC 1459 compatibility

#### Email Bridge (Native)

Email bridge provides SMTP/IMAP interfaces for email client compatibility.

```toml
[bridges.email]
enabled = true

[bridges.email.smtp]
enabled = true
port = 25
submission_port = 587
bind_address = "0.0.0.0"
mx_domains = ["jig.example.com"]
starttls = true
require_auth = true

[bridges.email.imap]
enabled = true
port = 143
bind_address = "0.0.0.0"
starttls = true

[bridges.email.relay]
method = { direct = null }  # or { community = null }, { send_grid = {...} }
community_relay = true
donated_quota_bytes = 107374182400  # 100 GB/day
relay_quota_per_day = 10_000
dns_discovery = true
spf_dkim_enforcement = "strict"

[bridges.email.deliverability]
enabled = true
analytics_backend = "clickhouse"
track_opens = false       # Privacy-first
track_bounces = true
track_clicks = false
```

**Key Features:**
- SMTP (receive + send) and IMAP (client access)
- Multiple relay methods: Direct, SendGrid, Community, Custom
- Deliverability tracking and analytics
- SPF/DKIM enforcement levels

#### WebSocket Bridge (Native)

WebSocket bridge provides real-time bidirectional communication for web clients.

```toml
[bridges.websocket]
enabled = true
port = 8080
bind_address = "0.0.0.0"
tls_enabled = true
max_connections = 100_000
ping_interval_sec = 30
compression = true
max_message_size_bytes = 52428800  # 50 MB
```

**Key Features:**
- Real-time connections with compression
- Configurable connection limits and timeouts
- TLS support (WSS)
- Ping/pong keepalive

#### Federation Bridge (Native)

Server-to-server communication for federated Jig instances.

```toml
[bridges.federation]
enabled = true
port = 7117
bind_address = "0.0.0.0"
public_address = "jig.example.com"
require_tls = true

[bridges.federation.discovery]
enabled = true
method = "web_finger"  # or "dns", "manual"
known_endpoints = []

[bridges.federation.identity]
require_proof = true
key_algorithm = "ed25519"
verification_level = "ca_with_transparency"  # or "none", "self_signed", "ca"

[bridges.federation.trust]
default_policy = "allow_all"  # or "block_all", "allow_with_warning"
trusted_servers = []
blocked_servers = []
```

**Key Features:**
- DNS or WebFinger-based discovery
- Cryptographic identity verification (ed25519)
- Flexible trust policies
- TLS-enforced federation traffic

#### ATProto Bridge (External)

Bridge to the AT Protocol (Bluesky) network.

```toml
[bridges.atproto]
enabled = true
pds_endpoint = "https://bsky.social"
server_did = "did:plc:example123"
did_resolution = true
firehose_enabled = true

[[bridges.atproto.ingest_transforms]]
transform_type = { custom = "atproto_to_jig" }
fuel_budget = 200_000
fuel_max = 2_000_000
required_capabilities = ["atproto.read", "net.http"]
validate_determinism = true
preserve_provenance = true

[[bridges.atproto.export_transforms]]
transform_type = { custom = "jig_to_atproto" }
fuel_budget = 200_000
fuel_max = 2_000_000
required_capabilities = ["atproto.write", "net.http"]
validate_determinism = true
preserve_provenance = true
```

**Key Features:**
- PDS (Personal Data Server) integration
- DID (Decentralized Identifier) resolution
- Firehose subscription for real-time updates
- Transform pipelines for ATProto records ↔ Jig blocks

#### ActivityPub Bridge (External)

Bridge to the Fediverse (Mastodon, Pleroma, etc.).

```toml
[bridges.activitypub]
enabled = true
actor_name = "@jig@example.com"
inbox_endpoint = "/inbox"
outbox_endpoint = "/outbox"
webfinger_enabled = true
accept_follows = true

[[bridges.activitypub.ingest_transforms]]
transform_type = { custom = "activitypub_to_jig" }
fuel_budget = 200_000
fuel_max = 2_000_000
required_capabilities = ["activitypub.read", "net.http"]
validate_determinism = true
preserve_provenance = true

[[bridges.activitypub.export_transforms]]
transform_type = { custom = "jig_to_activitypub" }
fuel_budget = 200_000
fuel_max = 2_000_000
required_capabilities = ["activitypub.write", "net.http"]
validate_determinism = true
preserve_provenance = true
```

**Key Features:**
- ActivityPub actor with inbox/outbox
- WebFinger for actor discovery
- Follow/unfollow support
- Transform pipelines for activities ↔ Jig blocks

### Bridge Categories (Templates)

These are shell configurations that provide taxonomy for community-built bridges:

#### Enterprise Messengers

Template for Slack, Mattermost, Microsoft Teams, etc.

```toml
[bridges.enterprise_messengers.slack]
bridge_type = "slack"
api_endpoint = "https://slack.com/api"
auth_token = "xoxb-..."
workspace_id = "T12345"
```

#### Consumer Messengers

Template for Discord, Matrix, Telegram, Signal, etc.

```toml
[bridges.consumer_messengers.discord]
bridge_type = "discord"
[bridges.consumer_messengers.discord.credentials]
token = "discord_bot_token"
```

#### Video Codecs

Template for H.264, VP9, AV1, etc.

```toml
[bridges.video_codecs.h264_to_av1]
source_codec = "h264"
target_codec = "av1"

[bridges.video_codecs.h264_to_av1.quality]
bitrate = 5000000
resolution = "1920x1080"
fps = 60
```

#### Audio Codecs

Template for MP3, Opus, AAC, FLAC, etc.

```toml
[bridges.audio_codecs.mp3_to_opus]
source_codec = "mp3"
target_codec = "opus"

[bridges.audio_codecs.mp3_to_opus.quality]
bitrate = 256000
sample_rate = 48000
channels = 2
```

#### Transport Bridges

Template for HTTPS, SSH, gRPC, etc.

```toml
[bridges.transports.ssh]
transport_type = "ssh"
endpoint = "ssh://example.com:22"
auth_method = { ssh_key = { private_key_path = "/path/to/key" } }
```

#### Document Bridges

Template for PDF, Office docs, Markdown, etc.

```toml
[bridges.documents.pdf]
document_type = "pdf"
ocr_enabled = true
extract_metadata = true
```

### Profile-Specific Bridge Defaults

| Bridge | Potato | Standard | Hyperscale |
|--------|--------|----------|------------|
| **IRC** | ✅ Enabled (localhost) | ✅ Enabled (public) | ✅ Enabled (public) |
| **Email** | ❌ Disabled | ✅ Enabled | ✅ Enabled |
| **WebSocket** | ❌ Disabled | ✅ Enabled (10K conns) | ✅ Enabled (100K conns) |
| **Federation** | ❌ Disabled | ❌ Disabled (opt-in) | ✅ Enabled |
| **ATProto** | ❌ Disabled | ❌ Disabled (opt-in) | ✅ Enabled |
| **ActivityPub** | ❌ Disabled | ❌ Disabled (opt-in) | ✅ Enabled |

**Implementation Notes:**
- Native bridges (IRC, Email, WebSocket, Federation) are implemented in `jig-server`
- External bridges (ATProto, ActivityPub) require community-built bridge implementations
- Category bridges serve as templates for OSS contributors to build against
- All bridges use the generic bridge configuration for fuel, rate limits, and monitoring

## Nameserver & Federation Configuration

Nameserver configuration controls the deterministic reputation, proof-of-work, and federation behavior of jig-nameserver instances. The nameserver enforces network-wide security policies, useful work governance, and adaptive fuel pricing based on reputation.

### Federation Modes

jig-nameserver supports three federation scenarios with different trust boundaries:

| Mode | Trust Level | Use Case | Auto-Trust Siblings |
|------|-------------|----------|---------------------|
| **Federated** | High | Parent org, shared governance | ✅ Yes |
| **SharedRuleset** | Medium | Data contract, network link | ❌ No (verification) |
| **Isolated** | Zero | Intranet, development | ❌ No |

### Key Components

**Proof-of-Work (PoW):**
- Blake3-based Hashcash with adaptive difficulty scaling
- Prevents Sybil attacks and spam
- Difficulty adjusts based on network load and reputation

**Reputation System:**
- PageRank-style scoring across nameserver network
- Translation contracts between different rulesets
- Decay over time to prevent stale reputation

**Tribunal System:**
- Multi-party verification for disputed blocks
- Auto-escalation with quorum requirements
- Fuel budgets for deterministic adjudication

**Anomaly Detection:**
- Non-determinism detection (multiple executions → different results)
- Excessive network calls (bandwidth abuse)
- Fuel anomalies (reported fuel != actual consumption)
- Hard failures (crashes, panics, timeouts)

### Profile-Specific Defaults

| Setting | Potato | Standard | Hyperscale |
|---------|--------|----------|------------|
| **Federation Mode** | Isolated | Isolated (opt-in) | Federated |
| **PoW Difficulty** | 18 bits | 20 bits | 22 bits |
| **Reputation Decay** | 30 days | 90 days | 365 days |
| **Tribunal Size** | 3 nodes | 5 nodes | 7 nodes |
| **Hot-Reload** | Rate limits only | Rate limits + penalties | All non-crypto |

### Example: Federated Mode

```toml
[federation]
mode = "federated"
enabled = true

[federation.parent_org]
org_id = "org_parent_12345"
trust_level = "high"
auto_trust_siblings = true
sync_reputation = true
sync_rulesets = true
mtls_required = true

[nameserver.network]
listen_address = "0.0.0.0:7117"
public_endpoint = "https://nameserver.example.com"
require_tls = true
connection_timeout_ms = 5000

[nameserver.pow]
algorithm = "blake3_hashcash"
difficulty_base = 22
adaptive_scaling = true
verification_mode = "verify_all"

[nameserver.reputation]
algorithm = "pagerank"
decay_halflife_days = 365
min_score_for_high_sec = 0.8
translation_enabled = true

[nameserver.tribunal]
enabled = true
quorum_size = 5
min_reputation_to_serve = 0.7
fuel_budget_per_verification = 500_000
auto_escalation = true

[nameserver.anomaly_detection]
enabled = true
non_determinism_threshold = 0.05
excessive_network_threshold_mb = 50
fuel_deviation_threshold_pct = 20
hard_failure_escalation = true
```

### Example: Isolated Mode (Potato Default)

```toml
[federation]
mode = "isolated"
enabled = false

[nameserver.network]
listen_address = "127.0.0.1:7117"
public_endpoint = "http://localhost:7117"
require_tls = false

[nameserver.pow]
algorithm = "blake3_hashcash"
difficulty_base = 18
adaptive_scaling = false

[nameserver.reputation]
algorithm = "simple_linear"
decay_halflife_days = 30
min_score_for_high_sec = 0.5

[nameserver.tribunal]
enabled = false

[nameserver.anomaly_detection]
enabled = true
non_determinism_threshold = 0.1
excessive_network_threshold_mb = 10
fuel_deviation_threshold_pct = 30
```

### Hot-Reload Boundaries

**Safe to Hot-Reload:**
- Rate limits and penalties
- Useful work discount percentages
- Anomaly detection thresholds
- Reputation decay parameters

**Requires Restart:**
- Network configuration (listen address, port)
- Storage backend changes
- PoW secret key rotation
- Federation mode changes

For complete nameserver integration details, see `NAMESERVER_INTEGRATION.md`.

## Analytics & Telemetry Configuration

Analytics configuration provides profile-specific observability with backends optimized for each scale:

| Profile | Analytics Backend | Telemetry | Sampling Rate |
|---------|-------------------|-----------|---------------|
| **Potato** | DuckDB (embedded) | Prometheus | 10% |
| **Standard** | Parquet (files) | Prometheus + OTLP | 50% |
| **Hyperscale** | ClickHouse (distributed) | Full OpenTelemetry | 100% |

### Privacy Modes

- **Anonymized** (default): PII removed, aggregate metrics only
- **Aggregated**: Summary statistics, no individual traces
- **Full**: Complete data with PII (compliance-gated)

### Example: Hyperscale Analytics

```toml
[analytics]
backend = "clickhouse"
retention_days = 365
sample_rate = 1.0
privacy_mode = "anonymized"

[analytics.clickhouse]
connection_string = "tcp://analytics-cluster:9000/jig_analytics"
batch_size = 10_000
flush_interval_sec = 30
compression = "lz4"
partitioning = "daily"
sharding_key = "tenant_id"

[telemetry]
metrics_enabled = true
metrics_endpoint = "http://prometheus:9090"
metrics_format = "prometheus"
trace_sampling = 1.0
log_level = "info"
structured_logging = true

[telemetry.opentelemetry]
enabled = true
otlp_endpoint = "grpc://otel-collector:4317"
service_name = "jig-server"
trace_exporter = "otlp"
metrics_exporter = "otlp"
logs_exporter = "otlp"
```

## Template Generation & Validation

jig-config v0.2.0 includes a powerful template generator and cross-config validator to help users get started quickly and catch misconfigurations early.

### Template Generator

Generate TOML configuration templates for any profile:

```bash
# Generate minimal potato config
cargo run --example config_generator -- --profile potato

# Generate full standard config with comments
cargo run --example config_generator -- --profile standard --full

# Generate hyperscale config without comments, save to file
cargo run --example config_generator -- --profile hyperscale --full --no-comments > hyperscale.toml

# Include examples
cargo run --example config_generator -- --profile potato --full --examples
```

**CLI Options:**
- `-p, --profile <PROFILE>`: Profile to generate (potato, standard, hyperscale, custom)
- `-f, --full`: Generate full configuration with all sections
- `--no-comments`: Generate without explanatory comments
- `-e, --examples`: Include example values
- `-h, --help`: Print help message

### Configuration Validator

The validator performs cross-config validation with severity levels:

**Severity Levels:**
- **Warning**: Config will work but may not be optimal
- **Error**: Config is invalid and must be fixed
- **Critical**: Config could cause data loss or security issues

**Validation Categories:**

1. **Runtime Constraints**
   - Fuel max must be > 0
   - Memory max must be > 0
   - Timeout must be > 0 and reasonable

2. **Storage Requirements**
   - SQLite requires path field
   - PostgreSQL/CockroachDB requires connection_string
   - Backend-specific field validation

3. **Analytics Bounds**
   - Sample rate must be 0.0-1.0
   - Retention days must be reasonable
   - Backend must be valid

4. **Cross-Config Dependencies**
   - Federation requires encryption (Critical)
   - High-throughput bridges with SQLite (Warning)
   - Hyperscale profile with SQLite storage (Warning)
   - Useful work requires nameserver URL (Error)

5. **Compliance Requirements**
   - HIPAA: 7-year retention, PII anonymization required
   - GDPR: PII anonymization recommended
   - SOC2: 1-year retention minimum

**Example Usage:**

```rust
use jig_config::validation::{ConfigValidator, Severity};

let mut validator = ConfigValidator::new();

// Validate runtime constraints
validator.validate_runtime_constraints(1_000_000, 32, 250);

// Validate storage backend
validator.validate_storage("sqlite", Some("jig.db"), None);

// Validate analytics configuration
validator.validate_analytics("duckdb", 90, 0.1);

// Check cross-config dependencies
validator.validate_federation_requires_encryption(true, false);

// Get validation results
if validator.has_errors() {
    for error in validator.errors_at_least(Severity::Error) {
        eprintln!("{}", error);
    }
}
```

**Example Validation Output:**

```
[CRITICAL] federation: Federation requires encryption to be enabled (security requirement)
[ERROR] storage.path: SQLite backend requires 'path' field
[WARNING] bridges: High-throughput bridges (["websocket"]) with SQLite may cause performance issues
```

## Examples

See `examples/` directory for complete configurations:

- **`potato.toml`**: Minimal single-node setup (default)
- **`hyperscale.toml`**: Multi-tier storage with all features

## Design Principles

Goal
- Define a clear, explicit, and low-nesting TOML configuration for invoking Jig components, with a strong emphasis on runtime selection and safety.

Style guide
- Names: simple, explicit, unambiguous. Prefer `this_name_clearly_says_what_it_does` over single letters.
- Case: use `snake_case` for keys, except special prefixes `dangerously-` and `shamefully-` which intentionally use hyphens for visibility.
- Nesting: minimize. Use top-level tables for major areas (`runtime`, `server`, `user`) and shallow sub-tables only when necessary.
- Similar keys: avoid ambiguous pairs (e.g., `image` vs `target`). Use a single canonical name everywhere (`target`).

Core sections
- `[runtime]`: The one place to choose what to run and how.
- `[server]`: Network-facing server settings (binds, ports, TLS).
- `[user]`: Client identity for tools like `jig-cli`.

Runtime configuration
- Canonical keys (shared):
  - `engine` (string): `wasmtime`, `podman`, `docker`, or `local`.
  - `target` (string): what to run.
    - Wasmtime: path to `.wasm` with `_start`.
    - Podman/Docker: container image reference.
    - Local: path to a local executable (e.g., `jig-server`).
  - `inherit_stdio` (bool): connect workload stdout/stderr to the caller.
  - `args` (array of strings): arguments passed to the workload.
  - `[runtime.env]` (table): key/value environment variables.

- Engine-specific options (namespaced under the engine):
  - `[runtime.wasmtime]`
    - `fuel` (integer, optional): initial fuel budget. Applied only when set.
    - `preopened` (array of tables): host dirs to preopen.
      - `host` (string): host directory path.
      - `guest` (string): guest mount path (e.g., `/data`).
      - `directory_permissions` (string): `read`, `write`, or `readwrite`.
      - `file_permissions` (string): `read`, `write`, or `readwrite`.
  - `[runtime.podman]` (future)
    - `network` (string): `bridge|host|none`.
    - `mounts` (array): `[{ host, container, mode }]` where `mode` is `ro|rw`.
    - `pull_policy` (string): `always|missing|never`.
    - `dangerously-run_as_root` (bool): run as root inside the container (adds `--user 0:0`). Default `false`.
    - `shamefully-disable_userns_remap` (bool): disable user namespace remap (`--userns=host`). Default `false`.
  - `[runtime.docker]` (future)
    - mirror `podman` options where sensible.

Local OS runtime
- `[runtime] engine = "local"`
- `target` should point to a local executable.
- Shares `args`, `env`, `inherit_stdio` with other engines.
- Optional future key: `working_directory`.

Examples
```toml
# jig-config.toml

[runtime]
engine = "wasmtime"
target = "./server.wasm"
inherit_stdio = true
args = ["--port", "8080"]

[runtime.env]
RUST_LOG = "info"

[runtime.wasmtime]
fuel = 1000000

[[runtime.wasmtime.preopened]]
host = "/var/jig/data"
guest = "/data"
directory_permissions = "readwrite"
file_permissions = "readwrite"
```

CLI mapping (consistent across engines)
- `--runtime` → `[runtime].engine`
- `--runtime-target` → `[runtime].target`
- `--runtime-env KEY=VALUE` → `[runtime.env]`
- `--runtime-arg <arg>` → `[runtime].args` (append)

Safety prefixes
- `dangerously-...`: options that expose elevated risk the user may not recognize.
- `shamefully-...`: options that knowingly enable an anti-pattern.
- Use sparingly and only when the names materially communicate risk.

Changelog & ownership
- As engine crates land (`jig-podman`, `jig-docker`), extend this doc with their exact keys.
- Keep names aligned with `jig-runtime` semantics to guarantee hot-swap.
