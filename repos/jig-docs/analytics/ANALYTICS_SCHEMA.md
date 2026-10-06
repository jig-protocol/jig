# Analytics Schema Reference

**Version:** 1.0.0
**Status:** Production-ready
**Applies to:** Receipt v0.2
**Backends:** ClickHouse (hyperscale), DuckDB/Parquet (potato/standard)

---

## Overview

This document defines the analytics schema for storing and querying execution receipts, enabling outcome-based pricing, performance monitoring, and compliance reporting.

### Design Principles

1. **Profile-Driven Backend Selection:**
   - **Potato:** DuckDB (embedded analytics)
   - **Standard:** Parquet files (local file system)
   - **Hyperscale:** ClickHouse (distributed OLAP)

2. **Receipt Fidelity:** All v0.2 receipt fields preserved in analytics layer

3. **Query Performance:** Optimized for common queries (execution cost, capability usage, outcome trends)

4. **Privacy-Preserving:** PII anonymized, signatures optional per profile

---

## Table Schemas

### 1. `receipts` Table

**Purpose:** One row per block execution, capturing all receipt v0.2 fields.

#### ClickHouse DDL

```sql
CREATE TABLE receipts (
  -- Core Identity
  block_id         String,
  host_did         String,
  executed_at      DateTime64(3, 'UTC'),

  -- Render Output
  render_hash      String,
  renders_match    UInt8,  -- Boolean: 0=false, 1=true, NULL if not provided

  -- Resource Usage
  fuel_used        UInt64,
  memory_peak_mb   UInt32,

  -- v0.2 Counters
  counters_fuel_total       UInt64,
  counters_bytes_tx         UInt64,
  counters_bytes_rx         UInt64,
  counters_syscalls         UInt64,

  -- v0.2 Timings (milliseconds)
  timings_queue_wait_ms     UInt32,
  timings_init_ms           UInt32,
  timings_exec_ms           UInt32,
  timings_total_ms          UInt32,

  -- v0.2 Limits (snapshot at execution time)
  limit_fuel_max            UInt64,
  limit_memory_max_mb       UInt32,
  limit_exec_timeout_ms     UInt32,

  -- v0.2 Outcome
  outcome_status    LowCardinality(String),   -- ok | soft_fail | hard_fail
  outcome_reason    LowCardinality(Nullable(String)),  -- ReasonCode if failure
  outcome_affordances Array(String),          -- Success signals

  -- Capabilities
  capabilities_used Array(LowCardinality(String)),
  attestations      Array(String),

  -- Signature (optional for privacy)
  signature         Nullable(String),

  -- Metadata (JSON blob for extensibility)
  metadata          String  -- Stored as JSON string, use JSONExtract* functions
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(executed_at)
ORDER BY (executed_at, block_id)
SETTINGS index_granularity = 8192;
```

#### DuckDB/Parquet Schema

DuckDB schema mirrors ClickHouse structure:

```sql
CREATE TABLE receipts (
  -- Core Identity
  block_id         VARCHAR,
  host_did         VARCHAR,
  executed_at      TIMESTAMP,

  -- Render Output
  render_hash      VARCHAR,
  renders_match    BOOLEAN,

  -- Resource Usage
  fuel_used        BIGINT,
  memory_peak_mb   INTEGER,

  -- v0.2 Counters
  counters_fuel_total       BIGINT,
  counters_bytes_tx         BIGINT,
  counters_bytes_rx         BIGINT,
  counters_syscalls         BIGINT,

  -- v0.2 Timings
  timings_queue_wait_ms     INTEGER,
  timings_init_ms           INTEGER,
  timings_exec_ms           INTEGER,
  timings_total_ms          INTEGER,

  -- v0.2 Limits
  limit_fuel_max            BIGINT,
  limit_memory_max_mb       INTEGER,
  limit_exec_timeout_ms     INTEGER,

  -- v0.2 Outcome
  outcome_status    VARCHAR,
  outcome_reason    VARCHAR,
  outcome_affordances VARCHAR[],  -- Array of strings

  -- Capabilities
  capabilities_used VARCHAR[],
  attestations      VARCHAR[],

  -- Signature
  signature         VARCHAR,

  -- Metadata
  metadata          JSON
);
```

**Parquet Configuration:**
```toml
[storage.intelligence.parquet]
compression = "snappy"
row_group_size = 50000
schema_version = "1.0.0"
```

#### Field Descriptions

| Field | Type | Description | Nullable |
|-------|------|-------------|----------|
| `block_id` | String | Content-addressed block identifier (CID) | No |
| `host_did` | String | DID of executing host | No |
| `executed_at` | DateTime | UTC timestamp of execution start | No |
| `render_hash` | String | Hash of deterministic render output | No |
| `renders_match` | Bool | Whether render matched expected hash | Yes |
| `fuel_used` | UInt64 | Total fuel consumed | No |
| `memory_peak_mb` | UInt32 | Peak memory usage in MB | Yes |
| `counters_fuel_total` | UInt64 | Total fuel (must equal fuel_used) | Yes |
| `counters_bytes_tx` | UInt64 | Network bytes transmitted | Yes |
| `counters_bytes_rx` | UInt64 | Network bytes received | Yes |
| `counters_syscalls` | UInt64 | System calls made (0 unless WASI) | Yes |
| `timings_queue_wait_ms` | UInt32 | Milliseconds waiting in queue | Yes |
| `timings_init_ms` | UInt32 | Milliseconds in initialization | Yes |
| `timings_exec_ms` | UInt32 | Milliseconds in execution | Yes |
| `timings_total_ms` | UInt32 | Total time (init + exec) | Yes |
| `limit_fuel_max` | UInt64 | Maximum fuel budget | Yes |
| `limit_memory_max_mb` | UInt32 | Maximum memory limit | Yes |
| `limit_exec_timeout_ms` | UInt32 | Maximum execution time | Yes |
| `outcome_status` | String | ok \| soft_fail \| hard_fail | Yes |
| `outcome_reason` | String | ReasonCode if failure | Yes |
| `outcome_affordances` | Array | Success signals | Yes |
| `capabilities_used` | Array | Capabilities invoked | No |
| `attestations` | Array | Useful-work attestations | No |
| `signature` | String | Host signature (ed25519) | Yes |
| `metadata` | JSON | Extensible metadata | No |

---

### 2. `receipt_capability_counters` Table

**Purpose:** Per-capability fuel attribution for granular pricing.

#### ClickHouse DDL

```sql
CREATE TABLE receipt_capability_counters (
  block_id       String,
  executed_at    DateTime64(3, 'UTC'),
  capability     LowCardinality(String),  -- Canonicalized capability key
  fuel_used      UInt64,
  status_counts  Map(String, UInt64)      -- Status bins: {OK: 1, FAIL: 0}
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(executed_at)
ORDER BY (executed_at, block_id, capability)
SETTINGS index_granularity = 8192;
```

#### DuckDB/Parquet Schema

```sql
CREATE TABLE receipt_capability_counters (
  block_id       VARCHAR,
  executed_at    TIMESTAMP,
  capability     VARCHAR,
  fuel_used      BIGINT,
  status_counts  JSON  -- Stored as JSON map: {"OK": 1, "FAIL": 0}
);
```

#### Example Rows

```sql
-- ClickHouse
INSERT INTO receipt_capability_counters VALUES
  ('cid:bafyBlock123', '2025-11-09 12:34:56.789', 'net:http:fetch|https://api.example.com/*', 310000, {'OK': 1}),
  ('cid:bafyBlock123', '2025-11-09 12:34:56.789', 'crypto:sign', 60000, {'OK': 1}),
  ('cid:bafyBlock123', '2025-11-09 12:34:56.789', 'core:compute', 51337, {'OK': 1});
```

---

### 3. `blocks` Table (Optional)

**Purpose:** Lightweight mirror of block metadata for JOIN queries with receipts.

#### ClickHouse DDL

```sql
CREATE TABLE blocks (
  block_id              String,
  author_did            String,
  reputation_tier       LowCardinality(String),  -- null_sec | low_sec | high_sec | verified
  manifest_version      LowCardinality(String),  -- Semver (e.g., "0.1.0")
  render_expected_hash  String,
  created_at            DateTime64(3, 'UTC'),
  capabilities_requested Array(String)
)
ENGINE = ReplacingMergeTree
ORDER BY (created_at, block_id)
SETTINGS index_granularity = 8192;
```

**Note:** `ReplacingMergeTree` allows updates if block metadata changes (e.g., reputation tier upgrade).

#### DuckDB/Parquet Schema

```sql
CREATE TABLE blocks (
  block_id              VARCHAR,
  author_did            VARCHAR,
  reputation_tier       VARCHAR,
  manifest_version      VARCHAR,
  render_expected_hash  VARCHAR,
  created_at            TIMESTAMP,
  capabilities_requested VARCHAR[]
);
```

---

## Common Queries

### 1. Total Fuel Usage by Capability (Last 7 Days)

**ClickHouse:**
```sql
SELECT
  capability,
  SUM(fuel_used) AS total_fuel,
  COUNT(*) AS execution_count
FROM receipt_capability_counters
WHERE executed_at >= now() - INTERVAL 7 DAY
GROUP BY capability
ORDER BY total_fuel DESC
LIMIT 10;
```

**DuckDB:**
```sql
SELECT
  capability,
  SUM(fuel_used) AS total_fuel,
  COUNT(*) AS execution_count
FROM receipt_capability_counters
WHERE executed_at >= NOW() - INTERVAL 7 DAY
GROUP BY capability
ORDER BY total_fuel DESC
LIMIT 10;
```

---

### 2. Outcome Distribution (Success vs Failures)

**ClickHouse:**
```sql
SELECT
  outcome_status,
  COUNT(*) AS count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS percentage
FROM receipts
WHERE executed_at >= now() - INTERVAL 24 HOUR
GROUP BY outcome_status;
```

**DuckDB:**
```sql
SELECT
  outcome_status,
  COUNT(*) AS count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS percentage
FROM receipts
WHERE executed_at >= NOW() - INTERVAL 24 HOUR
GROUP BY outcome_status;
```

---

### 3. Average Execution Time by Outcome Status

**ClickHouse:**
```sql
SELECT
  outcome_status,
  AVG(timings_exec_ms) AS avg_exec_ms,
  quantile(0.5)(timings_exec_ms) AS median_exec_ms,
  quantile(0.95)(timings_exec_ms) AS p95_exec_ms,
  quantile(0.99)(timings_exec_ms) AS p99_exec_ms
FROM receipts
WHERE executed_at >= now() - INTERVAL 7 DAY
  AND timings_exec_ms IS NOT NULL
GROUP BY outcome_status;
```

**DuckDB:**
```sql
SELECT
  outcome_status,
  AVG(timings_exec_ms) AS avg_exec_ms,
  quantile_cont(timings_exec_ms, 0.5) AS median_exec_ms,
  quantile_cont(timings_exec_ms, 0.95) AS p95_exec_ms,
  quantile_cont(timings_exec_ms, 0.99) AS p99_exec_ms
FROM receipts
WHERE executed_at >= NOW() - INTERVAL 7 DAY
  AND timings_exec_ms IS NOT NULL
GROUP BY outcome_status;
```

---

### 4. Affordance Success Rate

**ClickHouse:**
```sql
SELECT
  arrayJoin(outcome_affordances) AS affordance,
  COUNT(*) AS success_count,
  AVG(fuel_used) AS avg_fuel
FROM receipts
WHERE outcome_status = 'ok'
  AND executed_at >= now() - INTERVAL 30 DAY
GROUP BY affordance
ORDER BY success_count DESC;
```

**DuckDB:**
```sql
SELECT
  UNNEST(outcome_affordances) AS affordance,
  COUNT(*) AS success_count,
  AVG(fuel_used) AS avg_fuel
FROM receipts
WHERE outcome_status = 'ok'
  AND executed_at >= NOW() - INTERVAL 30 DAY
GROUP BY affordance
ORDER BY success_count DESC;
```

---

### 5. Pricing Calculation Query

**ClickHouse:**
```sql
SELECT
  r.block_id,
  r.executed_at,
  r.outcome_status,
  SUM(
    CASE
      WHEN c.capability LIKE 'net:%' THEN c.fuel_used * 0.0001 / 1000000  -- $0.0001 per 1M fuel
      WHEN c.capability LIKE 'crypto:%' THEN c.fuel_used * 0.00005 / 1000000
      ELSE c.fuel_used * 0.001 / 1000000  -- Default: $0.001 per 1M fuel
    END
  ) AS total_cost_usd
FROM receipts r
JOIN receipt_capability_counters c ON r.block_id = c.block_id
WHERE r.executed_at >= now() - INTERVAL 1 DAY
  AND r.outcome_status = 'ok'  -- Only charge successful executions
GROUP BY r.block_id, r.executed_at, r.outcome_status
ORDER BY total_cost_usd DESC
LIMIT 100;
```

**DuckDB:**
```sql
SELECT
  r.block_id,
  r.executed_at,
  r.outcome_status,
  SUM(
    CASE
      WHEN c.capability LIKE 'net:%' THEN c.fuel_used * 0.0001 / 1000000
      WHEN c.capability LIKE 'crypto:%' THEN c.fuel_used * 0.00005 / 1000000
      ELSE c.fuel_used * 0.001 / 1000000
    END
  ) AS total_cost_usd
FROM receipts r
JOIN receipt_capability_counters c ON r.block_id = c.block_id
WHERE r.executed_at >= NOW() - INTERVAL 1 DAY
  AND r.outcome_status = 'ok'
GROUP BY r.block_id, r.executed_at, r.outcome_status
ORDER BY total_cost_usd DESC
LIMIT 100;
```

---

## Profile-Specific Recommendations

### Potato Profile (DuckDB)

**Storage:**
- Local DuckDB file: `~/.jig/analytics.duckdb`
- Automatic schema creation on first write
- Max retention: 30 days (auto-cleanup)

**Performance:**
- Keep database < 1 GB for fast queries
- Use `PRAGMA memory_limit='512MB'` for constrained environments
- Disable full-text search to save space

**Example Configuration:**
```toml
[storage.intelligence]
backend = "duckdb"
path = "~/.jig/analytics.duckdb"
batch_size = 1000
retention_days = 30
```

---

### Standard Profile (Parquet)

**Storage:**
- Partitioned Parquet files: `~/.jig/parquet/receipts/YYYY-MM-DD/*.parquet`
- Daily partitions for efficient querying
- Max retention: 90 days

**Performance:**
- Use columnar compression (snappy)
- Row group size: 50,000 rows
- Query with DuckDB for analysis

**Example Configuration:**
```toml
[storage.intelligence]
backend = "parquet"
path = "~/.jig/parquet/"
compression = "snappy"
partition_by = "daily"
retention_days = 90
```

**Query Parquet with DuckDB:**
```sql
-- Load all receipts from last 7 days
SELECT * FROM read_parquet('~/.jig/parquet/receipts/2025-11-*/*.parquet')
WHERE executed_at >= NOW() - INTERVAL 7 DAY;
```

---

### Hyperscale Profile (ClickHouse)

**Storage:**
- Distributed ClickHouse cluster
- MergeTree engine with daily partitions
- Retention: 365 days (compliance)

**Performance:**
- Use `LowCardinality` for categorical fields
- Partition by day (`toYYYYMMDD(executed_at)`)
- Index on `(executed_at, block_id)` for fast lookups
- Enable TTL for automatic expiration

**Example Configuration:**
```toml
[storage.intelligence]
backend = "clickhouse"
connection_string = "tcp://analytics-cluster:9000/jig_analytics"
batch_size = 10_000
flush_interval_sec = 30
compression = "lz4"
retention_days = 365
```

**TTL Configuration (Auto-Expiry):**
```sql
ALTER TABLE receipts
  MODIFY TTL executed_at + INTERVAL 365 DAY;

ALTER TABLE receipt_capability_counters
  MODIFY TTL executed_at + INTERVAL 365 DAY;
```

---

## Migration Guide

### Potato → Standard (DuckDB → Parquet)

```bash
# Export from DuckDB
duckdb ~/.jig/analytics.duckdb "COPY receipts TO '~/.jig/export/receipts.parquet' (FORMAT PARQUET, COMPRESSION SNAPPY)"

# Import to Parquet (DuckDB can read/write Parquet)
mkdir -p ~/.jig/parquet/receipts/$(date +%Y-%m-%d)
mv ~/.jig/export/receipts.parquet ~/.jig/parquet/receipts/$(date +%Y-%m-%d)/
```

### Standard → Hyperscale (Parquet → ClickHouse)

```sql
-- ClickHouse can directly ingest Parquet files
INSERT INTO receipts
  SELECT * FROM file('~/.jig/parquet/receipts/**/*.parquet', Parquet);

INSERT INTO receipt_capability_counters
  SELECT * FROM file('~/.jig/parquet/receipt_capability_counters/**/*.parquet', Parquet);
```

---

## Compliance & Privacy

### PII Anonymization

**Fields Containing Potential PII:**
- `metadata` - May contain user-specific data
- `signature` - Links to host identity

**Anonymization Strategy:**
```sql
-- ClickHouse: Strip signatures for privacy-preserving mirrors
SELECT
  block_id,
  host_did,
  executed_at,
  fuel_used,
  outcome_status,
  NULL AS signature,  -- Anonymize
  '{}' AS metadata    -- Anonymize
FROM receipts;
```

### Audit Retention

**SOC2 Compliance:** 365 days minimum
**HIPAA Compliance:** 2,555 days (7 years)
**GDPR Compliance:** 730 days (2 years)

Set retention via profile configuration or ClickHouse TTL.

---

## Troubleshooting

### ClickHouse Performance Issues

**Symptom:** Slow queries on large datasets

**Solutions:**
1. Ensure partitions are working: `SELECT partition, count() FROM system.parts WHERE table = 'receipts' GROUP BY partition`
2. Check index usage: `EXPLAIN SELECT ... FROM receipts WHERE executed_at >= ...`
3. Add materialized views for common aggregations
4. Enable `allow_experimental_lightweight_delete` for faster cleanups

### DuckDB Out of Memory

**Symptom:** `Out of memory` errors during queries

**Solutions:**
1. Reduce memory limit: `PRAGMA memory_limit='256MB'`
2. Enable disk-based execution: `PRAGMA temp_directory='/tmp/duckdb'`
3. Query smaller date ranges
4. Archive old data to Parquet and delete from DuckDB

---

## Next Steps

- **Dashboards:** Build Grafana dashboards using ClickHouse data source
- **Alerting:** Configure alerts for outcome failure spikes
- **Cost Reports:** Generate monthly billing reports from pricing queries
- **Compliance:** Export audit logs for SOC2/HIPAA reviews

---

**See Also:**
- `jig-spec/src/receipts.md` - Receipt v0.2 schema specification
- `jig-config/README.md` - Analytics backend configuration
