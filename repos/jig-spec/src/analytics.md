# Analytics

**Audience:** This chapter is primarily for **server operators** (setting up analytics backends), **developers building analytics tools**, and **compliance teams** (understanding retention and privacy). **End users** don't need to read this unless they're curious how servers track performance and costs.

---

Analytics in Jig means storing execution receipts in a queryable database so you can answer questions like "How much did I spend on network calls this month?" or "What's the p95 latency for block executions?" Unlike traditional logging (just text files), Jig's analytics is structured, profile-driven, and privacy-preserving.

## Why Analytics?

Here's what you can do with receipt analytics:

**1. Outcome-based billing:**
Query fuel usage by capability, outcome status, and affordances to generate itemized bills.

**2. Performance monitoring:**
Track p50/p95/p99 execution times, identify slow blocks, detect anomalies.

**3. Compliance reporting:**
Export audit logs for SOC2/HIPAA/GDPR reviews (with retention policies enforced automatically).

**4. Capacity planning:**
See which capabilities are hitting quotas, predict when you'll need to scale storage/compute.

**Real-world example:**

Alice runs a server with 1000 users. She wants to know:

- Which blocks are burning the most fuel? (Query: top 10 blocks by `fuel_used`)
- Are users hitting timeouts? (Query: `outcome_status = 'hard_fail'` AND `outcome_reason = 'RUNTIME_TIMEOUT'`)
- How much should she charge Bob this month? (Query: SUM fuel costs grouped by `host_did`)

With analytics, Alice runs SQL queries against receipt data and gets answers in seconds.

**Trade-offs:**

- **Storage cost**: Receipts pile up (1M executions = ~500MB compressed). You need to configure retention policies.
- **Privacy risk**: Receipts contain metadata (who executed what, when). Anonymize before sharing.
- **Query complexity**: If you've never used SQL, the learning curve is steep. But there are tools (Grafana, Metabase) to build dashboards without writing SQL.

**For server operators:** Pick an analytics backend based on your deployment profile (potato = SQLite, standard = DuckDB and/or Parquet, hyperscale = ClickHouse).

**For developers:** Query receipts to build dashboards, alerting systems, or billing integrations.

## Design Principles

### 1. Profile-Driven Backend Selection

Jig's configuration profiles automatically choose the right analytics backend:

| Profile        | Backend                           | Use Case                              | Storage Limit                 |
| -------------- | --------------------------------- | ------------------------------------- | ----------------------------- |
| **Potato**     | SQLite                            | Single server, <100 users             | ~1 GB (30-day retention)      |
| **Standard**   | DuckDB (embedded) + Parquet files | Small community, 1K–10K users         | ~10 GB (90-day retention)     |
| **Hyperscale** | ClickHouse (distributed)          | Large federated networks, 100K+ users | Unlimited (365-day retention) |

**Why different backends?**

- **SQLite**: The database everybody already has. Simple to set up, no separate server needed. Perfect for potatoes (Raspberry Pi, VPS).
- **DuckDB**: Zero-config embedded analytics. Utility over basic SQLite while still being cheap and easy to run. Perfect for small communities (1K–10K users).
- **Parquet**: Columnar file format. Query with DuckDB, but files live on disk (cheap storage, good compression).
- **ClickHouse**: Distributed OLAP database. Handles billions of rows, sub-second queries, but requires dedicated infrastructure.

**For server operators:** Your backend is chosen automatically based on the `profile` setting in `jig-config.toml`. You can override it if needed.

### 2. Receipt Fidelity

All v0.2 receipt fields are preserved in the analytics layer. No information is lost—you can reconstruct the exact receipt from analytics data.

### 3. Query Performance

The schema is optimized for common queries:

- **Fuel usage by capability** (grouping by `capability`)
- **Execution costs** (joining receipts with capability counters)
- **Outcome trends** (filtering by `outcome_status` and time range)

### 4. Privacy-Preserving

**PII anonymization:**

- `signature` field is optional (omit it for privacy-preserving mirrors).
- `metadata` is stored as JSON blob (strip PII before inserting).
- No user email addresses or names are stored (only DIDs, which are pseudonymous).

**For compliance teams:** Configure retention policies to meet SOC2 (365 days), HIPAA (7 years), or GDPR (2 years) requirements.

## Table Schemas

The analytics layer has three tables:

### 1. `receipts` Table

**Purpose:** One row per block execution. Stores all receipt v0.2 fields.

**ClickHouse DDL:**

```sql
CREATE TABLE receipts (
  -- Core Identity
  block_id         String,
  host_did         String,
  executed_at      DateTime64(3, 'UTC'),

  -- Render Output
  render_hash      String,
  renders_match    UInt8,  -- 0=false, 1=true, NULL if not provided

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
  metadata          String  -- Stored as JSON, use JSONExtract* functions
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(executed_at)
ORDER BY (executed_at, block_id)
SETTINGS index_granularity = 8192;
```

**DuckDB/Parquet Schema:**

DuckDB mirrors the ClickHouse structure with minor type differences:

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
  outcome_affordances VARCHAR[],

  -- Capabilities
  capabilities_used VARCHAR[],
  attestations      VARCHAR[],

  -- Signature
  signature         VARCHAR,

  -- Metadata
  metadata          JSON
);
```

**Key fields:**

- **`executed_at`**: UTC timestamp. Used for partitioning (daily) and retention policies.
- **`fuel_used`**: Total CPU fuel consumed. Billing queries group by this.
- **`outcome_status`**: `ok`, `soft_fail`, or `hard_fail`. Filter by this to see success rates.
- **`outcome_affordances`**: Array of success signals (e.g., `["email.delivered"]`). Premium pricing queries filter by affordances.
- **`capabilities_used`**: Which capabilities were invoked. Join with `receipt_capability_counters` for per-capability costs.

**For developers:** When inserting receipts, flatten the v0.2 nested structure:

```json
// Receipt v0.2 (nested)
{
  "counters": {
    "fuel_total": 421337,
    "bytes_tx": 20480
  }
}

// Analytics row (flattened)
{
  "counters_fuel_total": 421337,
  "counters_bytes_tx": 20480
}
```

### 2. `receipt_capability_counters` Table

**Purpose:** Per-capability fuel attribution. Enables granular pricing (charge different rates for CPU, network, crypto).

**ClickHouse DDL:**

```sql
CREATE TABLE receipt_capability_counters (
  block_id       String,
  executed_at    DateTime64(3, 'UTC'),
  capability     LowCardinality(String),  -- Canonicalized (e.g., "net:http:fetch|https://api.example.com/*")
  fuel_used      UInt64,
  status_counts  Map(String, UInt64)      -- {"OK": 1, "FAIL": 0}
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(executed_at)
ORDER BY (executed_at, block_id, capability)
SETTINGS index_granularity = 8192;
```

**DuckDB/Parquet Schema:**

```sql
CREATE TABLE receipt_capability_counters (
  block_id       VARCHAR,
  executed_at    TIMESTAMP,
  capability     VARCHAR,
  fuel_used      BIGINT,
  status_counts  JSON  -- {"OK": 1, "FAIL": 0}
);
```

**Example rows:**

```sql
-- ClickHouse
INSERT INTO receipt_capability_counters VALUES
  ('cid:bafyBlock123', '2025-11-09 12:34:56.789', 'net:http:fetch|https://api.example.com/*', 310000, {'OK': 1}),
  ('cid:bafyBlock123', '2025-11-09 12:34:56.789', 'crypto:sign', 60000, {'OK': 1}),
  ('cid:bafyBlock123', '2025-11-09 12:34:56.789', 'core:compute', 51337, {'OK': 1});
```

**Why a separate table?**

Each block execution uses multiple capabilities. If we stored this in the `receipts` table as a JSON blob, querying "total fuel for network calls" would require parsing JSON (slow). Separate table = fast GROUP BY queries.

**For developers:** Populate this table by parsing `receipt.counters.fuel_by_capability` and creating one row per capability.

### 3. `blocks` Table (Optional)

**Purpose:** Lightweight mirror of block metadata. Enables JOIN queries like "show all receipts for blocks authored by high-sec users."

**ClickHouse DDL:**

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

**Note:** `ReplacingMergeTree` allows updates (e.g., if author's reputation tier changes, update their blocks).

**DuckDB/Parquet Schema:**

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

**For server operators:** Populating this table is optional. If you don't need author reputation analytics, skip it (saves storage).

## Common Queries

Here are SQL queries for typical analytics tasks:

### 1. Total Fuel Usage by Capability (Last 7 Days)

**Question:** Which capabilities are burning the most CPU?

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

**Result:**

```
capability                                  | total_fuel | execution_count
--------------------------------------------|------------|----------------
net:http:fetch|https://api.example.com/*   | 15000000   | 50
crypto:sign                                 | 3000000    | 100
core:compute                                | 2500000    | 200
```

### 2. Outcome Distribution (Success vs Failures)

**Question:** What percentage of executions succeed?

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

**Result:**

```
outcome_status | count | percentage
---------------|-------|------------
ok             | 9850  | 98.50
soft_fail      | 100   | 1.00
hard_fail      | 50    | 0.50
```

### 3. Average Execution Time by Outcome Status

**Question:** Do failures take longer than successes?

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

**Result:**

```
outcome_status | avg_exec_ms | median_exec_ms | p95_exec_ms | p99_exec_ms
---------------|-------------|----------------|-------------|-------------
ok             | 50          | 40             | 120         | 200
soft_fail      | 150         | 100            | 250         | 300
hard_fail      | 10          | 5              | 50          | 100
```

**Insight:** Soft fails take longer (network timeouts). Hard fails are fast (they crash early).

### 4. Affordance Success Rate

**Question:** How often does "email.delivered" succeed?

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

**Result:**

```
affordance           | success_count | avg_fuel
---------------------|---------------|----------
email.delivered      | 5000          | 450000
bridge.forwarded     | 3000          | 300000
net.http_2xx         | 2000          | 250000
```

### 5. Pricing Calculation Query

**Question:** How much should I charge users for successful executions?

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

**Result:**

```
block_id           | executed_at              | outcome_status | total_cost_usd
-------------------|--------------------------|----------------|----------------
cid:bafyBlock123   | 2025-11-09 12:34:56.789 | ok             | 0.000456
cid:bafyBlock456   | 2025-11-09 13:00:00.123 | ok             | 0.000234
```

**For developers:** Adjust the pricing rates in the CASE statement to match your server's pricing policy.

## Profile-Specific Recommendations

### Potato Profile (DuckDB)

**Storage:**

- Local DuckDB file: `~/.jig/analytics.duckdb`
- Automatic schema creation on first write
- Max retention: 30 days (auto-cleanup)

**Performance:**

- Keep database < 1 GB for fast queries
- Use `PRAGMA memory_limit='512MB'` for Raspberry Pi / low-RAM VPS
- Disable full-text search to save space

**Example Configuration:**

```toml
[storage.intelligence]
backend = "duckdb"
path = "~/.jig/analytics.duckdb"
batch_size = 1000
retention_days = 30
```

**For potato operators:** DuckDB is perfect for single-server deployments. Zero config, just works.

### Standard Profile (Parquet)

**Storage:**

- Partitioned Parquet files: `~/.jig/parquet/receipts/YYYY-MM-DD/*.parquet`
- Daily partitions for efficient querying
- Max retention: 90 days

**Performance:**

- Columnar compression (snappy) saves 80% storage vs raw JSON
- Row group size: 50,000 rows (balances compression vs query speed)
- Query with DuckDB for analysis (DuckDB can read Parquet natively)

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

**For standard operators:** Parquet is great for communities (1K–10K users). Cheap storage, fast queries, no database server needed.

### Hyperscale Profile (ClickHouse)

**Storage:**

- Distributed ClickHouse cluster
- MergeTree engine with daily partitions
- Retention: 365 days (compliance)

**Performance:**

- `LowCardinality` for categorical fields (saves memory)
- Partition by day: `toYYYYMMDD(executed_at)` (prunes old partitions fast)
- Index on `(executed_at, block_id)` (fast lookups)
- Enable TTL for automatic expiration (no manual cleanup)

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

**For hyperscale operators:** ClickHouse handles billions of rows. Sub-second queries on 100TB datasets. But requires dedicated infrastructure (3+ nodes for high availability).

## Migration Between Profiles

### Potato → Standard (DuckDB → Parquet)

```bash
# Export from DuckDB
duckdb ~/.jig/analytics.duckdb "COPY receipts TO '~/.jig/export/receipts.parquet' (FORMAT PARQUET, COMPRESSION SNAPPY)"

# Import to Parquet
mkdir -p ~/.jig/parquet/receipts/$(date +%Y-%m-%d)
mv ~/.jig/export/receipts.parquet ~/.jig/parquet/receipts/$(date +%Y-%m-%d)/
```

**Why migrate?**

Your community grew. DuckDB file hit 1GB. Queries are slow. Move to Parquet for better compression and partitioning.

### Standard → Hyperscale (Parquet → ClickHouse)

```sql
-- ClickHouse can directly ingest Parquet files
INSERT INTO receipts
  SELECT * FROM file('~/.jig/parquet/receipts/**/*.parquet', Parquet);

INSERT INTO receipt_capability_counters
  SELECT * FROM file('~/.jig/parquet/receipt_capability_counters/**/*.parquet', Parquet);
```

**Why migrate?**

Federated network with 100K+ users. Need distributed queries across multiple servers. ClickHouse scales horizontally.

## Compliance & Privacy

### PII Anonymization

**Fields Containing Potential PII:**

- `metadata` - May contain user-specific data (custom tags, session IDs)
- `signature` - Links to host identity (host DID)

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

**For compliance teams:** If you share analytics data with third parties (research, benchmarks), anonymize first.

### Audit Retention

**SOC2 Compliance:** 365 days minimum
**HIPAA Compliance:** 2,555 days (7 years)
**GDPR Compliance:** 730 days (2 years)

Set retention via profile configuration or ClickHouse TTL.

**For server operators:** Configure `retention_days` in `jig-config.toml` based on your compliance requirements.

## Troubleshooting

### ClickHouse Performance Issues

**Symptom:** Slow queries on large datasets (> 10 seconds for simple GROUP BY).

**Solutions:**

1. **Check partitions are working:**

```sql
SELECT partition, count()
FROM system.parts
WHERE table = 'receipts'
GROUP BY partition;
```

If all rows are in one partition, partitioning failed (check `toYYYYMMDD(executed_at)` syntax).

2. **Verify index usage:**

```sql
EXPLAIN SELECT ... FROM receipts WHERE executed_at >= ...
```

If index isn't used, add it: `ALTER TABLE receipts ADD INDEX idx_time (executed_at) TYPE minmax;`

3. **Add materialized views for common aggregations:**

```sql
CREATE MATERIALIZED VIEW daily_fuel_summary
ENGINE = SummingMergeTree()
ORDER BY (executed_date, capability)
AS SELECT
  toDate(executed_at) AS executed_date,
  capability,
  SUM(fuel_used) AS total_fuel
FROM receipt_capability_counters
GROUP BY executed_date, capability;
```

Query the materialized view instead of raw table (100× faster).

4. **Enable lightweight deletes:**

```sql
SET allow_experimental_lightweight_delete = 1;
DELETE FROM receipts WHERE executed_at < now() - INTERVAL 365 DAY;
```

### DuckDB Out of Memory

**Symptom:** `Out of memory` errors during queries.

**Solutions:**

1. **Reduce memory limit:**

```sql
PRAGMA memory_limit='256MB';
```

2. **Enable disk-based execution:**

```sql
PRAGMA temp_directory='/tmp/duckdb';
```

DuckDB spills to disk when RAM is full.

3. **Query smaller date ranges:**

```sql
-- Instead of:
SELECT * FROM receipts WHERE executed_at >= NOW() - INTERVAL 90 DAY;

-- Do:
SELECT * FROM receipts WHERE executed_at >= NOW() - INTERVAL 7 DAY;
```

4. **Archive old data to Parquet:**

```sql
COPY (SELECT * FROM receipts WHERE executed_at < NOW() - INTERVAL 30 DAY)
TO '~/.jig/archive/receipts-2025-10.parquet' (FORMAT PARQUET);

DELETE FROM receipts WHERE executed_at < NOW() - INTERVAL 30 DAY;
```

## Next Steps

**Build dashboards:**

- Use Grafana with ClickHouse data source
- Pre-built dashboards: execution trends, fuel costs, outcome success rates

**Configure alerting:**

- Alert on outcome failure spikes (> 5% hard_fail rate)
- Alert on p99 latency > 500ms
- Alert on storage quota approaching limit

**Generate billing reports:**

- Run pricing queries monthly
- Export to CSV for accounting systems
- Integrate with Stripe/payment processors

**Compliance audits:**

- Export receipts for SOC2/HIPAA reviews
- Provide audit logs to regulators (with PII anonymized)

## Normative Requirements Summary

**MUST:**

- Store all v0.2 receipt fields in analytics layer (no data loss).
- Partition by date (`executed_at`) for efficient retention policies.
- Use canonical capability keys (e.g., `net:http:fetch|https://...`).
- Enforce retention policies (delete expired data automatically).
- Anonymize PII before sharing analytics data externally.

**SHOULD:**

- Use profile-driven backend selection (potato = DuckDB, standard = Parquet, hyperscale = ClickHouse).
- Create separate `receipt_capability_counters` table for per-capability queries.
- Enable TTL for automatic expiration (ClickHouse).
- Index on `(executed_at, block_id)` for fast lookups.
- Use `LowCardinality` for categorical fields (ClickHouse optimization).

**MAY:**

- Populate optional `blocks` table for author reputation analytics.
- Create materialized views for common aggregations.
- Export data to Parquet for archival / backup.
- Integrate with external analytics tools (Grafana, Metabase, Superset).

---

**Related chapters:**

- **[Receipts](receipts.md)**: v0.2 receipt schema that analytics stores.
- **[Block Execution](block-execution.md)**: How fuel metering works (feeds into analytics).
- **[Security Considerations](security.md)**: Privacy best practices for analytics data.

**Next:** For detailed configuration examples, see the `jig-config` crate's profile examples. For query examples in production environments, check the ClickHouse or DuckDB documentation. For compliance-specific retention policies, consult your legal team (requirements vary by jurisdiction).
