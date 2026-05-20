# jig-server

Reference server implementation for the Jig protocol.

## Overview

`jig-server` hosts Jig executable blocks. It exposes an HTTP API for ingesting block bundles, executing their Wasm payloads (validation only in this release), and persisting manifests, resources, and execution receipts.

## Features

- **SQLite-backed block store** with manifest/receipt indexing
- **Wasmtime runtime** (fuel, memory, timeout limits) for validating block payloads
- **HTTP API** for ingesting blocks and fetching manifests/resources/receipts
- **Config-as-code** via `jig-config.toml`
- **Analytics backends** (feature-gated): SQLite (built-in), DuckDB + Parquet (standard), ClickHouse sink (hyperscale)
- **Analytics dispatcher** with bounded queue + batch/interval flush (configurable)

## Quick Start

```bash
# Write a config template
jig-server --init-config jig-config.toml

# Start with defaults (SQLite under ~/.jig/jig.db)
jig-server

# Start using a specific config file
jig-server --config jig-config.toml

# Override a few fields on the CLI
jig-server --db-path /tmp/jig.db --bind 0.0.0.0 --port 7117
```

## HTTP API (preview)

| Endpoint                   | Method | Description                                                         |
| -------------------------- | ------ | ------------------------------------------------------------------- |
| `/.well-known/jig`         | GET    | Basic server metadata (host DID, version)                           |
| `/blocks`                  | POST   | Ingest a block bundle (manifest + code + data)                      |
| `/blocks`                  | GET    | List recent blocks                                                  |
| `/blocks/{cid}`            | GET    | Retrieve manifest, code, and resources                              |
| `/receipts/{cid}`          | GET    | Fetch the execution receipt for a stored block                      |
| `/analytics/receipt-stats` | GET    | Aggregate receipt statistics over a time range (SQLite analytics; optional DuckDB backend) |
| `/metrics/timings`         | GET    | Timings percentiles (p50/p95/p99) — requires `--features telemetry_v0_2` |

Example ingest payload:

```json
{
  "manifest": { "...": "canonical manifest json" },
  "code_b64": "BASE64-WASM-HERE",
  "resources": [
    { "name": "input.json", "mime": "application/json", "data_b64": "..." }
  ]
}
```

### DuckDB backend (standard tier, feature-gated)

- Enable with: `--features analytics_duckdb`
- Query by adding `backend=duckdb` to the request.
- The DuckDB database file is created next to your SQLite file as `analytics.duckdb`.
- Behavior: the server projects recent receipts from the SQLite truth store into DuckDB, then computes the same `ReceiptStats` JSON via columnar queries.

### Parquet exporter (standard tier, feature-gated)

- Enable with: `--features analytics_parquet`
- Purpose: one-shot archival export for data lakes and offline analytics (not for serving queries)
- CLI usage:

```bash
# Export last day of receipts to a Parquet file
cargo run -p jig-server --features analytics_parquet -- \
  export-parquet \
  --out /tmp/receipts.parquet \
  --range last_day

# Custom range (Unix seconds)
cargo run -p jig-server --features analytics_parquet -- \
  export-parquet \
  --out /tmp/receipts.parquet \
  --range custom \
  --start-ts 1730851200 --end-ts 1730937600

# Alternate compression
cargo run -p jig-server --features analytics_parquet -- \
  export-parquet \
  --out /tmp/receipts.parquet \
  --compression snappy
```

- Parquet schema (Arrow):
  - `block_id: Utf8`
  - `executed_at: Int64` (Unix seconds)
  - `fuel_used: Int64`
  - `outcome: Utf8` (e.g. `ok`, `soft_fail`, `hard_fail`)
  - `host: Utf8` (server DID)
  - `capability: Utf8?` (top fuel-consuming capability if present)

### ClickHouse sink (hyperscale, feature-gated)

- Enable with: `--features analytics_clickhouse`
- Activation requires env vars:
  - `JIG_CLICKHOUSE_URL` (e.g. `http://localhost:8123`)
  - `JIG_CLICKHOUSE_DB` (optional, default: `default`)
  - `JIG_CLICKHOUSE_TABLE` (optional, default: `receipts`)
- Behavior: Receipts are enqueued to a background dispatcher and flushed in batches to ClickHouse via HTTP insert. Best-effort when queue is full (drop policy).

### Dispatcher tuning (config)

Configure the background dispatcher via `jig-config.toml`:

```toml
[analytics.dispatcher]
# Max in-flight rows before new ones are dropped
queue_capacity = 1024
# Rows per batch write
batch_size = 256
# Flush cadence in milliseconds (also flushes when batch_size is reached)
flush_interval_ms = 10
```

## Metrics: Timings (feature-gated)

`GET /metrics/timings` returns timing percentiles for queue_wait, init, exec, and total. This endpoint is available only when built with the `telemetry_v0_2` feature.

Enable and run:

```bash
cargo run -p jig-server --features telemetry_v0_2
```

Example:

```bash
curl "http://127.0.0.1:7117/metrics/timings"
```

Sample response:

```json
{
  "samples": 23,
  "queue_wait": { "p50": 0, "p95": 0, "p99": 0 },
  "init": { "p50": 5, "p95": 20, "p99": 40 },
  "exec": { "p50": 10, "p95": 900, "p99": 1000 },
  "total": { "p50": 15, "p95": 920, "p99": 1040 }
}
```

The server validates and stores the bundle, deriving the block CID. Wasm execution is currently limited to compilation checks; capability-scoped execution with receipts will follow once the runtime sandbox is finished.

## Analytics: Receipt Stats

`GET /analytics/receipt-stats` computes simple aggregates from stored receipts.

Query parameters:

- `range` one of `last_hour`, `last_day` (default), `last_week`, `last_month`, `custom`
- if `range=custom`, include `start_ts` and `end_ts` (Unix seconds)

Examples:

```bash
# Last day
curl "http://127.0.0.1:7117/analytics/receipt-stats?range=last_day"

# Custom range
curl "http://127.0.0.1:7117/analytics/receipt-stats?range=custom&start_ts=1730851200&end_ts=1730937600"

# Use DuckDB backend (feature)
cargo run -p jig-server --features analytics_duckdb
curl "http://127.0.0.1:7117/analytics/receipt-stats?range=last_day&backend=duckdb"
```

Sample response:

```json
{
  "total_receipts": 2,
  "total_fuel_used": 150,
  "avg_fuel_per_receipt": 75.0,
  "success_rate": 0.5,
  "outcome_breakdown": { "ok": 1, "hard_fail": 1 },
  "top_hosts": [["did:jig:server:local", 2]],
  "fuel_by_capability": { "core:compute": 100 },
  "timings_p50_ms": { "queue_wait": 0, "init": 5, "exec": 10, "total": 15 }
}
```

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
