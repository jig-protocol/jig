This config surface is aligned with `jig-config` and no longer relies on legacy defaults.

## Discovery & Precedence

Configuration is loaded with the following precedence (highest wins):

1. CLI flags (`--config`, `--db-path`, `--bind`, `--port`)
2. Environment variables (e.g. `JIG_DB_PATH`, `JIG_CLICKHOUSE_URL/DB/TABLE`)
3. `jig-config.toml` discovered in either:
   - Current working directory
   - Home default (see `jig-config::default_config_path()`)
4. Built-in defaults

Generate a starter file:

```bash
cargo run -p jig-server -- --init-config jig-config.toml
```

Run with explicit config:

```bash
cargo run -p jig-server -- --config jig-config.toml
```

## Analytics Dispatcher

Background dispatch of receipt rows can be tuned via `jig-config.toml` under the `analytics.dispatcher` section.

Example:

```toml
[analytics.dispatcher]
# Max in-flight rows before new ones are dropped
queue_capacity = 1024
# Rows per batch write
batch_size = 256
# Flush cadence in milliseconds (also flushes when batch_size is reached)
flush_interval_ms = 10
```

To enable the ClickHouse sink (feature-gated `analytics_clickhouse`), set environment variables at runtime:

- `JIG_CLICKHOUSE_URL` (required, e.g. `http://localhost:8123`)
- `JIG_CLICKHOUSE_DB` (optional, default: `default`)
- `JIG_CLICKHOUSE_TABLE` (optional, default: `receipts`)

You can also configure ClickHouse via `jig-config.toml` (applies when `analytics.backend = "clickhouse"`).
When present, the server maps these fields automatically:

```toml
[analytics]
backend = "clickhouse"

[analytics.clickhouse]
dsn = "tcp://analytics:9000/jig_analytics"  # Also supports http(s)://
database = "jig_analytics"                   # Used if DSN path is absent
batch_size = 512                               # Dispatcher batch size
flush_interval_secs = 2                        # Dispatcher flush cadence
```

Activation rules for ClickHouse (highest wins):

1. If `JIG_CLICKHOUSE_URL` is set in the environment, it is used.
2. Else if `analytics.clickhouse.dsn` is present in `jig-config.toml`, it is converted to an HTTP URL and used.
3. Otherwise, the ClickHouse sink is disabled.
