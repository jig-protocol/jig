# Backend Architecture: Composable Database Roles

## Implementation Status

✅ **Phase 1 Complete: Analytics Backend Abstraction (Tier 2 Foundation)**

- [x] `AnalyticsBackend` trait defined in `src/analytics/backend.rs`
- [x] SQLite adapter implemented in `src/analytics/backends/sqlite.rs` (Tier 1 default)
- [x] DuckDB adapter scaffolded in `src/analytics/backends/duckdb.rs` (Tier 2, feature-gated)
- [x] Parquet exporter scaffolded in `src/analytics/backends/parquet.rs` (Tier 2, feature-gated)
- [x] Backend registry pattern implemented in `src/analytics/backends/mod.rs`
- [x] Config-driven backend selection added to `AnalyticsConfig`
- [x] AnalyticsEngine refactored to use `Arc<dyn AnalyticsBackend>`
- [x] All 55 tests passing

✅ **Phase 2 Complete: Truth Backend Abstraction (Tier 2 Foundation)**

- [x] `NamesStorage` trait serves as truth backend interface (40+ methods)
- [x] `create_storage_backend()` factory function in `src/storage/backends/mod.rs`
- [x] SQLite backend remains default (existing `SqliteStorage`)
- [x] Postgres backend scaffolded in `src/storage/backends/postgres.rs` (Tier 2, feature-gated)
- [x] Config-driven backend selection added to `StorageConfig`
- [x] `tier2-storage` feature flag added to Cargo.toml
- [x] All 55 tests passing

✅ **Phase 3 Complete: Hot Backend Abstraction (Tier 2/3 Foundation)**

- [x] `HotBackend` trait defined in `src/hot/backend.rs` (15+ methods)
- [x] `InMemoryHot` backend implemented in `src/hot/backends/memory.rs` (Tier 1 default, fully working)
- [x] `RedisHot` backend scaffolded in `src/hot/backends/redis.rs` (Tier 2, feature-gated)
- [x] `ScyllaHot` backend scaffolded in `src/hot/backends/scylla.rs` (Tier 3, feature-gated, unique CQL architecture)
- [x] `create_hot_backend()` factory function in `src/hot/backends/mod.rs`
- [x] Config-driven backend selection added to `HotConfig`
- [x] TTL support implemented across all backend types
- [x] Hash operations (HSET/HGET/HGETALL) for complex objects
- [x] Atomic operations (INCR/DECR) for counters
- [x] `tier2-hot` and `tier3-hot` feature flags added to Cargo.toml
- [x] All 63 tests passing (including hot backend tests)

**Next Steps:**

- Add sqlx/tokio-postgres dependency and implement Postgres methods
- Add redis/deadpool-redis dependency and implement Redis methods
- Add scylla dependency and implement ScyllaDB methods
- Add DuckDB/Parquet dependencies and full implementations for analytics
- CockroachDB/TiDB adapters (Tier 3)

## Quick Start: Using Backend Abstraction

### Storage (Truth) Backend Selection

#### Default (Tier 1): SQLite for Everything

```toml
[storage]
database_path = "~/.jig/nameserver.db"
backend = "sqlite"  # Default
```

This uses the existing SQLite storage. No configuration needed - just works!

#### Tier 2: Postgres for Truth (Future)

```toml
[storage]
backend = "postgres"

[storage.backend_config]
connection_string = "postgres://localhost/nameserver"
pool_size = "10"
max_connections = "20"
```

Requires `cargo build --features tier2-storage` and sqlx dependency.

**Benefits:**
- Better concurrency (connection pooling)
- Vertical scaling (more RAM/CPU)
- Production-grade ACID guarantees
- Better query performance for large datasets

### Analytics Backend Selection

#### Default (Tier 1): SQLite for Analytics

```toml
[analytics]
enabled = true
backend = "sqlite"  # Default
```

This uses the existing SQLite storage via `AnalyticsEngine::new(storage)`.

#### Tier 2: DuckDB for Analytics (Future)

```toml
[analytics]
enabled = true
backend = "duckdb"

[analytics.backend_config]
database_path = "analytics.db"
parquet_export_path = "/data/parquet"
parquet_compression = "zstd"
```

Requires `cargo build --features tier2-analytics` and DuckDB dependency.

### Tier 2: Parquet Export (Future)

```toml
[analytics]
enabled = true
backend = "parquet"

[analytics.backend_config]
export_path = "/data/parquet/receipts"
compression = "zstd"
```

Exports analytics data to Parquet files for external tools (DuckDB, Arrow, Pandas, etc.).

### Hot State Backend Selection

#### Default (Tier 1): In-Memory Hot State

```toml
[hot]
backend = "memory"  # Default - in-memory HashMap with TTL
```

This uses the built-in InMemoryHot backend with RwLock-protected HashMap. Perfect for single-node deployments.

**Benefits:**
- Zero setup, no dependencies
- ~100μs latency (fastest possible)
- Full TTL support with automatic expiration
- Hash operations for complex objects
- Atomic increment/decrement operations

**Limitations:**
- No persistence (data lost on restart)
- Single-node only (no clustering)
- No pub/sub support

#### Tier 2: Redis/Valkey/DragonflyDB for Hot State (Future)

```toml
[hot]
backend = "redis"  # or "valkey" or "dragonfly"
fallback_to_memory = true

[hot.backend_config]
connection_string = "redis://localhost:6379"
pool_size = "5"
```

Requires `cargo build --features tier2-hot` and redis dependency.

**Benefits:**
- Optional persistence (RDB/AOF snapshots)
- Pub/sub support for real-time events
- ~1ms network latency
- ~100k ops/sec for single-node
- Connection pooling for better concurrency
- Graceful fallback to in-memory if unavailable

**Use cases:**
- Rate limiting across multiple nameserver instances
- Federation peer status caching
- PoW challenge deduplication
- Session state management

#### Tier 3: ScyllaDB for Hot State (Future)

```toml
[hot]
backend = "scylladb"
fallback_to_memory = false

[hot.backend_config]
nodes = "node1:9042,node2:9042,node3:9042"
keyspace = "jig_hot"
```

Requires `cargo build --features tier3-hot` and scylla dependency.

**IMPORTANT:** ScyllaDB uses CQL (Cassandra Query Language), not Redis protocol.

**Benefits:**
- Always persistent (disk-backed)
- Horizontally scalable across nodes
- Millions of ops/sec across cluster
- Row-level TTL via `USING TTL` clause
- Tunable consistency (eventual by default)
- ~2ms latency for distributed writes

**Use cases:**
- Hyperscale deployments
- Multi-region federation
- High-throughput rate limiting
- Persistent hot state (survives restarts)

**Architectural differences from Redis:**
- Uses CQL tables, not Redis commands
- Distributed by design (vs Redis Cluster)
- Persistent by default (vs in-memory by default)
- Eventual consistency (vs strong consistency)

#### Combined Tier 2: Postgres + DuckDB + Redis (Optimal Configuration)

```toml
# Truth backend: Postgres for ACID transactions
[storage]
backend = "postgres"

[storage.backend_config]
connection_string = "postgres://localhost/nameserver"
pool_size = "10"

# Analytics backend: DuckDB for fast OLAP queries
[analytics]
enabled = true
backend = "duckdb"

[analytics.backend_config]
database_path = "analytics.db"
parquet_export_path = "/data/parquet"
parquet_compression = "zstd"

# Hot backend: Redis for ephemeral state and caching
[hot]
backend = "redis"
fallback_to_memory = true

[hot.backend_config]
connection_string = "redis://localhost:6379"
pool_size = "5"
```

This is the **recommended Tier 2 configuration** - separates concerns by using:
- **Postgres** for transactional truth (identities, receipts, tribunal cases)
- **DuckDB** for analytical queries (receipt stats, anomaly analysis)
- **Redis** for hot state (rate limiting, caching, session management)

Each backend can scale independently!

## Philosophy

**Goal:** Maximize backend composability and minimize hardcoded database logic to enable:

1. Different backends for different roles (truth, hot, analytics, storage, etc.)
2. Multi-tenant configurations (different tenants use different backends)
3. Federation flexibility (nameservers in same federation can use different stacks)
4. Future-proof extensibility (add CockroachDB, TiDB, etc. without core rewrites)
5. Config-as-code control (jig-config drives backend selection)

## Database Roles

### Role Taxonomy

| Role          | Purpose                         | Characteristics                          | Example Backends                                |
| ------------- | ------------------------------- | ---------------------------------------- | ----------------------------------------------- |
| **truth**     | Source of truth, durable writes | ACID, transactions, schema               | Postgres, CockroachDB, TiDB, MySQL              |
| **hot**       | Fast ephemeral state, caching   | Low latency, in-memory, TTL              | Redis, Memcached, Valkey, DragonflyDB, ScyllaDB |
| **analytics** | Time-series, aggregations, OLAP | Columnar, compression, analytics queries | DuckDB, ClickHouse, TimescaleDB, Parquet files  |
| **storage**   | Blob/object storage             | Large files, content-addressed           | S3, IPFS, MinIO, R2                             |
| **vector**    | Similarity search, embeddings   | Vector indexing, nearest neighbor        | Qdrant, Weaviate, pgvector                      |
| **otlp**      | Observability, traces, metrics  | Time-series, sampling, aggregation       | Tempo, Jaeger, Prometheus                       |

### Tier 1 (Potato) - Current State

**Single Backend:** SQLite handles ALL roles

```toml
[storage]
database_path = "nameserver.db"
```

**Simplicity:** Zero config, one file, <60sec setup
**Limitations:** No role separation, limited scale, no horizontal scaling

### Tier 2 (Prosumer) - Target State

**Role Separation:** Different backends for different roles

```toml
[backend.truth]
type = "postgres"
connection_string = "postgres://localhost/nameserver"

[backend.analytics]
type = "duckdb"
database_path = "analytics.db"
# OR
type = "parquet"
export_path = "/data/analytics/"

[backend.hot]
type = "redis"
connection_string = "redis://localhost:6379"
# Fallback to in-memory if Redis unavailable
fallback_to_memory = true
```

**Benefits:**

- Postgres for ACID transactions (truth)
- DuckDB/Parquet for fast analytics (analytics)
- Redis for hot state/caching (hot)
- Independent scaling of each role

### Tier 3 (Hyperscale) - Future State

**Distributed Backends:** Horizontal scaling, federated analytics

```toml
[backend.truth]
type = "cockroachdb"
nodes = ["node1:26257", "node2:26257", "node3:26257"]

[backend.analytics]
type = "clickhouse"
cluster_url = "http://clickhouse.example.com:8123"
database = "nameserver_analytics"

[backend.storage]
type = "s3"
bucket = "nameserver-receipts"
region = "us-east-1"

[backend.vector]
type = "qdrant"
collection = "receipt_embeddings"
url = "http://qdrant:6333"
```

## Backend Abstraction Design

### Core Principle: Trait-Based Abstraction

Each role has a trait defining its interface. Implementations are backend-specific.

```rust
/// Analytics backend trait - any OLAP-capable backend
#[async_trait]
pub trait AnalyticsBackend: Send + Sync {
    /// Query receipt statistics for time range
    async fn query_receipts(&self, range: TimeRange) -> Result<Vec<ReceiptRecord>>;

    /// Query anomalies for time range
    async fn query_anomalies(&self, range: TimeRange) -> Result<Vec<AnomalyRecord>>;

    /// Export to backend-native format (Parquet, CSV, etc.)
    async fn export(&self, range: TimeRange, format: ExportFormat) -> Result<Vec<u8>>;

    /// Backend capabilities (supports aggregations, time-series, etc.)
    fn capabilities(&self) -> BackendCapabilities;
}

/// Truth backend trait - RDBMS with ACID guarantees
#[async_trait]
pub trait TruthBackend: Send + Sync {
    /// Store record with transaction support
    async fn store<T: Serialize>(&self, table: &str, record: T) -> Result<()>;

    /// Query with WHERE clause
    async fn query<T: DeserializeOwned>(&self, table: &str, filter: Filter) -> Result<Vec<T>>;

    /// Begin transaction
    async fn begin_tx(&self) -> Result<Box<dyn Transaction>>;
}

/// Hot backend trait - fast ephemeral state
#[async_trait]
pub trait HotBackend: Send + Sync {
    /// Get value with TTL awareness
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Set value with TTL
    async fn set(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> Result<()>;

    /// Increment counter
    async fn incr(&self, key: &str) -> Result<i64>;
}
```

### Backend Registry Pattern

Backends register themselves with capabilities metadata:

```rust
pub struct BackendRegistry {
    analytics: HashMap<String, Box<dyn AnalyticsBackendFactory>>,
    truth: HashMap<String, Box<dyn TruthBackendFactory>>,
    hot: HashMap<String, Box<dyn HotBackendFactory>>,
}

impl BackendRegistry {
    pub fn register_analytics<F: AnalyticsBackendFactory + 'static>(
        &mut self,
        name: &str,
        factory: F,
    ) {
        self.analytics.insert(name.to_string(), Box::new(factory));
    }

    pub fn create_analytics(
        &self,
        config: &AnalyticsBackendConfig,
    ) -> Result<Box<dyn AnalyticsBackend>> {
        let factory = self.analytics.get(&config.backend_type)
            .ok_or_else(|| anyhow!("Unknown analytics backend: {}", config.backend_type))?;
        factory.create(config)
    }
}
```

### Configuration Structure

```toml
# Tier 1: Simple mode (backward compatible)
[storage]
database_path = "nameserver.db"

# Tier 2+: Role-based backends
[backends]
# Which backend handles which role
truth = "postgres"
analytics = "duckdb"
hot = "redis"

[backends.postgres]
connection_string = "postgres://localhost/nameserver"
pool_size = 10
max_connections = 20

[backends.duckdb]
database_path = "analytics.db"
# Enable Parquet export
parquet_export_path = "/data/parquet/"
parquet_compression = "zstd"

[backends.redis]
connection_string = "redis://localhost:6379"
pool_size = 5
# Fallback to in-memory if Redis unavailable
fallback_to_memory = true
```

## Backend Characteristics Matrix

### Analytics Backends

| Backend         | Query Speed | Storage Size | Setup Complexity | Horizontal Scale    | Best For                   |
| --------------- | ----------- | ------------ | ---------------- | ------------------- | -------------------------- |
| **SQLite**      | Medium      | Large        | Zero             | No                  | Potato (T1)                |
| **DuckDB**      | Very Fast   | Medium       | Low              | No                  | Prosumer (T2)              |
| **Parquet**     | Fast (read) | Small        | Low              | Yes (file sharding) | Data export, archival      |
| **ClickHouse**  | Very Fast   | Small        | Medium           | Yes                 | Hyperscale (T3), real-time |
| **TimescaleDB** | Fast        | Medium       | Medium           | Yes                 | Time-series focus          |

**Key Characteristics:**

- **Columnar storage**: DuckDB, ClickHouse, Parquet
- **Time-series optimized**: ClickHouse, TimescaleDB
- **Embedded**: SQLite, DuckDB
- **Distributed**: ClickHouse, TimescaleDB
- **File-based**: Parquet (static export)

### Truth Backends

| Backend         | Consistency | Availability | Partition Tolerance | Scale       | Best For        |
| --------------- | ----------- | ------------ | ------------------- | ----------- | --------------- |
| **SQLite**      | Strong      | High (local) | No                  | Single-node | Potato (T1)     |
| **Postgres**    | Strong      | Medium       | No                  | Vertical    | Prosumer (T2)   |
| **CockroachDB** | Strong      | High         | Yes                 | Horizontal  | Hyperscale (T3) |
| **TiDB**        | Strong      | High         | Yes                 | Horizontal  | Hyperscale (T3) |

**Key Characteristics:**

- **ACID transactions**: All
- **SQL interface**: All
- **Schema evolution**: All support migrations
- **Distributed**: CockroachDB, TiDB

### Hot Backends

| Backend         | Latency | Persistence | Protocol      | Distributed | Throughput (single-node) | Best For                  |
| --------------- | ------- | ----------- | ------------- | ----------- | ------------------------ | ------------------------- |
| **In-Memory**   | ~100μs  | No          | Native (Rust) | No          | Unlimited (local)        | Potato (T1), testing      |
| **Redis**       | ~1ms    | Optional    | Redis         | No*         | ~100k ops/sec            | Prosumer (T2)             |
| **Valkey**      | ~1ms    | Optional    | Redis         | No*         | ~100k ops/sec            | Redis alternative         |
| **DragonflyDB** | ~1ms    | Optional    | Redis         | No          | ~200k ops/sec            | High-throughput T2        |
| **ScyllaDB**    | ~2ms    | Always      | CQL           | Yes         | ~1M ops/sec (cluster)    | Hyperscale (T3), **Tier** |

\* Redis Cluster available for distributed deployment

**Key Characteristics:**

- **In-memory**: All (ScyllaDB uses memory + disk)
- **TTL support**: All (in-memory via `HotEntry`, Redis via `EXPIRE`, ScyllaDB via `USING TTL`)
- **Pub/sub**: Redis, Valkey, DragonflyDB (not ScyllaDB - use Kafka instead)
- **Persistence options**: Redis (RDB/AOF), Valkey, DragonflyDB, ScyllaDB (always on disk)
- **Protocol**: Redis-compatible (Redis/Valkey/DragonflyDB), CQL (ScyllaDB)
- **Distributed**: ScyllaDB by design, Redis Cluster opt-in

## Implementation Strategy

### Phase 1: Analytics Backend Abstraction (Tier 2)

**Goal:** Make analytics backend swappable without changing AnalyticsEngine

1. **Create `AnalyticsBackend` trait** in `src/analytics/backend.rs`
2. **Implement SQLite adapter** wrapping existing queries
3. **Implement DuckDB adapter** with optimized columnar queries
4. **Implement Parquet exporter** (file-based "backend")
5. **Update AnalyticsEngine** to accept `Arc<dyn AnalyticsBackend>`
6. **Add config parsing** for backend selection
7. **Document** how to add new analytics backends

**Files to create:**

- `src/analytics/backend.rs` - Trait definition
- `src/analytics/backends/sqlite.rs` - SQLite adapter
- `src/analytics/backends/duckdb.rs` - DuckDB adapter
- `src/analytics/backends/parquet.rs` - Parquet exporter
- `src/analytics/backends/mod.rs` - Backend registry

**Config example:**

```toml
[analytics]
enabled = true
backend = "duckdb"  # or "sqlite", "parquet", "clickhouse"

[analytics.backends.duckdb]
database_path = "analytics.db"
parquet_export_path = "/data/parquet/"
```

### Phase 2: Truth Backend Abstraction (Tier 2/3)

**Goal:** Separate truth/transactions from analytics

1. **Create `TruthBackend` trait** in `src/storage/backend.rs`
2. **Refactor existing SQLite** to implement trait
3. **Implement Postgres adapter**
4. **Add migration system** for schema evolution
5. **Support multi-backend** (Postgres for truth, DuckDB for analytics)

### Phase 3: Hot Backend Abstraction (Tier 2/3) ✅ COMPLETE

**Goal:** Add hot state abstraction for rate limiting, caching, sessions with Redis (T2) and ScyllaDB (T3)

**Completed:**

1. ✅ **Created `HotBackend` trait** in `src/hot/backend.rs` (15+ methods)
   - Basic KV ops: `get`, `set`, `del`, `exists`, `expire`
   - Atomic ops: `incr`, `incr_by`, `decr`
   - Hash ops: `hset`, `hget`, `hgetall`, `hdel`
   - Batch ops: `mget`, `mset`
   - Maintenance: `flush`
2. ✅ **Implemented in-memory backend** (Tier 1 default) - fully working with tests
3. ✅ **Scaffolded Redis adapter** (Tier 2, feature-gated `tier2-hot`)
   - Supports Redis, Valkey, DragonflyDB (all Redis-protocol compatible)
   - Connection pooling, fallback to memory on failure
4. ✅ **Scaffolded ScyllaDB adapter** (Tier 3, feature-gated `tier3-hot`)
   - **Unique architecture**: Uses CQL (Cassandra Query Language), not Redis protocol
   - Distributed and persistent by design
   - Row-level TTL via `USING TTL` clause
5. ✅ **Added config-driven backend selection** via `HotConfig`
6. ✅ **Factory pattern** in `create_hot_backend()` for runtime selection

**Use cases:**
- Rate limiting (identity registration attempts)
- PoW challenge caching (deduplication)
- Federation peer status (online/offline tracking)
- Session state management

**Next:** Add actual redis/scylla dependencies when ready for Tier 2/3 deployments

## Adding a New Backend: Step-by-Step Guide

### Example: Adding ClickHouse for Analytics

**Step 1: Add dependency (with feature flag)**

```toml
[dependencies]
clickhouse = { version = "0.12", optional = true }

[features]
tier3-analytics = ["dep:clickhouse"]
```

**Step 2: Implement `AnalyticsBackend` trait**

```rust
// src/analytics/backends/clickhouse.rs
pub struct ClickHouseAnalytics {
    client: clickhouse::Client,
    database: String,
}

#[async_trait]
impl AnalyticsBackend for ClickHouseAnalytics {
    async fn query_receipts(&self, range: TimeRange) -> Result<Vec<ReceiptRecord>> {
        let (start, end) = range.to_datetime_range();
        let query = format!(
            "SELECT * FROM receipts WHERE executed_at BETWEEN ? AND ?"
        );
        self.client.query(&query)
            .bind(start)
            .bind(end)
            .fetch_all()
            .await
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_streaming: true,
            supports_aggregations: true,
            max_query_size: None, // unlimited
            columnar_storage: true,
        }
    }
}
```

**Step 3: Register backend in registry**

```rust
// src/analytics/backends/mod.rs
pub fn register_all_backends(registry: &mut BackendRegistry) {
    registry.register_analytics("sqlite", SqliteAnalyticsFactory);
    registry.register_analytics("duckdb", DuckDBAnalyticsFactory);

    #[cfg(feature = "tier3-analytics")]
    registry.register_analytics("clickhouse", ClickHouseAnalyticsFactory);
}
```

**Step 4: Add config parsing**

```rust
#[derive(Deserialize)]
pub struct ClickHouseConfig {
    pub cluster_url: String,
    pub database: String,
    pub username: Option<String>,
    pub password: Option<String>,
}
```

**Step 5: Document in this file** - Add row to backend comparison table

**That's it!** No changes to core AnalyticsEngine, just:

1. Implement trait (1 file)
2. Register backend (1 line)
3. Add config (1 struct)

## Control Plane Parity

### Config-as-Code: Backend Selection

**Tier 1 (Potato):** 100% defaults, zero config

```toml
# No [backends] section = SQLite for everything
```

**Tier 2 (Prosumer):** Backend per role

```toml
[backends]
truth = "postgres"
analytics = "duckdb"
hot = "redis"
```

**Tier 3 (Hyperscale):** Fine-grained per-role config

```toml
[backends]
truth = "cockroachdb"
analytics = "clickhouse"
hot = "dragonflydb"
storage = "s3"

[backends.cockroachdb]
nodes = ["node1:26257", "node2:26257"]
database = "nameserver"
max_retries = 3

[backends.clickhouse]
cluster_url = "http://clickhouse:8123"
database = "analytics"
async_inserts = true
compression = "lz4"

[backends.s3]
bucket = "nameserver-receipts"
region = "us-east-1"
endpoint = "https://s3.amazonaws.com"
```

**Multi-Tenant:** Different configs per tenant

```toml
[tenants.acme-corp.backends]
truth = "postgres"
analytics = "duckdb"

[tenants.enterprise-inc.backends]
truth = "cockroachdb"
analytics = "clickhouse"
```

### Control Plane Parity Goal: >95%

**Configurable:**

- Backend type per role
- Connection strings/paths
- Pool sizes, timeouts, retries
- Compression, encoding
- Feature flags (async inserts, etc.)
- Fallback behavior

**Hardcoded (minimal):**

- Backend trait interface (necessary abstraction)
- SQL schema structure (per backend type, not per deployment)
- Core query logic (can be overridden via custom backend impl)

## Migration Path

### From Tier 1 to Tier 2

**Zero Breaking Changes:** Tier 1 configs continue working

```toml
# Old config (still works)
[storage]
database_path = "nameserver.db"

# New config (opt-in)
[backends]
analytics = "duckdb"
truth = "sqlite"  # Can keep SQLite for truth if desired
```

**Data migration:**

```bash
# Export from SQLite
jig-ns export --format parquet -o /tmp/export.parquet

# Import to DuckDB
duckdb analytics.db "CREATE TABLE receipts AS SELECT * FROM parquet_scan('/tmp/export.parquet')"
```

### From Tier 2 to Tier 3

**Horizontal scaling:** Just change config

```toml
[backends]
# Before
analytics = "duckdb"

# After
analytics = "clickhouse"

[backends.clickhouse]
cluster_url = "http://clickhouse:8123"
```

## Summary

**Key Design Principles:**

1. ✅ **Trait-based abstraction** - Backend implementations are swappable
2. ✅ **Role-based separation** - Different backends for truth/analytics/hot/storage
3. ✅ **Registry pattern** - Backends register with capabilities
4. ✅ **Config-driven** - jig-config selects backend per role
5. ✅ **Future-proof** - Adding new backends requires no core changes
6. ✅ **Backward compatible** - Tier 1 SQLite configs continue working
7. ✅ **Multi-tenant aware** - Different tenants can use different backends

**Next Steps:**

1. Implement `AnalyticsBackend` trait (Phase 1)
2. Create DuckDB and Parquet adapters (Tier 2)
3. Update AnalyticsEngine to use abstraction
4. Add backend selection config
5. Document adding ClickHouse (Tier 3 example)
