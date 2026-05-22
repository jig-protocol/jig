//! ScyllaDB hot backend (Tier 3)
//!
//! Distributed persistent cache using ScyllaDB (Cassandra-compatible).
//! Different from Redis-like backends - uses CQL instead of Redis protocol.
//!
//! Key differences:
//! - Distributed by design (horizontal scaling across nodes)
//! - Persistent on disk (not just in-memory)
//! - Uses CQL (Cassandra Query Language) not Redis commands
//! - TTL at row level (not key level)
//! - Eventual consistency (tunable)
//!
//! Best for: Hyperscale deployments needing highest throughput (millions ops/sec)

#[cfg(feature = "tier3-hot")]
use crate::error::{NameServerError, Result};
#[cfg(feature = "tier3-hot")]
use crate::hot::backend::{HotBackend, HotBackendCapabilities};
#[cfg(feature = "tier3-hot")]
use async_trait::async_trait;
#[cfg(feature = "tier3-hot")]
use std::collections::HashMap;

#[cfg(feature = "tier3-hot")]
use scylla::{Session, SessionBuilder};

#[cfg(feature = "tier3-hot")]
/// ScyllaDB hot backend - uses scylla-rust-driver
pub struct ScyllaHot {
    session: Session,
    keyspace: String,
}

#[cfg(feature = "tier3-hot")]
impl std::fmt::Debug for ScyllaHot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScyllaHot")
            .field("keyspace", &self.keyspace)
            .field("session", &"<Session>")
            .finish()
    }
}

#[cfg(feature = "tier3-hot")]
impl ScyllaHot {
    pub async fn new(nodes: Vec<String>, keyspace: String) -> Result<Self> {
        // Initialize ScyllaDB session
        let session = SessionBuilder::new()
            .known_nodes(&nodes)
            .build()
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("Failed to connect to ScyllaDB: {}", e))
            })?;

        // Create keyspace
        let create_keyspace_query = format!(
            "CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': 1}}",
            keyspace
        );
        session
            .query_unpaged(create_keyspace_query.as_str(), &[])
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("Failed to create keyspace: {}", e))
            })?;

        // Use the keyspace
        session.use_keyspace(&keyspace, false).await.map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to use keyspace: {}", e))
        })?;

        // Create hot_kv table for key-value storage
        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS hot_kv (
                    key text PRIMARY KEY,
                    value blob
                )",
                &[],
            )
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("Failed to create hot_kv table: {}", e))
            })?;

        // Create hot_hashes table for hash operations
        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS hot_hashes (
                    key text,
                    field text,
                    value blob,
                    PRIMARY KEY (key, field)
                )",
                &[],
            )
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("Failed to create hot_hashes table: {}", e))
            })?;

        // Create hot_counters table for atomic counter operations
        session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS hot_counters (
                    key text PRIMARY KEY,
                    value counter
                )",
                &[],
            )
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!(
                    "Failed to create hot_counters table: {}",
                    e
                ))
            })?;

        Ok(Self { session, keyspace })
    }
}

#[cfg(feature = "tier3-hot")]
#[async_trait]
impl HotBackend for ScyllaHot {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let result = self
            .session
            .query_unpaged("SELECT value FROM hot_kv WHERE key = ?", (key,))
            .await
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("ScyllaDB query error: {}", e)))?;

        // Convert to rows result and get first row if exists
        let rows_result = result.into_rows_result().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to convert to rows: {}", e))
        })?;

        if let Some((value,)) = rows_result
            .maybe_first_row::<(Vec<u8>,)>()
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("Failed to parse row: {}", e)))?
        {
            return Ok(Some(value));
        }

        Ok(None)
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl_secs: Option<u64>) -> Result<()> {
        if let Some(ttl) = ttl_secs {
            // INSERT with TTL (ScyllaDB specific syntax)
            self.session
                .query_unpaged(
                    "INSERT INTO hot_kv (key, value) VALUES (?, ?) USING TTL ?",
                    (key, value, ttl as i32),
                )
                .await
                .map_err(|e| {
                    NameServerError::Other(anyhow::anyhow!("ScyllaDB insert error: {}", e))
                })?;
        } else {
            // INSERT without TTL
            self.session
                .query_unpaged(
                    "INSERT INTO hot_kv (key, value) VALUES (?, ?)",
                    (key, value),
                )
                .await
                .map_err(|e| {
                    NameServerError::Other(anyhow::anyhow!("ScyllaDB insert error: {}", e))
                })?;
        }

        Ok(())
    }

    async fn del(&self, key: &str) -> Result<bool> {
        self.session
            .query_unpaged("DELETE FROM hot_kv WHERE key = ?", (key,))
            .await
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("ScyllaDB delete error: {}", e)))?;

        // ScyllaDB DELETE is idempotent, always return true
        Ok(true)
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let result = self
            .session
            .query_unpaged("SELECT key FROM hot_kv WHERE key = ?", (key,))
            .await
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("ScyllaDB query error: {}", e)))?;

        let rows_result = result.into_rows_result().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to convert to rows: {}", e))
        })?;

        Ok(rows_result.rows_num() > 0)
    }

    async fn expire(&self, key: &str, ttl_secs: u64) -> Result<bool> {
        // In ScyllaDB, to update TTL we need to re-insert the value with new TTL
        // First, get the existing value
        if let Some(value) = self.get(key).await? {
            self.session
                .query_unpaged(
                    "INSERT INTO hot_kv (key, value) VALUES (?, ?) USING TTL ?",
                    (key, value, ttl_secs as i32),
                )
                .await
                .map_err(|e| {
                    NameServerError::Other(anyhow::anyhow!("ScyllaDB update TTL error: {}", e))
                })?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn incr(&self, key: &str) -> Result<i64> {
        self.incr_by(key, 1).await
    }

    async fn incr_by(&self, key: &str, amount: i64) -> Result<i64> {
        // ScyllaDB counters: UPDATE hot_counters SET value = value + ? WHERE key = ?
        self.session
            .query_unpaged(
                "UPDATE hot_counters SET value = value + ? WHERE key = ?",
                (amount, key),
            )
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("ScyllaDB counter update error: {}", e))
            })?;

        // Read back the counter value
        let result = self
            .session
            .query_unpaged("SELECT value FROM hot_counters WHERE key = ?", (key,))
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("ScyllaDB counter query error: {}", e))
            })?;

        let rows_result = result.into_rows_result().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to convert to rows: {}", e))
        })?;

        if let Some((value,)) = rows_result.maybe_first_row::<(i64,)>().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to parse counter: {}", e))
        })? {
            return Ok(value);
        }

        Ok(amount)
    }

    async fn decr(&self, key: &str) -> Result<i64> {
        self.incr_by(key, -1).await
    }

    async fn hset(&self, key: &str, field: &str, value: Vec<u8>) -> Result<()> {
        self.session
            .query_unpaged(
                "INSERT INTO hot_hashes (key, field, value) VALUES (?, ?, ?)",
                (key, field, value),
            )
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("ScyllaDB hash insert error: {}", e))
            })?;

        Ok(())
    }

    async fn hget(&self, key: &str, field: &str) -> Result<Option<Vec<u8>>> {
        let result = self
            .session
            .query_unpaged(
                "SELECT value FROM hot_hashes WHERE key = ? AND field = ?",
                (key, field),
            )
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("ScyllaDB hash query error: {}", e))
            })?;

        let rows_result = result.into_rows_result().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to convert to rows: {}", e))
        })?;

        if let Some((value,)) = rows_result.maybe_first_row::<(Vec<u8>,)>().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to parse hash value: {}", e))
        })? {
            return Ok(Some(value));
        }

        Ok(None)
    }

    async fn hgetall(&self, key: &str) -> Result<HashMap<String, Vec<u8>>> {
        let result = self
            .session
            .query_unpaged("SELECT field, value FROM hot_hashes WHERE key = ?", (key,))
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("ScyllaDB hash query error: {}", e))
            })?;

        let rows_result = result.into_rows_result().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to convert to rows: {}", e))
        })?;

        let mut map = HashMap::new();

        let mut rows_iter = rows_result.rows::<(String, Vec<u8>)>().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to create rows iterator: {}", e))
        })?;

        while let Some(row_result) = rows_iter.next() {
            let (field, value) = row_result.map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("Failed to parse hash row: {}", e))
            })?;
            map.insert(field, value);
        }

        Ok(map)
    }

    async fn hdel(&self, key: &str, field: &str) -> Result<bool> {
        self.session
            .query_unpaged(
                "DELETE FROM hot_hashes WHERE key = ? AND field = ?",
                (key, field),
            )
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("ScyllaDB hash delete error: {}", e))
            })?;

        // ScyllaDB DELETE is idempotent, always return true
        Ok(true)
    }

    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        // ScyllaDB doesn't support IN queries efficiently for large sets
        // Use individual queries (could be optimized with async batching)
        let mut results = Vec::with_capacity(keys.len());

        for key in keys {
            results.push(self.get(key).await?);
        }

        Ok(results)
    }

    async fn mset(&self, pairs: &[(&str, Vec<u8>)]) -> Result<()> {
        // Simple implementation: insert each pair individually
        // TODO: Optimize with batch statements
        for (key, value) in pairs {
            self.set(key, value.clone(), None).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        // TRUNCATE all tables
        self.session
            .query_unpaged("TRUNCATE hot_kv", &[])
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("ScyllaDB truncate error: {}", e))
            })?;

        self.session
            .query_unpaged("TRUNCATE hot_hashes", &[])
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("ScyllaDB truncate error: {}", e))
            })?;

        self.session
            .query_unpaged("TRUNCATE hot_counters", &[])
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("ScyllaDB truncate error: {}", e))
            })?;

        Ok(())
    }

    fn capabilities(&self) -> HotBackendCapabilities {
        HotBackendCapabilities {
            persistent: true,                // Always persists to disk
            ttl_support: true,               // Row-level TTL
            atomic_ops: true,                // Counters and LWT (lightweight transactions)
            pubsub: false,                   // No pub/sub (use Kafka for that)
            distributed: true,               // Horizontally scalable
            latency_us: 2000,                // ~2ms for distributed writes (tunable consistency)
            max_throughput: Some(1_000_000), // Millions of ops/sec across cluster
        }
    }

    fn name(&self) -> &'static str {
        "scylladb"
    }
}

// Placeholder stubs for non-tier3 builds
#[cfg(not(feature = "tier3-hot"))]
pub struct ScyllaHot;

#[cfg(not(feature = "tier3-hot"))]
impl ScyllaHot {
    pub async fn new(_nodes: Vec<String>, _keyspace: String) -> crate::error::Result<Self> {
        Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "ScyllaDB backend requires tier3-hot feature"
        )))
    }
}
