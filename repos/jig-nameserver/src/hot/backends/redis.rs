//! Redis hot backend (Tier 2)
//!
//! Supports Redis, Valkey, and DragonflyDB (all Redis-protocol compatible).
//! Provides persistence, pub/sub, and much higher throughput than in-memory.

#[cfg(feature = "tier2-hot")]
use crate::error::{NameServerError, Result};
#[cfg(feature = "tier2-hot")]
use crate::hot::backend::{HotBackend, HotBackendCapabilities};
#[cfg(feature = "tier2-hot")]
use async_trait::async_trait;
#[cfg(feature = "tier2-hot")]
use std::collections::HashMap;

#[cfg(feature = "tier2-hot")]
use redis::{AsyncCommands, RedisError, aio::ConnectionManager};

#[cfg(feature = "tier2-hot")]
/// Redis hot backend - uses redis-rs client with connection manager
#[derive(Clone)]
pub struct RedisHot {
    manager: ConnectionManager,
}

#[cfg(feature = "tier2-hot")]
impl std::fmt::Debug for RedisHot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisHot")
            .field("manager", &"<ConnectionManager>")
            .finish()
    }
}

#[cfg(feature = "tier2-hot")]
impl RedisHot {
    pub async fn new(connection_string: String, _pool_size: usize) -> Result<Self> {
        // Initialize Redis connection manager (handles connection pooling internally)
        let client = redis::Client::open(connection_string.as_str()).map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to create Redis client: {}", e))
        })?;

        let manager = client.get_connection_manager().await.map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to connect to Redis: {}", e))
        })?;

        Ok(Self { manager })
    }

    pub async fn ping(&self) -> Result<bool> {
        let mut conn = self.manager.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map(|_| true)
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("Redis PING failed: {}", e)))
    }

    /// Helper to convert RedisError to NameServerError
    fn map_redis_err(e: RedisError) -> NameServerError {
        NameServerError::Other(anyhow::anyhow!("Redis error: {}", e))
    }
}

#[cfg(feature = "tier2-hot")]
#[async_trait]
impl HotBackend for RedisHot {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.manager.clone();
        conn.get(key).await.map_err(Self::map_redis_err)
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl_secs: Option<u64>) -> Result<()> {
        let mut conn = self.manager.clone();
        if let Some(ttl) = ttl_secs {
            // SET key value EX ttl_secs
            conn.set_ex(key, value, ttl)
                .await
                .map_err(Self::map_redis_err)
        } else {
            // SET key value
            conn.set(key, value).await.map_err(Self::map_redis_err)
        }
    }

    async fn del(&self, key: &str) -> Result<bool> {
        let mut conn = self.manager.clone();
        let deleted: i32 = conn.del(key).await.map_err(Self::map_redis_err)?;
        Ok(deleted > 0)
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let mut conn = self.manager.clone();
        conn.exists(key).await.map_err(Self::map_redis_err)
    }

    async fn expire(&self, key: &str, ttl_secs: u64) -> Result<bool> {
        let mut conn = self.manager.clone();
        conn.expire(key, ttl_secs as i64)
            .await
            .map_err(Self::map_redis_err)
    }

    async fn incr(&self, key: &str) -> Result<i64> {
        let mut conn = self.manager.clone();
        conn.incr(key, 1).await.map_err(Self::map_redis_err)
    }

    async fn incr_by(&self, key: &str, amount: i64) -> Result<i64> {
        let mut conn = self.manager.clone();
        conn.incr(key, amount).await.map_err(Self::map_redis_err)
    }

    async fn decr(&self, key: &str) -> Result<i64> {
        let mut conn = self.manager.clone();
        conn.decr(key, 1).await.map_err(Self::map_redis_err)
    }

    async fn hset(&self, key: &str, field: &str, value: Vec<u8>) -> Result<()> {
        let mut conn = self.manager.clone();
        conn.hset(key, field, value)
            .await
            .map_err(Self::map_redis_err)
    }

    async fn hget(&self, key: &str, field: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.manager.clone();
        conn.hget(key, field).await.map_err(Self::map_redis_err)
    }

    async fn hgetall(&self, key: &str) -> Result<HashMap<String, Vec<u8>>> {
        let mut conn = self.manager.clone();
        conn.hgetall(key).await.map_err(Self::map_redis_err)
    }

    async fn hdel(&self, key: &str, field: &str) -> Result<bool> {
        let mut conn = self.manager.clone();
        let deleted: i32 = conn.hdel(key, field).await.map_err(Self::map_redis_err)?;
        Ok(deleted > 0)
    }

    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut conn = self.manager.clone();
        conn.get(keys).await.map_err(Self::map_redis_err)
    }

    async fn mset(&self, pairs: &[(&str, Vec<u8>)]) -> Result<()> {
        let mut conn = self.manager.clone();
        // Convert pairs to flat array for Redis MSET
        let flat: Vec<_> = pairs
            .iter()
            .flat_map(|(k, v)| vec![k.as_bytes(), v.as_slice()])
            .collect();

        redis::cmd("MSET")
            .arg(&flat)
            .query_async(&mut conn)
            .await
            .map_err(Self::map_redis_err)
    }

    async fn flush(&self) -> Result<()> {
        let mut conn = self.manager.clone();
        redis::cmd("FLUSHDB")
            .query_async(&mut conn)
            .await
            .map_err(Self::map_redis_err)
    }

    fn capabilities(&self) -> HotBackendCapabilities {
        HotBackendCapabilities {
            persistent: true, // RDB/AOF snapshots
            ttl_support: true,
            atomic_ops: true,
            pubsub: true,
            distributed: false, // Single-node (use Redis Cluster for distributed)
            latency_us: 1000,   // ~1ms network latency
            max_throughput: Some(100_000), // ~100k ops/sec for single-node Redis
        }
    }

    fn name(&self) -> &'static str {
        "redis"
    }
}

// Placeholder stubs for non-tier2 builds
#[cfg(not(feature = "tier2-hot"))]
pub struct RedisHot;

#[cfg(not(feature = "tier2-hot"))]
impl RedisHot {
    pub async fn new(_connection_string: String, _pool_size: usize) -> crate::error::Result<Self> {
        Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "Redis backend requires tier2-hot feature"
        )))
    }

    pub async fn ping(&self) -> crate::error::Result<bool> {
        Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "Redis backend requires tier2-hot feature"
        )))
    }
}
