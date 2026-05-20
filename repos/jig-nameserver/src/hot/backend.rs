//! Hot backend trait abstraction
//!
//! Defines the interface for hot/ephemeral state backends with TTL support.

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Hot backend capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotBackendCapabilities {
    /// Supports persistence (RDB/AOF snapshots)
    pub persistent: bool,

    /// Supports TTL on individual keys
    pub ttl_support: bool,

    /// Supports atomic increment/decrement
    pub atomic_ops: bool,

    /// Supports pub/sub
    pub pubsub: bool,

    /// Distributed/clustered
    pub distributed: bool,

    /// Typical latency in microseconds
    pub latency_us: u32,

    /// Max throughput (ops/sec)
    pub max_throughput: Option<u64>,
}

/// Hot backend trait - ephemeral state with TTL
#[async_trait]
pub trait HotBackend: Send + Sync + std::fmt::Debug {
    // ===== Basic Key-Value Operations =====

    /// Get value by key
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Set value with optional TTL (in seconds)
    async fn set(&self, key: &str, value: Vec<u8>, ttl_secs: Option<u64>) -> Result<()>;

    /// Delete key
    async fn del(&self, key: &str) -> Result<bool>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> Result<bool>;

    /// Set expiry on existing key (in seconds)
    async fn expire(&self, key: &str, ttl_secs: u64) -> Result<bool>;

    // ===== Atomic Operations =====

    /// Increment integer value (returns new value)
    async fn incr(&self, key: &str) -> Result<i64>;

    /// Increment by amount (returns new value)
    async fn incr_by(&self, key: &str, amount: i64) -> Result<i64>;

    /// Decrement integer value (returns new value)
    async fn decr(&self, key: &str) -> Result<i64>;

    // ===== Hash Operations (for complex objects) =====

    /// Set hash field
    async fn hset(&self, key: &str, field: &str, value: Vec<u8>) -> Result<()>;

    /// Get hash field
    async fn hget(&self, key: &str, field: &str) -> Result<Option<Vec<u8>>>;

    /// Get all hash fields
    async fn hgetall(&self, key: &str) -> Result<HashMap<String, Vec<u8>>>;

    /// Delete hash field
    async fn hdel(&self, key: &str, field: &str) -> Result<bool>;

    // ===== Batch Operations =====

    /// Get multiple keys at once
    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>>;

    /// Set multiple keys at once
    async fn mset(&self, pairs: &[(&str, Vec<u8>)]) -> Result<()>;

    // ===== Maintenance =====

    /// Flush all keys (for testing)
    async fn flush(&self) -> Result<()>;

    /// Backend capabilities
    fn capabilities(&self) -> HotBackendCapabilities;

    /// Backend name for config matching
    fn name(&self) -> &'static str;
}

/// Factory trait for creating hot backends from config
pub trait HotBackendFactory: Send + Sync {
    /// Create backend from config map
    fn create(&self, config: &HashMap<String, String>) -> Result<Box<dyn HotBackend>>;

    /// Backend name for registry lookup
    fn name(&self) -> &'static str;
}
