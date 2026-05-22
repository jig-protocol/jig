//! Hot backend implementations
//!
//! This module provides different implementations of the HotBackend trait
//! for various caching/ephemeral state systems.

pub mod memory;
pub mod redis;
pub mod scylla;

// Re-export for convenience
pub use memory::InMemoryHot;
pub use redis::RedisHot;
pub use scylla::ScyllaHot;

use crate::error::{NameServerError, Result};
use crate::hot::backend::HotBackend;
use std::collections::HashMap;

/// Create a hot backend from config
///
/// This factory function creates the appropriate hot backend based on
/// the backend type specified in the config.
pub fn create_hot_backend(
    backend_type: &str,
    backend_config: &HashMap<String, String>,
) -> Result<Box<dyn HotBackend>> {
    match backend_type {
        "memory" | "inmemory" => {
            // In-memory backend (Tier 1 default)
            Ok(Box::new(InMemoryHot::new()))
        }

        "redis" | "valkey" | "dragonfly" => {
            // Redis-protocol compatible backends (Tier 2)
            #[cfg(feature = "tier2-hot")]
            {
                let connection_string = backend_config
                    .get("connection_string")
                    .ok_or_else(|| {
                        NameServerError::Other(anyhow::anyhow!(
                            "Redis backend requires 'connection_string' in backend_config"
                        ))
                    })?
                    .clone();

                let pool_size = backend_config
                    .get("pool_size")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(5);

                // Note: All three (redis/valkey/dragonfly) use the same Redis protocol
                // The connection_string determines which you're connecting to
                let backend = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(async { RedisHot::new(connection_string, pool_size).await })
                })?;

                Ok(Box::new(backend))
            }

            #[cfg(not(feature = "tier2-hot"))]
            {
                let _ = backend_config;
                Err(NameServerError::Other(anyhow::anyhow!(
                    "Redis backend requires tier2-hot feature. Build with: cargo build --features tier2-hot"
                )))
            }
        }

        "scylladb" | "scylla" | "cassandra" => {
            // ScyllaDB/Cassandra backend (Tier 3)
            #[cfg(feature = "tier3-hot")]
            {
                let nodes_str = backend_config.get("nodes").ok_or_else(|| {
                    NameServerError::Other(anyhow::anyhow!(
                        "ScyllaDB backend requires 'nodes' (comma-separated) in backend_config"
                    ))
                })?;

                let nodes: Vec<String> =
                    nodes_str.split(',').map(|s| s.trim().to_string()).collect();

                let keyspace = backend_config
                    .get("keyspace")
                    .cloned()
                    .unwrap_or_else(|| "jig_hot".to_string());

                let backend = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(async { ScyllaHot::new(nodes, keyspace).await })
                })?;

                Ok(Box::new(backend))
            }

            #[cfg(not(feature = "tier3-hot"))]
            {
                let _ = backend_config;
                Err(NameServerError::Other(anyhow::anyhow!(
                    "ScyllaDB backend requires tier3-hot feature. Build with: cargo build --features tier3-hot"
                )))
            }
        }

        _ => Err(NameServerError::Other(anyhow::anyhow!(
            "Unknown hot backend: '{}'. Supported: memory, redis, valkey, dragonfly, scylladb",
            backend_type
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_backend_creation() {
        let config = HashMap::new();
        let backend = create_hot_backend("memory", &config);
        assert!(backend.is_ok());
    }

    #[test]
    fn test_unknown_backend() {
        let config = HashMap::new();
        let result = create_hot_backend("unknown", &config);
        assert!(result.is_err());
    }

    #[cfg(not(feature = "tier2-hot"))]
    #[test]
    fn test_redis_requires_feature() {
        let mut config = HashMap::new();
        config.insert(
            "connection_string".to_string(),
            "redis://localhost".to_string(),
        );
        let result = create_hot_backend("redis", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tier2-hot"));
    }
}
