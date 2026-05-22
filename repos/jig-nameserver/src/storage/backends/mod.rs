//! Storage backend implementations
//!
//! This module provides different implementations of the NamesStorage trait
//! for various backend databases (SQLite, Postgres, CockroachDB, etc.)

pub mod postgres;

// Re-export for convenience
pub use postgres::PostgresStorage;

/// Create a storage backend from config
///
/// This factory function creates the appropriate storage backend based on
/// the backend type specified in the config.
pub async fn create_storage_backend(
    backend_type: &str,
    backend_config: &std::collections::HashMap<String, String>,
    fallback_path: Option<&std::path::Path>,
) -> crate::error::Result<std::sync::Arc<dyn crate::storage::NamesStorage>> {
    match backend_type {
        "sqlite" => {
            // Use database_path from config or fallback
            let path = if let Some(path_str) = backend_config.get("database_path") {
                std::path::PathBuf::from(path_str)
            } else if let Some(path) = fallback_path {
                path.to_path_buf()
            } else {
                return Err(crate::error::NameServerError::Other(anyhow::anyhow!(
                    "SQLite backend requires database_path"
                )));
            };

            let storage = crate::storage::SqliteStorage::new(path)?;
            Ok(std::sync::Arc::new(storage))
        }

        "postgres" => {
            #[cfg(feature = "tier2-storage")]
            {
                let connection_string = backend_config
                    .get("connection_string")
                    .ok_or_else(|| {
                        crate::error::NameServerError::Other(anyhow::anyhow!(
                            "Postgres backend requires 'connection_string' in backend_config"
                        ))
                    })?
                    .clone();

                let pool_size = backend_config
                    .get("pool_size")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(10);

                let storage = PostgresStorage::new(connection_string, pool_size).await?;
                storage.run_migrations().await?;
                Ok(std::sync::Arc::new(storage))
            }

            #[cfg(not(feature = "tier2-storage"))]
            {
                let _ = (backend_config, fallback_path);
                Err(crate::error::NameServerError::Other(anyhow::anyhow!(
                    "Postgres backend requires tier2-storage feature. Build with: cargo build --features tier2-storage"
                )))
            }
        }

        "cockroachdb" => {
            // TODO: Tier 3 - CockroachDB implementation
            let _ = (backend_config, fallback_path);
            Err(crate::error::NameServerError::Other(anyhow::anyhow!(
                "CockroachDB backend not yet implemented (Tier 3)"
            )))
        }

        "tidb" => {
            // TODO: Tier 3 - TiDB implementation
            let _ = (backend_config, fallback_path);
            Err(crate::error::NameServerError::Other(anyhow::anyhow!(
                "TiDB backend not yet implemented (Tier 3)"
            )))
        }

        _ => Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "Unknown storage backend: '{}'. Supported: sqlite, postgres, cockroachdb, tidb",
            backend_type
        ))),
    }
}
