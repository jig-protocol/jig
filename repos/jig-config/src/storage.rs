//! Storage configuration for layered architecture
//!
//! Supports four storage tiers:
//! - **Truth**: ACID-compliant source of truth (SQLite, Postgres, CockroachDB)
//! - **Speed**: High-throughput writes and reads (ScyllaDB, Redis)
//! - **Intelligence**: Analytics and aggregations (ClickHouse, DuckDB, Parquet)
//! - **Archive**: Long-term cold storage (S3, filesystem)

use serde::{Deserialize, Serialize};

use crate::profiles::Profile;

/// Storage tier in layered architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageTier {
    /// Truth layer: ACID-compliant source of truth
    Truth,

    /// Speed layer: High-throughput real-time operations
    Speed,

    /// Intelligence layer: Analytics and aggregations
    Intelligence,

    /// Archive layer: Long-term cold storage
    Archive,
}

/// Storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// SQLite (default, zero-config)
    Sqlite,

    /// PostgreSQL (standard RDBMS)
    Postgres,

    /// CockroachDB (distributed SQL)
    #[serde(rename = "cockroachdb")]
    CockroachDB,

    /// ScyllaDB (Cassandra-compatible, high-throughput)
    #[serde(rename = "scylladb")]
    ScyllaDB,

    /// ClickHouse (columnar analytics)
    #[serde(rename = "clickhouse")]
    ClickHouse,

    /// DuckDB (embedded analytics)
    #[serde(rename = "duckdb")]
    DuckDB,

    /// Parquet (columnar file format)
    Parquet,

    /// S3 (object storage)
    S3,

    /// Redis (in-memory cache)
    Redis,

    /// In-memory (for testing)
    Memory,
}

/// Configuration for a storage layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageLayerConfig {
    /// Backend type
    pub backend: Backend,

    /// Connection string (used by SQL databases)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_string: Option<String>,

    /// Maximum connections (for pooled backends)
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Cache size in MB
    #[serde(default = "default_cache_size")]
    pub cache_size_mb: usize,

    /// SQLite-specific: Enable WAL mode
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub sqlite_wal: bool,

    /// ScyllaDB-specific: Contact points
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_points: Option<Vec<String>>,

    /// ScyllaDB-specific: Keyspace
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyspace: Option<String>,

    /// ScyllaDB-specific: Replication factor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replication_factor: Option<u32>,

    /// ScyllaDB-specific: Consistency level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistency_level: Option<String>,

    /// ClickHouse/DuckDB: Batch size for bulk operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<usize>,

    /// ClickHouse/DuckDB: Flush interval in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flush_interval_sec: Option<u32>,

    /// ClickHouse: Compression algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<String>,

    /// S3-specific: Bucket name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,

    /// S3-specific: Region
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// S3-specific: Custom endpoint (for S3-compatible storage)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// S3-specific: Access key ID (can reference env var)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,

    /// S3-specific: Secret access key (can reference env var)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,

    /// Parquet-specific: Output directory path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Storage configuration (legacy single-tier)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend
    pub backend: Backend,

    /// Connection string (for external databases)
    pub connection_string: String,

    /// Maximum connections (for pooled backends)
    pub max_connections: usize,

    /// Enable WAL mode for SQLite
    pub sqlite_wal: bool,

    /// Cache size in MB
    pub cache_size_mb: usize,
}

/// Multi-tier storage configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MultiTierStorageConfig {
    /// Truth layer configuration (required)
    pub truth: Option<StorageLayerConfig>,

    /// Speed layer configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed: Option<StorageLayerConfig>,

    /// Intelligence layer configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intelligence: Option<StorageLayerConfig>,

    /// Archive layer configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<StorageLayerConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: Backend::Sqlite,
            connection_string: String::new(),
            max_connections: 10,
            sqlite_wal: true,
            cache_size_mb: 100,
        }
    }
}

impl StorageLayerConfig {
    /// Create default configuration for a given backend and profile
    pub fn default_for_backend(backend: Backend, profile: Profile) -> Self {
        match backend {
            Backend::Sqlite => Self {
                backend,
                connection_string: Some("~/.jig/jig.db".to_string()),
                max_connections: 10,
                cache_size_mb: profile.storage_cache_mb(),
                sqlite_wal: true,
                ..Default::default()
            },
            Backend::Postgres => Self {
                backend,
                connection_string: Some("postgres://localhost/jig".to_string()),
                max_connections: profile.storage_max_connections(),
                cache_size_mb: profile.storage_cache_mb(),
                ..Default::default()
            },
            Backend::CockroachDB => Self {
                backend,
                connection_string: Some(
                    "postgres://jig@cluster/jig?sslmode=verify-full".to_string(),
                ),
                max_connections: profile.storage_max_connections(),
                cache_size_mb: profile.storage_cache_mb(),
                ..Default::default()
            },
            Backend::ScyllaDB => Self {
                backend,
                contact_points: Some(vec!["127.0.0.1:9042".to_string()]),
                keyspace: Some("jig_speed".to_string()),
                replication_factor: Some(profile.scylla_replication_factor()),
                consistency_level: Some("QUORUM".to_string()),
                ..Default::default()
            },
            Backend::ClickHouse => Self {
                backend,
                connection_string: Some("tcp://localhost:9000/jig_analytics".to_string()),
                batch_size: Some(profile.analytics_batch_size()),
                flush_interval_sec: Some(30),
                compression: Some("lz4".to_string()),
                ..Default::default()
            },
            Backend::DuckDB => Self {
                backend,
                path: Some("~/.jig/analytics.duckdb".to_string()),
                batch_size: Some(1000),
                ..Default::default()
            },
            Backend::Parquet => Self {
                backend,
                path: Some("~/.jig/parquet/".to_string()),
                compression: Some("snappy".to_string()),
                ..Default::default()
            },
            Backend::S3 => Self {
                backend,
                bucket: Some("jig-blocks".to_string()),
                region: Some("us-east-1".to_string()),
                ..Default::default()
            },
            Backend::Redis => Self {
                backend,
                connection_string: Some("redis://localhost:6379".to_string()),
                max_connections: profile.storage_max_connections(),
                cache_size_mb: profile.storage_cache_mb(),
                ..Default::default()
            },
            Backend::Memory => Self {
                backend,
                cache_size_mb: 100,
                ..Default::default()
            },
        }
    }

    /// Validate configuration for the specified backend
    pub fn validate(&self) -> Result<(), String> {
        match self.backend {
            Backend::Sqlite | Backend::Postgres | Backend::CockroachDB => {
                if self.connection_string.is_none()
                    || self.connection_string.as_ref().unwrap().is_empty()
                {
                    return Err(format!("{:?} requires connection_string", self.backend));
                }
            }
            Backend::ScyllaDB => {
                if self.contact_points.is_none() || self.contact_points.as_ref().unwrap().is_empty()
                {
                    return Err("ScyllaDB requires contact_points".to_string());
                }
                if self.keyspace.is_none() {
                    return Err("ScyllaDB requires keyspace".to_string());
                }
            }
            Backend::ClickHouse | Backend::Redis => {
                if self.connection_string.is_none() {
                    return Err(format!("{:?} requires connection_string", self.backend));
                }
            }
            Backend::DuckDB | Backend::Parquet => {
                if self.path.is_none() {
                    return Err(format!("{:?} requires path", self.backend));
                }
            }
            Backend::S3 => {
                if self.bucket.is_none() {
                    return Err("S3 requires bucket".to_string());
                }
                if self.region.is_none() {
                    return Err("S3 requires region".to_string());
                }
            }
            Backend::Memory => {
                // No validation needed
            }
        }

        Ok(())
    }
}

impl MultiTierStorageConfig {
    /// Create default configuration for a given profile
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self {
                truth: Some(StorageLayerConfig::default_for_backend(
                    Backend::Sqlite,
                    profile,
                )),
                speed: None,
                intelligence: Some(StorageLayerConfig::default_for_backend(
                    Backend::DuckDB,
                    profile,
                )),
                archive: None,
            },
            Profile::Standard => Self {
                truth: Some(StorageLayerConfig::default_for_backend(
                    Backend::Postgres,
                    profile,
                )),
                speed: Some(StorageLayerConfig::default_for_backend(
                    Backend::Redis,
                    profile,
                )),
                intelligence: Some(StorageLayerConfig::default_for_backend(
                    Backend::Parquet,
                    profile,
                )),
                archive: None,
            },
            Profile::Hyperscale => Self {
                truth: Some(StorageLayerConfig::default_for_backend(
                    Backend::CockroachDB,
                    profile,
                )),
                speed: Some(StorageLayerConfig::default_for_backend(
                    Backend::ScyllaDB,
                    profile,
                )),
                intelligence: Some(StorageLayerConfig::default_for_backend(
                    Backend::ClickHouse,
                    profile,
                )),
                archive: Some(StorageLayerConfig::default_for_backend(
                    Backend::S3,
                    profile,
                )),
            },
            Profile::Custom => Self {
                truth: None,
                speed: None,
                intelligence: None,
                archive: None,
            },
        }
    }

    /// Validate all configured storage layers
    pub fn validate(&self) -> Result<(), String> {
        // Truth layer is required
        if self.truth.is_none() {
            return Err("Truth storage layer is required".to_string());
        }

        // Validate each configured layer
        if let Some(ref truth) = self.truth {
            truth.validate()?;
        }
        if let Some(ref speed) = self.speed {
            speed.validate()?;
        }
        if let Some(ref intelligence) = self.intelligence {
            intelligence.validate()?;
        }
        if let Some(ref archive) = self.archive {
            archive.validate()?;
        }

        Ok(())
    }
}

impl Default for StorageLayerConfig {
    fn default() -> Self {
        Self {
            backend: Backend::Sqlite,
            connection_string: None,
            max_connections: 10,
            cache_size_mb: 100,
            sqlite_wal: true,
            contact_points: None,
            keyspace: None,
            replication_factor: None,
            consistency_level: None,
            batch_size: None,
            flush_interval_sec: None,
            compression: None,
            bucket: None,
            region: None,
            endpoint: None,
            access_key_id: None,
            secret_access_key: None,
            path: None,
        }
    }
}

// Serde helper functions
fn default_max_connections() -> usize {
    10
}

fn default_cache_size() -> usize {
    100
}

fn default_true() -> bool {
    true
}

fn is_default_true(val: &bool) -> bool {
    *val
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_tier_serialization() {
        let tier = StorageTier::Truth;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, r#""truth""#);

        let parsed: StorageTier = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tier);
    }

    #[test]
    fn test_backend_serialization() {
        let backends = vec![
            (Backend::Sqlite, r#""sqlite""#),
            (Backend::CockroachDB, r#""cockroachdb""#),
            (Backend::ScyllaDB, r#""scylladb""#),
            (Backend::ClickHouse, r#""clickhouse""#),
        ];

        for (backend, expected) in backends {
            let json = serde_json::to_string(&backend).unwrap();
            assert_eq!(json, expected);

            let parsed: Backend = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, backend);
        }
    }

    #[test]
    fn test_storage_layer_defaults() {
        let sqlite = StorageLayerConfig::default_for_backend(Backend::Sqlite, Profile::Potato);
        assert_eq!(sqlite.backend, Backend::Sqlite);
        assert!(sqlite.sqlite_wal);
        assert!(sqlite.connection_string.is_some());

        let scylla =
            StorageLayerConfig::default_for_backend(Backend::ScyllaDB, Profile::Hyperscale);
        assert_eq!(scylla.backend, Backend::ScyllaDB);
        assert!(scylla.contact_points.is_some());
        assert!(scylla.keyspace.is_some());
    }

    #[test]
    fn test_sqlite_validation() {
        let mut config = StorageLayerConfig::default_for_backend(Backend::Sqlite, Profile::Potato);
        assert!(config.validate().is_ok());

        // Missing connection_string
        config.connection_string = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_scylladb_validation() {
        let mut config =
            StorageLayerConfig::default_for_backend(Backend::ScyllaDB, Profile::Hyperscale);
        assert!(config.validate().is_ok());

        // Missing contact_points
        config.contact_points = None;
        assert!(config.validate().is_err());

        // Restore and test missing keyspace
        config.contact_points = Some(vec!["localhost:9042".to_string()]);
        config.keyspace = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_s3_validation() {
        let mut config = StorageLayerConfig::default_for_backend(Backend::S3, Profile::Hyperscale);
        assert!(config.validate().is_ok());

        // Missing bucket
        config.bucket = None;
        assert!(config.validate().is_err());

        // Restore bucket, remove region
        config.bucket = Some("test".to_string());
        config.region = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_multi_tier_potato_defaults() {
        let config = MultiTierStorageConfig::default_for_profile(Profile::Potato);

        assert!(config.truth.is_some());
        assert_eq!(config.truth.as_ref().unwrap().backend, Backend::Sqlite);

        assert!(config.speed.is_none());

        assert!(config.intelligence.is_some());
        assert_eq!(
            config.intelligence.as_ref().unwrap().backend,
            Backend::DuckDB
        );

        assert!(config.archive.is_none());
    }

    #[test]
    fn test_multi_tier_hyperscale_defaults() {
        let config = MultiTierStorageConfig::default_for_profile(Profile::Hyperscale);

        assert!(config.truth.is_some());
        assert_eq!(config.truth.as_ref().unwrap().backend, Backend::CockroachDB);

        assert!(config.speed.is_some());
        assert_eq!(config.speed.as_ref().unwrap().backend, Backend::ScyllaDB);

        assert!(config.intelligence.is_some());
        assert_eq!(
            config.intelligence.as_ref().unwrap().backend,
            Backend::ClickHouse
        );

        assert!(config.archive.is_some());
        assert_eq!(config.archive.as_ref().unwrap().backend, Backend::S3);
    }

    #[test]
    fn test_multi_tier_validation_requires_truth() {
        let config = MultiTierStorageConfig {
            truth: None,
            speed: None,
            intelligence: None,
            archive: None,
        };

        assert!(config.validate().is_err());
        assert!(
            config
                .validate()
                .unwrap_err()
                .contains("Truth storage layer is required")
        );
    }

    #[test]
    fn test_multi_tier_validation_validates_layers() {
        let mut config = MultiTierStorageConfig::default_for_profile(Profile::Potato);
        assert!(config.validate().is_ok());

        // Break truth layer
        config.truth.as_mut().unwrap().connection_string = None;
        assert!(config.validate().is_err());
    }
}
