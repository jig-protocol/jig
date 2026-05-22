//! Integration tests for multi-tier storage configuration.

use jig_config::profiles::Profile;
use jig_config::storage::{Backend, MultiTierStorageConfig, StorageLayerConfig};

#[test]
fn test_potato_profile_storage_defaults() {
    let config = MultiTierStorageConfig::default_for_profile(Profile::Potato);

    // Potato has truth (SQLite) and intelligence (DuckDB) only
    assert!(config.truth.is_some());
    assert_eq!(config.truth.as_ref().unwrap().backend, Backend::Sqlite);

    assert!(config.speed.is_none());

    assert!(config.intelligence.is_some());
    assert_eq!(
        config.intelligence.as_ref().unwrap().backend,
        Backend::DuckDB
    );

    assert!(config.archive.is_none());

    // Validation should pass
    assert!(config.validate().is_ok());
}

#[test]
fn test_standard_profile_storage_defaults() {
    let config = MultiTierStorageConfig::default_for_profile(Profile::Standard);

    // Standard has truth (Postgres), speed (Redis), intelligence (Parquet)
    assert!(config.truth.is_some());
    assert_eq!(config.truth.as_ref().unwrap().backend, Backend::Postgres);

    assert!(config.speed.is_some());
    assert_eq!(config.speed.as_ref().unwrap().backend, Backend::Redis);

    assert!(config.intelligence.is_some());
    assert_eq!(
        config.intelligence.as_ref().unwrap().backend,
        Backend::Parquet
    );

    assert!(config.archive.is_none());

    // Validation should pass
    assert!(config.validate().is_ok());
}

#[test]
fn test_hyperscale_profile_storage_defaults() {
    let config = MultiTierStorageConfig::default_for_profile(Profile::Hyperscale);

    // Hyperscale has all four tiers
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

    // Validation should pass
    assert!(config.validate().is_ok());
}

#[test]
fn test_custom_profile_requires_explicit_config() {
    let config = MultiTierStorageConfig::default_for_profile(Profile::Custom);

    // Custom has no defaults
    assert!(config.truth.is_none());
    assert!(config.speed.is_none());
    assert!(config.intelligence.is_none());
    assert!(config.archive.is_none());

    // Validation should fail (truth is required)
    assert!(config.validate().is_err());
}

#[test]
fn test_mixed_tier_configuration() {
    // Potato truth + Hyperscale intelligence
    let config = MultiTierStorageConfig {
        truth: Some(StorageLayerConfig::default_for_backend(
            Backend::Sqlite,
            Profile::Potato,
        )),
        speed: None,
        intelligence: Some(StorageLayerConfig::default_for_backend(
            Backend::ClickHouse,
            Profile::Hyperscale,
        )),
        archive: None,
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_toml_deserialization_potato() {
    let toml = r#"
        [truth]
        backend = "sqlite"
        connection_string = "~/.jig/jig.db"
        sqlite_wal = true
        max_connections = 10
        cache_size_mb = 100

        [intelligence]
        backend = "duckdb"
        path = "~/.jig/analytics.duckdb"
        batch_size = 1000
    "#;

    let config: MultiTierStorageConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert!(config.truth.is_some());
    assert_eq!(config.truth.as_ref().unwrap().backend, Backend::Sqlite);
    assert!(config.truth.as_ref().unwrap().sqlite_wal);

    assert!(config.intelligence.is_some());
    assert_eq!(
        config.intelligence.as_ref().unwrap().backend,
        Backend::DuckDB
    );

    assert!(config.validate().is_ok());
}

#[test]
fn test_toml_deserialization_hyperscale() {
    let toml = r#"
        [truth]
        backend = "cockroachdb"
        connection_string = "postgres://jig@cluster/jig?sslmode=verify-full"
        max_connections = 100
        cache_size_mb = 1024

        [speed]
        backend = "scylladb"
        contact_points = ["10.0.1.1:9042", "10.0.1.2:9042"]
        keyspace = "jig_speed"
        replication_factor = 3
        consistency_level = "QUORUM"

        [intelligence]
        backend = "clickhouse"
        connection_string = "tcp://analytics:9000/jig_analytics"
        batch_size = 10000
        flush_interval_sec = 30
        compression = "lz4"

        [archive]
        backend = "s3"
        bucket = "jig-blocks-prod"
        region = "us-east-1"
    "#;

    let config: MultiTierStorageConfig = toml::from_str(toml).expect("failed to parse TOML");

    assert!(config.truth.is_some());
    assert_eq!(config.truth.as_ref().unwrap().backend, Backend::CockroachDB);

    assert!(config.speed.is_some());
    assert_eq!(config.speed.as_ref().unwrap().backend, Backend::ScyllaDB);
    assert_eq!(
        config.speed.as_ref().unwrap().contact_points,
        Some(vec![
            "10.0.1.1:9042".to_string(),
            "10.0.1.2:9042".to_string()
        ])
    );

    assert!(config.intelligence.is_some());
    assert_eq!(
        config.intelligence.as_ref().unwrap().backend,
        Backend::ClickHouse
    );

    assert!(config.archive.is_some());
    assert_eq!(config.archive.as_ref().unwrap().backend, Backend::S3);

    assert!(config.validate().is_ok());
}

#[test]
fn test_validation_catches_missing_required_fields() {
    // SQLite without connection_string
    let toml = r#"
        [truth]
        backend = "sqlite"
        max_connections = 10
    "#;

    let config: MultiTierStorageConfig = toml::from_str(toml).expect("failed to parse TOML");
    assert!(config.validate().is_err());
}

#[test]
fn test_validation_catches_scylladb_missing_fields() {
    // ScyllaDB without keyspace
    let toml = r#"
        [truth]
        backend = "sqlite"
        connection_string = "~/.jig/jig.db"

        [speed]
        backend = "scylladb"
        contact_points = ["localhost:9042"]
    "#;

    let config: MultiTierStorageConfig = toml::from_str(toml).expect("failed to parse TOML");
    assert!(config.validate().is_err());
}

#[test]
fn test_validation_catches_s3_missing_fields() {
    // S3 without region
    let toml = r#"
        [truth]
        backend = "sqlite"
        connection_string = "~/.jig/jig.db"

        [archive]
        backend = "s3"
        bucket = "my-bucket"
    "#;

    let config: MultiTierStorageConfig = toml::from_str(toml).expect("failed to parse TOML");
    assert!(config.validate().is_err());
}

#[test]
fn test_profile_specific_cache_sizes() {
    let potato_sqlite = StorageLayerConfig::default_for_backend(Backend::Sqlite, Profile::Potato);
    let standard_sqlite =
        StorageLayerConfig::default_for_backend(Backend::Sqlite, Profile::Standard);
    let hyperscale_cockroach =
        StorageLayerConfig::default_for_backend(Backend::CockroachDB, Profile::Hyperscale);

    // Cache sizes scale with profile
    assert_eq!(potato_sqlite.cache_size_mb, 100);
    assert_eq!(standard_sqlite.cache_size_mb, 512);
    assert_eq!(hyperscale_cockroach.cache_size_mb, 1024);
}

#[test]
fn test_profile_specific_connection_limits() {
    let potato_pg = StorageLayerConfig::default_for_backend(Backend::Postgres, Profile::Potato);
    let standard_pg = StorageLayerConfig::default_for_backend(Backend::Postgres, Profile::Standard);
    let hyperscale_pg =
        StorageLayerConfig::default_for_backend(Backend::Postgres, Profile::Hyperscale);

    // Connection limits scale with profile
    assert_eq!(potato_pg.max_connections, 10);
    assert_eq!(standard_pg.max_connections, 50);
    assert_eq!(hyperscale_pg.max_connections, 100);
}

#[test]
fn test_scylladb_replication_scales() {
    let potato_scylla = StorageLayerConfig::default_for_backend(Backend::ScyllaDB, Profile::Potato);
    let standard_scylla =
        StorageLayerConfig::default_for_backend(Backend::ScyllaDB, Profile::Standard);
    let hyperscale_scylla =
        StorageLayerConfig::default_for_backend(Backend::ScyllaDB, Profile::Hyperscale);

    // Replication factor scales with profile
    assert_eq!(potato_scylla.replication_factor, Some(1));
    assert_eq!(standard_scylla.replication_factor, Some(2));
    assert_eq!(hyperscale_scylla.replication_factor, Some(3));
}

#[test]
fn test_toml_serialization_roundtrip() {
    let config = MultiTierStorageConfig::default_for_profile(Profile::Hyperscale);

    // Serialize to TOML
    let toml_str = toml::to_string(&config).expect("failed to serialize");

    // Deserialize back
    let parsed: MultiTierStorageConfig = toml::from_str(&toml_str).expect("failed to deserialize");

    // Should match original
    assert_eq!(
        config.truth.as_ref().unwrap().backend,
        parsed.truth.as_ref().unwrap().backend
    );
    assert_eq!(
        config.speed.as_ref().unwrap().backend,
        parsed.speed.as_ref().unwrap().backend
    );
    assert_eq!(
        config.intelligence.as_ref().unwrap().backend,
        parsed.intelligence.as_ref().unwrap().backend
    );
    assert_eq!(
        config.archive.as_ref().unwrap().backend,
        parsed.archive.as_ref().unwrap().backend
    );
}
