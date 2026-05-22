//! Analytics and Telemetry Configuration
//!
//! This module provides configuration for analytics backends (DuckDB, Parquet, ClickHouse)
//! and telemetry systems (metrics, tracing, logging) with profile-based defaults.
//!
//! ## Profile Defaults
//!
//! - **Potato**: DuckDB local storage, basic metrics, minimal overhead
//! - **Standard**: Parquet files, moderate sampling, structured logging
//! - **Hyperscale**: ClickHouse, full telemetry, OpenTelemetry integration
//!
//! ## Hot-Reload Support
//!
//! Most analytics and telemetry settings are hot-reloadable for operational flexibility:
//! - ✅ Sample rates, retention periods, log levels
//! - ✅ Metrics endpoints, trace sampling
//! - ❌ Backend type changes (require restart for connection pool)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Analytics Configuration
// ============================================================================

/// Analytics backend type
///
/// **Hot-reload:** No (requires restart)
/// **Reason:** Backend changes require new connection pools and storage initialization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AnalyticsBackend {
    /// DuckDB embedded analytics (potato/standard default)
    DuckDB,
    /// Parquet files on local/distributed filesystem
    Parquet,
    /// ClickHouse for hyperscale analytics
    ClickHouse,
    /// Analytics disabled
    Disabled,
}

/// Privacy mode for analytics data collection
///
/// **Hot-reload:** Yes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PrivacyMode {
    /// Anonymized - PII removed, hashed identifiers
    Anonymized,
    /// Aggregated - Summary statistics only, no individual records
    Aggregated,
    /// Full - Complete data retention (requires explicit consent)
    Full,
}

/// DuckDB-specific configuration
///
/// **Hot-reload:** Partial (path no, settings yes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DuckDBConfig {
    /// Path to DuckDB database file
    ///
    /// **Hot-reload:** No (requires reconnection)
    #[serde(default = "default_duckdb_path")]
    pub path: String,

    /// Memory limit in MB
    ///
    /// **Hot-reload:** Yes (via PRAGMA)
    #[serde(default = "default_duckdb_memory_limit")]
    pub memory_limit_mb: u32,

    /// Number of threads
    ///
    /// **Hot-reload:** Yes (via PRAGMA)
    #[serde(default = "default_duckdb_threads")]
    pub threads: u32,

    /// Enable read-only mode
    ///
    /// **Hot-reload:** No
    #[serde(default)]
    pub read_only: bool,
}

fn default_duckdb_path() -> String {
    "~/.jig/analytics.duckdb".to_string()
}

fn default_duckdb_memory_limit() -> u32 {
    512 // MB
}

fn default_duckdb_threads() -> u32 {
    4
}

/// Parquet-specific configuration
///
/// **Hot-reload:** Partial (path no, settings yes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParquetConfig {
    /// Base path for Parquet files
    ///
    /// **Hot-reload:** No
    #[serde(default = "default_parquet_path")]
    pub path: String,

    /// Partition by (e.g., "year", "month", "day")
    ///
    /// **Hot-reload:** No (affects file structure)
    #[serde(default = "default_parquet_partition")]
    pub partition_by: String,

    /// Compression algorithm
    ///
    /// **Hot-reload:** Yes (for new files)
    #[serde(default = "default_parquet_compression")]
    pub compression: String,

    /// Row group size
    ///
    /// **Hot-reload:** Yes (for new files)
    #[serde(default = "default_parquet_row_group_size")]
    pub row_group_size: u32,
}

fn default_parquet_path() -> String {
    "~/.jig/analytics/parquet".to_string()
}

fn default_parquet_partition() -> String {
    "day".to_string()
}

fn default_parquet_compression() -> String {
    "snappy".to_string()
}

fn default_parquet_row_group_size() -> u32 {
    50_000
}

/// ClickHouse-specific configuration
///
/// **Hot-reload:** Partial (connection string no, settings yes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClickHouseConfig {
    /// Connection DSN (e.g., "tcp://clickhouse.internal:9000")
    ///
    /// **Hot-reload:** No (requires reconnection)
    pub dsn: String,

    /// Database name
    ///
    /// **Hot-reload:** No
    #[serde(default = "default_clickhouse_database")]
    pub database: String,

    /// Batch size for inserts
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_clickhouse_batch_size")]
    pub batch_size: u32,

    /// Flush interval (seconds)
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_clickhouse_flush_interval")]
    pub flush_interval_secs: u32,

    /// Connection pool size
    ///
    /// **Hot-reload:** No
    #[serde(default = "default_clickhouse_pool_size")]
    pub pool_size: u32,

    /// Use compression for inserts
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_true")]
    pub compression: bool,
}

fn default_clickhouse_database() -> String {
    "jig_analytics".to_string()
}

fn default_clickhouse_batch_size() -> u32 {
    1000
}

fn default_clickhouse_flush_interval() -> u32 {
    60
}

fn default_clickhouse_pool_size() -> u32 {
    10
}

/// Complete analytics configuration
///
/// **Hot-reload:** Partial (backend no, settings yes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalyticsConfig {
    /// Analytics backend
    ///
    /// **Hot-reload:** No (requires restart)
    #[serde(default)]
    pub backend: AnalyticsBackend,

    /// Data retention period (days)
    ///
    /// **Hot-reload:** Yes (affects new deletions)
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,

    /// Sample rate (0.0 to 1.0)
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,

    /// Privacy mode
    ///
    /// **Hot-reload:** Yes
    #[serde(default)]
    pub privacy_mode: PrivacyMode,

    /// DuckDB-specific configuration
    #[serde(default)]
    pub duckdb: Option<DuckDBConfig>,

    /// Parquet-specific configuration
    #[serde(default)]
    pub parquet: Option<ParquetConfig>,

    /// ClickHouse-specific configuration
    #[serde(default)]
    pub clickhouse: Option<ClickHouseConfig>,
}

fn default_retention_days() -> u32 {
    90
}

fn default_sample_rate() -> f64 {
    1.0 // 100% by default
}

impl Default for AnalyticsBackend {
    fn default() -> Self {
        Self::DuckDB
    }
}

impl Default for PrivacyMode {
    fn default() -> Self {
        Self::Anonymized
    }
}

impl Default for DuckDBConfig {
    fn default() -> Self {
        Self {
            path: default_duckdb_path(),
            memory_limit_mb: default_duckdb_memory_limit(),
            threads: default_duckdb_threads(),
            read_only: false,
        }
    }
}

impl Default for ParquetConfig {
    fn default() -> Self {
        Self {
            path: default_parquet_path(),
            partition_by: default_parquet_partition(),
            compression: default_parquet_compression(),
            row_group_size: default_parquet_row_group_size(),
        }
    }
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            backend: AnalyticsBackend::DuckDB,
            retention_days: default_retention_days(),
            sample_rate: default_sample_rate(),
            privacy_mode: PrivacyMode::Anonymized,
            duckdb: Some(DuckDBConfig::default()),
            parquet: None,
            clickhouse: None,
        }
    }
}

// ============================================================================
// Telemetry Configuration
// ============================================================================

/// Log level enumeration
///
/// **Hot-reload:** Yes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Metrics export format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum MetricsFormat {
    /// Prometheus exposition format
    Prometheus,
    /// OpenTelemetry Protocol
    OTLP,
    /// StatsD protocol
    StatsD,
    /// JSON over HTTP
    Json,
}

/// OpenTelemetry configuration
///
/// **Hot-reload:** Partial (endpoint no, sampling yes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenTelemetryConfig {
    /// Enable OpenTelemetry integration
    ///
    /// **Hot-reload:** No (requires exporter initialization)
    #[serde(default)]
    pub enabled: bool,

    /// OTLP endpoint
    ///
    /// **Hot-reload:** No
    #[serde(default = "default_otlp_endpoint")]
    pub endpoint: String,

    /// Service name for traces
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Service version
    ///
    /// **Hot-reload:** Yes
    #[serde(default)]
    pub service_version: Option<String>,

    /// Environment (dev, staging, prod)
    ///
    /// **Hot-reload:** Yes
    #[serde(default)]
    pub environment: Option<String>,

    /// Additional resource attributes
    ///
    /// **Hot-reload:** Yes
    #[serde(default)]
    pub resource_attributes: HashMap<String, String>,
}

fn default_otlp_endpoint() -> String {
    "http://localhost:4317".to_string()
}

fn default_service_name() -> String {
    "jig-server".to_string()
}

/// Complete telemetry configuration
///
/// **Hot-reload:** Partial (endpoints no, settings yes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryConfig {
    /// Enable metrics collection
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,

    /// Metrics endpoint
    ///
    /// **Hot-reload:** No (requires HTTP server restart)
    #[serde(default = "default_metrics_endpoint")]
    pub metrics_endpoint: String,

    /// Metrics export format
    ///
    /// **Hot-reload:** No
    #[serde(default)]
    pub metrics_format: MetricsFormat,

    /// Trace sampling rate (0.0 to 1.0)
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_trace_sampling")]
    pub trace_sampling: f64,

    /// Log level
    ///
    /// **Hot-reload:** Yes
    #[serde(default)]
    pub log_level: LogLevel,

    /// Enable structured logging (JSON)
    ///
    /// **Hot-reload:** Yes
    #[serde(default)]
    pub structured_logging: bool,

    /// Enable stdout logging
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_true")]
    pub stdout_logging: bool,

    /// Log file path (optional)
    ///
    /// **Hot-reload:** No
    #[serde(default)]
    pub log_file_path: Option<String>,

    /// Log file rotation size (MB)
    ///
    /// **Hot-reload:** Yes
    #[serde(default = "default_log_rotation_size")]
    pub log_rotation_size_mb: u32,

    /// OpenTelemetry configuration
    #[serde(default)]
    pub opentelemetry: Option<OpenTelemetryConfig>,
}

fn default_metrics_endpoint() -> String {
    "http://localhost:9090/metrics".to_string()
}

fn default_trace_sampling() -> f64 {
    0.01 // 1%
}

fn default_log_rotation_size() -> u32 {
    100 // MB
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Info
    }
}

impl Default for MetricsFormat {
    fn default() -> Self {
        Self::Prometheus
    }
}

impl Default for OpenTelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otlp_endpoint(),
            service_name: default_service_name(),
            service_version: None,
            environment: None,
            resource_attributes: HashMap::new(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: default_true(),
            metrics_endpoint: default_metrics_endpoint(),
            metrics_format: MetricsFormat::Prometheus,
            trace_sampling: default_trace_sampling(),
            log_level: LogLevel::Info,
            structured_logging: false,
            stdout_logging: default_true(),
            log_file_path: None,
            log_rotation_size_mb: default_log_rotation_size(),
            opentelemetry: None,
        }
    }
}

fn default_true() -> bool {
    true
}

// ============================================================================
// Profile-Specific Defaults
// ============================================================================

impl AnalyticsConfig {
    /// Potato profile: DuckDB local storage, minimal overhead
    pub fn potato() -> Self {
        Self {
            backend: AnalyticsBackend::DuckDB,
            retention_days: 30, // 1 month
            sample_rate: 0.1,   // 10% sampling for low overhead
            privacy_mode: PrivacyMode::Anonymized,
            duckdb: Some(DuckDBConfig {
                path: "~/.jig/analytics.duckdb".to_string(),
                memory_limit_mb: 256, // Lower for potato
                threads: 2,
                read_only: false,
            }),
            parquet: None,
            clickhouse: None,
        }
    }

    /// Standard profile: Parquet files, moderate sampling
    pub fn standard() -> Self {
        Self {
            backend: AnalyticsBackend::Parquet,
            retention_days: 90, // 3 months
            sample_rate: 0.5,   // 50% sampling
            privacy_mode: PrivacyMode::Anonymized,
            duckdb: None,
            parquet: Some(ParquetConfig::default()),
            clickhouse: None,
        }
    }

    /// Hyperscale profile: ClickHouse, full telemetry
    pub fn hyperscale() -> Self {
        Self {
            backend: AnalyticsBackend::ClickHouse,
            retention_days: 365, // 1 year
            sample_rate: 1.0,    // 100% sampling
            privacy_mode: PrivacyMode::Aggregated,
            duckdb: None,
            parquet: None,
            clickhouse: Some(ClickHouseConfig {
                dsn: "tcp://clickhouse.internal:9000".to_string(),
                database: default_clickhouse_database(),
                batch_size: 5000, // Larger batches for hyperscale
                flush_interval_secs: 30,
                pool_size: 20,
                compression: true,
            }),
        }
    }
}

impl TelemetryConfig {
    /// Potato profile: Basic metrics, minimal tracing
    pub fn potato() -> Self {
        Self {
            metrics_enabled: true,
            metrics_endpoint: "http://localhost:9090/metrics".to_string(),
            metrics_format: MetricsFormat::Prometheus,
            trace_sampling: 0.01, // 1% tracing
            log_level: LogLevel::Info,
            structured_logging: false,
            stdout_logging: true,
            log_file_path: None,
            log_rotation_size_mb: 50,
            opentelemetry: None,
        }
    }

    /// Standard profile: Full metrics, moderate tracing, structured logs
    pub fn standard() -> Self {
        Self {
            metrics_enabled: true,
            metrics_endpoint: "http://localhost:9090/metrics".to_string(),
            metrics_format: MetricsFormat::Prometheus,
            trace_sampling: 0.1, // 10% tracing
            log_level: LogLevel::Info,
            structured_logging: true,
            stdout_logging: true,
            log_file_path: Some("/var/log/jig/server.log".to_string()),
            log_rotation_size_mb: 100,
            opentelemetry: None,
        }
    }

    /// Hyperscale profile: Full telemetry with OpenTelemetry
    pub fn hyperscale() -> Self {
        Self {
            metrics_enabled: true,
            metrics_endpoint: "http://localhost:9090/metrics".to_string(),
            metrics_format: MetricsFormat::OTLP,
            trace_sampling: 1.0, // 100% tracing
            log_level: LogLevel::Debug,
            structured_logging: true,
            stdout_logging: true,
            log_file_path: Some("/var/log/jig/server.log".to_string()),
            log_rotation_size_mb: 500,
            opentelemetry: Some(OpenTelemetryConfig {
                enabled: true,
                endpoint: "http://localhost:4317".to_string(),
                service_name: "jig-server".to_string(),
                service_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                environment: Some("production".to_string()),
                resource_attributes: HashMap::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analytics_backend_serialization() {
        let duckdb = AnalyticsBackend::DuckDB;
        let parquet = AnalyticsBackend::Parquet;
        let clickhouse = AnalyticsBackend::ClickHouse;
        let disabled = AnalyticsBackend::Disabled;

        assert_eq!(serde_json::to_string(&duckdb).unwrap(), r#""duckdb""#);
        assert_eq!(serde_json::to_string(&parquet).unwrap(), r#""parquet""#);
        assert_eq!(
            serde_json::to_string(&clickhouse).unwrap(),
            r#""clickhouse""#
        );
        assert_eq!(serde_json::to_string(&disabled).unwrap(), r#""disabled""#);
    }

    #[test]
    fn test_privacy_mode_serialization() {
        let anon = PrivacyMode::Anonymized;
        let agg = PrivacyMode::Aggregated;
        let full = PrivacyMode::Full;

        assert_eq!(serde_json::to_string(&anon).unwrap(), r#""anonymized""#);
        assert_eq!(serde_json::to_string(&agg).unwrap(), r#""aggregated""#);
        assert_eq!(serde_json::to_string(&full).unwrap(), r#""full""#);
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_analytics_config_potato() {
        let config = AnalyticsConfig::potato();
        assert_eq!(config.backend, AnalyticsBackend::DuckDB);
        assert_eq!(config.retention_days, 30);
        assert_eq!(config.sample_rate, 0.1);
        assert!(config.duckdb.is_some());
    }

    #[test]
    fn test_analytics_config_standard() {
        let config = AnalyticsConfig::standard();
        assert_eq!(config.backend, AnalyticsBackend::Parquet);
        assert_eq!(config.retention_days, 90);
        assert_eq!(config.sample_rate, 0.5);
        assert!(config.parquet.is_some());
    }

    #[test]
    fn test_analytics_config_hyperscale() {
        let config = AnalyticsConfig::hyperscale();
        assert_eq!(config.backend, AnalyticsBackend::ClickHouse);
        assert_eq!(config.retention_days, 365);
        assert_eq!(config.sample_rate, 1.0);
        assert!(config.clickhouse.is_some());
    }

    #[test]
    fn test_telemetry_config_potato() {
        let config = TelemetryConfig::potato();
        assert!(config.metrics_enabled);
        assert_eq!(config.trace_sampling, 0.01);
        assert_eq!(config.log_level, LogLevel::Info);
        assert!(!config.structured_logging);
        assert!(config.opentelemetry.is_none());
    }

    #[test]
    fn test_telemetry_config_standard() {
        let config = TelemetryConfig::standard();
        assert!(config.metrics_enabled);
        assert_eq!(config.trace_sampling, 0.1);
        assert!(config.structured_logging);
        assert!(config.log_file_path.is_some());
    }

    #[test]
    fn test_telemetry_config_hyperscale() {
        let config = TelemetryConfig::hyperscale();
        assert!(config.metrics_enabled);
        assert_eq!(config.trace_sampling, 1.0);
        assert_eq!(config.log_level, LogLevel::Debug);
        assert!(config.opentelemetry.is_some());
        assert!(config.opentelemetry.as_ref().unwrap().enabled);
    }

    #[test]
    fn test_duckdb_config_defaults() {
        let config = DuckDBConfig::default();
        assert_eq!(config.path, "~/.jig/analytics.duckdb");
        assert_eq!(config.memory_limit_mb, 512);
        assert_eq!(config.threads, 4);
        assert!(!config.read_only);
    }

    #[test]
    fn test_clickhouse_config_defaults() {
        let config = ClickHouseConfig {
            dsn: "tcp://localhost:9000".to_string(),
            database: "test".to_string(),
            batch_size: default_clickhouse_batch_size(),
            flush_interval_secs: default_clickhouse_flush_interval(),
            pool_size: default_clickhouse_pool_size(),
            compression: true,
        };

        assert_eq!(config.batch_size, 1000);
        assert_eq!(config.flush_interval_secs, 60);
        assert_eq!(config.pool_size, 10);
        assert!(config.compression);
    }
}
