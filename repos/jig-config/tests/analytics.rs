//! Integration tests for analytics and telemetry configuration

use jig_config::analytics::*;

// ============================================================================
// Analytics Backend Selection Tests
// ============================================================================

#[test]
fn test_potato_profile_uses_duckdb() {
    let config = AnalyticsConfig::potato();
    assert_eq!(config.backend, AnalyticsBackend::DuckDB);
    assert!(config.duckdb.is_some());
    assert!(config.parquet.is_none());
    assert!(config.clickhouse.is_none());
    assert_eq!(config.retention_days, 30);
    assert_eq!(config.sample_rate, 0.1);
}

#[test]
fn test_standard_profile_uses_parquet() {
    let config = AnalyticsConfig::standard();
    assert_eq!(config.backend, AnalyticsBackend::Parquet);
    assert!(config.duckdb.is_none());
    assert!(config.parquet.is_some());
    assert!(config.clickhouse.is_none());
    assert_eq!(config.retention_days, 90);
    assert_eq!(config.sample_rate, 0.5);
}

#[test]
fn test_hyperscale_profile_uses_clickhouse() {
    let config = AnalyticsConfig::hyperscale();
    assert_eq!(config.backend, AnalyticsBackend::ClickHouse);
    assert!(config.duckdb.is_none());
    assert!(config.parquet.is_none());
    assert!(config.clickhouse.is_some());
    assert_eq!(config.retention_days, 365);
    assert_eq!(config.sample_rate, 1.0);
}

// ============================================================================
// TOML Serialization Tests
// ============================================================================

#[test]
fn test_analytics_config_toml_roundtrip_duckdb() {
    let toml_str = r#"
backend = "duckdb"
retention_days = 30
sample_rate = 0.1
privacy_mode = "anonymized"

[duckdb]
path = "~/.jig/analytics.duckdb"
memory_limit_mb = 256
threads = 2
read_only = false
"#;

    let config: AnalyticsConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.backend, AnalyticsBackend::DuckDB);
    assert_eq!(config.retention_days, 30);
    assert_eq!(config.sample_rate, 0.1);
    assert!(config.duckdb.is_some());

    // Roundtrip
    let serialized = toml::to_string(&config).unwrap();
    let deserialized: AnalyticsConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(config.backend, deserialized.backend);
}

#[test]
fn test_analytics_config_toml_roundtrip_parquet() {
    let toml_str = r#"
backend = "parquet"
retention_days = 90
sample_rate = 0.5
privacy_mode = "aggregated"

[parquet]
path = "~/.jig/analytics/parquet"
partition_by = "day"
compression = "snappy"
row_group_size = 50000
"#;

    let config: AnalyticsConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.backend, AnalyticsBackend::Parquet);
    assert_eq!(config.privacy_mode, PrivacyMode::Aggregated);

    // Roundtrip
    let serialized = toml::to_string(&config).unwrap();
    let deserialized: AnalyticsConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(config.backend, deserialized.backend);
}

#[test]
fn test_analytics_config_toml_roundtrip_clickhouse() {
    let toml_str = r#"
backend = "clickhouse"
retention_days = 365
sample_rate = 1.0
privacy_mode = "full"

[clickhouse]
dsn = "tcp://clickhouse.internal:9000"
database = "jig_analytics"
batch_size = 5000
flush_interval_secs = 30
pool_size = 20
compression = true
"#;

    let config: AnalyticsConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.backend, AnalyticsBackend::ClickHouse);
    assert_eq!(config.privacy_mode, PrivacyMode::Full);
    assert_eq!(config.clickhouse.as_ref().unwrap().batch_size, 5000);

    // Roundtrip
    let serialized = toml::to_string(&config).unwrap();
    let deserialized: AnalyticsConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(config.backend, deserialized.backend);
}

// ============================================================================
// Telemetry Configuration Tests
// ============================================================================

#[test]
fn test_potato_profile_minimal_telemetry() {
    let config = TelemetryConfig::potato();
    assert!(config.metrics_enabled);
    assert_eq!(config.trace_sampling, 0.01);
    assert_eq!(config.log_level, LogLevel::Info);
    assert!(!config.structured_logging);
    assert!(config.opentelemetry.is_none());
}

#[test]
fn test_standard_profile_moderate_telemetry() {
    let config = TelemetryConfig::standard();
    assert!(config.metrics_enabled);
    assert_eq!(config.trace_sampling, 0.1);
    assert!(config.structured_logging);
    assert!(config.log_file_path.is_some());
    assert!(config.opentelemetry.is_none());
}

#[test]
fn test_hyperscale_profile_full_telemetry() {
    let config = TelemetryConfig::hyperscale();
    assert!(config.metrics_enabled);
    assert_eq!(config.trace_sampling, 1.0);
    assert_eq!(config.log_level, LogLevel::Debug);
    assert!(config.structured_logging);
    assert!(config.opentelemetry.is_some());
    assert!(config.opentelemetry.as_ref().unwrap().enabled);
}

#[test]
fn test_telemetry_config_toml_roundtrip() {
    let toml_str = r#"
metrics_enabled = true
metrics_endpoint = "http://localhost:9090/metrics"
metrics_format = "prometheus"
trace_sampling = 0.1
log_level = "debug"
structured_logging = true
stdout_logging = true
log_rotation_size_mb = 100
"#;

    let config: TelemetryConfig = toml::from_str(toml_str).unwrap();
    assert!(config.metrics_enabled);
    assert_eq!(config.trace_sampling, 0.1);
    assert_eq!(config.log_level, LogLevel::Debug);

    // Roundtrip
    let serialized = toml::to_string(&config).unwrap();
    let deserialized: TelemetryConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(config.log_level, deserialized.log_level);
}

#[test]
fn test_telemetry_with_opentelemetry() {
    let toml_str = r#"
metrics_enabled = true
metrics_endpoint = "http://localhost:9090/metrics"
metrics_format = "otlp"
trace_sampling = 1.0
log_level = "info"
structured_logging = true
stdout_logging = true

[opentelemetry]
enabled = true
endpoint = "http://localhost:4317"
service_name = "jig-server"
service_version = "0.2.0"
environment = "production"
"#;

    let config: TelemetryConfig = toml::from_str(toml_str).unwrap();
    assert!(config.opentelemetry.is_some());

    let otel = config.opentelemetry.as_ref().unwrap();
    assert!(otel.enabled);
    assert_eq!(otel.service_name, "jig-server");
    assert_eq!(otel.service_version, Some("0.2.0".to_string()));
    assert_eq!(otel.environment, Some("production".to_string()));
}

// ============================================================================
// Privacy Mode Tests
// ============================================================================

#[test]
fn test_privacy_mode_defaults_to_anonymized() {
    let config = AnalyticsConfig::default();
    assert_eq!(config.privacy_mode, PrivacyMode::Anonymized);
}

#[test]
fn test_privacy_mode_escalates_with_profile() {
    let potato = AnalyticsConfig::potato();
    let standard = AnalyticsConfig::standard();
    let hyperscale = AnalyticsConfig::hyperscale();

    assert_eq!(potato.privacy_mode, PrivacyMode::Anonymized);
    assert_eq!(standard.privacy_mode, PrivacyMode::Anonymized);
    assert_eq!(hyperscale.privacy_mode, PrivacyMode::Aggregated);
}

// ============================================================================
// Sampling Rate Tests
// ============================================================================

#[test]
fn test_sampling_rate_increases_with_profile() {
    let potato = AnalyticsConfig::potato();
    let standard = AnalyticsConfig::standard();
    let hyperscale = AnalyticsConfig::hyperscale();

    assert_eq!(potato.sample_rate, 0.1);
    assert_eq!(standard.sample_rate, 0.5);
    assert_eq!(hyperscale.sample_rate, 1.0);
}

#[test]
fn test_trace_sampling_increases_with_profile() {
    let potato = TelemetryConfig::potato();
    let standard = TelemetryConfig::standard();
    let hyperscale = TelemetryConfig::hyperscale();

    assert_eq!(potato.trace_sampling, 0.01);
    assert_eq!(standard.trace_sampling, 0.1);
    assert_eq!(hyperscale.trace_sampling, 1.0);
}

// ============================================================================
// Retention Tests
// ============================================================================

#[test]
fn test_retention_increases_with_profile() {
    let potato = AnalyticsConfig::potato();
    let standard = AnalyticsConfig::standard();
    let hyperscale = AnalyticsConfig::hyperscale();

    assert_eq!(potato.retention_days, 30);
    assert_eq!(standard.retention_days, 90);
    assert_eq!(hyperscale.retention_days, 365);
}

// ============================================================================
// Backend-Specific Configuration Tests
// ============================================================================

#[test]
fn test_duckdb_config_memory_limit() {
    let config = DuckDBConfig {
        path: "/tmp/test.duckdb".to_string(),
        memory_limit_mb: 1024,
        threads: 8,
        read_only: false,
    };

    assert_eq!(config.memory_limit_mb, 1024);
    assert_eq!(config.threads, 8);
}

#[test]
fn test_parquet_config_compression() {
    let config = ParquetConfig {
        path: "/data/parquet".to_string(),
        partition_by: "month".to_string(),
        compression: "zstd".to_string(),
        row_group_size: 100_000,
    };

    assert_eq!(config.compression, "zstd");
    assert_eq!(config.partition_by, "month");
}

#[test]
fn test_clickhouse_config_batching() {
    let config = ClickHouseConfig {
        dsn: "tcp://localhost:9000".to_string(),
        database: "test".to_string(),
        batch_size: 10_000,
        flush_interval_secs: 15,
        pool_size: 30,
        compression: true,
    };

    assert_eq!(config.batch_size, 10_000);
    assert_eq!(config.flush_interval_secs, 15);
    assert_eq!(config.pool_size, 30);
}

// ============================================================================
// Metrics Format Tests
// ============================================================================

#[test]
fn test_metrics_format_serialization() {
    let prom = MetricsFormat::Prometheus;
    let otlp = MetricsFormat::OTLP;
    let statsd = MetricsFormat::StatsD;
    let json = MetricsFormat::Json;

    assert_eq!(serde_json::to_string(&prom).unwrap(), r#""prometheus""#);
    assert_eq!(serde_json::to_string(&otlp).unwrap(), r#""otlp""#);
    assert_eq!(serde_json::to_string(&statsd).unwrap(), r#""statsd""#);
    assert_eq!(serde_json::to_string(&json).unwrap(), r#""json""#);
}

#[test]
fn test_metrics_format_defaults_to_prometheus() {
    let config = TelemetryConfig::default();
    assert_eq!(config.metrics_format, MetricsFormat::Prometheus);
}

// ============================================================================
// Log Level Tests
// ============================================================================

#[test]
fn test_log_level_progression() {
    let potato = TelemetryConfig::potato();
    let standard = TelemetryConfig::standard();
    let hyperscale = TelemetryConfig::hyperscale();

    assert_eq!(potato.log_level, LogLevel::Info);
    assert_eq!(standard.log_level, LogLevel::Info);
    assert_eq!(hyperscale.log_level, LogLevel::Debug);
}

#[test]
fn test_log_level_serialization() {
    let trace = LogLevel::Trace;
    let debug = LogLevel::Debug;
    let info = LogLevel::Info;
    let warn = LogLevel::Warn;
    let error = LogLevel::Error;

    assert_eq!(serde_json::to_string(&trace).unwrap(), r#""trace""#);
    assert_eq!(serde_json::to_string(&debug).unwrap(), r#""debug""#);
    assert_eq!(serde_json::to_string(&info).unwrap(), r#""info""#);
    assert_eq!(serde_json::to_string(&warn).unwrap(), r#""warn""#);
    assert_eq!(serde_json::to_string(&error).unwrap(), r#""error""#);
}

// ============================================================================
// Complete Configuration Tests
// ============================================================================

#[test]
fn test_complete_analytics_and_telemetry_config() {
    let toml_str = r#"
[analytics]
backend = "clickhouse"
retention_days = 180
sample_rate = 0.8
privacy_mode = "aggregated"

[analytics.clickhouse]
dsn = "tcp://clickhouse.example.com:9000"
database = "jig_prod"
batch_size = 2000
flush_interval_secs = 45
pool_size = 15
compression = true

[telemetry]
metrics_enabled = true
metrics_endpoint = "http://metrics.example.com:9090/metrics"
metrics_format = "prometheus"
trace_sampling = 0.5
log_level = "info"
structured_logging = true
stdout_logging = false
log_file_path = "/var/log/jig/app.log"
log_rotation_size_mb = 200

[telemetry.opentelemetry]
enabled = true
endpoint = "http://otel-collector.example.com:4317"
service_name = "jig-prod"
service_version = "1.0.0"
environment = "production"
"#;

    #[derive(serde::Deserialize)]
    struct CompleteConfig {
        analytics: AnalyticsConfig,
        telemetry: TelemetryConfig,
    }

    let config: CompleteConfig = toml::from_str(toml_str).unwrap();

    // Analytics assertions
    assert_eq!(config.analytics.backend, AnalyticsBackend::ClickHouse);
    assert_eq!(config.analytics.retention_days, 180);
    assert_eq!(config.analytics.sample_rate, 0.8);
    assert_eq!(config.analytics.privacy_mode, PrivacyMode::Aggregated);
    assert!(config.analytics.clickhouse.is_some());

    // Telemetry assertions
    assert!(config.telemetry.metrics_enabled);
    assert_eq!(config.telemetry.trace_sampling, 0.5);
    assert_eq!(config.telemetry.log_level, LogLevel::Info);
    assert!(config.telemetry.structured_logging);
    assert!(!config.telemetry.stdout_logging);
    assert!(config.telemetry.log_file_path.is_some());
    assert!(config.telemetry.opentelemetry.is_some());
}
