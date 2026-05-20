//! Analytics backend trait abstraction for composable database backends
//!
//! This module defines the trait interface for analytics backends, enabling
//! swappable implementations (SQLite, DuckDB, Parquet, ClickHouse, etc.)
//! without changing core analytics engine logic.

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Time range for analytics queries
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TimeRange {
    LastHour,
    LastDay,
    LastWeek,
    LastMonth,
    Custom { start_ts: i64, end_ts: i64 },
}

/// Receipt record for analytics queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptRecord {
    pub block_id: String,
    pub executed_at: i64,
    pub fuel_used: u64,
    pub outcome: String,
    pub host: String,
    pub capability: Option<String>,
}

/// Anomaly record for analytics queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyRecord {
    pub detected_at: i64,
    pub kind: String,
    pub severity: String,
    pub host: String,
    pub escalated: bool,
}

/// Penalty record for analytics queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyRecord {
    pub applied_at: i64,
    pub host: String,
    pub reason: String,
    pub penalty_bits: u32,
    pub expires_at: Option<i64>,
}

/// Useful work record for analytics queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsefulWorkRecord {
    pub task_id: String,
    pub status: String,
    pub completed_at: Option<i64>,
}

/// Cross-validation record for analytics queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossValidationRecord {
    pub receipt_id: String,
    pub validated_at: i64,
    pub consensus_reached: bool,
    pub fuel_discrepancy_pct: f64,
}

/// Export format for analytics data
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Csv,
    Parquet,
}

/// Backend capabilities metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Backend supports streaming queries
    pub supports_streaming: bool,
    /// Backend supports aggregations (GROUP BY, etc.)
    pub supports_aggregations: bool,
    /// Max query size (None = unlimited)
    pub max_query_size: Option<usize>,
    /// Uses columnar storage (better for analytics)
    pub columnar_storage: bool,
    /// Supports time-series optimizations
    pub time_series_optimized: bool,
}

/// Analytics backend trait - any OLAP-capable backend
#[async_trait]
pub trait AnalyticsBackend: Send + Sync {
    /// Query receipt records for time range
    async fn query_receipts(&self, range: TimeRange) -> Result<Vec<ReceiptRecord>>;

    /// Query anomaly records for time range
    async fn query_anomalies(&self, range: TimeRange) -> Result<Vec<AnomalyRecord>>;

    /// Query penalty records for time range
    async fn query_penalties(&self, range: TimeRange) -> Result<Vec<PenaltyRecord>>;

    /// Query useful work records for time range
    async fn query_useful_work(&self, range: TimeRange) -> Result<Vec<UsefulWorkRecord>>;

    /// Query cross-validation records for time range
    async fn query_cross_validations(&self, range: TimeRange)
    -> Result<Vec<CrossValidationRecord>>;

    /// Export data to backend-native format (Parquet, CSV, etc.)
    async fn export(&self, range: TimeRange, format: ExportFormat) -> Result<Vec<u8>>;

    /// Backend capabilities (supports aggregations, time-series, etc.)
    fn capabilities(&self) -> BackendCapabilities;

    /// Backend name for config matching
    fn name(&self) -> &'static str;
}

/// Factory trait for creating analytics backends from config
pub trait AnalyticsBackendFactory: Send + Sync {
    /// Create backend from config map
    fn create(&self, config: &HashMap<String, String>) -> Result<Box<dyn AnalyticsBackend>>;

    /// Backend name for registry lookup
    fn name(&self) -> &'static str;
}

/// Helper to convert TimeRange to Unix timestamp range
impl TimeRange {
    pub fn to_timestamp_range(&self) -> (i64, i64) {
        use chrono::{Duration, Utc};

        match self {
            TimeRange::LastHour => {
                let end = Utc::now();
                let start = end - Duration::hours(1);
                (start.timestamp(), end.timestamp())
            }
            TimeRange::LastDay => {
                let end = Utc::now();
                let start = end - Duration::days(1);
                (start.timestamp(), end.timestamp())
            }
            TimeRange::LastWeek => {
                let end = Utc::now();
                let start = end - Duration::weeks(1);
                (start.timestamp(), end.timestamp())
            }
            TimeRange::LastMonth => {
                let end = Utc::now();
                let start = end - Duration::days(30);
                (start.timestamp(), end.timestamp())
            }
            TimeRange::Custom { start_ts, end_ts } => (*start_ts, *end_ts),
        }
    }
}
