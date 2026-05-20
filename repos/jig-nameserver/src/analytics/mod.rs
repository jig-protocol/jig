//! Analytics module for nameserver metrics and insights
//!
//! Phase F: Three-tier analytics architecture
//! - Tier 1 (Potato): SQLite-only queries for local insights
//! - Tier 2 (Prosumer): DuckDB/Parquet for fast OLAP analysis
//! - Tier 3 (Hyperscale): ClickHouse streaming for federated analytics
//!
//! This module now implements composable backend architecture for database role separation.

pub mod backend;
pub mod backends;

use crate::error::Result;
use crate::storage::NamesStorage;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// Re-export backend types for convenience
pub use backend::{AnalyticsBackend, BackendCapabilities, ExportFormat, TimeRange};

/// Receipt execution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptStats {
    pub total_receipts: u64,
    pub total_fuel_used: u64,
    pub avg_fuel_per_receipt: f64,
    pub success_rate: f64,
    pub outcome_breakdown: HashMap<String, u64>,
    pub top_hosts: Vec<(String, u64)>, // (host, receipt_count)
    pub fuel_by_capability: HashMap<String, u64>,
}

/// Anomaly detection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyStats {
    pub total_anomalies: u64,
    pub by_kind: HashMap<String, u64>,
    pub by_severity: HashMap<String, u64>,
    pub escalation_rate: f64, // % of anomalies escalated to tribunal
    pub top_offenders: Vec<(String, u64)>, // (host, anomaly_count)
}

/// Penalty statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyStats {
    pub total_penalties_applied: u64,
    pub active_penalties: u64,
    pub expired_penalties: u64,
    pub total_penalty_bits: u64,
    pub avg_penalty_bits: f64,
    pub by_reason: HashMap<String, u64>,
}

/// Useful work statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsefulWorkStats {
    pub total_work_submitted: u64,
    pub pending_work: u64,
    pub in_flight_work: u64,
    pub completed_work: u64,
    pub completion_rate: f64,
    pub avg_completion_time_secs: f64,
}

/// Cross-validation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossValidationStats {
    pub total_validations: u64,
    pub validation_failures: u64,
    pub failure_rate: f64,
    pub avg_peer_count: f64,
    pub disagreement_types: HashMap<String, u64>, // fuel, outcome, render_hash
}

/// Comprehensive analytics dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsDashboard {
    pub time_range: String,
    pub receipts: ReceiptStats,
    pub anomalies: AnomalyStats,
    pub penalties: PenaltyStats,
    pub useful_work: UsefulWorkStats,
    pub cross_validation: CrossValidationStats,
}

/// Analytics engine for nameserver metrics
///
/// Now supports pluggable backends via AnalyticsBackend trait.
/// For backward compatibility, can still be constructed with NamesStorage (uses SQLite backend).
pub struct AnalyticsEngine {
    backend: Arc<dyn AnalyticsBackend>,
    // Keep storage reference for Tier 1 queries that backend doesn't handle yet
    storage: Arc<dyn NamesStorage>,
}

impl AnalyticsEngine {
    /// Create analytics engine with default SQLite backend
    pub fn new(storage: Arc<dyn NamesStorage>) -> Self {
        let backend = Arc::new(backends::sqlite::SqliteAnalytics::new(storage.clone()));
        Self { backend, storage }
    }

    /// Create analytics engine with custom backend
    pub fn with_backend(
        backend: Arc<dyn AnalyticsBackend>,
        storage: Arc<dyn NamesStorage>,
    ) -> Self {
        Self { backend, storage }
    }

    /// Get receipt statistics for the given time range
    pub async fn get_receipt_stats(&self, range: TimeRange) -> Result<ReceiptStats> {
        // Use backend to query receipts
        let receipt_records = self.backend.query_receipts(range).await?;

        let total_receipts = receipt_records.len() as u64;
        if total_receipts == 0 {
            return Ok(ReceiptStats {
                total_receipts: 0,
                total_fuel_used: 0,
                avg_fuel_per_receipt: 0.0,
                success_rate: 0.0,
                outcome_breakdown: HashMap::new(),
                top_hosts: Vec::new(),
                fuel_by_capability: HashMap::new(),
            });
        }

        // Compute total fuel
        let total_fuel_used: u64 = receipt_records.iter().map(|r| r.fuel_used).sum();
        let avg_fuel_per_receipt = total_fuel_used as f64 / total_receipts as f64;

        // Outcome breakdown
        let mut outcome_breakdown: HashMap<String, u64> = HashMap::new();
        let mut successful = 0u64;
        for record in &receipt_records {
            if record.outcome == "ok" || record.outcome == "Ok" {
                successful += 1;
            }
            *outcome_breakdown.entry(record.outcome.clone()).or_insert(0) += 1;
        }
        let success_rate = successful as f64 / total_receipts as f64;

        // Top hosts by receipt count
        let mut host_counts: HashMap<String, u64> = HashMap::new();
        for record in &receipt_records {
            *host_counts.entry(record.host.clone()).or_insert(0) += 1;
        }
        let mut top_hosts: Vec<_> = host_counts.into_iter().collect();
        top_hosts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        top_hosts.truncate(10);

        // Fuel by capability
        let mut fuel_by_capability: HashMap<String, u64> = HashMap::new();
        for record in &receipt_records {
            if let Some(cap) = &record.capability {
                *fuel_by_capability.entry(cap.clone()).or_insert(0) += record.fuel_used;
            }
        }

        Ok(ReceiptStats {
            total_receipts,
            total_fuel_used,
            avg_fuel_per_receipt,
            success_rate,
            outcome_breakdown,
            top_hosts,
            fuel_by_capability,
        })
    }

    /// Get anomaly detection statistics
    pub async fn get_anomaly_stats(&self, range: TimeRange) -> Result<AnomalyStats> {
        // Use backend to query anomalies
        let anomaly_records = self.backend.query_anomalies(range).await?;

        let total_anomalies = anomaly_records.len() as u64;
        if total_anomalies == 0 {
            return Ok(AnomalyStats {
                total_anomalies: 0,
                by_kind: HashMap::new(),
                by_severity: HashMap::new(),
                escalation_rate: 0.0,
                top_offenders: Vec::new(),
            });
        }

        // Breakdown by kind
        let mut by_kind: HashMap<String, u64> = HashMap::new();
        for record in &anomaly_records {
            *by_kind.entry(record.kind.clone()).or_insert(0) += 1;
        }

        // Breakdown by severity
        let mut by_severity: HashMap<String, u64> = HashMap::new();
        let mut escalated = 0u64;
        for record in &anomaly_records {
            *by_severity.entry(record.severity.clone()).or_insert(0) += 1;
            if record.escalated {
                escalated += 1;
            }
        }
        let escalation_rate = escalated as f64 / total_anomalies as f64;

        // Top offenders by host
        let mut host_counts: HashMap<String, u64> = HashMap::new();
        for record in &anomaly_records {
            *host_counts.entry(record.host.clone()).or_insert(0) += 1;
        }
        let mut top_offenders: Vec<_> = host_counts.into_iter().collect();
        top_offenders.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        top_offenders.truncate(10);

        Ok(AnomalyStats {
            total_anomalies,
            by_kind,
            by_severity,
            escalation_rate,
            top_offenders,
        })
    }

    /// Get penalty statistics
    pub async fn get_penalty_stats(&self, range: TimeRange) -> Result<PenaltyStats> {
        // Use backend to query penalties
        let penalty_records = self.backend.query_penalties(range).await?;

        if penalty_records.is_empty() {
            return Ok(PenaltyStats {
                total_penalties_applied: 0,
                active_penalties: 0,
                expired_penalties: 0,
                total_penalty_bits: 0,
                avg_penalty_bits: 0.0,
                by_reason: HashMap::new(),
            });
        }

        let total_penalties_applied = penalty_records.len() as u64;
        let total_penalty_bits: u64 = penalty_records.iter().map(|r| r.penalty_bits as u64).sum();
        let avg_penalty_bits = total_penalty_bits as f64 / total_penalties_applied as f64;

        // Count active vs expired
        let now = chrono::Utc::now().timestamp();
        let mut active_penalties = 0u64;
        let mut expired_penalties = 0u64;
        for record in &penalty_records {
            match record.expires_at {
                Some(expires) if expires < now => expired_penalties += 1,
                _ => active_penalties += 1,
            }
        }

        // By reason
        let mut by_reason: HashMap<String, u64> = HashMap::new();
        for record in &penalty_records {
            *by_reason.entry(record.reason.clone()).or_insert(0) += 1;
        }

        Ok(PenaltyStats {
            total_penalties_applied,
            active_penalties,
            expired_penalties,
            total_penalty_bits,
            avg_penalty_bits,
            by_reason,
        })
    }

    /// Get useful work statistics
    pub async fn get_useful_work_stats(&self, range: TimeRange) -> Result<UsefulWorkStats> {
        // Use backend to query useful work
        let work_records = self.backend.query_useful_work(range).await?;

        // Query current queue depth from storage
        let pending_work = self.storage.useful_work_queue_depth().await? as u64;

        // Calculate stats from records
        let mut completed_work = 0u64;
        let mut in_flight_work = 0u64;
        for record in &work_records {
            match record.status.as_str() {
                "completed" => completed_work += 1,
                "in_flight" => in_flight_work += 1,
                _ => {}
            }
        }

        let total_work_submitted = work_records.len() as u64;
        let completion_rate = if total_work_submitted > 0 {
            completed_work as f64 / total_work_submitted as f64
        } else {
            0.0
        };

        Ok(UsefulWorkStats {
            total_work_submitted,
            pending_work,
            in_flight_work,
            completed_work,
            completion_rate,
            avg_completion_time_secs: 0.0, // Would need completion timestamps
        })
    }

    /// Get cross-validation statistics
    pub async fn get_cross_validation_stats(
        &self,
        range: TimeRange,
    ) -> Result<CrossValidationStats> {
        // Use backend to query cross-validations
        let cv_records = self.backend.query_cross_validations(range).await?;

        let total_validations = cv_records.len() as u64;
        let validation_failures = cv_records.iter().filter(|r| !r.consensus_reached).count() as u64;

        let failure_rate = if total_validations > 0 {
            validation_failures as f64 / total_validations as f64
        } else {
            0.0
        };

        // Categorize disagreement types by fuel discrepancy
        let mut disagreement_types: HashMap<String, u64> = HashMap::new();
        for record in &cv_records {
            if !record.consensus_reached {
                // Categorize by magnitude of discrepancy
                let category = if record.fuel_discrepancy_pct > 50.0 {
                    "fuel_major"
                } else if record.fuel_discrepancy_pct > 10.0 {
                    "fuel_minor"
                } else {
                    "other"
                };
                *disagreement_types.entry(category.to_string()).or_insert(0) += 1;
            }
        }

        Ok(CrossValidationStats {
            total_validations,
            validation_failures,
            failure_rate,
            avg_peer_count: 0.0, // Would need peer count tracking
            disagreement_types,
        })
    }

    /// Get comprehensive analytics dashboard
    pub async fn get_dashboard(&self, range: TimeRange) -> Result<AnalyticsDashboard> {
        let range_str = match range {
            TimeRange::LastHour => "last_hour".to_string(),
            TimeRange::LastDay => "last_day".to_string(),
            TimeRange::LastWeek => "last_week".to_string(),
            TimeRange::LastMonth => "last_month".to_string(),
            TimeRange::Custom { start_ts, end_ts } => {
                let start = DateTime::from_timestamp(start_ts, 0).unwrap_or_else(Utc::now);
                let end = DateTime::from_timestamp(end_ts, 0).unwrap_or_else(Utc::now);
                format!("{start} to {end}")
            }
        };

        Ok(AnalyticsDashboard {
            time_range: range_str,
            receipts: self.get_receipt_stats(range).await?,
            anomalies: self.get_anomaly_stats(range).await?,
            penalties: self.get_penalty_stats(range).await?,
            useful_work: self.get_useful_work_stats(range).await?,
            cross_validation: self.get_cross_validation_stats(range).await?,
        })
    }

    /// Export analytics data as JSON
    pub async fn export_json(&self, range: TimeRange) -> Result<String> {
        let dashboard = self.get_dashboard(range).await?;
        serde_json::to_string_pretty(&dashboard)
            .map_err(|e| crate::error::NameServerError::Other(anyhow::anyhow!(e)))
    }

    /// Export analytics data as CSV
    pub async fn export_csv(&self, range: TimeRange) -> Result<String> {
        let dashboard = self.get_dashboard(range).await?;

        // Simple CSV format with key metrics
        let mut csv = String::from("metric,value\n");
        csv.push_str(&format!(
            "total_receipts,{}\n",
            dashboard.receipts.total_receipts
        ));
        csv.push_str(&format!(
            "total_fuel_used,{}\n",
            dashboard.receipts.total_fuel_used
        ));
        csv.push_str(&format!(
            "success_rate,{:.2}\n",
            dashboard.receipts.success_rate
        ));
        csv.push_str(&format!(
            "total_anomalies,{}\n",
            dashboard.anomalies.total_anomalies
        ));
        csv.push_str(&format!(
            "escalation_rate,{:.2}\n",
            dashboard.anomalies.escalation_rate
        ));
        csv.push_str(&format!(
            "active_penalties,{}\n",
            dashboard.penalties.active_penalties
        ));
        csv.push_str(&format!(
            "total_penalty_bits,{}\n",
            dashboard.penalties.total_penalty_bits
        ));

        Ok(csv)
    }
}

// Phase F Tier 2: Parquet export foundation
#[cfg(feature = "tier2-analytics")]
pub mod tier2 {
    use super::*;

    /// Export analytics to Parquet format for DuckDB analysis
    pub async fn export_parquet(
        _engine: &AnalyticsEngine,
        _range: TimeRange,
        _output_path: &str,
    ) -> Result<()> {
        // Not yet implemented in v0.0.1 - Tier 2 stub
        eprintln!("warning: Parquet export is not yet implemented in v0.0.1 (Tier 2 feature)");
        Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "Tier 2 Parquet export is not yet implemented in v0.0.1"
        )))
    }
}

// Phase F Tier 3: ClickHouse streaming foundation
#[cfg(feature = "tier3-analytics")]
pub mod tier3 {
    use super::*;

    /// Stream receipts to ClickHouse for real-time analytics
    pub async fn stream_to_clickhouse(
        _clickhouse_url: &str,
        _receipt: &jig_core::BlockReceipt,
    ) -> Result<()> {
        // Not yet implemented in v0.0.1 - Tier 3 stub
        eprintln!(
            "warning: ClickHouse streaming is not yet implemented in v0.0.1 (Tier 3 feature)"
        );
        Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "Tier 3 ClickHouse streaming is not yet implemented in v0.0.1"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[tokio::test]
    async fn test_time_range_conversion() {
        let range = TimeRange::LastHour;
        let (start_ts, end_ts) = range.to_timestamp_range();

        let duration = end_ts - start_ts;
        assert_eq!(duration, 3600); // 1 hour in seconds
    }

    #[tokio::test]
    async fn test_analytics_engine_creation() {
        let storage = Arc::new(MemoryStorage::default());
        let engine = AnalyticsEngine::new(storage);

        // Should be able to query empty analytics
        let dashboard = engine.get_dashboard(TimeRange::LastDay).await.unwrap();
        assert_eq!(dashboard.receipts.total_receipts, 0);
    }

    #[tokio::test]
    async fn test_json_export() {
        let storage = Arc::new(MemoryStorage::default());
        let engine = AnalyticsEngine::new(storage);

        let json = engine.export_json(TimeRange::LastHour).await.unwrap();
        assert!(json.contains("\"time_range\""));
        assert!(json.contains("\"receipts\""));
    }

    #[tokio::test]
    async fn test_csv_export() {
        let storage = Arc::new(MemoryStorage::default());
        let engine = AnalyticsEngine::new(storage);

        let csv = engine.export_csv(TimeRange::LastDay).await.unwrap();
        assert!(csv.starts_with("metric,value\n"));
        assert!(csv.contains("total_receipts"));
    }
}
