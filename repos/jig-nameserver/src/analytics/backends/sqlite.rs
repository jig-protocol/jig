//! SQLite analytics backend adapter (Tier 1)
//!
//! Wraps existing SQLite queries into the AnalyticsBackend trait interface.
//! This is the default backend for potato/single-node deployments.

use crate::analytics::backend::*;
use crate::error::Result;
use crate::storage::NamesStorage;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;

/// SQLite analytics backend - wraps NamesStorage
pub struct SqliteAnalytics {
    storage: Arc<dyn NamesStorage>,
}

impl SqliteAnalytics {
    pub fn new(storage: Arc<dyn NamesStorage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl AnalyticsBackend for SqliteAnalytics {
    async fn query_receipts(&self, range: TimeRange) -> Result<Vec<ReceiptRecord>> {
        let (start_ts, end_ts) = range.to_timestamp_range();

        // Fetch all receipts from storage (NamesStorage doesn't have time filtering yet)
        let all_receipts = self.storage.list_receipts(None, None, 10_000).await?;

        // Filter by time range and convert to ReceiptRecord
        let receipts: Vec<ReceiptRecord> = all_receipts
            .into_iter()
            .filter_map(|r| {
                let executed_at = DateTime::from_timestamp(
                    r.executed_at.unix_timestamp(),
                    r.executed_at.nanosecond(),
                )
                .unwrap_or_else(Utc::now);

                let ts = executed_at.timestamp();
                if ts >= start_ts && ts <= end_ts {
                    // Convert outcome to string
                    let outcome_str = r
                        .outcome
                        .as_ref()
                        .map(|o| format!("{:?}", o.status))
                        .unwrap_or_else(|| "Ok".to_string());

                    // Pick the first capability if available
                    let capability = r.capabilities_used.first().cloned();

                    Some(ReceiptRecord {
                        block_id: r.block_id.to_string(),
                        executed_at: ts,
                        fuel_used: r.fuel_used,
                        outcome: outcome_str,
                        host: r.host,
                        capability,
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(receipts)
    }

    async fn query_anomalies(&self, range: TimeRange) -> Result<Vec<AnomalyRecord>> {
        let (_start_ts, _end_ts) = range.to_timestamp_range();

        // TODO Tier 1 limitation: NamesStorage doesn't have list_anomalies method.
        // We can only query anomalies for a specific host via get_anomalies_for_host.
        // To properly implement this, we'd need to:
        // 1. Add list_anomalies() method to NamesStorage trait
        // 2. Implement it in SqliteStorage with time-range filtering
        // 3. Or upgrade to Tier 2 with proper analytics tables
        //
        // For now, return empty results to maintain API compatibility
        Ok(vec![])
    }

    async fn query_penalties(&self, range: TimeRange) -> Result<Vec<PenaltyRecord>> {
        let (_start_ts, _end_ts) = range.to_timestamp_range();

        // TODO Tier 1 limitation: NamesStorage doesn't have list_penalties method.
        // We can only query penalties for a specific host via get_active_penalties.
        // To properly implement this, we'd need to:
        // 1. Add list_penalties() method to NamesStorage trait
        // 2. Implement it in SqliteStorage with time-range filtering
        // 3. Or upgrade to Tier 2 with proper analytics tables
        //
        // For now, return empty results to maintain API compatibility
        Ok(vec![])
    }

    async fn query_useful_work(&self, _range: TimeRange) -> Result<Vec<UsefulWorkRecord>> {
        // Placeholder for Tier 2 - useful work not yet tracked in SQLite
        Ok(vec![])
    }

    async fn query_cross_validations(
        &self,
        _range: TimeRange,
    ) -> Result<Vec<CrossValidationRecord>> {
        // Placeholder for Tier 2 - cross-validation results not yet tracked in SQLite
        Ok(vec![])
    }

    async fn export(&self, range: TimeRange, format: ExportFormat) -> Result<Vec<u8>> {
        match format {
            ExportFormat::Json => {
                // Collect all data
                let receipts = self.query_receipts(range).await?;
                let anomalies = self.query_anomalies(range).await?;
                let penalties = self.query_penalties(range).await?;

                let data = serde_json::json!({
                    "receipts": receipts,
                    "anomalies": anomalies,
                    "penalties": penalties,
                });

                serde_json::to_vec_pretty(&data)
                    .map_err(|e| crate::error::NameServerError::Other(anyhow::anyhow!(e)))
            }
            ExportFormat::Csv => {
                // Simple CSV export of receipts only
                let receipts = self.query_receipts(range).await?;

                let mut csv =
                    String::from("block_id,executed_at,fuel_used,outcome,host,capability\n");
                for r in receipts {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        r.block_id,
                        r.executed_at,
                        r.fuel_used,
                        r.outcome,
                        r.host,
                        r.capability.unwrap_or_else(|| "".to_string())
                    ));
                }

                Ok(csv.into_bytes())
            }
            ExportFormat::Parquet => {
                // Parquet export requires tier2-analytics feature
                Err(crate::error::NameServerError::Other(anyhow::anyhow!(
                    "Parquet export requires tier2-analytics feature"
                )))
            }
        }
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_streaming: false,
            supports_aggregations: true,  // SQLite supports GROUP BY
            max_query_size: Some(10_000), // Hardcoded limit in list_* methods
            columnar_storage: false,      // Row-based storage
            time_series_optimized: false,
        }
    }

    fn name(&self) -> &'static str {
        "sqlite"
    }
}

/// Factory for creating SQLite analytics backends
pub struct SqliteAnalyticsFactory;

impl AnalyticsBackendFactory for SqliteAnalyticsFactory {
    fn create(&self, config: &HashMap<String, String>) -> Result<Box<dyn AnalyticsBackend>> {
        // For SQLite, we need the storage reference which is passed separately
        // This is a limitation of the factory pattern - we'll handle it in the registry
        let _ = config; // Config not used for SQLite (uses existing storage)
        Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "SQLite backend requires storage reference - use SqliteAnalytics::new() directly"
        )))
    }

    fn name(&self) -> &'static str {
        "sqlite"
    }
}
