//! DuckDB analytics backend adapter (Tier 2)
//!
//! Provides fast OLAP queries with columnar storage for prosumer deployments.
//! Feature-gated behind `tier2-analytics`.

#[cfg(feature = "tier2-analytics")]
use crate::analytics::backend::*;
#[cfg(feature = "tier2-analytics")]
use crate::error::{NameServerError, Result};
#[cfg(feature = "tier2-analytics")]
use async_trait::async_trait;
#[cfg(feature = "tier2-analytics")]
use std::collections::HashMap;
#[cfg(feature = "tier2-analytics")]
use std::path::PathBuf;
#[cfg(feature = "tier2-analytics")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "tier2-analytics")]
/// DuckDB analytics backend - fast columnar OLAP
pub struct DuckDBAnalytics {
    conn: Arc<Mutex<duckdb::Connection>>,
}

#[cfg(feature = "tier2-analytics")]
impl DuckDBAnalytics {
    pub fn new(database_path: PathBuf) -> Result<Self> {
        // Open DuckDB connection
        let conn = duckdb::Connection::open(&database_path)
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("Failed to open DuckDB: {}", e)))?;

        // Create tables if they don't exist
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS receipts (
                block_id TEXT PRIMARY KEY,
                executed_at INTEGER NOT NULL,
                fuel_used INTEGER NOT NULL,
                outcome TEXT NOT NULL,
                host TEXT NOT NULL,
                capability TEXT
            );

            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY,
                detected_at INTEGER NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                host TEXT NOT NULL,
                escalated BOOLEAN NOT NULL
            );

            CREATE TABLE IF NOT EXISTS penalties (
                id INTEGER PRIMARY KEY,
                applied_at INTEGER NOT NULL,
                host TEXT NOT NULL,
                reason TEXT NOT NULL,
                penalty_bits INTEGER NOT NULL,
                expires_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS useful_work (
                task_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                completed_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS cross_validations (
                id INTEGER PRIMARY KEY,
                receipt_id TEXT NOT NULL,
                validated_at INTEGER NOT NULL,
                consensus_reached BOOLEAN NOT NULL,
                fuel_discrepancy_pct REAL NOT NULL
            );
            ",
        )
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("Failed to create tables: {}", e)))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

#[cfg(feature = "tier2-analytics")]
#[async_trait]
impl AnalyticsBackend for DuckDBAnalytics {
    async fn query_receipts(&self, range: TimeRange) -> Result<Vec<ReceiptRecord>> {
        let (start_ts, end_ts) = range.to_timestamp_range();
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT block_id, executed_at, fuel_used, outcome, host, capability FROM receipts WHERE executed_at BETWEEN ? AND ? ORDER BY executed_at DESC")
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("DuckDB prepare error: {}", e)))?;

        let receipts = stmt
            .query_map([start_ts, end_ts], |row| {
                Ok(ReceiptRecord {
                    block_id: row.get(0)?,
                    executed_at: row.get(1)?,
                    fuel_used: row.get(2)?,
                    outcome: row.get(3)?,
                    host: row.get(4)?,
                    capability: row.get(5)?,
                })
            })
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("DuckDB query error: {}", e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("DuckDB row parse error: {}", e))
            })?;

        Ok(receipts)
    }

    async fn query_anomalies(&self, range: TimeRange) -> Result<Vec<AnomalyRecord>> {
        let (start_ts, end_ts) = range.to_timestamp_range();
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT detected_at, kind, severity, host, escalated FROM anomalies WHERE detected_at BETWEEN ? AND ? ORDER BY detected_at DESC")
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("DuckDB prepare error: {}", e)))?;

        let anomalies = stmt
            .query_map([start_ts, end_ts], |row| {
                Ok(AnomalyRecord {
                    detected_at: row.get(0)?,
                    kind: row.get(1)?,
                    severity: row.get(2)?,
                    host: row.get(3)?,
                    escalated: row.get(4)?,
                })
            })
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("DuckDB query error: {}", e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("DuckDB row parse error: {}", e))
            })?;

        Ok(anomalies)
    }

    async fn query_penalties(&self, range: TimeRange) -> Result<Vec<PenaltyRecord>> {
        let (start_ts, end_ts) = range.to_timestamp_range();
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT applied_at, host, reason, penalty_bits, expires_at FROM penalties WHERE applied_at BETWEEN ? AND ? ORDER BY applied_at DESC")
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("DuckDB prepare error: {}", e)))?;

        let penalties = stmt
            .query_map([start_ts, end_ts], |row| {
                Ok(PenaltyRecord {
                    applied_at: row.get(0)?,
                    host: row.get(1)?,
                    reason: row.get(2)?,
                    penalty_bits: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            })
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("DuckDB query error: {}", e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("DuckDB row parse error: {}", e))
            })?;

        Ok(penalties)
    }

    async fn query_useful_work(&self, range: TimeRange) -> Result<Vec<UsefulWorkRecord>> {
        let (start_ts, end_ts) = range.to_timestamp_range();
        let conn = self.conn.lock().unwrap();

        // Useful work doesn't have timestamp range filtering in the current schema
        // Just return all records for now
        let mut stmt = conn
            .prepare("SELECT task_id, status, completed_at FROM useful_work")
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("DuckDB prepare error: {}", e)))?;

        let work = stmt
            .query_map([], |row| {
                Ok(UsefulWorkRecord {
                    task_id: row.get(0)?,
                    status: row.get(1)?,
                    completed_at: row.get(2)?,
                })
            })
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("DuckDB query error: {}", e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("DuckDB row parse error: {}", e))
            })?;

        // Filter by time range if completed_at is present
        let (start_ts, end_ts) = (start_ts, end_ts);
        let filtered: Vec<_> = work
            .into_iter()
            .filter(|w| {
                w.completed_at
                    .map(|ts| ts >= start_ts && ts <= end_ts)
                    .unwrap_or(false)
            })
            .collect();

        Ok(filtered)
    }

    async fn query_cross_validations(
        &self,
        range: TimeRange,
    ) -> Result<Vec<CrossValidationRecord>> {
        let (start_ts, end_ts) = range.to_timestamp_range();
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT receipt_id, validated_at, consensus_reached, fuel_discrepancy_pct FROM cross_validations WHERE validated_at BETWEEN ? AND ? ORDER BY validated_at DESC")
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("DuckDB prepare error: {}", e)))?;

        let validations = stmt
            .query_map([start_ts, end_ts], |row| {
                Ok(CrossValidationRecord {
                    receipt_id: row.get(0)?,
                    validated_at: row.get(1)?,
                    consensus_reached: row.get(2)?,
                    fuel_discrepancy_pct: row.get(3)?,
                })
            })
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("DuckDB query error: {}", e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("DuckDB row parse error: {}", e))
            })?;

        Ok(validations)
    }

    async fn export(&self, range: TimeRange, format: ExportFormat) -> Result<Vec<u8>> {
        match format {
            ExportFormat::Json => {
                // Query and serialize to JSON
                let receipts = self.query_receipts(range).await?;
                serde_json::to_vec(&receipts).map_err(|e| {
                    NameServerError::Other(anyhow::anyhow!("JSON serialize error: {}", e))
                })
            }
            ExportFormat::Csv => {
                // Query and serialize to CSV
                let receipts = self.query_receipts(range).await?;
                let mut wtr = csv::Writer::from_writer(vec![]);

                for receipt in receipts {
                    wtr.serialize(receipt).map_err(|e| {
                        NameServerError::Other(anyhow::anyhow!("CSV serialize error: {}", e))
                    })?;
                }

                wtr.into_inner()
                    .map_err(|e| NameServerError::Other(anyhow::anyhow!("CSV flush error: {}", e)))
            }
            ExportFormat::Parquet => {
                // DuckDB has native COPY TO PARQUET support
                // For now, return error - would need temp file handling
                Err(NameServerError::Other(anyhow::anyhow!(
                    "DuckDB Parquet export requires file system access - use Parquet backend instead"
                )))
            }
        }
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_streaming: false,
            supports_aggregations: true,
            max_query_size: None, // No hardcoded limit
            columnar_storage: true,
            time_series_optimized: true,
        }
    }

    fn name(&self) -> &'static str {
        "duckdb"
    }
}

#[cfg(feature = "tier2-analytics")]
/// Factory for creating DuckDB analytics backends
pub struct DuckDBAnalyticsFactory;

#[cfg(feature = "tier2-analytics")]
impl AnalyticsBackendFactory for DuckDBAnalyticsFactory {
    fn create(&self, config: &HashMap<String, String>) -> Result<Box<dyn AnalyticsBackend>> {
        let database_path = config
            .get("database_path")
            .ok_or_else(|| {
                NameServerError::Other(anyhow::anyhow!(
                    "DuckDB backend requires 'database_path' config"
                ))
            })?
            .into();

        Ok(Box::new(DuckDBAnalytics::new(database_path)?))
    }

    fn name(&self) -> &'static str {
        "duckdb"
    }
}

// Placeholder stubs for non-tier2 builds
#[cfg(not(feature = "tier2-analytics"))]
pub struct DuckDBAnalytics;

#[cfg(not(feature = "tier2-analytics"))]
impl DuckDBAnalytics {
    pub fn new(_database_path: std::path::PathBuf) -> crate::error::Result<Self> {
        Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "DuckDB backend requires tier2-analytics feature"
        )))
    }
}
