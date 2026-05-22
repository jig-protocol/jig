//! DuckDB analytics backend (standard tier) for jig-server.
//! Feature-gated with `analytics_duckdb`.

use std::cmp::Reverse;
use std::path::Path;
use std::sync::{Arc, Mutex};

use duckdb::{self, Connection, params};

use crate::analytics::{ReceiptStats, TimeRange};
use crate::error::{Result, ServerError};

/// Simple DuckDB analytics helper for receipt summaries.
pub struct DuckDbAnalytics {
    conn: Arc<Mutex<duckdb::Connection>>,
}

impl DuckDbAnalytics {
    /// Open or create a DuckDB database at the given path and ensure tables exist.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| ServerError::Server(format!("DuckDB open error: {e}")))?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS receipts (
                block_id TEXT PRIMARY KEY,
                executed_at BIGINT NOT NULL,
                fuel_used BIGINT NOT NULL,
                outcome TEXT NOT NULL,
                host TEXT NOT NULL,
                capability TEXT
            );
            "#,
        )
        .map_err(|e| ServerError::Server(format!("DuckDB schema error: {e}")))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Insert a single receipt projection row.
    pub fn insert_receipt(
        &self,
        block_id: &str,
        executed_at: i64,
        fuel_used: u64,
        outcome: &str,
        host: &str,
        capability: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        // Use a simple delete+insert to avoid ON CONFLICT portability concerns.
        conn.execute("DELETE FROM receipts WHERE block_id = ?", [block_id])
            .map_err(|e| ServerError::Server(format!("DuckDB delete error: {e}")))?;
        let mut stmt = conn
            .prepare("INSERT INTO receipts (block_id, executed_at, fuel_used, outcome, host, capability) VALUES (?, ?, ?, ?, ?, ?)")
            .map_err(|e| ServerError::Server(format!("DuckDB prepare error: {e}")))?;
        stmt.execute(params![
            block_id,
            executed_at,
            fuel_used as i64,
            outcome,
            host,
            capability
        ])
        .map_err(|e| ServerError::Server(format!("DuckDB insert error: {e}")))?;
        Ok(())
    }

    /// Compute ReceiptStats for a time range from DuckDB receipts table.
    pub fn receipt_stats_for_range(&self, range: TimeRange) -> Result<ReceiptStats> {
        let (start_ts, end_ts) = range.to_timestamp_range();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT executed_at, fuel_used, outcome, host, capability FROM receipts WHERE executed_at BETWEEN ? AND ? ORDER BY executed_at DESC")
            .map_err(|e| ServerError::Server(format!("DuckDB prepare error: {e}")))?;

        let mut total_receipts = 0u64;
        let mut total_fuel_used = 0u64;
        let mut successes = 0u64;
        let mut outcome_breakdown: std::collections::HashMap<String, u64> = Default::default();
        let mut host_counts: std::collections::HashMap<String, u64> = Default::default();
        let mut fuel_by_capability: std::collections::HashMap<String, u64> = Default::default();

        let mut rows = stmt
            .query(params![start_ts, end_ts])
            .map_err(|e| ServerError::Server(format!("DuckDB query error: {e}")))?;
        while let Some(row) = rows
            .next()
            .map_err(|e| ServerError::Server(format!("DuckDB row error: {e}")))?
        {
            let _executed_at: i64 = row
                .get(0)
                .map_err(|e| ServerError::Server(format!("DuckDB col error: {e}")))?;
            let fuel_used: i64 = row
                .get(1)
                .map_err(|e| ServerError::Server(format!("DuckDB col error: {e}")))?;
            let outcome: String = row
                .get(2)
                .map_err(|e| ServerError::Server(format!("DuckDB col error: {e}")))?;
            let host: String = row
                .get(3)
                .map_err(|e| ServerError::Server(format!("DuckDB col error: {e}")))?;
            let capability: Option<String> = row
                .get(4)
                .map_err(|e| ServerError::Server(format!("DuckDB col error: {e}")))?;

            total_receipts += 1;
            total_fuel_used = total_fuel_used.saturating_add(fuel_used.max(0) as u64);
            *host_counts.entry(host).or_insert(0) += 1;

            let label = match outcome.to_ascii_lowercase().as_str() {
                "ok" | "success" => "ok".to_string(),
                "soft_fail" | "softfail" | "soft-fail" => "soft_fail".to_string(),
                "hard_fail" | "hardfail" | "hard-fail" | "error" => "hard_fail".to_string(),
                other => other.to_string(),
            };
            if label == "ok" {
                successes += 1;
            }
            *outcome_breakdown.entry(label).or_insert(0) += 1;

            if let Some(cap) = capability.as_deref() {
                *fuel_by_capability.entry(cap.to_string()).or_insert(0) += fuel_used.max(0) as u64;
            }
        }

        if total_receipts == 0 {
            return Ok(ReceiptStats {
                total_receipts: 0,
                total_fuel_used: 0,
                avg_fuel_per_receipt: 0.0,
                success_rate: 0.0,
                outcome_breakdown,
                top_hosts: Vec::new(),
                fuel_by_capability,
                timings_p50_ms: None,
            });
        }

        let avg_fuel_per_receipt = total_fuel_used as f64 / total_receipts as f64;
        let success_rate = successes as f64 / total_receipts as f64;
        let mut top_hosts: Vec<(String, u64)> = host_counts.into_iter().collect();
        top_hosts.sort_by_key(|(_, c)| Reverse(*c));
        top_hosts.truncate(10);

        Ok(ReceiptStats {
            total_receipts,
            total_fuel_used,
            avg_fuel_per_receipt,
            success_rate,
            outcome_breakdown,
            top_hosts,
            fuel_by_capability,
            timings_p50_ms: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "analytics_duckdb")]
    #[test]
    fn duckdb_receipt_stats_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("analytics.duckdb");
        let duck = DuckDbAnalytics::new(&db_path).unwrap();

        // Two receipts: one ok, one hard_fail
        duck.insert_receipt(
            "a",
            1_731_000_000,
            100,
            "ok",
            "did:jig:server:local",
            Some("core:compute"),
        )
        .unwrap();
        duck.insert_receipt(
            "b",
            1_731_000_100,
            50,
            "hard_fail",
            "did:jig:server:local",
            None,
        )
        .unwrap();

        let stats = duck
            .receipt_stats_for_range(TimeRange::Custom {
                start_ts: 1_700_000_000,
                end_ts: 1_800_000_000,
            })
            .unwrap();

        assert_eq!(stats.total_receipts, 2);
        assert_eq!(stats.total_fuel_used, 150);
        assert!((stats.avg_fuel_per_receipt - 75.0).abs() < f64::EPSILON);
        assert!((stats.success_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(stats.outcome_breakdown.get("ok").copied().unwrap_or(0), 1);
        assert_eq!(
            stats
                .outcome_breakdown
                .get("hard_fail")
                .copied()
                .unwrap_or(0),
            1
        );
        assert!(
            stats
                .top_hosts
                .iter()
                .any(|(h, _)| h == "did:jig:server:local")
        );
        assert_eq!(
            stats
                .fuel_by_capability
                .get("core:compute")
                .copied()
                .unwrap_or(0),
            100
        );
        assert!(stats.timings_p50_ms.is_none());
    }
}
