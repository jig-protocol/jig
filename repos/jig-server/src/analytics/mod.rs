//! SQLite analytics for jig-server receipts.
//! Simple ReceiptStats over a time range, built directly from stored BlockReceipt JSON.

use std::collections::HashMap;

use chrono::{Duration, TimeZone, Utc};
use jig_core::{OutcomeStatus, Timings};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::storage::{SqliteBlockStore, StoredReceipt};

#[cfg(feature = "analytics_clickhouse")]
pub mod clickhouse;
pub mod dispatcher;
#[cfg(feature = "analytics_duckdb")]
pub mod duckdb;
#[cfg(feature = "analytics_parquet")]
pub mod parquet;

pub use dispatcher::{AnalyticsDispatcher, AnalyticsRow, AnalyticsSink};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeRange {
    LastHour,
    LastDay,
    LastWeek,
    LastMonth,
    Custom { start_ts: i64, end_ts: i64 },
}

impl TimeRange {
    pub fn to_timestamp_range(&self) -> (i64, i64) {
        let now = Utc::now();
        match *self {
            TimeRange::LastHour => {
                let start = now - Duration::hours(1);
                (start.timestamp(), now.timestamp())
            }
            TimeRange::LastDay => {
                let start = now - Duration::days(1);
                (start.timestamp(), now.timestamp())
            }
            TimeRange::LastWeek => {
                let start = now - Duration::weeks(1);
                (start.timestamp(), now.timestamp())
            }
            TimeRange::LastMonth => {
                let start = now - Duration::days(30);
                (start.timestamp(), now.timestamp())
            }
            TimeRange::Custom { start_ts, end_ts } => (start_ts, end_ts),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiptStats {
    pub total_receipts: u64,
    pub total_fuel_used: u64,
    pub avg_fuel_per_receipt: f64,
    pub success_rate: f64,
    pub outcome_breakdown: HashMap<String, u64>,
    pub top_hosts: Vec<(String, u64)>,
    pub fuel_by_capability: HashMap<String, u64>,
    pub timings_p50_ms: Option<Timings>,
}

pub fn receipt_stats_for_range(store: &SqliteBlockStore, range: TimeRange) -> Result<ReceiptStats> {
    let (start_ts, end_ts) = range.to_timestamp_range();
    let start = Utc
        .timestamp_opt(start_ts, 0)
        .single()
        .unwrap_or_else(Utc::now);
    let end = Utc
        .timestamp_opt(end_ts, 0)
        .single()
        .unwrap_or_else(Utc::now);

    let receipts: Vec<StoredReceipt> =
        store.list_receipts_in_range(Some(start), Some(end), None)?;

    if receipts.is_empty() {
        return Ok(ReceiptStats {
            total_receipts: 0,
            total_fuel_used: 0,
            avg_fuel_per_receipt: 0.0,
            success_rate: 0.0,
            outcome_breakdown: HashMap::new(),
            top_hosts: Vec::new(),
            fuel_by_capability: HashMap::new(),
            timings_p50_ms: None,
        });
    }

    let total_receipts = receipts.len() as u64;
    let mut total_fuel_used = 0u64;
    let mut successes = 0u64;
    let mut outcome_breakdown: HashMap<String, u64> = HashMap::new();
    let mut host_counts: HashMap<String, u64> = HashMap::new();
    let mut fuel_by_capability: HashMap<String, u64> = HashMap::new();

    // naive p50 (median) approximation over exec from timings_ms
    let mut exec_samples: Vec<u32> = Vec::with_capacity(receipts.len());
    let mut init_samples: Vec<u32> = Vec::with_capacity(receipts.len());

    for r in &receipts {
        total_fuel_used = total_fuel_used.saturating_add(r.receipt.fuel_used);
        *host_counts.entry(r.receipt.host.clone()).or_insert(0) += 1;

        let label = match r
            .receipt
            .outcome
            .as_ref()
            .map(|o| o.status.clone())
            .unwrap_or(OutcomeStatus::Ok)
        {
            OutcomeStatus::Ok => "ok".to_string(),
            OutcomeStatus::SoftFail => "soft_fail".to_string(),
            OutcomeStatus::HardFail => "hard_fail".to_string(),
        };
        if label == "ok" {
            successes += 1;
        }
        *outcome_breakdown.entry(label).or_insert(0) += 1;

        if let Some(counters) = &r.receipt.counters {
            for (cap, fuel) in &counters.fuel_by_capability {
                *fuel_by_capability.entry(cap.clone()).or_insert(0) += *fuel;
            }
        }
        if let Some(t) = &r.receipt.timings_ms {
            exec_samples.push(t.exec);
            init_samples.push(t.init);
        }
    }

    let avg_fuel_per_receipt = total_fuel_used as f64 / total_receipts as f64;
    let success_rate = successes as f64 / total_receipts as f64;
    let mut top_hosts: Vec<(String, u64)> = host_counts.into_iter().collect();
    top_hosts.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
    top_hosts.truncate(10);

    let timings_p50_ms = if exec_samples.is_empty() {
        None
    } else {
        exec_samples.sort_unstable();
        init_samples.sort_unstable();
        let mid = exec_samples.len() / 2;
        let exec_p50 = exec_samples[mid];
        let init_p50 = init_samples[mid];
        Some(Timings::new(0, init_p50, exec_p50))
    };

    Ok(ReceiptStats {
        total_receipts,
        total_fuel_used,
        avg_fuel_per_receipt,
        success_rate,
        outcome_breakdown,
        top_hosts,
        fuel_by_capability,
        timings_p50_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{SqliteBlockStore, StoredBlock, StoredResource};
    use chrono::Utc;
    use jig_core::bundle::BlockBundle;
    use jig_core::manifest::{Author, BlockManifest};
    use jig_core::receipt::CountersBuilder;
    use semver::Version;
    use std::path::PathBuf;
    use time::OffsetDateTime;

    fn temp_path() -> PathBuf {
        let dir = tempfile::tempdir().unwrap();
        dir.path().join("analytics_test.db")
    }

    fn sample_block_manifest() -> BlockManifest {
        BlockManifest::builder()
            .version(Version::new(0, 1, 0))
            .author(Author {
                did: "did:jig:test".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap()
    }

    fn block_cid_for_manifest(manifest: &BlockManifest) -> cid::Cid {
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = BlockBundle {
            manifest_bytes: &manifest_bytes,
            code_bytes: &[],
            resources: vec![],
        };
        bundle.block_cid().unwrap()
    }

    #[test]
    fn stats_on_empty_db_are_zero() {
        let path = temp_path();
        let store = SqliteBlockStore::new(&path).unwrap();
        let stats = receipt_stats_for_range(&store, TimeRange::LastDay).unwrap();
        assert_eq!(stats.total_receipts, 0);
        assert_eq!(stats.total_fuel_used, 0);
        assert_eq!(stats.success_rate, 0.0);
        assert!(stats.top_hosts.is_empty());
        assert!(stats.outcome_breakdown.is_empty());
    }

    #[test]
    fn stats_with_mixed_outcomes_and_fuel() {
        let path = temp_path();
        let store = SqliteBlockStore::new(&path).unwrap();

        // Prepare block + receipt A (OK)
        let manifest = sample_block_manifest();
        let cid = block_cid_for_manifest(&manifest);
        let block = StoredBlock {
            cid,
            manifest: manifest.clone(),
            code: vec![],
            resources: Vec::<StoredResource>::new(),
            created_at: Utc::now(),
        };
        store.store_block(&block).unwrap();

        let executed_at = OffsetDateTime::now_utc();
        let mut builder = jig_core::receipt::BlockReceipt::builder(cid)
            .host("did:jig:server:local")
            .executed_at(executed_at)
            .render_hash("sha256:abcd")
            .fuel_used(100);
        // counters by capability
        let usage = jig_core::capability_scope::CapabilityUsageKey::without_scope("core:compute");
        let counters = CountersBuilder::new()
            .fuel_total(100)
            .add_fuel(&usage, 100)
            .build();
        builder = builder.counters(counters).capability("core:compute");
        let receipt_ok = builder.build().unwrap();
        store
            .store_receipt(&crate::storage::StoredReceipt {
                cid,
                receipt: receipt_ok,
                created_at: Utc::now(),
            })
            .unwrap();

        // Prepare block + receipt B (HardFail)
        // Use a distinct manifest to ensure a distinct CID
        let manifest_b = BlockManifest::builder()
            .version(Version::new(0, 1, 1))
            .author(Author {
                did: "did:jig:test-b".into(),
                public_key: None,
                roles: vec![],
            })
            .build()
            .unwrap();
        let cid_b = block_cid_for_manifest(&manifest_b);
        let block_b = StoredBlock {
            cid: cid_b,
            manifest: manifest_b,
            code: vec![],
            resources: Vec::<StoredResource>::new(),
            created_at: Utc::now(),
        };
        store.store_block(&block_b).unwrap();

        let builder_b = jig_core::receipt::BlockReceipt::builder(cid_b)
            .host("did:jig:server:local")
            .executed_at(executed_at)
            .render_hash("sha256:cafe")
            .fuel_used(50)
            .outcome(jig_core::receipt::Outcome {
                status: OutcomeStatus::HardFail,
                affordances: vec![],
                reason: Some(jig_core::receipt::ReasonCode::CapabilityDenied),
            });
        let receipt_fail = builder_b.build().unwrap();
        store
            .store_receipt(&crate::storage::StoredReceipt {
                cid: cid_b,
                receipt: receipt_fail,
                created_at: Utc::now(),
            })
            .unwrap();

        let stats = receipt_stats_for_range(&store, TimeRange::LastDay).unwrap();
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
    }
}
