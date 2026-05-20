//! Transparency log hash computation and verification

use crate::error::Result;
use crate::storage::NamesStorage;
use crate::types::{TransparencyLogEntry, TransparencyLogHash};
use blake3;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// Compute a merkle root hash for a set of log entries
pub fn compute_merkle_root(entries: &[TransparencyLogEntry]) -> String {
    if entries.is_empty() {
        return blake3::hash(b"empty").to_hex().to_string();
    }

    // Simple merkle tree: hash each entry, then hash pairs recursively
    let mut hashes: Vec<String> = entries
        .iter()
        .map(|entry| {
            let data = format!(
                "{}|{}|{}|{}",
                entry.id,
                entry.event_kind_str(),
                entry.subject.as_deref().unwrap_or(""),
                serde_json::to_string(&entry.payload).unwrap_or_else(|_| "null".into())
            );
            blake3::hash(data.as_bytes()).to_hex().to_string()
        })
        .collect();

    // Build merkle tree by hashing pairs
    while hashes.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in hashes.chunks(2) {
            let combined = if chunk.len() == 2 {
                format!("{}|{}", chunk[0], chunk[1])
            } else {
                chunk[0].clone()
            };
            next_level.push(blake3::hash(combined.as_bytes()).to_hex().to_string());
        }
        hashes = next_level;
    }

    hashes[0].clone()
}

/// Compute and store a transparency hash for the given time period
pub async fn compute_period_hash(
    storage: Arc<dyn NamesStorage>,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> Result<TransparencyLogHash> {
    // Fetch all entries in the period
    let entries = storage
        .list_transparency_log(Some(period_start), Some(period_end), None, 100_000)
        .await?;

    // Get previous hash to chain
    let previous_hash = storage
        .get_latest_transparency_hash()
        .await?
        .map(|h| h.merkle_root);

    // Compute merkle root
    let merkle_root = compute_merkle_root(&entries);

    // Create hash record
    let hash = TransparencyLogHash {
        id: Uuid::now_v7(),
        period_start,
        period_end,
        entry_count: entries.len() as i64,
        merkle_root,
        previous_hash,
        computed_at: Utc::now(),
    };

    // Store it
    storage.store_transparency_hash(hash.clone()).await?;

    Ok(hash)
}

/// Verify the chain integrity by checking all hashes link correctly
pub async fn verify_chain(storage: Arc<dyn NamesStorage>) -> Result<bool> {
    let hashes = storage.list_transparency_hashes(1000).await?;

    if hashes.is_empty() {
        return Ok(true); // Empty chain is valid
    }

    // Check each hash links to the previous one
    for i in 1..hashes.len() {
        let current = &hashes[i];
        let previous = &hashes[i - 1];

        // Check that current's previous_hash matches previous merkle_root
        if let Some(ref prev_hash) = current.previous_hash {
            if prev_hash != &previous.merkle_root {
                return Ok(false); // Chain broken!
            }
        } else if i > 0 {
            return Ok(false); // Should have previous hash
        }
    }

    Ok(true)
}

/// Background task that computes hashes every hour
pub async fn start_hash_computation_task(storage: Arc<dyn NamesStorage>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // 1 hour

    loop {
        interval.tick().await;

        let now = Utc::now();
        let period_start = now - Duration::hours(1);
        let period_end = now;

        match compute_period_hash(storage.clone(), period_start, period_end).await {
            Ok(hash) => {
                tracing::info!(
                    "Computed transparency hash for period {} to {}: {} entries, root: {}",
                    period_start,
                    period_end,
                    hash.entry_count,
                    &hash.merkle_root[..16]
                );
            }
            Err(e) => {
                tracing::error!("Failed to compute transparency hash: {}", e);
            }
        }
    }
}

impl TransparencyLogEntry {
    fn event_kind_str(&self) -> &'static str {
        use crate::types::TransparencyLogEventKind::*;
        match self.event_kind {
            TribunalDecision => "tribunal_decision",
            ReputationUpdate => "reputation_update",
            UsefulWorkCompleted => "useful_work_completed",
            PenaltyApplied => "penalty_applied",
            IdentityClaimed => "identity_claimed",
            HostRuntimePublished => "host_runtime_published", // Phase C
            CrossValidationDiscrepancy => "cross_validation_discrepancy", // Phase D
            TribunalCaseOpened => "tribunal_case_opened",     // Phase D
            PoWPenaltyApplied => "pow_penalty_applied",       // Phase D
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::types::TransparencyLogEventKind;

    #[tokio::test]
    async fn test_compute_merkle_root_empty() {
        let entries = vec![];
        let root = compute_merkle_root(&entries);
        assert!(!root.is_empty());
    }

    #[tokio::test]
    async fn test_compute_merkle_root_single() {
        let entry = TransparencyLogEntry {
            id: Uuid::now_v7(),
            event_kind: TransparencyLogEventKind::IdentityClaimed,
            subject: Some("alice@example.com".into()),
            payload: serde_json::json!({"test": "data"}),
            hash: None,
            recorded_at: Utc::now(),
        };
        let root = compute_merkle_root(&[entry]);
        assert!(!root.is_empty());
        assert_eq!(root.len(), 64); // blake3 hex output
    }

    #[tokio::test]
    async fn test_compute_period_hash() {
        let storage: Arc<dyn NamesStorage> = Arc::new(MemoryStorage::default());
        let now = Utc::now();

        // Add some entries
        for i in 0..5 {
            let entry = TransparencyLogEntry {
                id: Uuid::now_v7(),
                event_kind: TransparencyLogEventKind::UsefulWorkCompleted,
                subject: Some(format!("worker-{i}")),
                payload: serde_json::json!({"index": i}),
                hash: None,
                recorded_at: now - Duration::minutes(30),
            };
            storage.append_transparency_log(entry).await.unwrap();
        }

        // Compute hash for the period
        let period_start = now - Duration::hours(1);
        let period_end = now;
        let hash = compute_period_hash(storage.clone(), period_start, period_end)
            .await
            .unwrap();

        assert_eq!(hash.entry_count, 5);
        assert!(!hash.merkle_root.is_empty());
        assert!(hash.previous_hash.is_none()); // First hash
    }

    #[tokio::test]
    async fn test_verify_chain() {
        let storage: Arc<dyn NamesStorage> = Arc::new(MemoryStorage::default());
        let now = Utc::now();

        // Create a chain of hashes
        for i in 0..3 {
            let entry = TransparencyLogEntry {
                id: Uuid::now_v7(),
                event_kind: TransparencyLogEventKind::PenaltyApplied,
                subject: Some(format!("subject-{i}")),
                payload: serde_json::json!({}),
                hash: None,
                recorded_at: now - Duration::hours(3 - i as i64),
            };
            storage.append_transparency_log(entry).await.unwrap();

            // Compute hash for each hour
            let period_start = now - Duration::hours(3 - i as i64);
            let period_end = now - Duration::hours(2 - i as i64);
            compute_period_hash(storage.clone(), period_start, period_end)
                .await
                .unwrap();
        }

        // Verify chain integrity
        let is_valid = verify_chain(storage.clone()).await.unwrap();
        assert!(is_valid);
    }
}
