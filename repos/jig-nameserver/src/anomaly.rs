//! Receipt anomaly detection for adaptive governance
//!
//! Detects suspicious patterns in executable block receipts and auto-escalates
//! to tribunal or applies PoW penalties based on severity.
//!
//! Phase D: Cross-nameserver verification protocol for detecting unreliable hosts.
//! All thresholds are config-driven via jig-config for operator customization.

use crate::config::{AnomalyDetectionConfig, FederationConfig};
use crate::error::{NameServerError, Result};
use crate::federation::discover_for_domain;
use crate::types::{AnomalyKind, AnomalySeverity, ReceiptAnomaly};
use chrono::Utc;
use jig_core::{BlockReceipt, OutcomeStatus};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Response wrapper for /v1/receipts/:block_id endpoint
#[derive(Deserialize)]
struct GetReceiptResponse {
    receipt: Option<BlockReceipt>,
}

/// Convert OutcomeStatus to string for serialization
fn outcome_status_to_str(status: &OutcomeStatus) -> &'static str {
    match status {
        OutcomeStatus::Ok => "ok",
        OutcomeStatus::SoftFail => "soft_fail",
        OutcomeStatus::HardFail => "hard_fail",
    }
}

/// Anomaly detector for receipt analysis (config-driven)
pub struct ReceiptAnomalyDetector {
    anomaly_config: Arc<AnomalyDetectionConfig>,
    #[allow(dead_code)] // Will be used for Tier 2/3 federated analytics
    federation_config: Arc<FederationConfig>,
    http_client: Client,
}

impl ReceiptAnomalyDetector {
    /// Create a new anomaly detector with config-driven behavior
    pub fn new(
        anomaly_config: Arc<AnomalyDetectionConfig>,
        federation_config: Arc<FederationConfig>,
    ) -> Self {
        let timeout_secs = anomaly_config.cross_validation.validation_timeout_secs;
        Self {
            anomaly_config,
            federation_config,
            http_client: Client::builder()
                .timeout(Duration::from_secs(timeout_secs as u64))
                .build()
                .unwrap(),
        }
    }

    /// Analyze a receipt for anomalies
    pub fn analyze_receipt(
        &self,
        receipt: &BlockReceipt,
        historical_avg_fuel: Option<u64>,
    ) -> Result<Vec<ReceiptAnomaly>> {
        let mut anomalies = Vec::new();

        // Rule 1: Non-deterministic execution (renders_match=false)
        if let Some(renders_match) = receipt.renders_match
            && !renders_match
        {
            anomalies.push(ReceiptAnomaly {
                id: Uuid::now_v7(),
                block_id: receipt.block_id.to_string(),
                host_did: receipt.host.clone(),
                kind: AnomalyKind::NonDeterministicExecution,
                severity: AnomalySeverity::High,
                description: "Receipt indicates non-deterministic execution (renders_match=false)"
                    .into(),
                evidence: json!({
                    "renders_match": false,
                    "render_hash": receipt.render_hash,
                    "fuel_used": receipt.fuel_used
                }),
                detected_at: Utc::now(),
                auto_escalated: false,
                tribunal_case_id: None,
            });
        }

        // Rule 2: Excessive network usage
        if let Some(ref counters) = receipt.counters
            && let Some(&net_fuel) = counters.fuel_by_capability.get("net.fetch")
            && net_fuel > self.anomaly_config.max_network_fuel
        {
            anomalies.push(ReceiptAnomaly {
                id: Uuid::now_v7(),
                block_id: receipt.block_id.to_string(),
                host_did: receipt.host.clone(),
                kind: AnomalyKind::ExcessiveNetworkUsage,
                severity: AnomalySeverity::Medium,
                description: format!(
                    "Excessive network fuel usage: {} (max: {})",
                    net_fuel, self.anomaly_config.max_network_fuel
                ),
                evidence: json!({
                    "net_fuel": net_fuel,
                    "max_allowed": self.anomaly_config.max_network_fuel,
                    "total_fuel": receipt.fuel_used
                }),
                detected_at: Utc::now(),
                auto_escalated: false,
                tribunal_case_id: None,
            });
        }

        // Rule 3: Fuel usage anomalies (if historical average available)
        if let Some(avg_fuel) = historical_avg_fuel {
            let excessive_threshold =
                (avg_fuel as f64 * self.anomaly_config.fuel_anomaly.excessive_threshold) as u64;
            let suspicious_threshold =
                (avg_fuel as f64 * self.anomaly_config.fuel_anomaly.suspicious_threshold) as u64;

            if receipt.fuel_used > excessive_threshold {
                anomalies.push(ReceiptAnomaly {
                    id: Uuid::now_v7(),
                    block_id: receipt.block_id.to_string(),
                    host_did: receipt.host.clone(),
                    kind: AnomalyKind::ExcessiveFuelUsage,
                    severity: AnomalySeverity::Medium,
                    description: format!(
                        "Fuel usage {} significantly above average {} (threshold: {})",
                        receipt.fuel_used, avg_fuel, excessive_threshold
                    ),
                    evidence: json!({
                        "fuel_used": receipt.fuel_used,
                        "historical_avg": avg_fuel,
                        "threshold": excessive_threshold,
                        "multiplier": self.anomaly_config.fuel_anomaly.excessive_threshold
                    }),
                    detected_at: Utc::now(),
                    auto_escalated: false,
                    tribunal_case_id: None,
                });
            } else if receipt.fuel_used < suspicious_threshold && avg_fuel > 1000 {
                // Only flag if average is significant (> 1000 fuel)
                anomalies.push(ReceiptAnomaly {
                    id: Uuid::now_v7(),
                    block_id: receipt.block_id.to_string(),
                    host_did: receipt.host.clone(),
                    kind: AnomalyKind::SuspiciousFuelPattern,
                    severity: AnomalySeverity::Low,
                    description: format!(
                        "Fuel usage {} significantly below average {} (threshold: {})",
                        receipt.fuel_used, avg_fuel, suspicious_threshold
                    ),
                    evidence: json!({
                        "fuel_used": receipt.fuel_used,
                        "historical_avg": avg_fuel,
                        "threshold": suspicious_threshold,
                        "multiplier": self.anomaly_config.fuel_anomaly.suspicious_threshold
                    }),
                    detected_at: Utc::now(),
                    auto_escalated: false,
                    tribunal_case_id: None,
                });
            }
        }

        // Rule 4: Hard failure detection
        if let Some(ref outcome) = receipt.outcome
            && outcome.status == OutcomeStatus::HardFail
        {
            anomalies.push(ReceiptAnomaly {
                id: Uuid::now_v7(),
                block_id: receipt.block_id.to_string(),
                host_did: receipt.host.clone(),
                kind: AnomalyKind::RepeatedHardFailures,
                severity: AnomalySeverity::Low, // Will be escalated if repeated
                description: "Receipt indicates hard failure".into(),
                evidence: json!({
                    "outcome_status": "hard_fail",
                    "reason": outcome.reason,
                    "fuel_used": receipt.fuel_used
                }),
                detected_at: Utc::now(),
                auto_escalated: false,
                tribunal_case_id: None,
            });
        }

        Ok(anomalies)
    }

    /// Calculate recommended PoW penalty bits based on anomaly severity
    pub fn calculate_pow_penalty(&self, severity: &AnomalySeverity) -> u32 {
        match severity {
            AnomalySeverity::Low => 0,      // No penalty, log only
            AnomalySeverity::Medium => 2,   // +2 bits warning
            AnomalySeverity::High => 4,     // +4 bits tribunal
            AnomalySeverity::Critical => 8, // +8 bits suspension
        }
    }

    /// Determine if anomaly should auto-escalate to tribunal
    pub fn should_auto_escalate(&self, severity: &AnomalySeverity) -> bool {
        matches!(severity, AnomalySeverity::High | AnomalySeverity::Critical)
    }

    /// Phase D: Cross-validate receipt with federated nameserver peers
    ///
    /// Requests receipt validation from 2+ federated peers and compares:
    /// - fuel_used (±5% tolerance for determinism variations)
    /// - outcome.status
    /// - render_hash
    ///
    /// Returns anomaly if majority of peers disagree with this host's receipt.
    pub async fn cross_validate_receipt(
        &self,
        receipt: &BlockReceipt,
        federation_peers: &[String],
    ) -> Result<Option<ReceiptAnomaly>> {
        if federation_peers.len() < 2 {
            debug!(
                "Not enough federation peers ({}) for cross-validation, skipping",
                federation_peers.len()
            );
            return Ok(None);
        }

        info!(
            host = %receipt.host,
            block_id = %receipt.block_id,
            peers = federation_peers.len(),
            "Requesting cross-validation from federation peers"
        );

        // Request validation from each peer
        let mut peer_receipts = Vec::new();
        let max_peers = self.anomaly_config.cross_validation.max_validation_peers;
        for peer_url in federation_peers.iter().take(max_peers) {
            match self
                .request_peer_receipt(peer_url, &receipt.block_id.to_string())
                .await
            {
                Ok(Some(peer_receipt)) => peer_receipts.push(peer_receipt),
                Ok(None) => {
                    debug!(peer = %peer_url, "Peer doesn't have this receipt");
                }
                Err(e) => {
                    warn!(peer = %peer_url, error = %e, "Failed to get receipt from peer");
                }
            }
        }

        if peer_receipts.is_empty() {
            debug!("No peer receipts available for cross-validation");
            return Ok(None);
        }

        // Compare receipts
        let mut fuel_disagreements = 0;
        let mut outcome_disagreements = 0;
        let mut render_hash_disagreements = 0;

        for peer_receipt in &peer_receipts {
            // Compare fuel_used (tolerance from config)
            let fuel_tolerance = self.anomaly_config.cross_validation.fuel_tolerance_pct;
            let fuel_diff_pct = ((receipt.fuel_used as f64 - peer_receipt.fuel_used as f64).abs()
                / receipt.fuel_used as f64)
                * 100.0;
            if fuel_diff_pct > fuel_tolerance {
                fuel_disagreements += 1;
            }

            // Compare outcome
            let our_outcome = receipt
                .outcome
                .as_ref()
                .map(|o| o.status.clone())
                .unwrap_or(OutcomeStatus::Ok);
            let peer_outcome = peer_receipt
                .outcome
                .as_ref()
                .map(|o| o.status.clone())
                .unwrap_or(OutcomeStatus::Ok);
            if our_outcome != peer_outcome {
                outcome_disagreements += 1;
            }

            // Compare render_hash
            if receipt.render_hash != peer_receipt.render_hash {
                render_hash_disagreements += 1;
            }
        }

        // Determine if majority disagrees (consensus threshold from config)
        let total_peers = peer_receipts.len();
        let consensus_threshold = self.anomaly_config.cross_validation.consensus_threshold;
        let required_agreement = (total_peers as f64 * consensus_threshold).ceil() as usize;

        if fuel_disagreements >= required_agreement
            || outcome_disagreements >= required_agreement
            || render_hash_disagreements >= required_agreement
        {
            info!(
                host = %receipt.host,
                block_id = %receipt.block_id,
                fuel_disagree = fuel_disagreements,
                outcome_disagree = outcome_disagreements,
                render_hash_disagree = render_hash_disagreements,
                total_peers = total_peers,
                "Cross-validation FAILED - majority of peers disagree"
            );

            return Ok(Some(ReceiptAnomaly {
                id: Uuid::now_v7(),
                block_id: receipt.block_id.to_string(),
                host_did: receipt.host.clone(),
                kind: AnomalyKind::CrossValidationFailed,
                severity: AnomalySeverity::Critical,
                description: format!(
                    "Majority of peers ({}/{}) disagree with this host's receipt",
                    std::cmp::max(
                        std::cmp::max(fuel_disagreements, outcome_disagreements),
                        render_hash_disagreements
                    ),
                    total_peers
                ),
                evidence: json!({
                    "local_fuel": receipt.fuel_used,
                    "local_outcome": receipt.outcome.as_ref().map(|o| outcome_status_to_str(&o.status)),
                    "local_render_hash": receipt.render_hash,
                    "peer_count": total_peers,
                    "fuel_disagreements": fuel_disagreements,
                    "outcome_disagreements": outcome_disagreements,
                    "render_hash_disagreements": render_hash_disagreements,
                    "peer_receipts": peer_receipts.iter().map(|r| json!({
                        "host": r.host,
                        "fuel_used": r.fuel_used,
                        "outcome": r.outcome.as_ref().map(|o| outcome_status_to_str(&o.status)),
                        "render_hash": r.render_hash,
                    })).collect::<Vec<_>>(),
                }),
                detected_at: Utc::now(),
                auto_escalated: false,
                tribunal_case_id: None,
            }));
        }

        info!(
            host = %receipt.host,
            block_id = %receipt.block_id,
            peers = total_peers,
            "Cross-validation PASSED - receipts match across federation"
        );

        Ok(None)
    }

    /// Request receipt from a peer nameserver
    async fn request_peer_receipt(
        &self,
        peer_url: &str,
        block_id: &str,
    ) -> Result<Option<BlockReceipt>> {
        let url = format!("{peer_url}/v1/receipts/{block_id}");

        debug!(url = %url, "Requesting receipt from peer");

        let response =
            self.http_client.get(&url).send().await.map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("Peer request failed: {}", e))
            })?;

        if response.status().is_success() {
            let wrapper: GetReceiptResponse = response.json().await.map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("Failed to parse peer receipt: {}", e))
            })?;
            Ok(wrapper.receipt)
        } else {
            Err(NameServerError::Other(anyhow::anyhow!(
                "Peer returned error: {}",
                response.status()
            )))
        }
    }

    /// Discover federation peer nameservers for cross-validation
    pub async fn discover_federation_peers(
        &self,
        host: &str,
        seed_peers: &[String],
    ) -> Result<Vec<String>> {
        // Use seed peers from config if available
        if !seed_peers.is_empty() {
            return Ok(seed_peers.to_vec());
        }

        // Extract domain from host
        let domain = Self::extract_domain(host)?;

        // Discover via DNS
        let peers = discover_for_domain(&domain).await?;
        Ok(peers
            .into_iter()
            .map(|addr| format!("http://{addr}"))
            .collect())
    }

    /// Extract domain from host identifier
    fn extract_domain(host: &str) -> Result<String> {
        // Host format examples: "ns1.example.com", "10.0.1.5:7070", "example.com"
        let cleaned = host.split(':').next().unwrap_or(host);

        // If it's an IP address, we can't extract a domain
        if cleaned.parse::<std::net::IpAddr>().is_ok() {
            return Err(NameServerError::BadRequest(
                "Cannot extract domain from IP address".into(),
            ));
        }

        Ok(cleaned.to_string())
    }
}

/// Auto-escalate anomaly to tribunal and apply penalty
/// Returns (updated_anomaly, tribunal_case, penalty)
pub async fn escalate_anomaly(
    anomaly: ReceiptAnomaly,
    detector: &ReceiptAnomalyDetector,
    storage: &dyn crate::storage::NamesStorage,
) -> Result<(
    ReceiptAnomaly,
    crate::types::TribunalCase,
    crate::types::PoWPenalty,
)> {
    use crate::types::{
        PenaltyReason, PoWPenalty, ReputationSubject, TribunalCase, TribunalStatus,
    };
    use chrono::Utc;
    use uuid::Uuid;

    // Create tribunal case
    let case_id = Uuid::now_v7();
    let tribunal_case = TribunalCase {
        id: case_id,
        subject: ReputationSubject::Server, // Host is a server in our model
        subject_id: anomaly.host_did.clone(),
        ruleset: "receipt_verification".to_string(),
        status: TribunalStatus::Open,
        reason: format!("Auto-escalated: {}", anomaly.description),
        reporter: "system:anomaly_detector".to_string(),
        severity: Some(format!("{:?}", anomaly.severity)),
        metadata: Some(json!({
            "anomaly_id": anomaly.id.to_string(),
            "anomaly_kind": format!("{:?}", anomaly.kind),
            "block_id": anomaly.block_id,
            "evidence": anomaly.evidence,
        })),
        opened_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Calculate penalty bits
    let penalty_bits = detector.calculate_pow_penalty(&anomaly.severity);

    // Create penalty
    let penalty_id = Uuid::now_v7();
    let penalty = PoWPenalty {
        id: penalty_id,
        host_did: anomaly.host_did.clone(),
        reason: PenaltyReason::ReceiptAnomaly(anomaly.kind.clone()),
        additional_bits: penalty_bits,
        applied_at: Utc::now(),
        expires_at: None, // Permanent until tribunal resolves
        anomaly_id: Some(anomaly.id),
        tribunal_case_id: Some(case_id),
    };

    // Update anomaly with tribunal case link
    let mut updated_anomaly = anomaly.clone();
    updated_anomaly.auto_escalated = true;
    updated_anomaly.tribunal_case_id = Some(case_id);

    // Store tribunal case, penalty, and updated anomaly
    storage.create_tribunal_case(tribunal_case.clone()).await?;
    storage.apply_penalty(penalty.clone()).await?;
    storage.store_anomaly(updated_anomaly.clone()).await?;

    Ok((updated_anomaly, tribunal_case, penalty))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::{Counters, HashAlgorithms};
    use std::collections::BTreeMap;

    fn build_test_receipt(fuel_used: u64, renders_match: Option<bool>) -> BlockReceipt {
        BlockReceipt {
            block_id: cid::Cid::default(),
            host: "test-host".to_string(),
            executed_at: time::OffsetDateTime::now_utc(),
            render_hash: "test-hash".to_string(),
            fuel_used,
            memory_peak_mb: Some(32),
            renders_match,
            counters: None,
            timings_ms: None,
            limits: None,
            outcome: None,
            capabilities_used: vec![],
            attestations: vec![],
            signature: None,
            metadata: BTreeMap::new(),
            hash_algorithms: HashAlgorithms::default(),
            receipt_schema_version: "0.2".to_string(),
        }
    }

    #[test]
    fn test_non_deterministic_detection() {
        let anomaly_config = Arc::new(AnomalyDetectionConfig::default());
        let federation_config = Arc::new(FederationConfig::default());
        let detector = ReceiptAnomalyDetector::new(anomaly_config, federation_config);
        let receipt = build_test_receipt(1000, Some(false));

        let anomalies = detector.analyze_receipt(&receipt, None).unwrap();

        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].kind,
            AnomalyKind::NonDeterministicExecution
        ));
        assert!(matches!(anomalies[0].severity, AnomalySeverity::High));
        assert!(!anomalies[0].auto_escalated);
    }

    #[test]
    fn test_excessive_fuel_detection() {
        let anomaly_config = Arc::new(AnomalyDetectionConfig::default());
        let federation_config = Arc::new(FederationConfig::default());
        let detector = ReceiptAnomalyDetector::new(anomaly_config, federation_config);
        let receipt = build_test_receipt(10000, Some(true));

        let anomalies = detector.analyze_receipt(&receipt, Some(1000)).unwrap();

        assert!(
            anomalies
                .iter()
                .any(|a| matches!(a.kind, AnomalyKind::ExcessiveFuelUsage))
        );
    }

    #[test]
    fn test_suspicious_low_fuel_detection() {
        let anomaly_config = Arc::new(AnomalyDetectionConfig::default());
        let federation_config = Arc::new(FederationConfig::default());
        let detector = ReceiptAnomalyDetector::new(anomaly_config, federation_config);
        let receipt = build_test_receipt(100, Some(true));

        let anomalies = detector.analyze_receipt(&receipt, Some(5000)).unwrap();

        assert!(
            anomalies
                .iter()
                .any(|a| matches!(a.kind, AnomalyKind::SuspiciousFuelPattern))
        );
    }

    #[test]
    fn test_excessive_network_usage() {
        let anomaly_config = Arc::new(AnomalyDetectionConfig::default());
        let federation_config = Arc::new(FederationConfig::default());
        let detector = ReceiptAnomalyDetector::new(anomaly_config, federation_config);
        let mut receipt = build_test_receipt(2000000, Some(true));

        let mut fuel_by_cap = BTreeMap::new();
        fuel_by_cap.insert("net.fetch".to_string(), 1_500_000);
        receipt.counters = Some(Counters {
            fuel_total: 2000000,
            fuel_by_capability: fuel_by_cap,
            bytes_tx: 1024,
            bytes_rx: 2048,
            syscalls: 100,
            status_by_capability: BTreeMap::new(),
        });

        let anomalies = detector.analyze_receipt(&receipt, None).unwrap();

        assert!(
            anomalies
                .iter()
                .any(|a| matches!(a.kind, AnomalyKind::ExcessiveNetworkUsage))
        );
    }

    #[test]
    fn test_pow_penalty_calculation() {
        let anomaly_config = Arc::new(AnomalyDetectionConfig::default());
        let federation_config = Arc::new(FederationConfig::default());
        let detector = ReceiptAnomalyDetector::new(anomaly_config, federation_config);

        assert_eq!(detector.calculate_pow_penalty(&AnomalySeverity::Low), 0);
        assert_eq!(detector.calculate_pow_penalty(&AnomalySeverity::Medium), 2);
        assert_eq!(detector.calculate_pow_penalty(&AnomalySeverity::High), 4);
        assert_eq!(
            detector.calculate_pow_penalty(&AnomalySeverity::Critical),
            8
        );
    }

    #[test]
    fn test_auto_escalation_logic() {
        let anomaly_config = Arc::new(AnomalyDetectionConfig::default());
        let federation_config = Arc::new(FederationConfig::default());
        let detector = ReceiptAnomalyDetector::new(anomaly_config, federation_config);

        assert!(!detector.should_auto_escalate(&AnomalySeverity::Low));
        assert!(!detector.should_auto_escalate(&AnomalySeverity::Medium));
        assert!(detector.should_auto_escalate(&AnomalySeverity::High));
        assert!(detector.should_auto_escalate(&AnomalySeverity::Critical));
    }

    #[tokio::test]
    async fn test_full_escalation_flow() {
        use crate::storage::{MemoryStorage, NamesStorage};
        use crate::types::TribunalStatus;

        let storage = MemoryStorage::default();
        let anomaly_config = Arc::new(AnomalyDetectionConfig::default());
        let federation_config = Arc::new(FederationConfig::default());
        let detector = ReceiptAnomalyDetector::new(anomaly_config, federation_config);

        // Create a high-severity anomaly (non-deterministic execution)
        let receipt = build_test_receipt(1000, Some(false));
        let anomalies = detector.analyze_receipt(&receipt, None).unwrap();
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(anomalies[0].severity, AnomalySeverity::High));

        let anomaly = anomalies[0].clone();

        // Escalate it
        let (updated_anomaly, tribunal_case, penalty) =
            super::escalate_anomaly(anomaly.clone(), &detector, &storage)
                .await
                .unwrap();

        // Verify anomaly was updated
        assert!(updated_anomaly.auto_escalated);
        assert!(updated_anomaly.tribunal_case_id.is_some());

        // Verify tribunal case was created
        assert_eq!(tribunal_case.status, TribunalStatus::Open);
        assert_eq!(tribunal_case.subject_id, anomaly.host_did);
        assert!(tribunal_case.reason.contains("Auto-escalated"));

        // Verify penalty was applied
        assert_eq!(penalty.additional_bits, 4); // High severity = 4 bits
        assert_eq!(penalty.host_did, anomaly.host_did);
        assert!(penalty.anomaly_id.is_some());
        assert!(penalty.tribunal_case_id.is_some());

        // Verify everything was stored
        let penalties = storage
            .get_active_penalties(&anomaly.host_did)
            .await
            .unwrap();
        assert_eq!(penalties.len(), 1);

        let total_bits = storage
            .get_total_penalty_bits(&anomaly.host_did)
            .await
            .unwrap();
        assert_eq!(total_bits, 4);
    }
}
