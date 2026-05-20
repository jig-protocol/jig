//! Core types for identity, claims, and aliases

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeyEd25519(pub [u8; 32]);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityHandle {
    pub handle: String, // e.g. "alice@example.com" or "@alice:jig"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityRecord {
    pub handle: IdentityHandle,
    pub key: PublicKeyEd25519,
    pub display_name: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    pub subject: IdentityHandle,
    pub key: PublicKeyEd25519,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub statement: String, // freeform, e.g. "link alice@example to this key"
    pub issuer: String,    // who signed, usually same as subject
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalAlias {
    pub alias: String,                   // short-lived pseudonym
    pub scope: String,                   // local scope, e.g. channel id, server id
    pub subject: Option<IdentityHandle>, // None == anonymous
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PowChallenge {
    pub id: Uuid,
    pub action: String,                  // e.g., "claim" | "alias"
    pub subject: Option<IdentityHandle>, // for claim: handle; for alias: subject (optional)
    pub scope: Option<String>,           // for alias minting
    pub difficulty: u16,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PowSubmission {
    pub challenge_id: Uuid,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReputationSubject {
    User,
    Server,
    Nameserver,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReputationScore {
    pub subject: ReputationSubject,
    pub subject_id: String,
    pub ruleset: String,
    pub score: f64,
    #[serde(default)]
    pub weight: f64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReputationObservation {
    pub id: Uuid,
    pub subject: ReputationSubject,
    pub subject_id: String,
    pub ruleset: String,
    pub observer: String,
    pub score: f64,
    #[serde(default)]
    pub weight: f64,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReputationAggregate {
    pub subject: ReputationSubject,
    pub subject_id: String,
    pub ruleset: String,
    pub score: f64,
    pub weight: f64,
    pub sample_size: usize,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TribunalStatus {
    Open,
    Escalated,
    Resolved,
    Dismissed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TribunalOutcome {
    Sustain,
    Modify,
    Overturn,
    Escalate,
    Dismiss,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TribunalCase {
    pub id: Uuid,
    pub subject: ReputationSubject,
    pub subject_id: String,
    pub ruleset: String,
    pub status: TribunalStatus,
    pub reason: String,
    pub reporter: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    pub opened_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TribunalDecision {
    pub id: Uuid,
    pub case_id: Uuid,
    pub outcome: TribunalOutcome,
    #[serde(default)]
    pub penalty_delta: Option<f64>,
    pub decided_by: String,
    pub decided_at: DateTime<Utc>,
    #[serde(default)]
    pub notes: Option<String>,
}

// Phase C: Content-addressed tribunal decision block for gossip and transparency
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TribunalDecisionBlock {
    pub case_id: Uuid,
    pub decision_id: Uuid,
    pub subject: ReputationSubject,
    pub subject_id: String,
    pub ruleset: String,
    pub outcome: TribunalOutcome,
    #[serde(default)]
    pub penalty_delta: Option<f64>,
    pub decided_by: String,
    pub decided_at: DateTime<Utc>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
}

impl TribunalDecisionBlock {
    /// Generate content identifier (CID) using BLAKE3 hash of canonical JSON
    pub fn compute_cid(&self) -> Result<String, serde_json::Error> {
        // Serialize to canonical JSON (sorted keys, no whitespace)
        let canonical_json = serde_json::to_vec(self)?;
        Ok(blake3::hash(&canonical_json).to_hex().to_string())
    }

    /// Create a block from a TribunalDecision and TribunalCase
    pub fn from_decision_and_case(
        decision: &TribunalDecision,
        case: &TribunalCase,
        evidence: Option<String>,
    ) -> Self {
        Self {
            case_id: decision.case_id,
            decision_id: decision.id,
            subject: case.subject.clone(),
            subject_id: case.subject_id.clone(),
            ruleset: case.ruleset.clone(),
            outcome: decision.outcome.clone(),
            penalty_delta: decision.penalty_delta,
            decided_by: decision.decided_by.clone(),
            decided_at: decision.decided_at,
            notes: decision.notes.clone(),
            evidence,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsefulWorkKind {
    ValidateBlock,
    VerifyObservation,
    AuditRuleset,
    Custom,
    // Phase B: Executable block validation
    ProcessExecutableBlock,
    ValidateFuelCounts,
    CrossValidateReceipt,
    ResolveReceiptDispute,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum UsefulWorkStatus {
    #[default]
    Queued,
    InProgress,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsefulWorkAssignment {
    pub id: Uuid,
    pub kind: UsefulWorkKind,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub ruleset: Option<String>,
    #[serde(default)]
    pub payload: JsonValue,
    #[serde(default)]
    pub assigned_to: Option<String>,
    #[serde(default)]
    pub status: UsefulWorkStatus,
    #[serde(default)]
    pub priority: i32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsefulWorkResult {
    pub assignment_id: Uuid,
    pub worker: String,
    pub status: UsefulWorkStatus,
    #[serde(default)]
    pub output: JsonValue,
    #[serde(default)]
    pub metadata: JsonValue,
    pub submitted_at: DateTime<Utc>,
}

// Phase B: Receipt attestations for cross-validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Confirmed,
    Disputed,
    SoftFail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Attestation {
    pub id: Uuid,
    pub block_id: String,
    pub verifier_did: String,
    pub verdict: AttestationVerdict,
    #[serde(default)]
    pub fuel_delta: Option<i64>, // difference from original receipt
    #[serde(default)]
    pub evidence_cid: Option<String>, // optional IPFS/S3 pointer to evidence
    pub attested_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransparencyLogEventKind {
    TribunalDecision,
    ReputationUpdate,
    UsefulWorkCompleted,
    PenaltyApplied,
    IdentityClaimed,
    HostRuntimePublished, // Phase C: Runtime config updates (runtime_hash + policy_hash changes)
    CrossValidationDiscrepancy, // Phase D: Federation peers disagree on receipt
    TribunalCaseOpened,   // Phase D: Anomaly escalated to tribunal
    PoWPenaltyApplied,    // Phase D: PoW penalty applied for anomaly
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransparencyLogEntry {
    pub id: Uuid,
    pub event_kind: TransparencyLogEventKind,
    pub subject: Option<String>,
    pub payload: JsonValue,
    #[serde(default)]
    pub hash: Option<String>,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransparencyLogHash {
    pub id: Uuid,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub entry_count: i64,
    pub merkle_root: String,
    pub previous_hash: Option<String>,
    pub computed_at: DateTime<Utc>,
}

// Phase D: Receipt Anomaly Detection Types

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    NonDeterministicExecution, // renders_match=false
    ExcessiveFuelUsage,        // fuel_used >> historical avg
    SuspiciousFuelPattern,     // fuel_used << historical avg (possible tampering)
    ExcessiveNetworkUsage,     // net.fetch abuse
    RepeatedHardFailures,      // pattern of hard_fail outcomes
    SuspiciousCapabilityUsage, // unusual capability combinations
    CrossValidationFailed,     // Phase D: Majority of federation peers disagree
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AnomalySeverity {
    Low,      // Log only
    Medium,   // +2 PoW bits warning
    High,     // +4 PoW bits + tribunal case
    Critical, // Suspend host
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReceiptAnomaly {
    pub id: Uuid,
    pub block_id: String,
    pub host_did: String,
    pub kind: AnomalyKind,
    pub severity: AnomalySeverity,
    pub description: String,
    pub evidence: serde_json::Value, // Structured evidence (fuel values, capability usage, etc.)
    pub detected_at: DateTime<Utc>,
    #[serde(default)]
    pub auto_escalated: bool, // True if auto-created tribunal case
    #[serde(default)]
    pub tribunal_case_id: Option<Uuid>, // Link to case if escalated
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PenaltyReason {
    ReceiptAnomaly(AnomalyKind), // Penalty due to detected anomaly
    TribunalDecision,            // Penalty from tribunal ruling
    RepeatedViolations,          // Escalated penalty for repeat offenses
    ManualOverride,              // Admin-applied penalty
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoWPenalty {
    pub id: Uuid,
    pub host_did: String,
    pub reason: PenaltyReason,
    pub additional_bits: u32, // Extra PoW difficulty bits
    pub applied_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>, // None = permanent until lifted
    #[serde(default)]
    pub anomaly_id: Option<Uuid>, // Link to anomaly if reason is ReceiptAnomaly
    #[serde(default)]
    pub tribunal_case_id: Option<Uuid>, // Link to case if reason is TribunalDecision
}

// Federation Gossip Types

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FederationPeerStatus {
    Active,
    Unreachable,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationPeer {
    pub id: Uuid,
    pub domain: String,
    pub endpoint: String, // e.g. "https://ns.example.com"
    #[serde(default)]
    pub public_key: Option<Vec<u8>>, // Ed25519 public key for signing
    pub status: FederationPeerStatus,
    #[serde(default)]
    pub capabilities_hash: Option<String>, // Hash of peer's capabilities
    pub discovered_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    #[serde(default)]
    pub metadata: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GossipMessageKind {
    PolicyHash,
    ReputationSummary,
    TribunalDecision,
    Handshake,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GossipMessage {
    pub id: Uuid,
    pub kind: GossipMessageKind,
    pub from_peer: String, // domain of sender
    pub payload: JsonValue,
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyHashExchange {
    pub domain: String,
    pub policy_version: String,
    pub policy_hash: String, // BLAKE3 hash of policy config
    pub rulesets: Vec<String>,
    #[serde(default)]
    pub capabilities_url: Option<String>, // URL to /.well-known/jig-ns/capabilities
    #[serde(default)]
    pub runtime_hash: Option<String>, // Phase C: BLAKE3 hash of runtime config
    #[serde(default)]
    pub affordances: Vec<String>, // Phase C: e.g. ["email.delivered", "bridge.forwarded"]
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReputationSummaryGossip {
    pub ruleset: String,
    pub aggregate_score: f64, // Overall reputation score for this ruleset
    pub sample_size: usize,   // Number of observations aggregated
    pub peer_count: usize,    // Number of unique observers
    #[serde(default)]
    pub penalty_count: i64, // Count of penalties applied (no PII)
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub computed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TribunalDecisionGossip {
    pub case_id: Uuid,
    pub decision_id: Uuid,
    pub subject: ReputationSubject,
    pub subject_hash: String, // Hash of subject_id for privacy
    pub ruleset: String,
    pub outcome: TribunalOutcome,
    #[serde(default)]
    pub penalty_delta: Option<f64>,
    pub decided_at: DateTime<Utc>,
    #[serde(default)]
    pub transparency_log_hash: Option<String>, // Link to transparency log entry
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationHandshake {
    pub domain: String,
    pub version: String, // Protocol version
    pub capabilities_hash: String,
    pub supported_features: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip() {
        let rec = IdentityRecord {
            handle: IdentityHandle {
                handle: "alice@example.com".into(),
            },
            key: PublicKeyEd25519([0u8; 32]),
            display_name: Some("Alice".into()),
            updated_at: Utc::now(),
        };
        let js = serde_json::to_string(&rec).unwrap();
        let back: IdentityRecord = serde_json::from_str(&js).unwrap();
        assert_eq!(rec.handle.handle, back.handle.handle);
    }

    // Phase C tests
    #[test]
    fn tribunal_decision_block_cid_generation() {
        let block = TribunalDecisionBlock {
            case_id: Uuid::now_v7(),
            decision_id: Uuid::now_v7(),
            subject: ReputationSubject::User,
            subject_id: "user123".to_string(),
            ruleset: "high-sec".to_string(),
            outcome: TribunalOutcome::Sustain,
            penalty_delta: Some(-10.0),
            decided_by: "tribunal@example.com".to_string(),
            decided_at: Utc::now(),
            notes: Some("Test decision".to_string()),
            evidence: Some("https://example.com/evidence".to_string()),
        };

        let cid1 = block.compute_cid().unwrap();
        let cid2 = block.compute_cid().unwrap();

        // CID should be deterministic
        assert_eq!(cid1, cid2);
        assert_eq!(cid1.len(), 64); // BLAKE3 hex output is 64 chars
    }

    #[test]
    fn tribunal_decision_block_roundtrip() {
        let block = TribunalDecisionBlock {
            case_id: Uuid::now_v7(),
            decision_id: Uuid::now_v7(),
            subject: ReputationSubject::Server,
            subject_id: "server.example.com".to_string(),
            ruleset: "federation".to_string(),
            outcome: TribunalOutcome::Modify,
            penalty_delta: Some(-5.0),
            decided_by: "admin@example.com".to_string(),
            decided_at: Utc::now(),
            notes: Some("Modified penalty".to_string()),
            evidence: None,
        };

        let json = serde_json::to_string(&block).unwrap();
        let deserialized: TribunalDecisionBlock = serde_json::from_str(&json).unwrap();

        assert_eq!(block.case_id, deserialized.case_id);
        assert_eq!(block.decision_id, deserialized.decision_id);
        assert_eq!(block.subject, deserialized.subject);
        assert_eq!(block.outcome, deserialized.outcome);
    }

    #[test]
    fn policy_hash_exchange_with_runtime_fields() {
        let policy = PolicyHashExchange {
            domain: "example.com".to_string(),
            policy_version: "1.0.0".to_string(),
            policy_hash: "abc123".to_string(),
            rulesets: vec!["high-sec".to_string(), "federation".to_string()],
            capabilities_url: Some(
                "https://example.com/.well-known/jig-ns/capabilities".to_string(),
            ),
            runtime_hash: Some("def456".to_string()),
            affordances: vec![
                "email.delivered".to_string(),
                "bridge.forwarded".to_string(),
            ],
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: PolicyHashExchange = serde_json::from_str(&json).unwrap();

        assert_eq!(policy.domain, deserialized.domain);
        assert_eq!(policy.runtime_hash, deserialized.runtime_hash);
        assert_eq!(policy.affordances, deserialized.affordances);
    }

    #[test]
    fn policy_hash_exchange_backward_compatibility() {
        // Test that old PolicyHashExchange without runtime_hash/affordances can be deserialized
        let old_json = r#"{
            "domain": "example.com",
            "policy_version": "1.0.0",
            "policy_hash": "abc123",
            "rulesets": ["high-sec"],
            "timestamp": "2025-01-01T00:00:00Z"
        }"#;

        let policy: PolicyHashExchange = serde_json::from_str(old_json).unwrap();

        assert_eq!(policy.domain, "example.com");
        assert_eq!(policy.runtime_hash, None);
        assert_eq!(policy.affordances, Vec::<String>::new());
    }

    #[test]
    fn transparency_log_host_runtime_published() {
        let entry = TransparencyLogEntry {
            id: Uuid::now_v7(),
            event_kind: TransparencyLogEventKind::HostRuntimePublished,
            subject: Some("ns.example.com".to_string()),
            payload: serde_json::json!({"runtime_hash": "abc123", "policy_hash": "def456"}),
            hash: Some("hash123".to_string()),
            recorded_at: Utc::now(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: TransparencyLogEntry = serde_json::from_str(&json).unwrap();

        assert!(matches!(
            deserialized.event_kind,
            TransparencyLogEventKind::HostRuntimePublished
        ));
        assert_eq!(entry.subject, deserialized.subject);
    }
}
