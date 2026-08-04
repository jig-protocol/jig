use super::NamesStorage;
use crate::error::{NameServerError, Result};
use crate::types::{
    AnomalyKind, AnomalySeverity, IdentityHandle, IdentityRecord, LocalAlias, PenaltyReason,
    PoWPenalty, PublicKeyEd25519, ReceiptAnomaly, ReputationObservation, ReputationScore,
    ReputationSubject, TransparencyLogEntry, TransparencyLogEventKind, TransparencyLogHash,
    TribunalCase, TribunalDecision, TribunalDecisionBlock, TribunalOutcome, TribunalStatus,
    UsefulWorkAssignment, UsefulWorkKind, UsefulWorkResult, UsefulWorkStatus,
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use cid::Cid;
use rusqlite::{Connection, params};
use serde_json::{self, Value as JsonValue};
use std::path::PathBuf;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone)]
pub struct SqliteStorage {
    db_path: PathBuf,
}

impl SqliteStorage {
    pub fn new(db_path: PathBuf) -> Result<Self> {
        let st = Self { db_path };
        st.init()?;
        Ok(st)
    }

    fn init(&self) -> Result<()> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS identities (
                handle TEXT PRIMARY KEY,
                key BLOB NOT NULL,
                display_name TEXT,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS aliases (
                alias TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                subject TEXT,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pow_challenges (
                id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                subject TEXT,
                scope TEXT,
                difficulty INTEGER NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cache_identities (
                handle TEXT PRIMARY KEY,
                key BLOB NOT NULL,
                display_name TEXT,
                updated_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT PRIMARY KEY,
                window_minute INTEGER NOT NULL,
                count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS penalties (
                key TEXT PRIMARY KEY,
                points INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reputation_scores (
                subject_kind TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                ruleset TEXT NOT NULL,
                score REAL NOT NULL,
                weight REAL NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (subject_kind, subject_id, ruleset)
            );

            CREATE TABLE IF NOT EXISTS reputation_observations (
                id TEXT PRIMARY KEY,
                subject_kind TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                ruleset TEXT NOT NULL,
                observer TEXT NOT NULL,
                score REAL NOT NULL,
                weight REAL NOT NULL,
                evidence TEXT,
                expires_at INTEGER,
                recorded_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tribunal_cases (
                id TEXT PRIMARY KEY,
                subject_kind TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                ruleset TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                reporter TEXT NOT NULL,
                severity TEXT,
                metadata TEXT,
                opened_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tribunal_decisions (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                penalty_delta REAL,
                decided_by TEXT NOT NULL,
                decided_at INTEGER NOT NULL,
                notes TEXT,
                FOREIGN KEY(case_id) REFERENCES tribunal_cases(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS tribunal_decision_blocks (
                cid TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                subject_kind TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                ruleset TEXT NOT NULL,
                outcome TEXT NOT NULL,
                penalty_delta REAL,
                decided_by TEXT NOT NULL,
                decided_at INTEGER NOT NULL,
                notes TEXT,
                evidence TEXT
            );

            CREATE TABLE IF NOT EXISTS useful_work_assignments (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                subject TEXT,
                ruleset TEXT,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                assigned_to TEXT,
                priority INTEGER NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_updated INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS useful_work_results (
                assignment_id TEXT PRIMARY KEY,
                worker TEXT NOT NULL,
                status TEXT NOT NULL,
                output TEXT NOT NULL,
                metadata TEXT NOT NULL,
                submitted_at INTEGER NOT NULL,
                FOREIGN KEY(assignment_id) REFERENCES useful_work_assignments(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS transparency_log (
                id TEXT PRIMARY KEY,
                event_kind TEXT NOT NULL,
                subject TEXT,
                payload TEXT NOT NULL,
                hash TEXT,
                recorded_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_transparency_log_recorded ON transparency_log(recorded_at);
            CREATE INDEX IF NOT EXISTS idx_transparency_log_kind ON transparency_log(event_kind);

            CREATE TABLE IF NOT EXISTS transparency_hashes (
                id TEXT PRIMARY KEY,
                period_start INTEGER NOT NULL,
                period_end INTEGER NOT NULL,
                entry_count INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                previous_hash TEXT,
                computed_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_transparency_hashes_computed ON transparency_hashes(computed_at);

            CREATE TABLE IF NOT EXISTS federation_peers (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE,
                endpoint TEXT NOT NULL,
                public_key BLOB,
                status TEXT NOT NULL,
                capabilities_hash TEXT,
                discovered_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                metadata TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_federation_peers_domain ON federation_peers(domain);
            CREATE INDEX IF NOT EXISTS idx_federation_peers_status ON federation_peers(status);

            CREATE TABLE IF NOT EXISTS gossip_messages (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                from_peer TEXT NOT NULL,
                payload TEXT NOT NULL,
                signature BLOB,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_gossip_messages_kind ON gossip_messages(kind);
            CREATE INDEX IF NOT EXISTS idx_gossip_messages_timestamp ON gossip_messages(timestamp);

            CREATE TABLE IF NOT EXISTS policy_hashes (
                domain TEXT PRIMARY KEY,
                policy_version TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                rulesets TEXT NOT NULL,
                capabilities_url TEXT,
                runtime_hash TEXT,
                affordances TEXT,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_policy_hashes_timestamp ON policy_hashes(timestamp);

            CREATE TABLE IF NOT EXISTS receipts (
                block_id TEXT PRIMARY KEY,
                receipt_schema_version TEXT NOT NULL,
                host_did TEXT NOT NULL,
                executed_at INTEGER NOT NULL,
                render_hash TEXT NOT NULL,
                renders_match INTEGER,
                fuel_used INTEGER NOT NULL,
                memory_peak_mb INTEGER,
                counters_fuel_total INTEGER,
                counters_bytes_tx INTEGER,
                counters_bytes_rx INTEGER,
                counters_syscalls INTEGER,
                timings_queue_wait_ms INTEGER,
                timings_init_ms INTEGER,
                timings_exec_ms INTEGER,
                timings_total_ms INTEGER,
                limit_fuel_max INTEGER,
                limit_memory_max_mb INTEGER,
                limit_exec_timeout_ms INTEGER,
                outcome_status TEXT,
                outcome_reason TEXT,
                outcome_affordances TEXT,
                hash_algorithms TEXT NOT NULL,
                capabilities_used TEXT NOT NULL,
                attestations TEXT NOT NULL,
                signature TEXT,
                metadata TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_receipts_host ON receipts(host_did);
            CREATE INDEX IF NOT EXISTS idx_receipts_executed ON receipts(executed_at);
            CREATE INDEX IF NOT EXISTS idx_receipts_outcome ON receipts(outcome_status);

            CREATE TABLE IF NOT EXISTS receipt_capability_counters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_id TEXT NOT NULL,
                executed_at INTEGER NOT NULL,
                capability TEXT NOT NULL,
                fuel_used INTEGER NOT NULL,
                FOREIGN KEY (block_id) REFERENCES receipts(block_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_rcc_block ON receipt_capability_counters(block_id);
            CREATE INDEX IF NOT EXISTS idx_rcc_capability ON receipt_capability_counters(capability);
            CREATE INDEX IF NOT EXISTS idx_rcc_executed ON receipt_capability_counters(executed_at);

            CREATE TABLE IF NOT EXISTS attestations (
                id TEXT PRIMARY KEY,
                block_id TEXT NOT NULL,
                verifier_did TEXT NOT NULL,
                verdict TEXT NOT NULL,
                fuel_delta INTEGER,
                evidence_cid TEXT,
                attested_at INTEGER NOT NULL,
                signature TEXT NOT NULL,
                FOREIGN KEY (block_id) REFERENCES receipts(block_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_attestations_block ON attestations(block_id);
            CREATE INDEX IF NOT EXISTS idx_attestations_verifier ON attestations(verifier_did);
            CREATE INDEX IF NOT EXISTS idx_attestations_verdict ON attestations(verdict);

            CREATE TABLE IF NOT EXISTS anomalies (
                id TEXT PRIMARY KEY,
                block_id TEXT NOT NULL,
                host_did TEXT NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                detected_at INTEGER NOT NULL,
                auto_escalated INTEGER NOT NULL DEFAULT 0,
                tribunal_case_id TEXT,
                FOREIGN KEY (block_id) REFERENCES receipts(block_id) ON DELETE CASCADE,
                FOREIGN KEY (tribunal_case_id) REFERENCES tribunal_cases(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_anomalies_block ON anomalies(block_id);
            CREATE INDEX IF NOT EXISTS idx_anomalies_host ON anomalies(host_did);
            CREATE INDEX IF NOT EXISTS idx_anomalies_kind ON anomalies(kind);
            CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity);
            CREATE INDEX IF NOT EXISTS idx_anomalies_detected ON anomalies(detected_at);

            -- Phase-D PoW penalties are a separate system from the legacy
            -- points-based `penalties` table above; they must not share a name.
            CREATE TABLE IF NOT EXISTS pow_penalties (
                id TEXT PRIMARY KEY,
                host_did TEXT NOT NULL,
                reason TEXT NOT NULL,
                additional_bits INTEGER NOT NULL,
                applied_at INTEGER NOT NULL,
                expires_at INTEGER,
                anomaly_id TEXT,
                tribunal_case_id TEXT,
                FOREIGN KEY (anomaly_id) REFERENCES anomalies(id) ON DELETE CASCADE,
                FOREIGN KEY (tribunal_case_id) REFERENCES tribunal_cases(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pow_penalties_host ON pow_penalties(host_did);
            CREATE INDEX IF NOT EXISTS idx_pow_penalties_expires ON pow_penalties(expires_at);
            CREATE INDEX IF NOT EXISTS idx_pow_penalties_applied ON pow_penalties(applied_at);
            "#,
        )?;
        Ok(())
    }
}

fn subject_to_str(subject: &ReputationSubject) -> &'static str {
    match subject {
        ReputationSubject::User => "user",
        ReputationSubject::Server => "server",
        ReputationSubject::Nameserver => "nameserver",
    }
}

fn subject_from_str(value: &str) -> Result<ReputationSubject> {
    match value {
        "user" => Ok(ReputationSubject::User),
        "server" => Ok(ReputationSubject::Server),
        "nameserver" => Ok(ReputationSubject::Nameserver),
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown subject kind: {other}"
        ))),
    }
}

fn status_to_str(status: &TribunalStatus) -> &'static str {
    match status {
        TribunalStatus::Open => "open",
        TribunalStatus::Escalated => "escalated",
        TribunalStatus::Resolved => "resolved",
        TribunalStatus::Dismissed => "dismissed",
    }
}

fn status_from_str(value: &str) -> Result<TribunalStatus> {
    match value {
        "open" => Ok(TribunalStatus::Open),
        "escalated" => Ok(TribunalStatus::Escalated),
        "resolved" => Ok(TribunalStatus::Resolved),
        "dismissed" => Ok(TribunalStatus::Dismissed),
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown tribunal status: {other}"
        ))),
    }
}

fn outcome_to_str(outcome: &TribunalOutcome) -> &'static str {
    match outcome {
        TribunalOutcome::Sustain => "sustain",
        TribunalOutcome::Modify => "modify",
        TribunalOutcome::Overturn => "overturn",
        TribunalOutcome::Escalate => "escalate",
        TribunalOutcome::Dismiss => "dismiss",
    }
}

fn outcome_from_str(value: &str) -> Result<TribunalOutcome> {
    match value {
        "sustain" => Ok(TribunalOutcome::Sustain),
        "modify" => Ok(TribunalOutcome::Modify),
        "overturn" => Ok(TribunalOutcome::Overturn),
        "escalate" => Ok(TribunalOutcome::Escalate),
        "dismiss" => Ok(TribunalOutcome::Dismiss),
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown tribunal outcome: {other}"
        ))),
    }
}

fn work_kind_to_str(kind: &UsefulWorkKind) -> &'static str {
    match kind {
        UsefulWorkKind::ValidateBlock => "validate_block",
        UsefulWorkKind::VerifyObservation => "verify_observation",
        UsefulWorkKind::AuditRuleset => "audit_ruleset",
        UsefulWorkKind::Custom => "custom",
        // Phase B
        UsefulWorkKind::ProcessExecutableBlock => "process_executable_block",
        UsefulWorkKind::ValidateFuelCounts => "validate_fuel_counts",
        UsefulWorkKind::CrossValidateReceipt => "cross_validate_receipt",
        UsefulWorkKind::ResolveReceiptDispute => "resolve_receipt_dispute",
    }
}

fn work_kind_from_str(value: &str) -> Result<UsefulWorkKind> {
    match value {
        "validate_block" => Ok(UsefulWorkKind::ValidateBlock),
        "verify_observation" => Ok(UsefulWorkKind::VerifyObservation),
        "audit_ruleset" => Ok(UsefulWorkKind::AuditRuleset),
        "custom" => Ok(UsefulWorkKind::Custom),
        // Phase B
        "process_executable_block" => Ok(UsefulWorkKind::ProcessExecutableBlock),
        "validate_fuel_counts" => Ok(UsefulWorkKind::ValidateFuelCounts),
        "cross_validate_receipt" => Ok(UsefulWorkKind::CrossValidateReceipt),
        "resolve_receipt_dispute" => Ok(UsefulWorkKind::ResolveReceiptDispute),
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown useful work kind: {other}"
        ))),
    }
}

fn work_status_to_str(status: &UsefulWorkStatus) -> &'static str {
    match status {
        UsefulWorkStatus::Queued => "queued",
        UsefulWorkStatus::InProgress => "in_progress",
        UsefulWorkStatus::Completed => "completed",
        UsefulWorkStatus::Failed => "failed",
    }
}

fn work_status_from_str(value: &str) -> Result<UsefulWorkStatus> {
    match value {
        "queued" => Ok(UsefulWorkStatus::Queued),
        "in_progress" => Ok(UsefulWorkStatus::InProgress),
        "completed" => Ok(UsefulWorkStatus::Completed),
        "failed" => Ok(UsefulWorkStatus::Failed),
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown useful work status: {other}"
        ))),
    }
}

fn event_kind_to_str(kind: &TransparencyLogEventKind) -> &'static str {
    match kind {
        TransparencyLogEventKind::TribunalDecision => "tribunal_decision",
        TransparencyLogEventKind::ReputationUpdate => "reputation_update",
        TransparencyLogEventKind::UsefulWorkCompleted => "useful_work_completed",
        TransparencyLogEventKind::PenaltyApplied => "penalty_applied",
        TransparencyLogEventKind::IdentityClaimed => "identity_claimed",
        TransparencyLogEventKind::HostRuntimePublished => "host_runtime_published", // Phase C
        TransparencyLogEventKind::CrossValidationDiscrepancy => "cross_validation_discrepancy", // Phase D
        TransparencyLogEventKind::TribunalCaseOpened => "tribunal_case_opened", // Phase D
        TransparencyLogEventKind::PoWPenaltyApplied => "pow_penalty_applied",   // Phase D
    }
}

fn event_kind_from_str(value: &str) -> Result<TransparencyLogEventKind> {
    match value {
        "tribunal_decision" => Ok(TransparencyLogEventKind::TribunalDecision),
        "reputation_update" => Ok(TransparencyLogEventKind::ReputationUpdate),
        "useful_work_completed" => Ok(TransparencyLogEventKind::UsefulWorkCompleted),
        "penalty_applied" => Ok(TransparencyLogEventKind::PenaltyApplied),
        "identity_claimed" => Ok(TransparencyLogEventKind::IdentityClaimed),
        "host_runtime_published" => Ok(TransparencyLogEventKind::HostRuntimePublished), // Phase C
        "cross_validation_discrepancy" => Ok(TransparencyLogEventKind::CrossValidationDiscrepancy), // Phase D
        "tribunal_case_opened" => Ok(TransparencyLogEventKind::TribunalCaseOpened), // Phase D
        "pow_penalty_applied" => Ok(TransparencyLogEventKind::PoWPenaltyApplied),   // Phase D
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown transparency log event kind: {other}"
        ))),
    }
}

fn peer_status_to_str(status: &crate::types::FederationPeerStatus) -> &'static str {
    match status {
        crate::types::FederationPeerStatus::Active => "active",
        crate::types::FederationPeerStatus::Unreachable => "unreachable",
        crate::types::FederationPeerStatus::Suspended => "suspended",
    }
}

fn peer_status_from_str(value: &str) -> Result<crate::types::FederationPeerStatus> {
    match value {
        "active" => Ok(crate::types::FederationPeerStatus::Active),
        "unreachable" => Ok(crate::types::FederationPeerStatus::Unreachable),
        "suspended" => Ok(crate::types::FederationPeerStatus::Suspended),
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown peer status: {other}"
        ))),
    }
}

fn gossip_kind_to_str(kind: &crate::types::GossipMessageKind) -> &'static str {
    match kind {
        crate::types::GossipMessageKind::PolicyHash => "policy_hash",
        crate::types::GossipMessageKind::ReputationSummary => "reputation_summary",
        crate::types::GossipMessageKind::TribunalDecision => "tribunal_decision",
        crate::types::GossipMessageKind::Handshake => "handshake",
    }
}

fn gossip_kind_from_str(value: &str) -> Result<crate::types::GossipMessageKind> {
    match value {
        "policy_hash" => Ok(crate::types::GossipMessageKind::PolicyHash),
        "reputation_summary" => Ok(crate::types::GossipMessageKind::ReputationSummary),
        "tribunal_decision" => Ok(crate::types::GossipMessageKind::TribunalDecision),
        "handshake" => Ok(crate::types::GossipMessageKind::Handshake),
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown gossip kind: {other}"
        ))),
    }
}

fn anomaly_kind_to_str(kind: &AnomalyKind) -> &'static str {
    match kind {
        AnomalyKind::NonDeterministicExecution => "non_deterministic_execution",
        AnomalyKind::ExcessiveFuelUsage => "excessive_fuel_usage",
        AnomalyKind::SuspiciousFuelPattern => "suspicious_fuel_pattern",
        AnomalyKind::ExcessiveNetworkUsage => "excessive_network_usage",
        AnomalyKind::RepeatedHardFailures => "repeated_hard_failures",
        AnomalyKind::SuspiciousCapabilityUsage => "suspicious_capability_usage",
        AnomalyKind::CrossValidationFailed => "cross_validation_failed", // Phase D
    }
}

fn anomaly_kind_from_str(value: &str) -> Result<AnomalyKind> {
    match value {
        "non_deterministic_execution" => Ok(AnomalyKind::NonDeterministicExecution),
        "excessive_fuel_usage" => Ok(AnomalyKind::ExcessiveFuelUsage),
        "suspicious_fuel_pattern" => Ok(AnomalyKind::SuspiciousFuelPattern),
        "excessive_network_usage" => Ok(AnomalyKind::ExcessiveNetworkUsage),
        "repeated_hard_failures" => Ok(AnomalyKind::RepeatedHardFailures),
        "suspicious_capability_usage" => Ok(AnomalyKind::SuspiciousCapabilityUsage),
        "cross_validation_failed" => Ok(AnomalyKind::CrossValidationFailed), // Phase D
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown anomaly kind: {other}"
        ))),
    }
}

fn anomaly_severity_to_str(severity: &AnomalySeverity) -> &'static str {
    match severity {
        AnomalySeverity::Low => "low",
        AnomalySeverity::Medium => "medium",
        AnomalySeverity::High => "high",
        AnomalySeverity::Critical => "critical",
    }
}

fn anomaly_severity_from_str(value: &str) -> Result<AnomalySeverity> {
    match value {
        "low" => Ok(AnomalySeverity::Low),
        "medium" => Ok(AnomalySeverity::Medium),
        "high" => Ok(AnomalySeverity::High),
        "critical" => Ok(AnomalySeverity::Critical),
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown anomaly severity: {other}"
        ))),
    }
}

fn penalty_reason_to_str(reason: &PenaltyReason) -> String {
    match reason {
        PenaltyReason::ReceiptAnomaly(kind) => {
            format!("receipt_anomaly:{}", anomaly_kind_to_str(kind))
        }
        PenaltyReason::TribunalDecision => "tribunal_decision".to_string(),
        PenaltyReason::RepeatedViolations => "repeated_violations".to_string(),
        PenaltyReason::ManualOverride => "manual_override".to_string(),
    }
}

fn penalty_reason_from_str(value: &str) -> Result<PenaltyReason> {
    if let Some(kind_str) = value.strip_prefix("receipt_anomaly:") {
        let kind = anomaly_kind_from_str(kind_str)?;
        return Ok(PenaltyReason::ReceiptAnomaly(kind));
    }
    match value {
        "tribunal_decision" => Ok(PenaltyReason::TribunalDecision),
        "repeated_violations" => Ok(PenaltyReason::RepeatedViolations),
        "manual_override" => Ok(PenaltyReason::ManualOverride),
        other => Err(NameServerError::Other(anyhow::anyhow!(
            "unknown penalty reason: {other}"
        ))),
    }
}

#[async_trait]
impl NamesStorage for SqliteStorage {
    async fn upsert_identity(&self, record: IdentityRecord) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO identities(handle, key, display_name, updated_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(handle) DO UPDATE SET key=excluded.key, display_name=excluded.display_name, updated_at=excluded.updated_at",
                params![
                    record.handle.handle,
                    &record.key.0[..],
                    record.display_name,
                    record.updated_at.timestamp()
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("join error: {e}")))??;
        Ok(())
    }

    async fn get_identity(&self, handle: &str) -> Result<Option<IdentityRecord>> {
        let handle = handle.to_string();
        let path = self.db_path.clone();
        let rec = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT handle, key, display_name, updated_at FROM identities WHERE handle=?1",
            )?;
            let mut rows = stmt.query(params![handle])?;
            if let Some(row) = rows.next()? {
                let handle: String = row.get(0)?;
                let key: Vec<u8> = row.get(1)?;
                let display_name: Option<String> = row.get(2)?;
                let updated_at: i64 = row.get(3)?;
                let mut key_arr = [0u8; 32];
                if key.len() == 32 {
                    key_arr.copy_from_slice(&key);
                }
                let rec = IdentityRecord {
                    handle: IdentityHandle { handle },
                    key: PublicKeyEd25519(key_arr),
                    display_name,
                    updated_at: DateTime::<Utc>::from_timestamp(updated_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(updated_at, 0).single().unwrap()),
                };
                Ok::<_, NameServerError>(Some(rec))
            } else {
                Ok::<_, NameServerError>(None)
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("join error: {e}")))??;
        Ok(rec)
    }

    async fn put_alias(&self, alias: LocalAlias) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO aliases(alias, scope, subject, issued_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    alias.alias,
                    alias.scope,
                    alias.subject.map(|s| s.handle),
                    alias.issued_at.timestamp(),
                    alias.expires_at.timestamp()
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("join error: {e}")))??;
        Ok(())
    }

    async fn get_alias(&self, alias: &str) -> Result<Option<LocalAlias>> {
        let alias_str = alias.to_string();
        let path = self.db_path.clone();
        let rec = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT alias, scope, subject, issued_at, expires_at FROM aliases WHERE alias=?1",
            )?;
            let mut rows = stmt.query(params![alias_str])?;
            if let Some(row) = rows.next()? {
                let alias: String = row.get(0)?;
                let scope: String = row.get(1)?;
                let subject: Option<String> = row.get(2)?;
                let issued_at: i64 = row.get(3)?;
                let expires_at: i64 = row.get(4)?;
                let rec = LocalAlias {
                    alias,
                    scope,
                    subject: subject.map(|s| IdentityHandle { handle: s }),
                    issued_at: Utc.timestamp_opt(issued_at, 0).single().unwrap(),
                    expires_at: Utc.timestamp_opt(expires_at, 0).single().unwrap(),
                };
                Ok::<_, NameServerError>(Some(rec))
            } else {
                Ok::<_, NameServerError>(None)
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("join error: {e}")))??;
        Ok(rec)
    }

    async fn reap_expired(&self) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "DELETE FROM aliases WHERE expires_at <= ?1",
                params![Utc::now().timestamp()],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("join error: {e}")))??;
        Ok(())
    }

    async fn create_challenge(&self, ch: crate::types::PowChallenge) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO pow_challenges(id, action, subject, scope, difficulty, issued_at, expires_at, used) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    ch.id.to_string(),
                    ch.action,
                    ch.subject.map(|s| s.handle),
                    ch.scope,
                    ch.difficulty as i64,
                    ch.issued_at.timestamp(),
                    ch.expires_at.timestamp(),
                    if ch.used {1} else {0}
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("join error: {e}")))??;
        Ok(())
    }

    async fn get_challenge(&self, id: uuid::Uuid) -> Result<Option<crate::types::PowChallenge>> {
        let id_str = id.to_string();
        let path = self.db_path.clone();
        let rec = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare("SELECT id, action, subject, scope, difficulty, issued_at, expires_at, used FROM pow_challenges WHERE id=?1")?;
            let mut rows = stmt.query(params![id_str])?;
            if let Some(row) = rows.next()? {
                let id_s: String = row.get(0)?;
                let action: String = row.get(1)?;
                let subject: Option<String> = row.get(2)?;
                let scope: Option<String> = row.get(3)?;
                let difficulty: i64 = row.get(4)?;
                let issued_at: i64 = row.get(5)?;
                let expires_at: i64 = row.get(6)?;
                let used_i: i64 = row.get(7)?;
                let ch = crate::types::PowChallenge {
                    id: uuid::Uuid::parse_str(&id_s).map_err(|e| NameServerError::Storage(e.to_string()))?,
                    action,
                    subject: subject.map(|s| crate::types::IdentityHandle { handle: s }),
                    scope,
                    difficulty: difficulty as u16,
                    issued_at: Utc.timestamp_opt(issued_at, 0).single().unwrap(),
                    expires_at: Utc.timestamp_opt(expires_at, 0).single().unwrap(),
                    used: used_i != 0,
                };
                Ok::<_, NameServerError>(Some(ch))
            } else {
                Ok::<_, NameServerError>(None)
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("join error: {e}")))??;
        Ok(rec)
    }

    async fn mark_challenge_used(&self, id: uuid::Uuid) -> Result<()> {
        let id_str = id.to_string();
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "UPDATE pow_challenges SET used=1 WHERE id=?1",
                params![id_str],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("join error: {e}")))??;
        Ok(())
    }

    async fn cache_identity(
        &self,
        record: crate::types::IdentityRecord,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO cache_identities(handle, key, display_name, updated_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(handle) DO UPDATE SET key=excluded.key, display_name=excluded.display_name, updated_at=excluded.updated_at, expires_at=excluded.expires_at",
                params![
                    record.handle.handle,
                    &record.key.0[..],
                    record.display_name,
                    record.updated_at.timestamp(),
                    expires_at.timestamp()
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("join error: {e}")))??;
        Ok(())
    }

    async fn get_cached_identity(
        &self,
        handle: &str,
    ) -> Result<Option<crate::types::IdentityRecord>> {
        let handle = handle.to_string();
        let path = self.db_path.clone();
        let rec = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare("SELECT handle, key, display_name, updated_at, expires_at FROM cache_identities WHERE handle=?1")?;
            let mut rows = stmt.query(params![handle])?;
            if let Some(row) = rows.next()? {
                let handle: String = row.get(0)?;
                let key: Vec<u8> = row.get(1)?;
                let display_name: Option<String> = row.get(2)?;
                let updated_at: i64 = row.get(3)?;
                let expires_at: i64 = row.get(4)?;
                if Utc.timestamp_opt(expires_at, 0).single().unwrap() <= Utc::now() {
                    // expired; best-effort cleanup
                    let _ = conn.execute("DELETE FROM cache_identities WHERE handle=?1", params![handle]);
                    return Ok::<_, NameServerError>(None);
                }
                let mut key_arr = [0u8; 32];
                if key.len() == 32 { key_arr.copy_from_slice(&key); }
                let rec = crate::types::IdentityRecord {
                    handle: crate::types::IdentityHandle { handle },
                    key: crate::types::PublicKeyEd25519(key_arr),
                    display_name,
                    updated_at: Utc.timestamp_opt(updated_at, 0).single().unwrap(),
                };
                Ok::<_, NameServerError>(Some(rec))
            } else {
                Ok::<_, NameServerError>(None)
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("join error: {e}")))??;
        Ok(rec)
    }

    async fn rate_check_and_increment(&self, key: &str, limit_per_min: u32) -> Result<bool> {
        let key_s = key.to_string();
        let path = self.db_path.clone();
        let allowed = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let now_min = Utc::now().timestamp() / 60;
            let tx = conn.unchecked_transaction()?;
            // Read current
            let mut stmt = tx.prepare("SELECT window_minute, count FROM rate_limits WHERE key=?1")?;
            let mut rows = stmt.query(params![key_s.clone()])?;
            let (new_min, new_count) = if let Some(row) = rows.next()? {
                let win: i64 = row.get(0)?;
                let cnt: i64 = row.get(1)?;
                if win == now_min {
                    if (cnt as u32) >= limit_per_min { (win, cnt) } else { (win, cnt + 1) }
                } else {
                    (now_min, 1)
                }
            } else {
                (now_min, 1)
            };
            drop(rows);
            drop(stmt);
            // Write back
            tx.execute(
                "INSERT INTO rate_limits(key, window_minute, count) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET window_minute=excluded.window_minute, count=excluded.count",
                params![key_s, new_min, new_count],
            )?;
            tx.commit()?;
            Ok::<_, NameServerError>(new_min == now_min && (new_count as u32) <= limit_per_min)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(allowed)
    }

    async fn add_penalty(&self, key: &str, amount: u32) -> Result<()> {
        let key_s = key.to_string();
        let amt = amount as i64;
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let now = Utc::now().timestamp();
            conn.execute(
                "INSERT INTO penalties(key, points, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET points = penalties.points + ?2, updated_at = ?3",
                params![key_s, amt, now],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_penalty_points(&self, key: &str, decay_secs: i64) -> Result<u32> {
        let key_s = key.to_string();
        let path = self.db_path.clone();
        let pts = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare("SELECT points, updated_at FROM penalties WHERE key=?1")?;
            let mut rows = stmt.query(params![key_s.clone()])?;
            if let Some(row) = rows.next()? {
                let mut points: i64 = row.get(0)?;
                let mut updated_at: i64 = row.get(1)?;
                let now = Utc::now().timestamp();
                let elapsed = now - updated_at;
                if elapsed > 0 && decay_secs > 0 {
                    let decay_steps = elapsed / decay_secs;
                    if decay_steps > 0 {
                        points = (points - decay_steps).max(0);
                        updated_at = now;
                        conn.execute(
                            "UPDATE penalties SET points=?1, updated_at=?2 WHERE key=?3",
                            params![points, updated_at, key_s],
                        )?;
                    }
                }
                Ok::<_, NameServerError>(points as u32)
            } else {
                Ok::<_, NameServerError>(0u32)
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(pts)
    }

    async fn reset_penalty(&self, key: &str) -> Result<()> {
        let key_s = key.to_string();
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute("DELETE FROM penalties WHERE key=?1", params![key_s])?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_rate_info(&self, key: &str) -> Result<Option<(i64, u32)>> {
        let key_s = key.to_string();
        let path = self.db_path.clone();
        let info = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt =
                conn.prepare("SELECT window_minute, count FROM rate_limits WHERE key=?1")?;
            let mut rows = stmt.query(params![key_s])?;
            if let Some(row) = rows.next()? {
                let win: i64 = row.get(0)?;
                let cnt: i64 = row.get(1)?;
                Ok::<_, NameServerError>(Some((win, cnt as u32)))
            } else {
                Ok::<_, NameServerError>(None)
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(info)
    }

    async fn reset_rate(&self, key: &str) -> Result<()> {
        let key_s = key.to_string();
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute("DELETE FROM rate_limits WHERE key=?1", params![key_s])?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn upsert_reputation(&self, score: ReputationScore) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO reputation_scores(subject_kind, subject_id, ruleset, score, weight, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(subject_kind, subject_id, ruleset)
                 DO UPDATE SET score=excluded.score, weight=excluded.weight, updated_at=excluded.updated_at",
                params![
                    subject_to_str(&score.subject),
                    score.subject_id,
                    score.ruleset,
                    score.score,
                    score.weight,
                    score.updated_at.timestamp()
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_reputation(
        &self,
        subject: ReputationSubject,
        subject_id: &str,
        ruleset: &str,
    ) -> Result<Option<ReputationScore>> {
        let subject_kind = subject_to_str(&subject).to_string();
        let subject_id = subject_id.to_string();
        let ruleset = ruleset.to_string();
        let path = self.db_path.clone();
        let rec = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT subject_kind, subject_id, ruleset, score, weight, updated_at FROM reputation_scores WHERE subject_kind=?1 AND subject_id=?2 AND ruleset=?3",
            )?;
            let mut rows = stmt.query(params![subject_kind, subject_id, ruleset])?;
            if let Some(row) = rows.next()? {
                let subject_str: String = row.get(0)?;
                let subject = subject_from_str(&subject_str)?;
                let subject_id: String = row.get(1)?;
                let ruleset: String = row.get(2)?;
                let score: f64 = row.get(3)?;
                let weight: f64 = row.get(4)?;
                let updated_at: i64 = row.get(5)?;
                Ok::<_, NameServerError>(Some(ReputationScore {
                    subject,
                    subject_id,
                    ruleset,
                    score,
                    weight,
                    updated_at: DateTime::<Utc>::from_timestamp(updated_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(updated_at, 0).single().unwrap()),
                }))
            } else {
                Ok::<_, NameServerError>(None)
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(rec)
    }

    async fn list_reputation(
        &self,
        subject: ReputationSubject,
        subject_id: &str,
    ) -> Result<Vec<ReputationScore>> {
        let subject_kind = subject_to_str(&subject).to_string();
        let subject_id = subject_id.to_string();
        let path = self.db_path.clone();
        let rows = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT subject_kind, subject_id, ruleset, score, weight, updated_at FROM reputation_scores WHERE subject_kind=?1 AND subject_id=?2",
            )?;
            let mut rows = stmt.query(params![subject_kind, subject_id])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                let subject_str: String = row.get(0)?;
                let subject = subject_from_str(&subject_str)?;
                let subject_id: String = row.get(1)?;
                let ruleset: String = row.get(2)?;
                let score: f64 = row.get(3)?;
                let weight: f64 = row.get(4)?;
                let updated_at: i64 = row.get(5)?;
                out.push(ReputationScore {
                    subject,
                    subject_id,
                    ruleset,
                    score,
                    weight,
                    updated_at: DateTime::<Utc>::from_timestamp(updated_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(updated_at, 0).single().unwrap()),
                });
            }
            Ok::<_, NameServerError>(out)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(rows)
    }

    async fn add_reputation_observation(&self, obs: ReputationObservation) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO reputation_observations(id, subject_kind, subject_id, ruleset, observer, score, weight, evidence, expires_at, recorded_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    obs.id.to_string(),
                    subject_to_str(&obs.subject),
                    obs.subject_id,
                    obs.ruleset,
                    obs.observer,
                    obs.score,
                    obs.weight,
                    obs.evidence,
                    obs.expires_at.map(|dt| dt.timestamp()),
                    obs.recorded_at.timestamp()
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn list_reputation_observations(
        &self,
        subject: ReputationSubject,
        subject_id: &str,
        ruleset: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ReputationObservation>> {
        let subject_kind = subject_to_str(&subject).to_string();
        let subject_id = subject_id.to_string();
        let ruleset = ruleset.map(|s| s.to_string());
        let path = self.db_path.clone();
        let rows = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut out = Vec::new();
            if let Some(ruleset) = &ruleset {
                let mut stmt = conn.prepare(
                    "SELECT id, subject_kind, subject_id, ruleset, observer, score, weight, evidence, expires_at, recorded_at \
                     FROM reputation_observations WHERE subject_kind=?1 AND subject_id=?2 AND ruleset=?3 \
                     ORDER BY recorded_at DESC LIMIT ?4",
                )?;
                let mut rows = stmt.query(params![
                    subject_kind,
                    subject_id,
                    ruleset,
                    limit as i64
                ])?;
                while let Some(row) = rows.next()? {
                    let subject_str: String = row.get(1)?;
                    let recorded_at: i64 = row.get(9)?;
                    let expires_at: Option<i64> = row.get(8)?;
                    out.push(ReputationObservation {
                        id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
                        subject: subject_from_str(&subject_str)?,
                        subject_id: row.get(2)?,
                        ruleset: row.get(3)?,
                        observer: row.get(4)?,
                        score: row.get(5)?,
                        weight: row.get(6)?,
                        evidence: row.get(7)?,
                        expires_at: expires_at.map(|ts| {
                            DateTime::<Utc>::from_timestamp(ts, 0)
                                .unwrap_or_else(|| Utc.timestamp_opt(ts, 0).single().unwrap())
                        }),
                        recorded_at: DateTime::<Utc>::from_timestamp(recorded_at, 0)
                            .unwrap_or_else(|| Utc.timestamp_opt(recorded_at, 0).single().unwrap()),
                    });
                }
            } else {
                let mut stmt = conn.prepare(
                    "SELECT id, subject_kind, subject_id, ruleset, observer, score, weight, evidence, expires_at, recorded_at \
                     FROM reputation_observations WHERE subject_kind=?1 AND subject_id=?2 \
                     ORDER BY recorded_at DESC LIMIT ?3",
                )?;
                let mut rows = stmt.query(params![subject_kind, subject_id, limit as i64])?;
                while let Some(row) = rows.next()? {
                    let subject_str: String = row.get(1)?;
                    let recorded_at: i64 = row.get(9)?;
                    let expires_at: Option<i64> = row.get(8)?;
                    out.push(ReputationObservation {
                        id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
                        subject: subject_from_str(&subject_str)?,
                        subject_id: row.get(2)?,
                        ruleset: row.get(3)?,
                        observer: row.get(4)?,
                        score: row.get(5)?,
                        weight: row.get(6)?,
                        evidence: row.get(7)?,
                        expires_at: expires_at.map(|ts| {
                            DateTime::<Utc>::from_timestamp(ts, 0)
                                .unwrap_or_else(|| Utc.timestamp_opt(ts, 0).single().unwrap())
                        }),
                        recorded_at: DateTime::<Utc>::from_timestamp(recorded_at, 0)
                            .unwrap_or_else(|| Utc.timestamp_opt(recorded_at, 0).single().unwrap()),
                    });
                }
            }
            let mut out = Vec::new();
            out.sort_by(|a: &ReputationObservation, b| {
                b.recorded_at.cmp(&a.recorded_at)
            });
            out.truncate(limit);
            Ok::<_, NameServerError>(out)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(rows)
    }

    async fn purge_expired_observations(&self, now: DateTime<Utc>) -> Result<()> {
        let cutoff = now.timestamp();
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "DELETE FROM reputation_observations WHERE expires_at IS NOT NULL AND expires_at <= ?1",
                params![cutoff],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn create_tribunal_case(&self, case: TribunalCase) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO tribunal_cases(id, subject_kind, subject_id, ruleset, status, reason, reporter, severity, metadata, opened_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    case.id.to_string(),
                    subject_to_str(&case.subject),
                    case.subject_id,
                    case.ruleset,
                    status_to_str(&case.status),
                    case.reason,
                    case.reporter,
                    case.severity,
                    case.metadata.map(|v| v.to_string()),
                    case.opened_at.timestamp(),
                    case.updated_at.timestamp()
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn update_tribunal_case_status(
        &self,
        id: Uuid,
        status: TribunalStatus,
        updated_at: DateTime<Utc>,
    ) -> Result<()> {
        let path = self.db_path.clone();
        let id_str = id.to_string();
        let status_str = status_to_str(&status).to_string();
        let updated_at = updated_at.timestamp();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "UPDATE tribunal_cases SET status=?1, updated_at=?2 WHERE id=?3",
                params![status_str, updated_at, id_str],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_tribunal_case(&self, id: Uuid) -> Result<Option<TribunalCase>> {
        let id_str = id.to_string();
        let path = self.db_path.clone();
        let case = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT id, subject_kind, subject_id, ruleset, status, reason, reporter, severity, metadata, opened_at, updated_at FROM tribunal_cases WHERE id=?1",
            )?;
            let mut rows = stmt.query(params![id_str])?;
            if let Some(row) = rows.next()? {
                let subject_str: String = row.get(1)?;
                let status_str: String = row.get(4)?;
                let opened_at: i64 = row.get(9)?;
                let updated_at: i64 = row.get(10)?;
                Ok::<_, NameServerError>(Some(TribunalCase {
                    id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
                    subject: subject_from_str(&subject_str)?,
                    subject_id: row.get(2)?,
                    ruleset: row.get(3)?,
                    status: status_from_str(&status_str)?,
                    reason: row.get(5)?,
                    reporter: row.get(6)?,
                    severity: row.get(7)?,
                    metadata: row
                        .get::<_, Option<String>>(8)?
                        .and_then(|s| serde_json::from_str(&s).ok()),
                    opened_at: DateTime::<Utc>::from_timestamp(opened_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(opened_at, 0).single().unwrap()),
                    updated_at: DateTime::<Utc>::from_timestamp(updated_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(updated_at, 0).single().unwrap()),
                }))
            } else {
                Ok::<_, NameServerError>(None)
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(case)
    }

    async fn list_tribunal_cases(
        &self,
        status: Option<TribunalStatus>,
        limit: usize,
    ) -> Result<Vec<TribunalCase>> {
        let status_str = status.map(|s| status_to_str(&s).to_string());
        let path = self.db_path.clone();
        let cases = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut out = Vec::new();
            if let Some(status) = &status_str {
                let mut stmt = conn.prepare(
                    "SELECT id, subject_kind, subject_id, ruleset, status, reason, reporter, severity, metadata, opened_at, updated_at \
                     FROM tribunal_cases WHERE status=?1 ORDER BY opened_at DESC LIMIT ?2",
                )?;
                let mut rows = stmt.query(params![status, limit as i64])?;
                while let Some(row) = rows.next()? {
                    out.push(row_to_case(row)?);
                }
            } else {
                let mut stmt = conn.prepare(
                    "SELECT id, subject_kind, subject_id, ruleset, status, reason, reporter, severity, metadata, opened_at, updated_at \
                     FROM tribunal_cases ORDER BY opened_at DESC LIMIT ?1",
                )?;
                let mut rows = stmt.query(params![limit as i64])?;
                while let Some(row) = rows.next()? {
                    out.push(row_to_case(row)?);
                }
            }
            Ok::<_, NameServerError>(out)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(cases)
    }

    async fn append_tribunal_decision(&self, decision: TribunalDecision) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO tribunal_decisions(id, case_id, outcome, penalty_delta, decided_by, decided_at, notes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    decision.id.to_string(),
                    decision.case_id.to_string(),
                    outcome_to_str(&decision.outcome),
                    decision.penalty_delta,
                    decision.decided_by,
                    decision.decided_at.timestamp(),
                    decision.notes
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn list_tribunal_decisions(&self, case_id: Uuid) -> Result<Vec<TribunalDecision>> {
        let path = self.db_path.clone();
        let id_str = case_id.to_string();
        let rows = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT id, outcome, penalty_delta, decided_by, decided_at, notes FROM tribunal_decisions WHERE case_id=?1 ORDER BY decided_at DESC",
            )?;
            let mut rows = stmt.query(params![id_str])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                let decided_at: i64 = row.get(4)?;
                out.push(TribunalDecision {
                    id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
                    case_id,
                    outcome: outcome_from_str(&row.get::<_, String>(1)?)?,
                    penalty_delta: row.get(2)?,
                    decided_by: row.get(3)?,
                    decided_at: DateTime::<Utc>::from_timestamp(decided_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(decided_at, 0).single().unwrap()),
                    notes: row.get(5)?,
                });
            }
            Ok::<_, NameServerError>(out)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(rows)
    }

    // Phase C: Tribunal decision blocks
    async fn store_tribunal_decision_block(&self, block: TribunalDecisionBlock) -> Result<String> {
        let cid = block.compute_cid().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("CID computation failed: {}", e))
        })?;
        let path = self.db_path.clone();
        let cid_clone = cid.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT OR REPLACE INTO tribunal_decision_blocks(cid, case_id, decision_id, subject_kind, subject_id, ruleset, outcome, penalty_delta, decided_by, decided_at, notes, evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    cid_clone,
                    block.case_id.to_string(),
                    block.decision_id.to_string(),
                    subject_to_str(&block.subject),
                    block.subject_id,
                    block.ruleset,
                    outcome_to_str(&block.outcome),
                    block.penalty_delta,
                    block.decided_by,
                    block.decided_at.timestamp(),
                    block.notes,
                    block.evidence
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(cid)
    }

    async fn get_tribunal_decision_block(
        &self,
        cid: &str,
    ) -> Result<Option<TribunalDecisionBlock>> {
        let path = self.db_path.clone();
        let cid_str = cid.to_string();
        let block = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT case_id, decision_id, subject_kind, subject_id, ruleset, outcome, penalty_delta, decided_by, decided_at, notes, evidence FROM tribunal_decision_blocks WHERE cid=?1",
            )?;
            let mut rows = stmt.query(params![cid_str])?;
            if let Some(row) = rows.next()? {
                let decided_at: i64 = row.get(8)?;
                Ok::<_, NameServerError>(Some(TribunalDecisionBlock {
                    case_id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
                    decision_id: Uuid::parse_str(&row.get::<_, String>(1)?).unwrap_or_else(|_| Uuid::now_v7()),
                    subject: subject_from_str(&row.get::<_, String>(2)?)?,
                    subject_id: row.get(3)?,
                    ruleset: row.get(4)?,
                    outcome: outcome_from_str(&row.get::<_, String>(5)?)?,
                    penalty_delta: row.get(6)?,
                    decided_by: row.get(7)?,
                    decided_at: DateTime::<Utc>::from_timestamp(decided_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(decided_at, 0).single().unwrap()),
                    notes: row.get(9)?,
                    evidence: row.get(10)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(block)
    }

    async fn enqueue_useful_work(&self, assignment: UsefulWorkAssignment) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO useful_work_assignments(id, kind, subject, ruleset, payload, status, assigned_to, priority, issued_at, expires_at, last_updated)\n                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    assignment.id.to_string(),
                    work_kind_to_str(&assignment.kind),
                    assignment.subject,
                    assignment.ruleset,
                    serde_json::to_string(&assignment.payload).unwrap_or_else(|_| "null".into()),
                    work_status_to_str(&assignment.status),
                    assignment.assigned_to,
                    assignment.priority,
                    assignment.issued_at.timestamp(),
                    assignment.expires_at.timestamp(),
                    assignment.last_updated.timestamp()
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn claim_useful_work(
        &self,
        worker: &str,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<Vec<UsefulWorkAssignment>> {
        let worker = worker.to_string();
        let path = self.db_path.clone();
        let now_ts = now.timestamp();
        let claimed = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "UPDATE useful_work_assignments SET status='failed', last_updated=?1 WHERE status='queued' AND expires_at <= ?1",
                params![now_ts],
            )?;
            let mut stmt = conn.prepare(
                "SELECT id, kind, subject, ruleset, payload, status, assigned_to, priority, issued_at, expires_at, last_updated FROM useful_work_assignments WHERE status='queued' AND expires_at > ?1 ORDER BY priority DESC, issued_at ASC LIMIT ?2",
            )?;
            let mut rows = stmt.query(params![now_ts, limit as i64])?;
            let mut selected: Vec<UsefulWorkAssignment> = Vec::new();
            while let Some(row) = rows.next()? {
                selected.push(row_to_useful_work(row)?);
            }
            let mut claimed = Vec::new();
            for mut assignment in selected {
                let updated = conn.execute(
                    "UPDATE useful_work_assignments SET status=?1, assigned_to=?2, last_updated=?3 WHERE id=?4 AND status='queued'",
                    params![
                        work_status_to_str(&UsefulWorkStatus::InProgress),
                        worker,
                        now_ts,
                        assignment.id.to_string()
                    ],
                )?;
                if updated == 1 {
                    assignment.status = UsefulWorkStatus::InProgress;
                    assignment.assigned_to = Some(worker.clone());
                    assignment.last_updated = now;
                    claimed.push(assignment);
                }
            }
            Ok::<_, NameServerError>(claimed)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(claimed)
    }

    async fn complete_useful_work(&self, result: UsefulWorkResult) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = Connection::open(path)?;
            let tx = conn.transaction()?;
            tx.execute(
                "UPDATE useful_work_assignments SET status=?1, assigned_to=?2, last_updated=?3 WHERE id=?4",
                params![
                    work_status_to_str(&result.status),
                    result.worker,
                    result.submitted_at.timestamp(),
                    result.assignment_id.to_string()
                ],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO useful_work_results(assignment_id, worker, status, output, metadata, submitted_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    result.assignment_id.to_string(),
                    result.worker,
                    work_status_to_str(&result.status),
                    serde_json::to_string(&result.output).unwrap_or_else(|_| "null".into()),
                    serde_json::to_string(&result.metadata).unwrap_or_else(|_| "null".into()),
                    result.submitted_at.timestamp()
                ],
            )?;
            tx.commit()?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_useful_work(&self, id: Uuid) -> Result<Option<UsefulWorkAssignment>> {
        let id_str = id.to_string();
        let path = self.db_path.clone();
        let assignment = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT id, kind, subject, ruleset, payload, status, assigned_to, priority, issued_at, expires_at, last_updated FROM useful_work_assignments WHERE id=?1",
            )?;
            let mut rows = stmt.query(params![id_str])?;
            if let Some(row) = rows.next()? {
                let assignment = row_to_useful_work(row)?;
                return Ok::<_, NameServerError>(Some(assignment));
            }
            Ok::<_, NameServerError>(None)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(assignment)
    }

    async fn useful_work_queue_depth(&self) -> Result<usize> {
        let path = self.db_path.clone();
        let count = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT COUNT(*) FROM useful_work_assignments WHERE status='queued' OR status='in_progress'",
            )?;
            let mut rows = stmt.query([])?;
            if let Some(row) = rows.next()? {
                let count: i64 = row.get(0)?;
                return Ok::<_, NameServerError>(count as usize);
            }
            Ok::<_, NameServerError>(0usize)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(count)
    }

    async fn useful_work_inflight(&self, worker: &str) -> Result<usize> {
        let worker = worker.to_string();
        let path = self.db_path.clone();
        let count = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT COUNT(*) FROM useful_work_assignments WHERE status='in_progress' AND assigned_to=?1",
            )?;
            let mut rows = stmt.query(params![worker])?;
            if let Some(row) = rows.next()? {
                let count: i64 = row.get(0)?;
                return Ok::<_, NameServerError>(count as usize);
            }
            Ok::<_, NameServerError>(0usize)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(count)
    }

    async fn append_transparency_log(&self, entry: TransparencyLogEntry) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO transparency_log(id, event_kind, subject, payload, hash, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    entry.id.to_string(),
                    event_kind_to_str(&entry.event_kind),
                    entry.subject,
                    serde_json::to_string(&entry.payload).unwrap_or_else(|_| "null".into()),
                    entry.hash,
                    entry.recorded_at.timestamp()
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn list_transparency_log(
        &self,
        start: Option<chrono::DateTime<Utc>>,
        end: Option<chrono::DateTime<Utc>>,
        event_kind: Option<TransparencyLogEventKind>,
        limit: usize,
    ) -> Result<Vec<TransparencyLogEntry>> {
        let path = self.db_path.clone();
        let entries = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut query = "SELECT id, event_kind, subject, payload, hash, recorded_at FROM transparency_log WHERE 1=1".to_string();
            let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

            if let Some(s) = start {
                query.push_str(" AND recorded_at >= ?");
                params_vec.push(Box::new(s.timestamp()));
            }
            if let Some(e) = end {
                query.push_str(" AND recorded_at <= ?");
                params_vec.push(Box::new(e.timestamp()));
            }
            if let Some(kind) = event_kind {
                query.push_str(" AND event_kind = ?");
                params_vec.push(Box::new(event_kind_to_str(&kind).to_string()));
            }
            query.push_str(" ORDER BY recorded_at ASC LIMIT ?");
            params_vec.push(Box::new(limit as i64));

            let mut stmt = conn.prepare(&query)?;
            let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();
            let mut rows = stmt.query(params_refs.as_slice())?;

            let mut entries = Vec::new();
            while let Some(row) = rows.next()? {
                entries.push(row_to_transparency_log_entry(row)?);
            }
            Ok::<_, NameServerError>(entries)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(entries)
    }

    async fn store_transparency_hash(&self, hash: TransparencyLogHash) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO transparency_hashes(id, period_start, period_end, entry_count, merkle_root, previous_hash, computed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    hash.id.to_string(),
                    hash.period_start.timestamp(),
                    hash.period_end.timestamp(),
                    hash.entry_count,
                    hash.merkle_root,
                    hash.previous_hash,
                    hash.computed_at.timestamp()
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_latest_transparency_hash(&self) -> Result<Option<TransparencyLogHash>> {
        let path = self.db_path.clone();
        let hash = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT id, period_start, period_end, entry_count, merkle_root, previous_hash, computed_at FROM transparency_hashes ORDER BY computed_at DESC LIMIT 1",
            )?;
            let mut rows = stmt.query([])?;
            if let Some(row) = rows.next()? {
                let hash = row_to_transparency_hash(row)?;
                return Ok::<_, NameServerError>(Some(hash));
            }
            Ok::<_, NameServerError>(None)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(hash)
    }

    async fn list_transparency_hashes(&self, limit: usize) -> Result<Vec<TransparencyLogHash>> {
        let path = self.db_path.clone();
        let hashes = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT id, period_start, period_end, entry_count, merkle_root, previous_hash, computed_at FROM transparency_hashes ORDER BY computed_at ASC LIMIT ?",
            )?;
            let mut rows = stmt.query(params![limit as i64])?;
            let mut hashes = Vec::new();
            while let Some(row) = rows.next()? {
                hashes.push(row_to_transparency_hash(row)?);
            }
            Ok::<_, NameServerError>(hashes)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(hashes)
    }

    // Federation peers
    async fn upsert_federation_peer(&self, peer: crate::types::FederationPeer) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let public_key_bytes = peer.public_key.as_deref().unwrap_or(&[]);
            let metadata_json = serde_json::to_string(&peer.metadata).unwrap_or_default();
            conn.execute(
                "INSERT INTO federation_peers (id, domain, endpoint, public_key, status, capabilities_hash, discovered_at, last_seen_at, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(domain) DO UPDATE SET endpoint=excluded.endpoint, public_key=excluded.public_key, status=excluded.status,
                    capabilities_hash=excluded.capabilities_hash, last_seen_at=excluded.last_seen_at, metadata=excluded.metadata",
                params![
                    peer.id.to_string(),
                    peer.domain,
                    peer.endpoint,
                    public_key_bytes,
                    peer_status_to_str(&peer.status),
                    peer.capabilities_hash,
                    peer.discovered_at.timestamp(),
                    peer.last_seen_at.timestamp(),
                    metadata_json,
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_federation_peer(
        &self,
        domain: &str,
    ) -> Result<Option<crate::types::FederationPeer>> {
        let path = self.db_path.clone();
        let domain = domain.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT id, domain, endpoint, public_key, status, capabilities_hash, discovered_at, last_seen_at, metadata FROM federation_peers WHERE domain = ?",
            )?;
            let result = stmt.query_row(params![domain], |row| {
                let id: String = row.get(0)?;
                let status_str: String = row.get(4)?;
                let discovered_at: i64 = row.get(6)?;
                let last_seen_at: i64 = row.get(7)?;
                let metadata_str: String = row.get(8)?;
                Ok(crate::types::FederationPeer {
                    id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::now_v7()),
                    domain: row.get(1)?,
                    endpoint: row.get(2)?,
                    public_key: row.get::<_, Option<Vec<u8>>>(3)?,
                    status: peer_status_from_str(&status_str).unwrap_or(crate::types::FederationPeerStatus::Unreachable),
                    capabilities_hash: row.get(5)?,
                    discovered_at: DateTime::<Utc>::from_timestamp(discovered_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(discovered_at, 0).single().unwrap()),
                    last_seen_at: DateTime::<Utc>::from_timestamp(last_seen_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(last_seen_at, 0).single().unwrap()),
                    metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
                })
            });
            match result {
                Ok(peer) => Ok(Some(peer)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    async fn list_federation_peers(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::types::FederationPeer>> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT id, domain, endpoint, public_key, status, capabilities_hash, discovered_at, last_seen_at, metadata FROM federation_peers ORDER BY last_seen_at DESC LIMIT ?",
            )?;
            let mut rows = stmt.query(params![limit as i64])?;
            let mut peers = Vec::new();
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let status_str: String = row.get(4)?;
                let discovered_at: i64 = row.get(6)?;
                let last_seen_at: i64 = row.get(7)?;
                let metadata_str: String = row.get(8)?;
                peers.push(crate::types::FederationPeer {
                    id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::now_v7()),
                    domain: row.get(1)?,
                    endpoint: row.get(2)?,
                    public_key: row.get::<_, Option<Vec<u8>>>(3)?,
                    status: peer_status_from_str(&status_str).unwrap_or(crate::types::FederationPeerStatus::Unreachable),
                    capabilities_hash: row.get(5)?,
                    discovered_at: DateTime::<Utc>::from_timestamp(discovered_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(discovered_at, 0).single().unwrap()),
                    last_seen_at: DateTime::<Utc>::from_timestamp(last_seen_at, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(last_seen_at, 0).single().unwrap()),
                    metadata: serde_json::from_str(&metadata_str).unwrap_or_default(),
                });
            }
            Ok::<_, NameServerError>(peers)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    async fn update_peer_status(
        &self,
        domain: &str,
        status: crate::types::FederationPeerStatus,
        last_seen: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let path = self.db_path.clone();
        let domain = domain.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "UPDATE federation_peers SET status = ?, last_seen_at = ? WHERE domain = ?",
                params![peer_status_to_str(&status), last_seen.timestamp(), domain],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    // Gossip messages
    async fn store_gossip_message(&self, message: crate::types::GossipMessage) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let payload_json = serde_json::to_string(&message.payload).unwrap_or_default();
            let signature_bytes = message.signature.as_deref().unwrap_or(&[]);
            conn.execute(
                "INSERT INTO gossip_messages (id, kind, from_peer, payload, signature, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    message.id.to_string(),
                    gossip_kind_to_str(&message.kind),
                    message.from_peer,
                    payload_json,
                    signature_bytes,
                    message.timestamp.timestamp(),
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn list_gossip_messages(
        &self,
        kind: Option<crate::types::GossipMessageKind>,
        limit: usize,
    ) -> Result<Vec<crate::types::GossipMessage>> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let (query, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = if let Some(k) = kind {
                (
                    "SELECT id, kind, from_peer, payload, signature, timestamp FROM gossip_messages WHERE kind = ? ORDER BY timestamp DESC LIMIT ?".to_string(),
                    vec![Box::new(gossip_kind_to_str(&k).to_string()), Box::new(limit as i64)],
                )
            } else {
                (
                    "SELECT id, kind, from_peer, payload, signature, timestamp FROM gossip_messages ORDER BY timestamp DESC LIMIT ?".to_string(),
                    vec![Box::new(limit as i64)],
                )
            };
            let mut stmt = conn.prepare(&query)?;
            let params_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            let mut rows = stmt.query(params_refs.as_slice())?;
            let mut messages = Vec::new();
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let kind_str: String = row.get(1)?;
                let payload_str: String = row.get(3)?;
                let timestamp: i64 = row.get(5)?;
                messages.push(crate::types::GossipMessage {
                    id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::now_v7()),
                    kind: gossip_kind_from_str(&kind_str).unwrap_or(crate::types::GossipMessageKind::Handshake),
                    from_peer: row.get(2)?,
                    payload: serde_json::from_str(&payload_str).unwrap_or_default(),
                    signature: row.get::<_, Option<Vec<u8>>>(4)?,
                    timestamp: DateTime::<Utc>::from_timestamp(timestamp, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(timestamp, 0).single().unwrap()),
                });
            }
            Ok::<_, NameServerError>(messages)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    // Policy hashes
    async fn store_policy_hash(&self, policy: crate::types::PolicyHashExchange) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let rulesets_json = serde_json::to_string(&policy.rulesets).unwrap_or_default();
            conn.execute(
                "INSERT INTO policy_hashes (domain, policy_version, policy_hash, rulesets, capabilities_url, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(domain) DO UPDATE SET policy_version=excluded.policy_version, policy_hash=excluded.policy_hash,
                    rulesets=excluded.rulesets, capabilities_url=excluded.capabilities_url, timestamp=excluded.timestamp",
                params![
                    policy.domain,
                    policy.policy_version,
                    policy.policy_hash,
                    rulesets_json,
                    policy.capabilities_url,
                    policy.timestamp.timestamp(),
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_policy_hash(
        &self,
        domain: &str,
    ) -> Result<Option<crate::types::PolicyHashExchange>> {
        let path = self.db_path.clone();
        let domain = domain.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT domain, policy_version, policy_hash, rulesets, capabilities_url, runtime_hash, affordances, timestamp FROM policy_hashes WHERE domain = ?",
            )?;
            let result = stmt.query_row(params![domain], |row| {
                let rulesets_str: String = row.get(3)?;
                let affordances_str: Option<String> = row.get(6)?;
                let timestamp: i64 = row.get(7)?;
                Ok(crate::types::PolicyHashExchange {
                    domain: row.get(0)?,
                    policy_version: row.get(1)?,
                    policy_hash: row.get(2)?,
                    rulesets: serde_json::from_str(&rulesets_str).unwrap_or_default(),
                    capabilities_url: row.get(4)?,
                    runtime_hash: row.get(5)?,
                    affordances: affordances_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
                    timestamp: DateTime::<Utc>::from_timestamp(timestamp, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(timestamp, 0).single().unwrap()),
                })
            });
            match result {
                Ok(policy) => Ok(Some(policy)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    async fn list_policy_hashes(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::types::PolicyHashExchange>> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT domain, policy_version, policy_hash, rulesets, capabilities_url, runtime_hash, affordances, timestamp FROM policy_hashes ORDER BY timestamp DESC LIMIT ?",
            )?;
            let mut rows = stmt.query(params![limit as i64])?;
            let mut policies = Vec::new();
            while let Some(row) = rows.next()? {
                let rulesets_str: String = row.get(3)?;
                let affordances_str: Option<String> = row.get(6)?;
                let timestamp: i64 = row.get(7)?;
                policies.push(crate::types::PolicyHashExchange {
                    domain: row.get(0)?,
                    policy_version: row.get(1)?,
                    policy_hash: row.get(2)?,
                    rulesets: serde_json::from_str(&rulesets_str).unwrap_or_default(),
                    capabilities_url: row.get(4)?,
                    runtime_hash: row.get(5)?,
                    affordances: affordances_str.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
                    timestamp: DateTime::<Utc>::from_timestamp(timestamp, 0)
                        .unwrap_or_else(|| Utc.timestamp_opt(timestamp, 0).single().unwrap()),
                });
            }
            Ok::<_, NameServerError>(policies)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    // Receipt storage (Phase A)
    async fn store_receipt(&self, receipt: jig_core::BlockReceipt) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;

            // Serialize complex fields to JSON
            let block_id = receipt.block_id.to_string();
            let hash_algorithms = serde_json::to_string(&receipt.hash_algorithms)
                .map_err(|e| NameServerError::Other(anyhow::anyhow!("hash_algorithms serialization: {e}")))?;
            let capabilities_used = serde_json::to_string(&receipt.capabilities_used)
                .map_err(|e| NameServerError::Other(anyhow::anyhow!("capabilities serialization: {e}")))?;
            let attestations = serde_json::to_string(&receipt.attestations)
                .map_err(|e| NameServerError::Other(anyhow::anyhow!("attestations serialization: {e}")))?;
            let metadata = serde_json::to_string(&receipt.metadata)
                .map_err(|e| NameServerError::Other(anyhow::anyhow!("metadata serialization: {e}")))?;
            let executed_at = receipt.executed_at.unix_timestamp();

            // Extract optional v0.2 fields
            let renders_match = receipt.renders_match.map(|b| if b { 1 } else { 0 });
            let (counters_fuel_total, counters_bytes_tx, counters_bytes_rx, counters_syscalls) =
                if let Some(ref c) = receipt.counters {
                    (Some(c.fuel_total as i64), Some(c.bytes_tx as i64), Some(c.bytes_rx as i64), Some(c.syscalls as i64))
                } else {
                    (None, None, None, None)
                };

            let (timings_queue_wait, timings_init, timings_exec, timings_total) =
                if let Some(ref t) = receipt.timings_ms {
                    (Some(t.queue_wait as i64), Some(t.init as i64), Some(t.exec as i64), Some(t.total as i64))
                } else {
                    (None, None, None, None)
                };

            let (limit_fuel_max, limit_memory_max_mb, limit_exec_timeout_ms) =
                if let Some(ref l) = receipt.limits {
                    (Some(l.fuel_max as i64), Some(l.memory_max_mb as i64), Some(l.execution_timeout_ms as i64))
                } else {
                    (None, None, None)
                };

            let (outcome_status, outcome_reason, outcome_affordances) =
                if let Some(ref o) = receipt.outcome {
                    let status_str = match o.status {
                        jig_core::OutcomeStatus::Ok => "ok",
                        jig_core::OutcomeStatus::SoftFail => "soft_fail",
                        jig_core::OutcomeStatus::HardFail => "hard_fail",
                    };
                    let affordances = if !o.affordances.is_empty() {
                        Some(serde_json::to_string(&o.affordances)
                            .map_err(|e| NameServerError::Other(anyhow::anyhow!("affordances serialization: {e}")))?)
                    } else {
                        None
                    };
                    // Serialize ReasonCode as JSON string
                    let reason_str = o.reason.as_ref().map(|r| {
                        serde_json::to_string(r)
                            .map_err(|e| NameServerError::Other(anyhow::anyhow!("reason serialization: {e}")))
                    }).transpose()?;
                    (Some(status_str.to_string()), reason_str, affordances)
                } else {
                    (None, None, None)
                };

            conn.execute(
                "INSERT OR REPLACE INTO receipts (
                    block_id, receipt_schema_version, host_did, executed_at, render_hash, renders_match,
                    fuel_used, memory_peak_mb, counters_fuel_total, counters_bytes_tx, counters_bytes_rx,
                    counters_syscalls, timings_queue_wait_ms, timings_init_ms, timings_exec_ms, timings_total_ms,
                    limit_fuel_max, limit_memory_max_mb, limit_exec_timeout_ms, outcome_status, outcome_reason,
                    outcome_affordances, hash_algorithms, capabilities_used, attestations, signature, metadata
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27)",
                params![
                    block_id,
                    receipt.receipt_schema_version,
                    receipt.host,
                    executed_at,
                    receipt.render_hash,
                    renders_match,
                    receipt.fuel_used as i64,
                    receipt.memory_peak_mb.map(|m| m as i64),
                    counters_fuel_total,
                    counters_bytes_tx,
                    counters_bytes_rx,
                    counters_syscalls,
                    timings_queue_wait,
                    timings_init,
                    timings_exec,
                    timings_total,
                    limit_fuel_max,
                    limit_memory_max_mb,
                    limit_exec_timeout_ms,
                    outcome_status,
                    outcome_reason,
                    outcome_affordances,
                    hash_algorithms,
                    capabilities_used,
                    attestations,
                    receipt.signature,
                    metadata,
                ],
            )?;

            // Store per-capability fuel counters if present
            if let Some(ref counters) = receipt.counters {
                for (capability, fuel) in &counters.fuel_by_capability {
                    conn.execute(
                        "INSERT INTO receipt_capability_counters (block_id, executed_at, capability, fuel_used)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![block_id, executed_at, capability, *fuel as i64],
                    )?;
                }
            }

            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    async fn get_receipt(&self, block_id: &str) -> Result<Option<jig_core::BlockReceipt>> {
        let path = self.db_path.clone();
        let block_id = block_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare("SELECT * FROM receipts WHERE block_id = ?1")?;
            let mut rows = stmt.query(params![block_id])?;
            if let Some(row) = rows.next()? {
                Ok::<_, NameServerError>(Some(row_to_receipt(row)?))
            } else {
                Ok(None)
            }
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    async fn list_receipts(
        &self,
        host_did: Option<&str>,
        outcome_status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<jig_core::BlockReceipt>> {
        let path = self.db_path.clone();
        let host_did = host_did.map(|s| s.to_string());
        let outcome_status = outcome_status.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;

            let mut query = "SELECT * FROM receipts WHERE 1=1".to_string();
            let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

            if let Some(ref host) = host_did {
                query.push_str(" AND host_did = ?");
                params_vec.push(Box::new(host.clone()));
            }
            if let Some(ref status) = outcome_status {
                query.push_str(" AND outcome_status = ?");
                params_vec.push(Box::new(status.clone()));
            }
            query.push_str(" ORDER BY executed_at DESC LIMIT ?");
            params_vec.push(Box::new(limit as i64));

            let mut stmt = conn.prepare(&query)?;
            let params_refs: Vec<&dyn rusqlite::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            let mut rows = stmt.query(params_refs.as_slice())?;

            let mut receipts = Vec::new();
            while let Some(row) = rows.next()? {
                receipts.push(row_to_receipt(row)?);
            }
            Ok::<_, NameServerError>(receipts)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    // Attestation storage (Phase B)
    async fn store_attestation(&self, attestation: crate::types::Attestation) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO attestations (id, block_id, verifier_did, verdict, fuel_delta, evidence_cid, attested_at, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    attestation.id.to_string(),
                    attestation.block_id,
                    attestation.verifier_did,
                    match attestation.verdict {
                        crate::types::AttestationVerdict::Confirmed => "confirmed",
                        crate::types::AttestationVerdict::Disputed => "disputed",
                        crate::types::AttestationVerdict::SoftFail => "soft_fail",
                    },
                    attestation.fuel_delta,
                    attestation.evidence_cid,
                    attestation.attested_at.timestamp(),
                    attestation.signature,
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    async fn get_attestations(&self, block_id: &str) -> Result<Vec<crate::types::Attestation>> {
        let path = self.db_path.clone();
        let block_id = block_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT * FROM attestations WHERE block_id = ? ORDER BY attested_at DESC",
            )?;
            let mut rows = stmt.query(rusqlite::params![block_id])?;

            let mut attestations = Vec::new();
            while let Some(row) = rows.next()? {
                attestations.push(row_to_attestation(row)?);
            }
            Ok::<_, NameServerError>(attestations)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    async fn list_attestations(
        &self,
        verifier_did: Option<&str>,
        verdict: Option<crate::types::AttestationVerdict>,
        limit: usize,
    ) -> Result<Vec<crate::types::Attestation>> {
        let path = self.db_path.clone();
        let verifier_did = verifier_did.map(|s| s.to_string());
        let verdict_str = verdict.map(|v| match v {
            crate::types::AttestationVerdict::Confirmed => "confirmed",
            crate::types::AttestationVerdict::Disputed => "disputed",
            crate::types::AttestationVerdict::SoftFail => "soft_fail",
        });
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;

            let mut query = "SELECT * FROM attestations WHERE 1=1".to_string();
            let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

            if let Some(ref did) = verifier_did {
                query.push_str(" AND verifier_did = ?");
                params_vec.push(Box::new(did.clone()));
            }
            if let Some(v) = verdict_str {
                query.push_str(" AND verdict = ?");
                params_vec.push(Box::new(v));
            }
            query.push_str(" ORDER BY attested_at DESC LIMIT ?");
            params_vec.push(Box::new(limit as i64));

            let mut stmt = conn.prepare(&query)?;
            let params_refs: Vec<&dyn rusqlite::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            let mut rows = stmt.query(params_refs.as_slice())?;

            let mut attestations = Vec::new();
            while let Some(row) = rows.next()? {
                attestations.push(row_to_attestation(row)?);
            }
            Ok::<_, NameServerError>(attestations)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))?
    }

    // Anomaly storage (Phase D)
    async fn store_anomaly(&self, anomaly: ReceiptAnomaly) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO anomalies(id, block_id, host_did, kind, severity, description, evidence, detected_at, auto_escalated, tribunal_case_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    anomaly.id.to_string(),
                    anomaly.block_id,
                    anomaly.host_did,
                    anomaly_kind_to_str(&anomaly.kind),
                    anomaly_severity_to_str(&anomaly.severity),
                    anomaly.description,
                    serde_json::to_string(&anomaly.evidence).unwrap_or_else(|_| "{}".into()),
                    anomaly.detected_at.timestamp(),
                    anomaly.auto_escalated as i32,
                    anomaly.tribunal_case_id.map(|id| id.to_string()),
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_anomalies_for_block(&self, block_id: &str) -> Result<Vec<ReceiptAnomaly>> {
        let path = self.db_path.clone();
        let block_id = block_id.to_string();
        let anomalies = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT id, block_id, host_did, kind, severity, description, evidence, detected_at, auto_escalated, tribunal_case_id
                 FROM anomalies WHERE block_id = ?1 ORDER BY detected_at DESC",
            )?;
            let mut rows = stmt.query(params![block_id])?;
            let mut anomalies = Vec::new();
            while let Some(row) = rows.next()? {
                anomalies.push(row_to_anomaly(row)?);
            }
            Ok::<_, NameServerError>(anomalies)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(anomalies)
    }

    async fn get_anomalies_for_host(
        &self,
        host_did: &str,
        kind: Option<AnomalyKind>,
        severity: Option<AnomalySeverity>,
        limit: usize,
    ) -> Result<Vec<ReceiptAnomaly>> {
        let path = self.db_path.clone();
        let host_did = host_did.to_string();
        let kind_str = kind.as_ref().map(anomaly_kind_to_str);
        let severity_str = severity.as_ref().map(anomaly_severity_to_str);
        let anomalies = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut query = "SELECT id, block_id, host_did, kind, severity, description, evidence, detected_at, auto_escalated, tribunal_case_id FROM anomalies WHERE host_did = ?1".to_string();
            let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(host_did)];

            if let Some(k) = kind_str {
                query.push_str(" AND kind = ?");
                params_vec.push(Box::new(k.to_string()));
            }
            if let Some(s) = severity_str {
                query.push_str(" AND severity = ?");
                params_vec.push(Box::new(s.to_string()));
            }
            query.push_str(" ORDER BY detected_at DESC LIMIT ?");
            params_vec.push(Box::new(limit as i64));

            let mut stmt = conn.prepare(&query)?;
            let params_refs: Vec<&dyn rusqlite::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();
            let mut rows = stmt.query(params_refs.as_slice())?;

            let mut anomalies = Vec::new();
            while let Some(row) = rows.next()? {
                anomalies.push(row_to_anomaly(row)?);
            }
            Ok::<_, NameServerError>(anomalies)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(anomalies)
    }

    async fn count_recent_anomalies(
        &self,
        host_did: &str,
        kind: AnomalyKind,
        since: chrono::DateTime<Utc>,
    ) -> Result<usize> {
        let path = self.db_path.clone();
        let host_did = host_did.to_string();
        let kind_str = anomaly_kind_to_str(&kind).to_string();
        let since_ts = since.timestamp();
        let count = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT COUNT(*) FROM anomalies WHERE host_did = ?1 AND kind = ?2 AND detected_at >= ?3",
            )?;
            let count: i64 = stmt.query_row(params![host_did, kind_str, since_ts], |row| row.get(0))?;
            Ok::<_, NameServerError>(count as usize)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(count)
    }

    async fn apply_penalty(&self, penalty: PoWPenalty) -> Result<()> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "INSERT INTO pow_penalties(id, host_did, reason, additional_bits, applied_at, expires_at, anomaly_id, tribunal_case_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    penalty.id.to_string(),
                    penalty.host_did,
                    penalty_reason_to_str(&penalty.reason),
                    penalty.additional_bits as i64,
                    penalty.applied_at.timestamp(),
                    penalty.expires_at.map(|dt| dt.timestamp()),
                    penalty.anomaly_id.map(|id| id.to_string()),
                    penalty.tribunal_case_id.map(|id| id.to_string()),
                ],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_active_penalties(&self, host_did: &str) -> Result<Vec<PoWPenalty>> {
        let path = self.db_path.clone();
        let host_did = host_did.to_string();
        let now = Utc::now().timestamp();
        let penalties = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            let mut stmt = conn.prepare(
                "SELECT id, host_did, reason, additional_bits, applied_at, expires_at, anomaly_id, tribunal_case_id
                 FROM pow_penalties WHERE host_did = ?1 AND (expires_at IS NULL OR expires_at > ?2)
                 ORDER BY applied_at DESC",
            )?;
            let mut rows = stmt.query(params![host_did, now])?;
            let mut penalties = Vec::new();
            while let Some(row) = rows.next()? {
                penalties.push(row_to_penalty(row)?);
            }
            Ok::<_, NameServerError>(penalties)
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(penalties)
    }

    async fn lift_penalty(&self, penalty_id: Uuid) -> Result<()> {
        let path = self.db_path.clone();
        let penalty_id_str = penalty_id.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(path)?;
            conn.execute(
                "DELETE FROM pow_penalties WHERE id = ?1",
                params![penalty_id_str],
            )?;
            Ok::<_, NameServerError>(())
        })
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("join error: {e}"))))??;
        Ok(())
    }

    async fn get_total_penalty_bits(&self, host_did: &str) -> Result<u32> {
        let penalties = self.get_active_penalties(host_did).await?;
        let total: u32 = penalties.iter().map(|p| p.additional_bits).sum();
        Ok(total)
    }
}

fn row_to_case(row: &rusqlite::Row<'_>) -> Result<TribunalCase> {
    let subject_str: String = row.get(1)?;
    let status_str: String = row.get(4)?;
    let opened_at: i64 = row.get(9)?;
    let updated_at: i64 = row.get(10)?;
    Ok(TribunalCase {
        id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
        subject: subject_from_str(&subject_str)?,
        subject_id: row.get(2)?,
        ruleset: row.get(3)?,
        status: status_from_str(&status_str)?,
        reason: row.get(5)?,
        reporter: row.get(6)?,
        severity: row.get(7)?,
        metadata: row
            .get::<_, Option<String>>(8)?
            .and_then(|s| serde_json::from_str(&s).ok()),
        opened_at: DateTime::<Utc>::from_timestamp(opened_at, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(opened_at, 0).single().unwrap()),
        updated_at: DateTime::<Utc>::from_timestamp(updated_at, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(updated_at, 0).single().unwrap()),
    })
}

fn row_to_useful_work(row: &rusqlite::Row<'_>) -> Result<UsefulWorkAssignment> {
    let payload_str: String = row.get(4)?;
    let payload = serde_json::from_str(&payload_str).unwrap_or(JsonValue::Null);
    let status_str: String = row.get(5)?;
    let issued_at: i64 = row.get(8)?;
    let expires_at: i64 = row.get(9)?;
    let last_updated: i64 = row.get(10)?;
    Ok(UsefulWorkAssignment {
        id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
        kind: work_kind_from_str(&row.get::<_, String>(1)?)?,
        subject: row.get(2)?,
        ruleset: row.get(3)?,
        payload,
        status: work_status_from_str(&status_str)?,
        assigned_to: row.get(6)?,
        priority: row.get(7)?,
        issued_at: DateTime::<Utc>::from_timestamp(issued_at, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(issued_at, 0).single().unwrap()),
        expires_at: DateTime::<Utc>::from_timestamp(expires_at, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(expires_at, 0).single().unwrap()),
        last_updated: DateTime::<Utc>::from_timestamp(last_updated, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(last_updated, 0).single().unwrap()),
    })
}

fn row_to_transparency_log_entry(row: &rusqlite::Row<'_>) -> Result<TransparencyLogEntry> {
    let payload_str: String = row.get(3)?;
    let payload = serde_json::from_str(&payload_str).unwrap_or(JsonValue::Null);
    let event_kind_str: String = row.get(1)?;
    let recorded_at: i64 = row.get(5)?;
    Ok(TransparencyLogEntry {
        id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
        event_kind: event_kind_from_str(&event_kind_str)?,
        subject: row.get(2)?,
        payload,
        hash: row.get(4)?,
        recorded_at: DateTime::<Utc>::from_timestamp(recorded_at, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(recorded_at, 0).single().unwrap()),
    })
}

fn row_to_transparency_hash(row: &rusqlite::Row<'_>) -> Result<TransparencyLogHash> {
    let period_start: i64 = row.get(1)?;
    let period_end: i64 = row.get(2)?;
    let computed_at: i64 = row.get(6)?;
    Ok(TransparencyLogHash {
        id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
        period_start: DateTime::<Utc>::from_timestamp(period_start, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(period_start, 0).single().unwrap()),
        period_end: DateTime::<Utc>::from_timestamp(period_end, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(period_end, 0).single().unwrap()),
        entry_count: row.get(3)?,
        merkle_root: row.get(4)?,
        previous_hash: row.get(5)?,
        computed_at: DateTime::<Utc>::from_timestamp(computed_at, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(computed_at, 0).single().unwrap()),
    })
}

fn row_to_receipt(row: &rusqlite::Row<'_>) -> Result<jig_core::BlockReceipt> {
    let block_id_str: String = row.get(0)?;
    let block_id = Cid::from_str(&block_id_str)
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("invalid CID: {e}")))?;

    let executed_at: i64 = row.get(3)?;
    let executed_at = time::OffsetDateTime::from_unix_timestamp(executed_at)
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("invalid timestamp: {e}")))?;

    // Deserialize JSON fields
    let hash_algorithms: jig_core::HashAlgorithms =
        serde_json::from_str(&row.get::<_, String>(22)?)
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("invalid hash_algorithms: {e}")))?;
    let capabilities_used: Vec<String> = serde_json::from_str(&row.get::<_, String>(23)?)
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("invalid capabilities_used: {e}")))?;
    let attestations: Vec<String> = serde_json::from_str(&row.get::<_, String>(24)?)
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("invalid attestations: {e}")))?;
    let metadata: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&row.get::<_, String>(26)?)
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("invalid metadata: {e}")))?;

    // Optional v0.2 fields
    let renders_match: Option<i64> = row.get(5)?;
    let counters = if let Some(fuel_total) = row.get::<_, Option<i64>>(8)? {
        Some(jig_core::Counters {
            fuel_total: fuel_total as u64,
            fuel_by_capability: std::collections::BTreeMap::new(), // Populated separately if needed
            status_by_capability: std::collections::BTreeMap::new(), // New field - empty for now
            bytes_tx: row.get::<_, Option<i64>>(9)?.unwrap_or(0) as u64,
            bytes_rx: row.get::<_, Option<i64>>(10)?.unwrap_or(0) as u64,
            syscalls: row.get::<_, Option<i64>>(11)?.unwrap_or(0) as u64,
        })
    } else {
        None
    };

    let timings_ms = if let Some(exec) = row.get::<_, Option<i64>>(14)? {
        Some(jig_core::Timings {
            queue_wait: row.get::<_, Option<i64>>(12)?.unwrap_or(0) as u32,
            init: row.get::<_, Option<i64>>(13)?.unwrap_or(0) as u32,
            exec: exec as u32,
            total: row.get::<_, Option<i64>>(15)?.unwrap_or(0) as u32,
        })
    } else {
        None
    };

    let limits = if let Some(fuel_max) = row.get::<_, Option<i64>>(16)? {
        Some(jig_core::Limits {
            fuel_max: fuel_max as u64,
            memory_max_mb: row.get::<_, Option<i64>>(17)?.unwrap_or(32) as u32,
            execution_timeout_ms: row.get::<_, Option<i64>>(18)?.unwrap_or(250) as u32,
        })
    } else {
        None
    };

    let outcome = if let Some(status_str) = row.get::<_, Option<String>>(19)? {
        let status = match status_str.as_str() {
            "ok" => jig_core::OutcomeStatus::Ok,
            "soft_fail" => jig_core::OutcomeStatus::SoftFail,
            "hard_fail" => jig_core::OutcomeStatus::HardFail,
            _ => jig_core::OutcomeStatus::Ok,
        };
        let affordances: Vec<String> = row
            .get::<_, Option<String>>(21)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        // Deserialize ReasonCode from JSON string
        let reason: Option<jig_core::ReasonCode> = row
            .get::<_, Option<String>>(20)?
            .and_then(|s| serde_json::from_str(&s).ok());
        Some(jig_core::Outcome {
            status,
            affordances,
            reason,
        })
    } else {
        None
    };

    Ok(jig_core::BlockReceipt {
        receipt_schema_version: row.get(1)?,
        block_id,
        host: row.get(2)?,
        executed_at,
        render_hash: row.get(4)?,
        renders_match: renders_match.map(|v| v != 0),
        fuel_used: row.get::<_, i64>(6)? as u64,
        memory_peak_mb: row.get::<_, Option<i64>>(7)?.map(|m| m as u32),
        counters,
        timings_ms,
        limits,
        outcome,
        hash_algorithms,
        capabilities_used,
        attestations,
        signature: row.get(25)?,
        metadata,
    })
}

fn row_to_anomaly(row: &rusqlite::Row<'_>) -> Result<ReceiptAnomaly> {
    let detected_at: i64 = row.get(7)?;
    let evidence_str: String = row.get(6)?;
    let evidence = serde_json::from_str(&evidence_str).unwrap_or(serde_json::json!({}));

    Ok(ReceiptAnomaly {
        id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
        block_id: row.get(1)?,
        host_did: row.get(2)?,
        kind: anomaly_kind_from_str(&row.get::<_, String>(3)?)?,
        severity: anomaly_severity_from_str(&row.get::<_, String>(4)?)?,
        description: row.get(5)?,
        evidence,
        detected_at: DateTime::<Utc>::from_timestamp(detected_at, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(detected_at, 0).single().unwrap()),
        auto_escalated: row.get::<_, i32>(8)? != 0,
        tribunal_case_id: row
            .get::<_, Option<String>>(9)?
            .and_then(|s| Uuid::parse_str(&s).ok()),
    })
}

fn row_to_penalty(row: &rusqlite::Row<'_>) -> Result<PoWPenalty> {
    let applied_at: i64 = row.get(4)?;
    let expires_at: Option<i64> = row.get(5)?;
    let reason_str: String = row.get(2)?;

    Ok(PoWPenalty {
        id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
        host_did: row.get(1)?,
        reason: penalty_reason_from_str(&reason_str)?,
        additional_bits: row.get::<_, i64>(3)? as u32,
        applied_at: DateTime::<Utc>::from_timestamp(applied_at, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(applied_at, 0).single().unwrap()),
        expires_at: expires_at.and_then(|ts| {
            DateTime::<Utc>::from_timestamp(ts, 0).or_else(|| Utc.timestamp_opt(ts, 0).single())
        }),
        anomaly_id: row
            .get::<_, Option<String>>(6)?
            .and_then(|s| Uuid::parse_str(&s).ok()),
        tribunal_case_id: row
            .get::<_, Option<String>>(7)?
            .and_then(|s| Uuid::parse_str(&s).ok()),
    })
}

fn row_to_attestation(row: &rusqlite::Row<'_>) -> Result<crate::types::Attestation> {
    let attested_at: i64 = row.get(6)?;
    let verdict_str: String = row.get(3)?;
    let verdict = match verdict_str.as_str() {
        "confirmed" => crate::types::AttestationVerdict::Confirmed,
        "disputed" => crate::types::AttestationVerdict::Disputed,
        "soft_fail" => crate::types::AttestationVerdict::SoftFail,
        _ => crate::types::AttestationVerdict::Confirmed,
    };

    Ok(crate::types::Attestation {
        id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_else(|_| Uuid::now_v7()),
        block_id: row.get(1)?,
        verifier_did: row.get(2)?,
        verdict,
        fuel_delta: row.get(4)?,
        evidence_cid: row.get(5)?,
        attested_at: DateTime::<Utc>::from_timestamp(attested_at, 0)
            .unwrap_or_else(|| Utc.timestamp_opt(attested_at, 0).single().unwrap()),
        signature: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scratch directory that removes itself, so tests never depend on a
    /// tempfile dev-dependency the workspace does not carry.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("jig_ns_sqlite_{}", Uuid::now_v7()));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn db_path(&self) -> PathBuf {
            self.0.join("names.db")
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn column_names(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .expect("prepare pragma");
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query pragma");
        rows.map(|r| r.expect("column name")).collect()
    }

    #[test]
    fn init_succeeds_on_fresh_db_and_is_idempotent() {
        let scratch = ScratchDir::new();
        SqliteStorage::new(scratch.db_path()).expect("first init on a fresh database");
        SqliteStorage::new(scratch.db_path()).expect("re-init over an existing database");
    }

    /// The two penalty systems are distinct schemas that both must survive
    /// migration; a careless rename silently rewires one onto the other.
    #[test]
    fn legacy_and_pow_penalty_tables_keep_distinct_schemas() {
        let scratch = ScratchDir::new();
        SqliteStorage::new(scratch.db_path()).expect("init");
        let conn = Connection::open(scratch.db_path()).expect("open db");

        let legacy = column_names(&conn, "penalties");
        assert!(
            legacy.iter().any(|c| c == "key") && legacy.iter().any(|c| c == "points"),
            "legacy `penalties` must keep its key/points shape, got {legacy:?}"
        );
        assert!(
            !legacy.iter().any(|c| c == "host_did"),
            "legacy `penalties` must not carry the PoW shape, got {legacy:?}"
        );

        let pow = column_names(&conn, "pow_penalties");
        assert!(
            pow.iter().any(|c| c == "host_did") && pow.iter().any(|c| c == "additional_bits"),
            "`pow_penalties` must carry the Phase-D shape, got {pow:?}"
        );
        assert!(
            !pow.iter().any(|c| c == "points"),
            "`pow_penalties` must not carry the legacy shape, got {pow:?}"
        );
    }

    #[tokio::test]
    async fn pow_penalty_round_trip_against_file_backed_store() {
        let scratch = ScratchDir::new();
        let store = SqliteStorage::new(scratch.db_path()).expect("init");

        let penalty = PoWPenalty {
            id: Uuid::now_v7(),
            host_did: "did:key:zPenaltyHost".to_string(),
            reason: PenaltyReason::ManualOverride,
            additional_bits: 4,
            applied_at: Utc::now(),
            expires_at: None,
            anomaly_id: None,
            tribunal_case_id: None,
        };

        store.apply_penalty(penalty.clone()).await.expect("apply");

        let active = store
            .get_active_penalties(&penalty.host_did)
            .await
            .expect("get active");
        assert_eq!(active.len(), 1, "expected the applied penalty back");
        assert_eq!(active[0].id, penalty.id);
        assert_eq!(active[0].additional_bits, 4);
        assert_eq!(
            store
                .get_total_penalty_bits(&penalty.host_did)
                .await
                .expect("total bits"),
            4
        );

        store.lift_penalty(penalty.id).await.expect("lift");
        assert!(
            store
                .get_active_penalties(&penalty.host_did)
                .await
                .expect("get active after lift")
                .is_empty(),
            "lifted penalty must not remain active"
        );
    }

    /// The legacy points API must keep working off its own table.
    #[tokio::test]
    async fn legacy_penalty_points_round_trip() {
        let scratch = ScratchDir::new();
        let store = SqliteStorage::new(scratch.db_path()).expect("init");

        store.add_penalty("ip:203.0.113.7", 3).await.expect("add");
        assert_eq!(
            store
                .get_penalty_points("ip:203.0.113.7", 0)
                .await
                .expect("points"),
            3
        );

        store.reset_penalty("ip:203.0.113.7").await.expect("reset");
        assert_eq!(
            store
                .get_penalty_points("ip:203.0.113.7", 0)
                .await
                .expect("points after reset"),
            0
        );
    }
}
