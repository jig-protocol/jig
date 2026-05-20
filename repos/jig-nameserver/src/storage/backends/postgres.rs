//! Postgres storage backend adapter (Tier 2)
//!
//! Implements NamesStorage trait using PostgreSQL for ACID transactions,
//! vertical scaling, and better query performance than SQLite.

#[cfg(feature = "tier2-storage")]
use crate::error::{NameServerError, Result};
#[cfg(feature = "tier2-storage")]
use crate::storage::NamesStorage;
#[cfg(feature = "tier2-storage")]
use crate::types::*;
#[cfg(feature = "tier2-storage")]
use async_trait::async_trait;

#[cfg(feature = "tier2-storage")]
use sqlx::PgPool;

#[cfg(feature = "tier2-storage")]
/// Postgres storage backend - implements NamesStorage with PostgreSQL
pub struct PostgresStorage {
    pool: PgPool,
}

#[cfg(feature = "tier2-storage")]
impl PostgresStorage {
    pub async fn new(connection_string: String, _pool_size: usize) -> Result<Self> {
        // Initialize connection pool
        let pool = PgPool::connect(&connection_string).await.map_err(|e| {
            NameServerError::Other(anyhow::anyhow!("Failed to connect to Postgres: {}", e))
        })?;

        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> Result<()> {
        // Create tables matching actual Jig types (IdentityRecord, LocalAlias, PowChallenge)
        sqlx::query(
            "
            CREATE TABLE IF NOT EXISTS identities (
                handle TEXT PRIMARY KEY,
                key BYTEA NOT NULL,
                display_name TEXT,
                updated_at TIMESTAMPTZ NOT NULL
            );

            CREATE TABLE IF NOT EXISTS aliases (
                alias TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                subject_handle TEXT,
                issued_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pow_challenges (
                id UUID PRIMARY KEY,
                action TEXT NOT NULL,
                subject_handle TEXT,
                scope TEXT,
                difficulty SMALLINT NOT NULL,
                issued_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                used BOOLEAN NOT NULL DEFAULT FALSE
            );

            CREATE TABLE IF NOT EXISTS receipts (
                receipt_cid TEXT PRIMARY KEY,
                identity_cid TEXT NOT NULL,
                runtime_cid TEXT,
                payload_cid TEXT,
                signature TEXT NOT NULL,
                executed_at BIGINT NOT NULL,
                fuel_used INTEGER,
                outcome TEXT
            );

            CREATE TABLE IF NOT EXISTS anomalies (
                id SERIAL PRIMARY KEY,
                receipt_cid TEXT NOT NULL,
                detected_at BIGINT NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                escalated BOOLEAN NOT NULL DEFAULT FALSE
            );

            CREATE TABLE IF NOT EXISTS penalties (
                id SERIAL PRIMARY KEY,
                identity_cid TEXT NOT NULL,
                applied_at BIGINT NOT NULL,
                reason TEXT NOT NULL,
                penalty_bits INTEGER NOT NULL,
                expires_at BIGINT
            );

            CREATE TABLE IF NOT EXISTS useful_work (
                task_id TEXT PRIMARY KEY,
                identity_cid TEXT NOT NULL,
                status TEXT NOT NULL,
                priority INTEGER NOT NULL,
                created_at BIGINT NOT NULL,
                claimed_at BIGINT,
                completed_at BIGINT
            );
            ",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("Failed to run migrations: {}", e)))?;

        Ok(())
    }
}

#[cfg(feature = "tier2-storage")]
#[async_trait]
impl NamesStorage for PostgresStorage {
    async fn upsert_identity(&self, record: IdentityRecord) -> Result<()> {
        // Extract fields from nested types
        let handle_str = &record.handle.handle;
        let key_bytes = &record.key.0[..]; // Convert [u8; 32] to &[u8]

        sqlx::query(
            "INSERT INTO identities (handle, key, display_name, updated_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (handle) DO UPDATE SET
                key = EXCLUDED.key,
                display_name = EXCLUDED.display_name,
                updated_at = EXCLUDED.updated_at",
        )
        .bind(handle_str)
        .bind(key_bytes)
        .bind(&record.display_name)
        .bind(&record.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("Failed to upsert identity: {}", e)))?;

        Ok(())
    }

    async fn get_identity(&self, handle: &str) -> Result<Option<IdentityRecord>> {
        let row = sqlx::query_as::<
            _,
            (
                String,
                Vec<u8>,
                Option<String>,
                chrono::DateTime<chrono::Utc>,
            ),
        >(
            "SELECT handle, key, display_name, updated_at FROM identities WHERE handle = $1",
        )
        .bind(handle)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("Failed to get identity: {}", e)))?;

        Ok(
            row.map(|(handle_str, key_bytes, display_name, updated_at)| {
                // Convert Vec<u8> back to [u8; 32]
                let mut key_array = [0u8; 32];
                if key_bytes.len() == 32 {
                    key_array.copy_from_slice(&key_bytes);
                }

                IdentityRecord {
                    handle: IdentityHandle { handle: handle_str },
                    key: PublicKeyEd25519(key_array),
                    display_name,
                    updated_at,
                }
            }),
        )
    }

    async fn put_alias(&self, alias: LocalAlias) -> Result<()> {
        // Extract subject handle if present
        let subject_handle = alias.subject.as_ref().map(|h| h.handle.as_str());

        sqlx::query(
            "INSERT INTO aliases (alias, scope, subject_handle, issued_at, expires_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&alias.alias)
        .bind(&alias.scope)
        .bind(subject_handle)
        .bind(&alias.issued_at)
        .bind(&alias.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("Failed to put alias: {}", e)))?;

        Ok(())
    }

    async fn get_alias(&self, alias: &str) -> Result<Option<LocalAlias>> {
        let row = sqlx::query_as::<_, (String, String, Option<String>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>(
            "SELECT alias, scope, subject_handle, issued_at, expires_at FROM aliases WHERE alias = $1",
        )
        .bind(alias)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("Failed to get alias: {}", e)))?;

        Ok(row.map(
            |(alias, scope, subject_handle, issued_at, expires_at)| LocalAlias {
                alias,
                scope,
                subject: subject_handle.map(|h| IdentityHandle { handle: h }),
                issued_at,
                expires_at,
            },
        ))
    }

    async fn reap_expired(&self) -> Result<()> {
        let now = chrono::Utc::now();
        sqlx::query("DELETE FROM aliases WHERE expires_at < $1")
            .bind(&now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("Failed to reap expired: {}", e))
            })?;

        Ok(())
    }

    async fn create_challenge(&self, ch: PowChallenge) -> Result<()> {
        // Extract subject handle if present
        let subject_handle = ch.subject.as_ref().map(|h| h.handle.as_str());

        sqlx::query(
            "INSERT INTO pow_challenges (id, action, subject_handle, scope, difficulty, issued_at, expires_at, used)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(ch.id)
        .bind(&ch.action)
        .bind(subject_handle)
        .bind(&ch.scope)
        .bind(ch.difficulty as i16)
        .bind(&ch.issued_at)
        .bind(&ch.expires_at)
        .bind(ch.used)
        .execute(&self.pool)
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("Failed to create challenge: {}", e)))?;

        Ok(())
    }

    async fn get_challenge(&self, id: uuid::Uuid) -> Result<Option<PowChallenge>> {
        let row = sqlx::query_as::<_, (uuid::Uuid, String, Option<String>, Option<String>, i16, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>, bool)>(
            "SELECT id, action, subject_handle, scope, difficulty, issued_at, expires_at, used FROM pow_challenges WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| NameServerError::Other(anyhow::anyhow!("Failed to get challenge: {}", e)))?;

        Ok(row.map(
            |(id, action, subject_handle, scope, difficulty, issued_at, expires_at, used)| {
                PowChallenge {
                    id,
                    action,
                    subject: subject_handle.map(|h| IdentityHandle { handle: h }),
                    scope,
                    difficulty: difficulty as u16,
                    issued_at,
                    expires_at,
                    used,
                }
            },
        ))
    }

    async fn mark_challenge_used(&self, id: uuid::Uuid) -> Result<()> {
        sqlx::query("UPDATE pow_challenges SET used = TRUE WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                NameServerError::Other(anyhow::anyhow!("Failed to mark challenge used: {}", e))
            })?;

        Ok(())
    }

    async fn cache_identity(
        &self,
        _record: IdentityRecord,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_cached_identity(&self, _handle: &str) -> Result<Option<IdentityRecord>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn rate_check_and_increment(&self, _key: &str, _limit_per_min: u32) -> Result<bool> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn add_penalty(&self, _key: &str, _amount: u32) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_penalty_points(&self, _key: &str, _decay_secs: i64) -> Result<u32> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn reset_penalty(&self, _key: &str) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_rate_info(&self, _key: &str) -> Result<Option<(i64, u32)>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn reset_rate(&self, _key: &str) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn upsert_reputation(&self, _score: ReputationScore) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_reputation(
        &self,
        _subject: ReputationSubject,
        _subject_id: &str,
        _ruleset: &str,
    ) -> Result<Option<ReputationScore>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_reputation(
        &self,
        _subject: ReputationSubject,
        _subject_id: &str,
    ) -> Result<Vec<ReputationScore>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn add_reputation_observation(&self, _obs: ReputationObservation) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_reputation_observations(
        &self,
        _subject: ReputationSubject,
        _subject_id: &str,
        _ruleset: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<ReputationObservation>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn purge_expired_observations(&self, _now: chrono::DateTime<chrono::Utc>) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn create_tribunal_case(&self, _case: TribunalCase) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn update_tribunal_case_status(
        &self,
        _id: uuid::Uuid,
        _status: TribunalStatus,
        _updated_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_tribunal_case(&self, _id: uuid::Uuid) -> Result<Option<TribunalCase>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_tribunal_cases(
        &self,
        _status: Option<TribunalStatus>,
        _limit: usize,
    ) -> Result<Vec<TribunalCase>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn append_tribunal_decision(&self, _decision: TribunalDecision) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_tribunal_decisions(&self, _case_id: uuid::Uuid) -> Result<Vec<TribunalDecision>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn store_tribunal_decision_block(&self, _block: TribunalDecisionBlock) -> Result<String> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_tribunal_decision_block(
        &self,
        _cid: &str,
    ) -> Result<Option<TribunalDecisionBlock>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn enqueue_useful_work(&self, _assignment: UsefulWorkAssignment) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn claim_useful_work(
        &self,
        _worker: &str,
        _limit: usize,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<UsefulWorkAssignment>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn complete_useful_work(&self, _result: UsefulWorkResult) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_useful_work(&self, _id: uuid::Uuid) -> Result<Option<UsefulWorkAssignment>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn useful_work_queue_depth(&self) -> Result<usize> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn useful_work_inflight(&self, _worker: &str) -> Result<usize> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn append_transparency_log(&self, _entry: TransparencyLogEntry) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_transparency_log(
        &self,
        _start: Option<chrono::DateTime<chrono::Utc>>,
        _end: Option<chrono::DateTime<chrono::Utc>>,
        _event_kind: Option<TransparencyLogEventKind>,
        _limit: usize,
    ) -> Result<Vec<TransparencyLogEntry>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn store_transparency_hash(&self, _hash: TransparencyLogHash) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_latest_transparency_hash(&self) -> Result<Option<TransparencyLogHash>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_transparency_hashes(&self, _limit: usize) -> Result<Vec<TransparencyLogHash>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn upsert_federation_peer(&self, _peer: FederationPeer) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_federation_peer(&self, _domain: &str) -> Result<Option<FederationPeer>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_federation_peers(&self, _limit: usize) -> Result<Vec<FederationPeer>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn update_peer_status(
        &self,
        _domain: &str,
        _status: FederationPeerStatus,
        _last_seen: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn store_gossip_message(&self, _message: GossipMessage) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_gossip_messages(
        &self,
        _kind: Option<GossipMessageKind>,
        _limit: usize,
    ) -> Result<Vec<GossipMessage>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn store_policy_hash(&self, _policy: PolicyHashExchange) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_policy_hash(&self, _domain: &str) -> Result<Option<PolicyHashExchange>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_policy_hashes(&self, _limit: usize) -> Result<Vec<PolicyHashExchange>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn store_receipt(&self, _receipt: jig_core::BlockReceipt) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_receipt(&self, _block_id: &str) -> Result<Option<jig_core::BlockReceipt>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_receipts(
        &self,
        _host_did: Option<&str>,
        _outcome_status: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<jig_core::BlockReceipt>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn store_attestation(&self, _attestation: Attestation) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_attestations(&self, _block_id: &str) -> Result<Vec<Attestation>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn list_attestations(
        &self,
        _verifier_did: Option<&str>,
        _verdict: Option<AttestationVerdict>,
        _limit: usize,
    ) -> Result<Vec<Attestation>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn store_anomaly(&self, _anomaly: ReceiptAnomaly) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_anomalies_for_block(&self, _block_id: &str) -> Result<Vec<ReceiptAnomaly>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_anomalies_for_host(
        &self,
        _host_did: &str,
        _kind: Option<AnomalyKind>,
        _severity: Option<AnomalySeverity>,
        _limit: usize,
    ) -> Result<Vec<ReceiptAnomaly>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn count_recent_anomalies(
        &self,
        _host_did: &str,
        _kind: AnomalyKind,
        _since: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn apply_penalty(&self, _penalty: PoWPenalty) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_active_penalties(&self, _host_did: &str) -> Result<Vec<PoWPenalty>> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn lift_penalty(&self, _penalty_id: uuid::Uuid) -> Result<()> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }

    async fn get_total_penalty_bits(&self, _host_did: &str) -> Result<u32> {
        Err(NameServerError::Other(anyhow::anyhow!(
            "Postgres backend not yet implemented"
        )))
    }
}

// Placeholder stubs for non-tier2 builds
#[cfg(not(feature = "tier2-storage"))]
pub struct PostgresStorage;

#[cfg(not(feature = "tier2-storage"))]
impl PostgresStorage {
    pub async fn new(_connection_string: String, _pool_size: usize) -> crate::error::Result<Self> {
        Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "Postgres backend requires tier2-storage feature"
        )))
    }

    pub async fn run_migrations(&self) -> crate::error::Result<()> {
        Err(crate::error::NameServerError::Other(anyhow::anyhow!(
            "Postgres backend requires tier2-storage feature"
        )))
    }
}
