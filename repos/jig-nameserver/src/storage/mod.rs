//! Storage for identities, claims, and aliases

use crate::error::Result;
use crate::types::{
    AnomalyKind, AnomalySeverity, FederationPeer, FederationPeerStatus, GossipMessage,
    GossipMessageKind, IdentityRecord, LocalAlias, PoWPenalty, PolicyHashExchange, PowChallenge,
    ReceiptAnomaly, ReputationObservation, ReputationScore, ReputationSubject,
    TransparencyLogEntry, TransparencyLogEventKind, TransparencyLogHash, TribunalCase,
    TribunalDecision, TribunalDecisionBlock, TribunalStatus, UsefulWorkAssignment,
    UsefulWorkResult, UsefulWorkStatus,
};
use async_trait::async_trait;
use chrono::Utc;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub mod backends;
pub mod sqlite;
pub use sqlite::SqliteStorage;

// Re-export backend factory function for convenience
pub use backends::create_storage_backend;

#[async_trait]
pub trait NamesStorage: Send + Sync + 'static {
    async fn upsert_identity(&self, record: IdentityRecord) -> Result<()>;
    async fn get_identity(&self, handle: &str) -> Result<Option<IdentityRecord>>;

    async fn put_alias(&self, alias: LocalAlias) -> Result<()>;
    async fn get_alias(&self, alias: &str) -> Result<Option<LocalAlias>>;
    async fn reap_expired(&self) -> Result<()>;

    // PoW challenges
    async fn create_challenge(&self, ch: PowChallenge) -> Result<()>;
    async fn get_challenge(&self, id: Uuid) -> Result<Option<PowChallenge>>;
    async fn mark_challenge_used(&self, id: Uuid) -> Result<()>;

    // Federation cache for identity records
    async fn cache_identity(
        &self,
        record: IdentityRecord,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<()>;
    async fn get_cached_identity(&self, handle: &str) -> Result<Option<IdentityRecord>>;

    // Rate limiting and penalties
    async fn rate_check_and_increment(&self, key: &str, limit_per_min: u32) -> Result<bool>;
    async fn add_penalty(&self, key: &str, amount: u32) -> Result<()>;
    async fn get_penalty_points(&self, key: &str, decay_secs: i64) -> Result<u32>;
    async fn reset_penalty(&self, key: &str) -> Result<()>;
    async fn get_rate_info(&self, key: &str) -> Result<Option<(i64, u32)>>;
    async fn reset_rate(&self, key: &str) -> Result<()>;

    // Reputation per ruleset
    async fn upsert_reputation(&self, score: ReputationScore) -> Result<()>;
    async fn get_reputation(
        &self,
        subject: ReputationSubject,
        subject_id: &str,
        ruleset: &str,
    ) -> Result<Option<ReputationScore>>;
    async fn list_reputation(
        &self,
        subject: ReputationSubject,
        subject_id: &str,
    ) -> Result<Vec<ReputationScore>>;
    async fn add_reputation_observation(&self, obs: ReputationObservation) -> Result<()>;
    async fn list_reputation_observations(
        &self,
        subject: ReputationSubject,
        subject_id: &str,
        ruleset: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ReputationObservation>>;
    async fn purge_expired_observations(&self, now: chrono::DateTime<Utc>) -> Result<()>;

    async fn create_tribunal_case(&self, case: TribunalCase) -> Result<()>;
    async fn update_tribunal_case_status(
        &self,
        id: Uuid,
        status: TribunalStatus,
        updated_at: chrono::DateTime<Utc>,
    ) -> Result<()>;
    async fn get_tribunal_case(&self, id: Uuid) -> Result<Option<TribunalCase>>;
    async fn list_tribunal_cases(
        &self,
        status: Option<TribunalStatus>,
        limit: usize,
    ) -> Result<Vec<TribunalCase>>;
    async fn append_tribunal_decision(&self, decision: TribunalDecision) -> Result<()>;
    async fn list_tribunal_decisions(&self, case_id: Uuid) -> Result<Vec<TribunalDecision>>;

    // Phase C: Tribunal decision blocks (content-addressed)
    async fn store_tribunal_decision_block(&self, block: TribunalDecisionBlock) -> Result<String>;
    async fn get_tribunal_decision_block(&self, cid: &str)
    -> Result<Option<TribunalDecisionBlock>>;

    async fn enqueue_useful_work(&self, assignment: UsefulWorkAssignment) -> Result<()>;
    async fn claim_useful_work(
        &self,
        worker: &str,
        limit: usize,
        now: chrono::DateTime<Utc>,
    ) -> Result<Vec<UsefulWorkAssignment>>;
    async fn complete_useful_work(&self, result: UsefulWorkResult) -> Result<()>;
    async fn get_useful_work(&self, id: Uuid) -> Result<Option<UsefulWorkAssignment>>;
    async fn useful_work_queue_depth(&self) -> Result<usize>;
    async fn useful_work_inflight(&self, worker: &str) -> Result<usize>;

    async fn append_transparency_log(&self, entry: TransparencyLogEntry) -> Result<()>;
    async fn list_transparency_log(
        &self,
        start: Option<chrono::DateTime<Utc>>,
        end: Option<chrono::DateTime<Utc>>,
        event_kind: Option<TransparencyLogEventKind>,
        limit: usize,
    ) -> Result<Vec<TransparencyLogEntry>>;
    async fn store_transparency_hash(&self, hash: TransparencyLogHash) -> Result<()>;
    async fn get_latest_transparency_hash(&self) -> Result<Option<TransparencyLogHash>>;
    async fn list_transparency_hashes(&self, limit: usize) -> Result<Vec<TransparencyLogHash>>;

    // Federation peers and gossip
    async fn upsert_federation_peer(&self, peer: crate::types::FederationPeer) -> Result<()>;
    async fn get_federation_peer(
        &self,
        domain: &str,
    ) -> Result<Option<crate::types::FederationPeer>>;
    async fn list_federation_peers(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::types::FederationPeer>>;
    async fn update_peer_status(
        &self,
        domain: &str,
        status: crate::types::FederationPeerStatus,
        last_seen: chrono::DateTime<Utc>,
    ) -> Result<()>;

    async fn store_gossip_message(&self, message: crate::types::GossipMessage) -> Result<()>;
    async fn list_gossip_messages(
        &self,
        kind: Option<crate::types::GossipMessageKind>,
        limit: usize,
    ) -> Result<Vec<crate::types::GossipMessage>>;

    async fn store_policy_hash(&self, policy: crate::types::PolicyHashExchange) -> Result<()>;
    async fn get_policy_hash(
        &self,
        domain: &str,
    ) -> Result<Option<crate::types::PolicyHashExchange>>;
    async fn list_policy_hashes(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::types::PolicyHashExchange>>;

    // Receipt storage (Phase A)
    async fn store_receipt(&self, receipt: jig_core::BlockReceipt) -> Result<()>;
    async fn get_receipt(&self, block_id: &str) -> Result<Option<jig_core::BlockReceipt>>;
    async fn list_receipts(
        &self,
        host_did: Option<&str>,
        outcome_status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<jig_core::BlockReceipt>>;

    // Attestation storage (Phase B)
    async fn store_attestation(&self, attestation: crate::types::Attestation) -> Result<()>;
    async fn get_attestations(&self, block_id: &str) -> Result<Vec<crate::types::Attestation>>;
    async fn list_attestations(
        &self,
        verifier_did: Option<&str>,
        verdict: Option<crate::types::AttestationVerdict>,
        limit: usize,
    ) -> Result<Vec<crate::types::Attestation>>;

    // Anomaly storage (Phase D)
    async fn store_anomaly(&self, anomaly: ReceiptAnomaly) -> Result<()>;
    async fn get_anomalies_for_block(&self, block_id: &str) -> Result<Vec<ReceiptAnomaly>>;
    async fn get_anomalies_for_host(
        &self,
        host_did: &str,
        kind: Option<AnomalyKind>,
        severity: Option<AnomalySeverity>,
        limit: usize,
    ) -> Result<Vec<ReceiptAnomaly>>;
    async fn count_recent_anomalies(
        &self,
        host_did: &str,
        kind: AnomalyKind,
        since: chrono::DateTime<Utc>,
    ) -> Result<usize>;

    // Penalty storage (Phase D)
    async fn apply_penalty(&self, penalty: PoWPenalty) -> Result<()>;
    async fn get_active_penalties(&self, host_did: &str) -> Result<Vec<PoWPenalty>>;
    async fn lift_penalty(&self, penalty_id: Uuid) -> Result<()>;
    async fn get_total_penalty_bits(&self, host_did: &str) -> Result<u32>;
}

// Type aliases to reduce complexity
type IdentityCacheEntry = (IdentityRecord, chrono::DateTime<Utc>);
type ReputationKey = (ReputationSubject, String, String);

/// Simple in-memory storage suitable for tests and dev
#[derive(Default, Clone)]
pub struct MemoryStorage {
    identities: Arc<RwLock<HashMap<String, IdentityRecord>>>,
    aliases: Arc<RwLock<HashMap<String, LocalAlias>>>,
    challenges: Arc<RwLock<HashMap<Uuid, PowChallenge>>>,
    cache: Arc<RwLock<HashMap<String, IdentityCacheEntry>>>,
    rate: Arc<RwLock<HashMap<String, (i64, u32)>>>,
    penalties: Arc<RwLock<HashMap<String, (u32, i64)>>>, // Old penalty system (legacy)
    pow_penalties: Arc<RwLock<Vec<PoWPenalty>>>,         // Phase D: New PoW penalty system
    reputation: Arc<RwLock<HashMap<ReputationKey, ReputationScore>>>,
    observations: Arc<RwLock<Vec<ReputationObservation>>>,
    tribunal_cases: Arc<RwLock<HashMap<Uuid, TribunalCase>>>,
    tribunal_decisions: Arc<RwLock<HashMap<Uuid, Vec<TribunalDecision>>>>,
    tribunal_decision_blocks: Arc<RwLock<HashMap<String, TribunalDecisionBlock>>>, // Phase C: CID -> Block
    useful_work: Arc<RwLock<HashMap<Uuid, UsefulWorkAssignment>>>,
    useful_work_results: Arc<RwLock<HashMap<Uuid, UsefulWorkResult>>>,
    transparency_log: Arc<RwLock<Vec<TransparencyLogEntry>>>,
    transparency_hashes: Arc<RwLock<Vec<TransparencyLogHash>>>,
    federation_peers: Arc<RwLock<HashMap<String, FederationPeer>>>,
    gossip_messages: Arc<RwLock<Vec<GossipMessage>>>,
    policy_hashes: Arc<RwLock<HashMap<String, PolicyHashExchange>>>,
    receipts: Arc<RwLock<HashMap<String, jig_core::BlockReceipt>>>,
    attestations: Arc<RwLock<Vec<crate::types::Attestation>>>,
    anomalies: Arc<RwLock<Vec<ReceiptAnomaly>>>, // Phase D: Receipt anomalies
}

#[async_trait]
impl NamesStorage for MemoryStorage {
    async fn upsert_identity(&self, record: IdentityRecord) -> Result<()> {
        let mut map = self.identities.write().await;
        map.insert(record.handle.handle.clone(), record);
        Ok(())
    }

    async fn get_identity(&self, handle: &str) -> Result<Option<IdentityRecord>> {
        let map = self.identities.read().await;
        Ok(map.get(handle).cloned())
    }

    async fn put_alias(&self, alias: LocalAlias) -> Result<()> {
        let mut map = self.aliases.write().await;
        map.insert(alias.alias.clone(), alias);
        Ok(())
    }

    async fn get_alias(&self, alias: &str) -> Result<Option<LocalAlias>> {
        let map = self.aliases.read().await;
        Ok(map.get(alias).cloned())
    }

    async fn reap_expired(&self) -> Result<()> {
        let mut map = self.aliases.write().await;
        let now = Utc::now();
        map.retain(|_, a| a.expires_at > now);
        Ok(())
    }

    async fn create_challenge(&self, ch: PowChallenge) -> Result<()> {
        let mut map = self.challenges.write().await;
        map.insert(ch.id, ch);
        Ok(())
    }

    async fn get_challenge(&self, id: Uuid) -> Result<Option<PowChallenge>> {
        let map = self.challenges.read().await;
        Ok(map.get(&id).cloned())
    }

    async fn mark_challenge_used(&self, id: Uuid) -> Result<()> {
        let mut map = self.challenges.write().await;
        if let Some(ch) = map.get_mut(&id) {
            ch.used = true;
        }
        Ok(())
    }

    async fn cache_identity(
        &self,
        record: IdentityRecord,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let mut map = self.cache.write().await;
        map.insert(record.handle.handle.clone(), (record, expires_at));
        Ok(())
    }

    async fn get_cached_identity(&self, handle: &str) -> Result<Option<IdentityRecord>> {
        let mut map = self.cache.write().await;
        if let Some((rec, exp)) = map.get(handle).cloned() {
            if exp > Utc::now() {
                return Ok(Some(rec));
            } else {
                map.remove(handle);
                return Ok(None);
            }
        }
        Ok(None)
    }

    async fn rate_check_and_increment(&self, key: &str, limit_per_min: u32) -> Result<bool> {
        let now_min = Utc::now().timestamp() / 60;
        let mut map = self.rate.write().await;
        let entry = map.entry(key.to_string()).or_insert((now_min, 0));
        if entry.0 != now_min {
            entry.0 = now_min;
            entry.1 = 0;
        }
        if entry.1 >= limit_per_min {
            return Ok(false);
        }
        entry.1 += 1;
        Ok(true)
    }

    async fn add_penalty(&self, key: &str, amount: u32) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut map = self.penalties.write().await;
        let ent = map.entry(key.to_string()).or_insert((0, now));
        ent.0 = ent.0.saturating_add(amount);
        ent.1 = now;
        Ok(())
    }

    async fn get_penalty_points(&self, key: &str, decay_secs: i64) -> Result<u32> {
        let now = Utc::now().timestamp();
        let mut map = self.penalties.write().await;
        if let Some((points, last)) = map.get_mut(key) {
            let elapsed = now - *last;
            if elapsed > 0 && decay_secs > 0 {
                let decay_steps = (elapsed / decay_secs) as u32;
                if decay_steps > 0 {
                    *points = points.saturating_sub(decay_steps);
                    *last = now;
                }
            }
            return Ok(*points);
        }
        Ok(0)
    }

    async fn reset_penalty(&self, key: &str) -> Result<()> {
        let mut map = self.penalties.write().await;
        map.remove(key);
        Ok(())
    }

    async fn get_rate_info(&self, key: &str) -> Result<Option<(i64, u32)>> {
        let map = self.rate.read().await;
        Ok(map.get(key).cloned())
    }

    async fn reset_rate(&self, key: &str) -> Result<()> {
        let mut map = self.rate.write().await;
        map.remove(key);
        Ok(())
    }

    async fn upsert_reputation(&self, score: ReputationScore) -> Result<()> {
        let mut map = self.reputation.write().await;
        map.insert(
            (
                score.subject.clone(),
                score.subject_id.clone(),
                score.ruleset.clone(),
            ),
            score,
        );
        Ok(())
    }

    async fn get_reputation(
        &self,
        subject: ReputationSubject,
        subject_id: &str,
        ruleset: &str,
    ) -> Result<Option<ReputationScore>> {
        let map = self.reputation.read().await;
        Ok(map
            .get(&(subject, subject_id.to_string(), ruleset.to_string()))
            .cloned())
    }

    async fn list_reputation(
        &self,
        subject: ReputationSubject,
        subject_id: &str,
    ) -> Result<Vec<ReputationScore>> {
        let map = self.reputation.read().await;
        Ok(map
            .iter()
            .filter_map(|((kind, id, _), score)| {
                if kind == &subject && id == subject_id {
                    Some(score.clone())
                } else {
                    None
                }
            })
            .collect())
    }

    async fn add_reputation_observation(&self, obs: ReputationObservation) -> Result<()> {
        let mut list = self.observations.write().await;
        list.push(obs);
        Ok(())
    }

    async fn list_reputation_observations(
        &self,
        subject: ReputationSubject,
        subject_id: &str,
        ruleset: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ReputationObservation>> {
        let list = self.observations.read().await;
        let mut filtered: Vec<_> = list
            .iter()
            .filter(|obs| {
                obs.subject == subject
                    && obs.subject_id == subject_id
                    && ruleset.map(|r| obs.ruleset == r).unwrap_or(true)
            })
            .cloned()
            .collect();
        filtered.sort_by_key(|obs| std::cmp::Reverse(obs.recorded_at));
        filtered.truncate(limit);
        Ok(filtered)
    }

    async fn purge_expired_observations(&self, now: chrono::DateTime<Utc>) -> Result<()> {
        let mut list = self.observations.write().await;
        list.retain(|obs| obs.expires_at.map(|exp| exp > now).unwrap_or(true));
        Ok(())
    }

    async fn create_tribunal_case(&self, case: TribunalCase) -> Result<()> {
        let mut cases = self.tribunal_cases.write().await;
        cases.insert(case.id, case);
        Ok(())
    }

    async fn update_tribunal_case_status(
        &self,
        id: Uuid,
        status: TribunalStatus,
        updated_at: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let mut cases = self.tribunal_cases.write().await;
        if let Some(existing) = cases.get_mut(&id) {
            existing.status = status;
            existing.updated_at = updated_at;
        }
        Ok(())
    }

    async fn get_tribunal_case(&self, id: Uuid) -> Result<Option<TribunalCase>> {
        let cases = self.tribunal_cases.read().await;
        Ok(cases.get(&id).cloned())
    }

    async fn list_tribunal_cases(
        &self,
        status: Option<TribunalStatus>,
        limit: usize,
    ) -> Result<Vec<TribunalCase>> {
        let cases = self.tribunal_cases.read().await;
        let mut items: Vec<_> = cases
            .values()
            .filter(|case| status.as_ref().map(|s| case.status == *s).unwrap_or(true))
            .cloned()
            .collect();
        items.sort_by_key(|case| std::cmp::Reverse(case.opened_at));
        items.truncate(limit);
        Ok(items)
    }

    async fn append_tribunal_decision(&self, decision: TribunalDecision) -> Result<()> {
        let mut map = self.tribunal_decisions.write().await;
        map.entry(decision.case_id)
            .or_insert_with(Vec::new)
            .push(decision);
        Ok(())
    }

    async fn list_tribunal_decisions(&self, case_id: Uuid) -> Result<Vec<TribunalDecision>> {
        let map = self.tribunal_decisions.read().await;
        Ok(map.get(&case_id).cloned().unwrap_or_default())
    }

    // Phase C: Tribunal decision blocks
    async fn store_tribunal_decision_block(&self, block: TribunalDecisionBlock) -> Result<String> {
        let cid = block
            .compute_cid()
            .map_err(|e| crate::error::NameServerError::Other(anyhow::anyhow!(e)))?;
        let mut map = self.tribunal_decision_blocks.write().await;
        map.insert(cid.clone(), block);
        Ok(cid)
    }

    async fn get_tribunal_decision_block(
        &self,
        cid: &str,
    ) -> Result<Option<TribunalDecisionBlock>> {
        let map = self.tribunal_decision_blocks.read().await;
        Ok(map.get(cid).cloned())
    }

    async fn enqueue_useful_work(&self, assignment: UsefulWorkAssignment) -> Result<()> {
        let mut map = self.useful_work.write().await;
        map.insert(assignment.id, assignment);
        Ok(())
    }

    async fn claim_useful_work(
        &self,
        worker: &str,
        limit: usize,
        now: chrono::DateTime<Utc>,
    ) -> Result<Vec<UsefulWorkAssignment>> {
        let mut map = self.useful_work.write().await;
        let mut candidates: Vec<_> = map
            .values_mut()
            .filter(|assignment| {
                assignment.status == UsefulWorkStatus::Queued && assignment.expires_at > now
            })
            .collect();
        candidates.sort_by_key(|assignment| (Reverse(assignment.priority), assignment.issued_at));

        let mut claimed = Vec::new();
        for assignment in candidates.into_iter() {
            if claimed.len() >= limit {
                break;
            }
            assignment.status = UsefulWorkStatus::InProgress;
            assignment.assigned_to = Some(worker.to_string());
            assignment.last_updated = now;
            claimed.push(assignment.clone());
        }
        Ok(claimed)
    }

    async fn complete_useful_work(&self, result: UsefulWorkResult) -> Result<()> {
        let mut map = self.useful_work.write().await;
        if let Some(assignment) = map.get_mut(&result.assignment_id) {
            assignment.status = result.status.clone();
            assignment.assigned_to = Some(result.worker.clone());
            assignment.last_updated = result.submitted_at;
        }
        let mut results = self.useful_work_results.write().await;
        results.insert(result.assignment_id, result);
        Ok(())
    }

    async fn get_useful_work(&self, id: Uuid) -> Result<Option<UsefulWorkAssignment>> {
        let map = self.useful_work.read().await;
        Ok(map.get(&id).cloned())
    }

    async fn useful_work_queue_depth(&self) -> Result<usize> {
        let map = self.useful_work.read().await;
        Ok(map
            .values()
            .filter(|assignment| {
                matches!(
                    assignment.status,
                    UsefulWorkStatus::Queued | UsefulWorkStatus::InProgress
                )
            })
            .count())
    }

    async fn useful_work_inflight(&self, worker: &str) -> Result<usize> {
        let map = self.useful_work.read().await;
        Ok(map
            .values()
            .filter(|assignment| {
                assignment.status == UsefulWorkStatus::InProgress
                    && assignment.assigned_to.as_deref() == Some(worker)
            })
            .count())
    }

    async fn append_transparency_log(&self, entry: TransparencyLogEntry) -> Result<()> {
        let mut log = self.transparency_log.write().await;
        log.push(entry);
        Ok(())
    }

    async fn list_transparency_log(
        &self,
        start: Option<chrono::DateTime<Utc>>,
        end: Option<chrono::DateTime<Utc>>,
        event_kind: Option<TransparencyLogEventKind>,
        limit: usize,
    ) -> Result<Vec<TransparencyLogEntry>> {
        let log = self.transparency_log.read().await;
        let mut entries: Vec<_> = log
            .iter()
            .filter(|e| {
                if let Some(s) = start
                    && e.recorded_at < s
                {
                    return false;
                }
                if let Some(end) = end
                    && e.recorded_at > end
                {
                    return false;
                }
                if let Some(ref kind) = event_kind
                    && &e.event_kind != kind
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        entries.sort_by_key(|e| e.recorded_at);
        entries.truncate(limit);
        Ok(entries)
    }

    async fn store_transparency_hash(&self, hash: TransparencyLogHash) -> Result<()> {
        let mut hashes = self.transparency_hashes.write().await;
        hashes.push(hash);
        Ok(())
    }

    async fn get_latest_transparency_hash(&self) -> Result<Option<TransparencyLogHash>> {
        let hashes = self.transparency_hashes.read().await;
        Ok(hashes.last().cloned())
    }

    async fn list_transparency_hashes(&self, limit: usize) -> Result<Vec<TransparencyLogHash>> {
        let hashes = self.transparency_hashes.read().await;
        let len = hashes.len();
        let start = len.saturating_sub(limit);
        Ok(hashes[start..].to_vec())
    }

    // Federation peers
    async fn upsert_federation_peer(&self, peer: FederationPeer) -> Result<()> {
        let mut peers = self.federation_peers.write().await;
        peers.insert(peer.domain.clone(), peer);
        Ok(())
    }

    async fn get_federation_peer(&self, domain: &str) -> Result<Option<FederationPeer>> {
        let peers = self.federation_peers.read().await;
        Ok(peers.get(domain).cloned())
    }

    async fn list_federation_peers(&self, limit: usize) -> Result<Vec<FederationPeer>> {
        let peers = self.federation_peers.read().await;
        Ok(peers.values().take(limit).cloned().collect())
    }

    async fn update_peer_status(
        &self,
        domain: &str,
        status: FederationPeerStatus,
        last_seen: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let mut peers = self.federation_peers.write().await;
        if let Some(peer) = peers.get_mut(domain) {
            peer.status = status;
            peer.last_seen_at = last_seen;
        }
        Ok(())
    }

    // Gossip messages
    async fn store_gossip_message(&self, message: GossipMessage) -> Result<()> {
        let mut messages = self.gossip_messages.write().await;
        messages.push(message);
        Ok(())
    }

    async fn list_gossip_messages(
        &self,
        kind: Option<GossipMessageKind>,
        limit: usize,
    ) -> Result<Vec<GossipMessage>> {
        let messages = self.gossip_messages.read().await;
        let filtered: Vec<_> = messages
            .iter()
            .filter(|m| kind.is_none() || kind.as_ref() == Some(&m.kind))
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }

    // Policy hashes
    async fn store_policy_hash(&self, policy: PolicyHashExchange) -> Result<()> {
        let mut policies = self.policy_hashes.write().await;
        policies.insert(policy.domain.clone(), policy);
        Ok(())
    }

    async fn get_policy_hash(&self, domain: &str) -> Result<Option<PolicyHashExchange>> {
        let policies = self.policy_hashes.read().await;
        Ok(policies.get(domain).cloned())
    }

    async fn list_policy_hashes(&self, limit: usize) -> Result<Vec<PolicyHashExchange>> {
        let policies = self.policy_hashes.read().await;
        Ok(policies.values().take(limit).cloned().collect())
    }

    // Receipt storage (Phase A)
    async fn store_receipt(&self, receipt: jig_core::BlockReceipt) -> Result<()> {
        let block_id = receipt.block_id.to_string();
        let mut receipts = self.receipts.write().await;
        receipts.insert(block_id, receipt);
        Ok(())
    }

    async fn get_receipt(&self, block_id: &str) -> Result<Option<jig_core::BlockReceipt>> {
        let receipts = self.receipts.read().await;
        Ok(receipts.get(block_id).cloned())
    }

    async fn list_receipts(
        &self,
        host_did: Option<&str>,
        outcome_status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<jig_core::BlockReceipt>> {
        let receipts = self.receipts.read().await;
        let mut filtered: Vec<_> = receipts
            .values()
            .filter(|r| {
                if let Some(host) = host_did
                    && r.host != host
                {
                    return false;
                }
                if let Some(status) = outcome_status {
                    if let Some(outcome) = &r.outcome {
                        let outcome_str = match outcome.status {
                            jig_core::OutcomeStatus::Ok => "ok",
                            jig_core::OutcomeStatus::SoftFail => "soft_fail",
                            jig_core::OutcomeStatus::HardFail => "hard_fail",
                        };
                        if outcome_str != status {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Sort by executed_at descending (most recent first)
        filtered.sort_by(|a, b| b.executed_at.cmp(&a.executed_at));
        filtered.truncate(limit);
        Ok(filtered)
    }

    // Attestation storage (Phase B)
    async fn store_attestation(&self, attestation: crate::types::Attestation) -> Result<()> {
        let mut map = self.attestations.write().await;
        map.push(attestation);
        Ok(())
    }

    async fn get_attestations(&self, block_id: &str) -> Result<Vec<crate::types::Attestation>> {
        let map = self.attestations.read().await;
        let results = map
            .iter()
            .filter(|a| a.block_id == block_id)
            .cloned()
            .collect();
        Ok(results)
    }

    async fn list_attestations(
        &self,
        verifier_did: Option<&str>,
        verdict: Option<crate::types::AttestationVerdict>,
        limit: usize,
    ) -> Result<Vec<crate::types::Attestation>> {
        let map = self.attestations.read().await;
        let mut filtered: Vec<crate::types::Attestation> = map
            .iter()
            .filter(|a| {
                if let Some(did) = verifier_did
                    && a.verifier_did != did
                {
                    return false;
                }
                if let Some(v) = &verdict
                    && &a.verdict != v
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        // Sort by attested_at descending (most recent first)
        filtered.sort_by(|a, b| b.attested_at.cmp(&a.attested_at));
        filtered.truncate(limit);
        Ok(filtered)
    }

    // Anomaly storage (Phase D)
    async fn store_anomaly(&self, anomaly: ReceiptAnomaly) -> Result<()> {
        let mut map = self.anomalies.write().await;
        map.push(anomaly);
        Ok(())
    }

    async fn get_anomalies_for_block(&self, block_id: &str) -> Result<Vec<ReceiptAnomaly>> {
        let map = self.anomalies.read().await;
        let results = map
            .iter()
            .filter(|a| a.block_id == block_id)
            .cloned()
            .collect();
        Ok(results)
    }

    async fn get_anomalies_for_host(
        &self,
        host_did: &str,
        kind: Option<AnomalyKind>,
        severity: Option<AnomalySeverity>,
        limit: usize,
    ) -> Result<Vec<ReceiptAnomaly>> {
        let map = self.anomalies.read().await;
        let mut filtered: Vec<ReceiptAnomaly> = map
            .iter()
            .filter(|a| {
                if a.host_did != host_did {
                    return false;
                }
                if let Some(ref k) = kind
                    && &a.kind != k
                {
                    return false;
                }
                if let Some(ref s) = severity
                    && &a.severity != s
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        // Sort by detected_at descending (most recent first)
        filtered.sort_by(|a, b| b.detected_at.cmp(&a.detected_at));
        filtered.truncate(limit);
        Ok(filtered)
    }

    async fn count_recent_anomalies(
        &self,
        host_did: &str,
        kind: AnomalyKind,
        since: chrono::DateTime<Utc>,
    ) -> Result<usize> {
        let map = self.anomalies.read().await;
        let count = map
            .iter()
            .filter(|a| a.host_did == host_did && a.kind == kind && a.detected_at >= since)
            .count();
        Ok(count)
    }

    async fn apply_penalty(&self, penalty: PoWPenalty) -> Result<()> {
        let mut map = self.pow_penalties.write().await;
        map.push(penalty);
        Ok(())
    }

    async fn get_active_penalties(&self, host_did: &str) -> Result<Vec<PoWPenalty>> {
        let map = self.pow_penalties.read().await;
        let now = Utc::now();
        let results = map
            .iter()
            .filter(|p| {
                p.host_did == host_did
                    && (p.expires_at.is_none()
                        || p.expires_at.map(|exp| exp > now).unwrap_or(false))
            })
            .cloned()
            .collect();
        Ok(results)
    }

    async fn lift_penalty(&self, penalty_id: Uuid) -> Result<()> {
        let mut map = self.pow_penalties.write().await;
        map.retain(|p| p.id != penalty_id);
        Ok(())
    }

    async fn get_total_penalty_bits(&self, host_did: &str) -> Result<u32> {
        let penalties = self.get_active_penalties(host_did).await?;
        let total: u32 = penalties.iter().map(|p| p.additional_bits).sum();
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IdentityHandle;
    use crate::types::*;

    #[tokio::test]
    async fn memory_storage_roundtrip() {
        let st = MemoryStorage::default();
        let id = IdentityRecord {
            handle: IdentityHandle {
                handle: "alice@example.com".into(),
            },
            key: PublicKeyEd25519([0u8; 32]),
            display_name: None,
            updated_at: Utc::now(),
        };
        st.upsert_identity(id.clone()).await.unwrap();
        let got = st.get_identity(&id.handle.handle).await.unwrap().unwrap();
        assert_eq!(got.handle.handle, id.handle.handle);

        st.add_penalty("alice", 3).await.unwrap();
        let pts = st.get_penalty_points("alice", 60).await.unwrap();
        assert_eq!(pts, 3);
        st.reset_penalty("alice").await.unwrap();
        let pts = st.get_penalty_points("alice", 60).await.unwrap();
        assert_eq!(pts, 0);

        let observation = ReputationObservation {
            id: Uuid::now_v7(),
            subject: ReputationSubject::User,
            subject_id: "alice@example.com".into(),
            ruleset: "high-sec".into(),
            observer: "ns-1".into(),
            score: 0.9,
            weight: 1.2,
            evidence: Some("auto-observation".into()),
            expires_at: Some(Utc::now() + chrono::Duration::minutes(10)),
            recorded_at: Utc::now(),
        };
        st.add_reputation_observation(observation.clone())
            .await
            .unwrap();
        let obs_list = st
            .list_reputation_observations(
                ReputationSubject::User,
                "alice@example.com",
                Some("high-sec"),
                10,
            )
            .await
            .unwrap();
        assert_eq!(obs_list.len(), 1);
        st.purge_expired_observations(Utc::now()).await.unwrap();

        let score = ReputationScore {
            subject: ReputationSubject::User,
            subject_id: "alice@example.com".into(),
            ruleset: "high-sec".into(),
            score: 0.8,
            weight: 1.0,
            updated_at: Utc::now(),
        };
        st.upsert_reputation(score.clone()).await.unwrap();
        let fetched = st
            .get_reputation(ReputationSubject::User, "alice@example.com", "high-sec")
            .await
            .unwrap()
            .unwrap();
        assert!((fetched.score - 0.8).abs() < f64::EPSILON);
        let list = st
            .list_reputation(ReputationSubject::User, "alice@example.com")
            .await
            .unwrap();
        assert_eq!(list.len(), 1);

        let case = TribunalCase {
            id: Uuid::now_v7(),
            subject: ReputationSubject::User,
            subject_id: "alice@example.com".into(),
            ruleset: "high-sec".into(),
            status: TribunalStatus::Open,
            reason: "suspicious activity".into(),
            reporter: "ns-1".into(),
            severity: Some("medium".into()),
            metadata: None,
            opened_at: Utc::now(),
            updated_at: Utc::now(),
        };
        st.create_tribunal_case(case.clone()).await.unwrap();
        let fetched_case = st.get_tribunal_case(case.id).await.unwrap().unwrap();
        assert_eq!(fetched_case.reason, "suspicious activity");

        let decision = TribunalDecision {
            id: Uuid::now_v7(),
            case_id: case.id,
            outcome: TribunalOutcome::Sustain,
            penalty_delta: Some(1.0),
            decided_by: "ns-1".into(),
            decided_at: Utc::now(),
            notes: Some("auto decision".into()),
        };
        st.append_tribunal_decision(decision.clone()).await.unwrap();
        st.update_tribunal_case_status(case.id, TribunalStatus::Resolved, Utc::now())
            .await
            .unwrap();
        let decisions = st.list_tribunal_decisions(case.id).await.unwrap();
        assert_eq!(decisions.len(), 1);
        let cases = st
            .list_tribunal_cases(Some(TribunalStatus::Resolved), 10)
            .await
            .unwrap();
        assert_eq!(cases.len(), 1);
    }

    // Phase C: Test tribunal decision blocks
    #[tokio::test]
    async fn tribunal_decision_block_storage() {
        let st = MemoryStorage::default();

        // Create a tribunal case and decision
        let case = TribunalCase {
            id: Uuid::now_v7(),
            subject: ReputationSubject::User,
            subject_id: "bob@example.com".into(),
            ruleset: "federation".into(),
            status: TribunalStatus::Open,
            reason: "spam".into(),
            reporter: "alice@example.com".into(),
            severity: Some("high".into()),
            metadata: None,
            opened_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let decision = TribunalDecision {
            id: Uuid::now_v7(),
            case_id: case.id,
            outcome: TribunalOutcome::Sustain,
            penalty_delta: Some(-15.0),
            decided_by: "tribunal@example.com".into(),
            decided_at: Utc::now(),
            notes: Some("Confirmed spam activity".into()),
        };

        // Create decision block from case and decision
        let block = TribunalDecisionBlock::from_decision_and_case(
            &decision,
            &case,
            Some("https://example.com/evidence/123".to_string()),
        );

        // Store the block and get CID
        let cid = st
            .store_tribunal_decision_block(block.clone())
            .await
            .unwrap();

        // Verify CID format
        assert_eq!(cid.len(), 64); // BLAKE3 hex is 64 chars

        // Retrieve the block by CID
        let retrieved = st
            .get_tribunal_decision_block(&cid)
            .await
            .unwrap()
            .expect("Block should exist");

        // Verify all fields match
        assert_eq!(retrieved.case_id, case.id);
        assert_eq!(retrieved.decision_id, decision.id);
        assert_eq!(retrieved.subject, ReputationSubject::User);
        assert_eq!(retrieved.subject_id, "bob@example.com");
        assert_eq!(retrieved.ruleset, "federation");
        assert_eq!(retrieved.outcome, TribunalOutcome::Sustain);
        assert_eq!(retrieved.penalty_delta, Some(-15.0));
        assert_eq!(
            retrieved.evidence,
            Some("https://example.com/evidence/123".to_string())
        );

        // Test retrieval of non-existent block
        let missing = st.get_tribunal_decision_block("nonexistent").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn useful_work_lifecycle() {
        let st = MemoryStorage::default();
        let now = Utc::now();

        // Create and enqueue work
        let assignment = UsefulWorkAssignment {
            id: Uuid::now_v7(),
            kind: UsefulWorkKind::ValidateBlock,
            subject: Some("block-123".into()),
            ruleset: Some("high-sec".into()),
            payload: serde_json::json!({"data": "test"}),
            assigned_to: None,
            status: UsefulWorkStatus::Queued,
            priority: 10,
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(600),
            last_updated: now,
        };

        st.enqueue_useful_work(assignment.clone()).await.unwrap();

        // Check queue depth
        let depth = st.useful_work_queue_depth().await.unwrap();
        assert_eq!(depth, 1);

        // Check inflight count for worker (should be 0)
        let inflight = st.useful_work_inflight("worker-1").await.unwrap();
        assert_eq!(inflight, 0);

        // Claim work
        let claimed = st.claim_useful_work("worker-1", 1, now).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].status, UsefulWorkStatus::InProgress);
        assert_eq!(claimed[0].assigned_to.as_deref(), Some("worker-1"));

        // Check inflight count for worker (should be 1)
        let inflight = st.useful_work_inflight("worker-1").await.unwrap();
        assert_eq!(inflight, 1);

        // Complete work
        let result = UsefulWorkResult {
            assignment_id: assignment.id,
            worker: "worker-1".into(),
            status: UsefulWorkStatus::Completed,
            output: serde_json::json!({"result": "success"}),
            metadata: serde_json::json!({"time_ms": 100}),
            submitted_at: now + chrono::Duration::seconds(5),
        };

        st.complete_useful_work(result).await.unwrap();

        // Fetch assignment and verify status updated
        let fetched = st.get_useful_work(assignment.id).await.unwrap().unwrap();
        assert_eq!(fetched.status, UsefulWorkStatus::Completed);

        // Queue depth should now count 0 (completed work not queued/in_progress)
        let depth = st.useful_work_queue_depth().await.unwrap();
        assert_eq!(depth, 0);
    }

    #[tokio::test]
    async fn useful_work_priority_ordering() {
        let st = MemoryStorage::default();
        let now = Utc::now();

        // Create multiple work items with different priorities
        let low_priority = UsefulWorkAssignment {
            id: Uuid::now_v7(),
            kind: UsefulWorkKind::Custom,
            subject: None,
            ruleset: None,
            payload: serde_json::Value::Null,
            assigned_to: None,
            status: UsefulWorkStatus::Queued,
            priority: 1,
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(600),
            last_updated: now,
        };

        let high_priority = UsefulWorkAssignment {
            id: Uuid::now_v7(),
            kind: UsefulWorkKind::AuditRuleset,
            subject: None,
            ruleset: None,
            payload: serde_json::Value::Null,
            assigned_to: None,
            status: UsefulWorkStatus::Queued,
            priority: 100,
            issued_at: now + chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::seconds(600),
            last_updated: now,
        };

        // Enqueue low priority first, then high priority
        st.enqueue_useful_work(low_priority.clone()).await.unwrap();
        st.enqueue_useful_work(high_priority.clone()).await.unwrap();

        // Claim work - should get high priority first
        let claimed = st.claim_useful_work("worker-1", 2, now).await.unwrap();
        assert_eq!(claimed.len(), 2);
        assert_eq!(claimed[0].priority, 100); // High priority first
        assert_eq!(claimed[1].priority, 1); // Low priority second
    }

    #[tokio::test]
    async fn useful_work_worker_limits() {
        let st = MemoryStorage::default();
        let now = Utc::now();

        // Create 5 work items
        for i in 0..5 {
            let assignment = UsefulWorkAssignment {
                id: Uuid::now_v7(),
                kind: UsefulWorkKind::VerifyObservation,
                subject: Some(format!("item-{i}")),
                ruleset: None,
                payload: serde_json::Value::Null,
                assigned_to: None,
                status: UsefulWorkStatus::Queued,
                priority: 0,
                issued_at: now,
                expires_at: now + chrono::Duration::seconds(600),
                last_updated: now,
            };
            st.enqueue_useful_work(assignment).await.unwrap();
        }

        // Claim 2 for worker-1
        let claimed = st.claim_useful_work("worker-1", 2, now).await.unwrap();
        assert_eq!(claimed.len(), 2);

        // Verify inflight count
        let inflight = st.useful_work_inflight("worker-1").await.unwrap();
        assert_eq!(inflight, 2);

        // Claim 3 for worker-2 (should get remaining 3)
        let claimed = st.claim_useful_work("worker-2", 10, now).await.unwrap();
        assert_eq!(claimed.len(), 3);

        // Verify worker-2 inflight count
        let inflight = st.useful_work_inflight("worker-2").await.unwrap();
        assert_eq!(inflight, 3);

        // Try to claim more for worker-1 (should get nothing as all work is assigned)
        let claimed = st.claim_useful_work("worker-1", 10, now).await.unwrap();
        assert_eq!(claimed.len(), 0);
    }
}
