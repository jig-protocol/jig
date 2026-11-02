//! Per-server authentication state, shared across every request.
//!
//! # Why this is `Arc`-wrapped in `AppState`
//!
//! `AppState` derives `Clone` and is cloned per request handler. The replay
//! guard must be **one** structure shared by every clone: it defends by
//! remembering nonces, and a guard that each clone owned privately would
//! remember nothing another clone had seen. A replayed request would land on a
//! clone with an empty set and be accepted.
//!
//! So `AppState` holds `Arc<AuthState>`, not `AuthState`. If a future change
//! makes this fail to compile, the fix is more `Arc`, **never** making
//! `ReplayGuard` cloneable — that would compile fine and silently disable
//! replay defence.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Context as _;

use jig_config::v0_0_2_server::{AdmissionSection, AuthSection, UnknownDidsPolicy};

use crate::auth::admission::{Floor, SeededRecords, UnknownDids};
use crate::auth::pools::{Pool, WritePools};
use crate::auth::rate::RateLimiter;
use crate::auth::{
    AdmissionPolicy, DisclosurePolicy, GateOutcome, ReplayGuard, ReputationSource, admit,
};

/// Authentication state owned by the server and shared by all requests.
pub struct AuthState {
    /// Replay defence for tier-0 requests.
    ///
    /// `Mutex` rather than `RwLock`: every check mutates by recording the
    /// nonce, so a read lock would never be taken and would only add a second
    /// locking discipline to reason about.
    pub replay_guard: Mutex<ReplayGuard>,
    /// How much of a refusal's truth this server discloses to the caller.
    pub disclosure: DisclosurePolicy,
    /// Gate 2: what the operator decided about whom to admit.
    pub admission: AdmissionPolicy,
    /// Gate 2: what this server knows about each DID. Seeded from config in
    /// this phase; the seam a ledger plugs into.
    pub reputation: Arc<dyn ReputationSource>,
    /// `[auth.rate_limit]` per verified DID; `None` when off.
    did_rate: Option<RateLimiter>,
    /// `[auth.rate_limit]` per remote address; `None` when off.
    ip_rate: Option<RateLimiter>,
    /// `[auth.pools]`: local write capacity shared by members, invited and
    /// strangers; `None` when off.
    write_pools: Option<WritePools>,
    /// `[auth.pools] local_member_age_secs`.
    local_member_age_secs: u64,
    /// Where admission proofs of work are recorded; `None` in a state built
    /// without a store, where no DID is ever proven.
    proofs: Option<Arc<jig_pipeline::persist::SqliteStore>>,
    /// The DIDs that may subscribe to this server's federation stream: the
    /// configured peers' `expected_did`s, canonical. Behind a lock so a peer
    /// added after boot is trusted without a restart.
    federation_peers: RwLock<BTreeSet<String>>,
}

impl AuthState {
    /// Build from the operator's `[auth]` section.
    ///
    /// Fails, rather than boots, on a DID the admission section cannot mean:
    /// the gates compare against the DID rebuilt from the caller's verified
    /// key, in canonical lower-case form, so an entry that is not a parseable
    /// `did:jig:z…` could never match anything. A ban that can never match is
    /// worse than a boot error; a membership record that can never match is a
    /// member locked out with no message. Valid entries are canonicalized, so
    /// an operator who pasted the spelling a block happened to carry still
    /// bans the key they meant.
    pub fn from_config(auth: &AuthSection) -> anyhow::Result<Self> {
        let banned = auth
            .admission
            .banned_dids
            .iter()
            .enumerate()
            .map(|(i, d)| {
                canonical_did(d)
                    .map_err(|e| anyhow::anyhow!("[auth.admission] banned_dids[{i}]: {e}"))
            })
            .collect::<anyhow::Result<BTreeSet<String>>>()?;
        let records = auth
            .admission
            .records
            .iter()
            .enumerate()
            .map(|(i, r)| {
                canonical_did(&r.did)
                    .map(|did| (did, r.ruleset_key.clone(), r.score))
                    .map_err(|e| anyhow::anyhow!("[auth.admission] records[{i}].did: {e}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        // Zero bits is no work; past the maximum clients refuse to do it.
        if auth.admission.unknown_dids == UnknownDidsPolicy::ProofOfWork
            && !(1..=jig_core::admission_pow::MAX_BITS).contains(&auth.admission.pow_bits)
        {
            anyhow::bail!(
                "[auth.admission] pow_bits must be 1..={} under \"proof-of-work\"; got {}",
                jig_core::admission_pow::MAX_BITS,
                auth.admission.pow_bits
            );
        }

        let limits = &auth.rate_limit;
        Ok(Self {
            replay_guard: Mutex::new(
                ReplayGuard::new(auth.replay_window_ms, auth.replay_capacity)
                    .with_per_did_share(limits.replay_per_did),
            ),
            disclosure: DisclosurePolicy::default(),
            admission: admission_policy(&auth.admission, banned),
            reputation: Arc::new(SeededRecords::new(records)),
            did_rate: RateLimiter::new(
                limits.per_did_burst,
                limits.per_did_per_second,
                limits.max_tracked,
            ),
            ip_rate: RateLimiter::new(
                limits.per_ip_burst,
                limits.per_ip_per_second,
                limits.max_tracked,
            ),
            write_pools: WritePools::new(&auth.pools, std::time::Instant::now())?,
            local_member_age_secs: auth.pools.local_member_age_secs,
            proofs: None,
            federation_peers: RwLock::new(BTreeSet::new()),
        })
    }

    /// Trust `did` as a federation peer. Fails on a DID that is not a
    /// parseable `did:jig:z…`, for the reason [`Self::from_config`] does: an
    /// entry that can never match is a peer locked out with no message.
    pub fn trust_federation_peer(&self, did: &str) -> anyhow::Result<()> {
        let did = canonical_did(did)?;
        self.federation_peers
            .write()
            .expect("federation peer lock poisoned")
            .insert(did);
        Ok(())
    }

    /// Whether `did`, which must be the identity gate 1 VERIFIED, is one of
    /// this server's federation peers.
    pub fn is_federation_peer(&self, did: &str) -> bool {
        canonical_did(did).is_ok_and(|did| {
            self.federation_peers
                .read()
                .expect("federation peer lock poisoned")
                .contains(&did)
        })
    }

    /// Read and record admission proofs of work in `store`.
    pub fn with_proofs(mut self, store: Arc<jig_pipeline::persist::SqliteStore>) -> Self {
        self.proofs = Some(store);
        self
    }

    /// The bits of work this server asks of a new DID, when it asks for any.
    pub fn pow_bits(&self) -> Option<u8> {
        match self.admission.unknown_dids {
            Some(UnknownDids::ProofOfWork { bits }) => Some(bits),
            _ => None,
        }
    }

    /// Whether `did` has done this server's proof of work.
    pub fn proven(&self, did: &str) -> bool {
        self.proofs
            .as_ref()
            .is_some_and(|store| store.admission_proven(did).unwrap_or(false))
    }

    /// Record that `did` did `bits` of work.
    pub fn record_proof(&self, did: &str, bits: u8) -> anyhow::Result<()> {
        let store = self
            .proofs
            .as_ref()
            .context("this server keeps no admission proofs")?;
        Ok(store.record_admission_proof(did, bits)?)
    }

    /// Whether `did` is banned here, whatever else is true of it.
    pub fn banned(&self, did: &str) -> bool {
        self.admission.banned_dids.contains(did)
    }

    /// Read both rate limits' time from `clock`: tests hold it still, so a
    /// rate test sees exactly the configured burst and refill.
    pub fn set_rate_clock(&self, clock: &super::rate::ManualClock) {
        for rate in [&self.did_rate, &self.ip_rate].into_iter().flatten() {
            rate.set_clock(clock.clone());
        }
    }

    /// Gate 2, then the DID's rate: what every read, subscription and write
    /// runs on the identity gate 1 verified. Admission first, so a refused
    /// caller spends nothing and learns nothing about its rate.
    pub fn admit_and_charge(&self, did: &str) -> Result<(), GateOutcome> {
        self.admit(did)?;
        match &self.did_rate {
            Some(rate) if !rate.take(did) => Err(GateOutcome::RateLimited),
            _ => Ok(()),
        }
    }

    /// The capacity pool `did`'s requests are served from (JEP-0008 rule
    /// 21), at `now_unix` on this server's clock. `did` must be the identity
    /// gate 1 VERIFIED.
    ///
    /// A member is a DID the operator recorded with no negative score, or one
    /// whose admission proof of work is at least `local_member_age_secs` old.
    /// No DID is invited until invites exist (JEP-0009). Everyone else is a
    /// stranger. This server keeps no penalty history yet, so "without a
    /// penalty" (rule 21) adds nothing to the age test.
    pub fn pool_of(&self, did: &str, now_unix: i64) -> Pool {
        let view = self.reputation.view(did);
        if !view.is_empty() && view.scores.values().all(|score| *score >= 0) {
            return Pool::Member;
        }
        let age = i64::try_from(self.local_member_age_secs).unwrap_or(i64::MAX);
        let aged = self
            .proofs
            .as_ref()
            .and_then(|store| store.admission_proven_at(did).ok().flatten())
            .is_some_and(|at| now_unix.saturating_sub(at) >= age);
        if aged { Pool::Member } else { Pool::Stranger }
    }

    /// Gate 2, the DID's rate, then its pool's share of the write capacity:
    /// what a write from a local client runs on its author. Rate limits come
    /// before the pool (JEP-0008 rule 23), so one identity cannot spend its
    /// pool's share by itself.
    pub fn admit_write_at(
        &self,
        did: &str,
        now: std::time::Instant,
        now_unix: i64,
    ) -> Result<(), GateOutcome> {
        self.admit_and_charge(did)?;
        let Some(pools) = &self.write_pools else {
            return Ok(());
        };
        let pool = self.pool_of(did, now_unix);
        if pools.try_take(pool, now) {
            Ok(())
        } else {
            tracing::debug!(?pool, "write refused: its capacity pool is spent");
            Err(GateOutcome::RateLimited)
        }
    }

    /// Take one request's worth from `ip`'s bucket. False when it is over.
    pub fn charge_ip(&self, ip: std::net::IpAddr) -> bool {
        self.ip_rate
            .as_ref()
            .is_none_or(|rate| rate.take(&ip.to_string()))
    }

    /// Gate 2 for `did`, which must be the identity gate 1 VERIFIED — never
    /// one merely claimed. Pure apart from the view lookup.
    pub fn admit(&self, did: &str) -> Result<(), GateOutcome> {
        let mut view = self.reputation.view(did);
        // Only a proof-of-work policy reads it: no store lookup otherwise.
        view.proven = self.pow_bits().is_some() && self.proven(did);
        admit(did, &view, &self.admission)
    }

    /// Gate 2 for the author of a block a peer relayed or a bridge submitted.
    /// The same policy, except that proof of work is not asked for: the
    /// author never spoke to this server, so it could not have done it. Bans,
    /// floors and the rate still apply.
    fn admit_relayed_and_charge(&self, did: &str) -> Result<(), GateOutcome> {
        match self.admit_and_charge(did) {
            Err(GateOutcome::AdmissionProofRequired { .. }) => {
                let mut admit_all = self.admission.clone();
                admit_all.unknown_dids = Some(UnknownDids::Admit);
                let mut view = self.reputation.view(did);
                view.proven = true;
                admit(did, &view, &admit_all)?;
                match &self.did_rate {
                    Some(rate) if !rate.take(did) => Err(GateOutcome::RateLimited),
                    _ => Ok(()),
                }
            }
            other => other,
        }
    }
}

fn admission_refusal(outcome: GateOutcome) -> jig_pipeline::ingest::AdmissionRefusal {
    use jig_pipeline::ingest::AdmissionRefusal;
    // The audit record of what actually happened, whatever the write surface
    // tells the caller.
    tracing::info!(audit = %crate::auth::audit_line(&outcome), "write refused");
    match outcome {
        GateOutcome::AdmissionBanned => AdmissionRefusal::Banned,
        GateOutcome::AdmissionBelowRuleset { ruleset_key } => {
            AdmissionRefusal::BelowRuleset { ruleset_key }
        }
        GateOutcome::AdmissionProofRequired { bits } => AdmissionRefusal::ProofRequired { bits },
        GateOutcome::RateLimited => AdmissionRefusal::RateLimited,
        // Gate 2 only ever returns admission outcomes.
        _ => AdmissionRefusal::Unknown,
    }
}

/// The pipeline asks the server whether to admit a block's author; the
/// answer is the same gate 2 the read surfaces run, over the same policy and
/// view. Mapped to the pipeline's own refusal type so jig-pipeline never
/// depends on this crate's outcomes.
impl jig_pipeline::ingest::Admission for AuthState {
    fn admit(&self, sender_did: &str) -> Result<(), jig_pipeline::ingest::AdmissionRefusal> {
        self.admit_write_at(
            sender_did,
            std::time::Instant::now(),
            chrono::Utc::now().timestamp(),
        )
        .map_err(admission_refusal)
    }

    fn admit_relayed(
        &self,
        sender_did: &str,
    ) -> Result<(), jig_pipeline::ingest::AdmissionRefusal> {
        self.admit_relayed_and_charge(sender_did)
            .map_err(admission_refusal)
    }
}

/// The canonical form of a configured DID: an operator typed it, so it may
/// be in any letter case, and is re-spelled from its key (so the case matches
/// what the gates compare against).
fn canonical_did(raw: &str) -> anyhow::Result<String> {
    let did = jig_core::did::Did::canonicalize(raw)
        .map_err(|e| anyhow::anyhow!("`{raw}` is not a did:jig:z… DID ({e})"))?;
    Ok(did.to_did_jig_string())
}

fn admission_policy(section: &AdmissionSection, banned_dids: BTreeSet<String>) -> AdmissionPolicy {
    AdmissionPolicy {
        unknown_dids: Some(match section.unknown_dids {
            UnknownDidsPolicy::Admit => UnknownDids::Admit,
            UnknownDidsPolicy::Refuse => UnknownDids::Refuse,
            UnknownDidsPolicy::ProofOfWork => UnknownDids::ProofOfWork {
                bits: section.pow_bits,
            },
        }),
        floors: section
            .floors
            .iter()
            .map(|f| Floor {
                ruleset_key: f.ruleset_key.clone(),
                minimum: f.minimum,
            })
            .collect(),
        banned_dids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard must be sized from config, not from a hardcoded default —
    /// otherwise the `[auth]` knobs are decorative.
    #[test]
    fn the_guard_is_sized_from_config() {
        let section = AuthSection {
            require_authenticated_reads: true,
            replay_window_ms: 1_234,
            replay_capacity: 7,
            admission: AdmissionSection::default(),
            rate_limit: Default::default(),
            pools: Default::default(),
        };
        let state = AuthState::from_config(&section).unwrap();
        let mut guard = state.replay_guard.lock().unwrap();

        // Capacity 7: the eighth distinct nonce in-window must be refused.
        for i in 0..7 {
            guard
                .check_and_record("did:jig:zA", &format!("n{i}"), 5_000, 5_000)
                .expect("within capacity");
        }
        assert!(
            guard
                .check_and_record("did:jig:zA", "n7", 5_000, 5_000)
                .is_err(),
            "capacity from config must actually bound the guard"
        );

        // Window 1234ms: a request 2s old must be outside it.
        assert!(
            guard
                .check_and_record("did:jig:zA", "late", 5_000, 7_000)
                .is_err(),
            "window from config must actually bound freshness"
        );
    }

    /// The admission knobs must reach the decision — otherwise the
    /// `[auth.admission]` section is decorative.
    #[test]
    fn admission_is_built_from_config() {
        use jig_config::v0_0_2_server::{AdmissionFloor, ReputationRecord};
        let good = did_for(1);
        let bad = did_for(2);
        let low = did_for(3);
        let stranger = did_for(4);
        let mut section = AuthSection::default();
        section.admission.unknown_dids = UnknownDidsPolicy::Refuse;
        section.admission.banned_dids = vec![bad.clone()];
        section.admission.floors = vec![AdmissionFloor {
            ruleset_key: "r".to_string(),
            minimum: 0,
        }];
        section.admission.records = vec![
            ReputationRecord {
                did: good.clone(),
                ruleset_key: "r".to_string(),
                score: 3,
            },
            ReputationRecord {
                did: low.clone(),
                ruleset_key: "r".to_string(),
                score: -1,
            },
        ];
        let state = AuthState::from_config(&section).unwrap();

        assert_eq!(state.admit(&good), Ok(()));
        assert_eq!(state.admit(&bad), Err(GateOutcome::AdmissionBanned));
        assert_eq!(
            state.admit(&low),
            Err(GateOutcome::AdmissionBelowRuleset {
                ruleset_key: "r".to_string()
            })
        );
        assert_eq!(
            state.admit(&stranger),
            Err(GateOutcome::AdmissionUnknownDid)
        );
    }

    /// A peer-relayed or bridged author never spoke to this server, so it
    /// cannot have done the work: it is not asked for it. Everything else
    /// about admission still applies to it.
    #[test]
    fn relayed_authors_are_not_asked_for_work_but_are_still_banned() {
        use jig_pipeline::ingest::{Admission as _, AdmissionRefusal};
        let (stranger, bad) = (did_for(1), did_for(2));
        let mut section = AuthSection::default();
        section.admission.unknown_dids = UnknownDidsPolicy::ProofOfWork;
        section.admission.banned_dids = vec![bad.clone()];
        let state = AuthState::from_config(&section).unwrap();

        assert_eq!(
            jig_pipeline::ingest::Admission::admit(&state, &stranger),
            Err(AdmissionRefusal::ProofRequired { bits: 20 })
        );
        assert_eq!(state.admit_relayed(&stranger), Ok(()));
        assert_eq!(state.admit_relayed(&bad), Err(AdmissionRefusal::Banned));
    }

    /// Rule 21's local membership: a recorded DID with no negative score, or
    /// one whose admission proof is `local_member_age_secs` old. Rule 22: no
    /// record and no aged proof (a fresh DID, or an `--anon` key, which a
    /// server cannot tell apart from one) is a stranger.
    #[test]
    fn pools_are_assigned_by_record_and_proof_age() {
        use jig_config::v0_0_2_server::ReputationRecord;
        let (recorded, negative, proven, fresh) = (did_for(1), did_for(2), did_for(3), did_for(4));
        let mut section = AuthSection::default();
        section.pools.local_member_age_secs = 100;
        section.admission.records = vec![
            ReputationRecord {
                did: recorded.clone(),
                ruleset_key: "r".to_string(),
                score: 0,
            },
            ReputationRecord {
                did: negative.clone(),
                ruleset_key: "r".to_string(),
                score: -1,
            },
        ];
        let store = Arc::new(jig_pipeline::persist::SqliteStore::open_in_memory().unwrap());
        let state = AuthState::from_config(&section)
            .unwrap()
            .with_proofs(store.clone());
        state.record_proof(&proven, 20).unwrap();
        let proven_at = store.admission_proven_at(&proven).unwrap().unwrap();

        assert_eq!(state.pool_of(&recorded, proven_at), Pool::Member);
        assert_eq!(state.pool_of(&negative, proven_at), Pool::Stranger);
        assert_eq!(state.pool_of(&fresh, proven_at + 1_000), Pool::Stranger);
        assert_eq!(state.pool_of(&proven, proven_at + 99), Pool::Stranger);
        assert_eq!(state.pool_of(&proven, proven_at + 100), Pool::Member);
    }

    /// The flood test through the write gate, on injected time: a thousand
    /// fresh DIDs spend the stranger share, and an active member still has
    /// all of its own.
    #[test]
    fn a_stranger_flood_through_the_write_gate_leaves_members_writing() {
        use jig_config::v0_0_2_server::ReputationRecord;
        let member = did_for(1);
        let mut section = AuthSection::default();
        section.pools.writes_per_second = 50;
        section.pools.writes_burst = 50;
        section.admission.records = vec![ReputationRecord {
            did: member.clone(),
            ruleset_key: "r".to_string(),
            score: 1,
        }];
        let state = AuthState::from_config(&section).unwrap();
        let now = std::time::Instant::now();
        assert_eq!(
            state.admit_write_at(&member, now, 0),
            Ok(()),
            "members are active"
        );
        let admitted = (0..1_000u32)
            .filter(|i| {
                let key = ed25519_dalek::SigningKey::from_bytes(&{
                    let mut seed = [7u8; 32];
                    seed[..4].copy_from_slice(&i.to_le_bytes());
                    seed
                });
                let did = jig_core::did::Did::from_ed25519_pubkey(&key.verifying_key().to_bytes())
                    .to_did_jig_string();
                state.admit_write_at(&did, now, 0).is_ok()
            })
            .count();
        // 20 % of a burst of 50, and invited's idle 2 above half; nothing of
        // the active members'.
        assert_eq!(admitted, 10 + 2);
        for i in 0..34 {
            assert_eq!(
                state.admit_write_at(&member, now, 0),
                Ok(()),
                "member write {i}"
            );
        }
    }

    /// Relayed and bridged authors are not charged to the pools: the peer
    /// pays at its own ingress (JEP-0008 rule 30).
    #[test]
    fn relayed_writes_are_not_charged_to_the_pools() {
        use jig_pipeline::ingest::Admission as _;
        let mut section = AuthSection::default();
        section.pools.writes_per_second = 10;
        section.pools.writes_burst = 10;
        let state = AuthState::from_config(&section).unwrap();
        for i in 0..20 {
            assert_eq!(
                state.admit_relayed(&did_for(9)),
                Ok(()),
                "relayed write {i}"
            );
        }
    }

    /// Zero bits is no work, and past the maximum clients refuse to do it.
    #[test]
    fn pow_bits_out_of_range_is_refused_at_boot() {
        for bits in [0, 29, 255] {
            let mut section = AuthSection::default();
            section.admission.unknown_dids = UnknownDidsPolicy::ProofOfWork;
            section.admission.pow_bits = bits;
            let err = match AuthState::from_config(&section) {
                Ok(_) => panic!("pow_bits = {bits} must be refused at boot"),
                Err(e) => e,
            };
            assert!(err.to_string().contains("pow_bits"), "{err}");
        }
        // Only under proof-of-work: the knob is inert otherwise.
        let mut section = AuthSection::default();
        section.admission.pow_bits = 0;
        assert!(AuthState::from_config(&section).is_ok());
    }

    /// A server with no admission section admits everyone: the section
    /// narrows access and its absence must not.
    #[test]
    fn a_default_config_admits_everyone() {
        let state = AuthState::from_config(&AuthSection::default()).unwrap();
        assert_eq!(state.admit(&did_for(9)), Ok(()));
    }

    /// The gates compare canonical lower-case DIDs. An operator who pasted the
    /// upper-cased spelling a block carried must still ban the key they meant.
    #[test]
    fn configured_dids_are_canonicalized() {
        let bad = did_for(2);
        let (prefix, body) = bad.split_at("did:jig:z".len());
        let mut section = AuthSection::default();
        section.admission.banned_dids = vec![format!("  {prefix}{}  ", body.to_uppercase())];
        let state = AuthState::from_config(&section).unwrap();
        assert_eq!(state.admit(&bad), Err(GateOutcome::AdmissionBanned));
    }

    /// A ban that can never match is worse than a boot error.
    #[test]
    fn a_did_that_cannot_match_anything_is_refused_at_boot() {
        use jig_config::v0_0_2_server::ReputationRecord;
        for bad in ["did:jig:zBad", "did:jig:alice", "", "not a did"] {
            let mut section = AuthSection::default();
            section.admission.banned_dids = vec![bad.to_string()];
            let err = match AuthState::from_config(&section) {
                Ok(_) => panic!("{bad:?} must be refused at boot"),
                Err(e) => e,
            };
            assert!(err.to_string().contains("banned_dids[0]"), "{err}");
        }
        let mut section = AuthSection::default();
        section.admission.records = vec![ReputationRecord {
            did: "did:jig:zGood".to_string(),
            ruleset_key: "r".to_string(),
            score: 1,
        }];
        let err = match AuthState::from_config(&section) {
            Ok(_) => panic!("a record with an unparseable DID must be refused at boot"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("records[0].did"), "{err}");
    }

    fn did_for(seed: u8) -> String {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        jig_core::did::Did::from_ed25519_pubkey(&key.verifying_key().to_bytes()).to_did_jig_string()
    }

    /// Truthful disclosure is the default; a server that conceals should do so
    /// because an operator asked it to.
    #[test]
    fn disclosure_defaults_to_truthful() {
        let state = AuthState::from_config(&AuthSection::default()).unwrap();
        assert_eq!(state.disclosure, DisclosurePolicy::Truthful);
    }
}
