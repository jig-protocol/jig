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
use std::sync::{Arc, Mutex};

use jig_config::v0_0_2_server::{AdmissionSection, AuthSection, UnknownDidsPolicy};

use crate::auth::admission::{Floor, SeededRecords, UnknownDids};
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

        Ok(Self {
            replay_guard: Mutex::new(ReplayGuard::new(
                auth.replay_window_ms,
                auth.replay_capacity,
            )),
            disclosure: DisclosurePolicy::default(),
            admission: admission_policy(&auth.admission, banned),
            reputation: Arc::new(SeededRecords::new(records)),
        })
    }

    /// Gate 2 for `did`, which must be the identity gate 1 VERIFIED — never
    /// one merely claimed. Pure apart from the view lookup.
    pub fn admit(&self, did: &str) -> Result<(), GateOutcome> {
        admit(did, &self.reputation.view(did), &self.admission)
    }
}

/// The pipeline asks the server whether to admit a block's author; the
/// answer is the same gate 2 the read surfaces run, over the same policy and
/// view. Mapped to the pipeline's own refusal type so jig-pipeline never
/// depends on this crate's outcomes.
impl jig_pipeline::ingest::Admission for AuthState {
    fn admit(&self, sender_did: &str) -> Result<(), jig_pipeline::ingest::AdmissionRefusal> {
        use jig_pipeline::ingest::AdmissionRefusal;
        match AuthState::admit(self, sender_did) {
            Ok(()) => Ok(()),
            Err(outcome) => {
                // The audit record of what actually happened, whatever the
                // write surface tells the caller.
                tracing::info!(audit = %crate::auth::audit_line(&outcome), "write refused");
                Err(match outcome {
                    GateOutcome::AdmissionBanned => AdmissionRefusal::Banned,
                    GateOutcome::AdmissionBelowRuleset { ruleset_key } => {
                        AdmissionRefusal::BelowRuleset { ruleset_key }
                    }
                    // `admit` only ever returns admission outcomes.
                    _ => AdmissionRefusal::Unknown,
                })
            }
        }
    }
}

/// The canonical form of a configured DID: parsed as a real `did:jig:z…`
/// (so the key material is there) and re-spelled from it (so the case matches
/// what the gates compare against).
fn canonical_did(raw: &str) -> anyhow::Result<String> {
    let did = jig_core::did::Did::from_did_jig_string(raw.trim())
        .map_err(|e| anyhow::anyhow!("`{raw}` is not a canonical did:jig:z… DID ({e})"))?;
    let bytes = did.as_bytes()?;
    Ok(jig_core::did::Did::from_ed25519_pubkey(&bytes).to_did_jig_string())
}

fn admission_policy(section: &AdmissionSection, banned_dids: BTreeSet<String>) -> AdmissionPolicy {
    AdmissionPolicy {
        unknown_dids: Some(match section.unknown_dids {
            UnknownDidsPolicy::Admit => UnknownDids::Admit,
            UnknownDidsPolicy::Refuse => UnknownDids::Refuse,
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
