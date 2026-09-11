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
    pub fn from_config(auth: &AuthSection) -> Self {
        Self {
            replay_guard: Mutex::new(ReplayGuard::new(
                auth.replay_window_ms,
                auth.replay_capacity,
            )),
            disclosure: DisclosurePolicy::default(),
            admission: admission_policy(&auth.admission),
            reputation: Arc::new(SeededRecords::new(
                auth.admission
                    .records
                    .iter()
                    .map(|r| (r.did.clone(), r.ruleset_key.clone(), r.score)),
            )),
        }
    }

    /// Gate 2 for `did`, which must be the identity gate 1 VERIFIED — never
    /// one merely claimed. Pure apart from the view lookup.
    pub fn admit(&self, did: &str) -> Result<(), GateOutcome> {
        admit(did, &self.reputation.view(did), &self.admission)
    }
}

fn admission_policy(section: &AdmissionSection) -> AdmissionPolicy {
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
        banned_dids: section.banned_dids.iter().cloned().collect(),
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
        let state = AuthState::from_config(&section);
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
        let mut section = AuthSection::default();
        section.admission.unknown_dids = UnknownDidsPolicy::Refuse;
        section.admission.banned_dids = vec!["did:jig:zBad".to_string()];
        section.admission.floors = vec![AdmissionFloor {
            ruleset_key: "r".to_string(),
            minimum: 0,
        }];
        section.admission.records = vec![
            ReputationRecord {
                did: "did:jig:zGood".to_string(),
                ruleset_key: "r".to_string(),
                score: 3,
            },
            ReputationRecord {
                did: "did:jig:zLow".to_string(),
                ruleset_key: "r".to_string(),
                score: -1,
            },
        ];
        let state = AuthState::from_config(&section);

        assert_eq!(state.admit("did:jig:zGood"), Ok(()));
        assert_eq!(
            state.admit("did:jig:zBad"),
            Err(GateOutcome::AdmissionBanned)
        );
        assert_eq!(
            state.admit("did:jig:zLow"),
            Err(GateOutcome::AdmissionBelowRuleset {
                ruleset_key: "r".to_string()
            })
        );
        assert_eq!(
            state.admit("did:jig:zStranger"),
            Err(GateOutcome::AdmissionUnknownDid)
        );
    }

    /// A server with no admission section admits everyone: the section
    /// narrows access and its absence must not.
    #[test]
    fn a_default_config_admits_everyone() {
        let state = AuthState::from_config(&AuthSection::default());
        assert_eq!(state.admit("did:jig:zAnyone"), Ok(()));
    }

    /// Truthful disclosure is the default; a server that conceals should do so
    /// because an operator asked it to.
    #[test]
    fn disclosure_defaults_to_truthful() {
        let state = AuthState::from_config(&AuthSection::default());
        assert_eq!(state.disclosure, DisclosurePolicy::Truthful);
    }
}
