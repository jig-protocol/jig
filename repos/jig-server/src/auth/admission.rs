//! Gate 2: will this server talk to you at all?
//!
//! A pure function of three things — who is asking, what this server knows
//! about them, and what the operator decided — with no I/O, no clock and no
//! network. Shaped that way on purpose: it can later run as a sandboxed,
//! fuel-metered policy block, which is what makes reputation contracts
//! shareable (two servers running the same block reach the same verdict, and
//! that is checkable rather than promised). Build the seam now; do not build
//! policy-block execution now.
//!
//! # `unknown` and `below-threshold` are different
//!
//! Reputation is ruleset-scoped `key → score`, never a scalar, so every floor
//! is `(ruleset_key, minimum)` — and a DID with **no** score under that key is
//! *unknown for that ruleset*, governed by the operator's explicit
//! `unknown_dids` choice and never by the number. If "unknown" silently
//! resolved to "below threshold", a holder who ablated a key under
//! deanonymization pressure would land on a fresh DID and be refused
//! everywhere — the system would punish exactly the behaviour the anonymity
//! model requires. Refusing unknowns must be a choice the operator made.

use std::collections::{BTreeMap, BTreeSet};

use crate::auth::GateOutcome;

/// What this server knows about one DID: its score under each ruleset it has
/// a record for. Absence of a key is meaningful — see the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReputationView {
    pub scores: BTreeMap<String, i64>,
}

impl ReputationView {
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

/// The operator's explicit choice for a DID this server has no relevant
/// record for. There is no default that is not a choice, so this is not
/// derived from anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownDids {
    Admit,
    Refuse,
}

/// A reputation floor: refuse a DID whose score under `ruleset_key` is below
/// `minimum`. Says nothing about a DID with no score under the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Floor {
    pub ruleset_key: String,
    pub minimum: i64,
}

/// Everything the operator decided. Evaluated in this order: bans, then
/// floors in the order written, then — with no floors — whether the DID is
/// known at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmissionPolicy {
    pub unknown_dids: Option<UnknownDids>,
    pub floors: Vec<Floor>,
    pub banned_dids: BTreeSet<String>,
}

impl AdmissionPolicy {
    /// Whether this policy turns anyone away at all. A server that does is
    /// one where "open channel" means open to the admitted, and ungated
    /// surfaces (`/metrics`) must stop naming even open channels.
    pub fn refuses_anyone(&self) -> bool {
        self.unknown_dids() == UnknownDids::Refuse
            || !self.floors.is_empty()
            || !self.banned_dids.is_empty()
    }

    fn unknown_dids(&self) -> UnknownDids {
        // An unset choice admits: a server that never wrote an
        // `[auth.admission]` section has not decided to turn anyone away.
        self.unknown_dids.unwrap_or(UnknownDids::Admit)
    }
}

/// Where a [`ReputationView`] comes from. This phase seeds it from config; a
/// ledger plugs in here later without the decision changing.
pub trait ReputationSource: Send + Sync {
    fn view(&self, did: &str) -> ReputationView;
}

/// Records the operator wrote down: `did → (ruleset_key → score)`.
#[derive(Debug, Default)]
pub struct SeededRecords {
    records: BTreeMap<String, ReputationView>,
}

impl SeededRecords {
    pub fn new(entries: impl IntoIterator<Item = (String, String, i64)>) -> Self {
        let mut records: BTreeMap<String, ReputationView> = BTreeMap::new();
        for (did, ruleset_key, score) in entries {
            records
                .entry(did)
                .or_default()
                .scores
                .insert(ruleset_key, score);
        }
        Self { records }
    }
}

impl ReputationSource for SeededRecords {
    fn view(&self, did: &str) -> ReputationView {
        self.records.get(did).cloned().unwrap_or_default()
    }
}

/// Decide whether this server will deal with `did` at all.
///
/// Bans first: a banned DID is banned whatever its scores say. Then each
/// floor, in the order the operator wrote them; the first one that fails
/// names its ruleset. A floor whose ruleset the DID has no score under does
/// not compare anything — it asks the `unknown_dids` choice. With no floors
/// configured, a DID is unknown when the server has no record of it at all.
pub fn admit(
    did: &str,
    view: &ReputationView,
    policy: &AdmissionPolicy,
) -> Result<(), GateOutcome> {
    if policy.banned_dids.contains(did) {
        return Err(GateOutcome::AdmissionBanned);
    }

    if policy.floors.is_empty() {
        return match (view.is_empty(), policy.unknown_dids()) {
            (true, UnknownDids::Refuse) => Err(GateOutcome::AdmissionUnknownDid),
            _ => Ok(()),
        };
    }

    for floor in &policy.floors {
        match view.scores.get(&floor.ruleset_key) {
            Some(score) if *score < floor.minimum => {
                return Err(GateOutcome::AdmissionBelowRuleset {
                    ruleset_key: floor.ruleset_key.clone(),
                });
            }
            Some(_) => {}
            // No score under this ruleset: unknown for it. Never a
            // comparison against `minimum`.
            None => {
                if policy.unknown_dids() == UnknownDids::Refuse {
                    return Err(GateOutcome::AdmissionUnknownDid);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:jig:zSomeone";

    fn view(entries: &[(&str, i64)]) -> ReputationView {
        ReputationView {
            scores: entries
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
        }
    }

    fn floor(key: &str, minimum: i64) -> Floor {
        Floor {
            ruleset_key: key.to_string(),
            minimum,
        }
    }

    fn policy(unknown: UnknownDids, floors: Vec<Floor>, banned: &[&str]) -> AdmissionPolicy {
        AdmissionPolicy {
            unknown_dids: Some(unknown),
            floors,
            banned_dids: banned.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn an_unknown_did_is_admitted_or_refused_by_explicit_choice_alone() {
        let nobody = ReputationView::default();
        assert_eq!(
            admit(DID, &nobody, &policy(UnknownDids::Admit, vec![], &[])),
            Ok(())
        );
        assert_eq!(
            admit(DID, &nobody, &policy(UnknownDids::Refuse, vec![], &[])),
            Err(GateOutcome::AdmissionUnknownDid)
        );
    }

    /// A server that never wrote an admission section has not decided to
    /// turn anyone away.
    #[test]
    fn the_default_policy_admits_everyone() {
        assert_eq!(
            admit(DID, &ReputationView::default(), &AdmissionPolicy::default()),
            Ok(())
        );
    }

    /// THE test this module exists for. A floor of 0 must not read "no score"
    /// as "score below 0".
    #[test]
    fn a_floor_never_refuses_a_did_with_no_score_under_its_ruleset() {
        let p = policy(UnknownDids::Admit, vec![floor("r", 0)], &[]);
        assert_eq!(admit(DID, &ReputationView::default(), &p), Ok(()));
        assert_eq!(admit(DID, &view(&[("other", -100)]), &p), Ok(()));
    }

    #[test]
    fn a_floor_refuses_a_score_below_it_and_admits_one_at_it() {
        let p = policy(UnknownDids::Admit, vec![floor("r", 0)], &[]);
        assert_eq!(
            admit(DID, &view(&[("r", -1)]), &p),
            Err(GateOutcome::AdmissionBelowRuleset {
                ruleset_key: "r".to_string()
            })
        );
        assert_eq!(admit(DID, &view(&[("r", 0)]), &p), Ok(()));
        assert_eq!(admit(DID, &view(&[("r", 40)]), &p), Ok(()));
    }

    /// With a floor and `Refuse`, a DID scored only under some OTHER ruleset
    /// is unknown for this one — and the outcome says unknown, not below.
    #[test]
    fn unknown_for_a_ruleset_is_governed_by_the_unknown_choice() {
        let p = policy(UnknownDids::Refuse, vec![floor("r", 0)], &[]);
        assert_eq!(
            admit(DID, &view(&[("other", 99)]), &p),
            Err(GateOutcome::AdmissionUnknownDid)
        );
        assert_eq!(admit(DID, &view(&[("r", 3)]), &p), Ok(()));
    }

    #[test]
    fn a_ban_wins_over_everything_including_a_perfect_score() {
        let p = policy(UnknownDids::Admit, vec![floor("r", 0)], &[DID]);
        assert_eq!(
            admit(DID, &view(&[("r", 1_000)]), &p),
            Err(GateOutcome::AdmissionBanned)
        );
        // And over "unknown": a banned stranger is told banned, not unknown.
        let p = policy(UnknownDids::Refuse, vec![], &[DID]);
        assert_eq!(
            admit(DID, &ReputationView::default(), &p),
            Err(GateOutcome::AdmissionBanned)
        );
    }

    #[test]
    fn the_first_failing_floor_names_its_ruleset() {
        let p = policy(UnknownDids::Admit, vec![floor("a", 0), floor("b", 10)], &[]);
        assert_eq!(
            admit(DID, &view(&[("a", 5), ("b", 5)]), &p),
            Err(GateOutcome::AdmissionBelowRuleset {
                ruleset_key: "b".to_string()
            })
        );
    }

    #[test]
    fn refuses_anyone_is_false_only_for_the_admit_everyone_policy() {
        assert!(!AdmissionPolicy::default().refuses_anyone());
        assert!(!policy(UnknownDids::Admit, vec![], &[]).refuses_anyone());
        assert!(policy(UnknownDids::Refuse, vec![], &[]).refuses_anyone());
        assert!(policy(UnknownDids::Admit, vec![floor("r", 0)], &[]).refuses_anyone());
        assert!(policy(UnknownDids::Admit, vec![], &[DID]).refuses_anyone());
    }

    #[test]
    fn seeded_records_build_a_view_per_did() {
        let src = SeededRecords::new([
            ("did:jig:zA".to_string(), "r".to_string(), 5),
            ("did:jig:zA".to_string(), "s".to_string(), -2),
            ("did:jig:zB".to_string(), "r".to_string(), 0),
        ]);
        assert_eq!(src.view("did:jig:zA"), view(&[("r", 5), ("s", -2)]));
        assert_eq!(src.view("did:jig:zB"), view(&[("r", 0)]));
        assert!(src.view("did:jig:zNobody").is_empty());
    }
}
