//! What actually happened at a gate.
//!
//! This is the **internal truth** and it never crosses the wire. The wire sees
//! whatever [`crate::auth::disclosure`] policy maps it to, which by default is
//! the truthful mapping but need not be. Keeping the two apart is what lets a
//! server return 404 for a restricted channel later without touching a single
//! call site — and what keeps the operator's own logs honest while it does.

/// Which gate produced an outcome.
///
/// Recorded on every outcome because gate ordering is a security property:
/// a caller refused at admission must never receive an authorization
/// outcome, since "you are not a member" confirms the channel exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Authenticate,
    Admit,
    Authorize,
}

/// The precise reason a request was refused.
///
/// Variants are deliberately fine-grained. Anything coarser would force the
/// disclosure policy to guess, and would rob the audit log of the detail an
/// operator needs to run the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    /// The signature did not verify against the claimed DID's key.
    AuthSignatureInvalid,
    /// A well-formed, correctly signed request whose nonce was already seen
    /// inside the replay window.
    AuthReplayed,
    /// The request's HLC fell outside the acceptance window.
    AuthStale,
    /// A capability was presented after its expiry.
    AuthCapabilityExpired,
    /// A capability issued to one DID was presented by another.
    AuthCapabilitySubjectMismatch,
    /// No proof of possession accompanied the request at all.
    AuthMissing,

    /// The server has no reputation entry for this DID under any ruleset it
    /// consults. **Not** the same as a bad score: this is a caller the server
    /// has never seen, which is the expected state of a freshly-minted or
    /// deliberately ablated identity.
    AdmissionUnknownDid,
    /// The DID is known under `ruleset_key` and scores below this server's
    /// configured floor for it.
    AdmissionBelowRuleset { ruleset_key: String },
    /// The DID is explicitly refused by this server.
    AdmissionBanned,

    /// The caller is not a member of a restricted channel.
    AuthzNotMember,
    /// The caller is not the channel's owner and the action requires it.
    AuthzNotOwner,
    /// The named channel does not exist.
    AuthzChannelUnknown,
}

impl GateOutcome {
    /// Which gate produced this outcome.
    pub fn gate(&self) -> Gate {
        match self {
            GateOutcome::AuthSignatureInvalid
            | GateOutcome::AuthReplayed
            | GateOutcome::AuthStale
            | GateOutcome::AuthCapabilityExpired
            | GateOutcome::AuthCapabilitySubjectMismatch
            | GateOutcome::AuthMissing => Gate::Authenticate,

            GateOutcome::AdmissionUnknownDid
            | GateOutcome::AdmissionBelowRuleset { .. }
            | GateOutcome::AdmissionBanned => Gate::Admit,

            GateOutcome::AuthzNotMember
            | GateOutcome::AuthzNotOwner
            | GateOutcome::AuthzChannelUnknown => Gate::Authorize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each gate's outcomes must be distinguishable from the others'. The
    /// ordering property the design depends on — admission refusals must never
    /// surface as authorization refusals — is only checkable if the outcome
    /// itself says which gate produced it.
    #[test]
    fn every_outcome_names_its_gate() {
        assert_eq!(GateOutcome::AuthSignatureInvalid.gate(), Gate::Authenticate);
        assert_eq!(GateOutcome::AuthReplayed.gate(), Gate::Authenticate);
        assert_eq!(GateOutcome::AdmissionUnknownDid.gate(), Gate::Admit);
        assert_eq!(GateOutcome::AdmissionBanned.gate(), Gate::Admit);
        assert_eq!(GateOutcome::AuthzNotMember.gate(), Gate::Authorize);
        assert_eq!(GateOutcome::AuthzNotOwner.gate(), Gate::Authorize);
    }

    /// `unknown` and `below-threshold` are separate variants, not one variant
    /// with a score field. Collapsing them is the specific bug the design
    /// guards against: a holder who ablated a key under deanonymization
    /// pressure lands on a fresh DID, and must not be refused as though they
    /// had a bad score.
    #[test]
    fn unknown_and_below_threshold_are_distinct_variants() {
        let unknown = GateOutcome::AdmissionUnknownDid;
        let below = GateOutcome::AdmissionBelowRuleset {
            ruleset_key: "highsec.v1".to_string(),
        };
        assert_ne!(unknown, below);
        assert_eq!(unknown.gate(), below.gate());
    }
}
