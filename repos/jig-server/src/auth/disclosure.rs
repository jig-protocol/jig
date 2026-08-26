//! What we tell the caller happened, which is not always what happened.
//!
//! [`GateOutcome`] is the truth. `DisclosurePolicy` maps it to the triple that
//! goes on the wire. The default is the truthful mapping; an operator may
//! choose one that conceals.
//!
//! The split exists so concealment costs nothing to add later. Every refusal
//! in the server routes through [`DisclosurePolicy::disclose`], so a new policy
//! is a new match arm rather than an edit to every call site — which is what
//! "compatibly-built" means here.
//!
//! **Obfuscation is client-facing only.** [`audit_line`] always renders the
//! true outcome, whatever the policy says. An operator who cannot tell a 401
//! from a 404 in their own logs cannot run the server.

use crate::auth::{Gate, GateOutcome};

/// How much of the truth this server tells a refused caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisclosurePolicy {
    /// Report each outcome honestly. The v0.0.x default: a server that lies
    /// should do so because an operator asked it to.
    #[default]
    Truthful,
    /// Report authorization refusals on a channel as though the channel did
    /// not exist, so probing cannot enumerate restricted channels. The
    /// familiar pattern from sites that 404 rather than 403 on customer
    /// resources.
    ///
    /// Authentication outcomes are untouched: a caller who has not
    /// authenticated has not named a resource, so there is no existence to
    /// conceal, and a 404 there would only make clients retry instead of
    /// fixing their credentials.
    RestrictedAsNotFound,
}

impl DisclosurePolicy {
    /// Map an outcome to `(http_status, error_code, message)`.
    pub fn disclose(&self, outcome: &GateOutcome) -> (u16, &'static str, String) {
        match self {
            DisclosurePolicy::Truthful => truthful(outcome),
            DisclosurePolicy::RestrictedAsNotFound => match outcome.gate() {
                Gate::Authorize => (404, "NO_SUCH_CHANNEL", "no such channel".to_string()),
                _ => truthful(outcome),
            },
        }
    }
}

/// The honest mapping, used directly by [`DisclosurePolicy::Truthful`] and as
/// the fallback for outcomes a concealing policy does not rewrite.
fn truthful(outcome: &GateOutcome) -> (u16, &'static str, String) {
    match outcome {
        GateOutcome::AuthMissing => (
            401,
            "AUTH_REQUIRED",
            "request carries no proof of possession".to_string(),
        ),
        GateOutcome::AuthSignatureInvalid => (
            401,
            "INVALID_SIG",
            "signature verification failed".to_string(),
        ),
        GateOutcome::AuthReplayed => (401, "REPLAYED", "this request was already seen".to_string()),
        GateOutcome::AuthStale => (
            401,
            "STALE_REQUEST",
            "request timestamp is outside the acceptance window".to_string(),
        ),
        GateOutcome::AuthCapabilityExpired => (
            401,
            "CAPABILITY_EXPIRED",
            "capability has expired".to_string(),
        ),
        GateOutcome::AuthCapabilitySubjectMismatch => (
            401,
            "CAPABILITY_SUBJECT_MISMATCH",
            "capability was issued to a different DID".to_string(),
        ),

        // 403 rather than 401: the caller authenticated fine, this server
        // simply will not deal with them. Re-authenticating cannot help.
        GateOutcome::AdmissionUnknownDid => (
            403,
            "NOT_ADMITTED",
            "this server does not admit unknown identities".to_string(),
        ),
        GateOutcome::AdmissionBelowRuleset { ruleset_key } => (
            403,
            "NOT_ADMITTED",
            format!("reputation under ruleset {ruleset_key} is below this server's floor"),
        ),
        GateOutcome::AdmissionBanned => (
            403,
            "NOT_ADMITTED",
            "this identity is refused by this server".to_string(),
        ),

        GateOutcome::AuthzNotMember => (
            403,
            "NOT_A_MEMBER",
            "not a member of this channel".to_string(),
        ),
        GateOutcome::AuthzNotOwner => (
            403,
            "NOT_CHANNEL_OWNER",
            "not the owner of this channel".to_string(),
        ),
        GateOutcome::AuthzChannelUnknown => (404, "NO_SUCH_CHANNEL", "no such channel".to_string()),
    }
}

/// Render an outcome for the audit log. Always the truth, never the policy.
pub fn audit_line(outcome: &GateOutcome) -> String {
    format!("gate={:?} outcome={:?}", outcome.gate(), outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::GateOutcome;

    /// The default policy tells the truth. Anything else would mean v0.0.x
    /// servers lie by default, which is not a decision to make implicitly.
    #[test]
    fn truthful_policy_reports_each_gate_honestly() {
        let p = DisclosurePolicy::Truthful;

        let (status, code, _) = p.disclose(&GateOutcome::AuthSignatureInvalid);
        assert_eq!(status, 401);
        assert_eq!(code, "INVALID_SIG");

        let (status, code, _) = p.disclose(&GateOutcome::AuthzNotMember);
        assert_eq!(status, 403);
        assert_eq!(code, "NOT_A_MEMBER");

        let (status, code, _) = p.disclose(&GateOutcome::AuthzChannelUnknown);
        assert_eq!(status, 404);
        assert_eq!(code, "NO_SUCH_CHANNEL");
    }

    /// The obfuscating policy collapses "you may not" into "there is nothing
    /// here", so probing cannot distinguish a restricted channel from an
    /// absent one. This is the case that must work without touching call
    /// sites — it is the whole reason truth and disclosure are separate types.
    #[test]
    fn restricted_as_not_found_hides_existence() {
        let p = DisclosurePolicy::RestrictedAsNotFound;

        let (status, code, _) = p.disclose(&GateOutcome::AuthzNotMember);
        assert_eq!(
            status, 404,
            "a refused member must look like an absent channel"
        );
        assert_eq!(code, "NO_SUCH_CHANNEL");

        let (absent_status, absent_code, _) = p.disclose(&GateOutcome::AuthzChannelUnknown);
        assert_eq!(
            (status, code),
            (absent_status, absent_code),
            "refusal and absence must be indistinguishable on the wire"
        );
    }

    /// Obfuscation is client-facing only. If it also blinded the operator's
    /// own logs, nobody could run the server, and the feature would be torn
    /// out within months.
    #[test]
    fn the_audit_line_records_the_truth_even_when_the_wire_does_not() {
        let outcome = GateOutcome::AuthzNotMember;
        let p = DisclosurePolicy::RestrictedAsNotFound;

        let (status, _, _) = p.disclose(&outcome);
        assert_eq!(status, 404, "precondition: the wire is being obfuscated");

        let audit = audit_line(&outcome);
        assert!(
            audit.contains("AuthzNotMember"),
            "the log must name the real outcome, got: {audit}"
        );
        assert!(
            audit.contains("Authorize"),
            "the log must name the real gate, got: {audit}"
        );
    }

    /// Authentication failures are never obfuscated into 404s: a caller who
    /// cannot authenticate has not named a resource yet, so there is nothing
    /// to hide the existence of, and a misleading 404 would just make clients
    /// retry forever instead of fixing their signature.
    #[test]
    fn obfuscation_does_not_touch_authentication_outcomes() {
        let truthful = DisclosurePolicy::Truthful.disclose(&GateOutcome::AuthSignatureInvalid);
        let obfuscated =
            DisclosurePolicy::RestrictedAsNotFound.disclose(&GateOutcome::AuthSignatureInvalid);
        assert_eq!(truthful.0, obfuscated.0);
        assert_eq!(truthful.1, obfuscated.1);
    }
}
