//! The single place `IngestError` acquires an HTTP status and error code.
//!
//! `v0_0_2_blocks::map_ingest_error` (REST block submission) and
//! `v0_0_2_admin::map_ingest_error` (synthetic-block admin endpoints) both
//! call [`classify_ingest_error`] and wrap the resulting triple in their own
//! JSON body type (`ErrorBody`, `AdminError`). Before this module existed,
//! the two functions carried near-identical match arms independently, which
//! meant a new `IngestError` variant could be classified one way for one
//! HTTP surface and a different way (or not at all) for the other. Adding a
//! variant here is now the only place that decision gets made, and both
//! surfaces see it automatically.
//!
//! `v0_0_2_bridges` does NOT use this classifier: it maps `IngestError` to
//! `SubmitDenied`, a retryability distinction for bridge delivery rather
//! than an HTTP status.

use axum::http::StatusCode;
use jig_pipeline::ingest::{IngestError, RenderCause};
use std::time::Duration;

/// How long a client refused for a render deadline is told to wait, before
/// [`jitter`]. The deadline (250 ms by default) passed because this host was
/// loaded; about a second lets a burst drain without the client giving up.
pub const RENDER_DEADLINE_RETRY: Duration = Duration::from_secs(1);

/// `nominal` scaled by a factor drawn uniformly from 0.5 to 1.5: a fixed
/// wait, spread so that clients refused in one burst do not all come back
/// in the next one (JEP-0002 rule 7). Only for waits this server picks; a
/// rate limit's wait is when a token is back, and is sent as it is.
pub fn jitter(nominal: Duration) -> Duration {
    nominal.mul_f64(0.5 + rand::random::<f64>())
}

/// A wait in whole milliseconds, as `retry_after_ms` carries it: never 0.
pub fn millis(wait: Duration) -> u64 {
    u64::try_from(wait.as_millis()).unwrap_or(u64::MAX).max(1)
}

/// How long the client should wait before posting again, for the ingest
/// failures that waiting changes, before [`jitter`]. Every surface carries a
/// jittered draw of it as `retry_after_ms`; the classifier's message says the
/// same draw ([`classify_with_wait`]).
pub fn retry_after(e: &IngestError) -> Option<Duration> {
    match e {
        IngestError::RenderFailed {
            cause: RenderCause::DeadlineExceeded,
            ..
        } => Some(RENDER_DEADLINE_RETRY),
        _ => None,
    }
}

/// Classify an ingest failure into `(status, error_code, message)`. Callers
/// wrap this triple in whatever JSON body type their endpoint uses.
pub fn classify_ingest_error(e: &IngestError) -> (StatusCode, &'static str, String) {
    classify_with_wait(e, retry_after(e).map(jitter))
}

/// [`classify_ingest_error`], its message naming `wait` for a failure that
/// waiting changes: for a caller that sends the same wait in
/// `retry_after_ms`, so the message and the field agree.
pub fn classify_with_wait(
    e: &IngestError,
    wait: Option<Duration>,
) -> (StatusCode, &'static str, String) {
    match e {
        IngestError::InvalidSignature => (
            StatusCode::UNAUTHORIZED,
            "INVALID_SIG",
            "signature verification failed".to_string(),
        ),
        IngestError::DisallowedBlockKind { kind } => (
            StatusCode::FORBIDDEN,
            "DISALLOWED_BLOCK_KIND",
            format!("kind not in allow list: {kind}"),
        ),
        IngestError::ManifestLog { reason } => {
            (StatusCode::FORBIDDEN, "MANIFEST_LOG", reason.clone())
        }
        IngestError::KindRequired => (
            StatusCode::BAD_REQUEST,
            "KIND_REQUIRED",
            "manifest must declare block kind".to_string(),
        ),
        IngestError::NonCanonicalDid { .. } => {
            (StatusCode::BAD_REQUEST, "NON_CANONICAL_DID", e.to_string())
        }
        IngestError::BundleMalformed(m) => (StatusCode::BAD_REQUEST, "BUNDLE_MALFORMED", m.clone()),
        IngestError::ManifestGate(gate) => (
            StatusCode::BAD_REQUEST,
            match gate {
                jig_core::ManifestGateError::UnsupportedSchema(_) => "UNSUPPORTED_SCHEMA",
                jig_core::ManifestGateError::SuiteNotImplemented(_) => "UNSUPPORTED_SUITE",
            },
            gate.to_string(),
        ),
        // 404, not 400: the request is well-formed, the named channel isn't here.
        IngestError::UnknownChannel { .. } => {
            (StatusCode::NOT_FOUND, "UNKNOWN_CHANNEL", e.to_string())
        }
        // 400: the sender omitted a field its block kind requires (text-render
        // must carry metadata.body). Naming the field is the point — the client
        // cannot fix what it cannot identify.
        IngestError::MissingMetadata { .. } => {
            (StatusCode::BAD_REQUEST, "MISSING_METADATA", e.to_string())
        }
        // 500: this server has no Wasm executor, so it cannot produce a
        // render_hash for the kind. Nothing the client did, nothing it can fix.
        IngestError::NoExecutor { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "NO_EXECUTOR",
            e.to_string(),
        ),
        // 422: the block needs more fuel or stack than this server allows, and it
        // will every time. Resending it unchanged cannot help, so nothing here says
        // it might.
        IngestError::RenderFailed { cause, .. } if cause.is_too_expensive() => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "BLOCK_TOO_EXPENSIVE",
            format!("{e}; the block exceeds this server's render limits"),
        ),
        // 503: the render ran out of wall-clock time, which is this host's load,
        // not the block. Same code as a host fault, so a client that matches on it
        // still does; the status and the wait say this one is worth retrying.
        IngestError::RenderFailed {
            cause: RenderCause::DeadlineExceeded,
            ..
        } => {
            let ms = millis(wait.unwrap_or(RENDER_DEADLINE_RETRY));
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "RENDER_FAILED",
                format!("{e}; this server is busy, try again in {ms} ms (retry_after_ms={ms})"),
            )
        }
        // 500: the host failed (an engine fault, a render task that died, an
        // executor that refused). The block may be fine, so a retry may work.
        IngestError::RenderFailed { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "RENDER_FAILED",
            format!("{e} (may be transient; retry is reasonable)"),
        ),
        // Same code the admin archive path emits for its own owner check, so a
        // client sees one word for "not yours to change" whichever door it used.
        IngestError::DuplicateBlock { .. } => {
            (StatusCode::CONFLICT, "DUPLICATE_BLOCK", e.to_string())
        }
        // 409: the request is fine, the slug is taken. Clients treat it as
        // "already there" (install.sh re-runs rely on that).
        IngestError::ChannelExists { .. } => {
            (StatusCode::CONFLICT, "CHANNEL_EXISTS", e.to_string())
        }
        // 403 and the same word the read gates use: the caller authenticated
        // fine, this server simply will not deal with them.
        // 429, unlike the other refusals: waiting changes the answer.
        IngestError::NotAdmitted {
            refusal: jig_pipeline::ingest::AdmissionRefusal::RateLimited,
            ..
        } => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED", e.to_string()),
        IngestError::NotAdmitted {
            refusal: jig_pipeline::ingest::AdmissionRefusal::ProofRequired { .. },
            ..
        } => (
            StatusCode::FORBIDDEN,
            "PROOF_OF_WORK_REQUIRED",
            e.to_string(),
        ),
        IngestError::NotAdmitted { refusal, .. } => {
            (StatusCode::FORBIDDEN, "NOT_ADMITTED", refusal.to_string())
        }
        // 410, not 404: the channel existed and was deliberately retired, and
        // "create it" would be the wrong advice.
        IngestError::ChannelArchived { .. } => {
            (StatusCode::GONE, "CHANNEL_ARCHIVED", e.to_string())
        }
        IngestError::NotChannelOwner { .. } => {
            (StatusCode::FORBIDDEN, "NOT_CHANNEL_OWNER", e.to_string())
        }
        // Same code the read gate emits, so "not a member here" is one word
        // whether the caller was reading or posting.
        IngestError::NotChannelMember { .. } => {
            (StatusCode::FORBIDDEN, "NOT_A_MEMBER", e.to_string())
        }
        // 409: the request is well-formed, but a channel keeps its owner.
        IngestError::OwnerCannotLeave { .. } => {
            (StatusCode::CONFLICT, "OWNER_CANNOT_LEAVE", e.to_string())
        }
        // 403: this server creates only the channels it sequences (JEP-0005
        // rule 5). Policy, not a malformed request: the same block is fine
        // on the server it names.
        IngestError::NotSequencer { .. } => (StatusCode::FORBIDDEN, "NOT_SEQUENCER", e.to_string()),
        // 400: the block itself lacks a field this server requires.
        IngestError::SequencerRequired { .. } => {
            (StatusCode::BAD_REQUEST, "SEQUENCER_REQUIRED", e.to_string())
        }
        IngestError::BundleTooLarge { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "BUNDLE_TOO_LARGE",
            e.to_string(),
        ),
        // 403: the channel is carried here for the server that sequences it.
        IngestError::CarriedChannel { .. } => {
            (StatusCode::FORBIDDEN, "CARRIED_CHANNEL", e.to_string())
        }
        // 409: a sequencer move this server cannot take the channel over by
        // as it stands (JEP-0005 rule 11a), such as one citing a head it
        // does not hold yet.
        IngestError::MoveRefused { .. } => (StatusCode::CONFLICT, "MOVE_REFUSED", e.to_string()),
        // 409: a key link that has nothing to move here, or would merge two
        // standings, or lands on an encrypted channel (JEP-0005 rule 7b).
        IngestError::KeyLinkRefused { .. } => {
            (StatusCode::CONFLICT, "KEY_LINK_REFUSED", e.to_string())
        }
        // 409: an encrypted channel takes no key link until the MLS leaf
        // swap exists (JEP-0005 rule 7b).
        IngestError::MlsKeyLinkUnsupported { .. } => (
            StatusCode::CONFLICT,
            "MLS_KEY_LINK_UNSUPPORTED",
            e.to_string(),
        ),
        // 409: the owner moved the channel to another server (JEP-0005 rule
        // 11a); the message names it.
        IngestError::SequencerMoved { .. } => {
            (StatusCode::CONFLICT, "SEQUENCER_MOVED", e.to_string())
        }
        // 403: a follower relayed past its share, or past its grant
        // (JEP-0005 rules 7a, 15).
        IngestError::RelayedOutsideShare { .. } => {
            (StatusCode::FORBIDDEN, "RELAY_OUTSIDE_SHARE", e.to_string())
        }
        IngestError::GrantRefused { .. } => (StatusCode::FORBIDDEN, "GRANT_REFUSED", e.to_string()),
        IngestError::InvalidTerms { .. } => {
            (StatusCode::BAD_REQUEST, "INVALID_TERMS", e.to_string())
        }
        // 403: the signer lacks a right as of the block's position in the
        // channel's chain (JEP-0005 rule 7b).
        IngestError::MissingRight { .. } => (StatusCode::FORBIDDEN, "MISSING_RIGHT", e.to_string()),
        // 409: well-formed, but a root owner's role is fixed by the
        // channel's terms.
        IngestError::RootOwnerRole { .. } => {
            (StatusCode::CONFLICT, "ROOT_OWNER_ROLE", e.to_string())
        }
        IngestError::UnknownRole { .. } => (StatusCode::BAD_REQUEST, "UNKNOWN_ROLE", e.to_string()),
        // 403: only the channel's sequencer records what came of a share
        // (JEP-0005 rule 10).
        IngestError::SequencerOnly { .. } => {
            (StatusCode::FORBIDDEN, "SEQUENCER_ONLY", e.to_string())
        }
        IngestError::BadContractBlock { .. } => {
            (StatusCode::BAD_REQUEST, "BAD_CONTRACT_BLOCK", e.to_string())
        }
        // 400: the slug is outside the canonical grammar or in a reserved
        // namespace (`#dm/`, `#jig/`, `#email/`) the author may not use.
        IngestError::InvalidSlug { .. } => (StatusCode::BAD_REQUEST, "INVALID_SLUG", e.to_string()),
        // Same code as the envelope and manifest gates: a suite nobody speaks.
        IngestError::UnknownSuite { .. } => {
            (StatusCode::BAD_REQUEST, "UNSUPPORTED_SUITE", e.to_string())
        }
        IngestError::SuiteMismatch { .. } => {
            (StatusCode::BAD_REQUEST, "SUITE_MISMATCH", e.to_string())
        }
        IngestError::MlsRejected { .. } => (StatusCode::BAD_REQUEST, "MLS_REJECTED", e.to_string()),
        // 400: the request asks for something the protocol does not allow
        // (D25); the message names the two ways to get what was meant.
        IngestError::RestrictedRequiresMls { .. } => (
            StatusCode::BAD_REQUEST,
            "RESTRICTED_REQUIRES_MLS",
            e.to_string(),
        ),
        // 409: the block is fine, the channel's state refuses it, and no
        // retry will change that.
        IngestError::ChannelFrozen { .. } => {
            (StatusCode::CONFLICT, "CHANNEL_FROZEN", e.to_string())
        }
        // 400: the block names no tier this server knows, or an old client
        // asked for a plaintext channel it cannot label (JEP-0014 rule 1).
        IngestError::UnknownTier { .. } => (StatusCode::BAD_REQUEST, "UNKNOWN_TIER", e.to_string()),
        // 400: the tier and the suite contradict each other (rule 3).
        IngestError::TierSuiteMismatch { .. } => (
            StatusCode::BAD_REQUEST,
            "TIER_SUITE_MISMATCH",
            e.to_string(),
        ),
        // 409: the block is well formed; the channel's tier is fixed (rule 2).
        IngestError::TierFixed { .. } => (StatusCode::CONFLICT, "TIER_FIXED", e.to_string()),
        // 403: the client may read the channel, not post to it, until it
        // supports tiers (rule 5).
        IngestError::TierUnsupported { .. } => {
            (StatusCode::FORBIDDEN, "TIER_UNSUPPORTED", e.to_string())
        }
        // 409: the block is well formed; a 1:1 adds nobody (rule 18).
        IngestError::DmIsAPair { .. } => (StatusCode::CONFLICT, "DM_IS_A_PAIR", e.to_string()),
        IngestError::MemberDeclined { .. } => {
            (StatusCode::FORBIDDEN, "MEMBER_DECLINED", e.to_string())
        }
        // 409: someone else committed first. The client catches up and
        // rebuilds; nothing about the request itself was wrong.
        IngestError::StaleEpoch { .. } => (StatusCode::CONFLICT, "STALE_EPOCH", e.to_string()),
        // 400: the sender's clock runs ahead of the bound. An ordinary error,
        // not a contradiction: the message says what time this server has.
        IngestError::ClockSkew { .. } => (StatusCode::BAD_REQUEST, "CLOCK_SKEW", e.to_string()),
        IngestError::Identity(ide) => (StatusCode::UNAUTHORIZED, "IDENTITY_ERROR", ide.to_string()),
        IngestError::Persist(pe) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "PERSIST_ERROR",
            pe.to_string(),
        ),
        IngestError::Other(o) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INGEST_ERROR",
            o.to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v0_0_2_admin::map_ingest_error as admin_map_ingest_error;
    use crate::v0_0_2_blocks::map_ingest_error as blocks_map_ingest_error;

    /// One `IngestError` value per `classify_ingest_error` match arm that can
    /// be constructed locally. `Identity`/`Persist`/`Other` wrap external
    /// crate error types and aren't needed to exercise this classifier.
    fn sample_ingest_errors() -> Vec<IngestError> {
        vec![
            IngestError::InvalidSignature,
            IngestError::DisallowedBlockKind {
                kind: "widget".to_string(),
            },
            IngestError::ManifestLog {
                reason: "not the server".to_string(),
            },
            IngestError::KindRequired,
            IngestError::NonCanonicalDid {
                field: "member_did".to_string(),
            },
            IngestError::BundleMalformed("bad tuple".to_string()),
            IngestError::BundleTooLarge {
                len: jig_core::bundle::MAX_BUNDLE_BYTES + 1,
                max: jig_core::bundle::MAX_BUNDLE_BYTES,
            },
            IngestError::ManifestGate(jig_core::ManifestGateError::UnsupportedSchema(
                "https://example.com/v9".to_string(),
            )),
            IngestError::ManifestGate(jig_core::ManifestGateError::SuiteNotImplemented(
                jig_core::SuiteNotImplemented(jig_core::EncryptionSuite::Mls),
            )),
            IngestError::UnknownChannel {
                slug: "#nope".to_string(),
            },
            IngestError::MissingMetadata {
                kind: "text-render".to_string(),
                field: "body".to_string(),
            },
            IngestError::NoExecutor {
                kind: "text-render".to_string(),
            },
            IngestError::RenderFailed {
                kind: "text-render".to_string(),
                cause: RenderCause::DeadlineExceeded,
                detail: "boom".to_string(),
            },
            IngestError::RenderFailed {
                kind: "text-render".to_string(),
                cause: RenderCause::FuelExhausted,
                detail: "boom".to_string(),
            },
            IngestError::RenderFailed {
                kind: "text-render".to_string(),
                cause: RenderCause::StackExhausted,
                detail: "boom".to_string(),
            },
            IngestError::RenderFailed {
                kind: "text-render".to_string(),
                cause: RenderCause::HostFault,
                detail: "boom".to_string(),
            },
            IngestError::NotChannelOwner {
                kind: "member-add".to_string(),
                slug: "#room".to_string(),
                sender: "did:jig:zStranger".to_string(),
            },
            IngestError::NotChannelMember {
                kind: "text-render".to_string(),
                slug: "#room".to_string(),
                sender: "did:jig:zStranger".to_string(),
            },
            IngestError::DuplicateBlock {
                cid: "bafy_twice".to_string(),
            },
            IngestError::ChannelArchived {
                slug: "#retired".to_string(),
            },
            IngestError::ChannelExists {
                slug: "#taken".to_string(),
            },
            IngestError::NotAdmitted {
                sender: "did:jig:zBad".to_string(),
                refusal: jig_pipeline::ingest::AdmissionRefusal::Banned,
            },
            IngestError::OwnerCannotLeave {
                slug: "#mine".to_string(),
            },
            IngestError::UnknownSuite {
                suite: "rot13".to_string(),
            },
            IngestError::SuiteMismatch {
                slug: "#sealed".to_string(),
                channel: "mls".to_string(),
                block: "none".to_string(),
            },
            IngestError::MlsRejected {
                detail: "not a commit".to_string(),
            },
            IngestError::RestrictedRequiresMls {
                slug: "#private".to_string(),
            },
            IngestError::ChannelFrozen {
                slug: "#old".to_string(),
            },
            IngestError::UnknownTier {
                tier: "none".to_string(),
            },
            IngestError::TierSuiteMismatch {
                tier: "public",
                suite: "mls".to_string(),
            },
            IngestError::TierFixed {
                kind: "channel-promote".to_string(),
                slug: "#team".to_string(),
            },
            IngestError::TierUnsupported {
                slug: "#news".to_string(),
            },
            IngestError::DmIsAPair {
                slug: "#dm/0123456789abcdef".to_string(),
                member: "did:jig:zThird".to_string(),
            },
            IngestError::MemberDeclined {
                slug: "#team".to_string(),
                member: "did:jig:zBob".to_string(),
            },
            IngestError::StaleEpoch {
                slug: "#sealed".to_string(),
                current: 2,
                got: 1,
            },
            IngestError::ClockSkew {
                ahead_ms: 600_000,
                bound_ms: 300_000,
                server_ms: 1,
            },
            IngestError::NotSequencer {
                sequencer: "did:jig:zElsewhere".to_string(),
                server: "did:jig:zHere".to_string(),
            },
            IngestError::SequencerRequired {
                server: "did:jig:zHere".to_string(),
            },
            IngestError::CarriedChannel {
                kind: "text-render".to_string(),
                channel_id: "bafy-carried".to_string(),
                sequencer: "did:jig:zElsewhere".to_string(),
            },
            IngestError::RelayedOutsideShare {
                kind: "text-render".to_string(),
                channel_id: "bafy-other".to_string(),
                via: "did:jig:zFollower".to_string(),
            },
            IngestError::GrantRefused {
                kind: "member-add".to_string(),
                grant: "write",
                via: "did:jig:zFollower".to_string(),
            },
            IngestError::InvalidTerms {
                field: "co_owners".to_string(),
                detail: "not an array".to_string(),
            },
            IngestError::MissingRight {
                kind: "role-assign".to_string(),
                slug: "#room".to_string(),
                sender: "did:jig:zAdmin".to_string(),
                right: "owner".to_string(),
            },
            IngestError::RootOwnerRole {
                slug: "#room".to_string(),
                member: "did:jig:zOwner".to_string(),
            },
            IngestError::UnknownRole {
                role: "owner".to_string(),
            },
            IngestError::SequencerOnly {
                kind: "contract-accept".to_string(),
                slug: "#room".to_string(),
                sender: "did:jig:zMember".to_string(),
            },
            IngestError::BadContractBlock {
                kind: "channel-share".to_string(),
                detail: "`to` is missing".to_string(),
            },
            IngestError::InvalidSlug {
                slug: "#General".to_string(),
                reason: "uppercase".to_string(),
            },
        ]
    }

    fn render_failed(cause: RenderCause) -> IngestError {
        IngestError::RenderFailed {
            kind: "text-render".to_string(),
            cause,
            detail: "the render is incomplete".to_string(),
        }
    }

    /// A block too expensive for this server is a 422 that never suggests a
    /// retry; a missed deadline is a 503 that says how long to wait; a host
    /// fault keeps the 500 it always had.
    #[test]
    fn a_render_failure_is_classified_by_its_cause() {
        for cause in [RenderCause::FuelExhausted, RenderCause::StackExhausted] {
            let (status, code, message) = classify_ingest_error(&render_failed(cause));
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{cause:?}");
            assert_eq!(code, "BLOCK_TOO_EXPENSIVE", "{cause:?}");
            assert!(
                !message.contains("transient") && !message.contains("retry"),
                "{cause:?}: {message}"
            );
        }

        let (status, code, message) =
            classify_ingest_error(&render_failed(RenderCause::DeadlineExceeded));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "RENDER_FAILED");
        let said = message
            .rsplit_once("(retry_after_ms=")
            .and_then(|(_, ms)| ms.strip_suffix(')'))
            .and_then(|ms| ms.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("{message}"));
        assert!((500..=1500).contains(&said), "{message}");
        assert_eq!(
            retry_after(&render_failed(RenderCause::DeadlineExceeded)),
            Some(RENDER_DEADLINE_RETRY)
        );
        for cause in [
            RenderCause::FuelExhausted,
            RenderCause::StackExhausted,
            RenderCause::HostFault,
        ] {
            assert_eq!(retry_after(&render_failed(cause)), None, "{cause:?}");
        }
        // REST carries the wait in its body, as WS does in its Error frame.
        let (_, body) = blocks_map_ingest_error(render_failed(RenderCause::DeadlineExceeded));
        let wait = body.0.retry_after_ms.expect("a wait");
        assert!((500..=1500).contains(&wait), "{wait}");
        assert!(
            body.0
                .message
                .ends_with(&format!("(retry_after_ms={wait})")),
            "the message names the wait the field carries: {}",
            body.0.message
        );
        let (_, body) = blocks_map_ingest_error(render_failed(RenderCause::FuelExhausted));
        assert_eq!(body.0.retry_after_ms, None);

        let (status, code, message) = classify_ingest_error(&render_failed(RenderCause::HostFault));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(code, "RENDER_FAILED");
        assert!(message.contains("may be transient"), "{message}");
    }

    #[test]
    fn a_declined_member_add_is_forbidden() {
        let (status, code, _) = classify_ingest_error(&IngestError::MemberDeclined {
            slug: "#team".to_string(),
            member: "did:jig:zBob".to_string(),
        });
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code, "MEMBER_DECLINED");
    }

    #[test]
    fn a_dm_that_would_grow_is_a_conflict() {
        let (status, code, _) = classify_ingest_error(&IngestError::DmIsAPair {
            slug: "#dm/0123456789abcdef".to_string(),
            member: "did:jig:zThird".to_string(),
        });
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(code, "DM_IS_A_PAIR");
    }

    /// The property this module exists to guarantee: the REST (`v0_0_2_blocks`)
    /// and admin (`v0_0_2_admin`) wrappers must classify every `IngestError`
    /// identically — same status, same error code — differing only in which
    /// JSON body type carries the message.
    #[test]
    fn blocks_and_admin_wrappers_classify_identically() {
        for (a, b) in sample_ingest_errors()
            .into_iter()
            .zip(sample_ingest_errors())
        {
            let label = a.to_string();
            let (blocks_status, blocks_body) = blocks_map_ingest_error(a);
            let (admin_status, admin_body) = admin_map_ingest_error(b);
            assert_eq!(
                blocks_status, admin_status,
                "status mismatch classifying: {label}"
            );
            assert_eq!(
                blocks_body.0.code, admin_body.0.code,
                "code mismatch classifying: {label}"
            );
        }
    }

    /// A fixed wait is spread over half to one and a half times itself, so
    /// that clients refused together come back apart.
    #[test]
    fn a_fixed_wait_is_spread_around_its_nominal_value() {
        let nominal = Duration::from_millis(1000);
        let draws: Vec<u64> = (0..2000).map(|_| millis(jitter(nominal))).collect();
        assert!(
            draws.iter().all(|ms| (500..=1500).contains(ms)),
            "{draws:?}"
        );
        // Both halves are used: not a constant, not one-sided.
        assert!(draws.iter().any(|&ms| ms < 750), "{draws:?}");
        assert!(draws.iter().any(|&ms| ms > 1250), "{draws:?}");
        // A burst of 16 refusals lands on more than a handful of distinct
        // milliseconds, where the fixed wait put them all on one.
        let mut first: Vec<u64> = draws[..16].to_vec();
        first.sort_unstable();
        first.dedup();
        assert!(first.len() > 8, "{first:?}");
        assert_eq!(millis(Duration::ZERO), 1);
    }
}
