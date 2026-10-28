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
use jig_pipeline::ingest::IngestError;

/// Classify an ingest failure into `(status, error_code, message)`. Callers
/// wrap this triple in whatever JSON body type their endpoint uses.
pub fn classify_ingest_error(e: &IngestError) -> (StatusCode, &'static str, String) {
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
        // 500: the block was acceptable and executing it failed here. May be
        // transient, so the message says so rather than implying a bad request.
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
        IngestError::BundleTooLarge { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "BUNDLE_TOO_LARGE",
            e.to_string(),
        ),
        // 403: the channel is carried here for the server that sequences it.
        IngestError::CarriedChannel { .. } => {
            (StatusCode::FORBIDDEN, "CARRIED_CHANNEL", e.to_string())
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
}
