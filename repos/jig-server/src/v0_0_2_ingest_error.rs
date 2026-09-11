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
        IngestError::KindRequired => (
            StatusCode::BAD_REQUEST,
            "KIND_REQUIRED",
            "manifest must declare block kind".to_string(),
        ),
        IngestError::BundleMalformed(m) => (StatusCode::BAD_REQUEST, "BUNDLE_MALFORMED", m.clone()),
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
        // 403 and the same word the read gates use: the caller authenticated
        // fine, this server simply will not deal with them.
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
            IngestError::KindRequired,
            IngestError::BundleMalformed("bad tuple".to_string()),
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
            IngestError::NotAdmitted {
                sender: "did:jig:zBad".to_string(),
                refusal: jig_pipeline::ingest::AdmissionRefusal::Banned,
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
