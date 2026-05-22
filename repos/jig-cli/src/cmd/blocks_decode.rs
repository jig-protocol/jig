//! Shared decoder for blocks delivered over WSS.
//!
//! Both `jig tail` and `jig chat` need the same logic: turn a
//! `DeliveredBlock` (raw `bundle_b64` + receipt vec) into the four
//! presentation fields a UI cares about — sender DID, message body,
//! wall-clock timestamp, and whether the receipts disagree on the
//! rendered output. Keeping the decoder here means a bug fix shows
//! up in both surfaces.
//!
//! `tail.rs` formats `DecodedBlock` into its single-line text output;
//! `chat.rs` stuffs it into the `Message` struct rendered by ratatui.

use anyhow::{Context, Result};
use base64::Engine as _;
use jig_client::{DeliveredBlock, envelope::ReceiptRef};
use jig_core::BlockManifest;
use std::collections::HashSet;

/// Presentation-layer view of a delivered block. All fields are owned so
/// the originating `DeliveredBlock` can be dropped immediately.
#[derive(Debug, Clone)]
pub struct DecodedBlock {
    /// Canonical sender DID string (e.g. `did:jig:zABC...`) or
    /// `"<no-author>"` if the manifest is missing an authors entry.
    pub sender: String,
    /// Message body extracted from `manifest.metadata["body"]`. Falls
    /// back to `"<no-body>"` when absent.
    pub body: String,
    /// Wall-clock timestamp in milliseconds. Zero when the manifest
    /// doesn't include an HLC (synthetic blocks during early bring-up).
    /// Matches `HlcTimestamp::wall_ms` (`u64`).
    pub ts: u64,
    /// True when 2+ distinct render hashes were observed across the
    /// receipts — i.e. servers disagreed on the rendered output. v0.0.2
    /// is single-server so this should never fire; v0.0.3+ federation
    /// is the real use case.
    pub parity_warning: bool,
    /// Number of distinct render hashes — populated alongside
    /// `parity_warning` so tail.rs can keep emitting "(N hashes)".
    pub parity_hash_count: usize,
}

/// Decode a delivered block bundle into a `DecodedBlock`.
///
/// Bundle layout (must match `jig_client::blocks::BuiltBlock::canonical_bytes`):
///   * `bundle_b64` decodes to JSON-encoded `(manifest_bytes, code_bytes)`.
///   * `manifest_bytes` decodes to `BlockManifest`.
///   * Body lives at `manifest.metadata["body"]` (a JSON string).
///   * Sender DID is `manifest.authors[0].did`.
///   * Wall-clock timestamp comes from `manifest.hlc_ts.wall_ms` if set.
pub fn decode(d: &DeliveredBlock) -> Result<DecodedBlock> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&d.bundle_b64)
        .context("decoding bundle_b64")?;
    let (manifest_bytes, _code_bytes): (Vec<u8>, Vec<u8>) =
        serde_json::from_slice(&raw).context("decoding bundle tuple")?;
    let manifest: BlockManifest =
        serde_json::from_slice(&manifest_bytes).context("decoding block manifest")?;

    let sender = manifest
        .authors
        .first()
        .map(|a| a.did.to_did_jig_string())
        .unwrap_or_else(|| "<no-author>".into());
    let body = manifest
        .metadata
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("<no-body>")
        .to_string();
    let ts = manifest.hlc_ts.as_ref().map(|t| t.wall_ms).unwrap_or(0);
    let parity_hash_count = distinct_render_hashes(&d.receipts);
    let parity_warning = parity_hash_count >= 2;
    Ok(DecodedBlock {
        sender,
        body,
        ts,
        parity_warning,
        parity_hash_count,
    })
}

/// Count the distinct `render_hash` values across a receipt slice.
///
/// `None` render hashes are ignored (synthetic receipts produced before
/// Wasm execution lands carry no hash and shouldn't trigger a warning).
pub fn distinct_render_hashes(receipts: &[ReceiptRef]) -> usize {
    let hashes: HashSet<&str> = receipts
        .iter()
        .filter_map(|r| r.render_hash.as_deref())
        .collect();
    hashes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_client::Identity;
    use jig_client::blocks::build_text_render;
    use jig_core::HlcTimestamp;
    use tempfile::tempdir;

    fn test_identity() -> Identity {
        let dir = tempdir().unwrap();
        let path = dir.keep();
        Identity::generate_and_save(&path).unwrap()
    }

    fn delivered_for(bundle_b64: String, receipts: Vec<ReceiptRef>) -> DeliveredBlock {
        DeliveredBlock {
            bundle_b64,
            receipts,
            delivery_cid: "bafy_test_delivery".into(),
        }
    }

    fn rr(server: &str, render_hash: Option<&str>) -> ReceiptRef {
        ReceiptRef {
            server_did: server.into(),
            render_hash: render_hash.map(str::to_string),
            receipt_bytes_b64: "cmI=".into(),
        }
    }

    #[test]
    fn decode_extracts_sender_body_and_ts() {
        let id = test_identity();
        let did = id.did().clone();
        let hlc = HlcTimestamp {
            wall_ms: 1_747_680_000_000,
            logical: 0,
            server_did: did.clone(),
        };
        let block = build_text_render(&id, "#hello", "hi there", hlc);
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes());

        let d = delivered_for(bundle_b64, vec![]);
        let decoded = decode(&d).unwrap();

        assert_eq!(decoded.ts, 1_747_680_000_000);
        assert_eq!(decoded.sender, did.to_did_jig_string());
        assert_eq!(decoded.body, "hi there");
        assert!(!decoded.parity_warning);
        assert_eq!(decoded.parity_hash_count, 0);
    }

    #[test]
    fn decode_reports_parity_warning_on_distinct_hashes() {
        let id = test_identity();
        let did = id.did().clone();
        let hlc = HlcTimestamp {
            wall_ms: 1,
            logical: 0,
            server_did: did.clone(),
        };
        let block = build_text_render(&id, "#hello", "x", hlc);
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes());

        let receipts = vec![rr("did:jig:zA", Some("h1")), rr("did:jig:zB", Some("h2"))];
        let d = delivered_for(bundle_b64, receipts);
        let decoded = decode(&d).unwrap();
        assert!(decoded.parity_warning);
        assert_eq!(decoded.parity_hash_count, 2);
    }

    #[test]
    fn decode_reports_invalid_b64() {
        let d = delivered_for("not_base64_!!!".into(), vec![]);
        let err = decode(&d).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("decoding bundle_b64"), "context: {msg}");
    }

    #[test]
    fn distinct_render_hashes_ignores_none_hashes() {
        let receipts = vec![
            rr("did:jig:zA", None),
            rr("did:jig:zB", None),
            rr("did:jig:zC", Some("h1")),
        ];
        assert_eq!(distinct_render_hashes(&receipts), 1);
    }

    #[test]
    fn distinct_render_hashes_dedupes_matching_hashes() {
        let receipts = vec![
            rr("did:jig:zA", Some("h1")),
            rr("did:jig:zB", Some("h1")),
            rr("did:jig:zC", Some("h2")),
        ];
        assert_eq!(distinct_render_hashes(&receipts), 2);
    }
}
