//! `jig tail <channel>` — Phase F5 of v0.0.2 hello-world.
//!
//! Connects via WSS, subscribes to the named channel slug, decodes each
//! delivered block, and prints `<wall_ms>  <sender_did>  <body><parity>`.
//! Blocks until the connection drops (Ctrl-C to exit).
//!
//! Replaces the v0.0.1 HTTP-polling tail (`commands::tail_messages`),
//! which is now removed. The polling implementation was a stopgap before
//! the WSS subscription pipeline landed in Phase D.
//!
//! Render-parity marker:
//!   * 0 or 1 distinct `render_hash` values across the delivered receipts —
//!     no marker (the common case).
//!   * 2+ distinct values — append `"  ⚠ render mismatch (N hashes)"` so
//!     the operator sees that the producing servers disagreed on the
//!     rendered output. (v0.0.2 has only one server in the demo, so this
//!     should never fire; the wiring is here for v0.0.3+ federation.)

use anyhow::{Context, Result};
use jig_client::{Client, DeliveredBlock};

use crate::cmd::blocks_decode::decode;
#[cfg(test)]
use crate::cmd::blocks_decode::distinct_render_hashes;
use crate::cmd::common::{load_active_identity, load_server_url};

/// Apply `jig tail <channel>`.
pub async fn run(channel: String) -> Result<()> {
    let id = load_active_identity()?;
    let server_url = load_server_url()?;

    let client = Client::connect(&server_url, id)
        .await
        .with_context(|| format!("connecting to {server_url}"))?;

    let mut stream = client
        .subscribe_channel(&channel)
        .await
        .with_context(|| format!("subscribing to {channel}"))?;

    println!("Tailing {channel} on {server_url}... (Ctrl-C to exit)");
    while let Some(delivered) = stream.next().await {
        match decode_and_format(&delivered) {
            Ok(line) => println!("{line}"),
            // Best-effort: skip blocks we can't decode rather than panicking
            // the whole tail. Operators get a one-line diagnostic so they
            // know data was dropped.
            Err(e) => eprintln!("[skip block: {e}]"),
        }
    }
    Ok(())
}

/// Decode a delivered block bundle and format the one-line summary.
///
/// Delegates the heavy lifting (b64 + manifest parsing + receipt
/// dedupe) to `blocks_decode::decode` — shared with `jig chat`. This
/// function only owns the textual line format `<ts>  <sender>  <body>`
/// plus the optional render-parity warning suffix.
fn decode_and_format(d: &DeliveredBlock) -> Result<String> {
    let decoded = decode(d)?;
    let parity = render_parity_marker_from_count(decoded.parity_hash_count);
    Ok(format!(
        "{ts}  {sender}  {body}{parity}",
        ts = decoded.ts,
        sender = decoded.sender,
        body = decoded.body,
    ))
}

/// Compute the render-parity marker string from a distinct-hash count.
///
/// Returns an empty string for 0 or 1 distinct hashes (the common case)
/// and an explicit `⚠ render mismatch (N hashes)` warning otherwise.
fn render_parity_marker_from_count(n: usize) -> String {
    match n {
        0 | 1 => String::new(),
        n => format!("  ⚠ render mismatch ({n} hashes)"),
    }
}

/// Backwards-compat wrapper for tests that exercised the old API by
/// passing a receipt slice. Inlines the distinct-hash computation so
/// the parity-marker test cases keep working unchanged.
#[cfg(test)]
fn render_parity_marker(receipts: &[jig_client::envelope::ReceiptRef]) -> String {
    render_parity_marker_from_count(distinct_render_hashes(receipts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use jig_client::Identity;
    use jig_client::blocks::build_text_render;
    use jig_client::envelope::ReceiptRef;
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

    #[test]
    fn decode_and_format_extracts_sender_body_and_ts() {
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
        let line = decode_and_format(&d).unwrap();

        assert!(
            line.contains("1747680000000"),
            "wall_ms must appear: {line}"
        );
        assert!(
            line.contains(&did.to_did_jig_string()),
            "sender DID must appear: {line}"
        );
        assert!(line.contains("hi there"), "body must appear: {line}");
        assert!(
            !line.contains("⚠"),
            "no parity marker for zero-receipt deliveries: {line}"
        );
    }

    #[test]
    fn decode_and_format_handles_missing_hlc() {
        // Hand-roll a manifest with `hlc_ts: None` to confirm the
        // fallback `ts = 0` doesn't panic. (build_text_render always sets
        // hlc_ts, so we go through the manifest builder directly.)
        use jig_core::{Author, BlockKind, BlockManifest};
        use serde_json::json;
        let id = test_identity();
        let mut builder = BlockManifest::builder()
            .version(semver::Version::new(0, 1, 0))
            .author(Author {
                did: id.did().clone(),
                public_key: None,
                roles: vec![],
            });
        builder = builder.metadata_entry("channel", json!("#hello"));
        builder = builder.metadata_entry("body", json!("no clock"));
        let manifest = builder.build().unwrap().with_kind(BlockKind::TextRender);
        let manifest_bytes = manifest.to_canonical_bytes().unwrap();
        let bundle = (manifest_bytes, Vec::<u8>::new());
        let canonical = serde_json::to_vec(&bundle).unwrap();
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(canonical);

        let d = delivered_for(bundle_b64, vec![]);
        let line = decode_and_format(&d).unwrap();
        // Wall-clock fallback is `0` — the line must start with `0  `.
        assert!(line.starts_with("0  "), "ts fallback should be 0: {line}");
        assert!(line.contains("no clock"));
    }

    #[test]
    fn decode_and_format_reports_skip_on_invalid_b64() {
        let d = delivered_for("not_base64_!!!".into(), vec![]);
        let err = decode_and_format(&d).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("decoding bundle_b64"),
            "expected b64 context: {msg}"
        );
    }

    fn rr(server: &str, render_hash: Option<&str>) -> ReceiptRef {
        ReceiptRef {
            server_did: server.into(),
            render_hash: render_hash.map(str::to_string),
            receipt_bytes_b64: "cmI=".into(),
        }
    }

    #[test]
    fn parity_marker_empty_for_zero_receipts() {
        assert_eq!(render_parity_marker(&[]), "");
    }

    #[test]
    fn parity_marker_empty_for_one_receipt() {
        let receipts = vec![rr("did:jig:zA", Some("h1"))];
        assert_eq!(render_parity_marker(&receipts), "");
    }

    #[test]
    fn parity_marker_empty_for_matching_hashes() {
        let receipts = vec![rr("did:jig:zA", Some("h1")), rr("did:jig:zB", Some("h1"))];
        assert_eq!(render_parity_marker(&receipts), "");
    }

    #[test]
    fn parity_marker_flags_mismatch_for_two_distinct_hashes() {
        let receipts = vec![rr("did:jig:zA", Some("h1")), rr("did:jig:zB", Some("h2"))];
        assert_eq!(
            render_parity_marker(&receipts),
            "  ⚠ render mismatch (2 hashes)"
        );
    }

    #[test]
    fn parity_marker_counts_distinct_hashes_not_receipts() {
        // Three receipts but only two distinct hash values — the marker
        // should say "(2 hashes)", not "(3)".
        let receipts = vec![
            rr("did:jig:zA", Some("h1")),
            rr("did:jig:zB", Some("h2")),
            rr("did:jig:zC", Some("h1")),
        ];
        assert_eq!(
            render_parity_marker(&receipts),
            "  ⚠ render mismatch (2 hashes)"
        );
    }

    #[test]
    fn parity_marker_ignores_receipts_without_render_hash() {
        // Synthetic receipts (no Wasm execution) have `render_hash: None`
        // and should never trigger the marker.
        let receipts = vec![
            rr("did:jig:zA", None),
            rr("did:jig:zB", None),
            rr("did:jig:zC", Some("h1")),
        ];
        assert_eq!(render_parity_marker(&receipts), "");
    }
}
