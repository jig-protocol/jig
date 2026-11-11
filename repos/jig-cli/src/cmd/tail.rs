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

use std::collections::BTreeMap;

use std::sync::Arc;

use anyhow::{Context, Result};
#[cfg(test)]
use jig_client::DeliveredBlock;

use crate::cmd::blocks_decode::DecodedBlock;
#[cfg(test)]
use crate::cmd::blocks_decode::decode;
#[cfg(test)]
use crate::cmd::blocks_decode::distinct_render_hashes;
use crate::cmd::common::CliContext;
use crate::cmd::display::{bell_on_inbound, display_sender, format_hhmm};
use crate::cmd::follow::{Event, Feed, Follower, Live};
use crate::cmd::history;
use crate::cmd::reader::Reader;

/// Apply `jig tail <channel>`.
pub async fn run(ctx: &CliContext, channel: String) -> Result<()> {
    let id = ctx.identity()?;
    let server_url = ctx.server_url()?;

    let contacts = ctx.effective().contacts.clone();

    // Subscribe before reading the backlog: anything posted meanwhile queues
    // on the stream, and the follower skips what the backlog already showed.
    // The backlog used to come first, and a block posted between the two was
    // never shown. An encrypted channel replays through the MLS session.
    let reader = Arc::new(Reader::open(ctx, &channel).await?);
    let client = crate::cmd::secure::connect_pinned(&server_url, id)
        .await
        .with_context(|| format!("connecting to {server_url}"))?;
    let client = Arc::new(client);
    let feed = Live {
        client: client.clone(),
        server_url: server_url.clone(),
        slug: channel.clone(),
    };
    let stream = feed.subscribe().await?;

    // Failures here degrade to "no backlog" (see `history::backfill`) rather
    // than aborting the tail.
    let backlog = reader.backlog(client.identity(), &server_url).await?;
    reader.tidy(backlog.tidy);
    for line in backfill_lines(&backlog.lines, &contacts) {
        println!("{line}");
    }
    // No bell for replayed history — the operator was not present for it.
    println!("Tailing {channel} on {server_url}... (Ctrl-C to exit)");
    let mut follower = Follower::new(feed, stream, reader, &channel, backlog.deliveries);
    let ended = pump(&mut follower, &contacts).await;
    match crate::cmd::trust::live_contradiction(&client, &server_url) {
        Some(e) => Err(e),
        None => ended,
    }
}

/// Apply `jig read <channel>`: print the channel's recent messages and exit.
pub async fn read(ctx: &CliContext, channel: String, limit: usize, json: bool) -> Result<()> {
    let id = ctx.identity()?;
    let server_url = ctx.server_url()?;
    let reader = Reader::open(ctx, &channel).await?;
    // Unlike chat and tail, a failed fetch is this command's failure, not
    // something to degrade around.
    let lines = if let Some(secure) = reader.secure() {
        let synced = secure.recent(&channel, limit).await?;
        // Awaited, not spawned: this process exits as soon as it has printed.
        for did in &synced.tidy {
            let _ = secure.tidy(&channel, did).await;
        }
        synced
            .lines
            .into_iter()
            .filter(|d| d.is_message())
            .collect()
    } else {
        let blocks = history::fetch_history(&id, &server_url, &channel, limit).await?;
        crate::cmd::trust::check_history(&id, &server_url, &channel, &blocks).await?;
        history::decode_history(&blocks)
    };
    let skip = lines.len().saturating_sub(limit);
    let contacts = ctx.effective().contacts.clone();
    for d in &lines[skip..] {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "sender": d.sender,
                    "body": d.body,
                    "ts": d.ts,
                    "kind": d.kind.map(|k| k.as_str()),
                })
            );
        } else {
            println!("{}", format_decoded(d, &contacts));
        }
    }
    Ok(())
}

/// Print everything the follower yields, until it ends.
///
/// Always terminates in an `Err`: a follower only ends on a closed
/// connection, or on falling behind with no way to catch up, and `jig tail`
/// exiting 0 on either is precisely the silent-success bug this replaces.
async fn pump<F: Feed>(
    follower: &mut Follower<F>,
    contacts: &BTreeMap<String, String>,
) -> Result<()> {
    loop {
        match follower.next().await? {
            Event::Line(decoded) => {
                println!("{}", format_decoded(&decoded, contacts));
                bell_on_inbound(1, &mut std::io::stderr());
            }
            // Best-effort: skip blocks we can't decode rather than panicking
            // the whole tail. Operators get a one-line diagnostic so they
            // know data was dropped.
            Event::Unreadable(e) => eprintln!("[skip block: {e}]"),
            Event::CaughtUp { blocks } => {
                eprintln!("[fell behind; caught up {blocks} blocks from history]")
            }
        }
    }
}

/// Decode a delivered block bundle and format the one-line summary.
///
/// Delegates the heavy lifting (b64 + manifest parsing + receipt
/// dedupe) to `blocks_decode::decode` — shared with `jig chat`. This
/// function only owns the textual line format `HH:MM  <sender>: <body>`
/// plus the optional render-parity warning suffix.
///
/// `contacts` is the local `[contacts]` address book; senders with no entry
/// fall back to a truncated DID.
#[cfg(test)]
fn decode_and_format(d: &DeliveredBlock, contacts: &BTreeMap<String, String>) -> Result<String> {
    Ok(format_decoded(&decode(d)?, contacts))
}

/// Format one already-decoded block. Shared by the live stream and the
/// replayed backlog so history and live traffic look identical.
fn format_decoded(decoded: &DecodedBlock, contacts: &BTreeMap<String, String>) -> String {
    let parity = render_parity_marker_from_count(decoded.parity_hash_count);
    if decoded.sender == crate::cmd::blocks_decode::SYSTEM {
        return format!("{}  * {}", format_hhmm(decoded.ts), decoded.body);
    }
    format!(
        "{ts}  {sender}: {body}{parity}",
        ts = format_hhmm(decoded.ts),
        sender = display_sender(contacts, &decoded.sender),
        body = decoded.body,
    )
}

/// Render a fetched backlog, oldest first.
fn backfill_lines(backlog: &[DecodedBlock], contacts: &BTreeMap<String, String>) -> Vec<String> {
    backlog
        .iter()
        .map(|d| format_decoded(d, contacts))
        .collect()
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
        Identity::generate_for_tests(&path)
    }

    fn delivered_for(bundle_b64: String, receipts: Vec<ReceiptRef>) -> DeliveredBlock {
        DeliveredBlock {
            sig_b64: None,
            bundle_b64,
            receipts,
            delivery_cid: "bafy_test_delivery".into(),
            ingest: None,
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
        let line = decode_and_format(&d, &BTreeMap::new()).unwrap();

        assert!(
            !line.contains("1747680000000"),
            "raw epoch millis must not be printed: {line}"
        );
        assert!(
            line.starts_with(&crate::cmd::display::format_hhmm(1_747_680_000_000)),
            "line must open with the HH:MM clock: {line}"
        );
        assert!(
            !line.contains(&did.to_did_jig_string()),
            "the full 61-char DID must not be printed: {line}"
        );
        assert!(
            line.contains(&crate::cmd::display::shorten_did(&did.to_did_jig_string())),
            "shortened sender must appear: {line}"
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
        let line = decode_and_format(&d, &BTreeMap::new()).unwrap();
        // Wall-clock fallback is `0`, which renders as the `--:--` placeholder
        // rather than a misleading epoch-zero clock time.
        assert!(
            line.starts_with("--:--  "),
            "missing HLC should render as --:--: {line}"
        );
        assert!(line.contains("no clock"));
    }

    #[test]
    fn decode_and_format_renders_a_contact_name_when_one_is_configured() {
        let id = test_identity();
        let did = id.did().clone();
        let hlc = HlcTimestamp {
            wall_ms: 1_747_680_000_000,
            logical: 0,
            server_did: did.clone(),
        };
        let block = build_text_render(&id, "#hello", "yo", hlc);
        let bundle_b64 = base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes());

        let contacts: BTreeMap<String, String> =
            [(did.to_did_jig_string(), "dj".to_string())].into();
        let d = delivered_for(bundle_b64, vec![]);
        let line = decode_and_format(&d, &contacts).unwrap();
        assert!(line.contains("  dj: yo"), "contact name must win: {line}");
    }

    #[test]
    fn decode_and_format_reports_skip_on_invalid_b64() {
        let d = delivered_for("not_base64_!!!".into(), vec![]);
        let err = decode_and_format(&d, &BTreeMap::new()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bundle_b64"), "expected b64 context: {msg}");
    }

    fn rr(server: &str, render_hash: Option<&str>) -> ReceiptRef {
        ReceiptRef {
            server_did: server.into(),
            render_hash: render_hash.map(str::to_string),
            receipt_bytes_b64: "cmI=".into(),
        }
    }

    #[test]
    fn backfill_lines_render_oldest_first() {
        // `jig tail` on a busy channel used to sit silent until someone
        // spoke; the replayed backlog must come out in timeline order.
        let backlog = vec![
            DecodedBlock {
                sender: "did:jig:zAAAA".into(),
                body: "first".into(),
                ts: 1_747_680_000_000,
                parity_warning: false,
                parity_hash_count: 0,
                kind: Some(jig_core::BlockKind::TextRender),
            },
            DecodedBlock {
                sender: "did:jig:zAAAA".into(),
                body: "second".into(),
                ts: 1_747_680_060_000,
                parity_warning: false,
                parity_hash_count: 0,
                kind: Some(jig_core::BlockKind::TextRender),
            },
        ];
        let lines = backfill_lines(&backlog, &BTreeMap::new());
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("first"), "got {}", lines[0]);
        assert!(lines[1].ends_with("second"), "got {}", lines[1]);
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
