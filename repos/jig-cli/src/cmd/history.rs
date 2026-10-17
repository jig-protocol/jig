//! Channel backfill for `jig chat` and `jig tail`.
//!
//! Opening a channel used to show an empty pane no matter how much had
//! already been said in it: the WSS subscription only carries blocks that
//! arrive *after* you connect. This module fetches the tail of the channel
//! timeline over REST (`GET /api/v1/channels/:slug/blocks?limit=N`) so the
//! first frame has context in it.
//!
//! Two properties matter and are enforced here rather than at the call
//! sites:
//!   * the fetch is a plain async fn, callable **before** the terminal is
//!     put into raw mode — a network error prints as normal text instead of
//!     scribbling over the alternate screen;
//!   * a failure degrades to an empty backlog with a warning. A server that
//!     predates the history endpoint answers 404, and that must not make the
//!     client unusable.

use anyhow::{Context, Result};
use jig_client::read_auth::{ReadProof, signable_path};
use jig_client::{DeliveredBlock, Identity};

use crate::cmd::blocks_decode::{DecodedBlock, decode};
use crate::cmd::channel::{base_http_url, escape_slug_for_url};

/// How much history a fresh pane opens with. The server clamps to its own
/// `MAX_HISTORY_LIMIT` (200), so this is a client-side preference, not a
/// bound.
pub const DEFAULT_HISTORY_LIMIT: usize = 100;

/// Build the history URL for a channel slug.
pub fn history_url(base_url: &str, channel: &str, limit: usize) -> String {
    let base = base_http_url(base_url);
    let slug = escape_slug_for_url(channel);
    format!("{base}/api/v1/channels/{slug}/blocks?limit={limit}")
}

/// Parse a history response body into delivered blocks, signatures
/// included — every block is verified before it is shown.
pub fn parse_history(body: &str) -> Result<Vec<DeliveredBlock>> {
    serde_json::from_str(body).context("decoding channel history response")
}

/// Decode a fetched backlog, dropping entries that cannot be decoded.
///
/// A single malformed historical block must not cost the operator the whole
/// backlog, so failures are skipped with a diagnostic rather than
/// propagated.
pub fn decode_history(blocks: &[DeliveredBlock]) -> Vec<DecodedBlock> {
    blocks
        .iter()
        .filter_map(|b| match decode(b) {
            // Control blocks (channel-create, member-add, …) live on the
            // same timeline; replaying them as chat lines is noise.
            Ok(d) if !d.is_message() => None,
            Ok(d) => Some(d),
            Err(e) => {
                eprintln!("[skip history block {}: {e}]", b.delivery_cid);
                None
            }
        })
        .collect()
}

/// Fetch the last `limit` blocks of a channel, as `who`.
///
/// Signed: the server requires proof of possession on every read, and a
/// restricted channel's history is only served to its members.
pub async fn fetch_history(
    who: &Identity,
    base_url: &str,
    channel: &str,
    limit: usize,
) -> Result<Vec<DeliveredBlock>> {
    let url = history_url(base_url, channel, limit);
    let proof = ReadProof::sign(who, "GET", signable_path(&url));
    // Short timeout: this runs on the critical path to the first frame, and
    // a slow server should cost a warning, not a hung terminal.
    let http = crate::cmd::trust::http(base_url, std::time::Duration::from_secs(10)).await?;
    let mut req = http.get(&url);
    for (name, value) in proof.headers() {
        req = req.header(name, value);
    }
    let resp = req.send().await.with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("reading body of GET {url}"))?;
    if !status.is_success() {
        // Read the body rather than reporting a bare status: a 404 here is
        // most likely a server that predates the history endpoint, and the
        // body is what says so.
        anyhow::bail!("GET {url} returned {status}: {body}");
    }
    parse_history(&body)
}

/// Fetch + decode a backlog, degrading to an empty one on any failure.
///
/// Call this before entering raw mode: the warning goes to stderr as plain
/// text.
pub async fn backfill(
    who: &Identity,
    base_url: &str,
    channel: &str,
    limit: usize,
) -> Vec<DecodedBlock> {
    match fetch_history(who, base_url, channel, limit).await {
        Ok(blocks) => decode_history(&blocks),
        Err(e) => {
            eprintln!("warning: could not load history for {channel}: {e:#}");
            eprintln!("warning: opening with an empty pane.");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use jig_client::Identity;
    use jig_client::blocks::build_text_render;
    use jig_core::HlcTimestamp;
    use tempfile::tempdir;

    /// A text block as a v0.2 server delivers it, signature included.
    fn signed_text(body: &str, delivery: &str) -> DeliveredBlock {
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(&dir.keep()).unwrap();
        let block = build_text_render(
            &id,
            "#hello",
            body,
            HlcTimestamp::now_wall(id.did().clone()),
        );
        signed(&block, delivery)
    }

    fn signed(block: &jig_client::blocks::BuiltBlock, delivery: &str) -> DeliveredBlock {
        DeliveredBlock {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: Some(base64::engine::general_purpose::STANDARD.encode(&block.sender_sig)),
            receipts: vec![],
            delivery_cid: delivery.into(),
        }
    }

    #[test]
    fn history_url_escapes_the_slug_and_carries_the_limit() {
        // An unescaped `#` would truncate the path at the fragment marker
        // and silently request the whole-channel list route instead.
        assert_eq!(
            history_url("ws://127.0.0.1:7117/", "#hello", 100),
            "http://127.0.0.1:7117/api/v1/channels/%23hello/blocks?limit=100"
        );
    }

    #[test]
    fn parse_history_keeps_the_servers_signature() {
        // Without it the client could not tell a block the server rewrote
        // from one its author sent.
        let body = r#"[
            {"bundle_b64":"YQ==","sig_b64":"c2ln","receipts":[],"delivery_cid":"delivery:bafy1"},
            {"bundle_b64":"YQ==","receipts":[],"delivery_cid":"delivery:bafy2"}
        ]"#;
        let blocks = parse_history(body).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].delivery_cid, "delivery:bafy1");
        assert_eq!(blocks[0].sig_b64.as_deref(), Some("c2ln"));
        assert_eq!(blocks[1].sig_b64, None);
    }

    #[test]
    fn parse_history_accepts_an_empty_channel() {
        assert!(parse_history("[]").unwrap().is_empty());
    }

    #[test]
    fn decode_history_skips_undecodable_entries() {
        let blocks = vec![
            signed_text("first", "delivery:1"),
            DeliveredBlock {
                sig_b64: None,
                bundle_b64: "not_base64_!!!".into(),
                receipts: vec![],
                delivery_cid: "delivery:2".into(),
            },
            signed_text("third", "delivery:3"),
        ];
        let decoded = decode_history(&blocks);
        assert_eq!(decoded.len(), 2, "one bad block must not drop the backlog");
        assert_eq!(decoded[0].body, "first");
        assert_eq!(decoded[1].body, "third");
    }

    #[test]
    fn decode_history_drops_non_message_blocks() {
        // The timeline carries every block kind, so a live check showed the
        // channel-create block replaying as a `<no-body>` line at the top of
        // every freshly opened channel. Backfill is a message replay; only
        // message-shaped kinds belong in it.
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(&dir.keep()).unwrap();
        let hlc = HlcTimestamp {
            wall_ms: 1_747_680_000_000,
            logical: 0,
            server_did: id.did().clone(),
        };
        let create = jig_client::blocks::build_channel_create(&id, "#hello", "open", hlc.clone());
        let text = build_text_render(&id, "#hello", "hello team", hlc);

        let blocks = vec![
            signed(&create, "delivery:create"),
            signed(&text, "delivery:text"),
        ];

        let decoded = decode_history(&blocks);
        assert_eq!(decoded.len(), 1, "only the message block should replay");
        assert_eq!(decoded[0].body, "hello team");
    }

    #[tokio::test]
    async fn backfill_degrades_to_empty_when_the_server_is_unreachable() {
        // Port 1 is refused immediately. A server that has not been upgraded
        // answers 404 here instead; either way the pane must still open.
        let dir = tempdir().unwrap();
        let id = Identity::generate_and_save(&dir.keep()).unwrap();
        let backlog = backfill(&id, "http://127.0.0.1:1", "#hello", 10).await;
        assert!(
            backlog.is_empty(),
            "unreachable server must yield no backlog"
        );
    }
}
