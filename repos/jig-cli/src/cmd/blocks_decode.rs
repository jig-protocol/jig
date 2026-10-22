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
use jig_client::open::{Authenticity, OpenedBlock, open};
use jig_client::secure::Seen;
use jig_client::{DeliveredBlock, envelope::ReceiptRef};
use jig_core::BlockKind;
use std::collections::HashSet;

use crate::cmd::display::shorten_did;

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
    /// Declared block kind, when the manifest carries one. Lets callers
    /// tell a chat message from a control block (channel-create,
    /// member-add, …) that happens to share the same timeline.
    pub kind: Option<BlockKind>,
}

impl DecodedBlock {
    /// True for kinds a human reads as a message. Control blocks share the
    /// channel timeline but carry no body, so replaying them prints a
    /// `<no-body>` line the operator can do nothing with.
    pub fn is_message(&self) -> bool {
        self.sender == SYSTEM
            || matches!(
                self.kind,
                Some(BlockKind::TextRender | BlockKind::EmailRender)
            )
    }
}

/// Sender shown for a membership event on an encrypted channel — rendered
/// as `* <body>` rather than `<sender>: <body>`.
pub const SYSTEM: &str = "*";

/// Decode a delivered block bundle into a `DecodedBlock`, verifying the
/// author's signature first ([`jig_client::open`]). A block whose signature
/// does not verify is an error: a server must not be able to put words in
/// someone's mouth.
///
/// Bundle layout (must match `jig_client::blocks::BuiltBlock::canonical_bytes`):
///   * `bundle_b64` decodes to JSON-encoded `(manifest_bytes, code_bytes)`.
///   * `manifest_bytes` decodes to `BlockManifest`.
///   * Body lives at `manifest.metadata["body"]` (a JSON string).
///   * Sender DID is `manifest.authors[0].did`.
///   * Wall-clock timestamp comes from `manifest.hlc_ts.wall_ms` if set.
///
/// A text-render message is also checked against its server's `exec` receipt
/// ([`render_check`]) and marked when it could not be verified or the server's
/// render differs from this client's.
pub fn decode(d: &DeliveredBlock) -> Result<DecodedBlock> {
    let opened = open(d).context("opening delivered block")?;
    let mut decoded = plain(&opened, &d.receipts);
    if decoded.kind == Some(BlockKind::TextRender) {
        decoded.body.push_str(render_check(d, &opened).marker());
    }
    Ok(decoded)
}

/// What this client could say about a text-render message's server render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "local-runtime"), allow(dead_code))]
pub enum RenderCheck {
    /// This client ran the same component on the same invocation and agreed.
    Agreed,
    /// The server's receipt disagrees with this client on a comparable outcome. Shown, not
    /// resolved: it can also mean this client runs a different text-block build.
    Differs,
    /// Not checked: no `exec` receipt, an incomplete run, or a build without the runtime.
    Unverified,
}

impl RenderCheck {
    /// The fixed text appended to the message. Never server-supplied text.
    pub fn marker(self) -> &'static str {
        match self {
            RenderCheck::Agreed => "",
            RenderCheck::Differs => "  [server render differs]",
            RenderCheck::Unverified => "  [unverified]",
        }
    }
}

#[cfg(feature = "local-runtime")]
pub fn render_check(d: &DeliveredBlock, opened: &OpenedBlock) -> RenderCheck {
    use jig_client::verify::{Verification, verify};
    match verify(d, opened) {
        Verification::Agree => RenderCheck::Agreed,
        Verification::Diverge(_) => RenderCheck::Differs,
        Verification::NotComparable(_) | Verification::Unverified(_) => RenderCheck::Unverified,
    }
}

/// A build without the block runtime cannot re-execute anything.
#[cfg(not(feature = "local-runtime"))]
pub fn render_check(_d: &DeliveredBlock, _opened: &OpenedBlock) -> RenderCheck {
    RenderCheck::Unverified
}

/// Present a block given what an encrypted-channel session made of it.
/// `None` for a control block with nothing to show.
pub fn present(opened: &OpenedBlock, receipts: &[ReceiptRef], seen: &Seen) -> Option<DecodedBlock> {
    let system = |body: String| {
        let mut d = plain(opened, receipts);
        d.sender = SYSTEM.to_string();
        d.body = body;
        Some(d)
    };
    match seen {
        Seen::Plain => Some(plain(opened, receipts)),
        Seen::Control => None,
        Seen::Text { sender, text } => {
            let mut d = plain(opened, receipts);
            d.sender = sender.clone();
            d.body = format!("🔒 {text}");
            Some(d)
        }
        Seen::Sealed { reason } => {
            let mut d = plain(opened, receipts);
            d.body = format!("🔒 [cannot decrypt: {reason}]");
            Some(d)
        }
        Seen::Joined => {
            system("you joined — messages from here on are end-to-end encrypted".into())
        }
        Seen::Added { member } => system(format!("{} was added", shorten_did(member))),
        Seen::Removed { member } => system(format!("{} was removed", shorten_did(member))),
        Seen::Left { member, .. } => system(format!("{} left", shorten_did(member))),
        Seen::Gone => system("you are no longer in this channel".into()),
        Seen::Broken { reason } => {
            system(format!("could not follow a membership change: {reason}"))
        }
    }
}

/// A block as plaintext: body from metadata, sender from the verified key.
fn plain(opened: &OpenedBlock, receipts: &[ReceiptRef]) -> DecodedBlock {
    let manifest = &opened.manifest;
    let mut body = manifest
        .metadata
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("<no-body>")
        .to_string();
    if opened.authenticity == Authenticity::Unsigned {
        body.push_str("  [unsigned]");
    }
    let ts = manifest.hlc_ts.as_ref().map(|t| t.wall_ms).unwrap_or(0);
    let parity_hash_count = distinct_render_hashes(receipts);
    DecodedBlock {
        sender: opened.sender.clone(),
        body,
        ts,
        parity_warning: parity_hash_count >= 2,
        parity_hash_count,
        kind: manifest.kind,
    }
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
    use base64::Engine as _;
    use jig_client::Identity;
    use jig_client::blocks::BuiltBlock;
    use jig_client::blocks::build_text_render;
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

    /// As a v0.2 server delivers it: with the author's signature.
    fn signed(block: &BuiltBlock, receipts: Vec<ReceiptRef>) -> DeliveredBlock {
        DeliveredBlock {
            bundle_b64: base64::engine::general_purpose::STANDARD.encode(block.canonical_bytes()),
            sig_b64: Some(base64::engine::general_purpose::STANDARD.encode(&block.sender_sig)),
            receipts,
            delivery_cid: "bafy_test_delivery".into(),
            ingest: None,
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
        let decoded = decode(&signed(&block, vec![])).unwrap();

        assert_eq!(decoded.ts, 1_747_680_000_000);
        assert_eq!(decoded.sender, did.to_did_jig_string());
        // No server receipt to check against.
        assert_eq!(decoded.body, "hi there  [unverified]");
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
        let receipts = vec![rr("did:jig:zA", Some("h1")), rr("did:jig:zB", Some("h2"))];
        let decoded = decode(&signed(&block, receipts)).unwrap();
        assert!(decoded.parity_warning);
        assert_eq!(decoded.parity_hash_count, 2);
    }

    #[test]
    fn decode_reports_invalid_b64() {
        let d = delivered_for("not_base64_!!!".into(), vec![]);
        let err = decode(&d).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bundle_b64"), "context: {msg}");
    }

    /// A server that rewrites a block in transit is caught, not displayed.
    #[test]
    fn decode_refuses_a_block_whose_signature_does_not_verify() {
        let id = test_identity();
        let hlc = HlcTimestamp::now_wall(id.did().clone());
        let honest = build_text_render(&id, "#hello", "pay alice", hlc.clone());
        let rewritten = build_text_render(&id, "#hello", "pay mallory", hlc);
        let mut d = signed(&rewritten, vec![]);
        d.sig_b64 = signed(&honest, vec![]).sig_b64;
        let msg = format!("{:#}", decode(&d).unwrap_err());
        assert!(msg.contains("forged"), "{msg}");
    }

    #[test]
    fn decode_marks_an_unsigned_delivery() {
        let id = test_identity();
        let block = build_text_render(
            &id,
            "#hello",
            "hi",
            HlcTimestamp::now_wall(id.did().clone()),
        );
        let mut d = signed(&block, vec![]);
        d.sig_b64 = None;
        assert_eq!(decode(&d).unwrap().body, "hi  [unsigned]  [unverified]");
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
