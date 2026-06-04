//! Outbound translation: a delivered Jig block -> an `OutboundEmail`.
//!
//! Pure function. The caller (the EmailBridge in C9) resolves the recipient
//! email and the from-address; here we only decode the block and shape the
//! email. Returns `None` (with a warning) when the block has no body, can't be
//! decoded, or exceeds the inline size cap — the bridge drops such deliveries.

use base64::Engine as _;
use jig_bridge_core::DeliveredBlock;
use jig_core::BlockManifest;

use crate::provider::OutboundEmail;

/// Max inline message size we will turn into an email body (25 MB). Larger
/// blocks are dropped — attachment/large-payload handling is a later iteration.
const MAX_INLINE_BYTES: usize = 25 * 1024 * 1024;

/// Cap a derived subject so a body without newlines can't produce an enormous
/// Subject header.
const MAX_SUBJECT_CHARS: usize = 200;

/// Translate a delivered block into an outbound email addressed to `to` from
/// `from`. `None` if the block can't be decoded, has no body, or is too large.
pub fn block_to_outbound_email(
    delivered: &DeliveredBlock,
    to: String,
    from: String,
) -> Option<OutboundEmail> {
    translate(delivered, to, from, MAX_INLINE_BYTES)
}

/// Inner translator with an explicit size cap. Extracted so the cap can be
/// exercised in tests with a tiny threshold — building a real 25 MB block is
/// pathologically slow because the bundle format serializes the body's bytes as
/// a JSON integer-array, ballooning it to >100 MB of JSON + base64.
fn translate(
    delivered: &DeliveredBlock,
    to: String,
    from: String,
    max_inline_bytes: usize,
) -> Option<OutboundEmail> {
    let manifest = match decode_manifest(&delivered.bundle_b64) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                "email bridge: undecodable outbound block {}: {e}",
                delivered.delivery_cid
            );
            return None;
        }
    };

    let body = manifest
        .metadata
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if body.is_empty() {
        tracing::warn!(
            "email bridge: outbound block {} has no body, dropping",
            delivered.delivery_cid
        );
        return None;
    }
    // Byte length, not char count: transport size limits are byte-based.
    if body.len() > max_inline_bytes {
        tracing::warn!(
            "email bridge: outbound block {} body is {} bytes (> {} cap), dropping",
            delivered.delivery_cid,
            body.len(),
            max_inline_bytes
        );
        return None;
    }

    let subject = manifest
        .metadata
        .get("subject")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| derive_subject(body));

    Some(OutboundEmail {
        to,
        from,
        subject,
        body: body.to_string(),
    })
}

fn decode_manifest(bundle_b64: &str) -> anyhow::Result<BlockManifest> {
    let raw = base64::engine::general_purpose::STANDARD.decode(bundle_b64)?;
    let (manifest_bytes, _code_bytes): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&raw)?;
    Ok(serde_json::from_slice(&manifest_bytes)?)
}

/// First line of the body (trimmed, length-capped) as a fallback subject.
/// Falls back to a placeholder when the first line is blank/whitespace so we
/// never emit a completely empty Subject header.
fn derive_subject(body: &str) -> String {
    let first_line = body.lines().next().unwrap_or("").trim();
    if first_line.is_empty() {
        return "(no subject)".to_string();
    }
    first_line.chars().take(MAX_SUBJECT_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivered_from_body(body: &str) -> DeliveredBlock {
        let dir = tempfile::tempdir().unwrap();
        let id = jig_client::Identity::generate_and_save(dir.path()).unwrap();
        let hlc = jig_core::HlcTimestamp::now_wall(id.did().clone());
        let blk = jig_client::blocks::build_text_render(&id, "#dm/x", body, hlc);
        DeliveredBlock {
            bundle_b64: base64::engine::general_purpose::STANDARD
                .encode(blk.canonical_bytes()),
            receipts: vec![],
            delivery_cid: "cid1".into(),
        }
    }

    #[test]
    fn translates_text_render_block_to_email() {
        let delivered = delivered_from_body("hello alice");
        let email =
            block_to_outbound_email(&delivered, "alice@example.com".into(), "bob@jig.onl".into())
                .expect("should translate");
        assert_eq!(email.to, "alice@example.com");
        assert_eq!(email.from, "bob@jig.onl");
        assert!(email.body.contains("hello alice"));
        assert_eq!(email.subject, "hello alice"); // derived from the single-line body
    }

    #[test]
    fn empty_body_yields_none() {
        let delivered = delivered_from_body("");
        assert!(
            block_to_outbound_email(&delivered, "a@b".into(), "c@d".into()).is_none()
        );
    }

    #[test]
    fn oversized_body_yields_none() {
        // Exercise the cap via the internal `translate` with a tiny threshold so
        // we don't build a real 25 MB block (which the bundle format would
        // balloon to >100 MB of JSON + base64 — an 11s test).
        let delivered = delivered_from_body("hello alice"); // 11-byte body
        assert!(
            translate(&delivered, "a@b".into(), "c@d".into(), 5).is_none(),
            "body over the cap should drop"
        );
        assert!(
            translate(&delivered, "a@b".into(), "c@d".into(), 1000).is_some(),
            "body under the cap should translate"
        );
    }

    #[test]
    fn undecodable_bundle_yields_none() {
        let delivered = DeliveredBlock {
            bundle_b64: "not base64!!!".into(),
            receipts: vec![],
            delivery_cid: "bad".into(),
        };
        assert!(
            block_to_outbound_email(&delivered, "a@b".into(), "c@d".into()).is_none()
        );
    }
}
