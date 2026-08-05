//! Presentation helpers shared by `jig tail` and `jig chat`.
//!
//! Both surfaces render the same three things — a timestamp, a sender, and
//! a body — and both used to render the first two in their raw wire form:
//! epoch milliseconds (`1785861819798`) and a full 61-character DID. This
//! module owns the human-facing rendering so the two stay in step.
//!
//! Everything here is read-side only. Nothing in this module changes what
//! goes into a block: contact names are a local address book, never block
//! metadata. (Stamping `metadata["nickname"]` would arm the server's
//! identity check in `jig-pipeline`, which is a separate, deliberate
//! decision — not a rendering one.)

use std::collections::BTreeMap;
use std::io::Write;

use chrono::{FixedOffset, Local, TimeZone};

/// Placeholder for a block with no HLC (`ts == 0`), so the column still
/// lines up instead of printing a misleading `01:00`.
const NO_TIMESTAMP: &str = "--:--";

/// Number of leading characters of a DID kept when there is no contact
/// entry — `did:jig:` (8) plus 6 of the multibase body, which is enough to
/// tell two participants apart at a glance.
const DID_PREFIX_CHARS: usize = 14;

/// Render a wall-clock millisecond stamp as local `HH:MM`.
///
/// `0` means "the manifest carried no HLC" and renders as `--:--`.
pub fn format_hhmm(ts_ms: u64) -> String {
    format_hhmm_at(ts_ms, *Local::now().offset())
}

/// `format_hhmm` with an explicit UTC offset, so tests are not at the mercy
/// of the machine's timezone.
pub fn format_hhmm_at(ts_ms: u64, offset: FixedOffset) -> String {
    if ts_ms == 0 {
        return NO_TIMESTAMP.to_string();
    }
    let secs = (ts_ms / 1_000) as i64;
    match offset.timestamp_opt(secs, 0).single() {
        Some(dt) => dt.format("%H:%M").to_string(),
        None => NO_TIMESTAMP.to_string(),
    }
}

/// Resolve a sender DID to something a human can read.
///
/// Precedence: an exact `[contacts]` entry, else a truncated DID. The full
/// 61-character DID is never rendered — at that width every line is DID and
/// the message body scrolls off.
pub fn display_sender(contacts: &BTreeMap<String, String>, did: &str) -> String {
    if let Some(name) = contacts.get(did) {
        return name.clone();
    }
    shorten_did(did)
}

/// Truncate a DID to `DID_PREFIX_CHARS` characters plus an ellipsis.
/// Strings already that short (or shorter) pass through untouched, so
/// synthetic senders like `<decode-error>` are not mangled.
pub fn shorten_did(did: &str) -> String {
    let mut chars = did.chars();
    let head: String = chars.by_ref().take(DID_PREFIX_CHARS).collect();
    if chars.next().is_none() {
        return head;
    }
    format!("{head}…")
}

/// Ring the terminal bell for an inbound message.
///
/// Writes to the supplied sink (stderr in practice) rather than stdout:
/// `jig chat` hands stdout to ratatui, and `jig tail | grep` must not get a
/// `\x07` wedged into the piped stream.
pub fn ring_bell(out: &mut impl Write) {
    let _ = out.write_all(b"\x07");
    let _ = out.flush();
}

/// The error both `jig tail` and `jig chat` return when their subscription
/// ends. Shared so the two surfaces say the same thing, and so `main`'s
/// `Result` handling turns it into the non-zero exit that
/// `scripts/jig-room.sh` loops on.
pub fn connection_lost(channel: &str) -> anyhow::Error {
    anyhow::anyhow!("connection lost while subscribed to {channel} — the server closed the stream")
}

/// Ring once for a batch of `count` inbound messages, and not at all when
/// the batch is empty. Batching matters on reconnect, where a backlog would
/// otherwise arrive as one bell per message.
pub fn bell_on_inbound(count: usize, out: &mut impl Write) {
    if count > 0 {
        ring_bell(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc() -> FixedOffset {
        FixedOffset::east_opt(0).unwrap()
    }

    fn contacts_with(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn format_hhmm_renders_clock_time_not_epoch_millis() {
        // 2026-06-14T14:32:59Z
        let line = format_hhmm_at(1_781_015_579_000, utc());
        assert_eq!(line, "14:32", "expected HH:MM, got {line}");
    }

    #[test]
    fn format_hhmm_applies_the_supplied_offset() {
        let plus_two = FixedOffset::east_opt(2 * 3600).unwrap();
        assert_eq!(format_hhmm_at(1_781_015_579_000, plus_two), "16:32");
    }

    #[test]
    fn format_hhmm_uses_placeholder_for_missing_hlc() {
        assert_eq!(format_hhmm_at(0, utc()), "--:--");
    }

    #[test]
    fn display_sender_prefers_a_contact_name() {
        let contacts = contacts_with(&[("did:jig:zm5z5sAAAA", "dj")]);
        assert_eq!(display_sender(&contacts, "did:jig:zm5z5sAAAA"), "dj");
    }

    #[test]
    fn display_sender_shortens_unknown_dids() {
        // A real DID is 61 chars; nothing that long may reach the pane.
        let did = format!("did:jig:z{}", "m".repeat(52));
        let rendered = display_sender(&BTreeMap::new(), &did);
        assert_eq!(rendered, "did:jig:zmmmmm…");
        assert!(
            rendered.chars().count() < 20,
            "short form must stay narrow: {rendered}"
        );
    }

    #[test]
    fn shorten_did_passes_short_strings_through_unchanged() {
        assert_eq!(shorten_did("<decode-error>"), "<decode-error>");
        assert_eq!(shorten_did("dj"), "dj");
    }

    #[test]
    fn ring_bell_emits_the_bel_byte() {
        let mut sink: Vec<u8> = Vec::new();
        ring_bell(&mut sink);
        assert_eq!(sink, b"\x07");
    }

    #[test]
    fn bell_on_inbound_stays_silent_without_messages() {
        let mut sink: Vec<u8> = Vec::new();
        bell_on_inbound(0, &mut sink);
        assert!(sink.is_empty(), "an idle tick must not ring");
    }

    #[test]
    fn bell_on_inbound_rings_once_per_batch_not_per_message() {
        // A burst of backlog after a reconnect should be one ding, not
        // thirty — otherwise the terminal machine-guns at the user.
        let mut sink: Vec<u8> = Vec::new();
        bell_on_inbound(30, &mut sink);
        assert_eq!(sink, b"\x07");
    }
}
