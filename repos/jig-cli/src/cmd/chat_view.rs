//! View-model and rendering for `jig chat`.
//!
//! Split out of `chat.rs` so the run loop (connection, key handling,
//! submits) and the thing it paints stay separately readable — and so the
//! pane can be exercised against a `TestBackend` without a socket.
//!
//! Everything here is pure: state in, frame out. Network and terminal
//! ownership live in `chat.rs`.

use std::collections::BTreeMap;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use tokio::sync::mpsc;

use crate::cmd::blocks_decode::DecodedBlock;
use crate::cmd::display::{display_sender, format_hhmm};

/// In-memory view-model for the TUI. `messages` is append-only;
/// `render` slices it from the tail when there are more entries than
/// fit on screen (auto-scroll). `input_cursor` is a byte index into
/// `input` and is kept aligned to char boundaries by the key handler.
pub struct ChatState {
    pub channel: String,
    pub messages: Vec<Message>,
    pub input: String,
    pub input_cursor: usize,
    /// Transient operator-facing notice rendered in the input pane — today
    /// only "your message did not send". `None` renders the normal
    /// key-binding hint.
    pub status: Option<String>,
    /// Local DID → display-name map from `[contacts]` in `cli.toml`.
    /// Read-side only; see `crate::cmd::display`.
    pub contacts: BTreeMap<String, String>,
}

/// One decoded entry to display in the history pane.
#[derive(Debug, Clone)]
pub struct Message {
    pub sender: String,
    pub body: String,
    /// Wall-clock ms (matches `HlcTimestamp::wall_ms` / `DecodedBlock::ts`).
    pub ts: u64,
    pub parity_warning: bool,
}

impl From<DecodedBlock> for Message {
    fn from(d: DecodedBlock) -> Self {
        Self {
            sender: d.sender,
            body: d.body,
            ts: d.ts,
            parity_warning: d.parity_warning,
        }
    }
}

impl ChatState {
    pub fn new(channel: String) -> Self {
        Self {
            channel,
            messages: Vec::new(),
            input: String::new(),
            input_cursor: 0,
            status: None,
            contacts: BTreeMap::new(),
        }
    }

    /// Open a channel with its existing timeline already in the pane.
    ///
    /// `backlog` arrives oldest-first from
    /// [`crate::cmd::history::backfill`] and is kept in that order, so the
    /// newest message lands at the bottom where the live ones will follow.
    pub fn with_history(
        channel: String,
        backlog: Vec<DecodedBlock>,
        contacts: BTreeMap<String, String>,
    ) -> Self {
        Self {
            messages: backlog.into_iter().map(Message::from).collect(),
            contacts,
            ..Self::new(channel)
        }
    }
}

/// Result of one non-blocking drain of the inbound queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drained {
    /// How many messages were appended this tick (drives the bell).
    pub count: usize,
    /// True once the reader task has dropped its sender — i.e. the
    /// `BlockStream` ended, i.e. the connection is gone.
    pub disconnected: bool,
}

/// Move every queued message into `state`, reporting whether the sender
/// side has gone away.
///
/// Messages already buffered are drained *before* the disconnect is
/// reported, so the last thing the server said is not thrown away with the
/// connection.
pub(crate) fn drain_inbound(
    state: &mut ChatState,
    rx: &mut mpsc::UnboundedReceiver<Message>,
) -> Drained {
    let mut count = 0usize;
    loop {
        match rx.try_recv() {
            Ok(msg) => {
                state.messages.push(msg);
                count += 1;
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                return Drained {
                    count,
                    disconnected: false,
                };
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return Drained {
                    count,
                    disconnected: true,
                };
            }
        }
    }
}

/// Longest body echoed back in a failed-send notice; the input pane title
/// is one line, so a long message has to be clipped to stay readable.
const STATUS_BODY_CHARS: usize = 40;

/// Compose the input-pane notice for a submit that failed.
pub(crate) fn submit_failure_status(body: &str, err: &str) -> String {
    let mut shown: String = body.chars().take(STATUS_BODY_CHARS).collect();
    if body.chars().count() > STATUS_BODY_CHARS {
        shown.push('…');
    }
    format!("⚠ not sent: \"{shown}\" — {err}")
}

/// Render the two-pane chat view.
///
/// Auto-scroll strategy: rather than wiring a stateful `ListState`,
/// we slice `state.messages` to the last N entries where N is the
/// visible row count of the history pane. This always paints the
/// newest message at the bottom, which is the only behavior the demo
/// needs. Trade-off: no scroll-back, but v0.0.3 will add a proper
/// history viewer (PageUp/PageDown bound to a `ListState`).
pub fn render(f: &mut Frame, state: &ChatState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(f.size());

    // `f.size()` is whole-terminal; the history pane is `chunks[0]`.
    // Inner height = pane height minus the 2 rows of border. Saturating
    // sub keeps us safe on a 1-row terminal.
    let visible_rows = (chunks[0].height as usize).saturating_sub(2);
    let start = state.messages.len().saturating_sub(visible_rows.max(1));
    let visible = &state.messages[start..];

    let history: Vec<ListItem> = visible
        .iter()
        .map(|m| {
            let warning = if m.parity_warning { "  ⚠" } else { "" };
            ListItem::new(format!(
                "{}  {}: {}{}",
                format_hhmm(m.ts),
                display_sender(&state.contacts, &m.sender),
                m.body,
                warning
            ))
        })
        .collect();

    f.render_widget(
        List::new(history).block(
            Block::default()
                .borders(Borders::ALL)
                .title(state.channel.as_str()),
        ),
        chunks[0],
    );

    // The input pane title doubles as the status line: a failed submit
    // replaces the key-binding hint until the next send attempt.
    let input_title = state
        .status
        .clone()
        .unwrap_or_else(|| "input — Enter to send, Ctrl+Q or Esc to quit".to_string());
    f.render_widget(
        Paragraph::new(state.input.as_str())
            .block(Block::default().borders(Borders::ALL).title(input_title)),
        chunks[1],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};

    /// Render the chat view into a fresh TestBackend at the given size
    /// and return the buffer for assertions.
    fn render_to_buffer(state: &ChatState, width: u16, height: u16) -> Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state)).unwrap();
        terminal.backend().buffer().clone()
    }

    /// Walk a buffer row-by-row and return one `String` per row,
    /// preserving column order. The TestBackend stores cells as a
    /// flat row-major vec so we can iterate by chunks of `width`.
    fn buffer_to_lines(buf: &Buffer) -> Vec<String> {
        let width = buf.area.width as usize;
        let height = buf.area.height as usize;
        let mut lines = Vec::with_capacity(height);
        for y in 0..height {
            let mut line = String::with_capacity(width);
            for x in 0..width {
                let cell = buf.get(x as u16, y as u16);
                line.push_str(cell.symbol());
            }
            lines.push(line);
        }
        lines
    }

    #[test]
    fn render_chat_view_includes_history_and_input() {
        let state = ChatState {
            channel: "#hello".into(),
            messages: vec![Message {
                sender: "dj".into(),
                body: "hi".into(),
                ts: 0,
                parity_warning: false,
            }],
            input: "world".into(),
            input_cursor: 5,
            status: None,
            contacts: BTreeMap::new(),
        };
        let buf = render_to_buffer(&state, 80, 24);
        let lines = buffer_to_lines(&buf);
        assert!(
            lines.iter().any(|l| l.contains("#hello")),
            "channel title must appear: {lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("hi")),
            "message body must appear: {lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("world")),
            "input must appear: {lines:#?}"
        );
    }

    #[test]
    fn render_shows_clock_time_not_raw_epoch_millis() {
        // 2026-06-14T14:32:59Z — the exact rendering is timezone-dependent,
        // so the load-bearing assertion is that the 13-digit epoch stamp
        // never reaches the pane.
        let ts = 1_781_015_579_000u64;
        let state = ChatState {
            channel: "#hello".into(),
            messages: vec![Message {
                sender: "dj".into(),
                body: "hello team".into(),
                ts,
                parity_warning: false,
            }],
            input: String::new(),
            input_cursor: 0,
            status: None,
            contacts: BTreeMap::new(),
        };
        let buf = render_to_buffer(&state, 80, 24);
        let lines = buffer_to_lines(&buf);
        assert!(
            !lines.iter().any(|l| l.contains("1781015579000")),
            "raw epoch millis must not be rendered: {lines:#?}"
        );
        let clock = crate::cmd::display::format_hhmm(ts);
        assert!(
            lines
                .iter()
                .any(|l| l.contains(&format!("{clock}  dj: hello team"))),
            "expected `HH:MM  sender: body`: {lines:#?}"
        );
    }

    #[test]
    fn render_parity_warning_emits_warning_glyph() {
        let state = ChatState {
            channel: "#hello".into(),
            messages: vec![Message {
                sender: "deji".into(),
                body: "diverged".into(),
                ts: 42,
                parity_warning: true,
            }],
            input: String::new(),
            input_cursor: 0,
            status: None,
            contacts: BTreeMap::new(),
        };
        let buf = render_to_buffer(&state, 80, 24);
        let lines = buffer_to_lines(&buf);
        assert!(
            lines.iter().any(|l| l.contains("⚠")),
            "parity warning glyph must appear: {lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("diverged")),
            "body must still render: {lines:#?}"
        );
    }

    #[test]
    fn render_auto_scrolls_to_show_latest_message() {
        // 50 messages into a 24-row buffer (~22 visible history rows
        // after border). Latest message must appear; the earliest
        // must NOT (it's been scrolled off the top).
        let messages: Vec<Message> = (0..50)
            .map(|i| Message {
                sender: "dj".into(),
                body: format!("msg-{i:02}"),
                ts: i,
                parity_warning: false,
            })
            .collect();
        let state = ChatState {
            channel: "#hello".into(),
            messages,
            input: String::new(),
            input_cursor: 0,
            status: None,
            contacts: BTreeMap::new(),
        };
        let buf = render_to_buffer(&state, 80, 24);
        let lines = buffer_to_lines(&buf);
        assert!(
            lines.iter().any(|l| l.contains("msg-49")),
            "latest message must be visible: {lines:#?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("msg-00")),
            "earliest message must be scrolled off: {lines:#?}"
        );
    }

    #[test]
    fn render_uses_the_contact_name_and_never_the_full_did() {
        let did = format!("did:jig:z{}", "m".repeat(52));
        let mut state = ChatState::new("#hello".into());
        state.contacts.insert(did.clone(), "dj".into());
        state.messages.push(Message {
            sender: did.clone(),
            body: "hello team".into(),
            ts: 1_781_015_579_000,
            parity_warning: false,
        });

        let lines = buffer_to_lines(&render_to_buffer(&state, 80, 24));
        assert!(
            !lines.iter().any(|l| l.contains(&did)),
            "the full 61-char DID must never be rendered: {lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("dj: hello team")),
            "contact name must be used: {lines:#?}"
        );
    }

    #[test]
    fn render_falls_back_to_a_short_did_for_unknown_senders() {
        let did = format!("did:jig:z{}", "m".repeat(52));
        let mut state = ChatState::new("#hello".into());
        state.messages.push(Message {
            sender: did.clone(),
            body: "who am i".into(),
            ts: 1,
            parity_warning: false,
        });

        let lines = buffer_to_lines(&render_to_buffer(&state, 80, 24));
        assert!(
            !lines.iter().any(|l| l.contains(&did)),
            "unknown senders must still be truncated: {lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("did:jig:zmmmmm…")),
            "expected the short DID form: {lines:#?}"
        );
    }

    #[test]
    fn with_history_prefills_the_pane_in_arrival_order() {
        // The whole point of Task 1: opening a busy channel must not show
        // an empty pane. `backfill` hands back oldest-first, and that order
        // has to survive into the message list.
        let backlog = vec![
            DecodedBlock {
                sender: "dj".into(),
                body: "first".into(),
                ts: 1,
                parity_warning: false,
                parity_hash_count: 0,
                kind: Some(jig_core::BlockKind::TextRender),
            },
            DecodedBlock {
                sender: "deji".into(),
                body: "second".into(),
                ts: 2,
                parity_warning: false,
                parity_hash_count: 0,
                kind: Some(jig_core::BlockKind::TextRender),
            },
        ];
        let state = ChatState::with_history("#hello".into(), backlog, BTreeMap::new());
        assert_eq!(state.messages.len(), 2);
        assert_eq!(state.messages[0].body, "first");
        assert_eq!(state.messages[1].body, "second");

        let lines = buffer_to_lines(&render_to_buffer(&state, 80, 24));
        assert!(
            lines.iter().any(|l| l.contains("first")),
            "history must be on screen at open: {lines:#?}"
        );
    }

    #[test]
    fn with_history_opens_empty_when_there_is_no_backlog() {
        // The degraded path (history fetch failed) must still give a usable
        // pane rather than erroring out of `run`.
        let state = ChatState::with_history("#hello".into(), Vec::new(), BTreeMap::new());
        assert!(state.messages.is_empty());
        assert_eq!(state.channel, "#hello");
    }

    #[test]
    fn drain_inbound_reports_disconnect_when_the_reader_task_ends() {
        // The reader task drops `msg_tx` when the BlockStream ends, so a
        // disconnected receiver IS the disconnect signal. Before Task 4 the
        // loop swallowed it and sat on a dead pane forever.
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Message {
            sender: "dj".into(),
            body: "last words".into(),
            ts: 1,
            parity_warning: false,
        })
        .unwrap();
        drop(tx);

        let mut state = ChatState::new("#x".into());
        let drained = drain_inbound(&mut state, &mut rx);

        assert_eq!(drained.count, 1);
        assert!(
            drained.disconnected,
            "dropped sender must signal disconnect"
        );
        assert_eq!(
            state.messages.len(),
            1,
            "messages buffered before the drop must still be shown"
        );
    }

    #[test]
    fn drain_inbound_stays_connected_while_the_sender_lives() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let mut state = ChatState::new("#x".into());
        let drained = drain_inbound(&mut state, &mut rx);
        assert_eq!(drained.count, 0);
        assert!(!drained.disconnected, "an idle tick is not a disconnect");
        drop(tx);
    }

    #[test]
    fn submit_failure_status_names_the_message_that_did_not_send() {
        let status = submit_failure_status("hello team", "connection closed");
        assert!(
            status.contains("not sent"),
            "must not read as success: {status}"
        );
        assert!(
            status.contains("hello team"),
            "must quote the body: {status}"
        );
        assert!(
            status.contains("connection closed"),
            "must show why: {status}"
        );
    }

    #[test]
    fn submit_failure_status_truncates_a_long_body() {
        let long = "x".repeat(200);
        let status = submit_failure_status(&long, "boom");
        assert!(
            status.chars().count() < 120,
            "status must fit the input pane: {status}"
        );
        assert!(status.contains('…'), "truncation must be visible: {status}");
    }

    #[test]
    fn render_shows_a_failed_send_in_the_input_pane() {
        let mut state = ChatState::new("#hello".into());
        state.status = Some("⚠ not sent: \"hi\" — connection closed".into());
        let buf = render_to_buffer(&state, 80, 24);
        let lines = buffer_to_lines(&buf);
        assert!(
            lines.iter().any(|l| l.contains("not sent")),
            "a failed submit must be visible, not silent: {lines:#?}"
        );
    }

    #[test]
    fn message_from_decoded_block_copies_fields() {
        let decoded = DecodedBlock {
            sender: "did:jig:zABC".into(),
            body: "hello".into(),
            ts: 12345,
            parity_warning: true,
            parity_hash_count: 2,
            kind: Some(jig_core::BlockKind::TextRender),
        };
        let m: Message = decoded.into();
        assert_eq!(m.sender, "did:jig:zABC");
        assert_eq!(m.body, "hello");
        assert_eq!(m.ts, 12345);
        assert!(m.parity_warning);
    }
}
