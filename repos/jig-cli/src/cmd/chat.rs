//! `jig chat <channel>` — Phase F6 of v0.0.2 hello-world.
//!
//! Two-pane ratatui TUI: a scrolling history pane on top and a single-
//! line input pane at the bottom. Connects via WSS (reusing
//! `jig_client::Client`), subscribes to the channel, decodes inbound
//! blocks via the shared `cmd::blocks_decode` helper, and renders them
//! as `<ts>  <sender>: <body>` lines (with a `⚠` suffix when receipt
//! render hashes disagree).
//!
//! This is the demo command — `install.sh` invokes it at the end of
//! first-run setup, so the polish bar is slightly higher than the
//! other Phase F commands.
//!
//! Key bindings:
//!   * `Enter`           — submit the current input as a `text-render` block
//!   * `Backspace`       — delete char before cursor
//!   * `Left` / `Right`  — move cursor within input
//!   * `Home` / `End`    — jump to start / end of input
//!   * `Ctrl+Q` / `Esc`  — quit cleanly (terminal state restored)
//!
//! MANUAL: cargo run -p jig-cli -- chat "#hello"

use anyhow::{Context, Result};
use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode, KeyModifiers},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use jig_client::{Client, blocks::build_text_render};
use jig_core::HlcTimestamp;
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use std::{
    io::{Stdout, stdout},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc;

use crate::cmd::blocks_decode::{DecodedBlock, decode};
use crate::cmd::common::{load_active_identity, load_server_url};

/// Args struct for `jig chat <channel>`. Lives here (rather than in
/// `main.rs`) so the run loop stays self-contained — the clap layer
/// only needs to forward the channel slug.
#[derive(Debug, Clone)]
pub struct ChatArgs {
    pub channel: String,
}

/// In-memory view-model for the TUI. `messages` is append-only;
/// `render` slices it from the tail when there are more entries than
/// fit on screen (auto-scroll). `input_cursor` is a byte index into
/// `input` and is kept aligned to char boundaries by the key handler.
pub struct ChatState {
    pub channel: String,
    pub messages: Vec<Message>,
    pub input: String,
    pub input_cursor: usize,
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
        }
    }
}

/// RAII guard that restores the terminal on drop — including panic
/// paths. Without this, an unwrap inside the event loop leaves the
/// user's shell in raw-mode + alternate-screen, which renders the
/// terminal effectively useless until they `reset`.
struct TerminalGuard {
    active: bool,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enabling raw mode")?;
        stdout()
            .execute(EnterAlternateScreen)
            .context("entering alternate screen")?;
        Ok(Self { active: true })
    }

    /// Explicit teardown — call before normal exit so we can surface
    /// any errors from `disable_raw_mode` / `LeaveAlternateScreen`
    /// rather than swallowing them in `Drop`.
    fn leave(mut self) -> Result<()> {
        self.active = false;
        disable_raw_mode().context("disabling raw mode")?;
        stdout()
            .execute(LeaveAlternateScreen)
            .context("leaving alternate screen")?;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.active {
            // Best-effort: panic path. Ignore errors — we're already
            // unwinding and there's nowhere useful to report them.
            let _ = disable_raw_mode();
            let _ = stdout().execute(LeaveAlternateScreen);
        }
    }
}

/// Apply `jig chat <channel>`.
pub async fn run(args: ChatArgs) -> Result<()> {
    let id = load_active_identity()?;
    let server_url = load_server_url()?;

    let client = Client::connect(&server_url, id)
        .await
        .with_context(|| format!("connecting to {server_url}"))?;
    let client = Arc::new(client);

    let mut stream = client
        .subscribe_channel(&args.channel)
        .await
        .with_context(|| format!("subscribing to {}", args.channel))?;

    // Pump inbound blocks into an unbounded mpsc. The render loop
    // drains via `try_recv` each tick, so a fast-burst from the
    // server can't starve user input. Unbounded is fine here — chat
    // volume is small and the channel is dropped on exit.
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<Message>();
    tokio::spawn(async move {
        while let Some(block) = stream.next().await {
            match decode(&block) {
                Ok(decoded) => {
                    if msg_tx.send(decoded.into()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    // Surface the decoder error as a synthetic message
                    // so the operator sees that something arrived but
                    // couldn't be parsed. v0.0.2 is single-server so
                    // this is essentially never reached.
                    let _ = msg_tx.send(Message {
                        sender: "<decode-error>".into(),
                        body: format!("{e}"),
                        ts: 0,
                        parity_warning: false,
                    });
                }
            }
        }
    });

    let guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal: Terminal<CrosstermBackend<Stdout>> =
        Terminal::new(backend).context("constructing terminal")?;

    let mut state = ChatState::new(args.channel.clone());

    let result = event_loop(&mut terminal, &mut state, &mut msg_rx, &client).await;

    // Always restore the terminal before returning, even on error,
    // and prefer the explicit-teardown error over the loop's error
    // only if the loop itself succeeded.
    let leave_result = guard.leave();
    result.and(leave_result)
}

/// Inner event loop. Extracted so we can keep the `?` ergonomics in
/// `run` while ensuring `TerminalGuard::leave` is always called.
async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &mut ChatState,
    msg_rx: &mut mpsc::UnboundedReceiver<Message>,
    client: &Arc<Client>,
) -> Result<()> {
    loop {
        // Drain any inbound messages before redrawing so we paint the
        // latest state in one pass.
        while let Ok(msg) = msg_rx.try_recv() {
            state.messages.push(msg);
        }

        terminal.draw(|f| render(f, state)).context("draw frame")?;

        if event::poll(Duration::from_millis(50)).context("event poll")?
            && let Event::Key(key) = event::read().context("event read")?
        {
            // Filter out key-release events when present (crossterm
            // emits them on terminals with kitty-protocol enabled).
            if !matches!(
                key.kind,
                crossterm::event::KeyEventKind::Press | crossterm::event::KeyEventKind::Repeat
            ) {
                continue;
            }

            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Esc => return Ok(()),
                KeyCode::Char('q') | KeyCode::Char('c') if ctrl => return Ok(()),
                KeyCode::Enter => {
                    handle_submit(state, client);
                }
                KeyCode::Backspace => {
                    delete_before_cursor(state);
                }
                KeyCode::Left => {
                    move_cursor_left(state);
                }
                KeyCode::Right => {
                    move_cursor_right(state);
                }
                KeyCode::Home => state.input_cursor = 0,
                KeyCode::End => state.input_cursor = state.input.len(),
                KeyCode::Char(c) => {
                    insert_char(state, c);
                }
                _ => {}
            }
        }
    }
}

/// Fire-and-forget submit. Spawning means the WSS round-trip doesn't
/// block redraws; if the submit fails the user just won't see their
/// own message echo back from the server, which is the same UX as a
/// dropped network packet. v0.0.3 will surface submit errors via a
/// status line.
fn handle_submit(state: &mut ChatState, client: &Arc<Client>) {
    if state.input.is_empty() {
        return;
    }
    let body = std::mem::take(&mut state.input);
    state.input_cursor = 0;
    let channel = state.channel.clone();
    let client = client.clone();
    tokio::spawn(async move {
        // We need an Identity to derive the HLC stamp + sign the block.
        // The Client owns the original Identity by Arc, but doesn't
        // expose it; re-loading from disk is cheap (a single 32-byte
        // read + ed25519 pubkey derivation) and matches how `jig send`
        // does it in F5. Errors here are silently dropped — see
        // doc-comment above.
        let Ok(id) = load_active_identity() else {
            return;
        };
        let hlc = HlcTimestamp::now_wall(id.did().clone());
        let block = build_text_render(&id, &channel, &body, hlc);
        let _ = client.submit(block).await;
    });
}

fn insert_char(state: &mut ChatState, c: char) {
    state.input.insert(state.input_cursor, c);
    state.input_cursor += c.len_utf8();
}

fn delete_before_cursor(state: &mut ChatState) {
    if state.input_cursor == 0 {
        return;
    }
    // Walk backwards to the previous char boundary so multi-byte
    // chars (emoji, accented letters) get removed atomically.
    let mut new_cursor = state.input_cursor - 1;
    while new_cursor > 0 && !state.input.is_char_boundary(new_cursor) {
        new_cursor -= 1;
    }
    state
        .input
        .replace_range(new_cursor..state.input_cursor, "");
    state.input_cursor = new_cursor;
}

fn move_cursor_left(state: &mut ChatState) {
    if state.input_cursor == 0 {
        return;
    }
    let mut new_cursor = state.input_cursor - 1;
    while new_cursor > 0 && !state.input.is_char_boundary(new_cursor) {
        new_cursor -= 1;
    }
    state.input_cursor = new_cursor;
}

fn move_cursor_right(state: &mut ChatState) {
    if state.input_cursor >= state.input.len() {
        return;
    }
    let mut new_cursor = state.input_cursor + 1;
    while new_cursor < state.input.len() && !state.input.is_char_boundary(new_cursor) {
        new_cursor += 1;
    }
    state.input_cursor = new_cursor;
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
            ListItem::new(format!("{}  {}: {}{}", m.ts, m.sender, m.body, warning))
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

    f.render_widget(
        Paragraph::new(state.input.as_str()).block(
            Block::default()
                .borders(Borders::ALL)
                .title("input — Enter to send, Ctrl+Q or Esc to quit"),
        ),
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
    fn insert_char_appends_at_cursor_and_advances() {
        let mut state = ChatState::new("#x".into());
        insert_char(&mut state, 'h');
        insert_char(&mut state, 'i');
        assert_eq!(state.input, "hi");
        assert_eq!(state.input_cursor, 2);
    }

    #[test]
    fn insert_char_inserts_in_middle() {
        let mut state = ChatState::new("#x".into());
        state.input = "hllo".into();
        state.input_cursor = 1;
        insert_char(&mut state, 'e');
        assert_eq!(state.input, "hello");
        assert_eq!(state.input_cursor, 2);
    }

    #[test]
    fn backspace_removes_char_before_cursor() {
        let mut state = ChatState::new("#x".into());
        state.input = "hi".into();
        state.input_cursor = 2;
        delete_before_cursor(&mut state);
        assert_eq!(state.input, "h");
        assert_eq!(state.input_cursor, 1);
    }

    #[test]
    fn backspace_at_cursor_zero_is_noop() {
        let mut state = ChatState::new("#x".into());
        state.input = "hi".into();
        state.input_cursor = 0;
        delete_before_cursor(&mut state);
        assert_eq!(state.input, "hi");
        assert_eq!(state.input_cursor, 0);
    }

    #[test]
    fn cursor_movement_clamped_to_input_bounds() {
        let mut state = ChatState::new("#x".into());
        state.input = "abc".into();
        state.input_cursor = 0;
        move_cursor_left(&mut state);
        assert_eq!(state.input_cursor, 0, "cursor must clamp at 0");
        state.input_cursor = 3;
        move_cursor_right(&mut state);
        assert_eq!(state.input_cursor, 3, "cursor must clamp at len");
    }

    #[test]
    fn cursor_handles_multibyte_chars() {
        // Two-byte 'é' should advance/recede by 2 in cursor space so
        // we never land on a non-boundary index.
        let mut state = ChatState::new("#x".into());
        state.input = "é".into(); // 2 bytes
        state.input_cursor = 0;
        move_cursor_right(&mut state);
        assert_eq!(state.input_cursor, 2);
        move_cursor_left(&mut state);
        assert_eq!(state.input_cursor, 0);
    }

    #[test]
    fn message_from_decoded_block_copies_fields() {
        let decoded = DecodedBlock {
            sender: "did:jig:zABC".into(),
            body: "hello".into(),
            ts: 12345,
            parity_warning: true,
            parity_hash_count: 2,
        };
        let m: Message = decoded.into();
        assert_eq!(m.sender, "did:jig:zABC");
        assert_eq!(m.body, "hello");
        assert_eq!(m.ts, 12345);
        assert!(m.parity_warning);
    }
}
