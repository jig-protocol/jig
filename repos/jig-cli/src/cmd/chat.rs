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
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{
    io::{Stdout, stdout},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc;

use crate::cmd::blocks_decode::decode;
use crate::cmd::chat_view::{ChatState, Message, drain_inbound, render, submit_failure_status};
use crate::cmd::common::CliContext;
use crate::cmd::display::{bell_on_inbound, connection_lost};
use crate::cmd::history;

/// Args struct for `jig chat <channel>`. Lives here (rather than in
/// `main.rs`) so the run loop stays self-contained — the clap layer
/// only needs to forward the channel slug.
#[derive(Debug, Clone)]
pub struct ChatArgs {
    pub channel: String,
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
pub async fn run(ctx: &CliContext, args: ChatArgs) -> Result<()> {
    let id = ctx.identity()?;
    let server_url = ctx.server_url()?;

    // `handle_submit` re-loads the identity from a spawned task, so the
    // context has to outlive this frame. Cloning is cheap (two small
    // Configs + a PathBuf) and keeps `main.rs` free of Arc bookkeeping.
    let ctx = Arc::new(ctx.clone());

    // Fetch history BEFORE the terminal goes into raw mode: any warning
    // from a server without the history endpoint has to print as ordinary
    // text, not into the alternate screen we would otherwise already own.
    let backlog = history::backfill(
        &id,
        &server_url,
        &args.channel,
        history::DEFAULT_HISTORY_LIMIT,
    )
    .await;

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

    // Submit failures travel on their own channel: `msg_tx` belongs to the
    // reader task alone, so that its drop is an unambiguous "connection
    // gone" signal. A send-task clone of it would keep the queue alive past
    // the disconnect and hide the very thing we now detect.
    let (status_tx, mut status_rx) = mpsc::unbounded_channel::<String>();

    let guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal: Terminal<CrosstermBackend<Stdout>> =
        Terminal::new(backend).context("constructing terminal")?;

    let mut state = ChatState::with_history(
        args.channel.clone(),
        backlog,
        ctx.effective().contacts.clone(),
    );

    let result = event_loop(
        &mut terminal,
        &mut state,
        &mut msg_rx,
        &mut status_rx,
        &status_tx,
        &client,
        &ctx,
    )
    .await;

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
    status_rx: &mut mpsc::UnboundedReceiver<String>,
    status_tx: &mpsc::UnboundedSender<String>,
    client: &Arc<Client>,
    ctx: &Arc<CliContext>,
) -> Result<()> {
    loop {
        // Drain any inbound messages before redrawing so we paint the
        // latest state in one pass.
        let drained = drain_inbound(state, msg_rx);
        // Bell on stderr: stdout belongs to ratatui for the duration of the
        // TUI, so a `\x07` written there would land inside the frame buffer.
        bell_on_inbound(drained.count, &mut std::io::stderr());

        // Drain submit failures reported by the fire-and-forget send tasks.
        while let Ok(status) = status_rx.try_recv() {
            state.status = Some(status);
        }

        if drained.disconnected {
            // Paint the backlog we just drained before tearing the TUI down,
            // so the last messages are not lost with the connection.
            terminal.draw(|f| render(f, state)).context("draw frame")?;
            return Err(connection_lost(&state.channel));
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
                    handle_submit(state, client, ctx, status_tx);
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

/// Spawned submit. Spawning means the WSS round-trip doesn't block
/// redraws; failures come back over `status_tx` and are painted in the
/// input pane, so a message that did not send never looks sent.
fn handle_submit(
    state: &mut ChatState,
    client: &Arc<Client>,
    ctx: &Arc<CliContext>,
    status_tx: &mpsc::UnboundedSender<String>,
) {
    if state.input.is_empty() {
        return;
    }
    let body = std::mem::take(&mut state.input);
    state.input_cursor = 0;
    state.status = None;
    let channel = state.channel.clone();
    let client = client.clone();
    let ctx = ctx.clone();
    let status_tx = status_tx.clone();
    tokio::spawn(async move {
        // We need an Identity to derive the HLC stamp + sign the block.
        // The Client owns the original Identity by Arc, but doesn't
        // expose it; re-loading from disk is cheap (a single 32-byte
        // read + ed25519 pubkey derivation) and matches how `jig send`
        // does it in F5.
        let id = match ctx.identity() {
            Ok(id) => id,
            Err(e) => {
                let _ = status_tx.send(submit_failure_status(&body, &format!("{e:#}")));
                return;
            }
        };
        let hlc = HlcTimestamp::now_wall(id.did().clone());
        let block = build_text_render(&id, &channel, &body, hlc);
        if let Err(e) = client.submit(block).await {
            let _ = status_tx.send(submit_failure_status(&body, &format!("{e}")));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
