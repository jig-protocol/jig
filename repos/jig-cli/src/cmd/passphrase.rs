//! How the CLI unlocks identity keys: the environment and the OS keychain
//! (`jig_client::identity::KeyAccess::from_env`), then a passphrase typed at
//! the terminal.

#[cfg(not(unix))]
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::sync::{Arc, OnceLock};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use jig_client::identity::{KeyAccess, Prompt, PromptPurpose};
use zeroize::Zeroizing;

/// The key access every command uses, built once per process: finding the OS
/// keychain can mean running `secret-tool`.
pub fn key_access() -> anyhow::Result<&'static KeyAccess> {
    static ACCESS: OnceLock<KeyAccess> = OnceLock::new();
    if let Some(access) = ACCESS.get() {
        return Ok(access);
    }
    let access = KeyAccess::from_env()?
        .with_prompt(Arc::new(TerminalPrompt))
        // The CLI installs no tracing subscriber; a keychain that fails and
        // is replaced by a passphrase slot must still be said out loud.
        .with_notice(Arc::new(|message| eprintln!("warning: {message}")));
    Ok(ACCESS.get_or_init(|| access))
}

/// Say what loading an identity did to files on disk: a raw key sealed, old
/// rotated keys sealed. Printed to stderr, so it never mixes with output.
pub fn report_migration(identity: &jig_client::Identity, keys_dir: &std::path::Path) {
    if let Some(raw) = identity.migrated_from() {
        eprintln!(
            "note: sealed {} into {} and removed the unencrypted file. A deleted file can \
             survive on SSDs and in backups: if this key may have been copied, move to a \
             new one with `jig keys rotate`.",
            raw.display(),
            jig_client::identity::key_path(keys_dir, &identity.did_string()).display()
        );
    }
}

/// Say, every time, that this identity's key is stored unencrypted. An install
/// banner scrolls away; this does not.
pub fn warn_if_unsealed(identity: &jig_client::Identity) {
    if !identity.is_sealed() {
        eprintln!(
            "warning: the key for {} is stored unencrypted (JIG_KEYS_STORAGE=plaintext). \
             Seal it by running jig once without that variable, from a terminal or with \
             JIG_KEY_PASSPHRASE set.",
            identity.did_string()
        );
    }
}

/// Asks on the terminal, without echo. Declines when there is no terminal, so
/// a script fails with the error that names `JIG_KEY_PASSPHRASE` instead of
/// hanging.
struct TerminalPrompt;

/// Whether a person can be asked. On Unix that is the controlling terminal,
/// not stdin: `curl … | bash` runs `jig init` with stdin on the pipe and the
/// person still at `/dev/tty`, which is where crossterm reads keys from.
/// `JIG_NONINTERACTIVE=1` says never to ask, as it does for `install.sh`.
fn terminal_available() -> bool {
    if std::env::var_os("JIG_NONINTERACTIVE").is_some_and(|v| v == "1") {
        return false;
    }
    #[cfg(unix)]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
    }
    #[cfg(not(unix))]
    {
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }
}

impl Prompt for TerminalPrompt {
    fn passphrase(
        &self,
        did: &str,
        purpose: PromptPurpose,
    ) -> std::io::Result<Option<Zeroizing<String>>> {
        if !terminal_available() {
            return Ok(None);
        }
        match purpose {
            PromptPurpose::Unlock => read_hidden(&format!("passphrase for {did}: ")).map(Some),
            PromptPurpose::New => {
                let mut out = terminal_writer();
                writeln!(
                    out,
                    "No OS keychain is available, so {did} will be sealed with a passphrase."
                )?;
                for _ in 0..3 {
                    let first = read_hidden("new passphrase: ")?;
                    if first.is_empty() {
                        writeln!(terminal_writer(), "the passphrase cannot be empty")?;
                        continue;
                    }
                    let second = read_hidden("repeat it: ")?;
                    if *first == *second {
                        return Ok(Some(first));
                    }
                    writeln!(terminal_writer(), "the two did not match")?;
                }
                Ok(None)
            }
        }
    }
}

/// Read one line from the terminal with echo off. The label goes to the
/// terminal too, so it shows even when stderr is redirected.
fn read_hidden(label: &str) -> std::io::Result<Zeroizing<String>> {
    let mut out = terminal_writer();
    write!(out, "{label}")?;
    out.flush()?;
    terminal::enable_raw_mode()?;
    let result = read_line_raw();
    terminal::disable_raw_mode()?;
    writeln!(out)?;
    result
}

fn terminal_writer() -> Box<dyn std::io::Write> {
    #[cfg(unix)]
    if let Ok(tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        return Box::new(tty);
    }
    Box::new(std::io::stderr())
}

/// The longest passphrase the prompt takes, in bytes. The buffer is allocated
/// once at this size so it never moves: a `String` that grows leaves copies of
/// what it held in memory it frees without wiping.
const MAX_PASSPHRASE: usize = 1024;

fn read_line_raw() -> std::io::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::with_capacity(MAX_PASSPHRASE));
    let mut too_long = false;
    loop {
        let Event::Key(KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            ..
        }) = event::read()?
        else {
            continue;
        };
        match code {
            KeyCode::Enter if too_long => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("a passphrase can be at most {MAX_PASSPHRASE} bytes"),
                ));
            }
            KeyCode::Enter => return Ok(line),
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "passphrase entry cancelled",
                ));
            }
            KeyCode::Backspace => {
                line.pop();
            }
            KeyCode::Char(c) if line.len() + c.len_utf8() <= MAX_PASSPHRASE => line.push(c),
            KeyCode::Char(_) => too_long = true,
            _ => {}
        }
    }
}
