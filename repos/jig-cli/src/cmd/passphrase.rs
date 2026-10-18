//! How the CLI unlocks identity keys: the environment and the OS keychain
//! (`jig_client::identity::KeyAccess::from_env`), then a passphrase typed at
//! the terminal.

use std::io::{IsTerminal as _, Write as _};
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
    let access = KeyAccess::from_env()?.with_prompt(Arc::new(TerminalPrompt));
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

/// Asks on the terminal, without echo. Declines when stdin is not a terminal,
/// so a script fails with the error that names `JIG_KEY_PASSPHRASE` instead of
/// hanging.
struct TerminalPrompt;

impl Prompt for TerminalPrompt {
    fn passphrase(
        &self,
        did: &str,
        purpose: PromptPurpose,
    ) -> std::io::Result<Option<Zeroizing<String>>> {
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Ok(None);
        }
        match purpose {
            PromptPurpose::Unlock => read_hidden(&format!("passphrase for {did}: ")).map(Some),
            PromptPurpose::New => {
                eprintln!(
                    "No OS keychain is available, so {did} will be sealed with a passphrase."
                );
                for _ in 0..3 {
                    let first = read_hidden("new passphrase: ")?;
                    if first.is_empty() {
                        eprintln!("the passphrase cannot be empty");
                        continue;
                    }
                    let second = read_hidden("repeat it: ")?;
                    if *first == *second {
                        return Ok(Some(first));
                    }
                    eprintln!("the two did not match");
                }
                Ok(None)
            }
        }
    }
}

/// Read one line from the terminal with echo off.
fn read_hidden(label: &str) -> std::io::Result<Zeroizing<String>> {
    let mut stderr = std::io::stderr();
    write!(stderr, "{label}")?;
    stderr.flush()?;
    terminal::enable_raw_mode()?;
    let result = read_line_raw();
    terminal::disable_raw_mode()?;
    writeln!(stderr)?;
    result
}

fn read_line_raw() -> std::io::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
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
            KeyCode::Char(c) => line.push(c),
            _ => {}
        }
    }
}
