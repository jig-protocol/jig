//! The shared channel argument for commands that operate on one channel.
//!
//! These three commands all take "which channel", and all three took it
//! differently: `jig chat` wanted a required positional, `jig read` and
//! `jig tail` wanted a `--channel` flag and rejected a positional outright. A
//! new user who typed `jig tail '#ops'` — the shape `jig chat` had just taught
//! them — got `unexpected argument`. Nobody designed that; it accumulated one
//! subcommand at a time.
//!
//! [`ChannelArg`] is the single definition. Every channel-scoped command
//! flattens it, so the accepted forms cannot drift apart again, and adding a
//! fourth such command gets the same surface for free.
//!
//! `jig send` deliberately does **not** use this: its positional is the message
//! body (`jig send hello world`), so a positional channel there would be
//! genuinely ambiguous. It keeps a flag-only `--channel`.

use clap::Args;

/// A channel selection, accepted either positionally or as `--channel`.
#[derive(Args, Debug, Clone, Default)]
pub struct ChannelArg {
    /// Channel slug, e.g. `#hello`. Defaults to `[user] default_channel`
    /// from `~/.jig/cli.toml` when omitted.
    #[arg(
        value_name = "CHANNEL",
        conflicts_with = "channel_flag",
        value_parser = parse_channel,
    )]
    positional: Option<String>,

    /// Channel slug — the flag form of the positional argument above.
    /// Accepted so existing scripts and docs keep working.
    #[arg(
        long = "channel",
        value_name = "CHANNEL",
        value_parser = parse_channel,
    )]
    channel_flag: Option<String>,
}

/// Rejects a blank channel at parse time.
///
/// `jig tail "$CHANNEL"` with `CHANNEL` unset expands to `jig tail ""`. Without
/// this the empty string satisfies the argument and surfaces much later as an
/// opaque lookup failure against a channel literally named `""` — the same
/// silent-wrong-thing shape as sending to the wrong channel. Fail at the
/// boundary, where the message can name the actual problem.
fn parse_channel(raw: &str) -> Result<String, String> {
    if raw.trim().is_empty() {
        return Err("channel must not be blank (try `#hello`)".to_string());
    }
    Ok(raw.to_string())
}

impl ChannelArg {
    /// The channel the user named, falling back to `default_channel`.
    ///
    /// The two input forms are mutually exclusive at parse time (see
    /// `conflicts_with` above), so this is a fallback chain, not a precedence
    /// rule: at most one of them can ever be set.
    pub fn resolve(&self, default_channel: &str) -> String {
        self.positional
            .clone()
            .or_else(|| self.channel_flag.clone())
            .unwrap_or_else(|| default_channel.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Minimal harness: `ChannelArg` is only ever reached via `#[command(flatten)]`,
    /// so exercise it the same way rather than constructing it by hand.
    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        channel: ChannelArg,
    }

    fn resolve_from(args: &[&str], default_channel: &str) -> String {
        Harness::try_parse_from(args)
            .expect("args should parse")
            .channel
            .resolve(default_channel)
    }

    #[test]
    fn a_positional_channel_is_used() {
        assert_eq!(resolve_from(&["t", "#ops"], "#default"), "#ops");
    }

    #[test]
    fn the_channel_flag_is_used() {
        assert_eq!(
            resolve_from(&["t", "--channel", "#ops"], "#default"),
            "#ops"
        );
    }

    #[test]
    fn an_omitted_channel_falls_back_to_the_default() {
        assert_eq!(resolve_from(&["t"], "#default"), "#default");
    }

    /// Two plausible readings, so refuse rather than silently pick one.
    #[test]
    fn supplying_both_forms_is_a_parse_error() {
        let err = Harness::try_parse_from(["t", "#a", "--channel", "#b"])
            .expect_err("positional and --channel must conflict");
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict,
            "expected a conflict error, got: {err}"
        );
    }

    #[test]
    fn a_blank_positional_channel_is_rejected() {
        let err = Harness::try_parse_from(["t", ""]).expect_err("blank channel must be rejected");
        assert!(
            err.to_string().contains("must not be blank"),
            "error should name the problem, got: {err}"
        );
    }

    #[test]
    fn a_blank_channel_flag_is_rejected() {
        let err = Harness::try_parse_from(["t", "--channel", "   "])
            .expect_err("whitespace-only channel must be rejected");
        assert!(
            err.to_string().contains("must not be blank"),
            "error should name the problem, got: {err}"
        );
    }

    /// A blank *default* is not this type's problem to police — it comes from
    /// config, not the command line — but it must not panic here.
    #[test]
    fn a_blank_default_is_passed_through_unchanged() {
        assert_eq!(resolve_from(&["t"], ""), "");
    }
}

/// The real `jig` argument surface, which had no parse tests at all before this.
///
/// These assert on the *accepted command-line shapes*, which is the contract
/// users and scripts actually depend on — `docs/GETTING_STARTED.md` documents
/// `jig tail --channel`, and `install.sh` ends by running `jig chat <channel>`.
/// Both must keep parsing regardless of how the internals are refactored.
#[cfg(test)]
mod cli_surface {
    use crate::{Cli, Commands};
    use clap::Parser;

    const DEFAULT: &str = "#default";

    /// Resolve the channel for any channel-scoped command, so each test below
    /// reads as "this command line means this channel".
    fn channel_of(args: &[&str]) -> String {
        let parsed = Cli::try_parse_from(args).expect("args should parse");
        match parsed.command {
            Some(Commands::Tail { channel }) | Some(Commands::Chat { channel }) => {
                channel.resolve(DEFAULT)
            }
            Some(Commands::Read { channel, .. }) => channel.resolve(DEFAULT),
            other => panic!("expected a channel-scoped command, got {other:?}"),
        }
    }

    fn parse_err(args: &[&str]) -> clap::Error {
        Cli::try_parse_from(args).expect_err("these args should have been rejected")
    }

    // --- `jig tail`: the parity fix -------------------------------------

    #[test]
    fn tail_accepts_a_positional_channel() {
        assert_eq!(channel_of(&["jig", "tail", "#ops"]), "#ops");
    }

    /// Regression guard: documented in docs/GETTING_STARTED.md and
    /// repos/jig-cli/README.md. Removing this flag would silently break both.
    #[test]
    fn tail_still_accepts_the_channel_flag() {
        assert_eq!(channel_of(&["jig", "tail", "--channel", "#ops"]), "#ops");
    }

    #[test]
    fn tail_with_no_channel_uses_the_default() {
        assert_eq!(channel_of(&["jig", "tail"]), DEFAULT);
    }

    #[test]
    fn tail_rejects_both_channel_forms_at_once() {
        let err = parse_err(&["jig", "tail", "#a", "--channel", "#b"]);
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    // --- `jig chat`: the shape tail is now matching ----------------------

    /// Regression guard: `install.sh` hands off to `jig chat <channel>` as the
    /// last step of first-run setup, and `scripts/jig-room.sh` wraps it.
    #[test]
    fn chat_still_accepts_a_positional_channel() {
        assert_eq!(channel_of(&["jig", "chat", "#ops"]), "#ops");
    }

    /// New: `chat`'s channel used to be required, so it was the one command
    /// that ignored `[user] default_channel` entirely.
    #[test]
    fn chat_with_no_channel_now_uses_the_default() {
        assert_eq!(channel_of(&["jig", "chat"]), DEFAULT);
    }

    #[test]
    fn chat_now_accepts_the_channel_flag_too() {
        assert_eq!(channel_of(&["jig", "chat", "--channel", "#ops"]), "#ops");
    }

    // --- `jig read`: same treatment, so the set is uniform ---------------

    #[test]
    fn read_accepts_either_channel_form() {
        assert_eq!(channel_of(&["jig", "read", "#ops"]), "#ops");
        assert_eq!(channel_of(&["jig", "read", "--channel", "#ops"]), "#ops");
    }

    #[test]
    fn read_keeps_its_limit_flag_alongside_a_positional_channel() {
        let parsed = Cli::try_parse_from(["jig", "read", "#ops", "--limit", "10"])
            .expect("args should parse");
        match parsed.command {
            Some(Commands::Read { channel, limit }) => {
                assert_eq!(channel.resolve(DEFAULT), "#ops");
                assert_eq!(limit, 10);
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    // --- blank-channel rejection reaches the real commands --------------

    #[test]
    fn a_blank_channel_is_rejected_on_every_channel_command() {
        for args in [
            ["jig", "tail", ""].as_slice(),
            ["jig", "chat", ""].as_slice(),
            ["jig", "read", ""].as_slice(),
            ["jig", "tail", "--channel", ""].as_slice(),
        ] {
            let err = parse_err(args);
            assert!(
                err.to_string().contains("must not be blank"),
                "{args:?} should be rejected as blank, got: {err}"
            );
        }
    }

    // --- things this change must NOT have altered ------------------------

    /// `send`'s positional is the message body, so it keeps a flag-only
    /// channel. `jig send hello world` must stay two message words, not a
    /// channel plus a word.
    #[test]
    fn send_keeps_its_message_positional_and_flag_only_channel() {
        let parsed = Cli::try_parse_from(["jig", "send", "hello", "world", "--channel", "#ops"])
            .expect("args should parse");
        match parsed.command {
            Some(Commands::Send { message, channel }) => {
                assert_eq!(message, vec!["hello", "world"]);
                assert_eq!(channel.as_deref(), Some("#ops"));
            }
            other => panic!("expected Send, got {other:?}"),
        }
    }

    /// `jig "hello world"` with no subcommand is an implicit send, driven by a
    /// top-level positional. Adding positionals to subcommands must not have
    /// captured it into one.
    #[test]
    fn the_implicit_send_positional_still_parses_with_no_subcommand() {
        let parsed = Cli::try_parse_from(["jig", "hello", "world"]).expect("args should parse");
        assert!(
            parsed.command.is_none(),
            "bare words must not be parsed as a subcommand, got {:?}",
            parsed.command
        );
        assert_eq!(parsed.message, vec!["hello", "world"]);
    }

    /// The top-level `--channel` override is a separate argument from the
    /// per-command one and must still parse before the subcommand.
    #[test]
    fn the_global_channel_override_still_parses() {
        let parsed = Cli::try_parse_from(["jig", "--channel", "#global", "tail"])
            .expect("global --channel should still parse");
        assert_eq!(parsed.channel.as_deref(), Some("#global"));
        match parsed.command {
            Some(Commands::Tail { channel }) => {
                // Nothing named on the subcommand, so the global override —
                // which main() folds into `default_channel` — is what wins.
                assert_eq!(channel.resolve("#folded-global"), "#folded-global");
            }
            other => panic!("expected Tail, got {other:?}"),
        }
    }
}
