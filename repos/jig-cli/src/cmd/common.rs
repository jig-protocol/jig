//! Resolved run context shared by every subcommand.
//!
//! Every command needs the same three things: which config file we're
//! reading, which server we're talking to, and which identity is signing.
//! Before [`CliContext`] existed each command re-derived those from
//! `~/.jig/cli.toml` on its own, which meant the global `--server`,
//! `--config` and `--did` flags were parsed and then silently dropped.
//!
//! `main.rs` resolves exactly one `CliContext` *before* any subcommand
//! dispatch and hands it down, so there is a single place where overrides
//! are applied and a single place to look when a command talks to the
//! wrong server.
//!
//! # Precedence
//!
//! CLI flag > environment > config file > built-in default.
//!
//! The environment tier is empty: this crate reads no `JIG_*` (or any
//! other) environment variable today — it is named here only so that
//! whoever adds one slots it between the flag and the file instead of
//! inventing a different order.

use std::path::PathBuf;

use anyhow::{Context, Result};
use jig_client::Identity;

use crate::config::{self, Config};

/// The global flags declared on `Cli` in `main.rs`, lifted into one value
/// so `main` can pass them around without re-listing five fields.
#[derive(Debug, Clone, Default)]
pub struct GlobalOverrides {
    /// `--config <path>`. When set, the path MUST exist — see
    /// [`CliContext::resolve`].
    pub config: Option<PathBuf>,
    /// `--server <url>`; replaces `[server] base_url`.
    pub server: Option<String>,
    /// `--did <did>`; replaces `[user] did`, and therefore selects which
    /// keyfile [`CliContext::identity`] loads.
    pub did: Option<String>,
    /// `--display-name <name>`; replaces `[user] display_name`.
    pub display_name: Option<String>,
    /// `--channel <slug>`; replaces `[user] default_channel`.
    pub channel: Option<String>,
}

impl GlobalOverrides {
    /// The config file this invocation reads and writes: the explicit
    /// `--config` path when given, otherwise `~/.jig/cli.toml`.
    pub fn config_path(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(config::default_config_path)
    }
}

/// Config + overrides, resolved once per process.
///
/// Holds both the on-disk config and the effective (post-override) one.
/// Commands that *persist* config (`server set`, `keys rotate`) start from
/// [`CliContext::file_config`] so a one-shot `--server` override can never
/// leak into `cli.toml`; everything else reads
/// [`CliContext::effective`].
#[derive(Debug, Clone)]
pub struct CliContext {
    config_path: PathBuf,
    file_config: Config,
    effective: Config,
}

impl CliContext {
    /// Load the config file and apply the global flags on top.
    ///
    /// An explicitly-passed `--config` path that does not exist is a hard
    /// error: the operator named that file, so a typo must not degrade into
    /// "silently talk to the default server". The implicit
    /// `~/.jig/cli.toml` keeps the permissive behaviour — a first run
    /// legitimately has no config yet, and `jig init` is what creates it.
    pub fn resolve(overrides: &GlobalOverrides) -> Result<Self> {
        let config_path = overrides.config_path();
        if let Some(explicit) = &overrides.config
            && !explicit.exists()
        {
            anyhow::bail!(
                "config file not found: {} (passed via --config). \
                 Omit --config to use {}.",
                explicit.display(),
                config::default_config_path().display()
            );
        }

        let file_config = config::load_config(Some(&config_path))
            .with_context(|| format!("loading config from {}", config_path.display()))?;

        let mut effective = file_config.clone();
        if let Some(server) = &overrides.server {
            effective.server.base_url = server.clone();
        }
        if let Some(did) = &overrides.did {
            effective.user.did = did.clone();
        }
        if let Some(name) = &overrides.display_name {
            effective.user.display_name = name.clone();
        }
        if let Some(channel) = &overrides.channel {
            effective.user.default_channel = channel.clone();
        }

        Ok(Self {
            config_path,
            file_config,
            effective,
        })
    }

    /// Config with the CLI overrides applied — what commands should read.
    pub fn effective(&self) -> &Config {
        &self.effective
    }

    /// Config exactly as it is on disk, with no overrides applied — the
    /// starting point for any command that writes the file back.
    pub fn file_config(&self) -> &Config {
        &self.file_config
    }

    /// Persist `cfg` to the config file this invocation resolved
    /// (`--config <path>`, else `~/.jig/cli.toml`).
    pub fn save_file_config(&self, cfg: &Config) -> Result<()> {
        config::save_config(cfg, Some(&self.config_path))
            .with_context(|| format!("writing {}", self.config_path.display()))
    }

    /// Load the identity named by the effective `[user] did`.
    ///
    /// Bails with a friendly hint to run `jig init` if the DID looks empty
    /// or non-canonical. The keyfile must exist under
    /// `~/.jig/keys/<did>.key` with 0600 permissions on Unix.
    pub fn identity(&self) -> Result<Identity> {
        let did_str = self.effective.user.did.clone();
        if !did_str.starts_with("did:jig:") {
            anyhow::bail!(
                "`[user] did = \"{did_str}\"` in {} does not look like a Jig DID. \
                 Run `jig init` first.",
                self.config_path.display()
            );
        }
        let keys_dir = jig_client::identity::default_keys_dir();
        Identity::load_from_dir(&keys_dir, &did_str)
            .with_context(|| format!("loading identity {did_str} from {}", keys_dir.display()))
    }

    /// The effective server base URL. May be `http://`, `https://`,
    /// `ws://`, or `wss://` — `jig_client::Client::connect` accepts all
    /// four and transposes HTTP schemes to WS itself, so we don't rewrite
    /// here.
    pub fn server_url(&self) -> Result<String> {
        let url = self.effective.server.base_url.trim().to_string();
        if url.is_empty() {
            anyhow::bail!(
                "no server base URL configured in {} — run `jig server set <url>` first.",
                self.config_path.display()
            );
        }
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn overrides_for(path: &Path) -> GlobalOverrides {
        GlobalOverrides {
            config: Some(path.to_path_buf()),
            ..Default::default()
        }
    }

    fn write_config(path: &Path, base_url: &str, did: &str) {
        std::fs::write(
            path,
            format!(
                "[server]\nbase_url = \"{base_url}\"\n\n\
                 [user]\ndid = \"{did}\"\ndisplay_name = \"file\"\n\
                 default_channel = \"#file\"\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn missing_explicit_config_path_is_an_error_naming_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("typo.toml");
        let err = CliContext::resolve(&overrides_for(&missing)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("typo.toml"), "error must name the path: {msg}");
    }

    #[test]
    fn overrides_win_over_file_but_do_not_mutate_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        write_config(&path, "http://127.0.0.1:7999", "did:jig:zFile");

        let ctx = CliContext::resolve(&GlobalOverrides {
            config: Some(path.clone()),
            server: Some("http://127.0.0.1:1".into()),
            did: Some("did:jig:zOverride".into()),
            display_name: Some("flag".into()),
            channel: Some("#flag".into()),
        })
        .unwrap();

        assert_eq!(ctx.server_url().unwrap(), "http://127.0.0.1:1");
        assert_eq!(ctx.effective().user.did, "did:jig:zOverride");
        assert_eq!(ctx.effective().user.display_name, "flag");
        assert_eq!(ctx.effective().user.default_channel, "#flag");

        // The on-disk view stays pristine so `server set` / `keys rotate`
        // can't write a one-shot override back into the file.
        assert_eq!(ctx.file_config().server.base_url, "http://127.0.0.1:7999");
        assert_eq!(ctx.file_config().user.did, "did:jig:zFile");
    }

    #[test]
    fn file_values_are_used_when_no_override_is_given() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        write_config(&path, "wss://deji.jig.onl", "did:jig:zFile");

        let ctx = CliContext::resolve(&overrides_for(&path)).unwrap();
        assert_eq!(ctx.server_url().unwrap(), "wss://deji.jig.onl");
        assert_eq!(ctx.effective().user.did, "did:jig:zFile");
    }

    #[test]
    fn save_file_config_writes_to_the_explicit_config_path() {
        // `server set` / `keys rotate` must write back to the file the
        // operator named, not to `~/.jig/cli.toml`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alt.toml");
        write_config(&path, "http://127.0.0.1:7999", "did:jig:zFile");

        let ctx = CliContext::resolve(&overrides_for(&path)).unwrap();
        let mut updated = ctx.file_config().clone();
        updated.server.base_url = "http://written.example:1234".into();
        ctx.save_file_config(&updated).unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("http://written.example:1234"),
            "expected the rewritten base_url in {}: {body}",
            path.display()
        );
    }

    #[test]
    fn identity_rejects_non_canonical_did_before_touching_the_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        write_config(&path, "http://127.0.0.1:7117", "not-a-did");

        let err = CliContext::resolve(&overrides_for(&path))
            .unwrap()
            .identity()
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("jig init"), "expected onboarding hint: {msg}");
    }

    #[test]
    fn empty_base_url_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        write_config(&path, "   ", "did:jig:zFile");

        let ctx = CliContext::resolve(&overrides_for(&path)).unwrap();
        let msg = format!("{:#}", ctx.server_url().unwrap_err());
        assert!(msg.contains("jig server set"), "expected hint: {msg}");
    }
}
