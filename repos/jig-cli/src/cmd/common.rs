//! Shared helpers for v0.0.2 hello-world subcommands.
//!
//! `keys.rs`, `channel.rs`, `send.rs`, and `tail.rs` all need the same two
//! moves: load the identity referenced by `[user] did` in `~/.jig/cli.toml`,
//! and surface the configured server base URL. Factoring them here keeps
//! each subcommand body tight and avoids three slightly-different copies
//! drifting over time.
//!
//! Both helpers fail loudly with operator-readable context when the
//! config is missing or the keyfile can't be loaded — the goal is "tell
//! the user to run `jig init`" rather than dump a low-level IO error.

use anyhow::{Context, Result};
use jig_client::Identity;

use crate::config;

/// Load the identity referenced by `[user] did` in `~/.jig/cli.toml`.
///
/// Bails with a friendly hint to run `jig init` if the DID looks empty
/// or non-canonical. The keyfile must exist under `~/.jig/keys/<did>.key`
/// with 0600 permissions on Unix.
pub fn load_active_identity() -> Result<Identity> {
    let cfg = config::load_config(None)?;
    let did_str = cfg.user.did.clone();
    if !did_str.starts_with("did:jig:") {
        anyhow::bail!(
            "cli.toml `[user] did = \"{did_str}\"` does not look like a Jig DID. \
             Run `jig init` first."
        );
    }
    let keys_dir = jig_client::identity::default_keys_dir();
    let id = Identity::load_from_dir(&keys_dir, &did_str)
        .with_context(|| format!("loading identity {did_str} from {}", keys_dir.display()))?;
    Ok(id)
}

/// Return the configured server base URL (the `[server] base_url` field in
/// `~/.jig/cli.toml`). May be `http://`, `https://`, `ws://`, or `wss://` —
/// `jig_client::Client::connect` accepts all four and transposes HTTP
/// schemes to WS itself, so we don't rewrite here.
pub fn load_server_url() -> Result<String> {
    let cfg = config::load_config(None)?;
    let url = cfg.server.base_url.trim().to_string();
    if url.is_empty() {
        anyhow::bail!(
            "no server base URL configured — run `jig server set <url>` first."
        );
    }
    Ok(url)
}
