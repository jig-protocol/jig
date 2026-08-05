//! Configuration management

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub server: ServerSection,
    pub user: UserSection,
    /// Local address book: DID → display name, rendered by `jig chat` and
    /// `jig tail` in place of the 61-character DID.
    ///
    /// Purely a read-side, on-this-machine concern. It is deliberately NOT
    /// derived from block metadata: writing a `nickname` into a block is
    /// what arms the server's identity (TOFU) check, so names stay here.
    ///
    /// Declared last because it serialises as a TOML table — a map before
    /// `[server]`/`[user]` would swallow them.
    #[serde(default)]
    pub contacts: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerSection {
    pub base_url: String,
    /// Nameserver used by `jig ns` when `--nameserver` is not given.
    /// Optional and skipped when unset, so an existing `cli.toml` neither
    /// needs it nor grows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nameserver_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserSection {
    pub did: String,
    pub display_name: String,
    pub default_channel: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerSection {
                base_url: "http://127.0.0.1:7117".to_string(),
                nameserver_url: None,
            },
            user: UserSection {
                did: format!("did:jig:{}", whoami::username()),
                display_name: whoami::username(),
                default_channel: "#general".to_string(),
            },
            contacts: BTreeMap::new(),
        }
    }
}

/// Record `did → display_name` in the local address book, replacing any
/// previous name for that DID.
///
/// Blank inputs are ignored: an empty name renders as an empty sender
/// column, which is worse than the truncated DID it would replace.
pub fn remember_contact(cfg: &mut Config, did: &str, display_name: &str) {
    let did = did.trim();
    let name = display_name.trim();
    if did.is_empty() || name.is_empty() {
        return;
    }
    cfg.contacts.insert(did.to_string(), name.to_string());
}

pub fn load_config(path: Option<&Path>) -> Result<Config> {
    let config_path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_config_path);

    if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path)?;
        Ok(toml::from_str(&contents)?)
    } else {
        Ok(Config::default())
    }
}

pub fn save_config(config: &Config, path: Option<&Path>) -> Result<()> {
    let config_path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_config_path);

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let contents = toml::to_string_pretty(config)?;
    std::fs::write(&config_path, contents)?;
    Ok(())
}

/// Path to the v0.0.2 CLI config: `~/.jig/cli.toml`.
///
/// This is intentionally distinct from `~/.jig/config.toml` (the legacy
/// v0.0.1 path) and from `~/.jig/server.toml` (the server-side config).
pub fn default_config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".jig")
        .join("cli.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_without_a_contacts_table_still_loads() {
        // Every cli.toml written before contacts existed has no `[contacts]`
        // table; those must keep loading rather than failing at startup.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        std::fs::write(
            &path,
            "[server]\nbase_url = \"http://127.0.0.1:7117\"\n\n\
             [user]\ndid = \"did:jig:zA\"\ndisplay_name = \"dj\"\n\
             default_channel = \"#general\"\n",
        )
        .unwrap();

        let cfg = load_config(Some(&path)).unwrap();
        assert!(cfg.contacts.is_empty());
    }

    #[test]
    fn contacts_round_trip_through_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cli.toml");
        let mut cfg = Config::default();
        remember_contact(&mut cfg, "did:jig:zAlice", "alice");
        save_config(&cfg, Some(&path)).unwrap();

        let reloaded = load_config(Some(&path)).unwrap();
        assert_eq!(
            reloaded.contacts.get("did:jig:zAlice").map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn remember_contact_ignores_blank_names_and_dids() {
        // A blank display_name would render as an empty sender column,
        // which is worse than the truncated DID it replaces.
        let mut cfg = Config::default();
        remember_contact(&mut cfg, "did:jig:zA", "   ");
        remember_contact(&mut cfg, "  ", "alice");
        assert!(cfg.contacts.is_empty());
    }

    #[test]
    fn remember_contact_overwrites_a_stale_name_for_the_same_did() {
        let mut cfg = Config::default();
        remember_contact(&mut cfg, "did:jig:zA", "old");
        remember_contact(&mut cfg, "did:jig:zA", "new");
        assert_eq!(
            cfg.contacts.get("did:jig:zA").map(String::as_str),
            Some("new")
        );
    }
}
