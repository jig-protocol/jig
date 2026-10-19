//! Configuration management

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub server: ServerSection,
    pub user: UserSection,
    /// Which DIDs speak for which name suffixes (JEP-0004 `config` roots).
    /// Skipped when empty, so an existing `cli.toml` neither needs it nor
    /// grows it.
    #[serde(default, skip_serializing_if = "NamingSection::is_empty")]
    pub naming: NamingSection,
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

/// `[naming]`: the suffix delegations this client holds itself.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamingSection {
    /// `[naming.delegations.<suffix>]`. A suffix with no entry is looked up
    /// through `dns` discovery, except [`DEFAULT_SUFFIX`], which falls back
    /// to [`default_jig_delegation`].
    #[serde(default)]
    pub delegations: BTreeMap<String, DelegationEntry>,
}

impl NamingSection {
    fn is_empty(&self) -> bool {
        self.delegations.is_empty()
    }
}

/// One `[naming.delegations.<suffix>]` entry. Mirrors
/// `jig_client::naming::ConfigDelegation`, which has no `Serialize`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationEntry {
    /// The DIDs whose attestations count for this suffix.
    pub authorities: Vec<String>,
    /// The nameserver URLs to ask.
    pub nameservers: Vec<String>,
}

/// The suffix default names live under: `alice@jig`.
pub const DEFAULT_SUFFIX: &str = "jig";

/// The authority DID for [`DEFAULT_SUFFIX`].
///
/// TODO(DJ): replace with the DID from the project nameserver's key ceremony.
/// Until then this is [`PLACEHOLDER_JIG_AUTHORITY`], a test DID whose key
/// nobody holds, and a release build refuses to use it.
pub const DEFAULT_JIG_AUTHORITY: &str = PLACEHOLDER_JIG_AUTHORITY;

/// The project nameserver for [`DEFAULT_SUFFIX`].
///
/// TODO(DJ): confirm the URL alongside [`DEFAULT_JIG_AUTHORITY`].
pub const DEFAULT_JIG_NAMESERVER: &str = "https://ns.jig-protocol.org";

/// The DID of the ed25519 key with seed `[0x4a; 32]` ("J"). Only tests and
/// debug builds may resolve under it.
pub const PLACEHOLDER_JIG_AUTHORITY: &str =
    "did:jig:zgu6iu77ozi4lfrctnyf5ewdp3mmna4hfbycz6hkd7c767ol2ptqq";

/// The built-in delegation for [`DEFAULT_SUFFIX`], or why this build has
/// none: a release build fails closed while the authority is the
/// placeholder.
pub fn default_jig_delegation() -> Result<DelegationEntry> {
    default_delegation_for(DEFAULT_JIG_AUTHORITY, cfg!(debug_assertions))
}

fn default_delegation_for(authority: &str, debug_build: bool) -> Result<DelegationEntry> {
    if authority == PLACEHOLDER_JIG_AUTHORITY && !debug_build {
        anyhow::bail!(
            "this build has no authority for `@{DEFAULT_SUFFIX}` names yet (the project \
             nameserver's DID is still a placeholder); add a \
             [naming.delegations.{DEFAULT_SUFFIX}] entry to cli.toml to resolve them"
        );
    }
    Ok(DelegationEntry {
        authorities: vec![authority.to_string()],
        nameservers: vec![DEFAULT_JIG_NAMESERVER.to_string()],
    })
}

/// The delegations a resolver uses: `cli.toml`'s, plus the built-in one for
/// [`DEFAULT_SUFFIX`] when `cli.toml` has none for it and this build has one.
pub fn delegations(cfg: &Config) -> jig_client::naming::Delegations {
    let mut entries = cfg.naming.delegations.clone();
    if !entries.contains_key(DEFAULT_SUFFIX)
        && let Ok(default) = default_jig_delegation()
    {
        entries.insert(DEFAULT_SUFFIX.to_string(), default);
    }
    jig_client::naming::Delegations {
        config: entries
            .into_iter()
            .map(|(suffix, e)| {
                (
                    suffix,
                    jig_client::naming::ConfigDelegation {
                        authorities: e.authorities,
                        nameservers: e.nameservers,
                    },
                )
            })
            .collect(),
    }
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
                // TLS, like the server's default (`[tls] enabled = true`).
                base_url: "https://127.0.0.1:7117".to_string(),
                nameserver_url: None,
            },
            user: UserSection {
                did: format!("did:jig:{}", os_username()),
                display_name: os_username(),
                default_channel: "#general".to_string(),
            },
            naming: NamingSection::default(),
            contacts: BTreeMap::new(),
        }
    }
}

/// Record `did → display_name` in the local address book, replacing any
/// previous name for that DID.
///
/// Blank inputs are ignored: an empty name renders as an empty sender
/// column, which is worse than the truncated DID it would replace.
/// The OS account name, the default nickname. `whoami` can fail to read it
/// (no passwd entry in a minimal container); fall back to a fixed name.
pub fn os_username() -> String {
    whoami::username().unwrap_or_else(|_| "user".to_string())
}

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
    fn the_placeholder_authority_is_the_did_of_the_test_seed() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x4a; 32]);
        let did =
            jig_core::Did::from_ed25519_pubkey(key.verifying_key().as_bytes()).to_did_jig_string();
        assert_eq!(PLACEHOLDER_JIG_AUTHORITY, did);
    }

    #[test]
    fn a_release_build_refuses_the_placeholder_authority() {
        let err = default_delegation_for(PLACEHOLDER_JIG_AUTHORITY, false).unwrap_err();
        assert!(err.to_string().contains("placeholder"), "{err}");
        assert!(default_delegation_for(PLACEHOLDER_JIG_AUTHORITY, true).is_ok());
        let real = default_delegation_for("did:jig:zReal", false).unwrap();
        assert_eq!(real.authorities, ["did:jig:zReal"]);
        assert_eq!(real.nameservers, [DEFAULT_JIG_NAMESERVER]);
    }

    #[test]
    fn delegations_round_trip_through_cli_toml_and_back_the_default_suffix() {
        let mut cfg = Config::default();
        cfg.naming.delegations.insert(
            "example.org".into(),
            DelegationEntry {
                authorities: vec!["did:jig:zA".into()],
                nameservers: vec!["https://ns.example.org".into()],
            },
        );
        let text = toml::to_string_pretty(&cfg).unwrap();
        assert!(
            text.contains("[naming.delegations.\"example.org\"]"),
            "{text}"
        );
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.naming, cfg.naming);

        // cli.toml's own entries, plus the built-in `jig` one.
        let d = delegations(&back);
        assert_eq!(d.config["example.org"].authorities, ["did:jig:zA"]);
        assert_eq!(
            d.config[DEFAULT_SUFFIX].authorities,
            [DEFAULT_JIG_AUTHORITY]
        );
    }

    #[test]
    fn a_jig_entry_in_cli_toml_wins_over_the_built_in_one() {
        let mut cfg = Config::default();
        let mine = DelegationEntry {
            authorities: vec!["did:jig:zMine".into()],
            nameservers: vec!["http://127.0.0.1:7399".into()],
        };
        cfg.naming
            .delegations
            .insert(DEFAULT_SUFFIX.into(), mine.clone());
        assert_eq!(
            delegations(&cfg).config[DEFAULT_SUFFIX].authorities,
            mine.authorities
        );
    }

    #[test]
    fn a_config_without_naming_writes_no_naming_table() {
        let text = toml::to_string_pretty(&Config::default()).unwrap();
        assert!(!text.contains("naming"), "{text}");
    }

    #[test]
    fn default_server_is_the_local_server_over_tls() {
        let base = Config::default().server.base_url;
        let url = reqwest::Url::parse(&base).unwrap();
        assert_eq!(url.scheme(), "https", "the server serves TLS by default");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(7117));
    }

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
