//! v0.0.2 hello-world `jig-server` configuration.
//!
//! Standalone config type used by `jig-server`'s Phase B/D AppState boot path.
//! Intentionally independent of the existing Profile / NameserverNetworkConfig
//! systems in this crate — those serve other deployment targets and will be
//! reconciled with this module in v0.0.3+.
//!
//! ## Sections
//! - `[server]`     — bind address, server DID keyfile, allowed block kinds
//! - `[identity]`   — TOFU vs nameserver mode + trusted nameservers
//! - `[federation]` — peers + TLS toggle
//! - `[debug]`      — antipattern-flag-gated REST endpoints + nameserver enumeration
//!
//! All antipattern flags follow the project convention (`dangerously_`,
//! `naively_`, `unsafe_`, `debug_`-prefixed) and are listed by
//! [`JigServerConfig::unsafe_options_active`] for advertisement in
//! `GET /.well-known/jig`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct JigServerConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub identity: IdentitySection,
    #[serde(default)]
    pub federation: FederationSection,
    #[serde(default)]
    pub debug: DebugSection,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerSection {
    pub listen: String,
    pub server_did_keyfile: String,
    pub allowed_block_kinds: Vec<String>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7117".to_string(),
            server_did_keyfile: "~/.jig/server/server.key".to_string(),
            // Core v0.0.2 block kinds. text-render is the chat-message kind;
            // channel-create + member-add are required by F4's `jig channel
            // create/join` flow and are core (not opt-in) for v0.0.2 because
            // there's no other way to bootstrap a channel until v0.0.3+
            // ships Wasm-executed channel ops.
            allowed_block_kinds: vec![
                "text-render".to_string(),
                "channel-create".to_string(),
                "member-add".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityMode {
    Tofu,
    Nameserver,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdentitySection {
    pub mode: IdentityMode,
    #[serde(default)]
    pub trusted_nameservers: Vec<String>,
    pub cache_ttl_seconds: u64,
    pub naively_allow_unknown_handles_fallback: bool,
}

impl Default for IdentitySection {
    fn default() -> Self {
        Self {
            mode: IdentityMode::Tofu,
            trusted_nameservers: vec![],
            cache_ttl_seconds: 300,
            naively_allow_unknown_handles_fallback: false,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct FederationSection {
    #[serde(default)]
    pub peers: Vec<FederationPeer>,
    pub dangerously_disable_federation_tls: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FederationPeer {
    pub url: String,
    pub expected_did: String,
    #[serde(default)]
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct DebugSection {
    pub admin_endpoints: bool,
    pub list_handles: bool,
}

impl JigServerConfig {
    /// List of active antipattern flags. Returned by `GET /.well-known/jig`
    /// so federated peers can detect a misconfigured node. ALWAYS includes
    /// `naively_unbounded_clock_skew` in v0.0.2 (no time-attestation servers exist yet).
    pub fn unsafe_options_active(&self) -> Vec<String> {
        let mut active = vec!["naively_unbounded_clock_skew".to_string()];
        if self.debug.admin_endpoints {
            active.push("debug.admin_endpoints".to_string());
        }
        if self.federation.dangerously_disable_federation_tls {
            active.push("federation.dangerously_disable_federation_tls".to_string());
        }
        if self.identity.naively_allow_unknown_handles_fallback {
            active.push("identity.naively_allow_unknown_handles_fallback".to_string());
        }
        if self.debug.list_handles {
            active.push("debug.list_handles".to_string());
        }
        active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_round_trips_through_toml() {
        let cfg = JigServerConfig::default();
        let toml_str = toml::to_string(&cfg).unwrap();
        let parsed: JigServerConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn default_identity_mode_is_tofu() {
        let cfg = JigServerConfig::default();
        assert_eq!(cfg.identity.mode, IdentityMode::Tofu);
        assert!(cfg.identity.trusted_nameservers.is_empty());
    }

    #[test]
    fn default_listen_is_loopback_for_safety() {
        let cfg = JigServerConfig::default();
        assert_eq!(cfg.server.listen, "127.0.0.1:7117");
    }

    #[test]
    fn default_allowed_block_kinds_includes_core_v0_0_2_kinds() {
        // v0.0.2 needs text-render (chat messages), channel-create, and
        // member-add (channel ops) in the default allow list — the
        // hello-world flow can't run without them. Operators should
        // explicitly remove kinds to restrict; v0.0.2 doesn't ship a
        // narrower default.
        let cfg = JigServerConfig::default();
        for required in ["text-render", "channel-create", "member-add"] {
            assert!(
                cfg.server.allowed_block_kinds.iter().any(|k| k == required),
                "default allowed_block_kinds must include `{required}`; got {:?}",
                cfg.server.allowed_block_kinds
            );
        }
    }

    #[test]
    fn antipattern_flags_default_off() {
        let cfg = JigServerConfig::default();
        assert!(!cfg.federation.dangerously_disable_federation_tls);
        assert!(!cfg.debug.admin_endpoints);
        assert!(!cfg.identity.naively_allow_unknown_handles_fallback);
        assert!(!cfg.debug.list_handles);
    }

    #[test]
    fn unsafe_options_always_lists_unbounded_clock_skew() {
        let cfg = JigServerConfig::default();
        let active = cfg.unsafe_options_active();
        assert!(
            active.contains(&"naively_unbounded_clock_skew".to_string()),
            "v0.0.2 default install must always advertise naively_unbounded_clock_skew"
        );
    }

    #[test]
    fn unsafe_options_active_lists_enabled_antipatterns() {
        let mut cfg = JigServerConfig::default();
        cfg.debug.admin_endpoints = true;
        cfg.federation.dangerously_disable_federation_tls = true;
        cfg.identity.naively_allow_unknown_handles_fallback = true;
        cfg.debug.list_handles = true;
        let active = cfg.unsafe_options_active();
        assert!(active.contains(&"debug.admin_endpoints".to_string()));
        assert!(active.contains(&"federation.dangerously_disable_federation_tls".to_string()));
        assert!(active.contains(&"identity.naively_allow_unknown_handles_fallback".to_string()));
        assert!(active.contains(&"debug.list_handles".to_string()));
        assert!(active.contains(&"naively_unbounded_clock_skew".to_string()));
    }

    #[test]
    fn federation_peer_parses_from_toml() {
        let toml_input = r#"
            [server]
            listen = "0.0.0.0:443"
            server_did_keyfile = "/etc/jig/server.key"
            allowed_block_kinds = ["text-render"]

            [identity]
            mode = "nameserver"
            trusted_nameservers = ["https://ns.jig.onl"]
            cache_ttl_seconds = 600
            naively_allow_unknown_handles_fallback = false

            [federation]
            dangerously_disable_federation_tls = false

            [[federation.peers]]
            url = "wss://deji.jig.onl"
            expected_did = "did:jig:zABC"
            alias = "deji.jig"

            [debug]
            admin_endpoints = true
            list_handles = false
        "#;
        let cfg: JigServerConfig = toml::from_str(toml_input).unwrap();
        assert_eq!(cfg.server.listen, "0.0.0.0:443");
        assert_eq!(cfg.identity.mode, IdentityMode::Nameserver);
        assert_eq!(cfg.identity.trusted_nameservers, vec!["https://ns.jig.onl"]);
        assert_eq!(cfg.federation.peers.len(), 1);
        assert_eq!(cfg.federation.peers[0].alias.as_deref(), Some("deji.jig"));
        assert!(cfg.debug.admin_endpoints);
    }

    #[test]
    fn missing_sections_use_defaults() {
        // Minimal config — only [server] required-shape fields specified
        let toml_input = r#"
            [server]
            listen = "127.0.0.1:7117"
            server_did_keyfile = "/tmp/key"
            allowed_block_kinds = ["text-render"]
        "#;
        let cfg: JigServerConfig = toml::from_str(toml_input).unwrap();
        assert_eq!(cfg.identity.mode, IdentityMode::Tofu);
        assert!(cfg.federation.peers.is_empty());
        assert!(!cfg.debug.admin_endpoints);
    }
}
