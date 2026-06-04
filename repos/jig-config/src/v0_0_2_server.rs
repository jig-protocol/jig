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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct JigServerConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub identity: IdentitySection,
    #[serde(default)]
    pub federation: FederationSection,
    #[serde(default)]
    pub debug: DebugSection,
    #[serde(default)]
    pub bridges: BridgesSection,
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
    #[serde(default)]
    pub dangerously_disable_federation_tls: bool,
    /// Antipattern flag: when true, inbound peer blocks are persisted
    /// WITHOUT re-verifying the sender's ed25519 signature. v0.0.2 default
    /// behavior; v0.0.3+ rejects forged-author relays unless this is set.
    /// Surfaces in `unsafe_options_active` so federated peers and operators
    /// notice the carve-out via `GET /.well-known/jig`.
    #[serde(default)]
    pub naively_trust_peer_authored_blocks: bool,
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

/// Server-side bridge policy. Read at startup; gates whether
/// [`JigServerConfig::bridge_permitted`] returns true for each bridge name.
///
/// Defaults to deny-all: no bridges loaded unless explicitly allowlisted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BridgesSection {
    /// Allowlist: if non-empty, only these bridges may load. If empty, all
    /// bridges with `per_bridge.<name>.enabled = true` (and not in deny_list)
    /// may load. Empty + nothing in deny_list = deny-by-default (no bridges).
    #[serde(default)]
    pub allow_list: Vec<String>,

    /// Denylist: bridges in this list may not load regardless of allow_list.
    /// Special value `"*"` blocks all bridges (useful for high-sec lockdown).
    #[serde(default)]
    pub deny_list: Vec<String>,

    /// Per-bridge configuration. Keyed by bridge name (matches
    /// `Bridge::name()`).
    #[serde(default)]
    pub per_bridge: BTreeMap<String, BridgeSection>,
}

/// Per-bridge policy + configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BridgeSection {
    /// Kill-switch independent of allow_list / deny_list. A bridge with
    /// `enabled = false` does NOT load even if it's in allow_list.
    #[serde(default)]
    pub enabled: bool,

    /// Max submissions per minute. Enforcement scaffolded in alpha.1a;
    /// actual rate-counting lands in alpha.email.
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,

    /// Max submissions per day. Same scaffold-now-enforce-later treatment.
    #[serde(default)]
    pub rate_limit_per_day: Option<u32>,

    /// If non-empty, bridge submissions are restricted to these channel
    /// slugs. Empty = no channel restriction.
    #[serde(default)]
    pub allow_channels: Vec<String>,

    /// Bridge-specific opaque config table. Server passes this through to
    /// `BridgeContext::config` without inspection.
    #[serde(default)]
    pub config: toml::Table,
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
        if self.federation.naively_trust_peer_authored_blocks {
            active.push("federation.naively_trust_peer_authored_blocks".to_string());
        }
        if self.identity.naively_allow_unknown_handles_fallback {
            active.push("identity.naively_allow_unknown_handles_fallback".to_string());
        }
        if self.debug.list_handles {
            active.push("debug.list_handles".to_string());
        }
        // v0.0.3 (alpha.email): only the SQLite BridgeStorage backend ships;
        // the abstraction is unproven against Postgres/CockroachDB. Advertise
        // the limitation whenever any bridge would load, so federated peers +
        // operators can see it via /.well-known/jig.
        if self
            .bridges
            .per_bridge
            .keys()
            .any(|n| self.bridge_permitted(n))
        {
            active.push("naively_single_backend_bridge_storage".to_string());
        }
        active
    }

    /// Returns true if the bridge may load per current policy. Combines
    /// `allow_list`, `deny_list`, and per-bridge `enabled` checks.
    ///
    /// Decision order:
    /// 1. If bridge is in `deny_list` (or deny_list contains `"*"`) → false
    /// 2. If `allow_list` is non-empty AND bridge is not in it → false
    /// 3. If bridge has no `per_bridge` entry OR entry has `enabled = false` → false
    /// 4. Otherwise → true
    pub fn bridge_permitted(&self, name: &str) -> bool {
        // Step 1: deny_list check
        if self.bridges.deny_list.iter().any(|d| d == "*" || d == name) {
            return false;
        }
        // Step 2: allow_list gate
        if !self.bridges.allow_list.is_empty() && !self.bridges.allow_list.iter().any(|a| a == name)
        {
            return false;
        }
        // Step 3: per-bridge enabled check (also acts as deny-by-default
        // for bridges with no per_bridge entry at all)
        matches!(self.bridges.per_bridge.get(name), Some(b) if b.enabled)
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
        assert!(!cfg.federation.naively_trust_peer_authored_blocks);
        assert!(!cfg.debug.admin_endpoints);
        assert!(!cfg.identity.naively_allow_unknown_handles_fallback);
        assert!(!cfg.debug.list_handles);
    }

    #[test]
    fn naively_trust_peer_authored_blocks_surfaces_in_unsafe_options() {
        let mut cfg = JigServerConfig::default();
        assert!(
            !cfg.unsafe_options_active()
                .contains(&"federation.naively_trust_peer_authored_blocks".to_string()),
            "flag must not appear in active list when disabled"
        );
        cfg.federation.naively_trust_peer_authored_blocks = true;
        assert!(
            cfg.unsafe_options_active()
                .contains(&"federation.naively_trust_peer_authored_blocks".to_string()),
            "flag must appear in active list when enabled"
        );
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
        cfg.federation.naively_trust_peer_authored_blocks = true;
        cfg.identity.naively_allow_unknown_handles_fallback = true;
        cfg.debug.list_handles = true;
        let active = cfg.unsafe_options_active();
        assert!(active.contains(&"debug.admin_endpoints".to_string()));
        assert!(active.contains(&"federation.dangerously_disable_federation_tls".to_string()));
        assert!(active.contains(&"federation.naively_trust_peer_authored_blocks".to_string()));
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

    #[test]
    fn bridges_section_default_is_empty_allowlist() {
        let cfg = JigServerConfig::default();
        assert!(cfg.bridges.allow_list.is_empty());
        assert!(cfg.bridges.deny_list.is_empty());
        assert!(cfg.bridges.per_bridge.is_empty());
    }

    #[test]
    fn bridges_section_parses_full_toml() {
        let toml = r##"
            [bridges]
            allow_list = ["email", "slack"]
            deny_list = []

            [bridges.per_bridge.email]
            enabled = true
            rate_limit_per_minute = 60
            rate_limit_per_day = 5000
            allow_channels = ["#email-inbox", "#email-team"]

            [bridges.per_bridge.email.config]
            smtp_listen_addr = "0.0.0.0:25"
            resend_api_key = "rk_test"

            [bridges.per_bridge.slack]
            enabled = false
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.bridges.allow_list, vec!["email", "slack"]);
        assert!(cfg.bridges.deny_list.is_empty());

        let email = cfg.bridges.per_bridge.get("email").unwrap();
        assert!(email.enabled);
        assert_eq!(email.rate_limit_per_minute, Some(60));
        assert_eq!(email.rate_limit_per_day, Some(5000));
        assert_eq!(email.allow_channels, vec!["#email-inbox", "#email-team"]);
        assert_eq!(
            email
                .config
                .get("smtp_listen_addr")
                .and_then(|v| v.as_str()),
            Some("0.0.0.0:25"),
        );

        let slack = cfg.bridges.per_bridge.get("slack").unwrap();
        assert!(!slack.enabled);
    }

    #[test]
    fn bridge_permitted_default_deny_for_unknown() {
        // Empty config: nothing in allow_list, nothing in deny_list, no
        // per-bridge entry. Per spec: deny-by-default for unknown bridges.
        let cfg = JigServerConfig::default();
        assert!(!cfg.bridge_permitted("email"));
        assert!(!cfg.bridge_permitted("slack"));
    }

    #[test]
    fn bridge_permitted_allow_list_only() {
        let toml = r#"
            [bridges]
            allow_list = ["email"]

            [bridges.per_bridge.email]
            enabled = true
        "#;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        assert!(cfg.bridge_permitted("email"));
        assert!(!cfg.bridge_permitted("slack"));
    }

    #[test]
    fn bridge_permitted_deny_list_overrides_allow_list() {
        let toml = r#"
            [bridges]
            allow_list = ["email"]
            deny_list = ["*"]

            [bridges.per_bridge.email]
            enabled = true
        "#;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        // deny_list ["*"] blocks everything including allowlisted bridges.
        assert!(!cfg.bridge_permitted("email"));
    }

    #[test]
    fn bridge_permitted_per_bridge_enabled_false_overrides_allow_list() {
        let toml = r#"
            [bridges]
            allow_list = ["email"]

            [bridges.per_bridge.email]
            enabled = false
        "#;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        // Per-bridge kill-switch beats allowlist.
        assert!(!cfg.bridge_permitted("email"));
    }

    #[test]
    fn bridge_permitted_specific_deny_works() {
        let toml = r#"
            [bridges]
            allow_list = ["email", "slack"]
            deny_list = ["slack"]

            [bridges.per_bridge.email]
            enabled = true

            [bridges.per_bridge.slack]
            enabled = true
        "#;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        assert!(cfg.bridge_permitted("email"));
        assert!(!cfg.bridge_permitted("slack"));
    }

    #[test]
    fn single_backend_bridge_storage_flag_present_when_a_bridge_is_permitted() {
        let toml = r##"
            [bridges]
            allow_list = ["email"]
            [bridges.per_bridge.email]
            enabled = true
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        assert!(
            cfg.unsafe_options_active()
                .contains(&"naively_single_backend_bridge_storage".to_string()),
            "expected the single-backend flag when a bridge is permitted"
        );
    }

    #[test]
    fn no_bridge_storage_flag_when_no_bridge_permitted() {
        let cfg = JigServerConfig::default();
        assert!(
            !cfg.unsafe_options_active()
                .contains(&"naively_single_backend_bridge_storage".to_string()),
            "no bridge permitted by default -> flag absent"
        );
    }

    #[test]
    fn no_bridge_storage_flag_when_bridge_present_but_disabled() {
        // A bridge entry that is NOT permitted (enabled=false) must not trip the flag.
        let toml = r##"
            [bridges]
            allow_list = ["email"]
            [bridges.per_bridge.email]
            enabled = false
        "##;
        let cfg: JigServerConfig = toml::from_str(toml).unwrap();
        assert!(
            !cfg.unsafe_options_active()
                .contains(&"naively_single_backend_bridge_storage".to_string()),
            "disabled bridge is not permitted -> flag absent"
        );
    }
}
