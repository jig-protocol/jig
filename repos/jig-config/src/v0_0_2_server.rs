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
//! - `[nameserver]` — alias suffix this node is authoritative for (nameserver mode)
//!
//! Every section carries a container-level `#[serde(default)]`, so a config
//! file may omit a section entirely or set only the keys it cares about; the
//! rest come from that section's `impl Default`.
//!
//! All antipattern flags follow the project convention (`dangerously_`,
//! `naively_`, `unsafe_`, `debug_`-prefixed) and are listed by
//! [`JigServerConfig::unsafe_options_active`] for advertisement in
//! `GET /.well-known/jig`.

use std::collections::BTreeMap;
use std::path::Path;

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
    #[serde(default)]
    pub nameserver: NameserverSection,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
// Container-level (not per-field) default: a partially-written section must
// keep the documented defaults for the keys the operator omitted, rather than
// failing to parse. Container-level reuses the hand-written `impl Default`
// below, which per-field `#[serde(default)]` cannot do.
#[serde(default)]
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
// Must stay container-level: `IdentityMode` deliberately has no `Default`
// (neither variant is a safe automatic pick), so per-field `#[serde(default)]`
// on `mode` would not compile. The container form takes `mode` from the
// hand-written `impl Default` below instead.
#[serde(default)]
pub struct IdentitySection {
    pub mode: IdentityMode,
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
#[serde(default)]
pub struct FederationSection {
    pub peers: Vec<FederationPeer>,
    pub dangerously_disable_federation_tls: bool,
    /// Antipattern flag: when true, inbound peer blocks are persisted
    /// WITHOUT re-verifying the sender's ed25519 signature. v0.0.2 default
    /// behavior; v0.0.3+ rejects forged-author relays unless this is set.
    /// Surfaces in `unsafe_options_active` so federated peers and operators
    /// notice the carve-out via `GET /.well-known/jig`.
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
#[serde(default)]
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

/// Nameserver-mode settings. Only meaningful when this process runs as a
/// jig-nameserver; a plain chat server parses and ignores the section.
///
/// Supersedes the v0.0.2 carve-out where `alias_suffix` was a bare parameter
/// of `AppState::new` (its doc comment claimed it came from
/// `identity.trusted_nameservers[0]`, which no code ever implemented).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NameserverSection {
    /// The alias suffix this nameserver is authoritative for — the part after
    /// the `@` in `dj@gigue.jig`. Stored WITHOUT the `@` so callers can
    /// `format!("{local}@{alias_suffix}")` without stripping.
    pub alias_suffix: String,
}

impl Default for NameserverSection {
    fn default() -> Self {
        Self {
            // gigue runs the default nameserver for the `.jig` protocol
            // namespace, so an unconfigured install lands there.
            alias_suffix: "gigue.jig".to_string(),
        }
    }
}

impl NameserverSection {
    /// Reject alias suffixes that would produce unresolvable aliases. Aliases
    /// are compared byte-wise downstream, so a suffix that differs only in
    /// case or padding silently fails to resolve — catch it at boot instead.
    pub fn validate(&self) -> Result<(), String> {
        if self.alias_suffix.is_empty() {
            return Err("nameserver.alias_suffix must not be empty".to_string());
        }
        if self.alias_suffix.contains('@') {
            return Err(format!(
                "nameserver.alias_suffix must not contain '@' — it is the suffix alone \
                 (e.g. `gigue.jig`), not a full alias; got `{}`",
                self.alias_suffix
            ));
        }
        if self.alias_suffix.chars().any(|c| c.is_uppercase()) {
            return Err(format!(
                "nameserver.alias_suffix must be lowercase; got `{}`",
                self.alias_suffix
            ));
        }
        if self.alias_suffix.chars().any(char::is_whitespace) {
            return Err(format!(
                "nameserver.alias_suffix must not contain whitespace; got `{}`",
                self.alias_suffix
            ));
        }
        Ok(())
    }
}

impl JigServerConfig {
    /// Load the v0.0.2 server config from a TOML file. The file MAY also carry
    /// root-level jig-server `ServerConfig` keys (database_path/bind_address/
    /// port/[tls]/[execution]) — serde ignores unknown fields, so one
    /// production config.toml can drive both `ServerConfig::load` and this.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        toml::from_str(&s).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

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

    // --- partial-section defaults -------------------------------------
    // Operators routinely write a config that names a section but only sets
    // the one key they care about. Without container-level serde defaults
    // that is a hard parse error, which is why neither install.sh's config
    // nor `--init-config`'s template produced a bootable server.

    #[test]
    fn partial_server_section_keeps_sibling_defaults() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [server]
            listen = "0.0.0.0:9999"
        "#,
        )
        .expect("partial [server] must deserialize");
        let d = ServerSection::default();
        assert_eq!(cfg.server.listen, "0.0.0.0:9999");
        assert_eq!(cfg.server.server_did_keyfile, d.server_did_keyfile);
        assert_eq!(cfg.server.allowed_block_kinds, d.allowed_block_kinds);
    }

    #[test]
    fn partial_identity_section_keeps_sibling_defaults() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [identity]
            cache_ttl_seconds = 60
        "#,
        )
        .expect("partial [identity] must deserialize");
        assert_eq!(cfg.identity.cache_ttl_seconds, 60);
        assert_eq!(cfg.identity.mode, IdentityMode::Tofu);
        assert!(cfg.identity.trusted_nameservers.is_empty());
        assert!(!cfg.identity.naively_allow_unknown_handles_fallback);
    }

    #[test]
    fn partial_debug_section_keeps_sibling_defaults() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [debug]
            admin_endpoints = true
        "#,
        )
        .expect("partial [debug] must deserialize");
        assert!(cfg.debug.admin_endpoints);
        assert!(!cfg.debug.list_handles);
    }

    #[test]
    fn partial_federation_section_keeps_sibling_defaults() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [federation]
            dangerously_disable_federation_tls = true
        "#,
        )
        .expect("partial [federation] must deserialize");
        assert!(cfg.federation.dangerously_disable_federation_tls);
        assert!(cfg.federation.peers.is_empty());
        assert!(!cfg.federation.naively_trust_peer_authored_blocks);
    }

    #[test]
    fn empty_config_file_equals_full_default() {
        let cfg: JigServerConfig = toml::from_str("").expect("empty config must deserialize");
        assert_eq!(cfg, JigServerConfig::default());
    }

    // --- [nameserver] --------------------------------------------------

    #[test]
    fn nameserver_alias_suffix_defaults_to_gigue_jig() {
        assert_eq!(
            JigServerConfig::default().nameserver.alias_suffix,
            "gigue.jig"
        );
        let cfg: JigServerConfig = toml::from_str("[nameserver]").unwrap();
        assert_eq!(cfg.nameserver.alias_suffix, "gigue.jig");
    }

    #[test]
    fn nameserver_alias_suffix_round_trips_explicit_value() {
        let cfg: JigServerConfig = toml::from_str(
            r#"
            [nameserver]
            alias_suffix = "dj.jig"
        "#,
        )
        .unwrap();
        assert_eq!(cfg.nameserver.alias_suffix, "dj.jig");
        cfg.nameserver.validate().expect("dj.jig is valid");

        let reparsed: JigServerConfig = toml::from_str(&toml::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(reparsed, cfg);
    }

    #[test]
    fn nameserver_validate_rejects_the_four_malformed_suffixes() {
        let cases = [
            ("", "empty"),
            ("alice@dj.jig", "'@'"),
            ("DJ.jig", "lowercase"),
            ("dj .jig", "whitespace"),
        ];
        let mut messages = Vec::new();
        for (suffix, expected_fragment) in cases {
            let section = NameserverSection {
                alias_suffix: suffix.to_string(),
            };
            let err = section
                .validate()
                .expect_err("malformed alias_suffix must be rejected");
            assert!(
                err.contains(expected_fragment),
                "message for {suffix:?} should mention {expected_fragment}; got {err}"
            );
            messages.push(err);
        }
        // Each malformed shape gets its own message so an operator can tell
        // which rule they tripped from the log line alone.
        let distinct: std::collections::BTreeSet<&String> = messages.iter().collect();
        assert_eq!(distinct.len(), messages.len(), "messages: {messages:?}");
    }

    #[test]
    fn nameserver_default_suffix_validates() {
        JigServerConfig::default()
            .nameserver
            .validate()
            .expect("shipped default must be valid");
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

    #[test]
    fn load_reads_bridges_from_hybrid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
database_path = "/var/lib/jig/jig.db"
bind_address = "0.0.0.0"
port = 443

[tls]
enabled = true
cert_path = "/etc/jig/tls/fullchain.pem"
key_path = "/etc/jig/tls/privkey.pem"

[bridges.per_bridge.email]
enabled = true

[bridges.per_bridge.email.config]
bridge_domain = "mail.jig.onl"
provider = "resend"
bridge_secret = "literal-secret"
"#,
        )
        .unwrap();

        let cfg = JigServerConfig::load(&path).expect("load");
        assert!(cfg.bridge_permitted("email"));
        assert!(cfg.bridges.per_bridge.contains_key("email"));
    }
}
