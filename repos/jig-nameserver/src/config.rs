//! Configuration for the Jig Nameserver.

use crate::error::{NameServerError, Result};
use jig_config;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

fn merge_tables(target: &mut toml::value::Table, source: &toml::value::Table) {
    for (key, value) in source {
        let mut merged = false;
        if let Some(existing) = target.get_mut(key)
            && let (TomlValue::Table(existing_table), TomlValue::Table(src_table)) =
                (existing, value)
        {
            merge_tables(existing_table, src_table);
            merged = true;
        }
        if !merged {
            target.insert(key.clone(), value.clone());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NameServerConfig {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub penalties: PenaltyConfig,
    pub anonymous: AnonymousPolicy,
    pub admin: AdminConfig,
    pub automation: AutomationPolicy,
    pub reputation: ReputationConfig,
    pub useful_work: UsefulWorkConfig,
    pub capabilities: CapabilitiesConfig,
    pub analytics: AnalyticsConfig, // Phase F: Analytics and insights
    /// v0.0.2 alias-API wiring (`[v0_0_2]`), consumed by
    /// [`crate::server::build_app`] to boot `crate::v0_0_2::AppState`.
    ///
    /// Reuses jig-server's `JigServerConfig` verbatim so `[v0_0_2.nameserver]
    /// alias_suffixes` and `[v0_0_2.server] server_did_keyfile` mean exactly what
    /// they mean in a jig-server config. Only the keys the nameserver actually
    /// consumes are honoured (`server.server_did_keyfile`,
    /// `identity.naively_allow_unknown_handles_fallback`, `nameserver.alias_suffixes`);
    /// `server.allowed_block_kinds` is overridden with the ns-only allowlist by
    /// `v0_0_2::AppState::new`.
    #[serde(default)]
    pub v0_0_2: jig_config::v0_0_2_server::JigServerConfig,
    /// Per-IP and per-DID limits on the v0.0.2 `register`, `rotate` and
    /// `renew` routes (`[alias_rate_limits]`).
    pub alias_rate_limits: AliasRateLimitConfig,
    /// TLS for the listener (`[tls]`), on by default with a self-signed
    /// certificate the nameserver's DID vouches for at `/.well-known/jig-ns`.
    pub tls: jig_config::tls::TlsConfig,
}

/// `JIG_NS_*` variables a removed feature read, with what removed it. Setting
/// one has no effect any more, so loading warns about it rather than ignoring
/// it silently. An entry ending in `*` matches every variable with that prefix.
const REMOVED_ENV_VARS: &[(&str, &str)] = &[
    ("JIG_NS_SECRET", "the nameserver needs no secret"),
    (
        "JIG_NS_POW_*",
        "nameserver proof-of-work settings were removed",
    ),
    ("JIG_NS_RATE_PER_MIN", "use [alias_rate_limits] instead"),
    (
        "JIG_NS_RATE_PER_IP_PER_MIN",
        "use [alias_rate_limits] instead",
    ),
    (
        "JIG_NS_TRANSPARENCY_PATH",
        "the transparency log was removed",
    ),
    (
        "JIG_NS_TRANSPARENCY_INTERVAL",
        "the transparency log was removed",
    ),
    ("JIG_NS_RUNTIME_ENABLED", "the embedded runtime was removed"),
    ("JIG_NS_STORAGE_BACKEND", "only SQLite storage remains"),
    ("JIG_NS_ANALYTICS_BACKEND", "only SQLite analytics remain"),
    ("JIG_NS_HOT_*", "the hot-state backends were removed"),
    (
        "JIG_NS_FEDERATION_ENABLED",
        "nameserver federation was removed",
    ),
    ("JIG_NS_ALLOW_DOMAINS", "nameserver federation was removed"),
    ("JIG_NS_DENY_DOMAINS", "nameserver federation was removed"),
    ("JIG_NS_SEED_PEERS", "nameserver federation was removed"),
    ("JIG_NS_MAX_PEERS", "nameserver federation was removed"),
    ("JIG_NS_CACHE_TTL", "nameserver federation was removed"),
    (
        "JIG_NS_GOSSIP_INTERVAL",
        "nameserver federation was removed",
    ),
    (
        "JIG_NS_HANDSHAKE_TIMEOUT",
        "nameserver federation was removed",
    ),
    (
        "JIG_NS_GOSSIP_BATCH_SIZE",
        "nameserver federation was removed",
    ),
];

/// The removed variables set in `env`, each with why it is ignored, sorted by
/// name.
fn removed_env_vars_in(env: impl Iterator<Item = String>) -> Vec<(String, &'static str)> {
    let mut found: Vec<(String, &'static str)> = env
        .filter_map(|var| {
            REMOVED_ENV_VARS
                .iter()
                .find(|(pattern, _)| match pattern.strip_suffix('*') {
                    Some(prefix) => var.starts_with(prefix),
                    None => var == *pattern,
                })
                .map(|(_, why)| (var, *why))
        })
        .collect();
    found.sort();
    found
}

fn warn_removed_env_vars() {
    let names = std::env::vars_os().filter_map(|(k, _)| k.into_string().ok());
    for (var, why) in removed_env_vars_in(names) {
        tracing::warn!("{var} is set, but {why}; it is ignored. Unset it.");
    }
}

/// Config sections and keys the nameserver used to accept, with why each went.
/// Every config struct denies unknown fields, so these would fail anyway; this
/// names the fix instead of serde's generic "unknown field".
const REMOVED_KEYS: &[(&str, &str)] = &[
    ("pow", "the nameserver no longer runs proof-of-work"),
    ("rate_limits", "use [alias_rate_limits] instead"),
    ("transparency", "the transparency log was removed"),
    ("runtime", "the embedded runtime was removed"),
    ("anomaly_detection", "the anomaly detector was removed"),
    ("hot", "the hot-state backends were removed"),
    ("federation", "nameserver federation was removed"),
    (
        "capabilities.federation_enabled",
        "nameserver federation was removed",
    ),
    ("storage.backend", "only SQLite storage remains"),
    ("storage.backend_config", "only SQLite storage remains"),
    ("analytics.backend", "only SQLite analytics remain"),
    ("analytics.backend_config", "only SQLite analytics remain"),
];

/// Refuse a config that sets a removed key, naming it and the fix.
fn reject_removed_keys(table: &toml::value::Table) -> Result<()> {
    for (path, why) in REMOVED_KEYS {
        let found = match path.split_once('.') {
            None => table.contains_key(*path),
            Some((section, key)) => table
                .get(section)
                .and_then(TomlValue::as_table)
                .is_some_and(|t| t.contains_key(key)),
        };
        if found {
            let what = if path.contains('.') {
                format!("`{path}` is no longer a nameserver config key")
            } else {
                format!("`[{path}]` is no longer a nameserver config section")
            };
            return Err(NameServerError::Other(anyhow::anyhow!(
                "{what}: {why}. Delete it."
            )));
        }
    }
    Ok(())
}

/// The config file to load: `--config`, else `JIG_NS_CONFIG`.
fn config_path(explicit: Option<&Path>, env: Option<std::ffi::OsString>) -> Result<PathBuf> {
    explicit
        .map(Path::to_path_buf)
        .or_else(|| env.filter(|v| !v.is_empty()).map(PathBuf::from))
        .ok_or_else(|| {
            NameServerError::Other(anyhow::anyhow!(
                "no nameserver config: pass --config <path> or set JIG_NS_CONFIG. The \
                 nameserver no longer reads JIG_CONFIG, ~/.jig/config.toml or \
                 ./config/jig-nameserver/jig-config.toml"
            ))
        })
}

impl NameServerConfig {
    /// Load the config file named by `explicit` (the binary's `--config`), or
    /// else by `JIG_NS_CONFIG`, then apply the environment overrides. There is
    /// no default path: with neither set this fails, naming both. The result
    /// is [`validate`](Self::validate)d, so a misconfiguration surfaces as an
    /// `Err` the caller can log.
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        let path = config_path(explicit, std::env::var_os("JIG_NS_CONFIG"))?;
        Self::load_from_path(path)
    }

    /// Operator-fixable-misconfiguration check. Separate from parsing so tests
    /// (and callers who want to patch a field before booting) can build an
    /// unvalidated config, and so failures are errors rather than panics.
    pub fn validate(&self) -> Result<()> {
        self.v0_0_2
            .nameserver
            .validate()
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("[v0_0_2] {e}")))?;
        Ok(())
    }

    /// Load configuration from the given path. Validated like [`load`](Self::load).
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
        warn_removed_env_vars();
        let cfg = Self::load_from_path_with_profile(path, std::env::var("JIG_NS_PROFILE").ok())?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn load_from_path_with_profile(
        path: impl AsRef<Path>,
        profile_override: Option<String>,
    ) -> Result<Self> {
        let data = fs::read_to_string(&path)
            .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("read config: {e}"))))?;
        let value: TomlValue = toml::from_str(&data)
            .map_err(|e| NameServerError::Other(anyhow::anyhow!(format!("parse config: {e}"))))?;
        let table = value.as_table().cloned().ok_or_else(|| {
            NameServerError::Other(anyhow::anyhow!(
                "nameserver config file must contain a TOML table"
            ))
        })?;
        let mut cfg = Self::from_table(table, profile_override)?;
        cfg.apply_env_overrides();
        cfg.normalize();
        Ok(cfg)
    }

    pub(crate) fn from_table(
        mut table: toml::value::Table,
        profile_override: Option<String>,
    ) -> Result<Self> {
        let mut active_profile = profile_override.or_else(|| std::env::var("JIG_NS_PROFILE").ok());
        if let Some(table_profile) = table
            .remove("profile")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            && active_profile.is_none()
        {
            active_profile = Some(table_profile);
        }

        let profiles_table = match table.remove("profiles") {
            Some(TomlValue::Table(map)) => Some(map),
            Some(other) => {
                return Err(NameServerError::Other(anyhow::anyhow!(
                    "nameserver.profiles must be a table (found {})",
                    other.type_str()
                )));
            }
            None => None,
        };

        if let Some(profiles) = profiles_table.as_ref() {
            if let Some(default_table) = profiles.get("default").and_then(|v| v.as_table()) {
                merge_tables(&mut table, default_table);
            }
            if let Some(profile_name) = active_profile.as_deref()
                && let Some(profile_value) = profiles.get(profile_name)
            {
                if let Some(profile_table) = profile_value.as_table() {
                    merge_tables(&mut table, profile_table);
                } else {
                    return Err(NameServerError::Other(anyhow::anyhow!(
                        "nameserver.profiles.{profile_name} must be a table"
                    )));
                }
            }
        }

        reject_removed_keys(&table)?;
        let cfg_value = TomlValue::Table(table);
        let cfg: NameServerConfig = cfg_value.try_into().map_err(|e| {
            NameServerError::Other(anyhow::anyhow!(format!("parse nameserver config: {e}")))
        })?;
        Ok(cfg)
    }

    /// Write a starter config file. Fails if the file already exists and `overwrite` is false.
    pub fn write_template(path: impl AsRef<Path>, overwrite: bool) -> Result<()> {
        let path = path.as_ref();
        if path.exists() && !overwrite {
            return Err(NameServerError::Other(anyhow::anyhow!(
                "config file already exists at {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| NameServerError::Other(anyhow::anyhow!("create dir: {e}")))?;
        }
        let mut file = fs::File::create(path)
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("create config: {e}")))?;
        file.write_all(TEMPLATE.trim_start().as_bytes())
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("write config: {e}")))?;
        Ok(())
    }

    fn from_env() -> Self {
        Self {
            network: NetworkConfig::from_env(),
            storage: StorageConfig::from_env(),
            penalties: PenaltyConfig::from_env(),
            anonymous: AnonymousPolicy::from_env(),
            admin: AdminConfig::from_env(),
            automation: AutomationPolicy::from_env(),
            reputation: ReputationConfig::from_env(),
            useful_work: UsefulWorkConfig::from_env(),
            capabilities: CapabilitiesConfig::from_env(),
            analytics: AnalyticsConfig::from_env(),
            v0_0_2: jig_config::v0_0_2_server::JigServerConfig::default(),
            alias_rate_limits: AliasRateLimitConfig::default(),
            tls: jig_config::tls::TlsConfig::default(),
        }
    }

    /// Unsafe options this config sets, as `/.well-known/jig-ns` lists them
    /// (JEP-0004 rule 12), named the way jig-server names its own.
    pub fn unsafe_options_active(&self) -> Vec<String> {
        let mut active = Vec::new();
        if !self.tls.enabled {
            active.push("tls.enabled=false".to_string());
        }
        active
    }

    fn apply_env_overrides(&mut self) {
        // Allow env vars to override settings after TOML load for quick tweaks.
        self.network.merge_env();
        self.storage.merge_env();
        self.analytics.merge_env();
        self.penalties.merge_env();
        self.anonymous.merge_env();
        self.admin.merge_env();
        self.automation.merge_env();
        self.reputation.merge_env();
        self.useful_work.merge_env();
        self.capabilities.merge_env();
    }

    fn normalize(&mut self) {
        self.reputation.normalize();
    }
}

impl Default for NameServerConfig {
    fn default() -> Self {
        let mut cfg = Self::from_env();
        cfg.normalize();
        cfg
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkConfig {
    pub bind: String,
    pub port: u16,
    pub trust_proxy: bool,
    pub proxy_ip_header: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            trust_proxy: false,
            proxy_ip_header: default_proxy_header(),
        }
    }
}

impl NetworkConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(bind) = std::env::var("JIG_NS_BIND") {
            cfg.bind = bind;
        }
        if let Ok(port) = std::env::var("JIG_NS_PORT")
            && let Ok(parsed) = port.parse::<u16>()
        {
            cfg.port = parsed;
        }
        if let Ok(val) = std::env::var("JIG_NS_TRUST_PROXY")
            && let Ok(parsed) = val.parse::<bool>()
        {
            cfg.trust_proxy = parsed;
        }
        if let Ok(header) = std::env::var("JIG_NS_PROXY_IP_HEADER") {
            cfg.proxy_ip_header = header;
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(bind) = std::env::var("JIG_NS_BIND") {
            self.bind = bind;
        }
        if let Ok(port) = std::env::var("JIG_NS_PORT")
            && let Ok(parsed) = port.parse::<u16>()
        {
            self.port = parsed;
        }
        if let Ok(val) = std::env::var("JIG_NS_TRUST_PROXY")
            && let Ok(parsed) = val.parse::<bool>()
        {
            self.trust_proxy = parsed;
        }
        if let Ok(header) = std::env::var("JIG_NS_PROXY_IP_HEADER") {
            self.proxy_ip_header = header;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageConfig {
    pub database_path: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: default_database_path(),
        }
    }
}

impl StorageConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(path) = std::env::var("JIG_NS_DB_PATH") {
            cfg.database_path = PathBuf::from(path);
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(path) = std::env::var("JIG_NS_DB_PATH") {
            self.database_path = PathBuf::from(path);
        }
    }
}

/// Limits for the v0.0.2 alias-mutating routes, enforced by
/// [`crate::v0_0_2_rate_limit`]. Each counts requests in a fixed one-minute
/// window; a limit of `0` refuses every request on that bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AliasRateLimitConfig {
    pub enabled: bool,
    /// Requests per client IP per minute, across register, rotate and renew.
    pub per_ip_per_min: u32,
    /// Requests naming a given DID per minute (`did`, `old_did` or `new_did`).
    pub per_did_per_min: u32,
    /// `GET /v1/challenge` requests per client IP per minute (JEP-0008 rule
    /// 31): each one can make the nameserver sign an effort offer.
    pub challenge_per_ip_per_min: u32,
    /// Challenges issued and not yet used or expired. At the cap a new one is
    /// refused with `503 BUSY`; live ones are never evicted.
    pub max_pending_challenges: usize,
}

impl Default for AliasRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_ip_per_min: 30,
            per_did_per_min: 10,
            challenge_per_ip_per_min: 60,
            max_pending_challenges: 100_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PenaltyConfig {
    pub decay_secs: i64,
    pub step_bits: u16,
    pub max_points: u32,
}

impl Default for PenaltyConfig {
    fn default() -> Self {
        Self {
            decay_secs: default_penalty_decay(),
            step_bits: default_penalty_step(),
            max_points: 64,
        }
    }
}

impl PenaltyConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(secs) = std::env::var("JIG_NS_PENALTY_DECAY")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            cfg.decay_secs = parsed;
        }
        if let Ok(bits) = std::env::var("JIG_NS_PENALTY_STEP_BITS")
            && let Ok(parsed) = bits.parse::<u16>()
        {
            cfg.step_bits = parsed;
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(secs) = std::env::var("JIG_NS_PENALTY_DECAY")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            self.decay_secs = parsed;
        }
        if let Ok(bits) = std::env::var("JIG_NS_PENALTY_STEP_BITS")
            && let Ok(parsed) = bits.parse::<u16>()
        {
            self.step_bits = parsed;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AnonymousPolicy {
    pub enabled: bool,
    pub min_difficulty: u16,
}

impl Default for AnonymousPolicy {
    fn default() -> Self {
        Self {
            enabled: default_anonymous_enabled(),
            min_difficulty: default_anon_min_pow(),
        }
    }
}

impl AnonymousPolicy {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(enabled) = std::env::var("JIG_NS_ANON_ENABLED")
            && let Ok(parsed) = enabled.parse::<bool>()
        {
            cfg.enabled = parsed;
        }
        if let Ok(bits) = std::env::var("JIG_NS_ANON_MIN_POW")
            && let Ok(parsed) = bits.parse::<u16>()
        {
            cfg.min_difficulty = parsed;
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(enabled) = std::env::var("JIG_NS_ANON_ENABLED")
            && let Ok(parsed) = enabled.parse::<bool>()
        {
            self.enabled = parsed;
        }
        if let Ok(bits) = std::env::var("JIG_NS_ANON_MIN_POW")
            && let Ok(parsed) = bits.parse::<u16>()
        {
            self.min_difficulty = parsed;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct AdminConfig {
    pub token: Option<String>,
}

impl AdminConfig {
    fn from_env() -> Self {
        Self {
            token: std::env::var("JIG_NS_ADMIN_TOKEN")
                .ok()
                .filter(|v| !v.is_empty()),
        }
    }

    fn merge_env(&mut self) {
        if let Ok(token) = std::env::var("JIG_NS_ADMIN_TOKEN")
            && !token.is_empty()
        {
            self.token = Some(token);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AutomationPolicy {
    pub enabled: bool,
    pub power_law_alpha: f64,
    pub pile_on_factor: f64,
    pub max_multiplier: f64,
    pub quorum: u32,
    pub evidence_window_secs: i64,
    pub human_review_window_secs: i64,
}

impl Default for AutomationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            power_law_alpha: 1.4,
            pile_on_factor: 0.5,
            max_multiplier: 8.0,
            quorum: 3,
            evidence_window_secs: 600,
            human_review_window_secs: 3600,
        }
    }
}

impl AutomationPolicy {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(enabled) = std::env::var("JIG_NS_AUTOMATION_ENABLED")
            && let Ok(parsed) = enabled.parse::<bool>()
        {
            cfg.enabled = parsed;
        }
        if let Ok(alpha) = std::env::var("JIG_NS_AUTOMATION_ALPHA")
            && let Ok(parsed) = alpha.parse::<f64>()
        {
            cfg.power_law_alpha = parsed;
        }
        if let Ok(factor) = std::env::var("JIG_NS_AUTOMATION_PILE_ON")
            && let Ok(parsed) = factor.parse::<f64>()
        {
            cfg.pile_on_factor = parsed;
        }
        if let Ok(mult) = std::env::var("JIG_NS_AUTOMATION_MAX")
            && let Ok(parsed) = mult.parse::<f64>()
        {
            cfg.max_multiplier = parsed;
        }
        if let Ok(quorum) = std::env::var("JIG_NS_AUTOMATION_QUORUM")
            && let Ok(parsed) = quorum.parse::<u32>()
        {
            cfg.quorum = parsed;
        }
        if let Ok(secs) = std::env::var("JIG_NS_AUTOMATION_WINDOW")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            cfg.evidence_window_secs = parsed;
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(enabled) = std::env::var("JIG_NS_AUTOMATION_ENABLED")
            && let Ok(parsed) = enabled.parse::<bool>()
        {
            self.enabled = parsed;
        }
        if let Ok(alpha) = std::env::var("JIG_NS_AUTOMATION_ALPHA")
            && let Ok(parsed) = alpha.parse::<f64>()
        {
            self.power_law_alpha = parsed;
        }
        if let Ok(factor) = std::env::var("JIG_NS_AUTOMATION_PILE_ON")
            && let Ok(parsed) = factor.parse::<f64>()
        {
            self.pile_on_factor = parsed;
        }
        if let Ok(mult) = std::env::var("JIG_NS_AUTOMATION_MAX")
            && let Ok(parsed) = mult.parse::<f64>()
        {
            self.max_multiplier = parsed;
        }
        if let Ok(quorum) = std::env::var("JIG_NS_AUTOMATION_QUORUM")
            && let Ok(parsed) = quorum.parse::<u32>()
        {
            self.quorum = parsed;
        }
        if let Ok(secs) = std::env::var("JIG_NS_AUTOMATION_WINDOW")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            self.evidence_window_secs = parsed;
        }
    }

    pub fn score_hint_from_penalty(&self, penalty_points: u32) -> f64 {
        1.0 + penalty_points as f64
    }

    pub fn multiplier(&self, witness_weight: f64) -> f64 {
        if !self.enabled {
            return 1.0;
        }
        let base = witness_weight.max(1.0);
        let growth = (base - 1.0).powf(self.power_law_alpha).max(0.0);
        let amplification = 1.0 + growth * self.pile_on_factor;
        amplification.clamp(1.0, self.max_multiplier.max(1.0))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReputationZone {
    Null,
    Low,
    High,
    Anonymous,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ReputationConfig {
    pub default_ruleset: Option<String>,
    #[serde(default)]
    pub local_rulesets: Vec<RulesetDefinition>,
    #[serde(default)]
    pub translation_contracts: Vec<ReputationTranslation>,
}

impl ReputationConfig {
    fn from_env() -> Self {
        Self::default()
    }

    fn merge_env(&mut self) {
        // Reserved for future env overrides; noop today.
    }

    fn normalize(&mut self) {
        for ruleset in &mut self.local_rulesets {
            ruleset.key = ruleset.key.trim().to_lowercase();
            if let Some(authority) = &mut ruleset.authority {
                *authority = authority.trim().to_string();
            }
        }
        for contract in &mut self.translation_contracts {
            contract.from = contract.from.trim().to_lowercase();
            contract.to = contract.to.trim().to_lowercase();
        }
        if let Some(default) = &mut self.default_ruleset {
            *default = default.trim().to_lowercase();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesetDefinition {
    pub key: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub authority: Option<String>,
    #[serde(default)]
    pub weight: f64,
    #[serde(default)]
    pub pow_policy: RulePowPolicy,
    #[serde(default)]
    pub tribunal_policy: RuleTribunalPolicy,
}

impl Default for RulesetDefinition {
    fn default() -> Self {
        Self {
            key: String::new(),
            version: None,
            description: None,
            authority: None,
            weight: 1.0,
            pow_policy: RulePowPolicy::default(),
            tribunal_policy: RuleTribunalPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RulePowPolicy {
    pub min_bits: Option<u16>,
    pub max_bits: Option<u16>,
    pub multiplier: Option<f64>,
}

impl Default for RulePowPolicy {
    fn default() -> Self {
        Self {
            min_bits: None,
            max_bits: None,
            multiplier: Some(1.0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[derive(Default)]
pub struct RuleTribunalPolicy {
    pub quorum: Option<u32>,
    pub auto_escalate_score: Option<f64>,
    pub evidence_window_secs: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationTranslation {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub weight: f64,
    #[serde(default)]
    pub transform: TranslationKind,
}

impl Default for ReputationTranslation {
    fn default() -> Self {
        Self {
            from: String::new(),
            to: String::new(),
            weight: 1.0,
            transform: TranslationKind::Linear {
                slope: 1.0,
                intercept: 0.0,
                clamp_min: None,
                clamp_max: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TranslationKind {
    Linear {
        slope: f64,
        intercept: f64,
        #[serde(skip_serializing_if = "Option::is_none")]
        clamp_min: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        clamp_max: Option<f64>,
    },
    Table {
        entries: Vec<TranslationTableEntry>,
        #[serde(skip_serializing_if = "Option::is_none")]
        default: Option<f64>,
    },
}

impl Default for TranslationKind {
    fn default() -> Self {
        TranslationKind::Linear {
            slope: 1.0,
            intercept: 0.0,
            clamp_min: None,
            clamp_max: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranslationTableEntry {
    pub min: f64,
    pub max: f64,
    pub mapped: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UsefulWorkConfig {
    pub assignment_ttl_secs: i64,
    pub max_assignments_per_worker: usize,
    pub result_retention_secs: i64,
    pub max_queue_depth: usize,
}

impl Default for UsefulWorkConfig {
    fn default() -> Self {
        Self {
            assignment_ttl_secs: 600,
            max_assignments_per_worker: 5,
            result_retention_secs: 86400,
            max_queue_depth: 1024,
        }
    }
}

impl UsefulWorkConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Some(val) = std::env::var("JIG_NS_WORK_TTL")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
        {
            cfg.assignment_ttl_secs = val.max(60);
        }
        if let Some(val) = std::env::var("JIG_NS_WORK_MAX_PER_WORKER")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        {
            cfg.max_assignments_per_worker = val.max(1);
        }
        if let Some(val) = std::env::var("JIG_NS_WORK_RESULT_RETENTION")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
        {
            cfg.result_retention_secs = val.max(0);
        }
        if let Some(val) = std::env::var("JIG_NS_WORK_QUEUE_DEPTH")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        {
            cfg.max_queue_depth = val.max(1);
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Some(val) = std::env::var("JIG_NS_WORK_TTL")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
        {
            self.assignment_ttl_secs = val.max(60);
        }
        if let Some(val) = std::env::var("JIG_NS_WORK_MAX_PER_WORKER")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        {
            self.max_assignments_per_worker = val.max(1);
        }
        if let Some(val) = std::env::var("JIG_NS_WORK_RESULT_RETENTION")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
        {
            self.result_retention_secs = val.max(0);
        }
        if let Some(val) = std::env::var("JIG_NS_WORK_QUEUE_DEPTH")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        {
            self.max_queue_depth = val.max(1);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CapabilitiesConfig {
    pub version: String,
    pub domain: Option<String>,
    pub useful_work_types: Vec<String>,
    pub tribunal_enabled: bool,
    pub transparency_enabled: bool,
    #[serde(default)]
    pub affordances: Vec<String>, // Phase C: e.g. ["email.delivered", "bridge.forwarded"]
}

impl Default for CapabilitiesConfig {
    fn default() -> Self {
        Self {
            version: "v1".into(),
            domain: None,
            useful_work_types: vec![
                "validate_block".into(),
                "verify_observation".into(),
                "audit_ruleset".into(),
            ],
            tribunal_enabled: true,
            transparency_enabled: true,
            affordances: Vec::new(),
        }
    }
}

impl CapabilitiesConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(val) = std::env::var("JIG_NS_DOMAIN") {
            cfg.domain = Some(val);
        }
        if let Ok(val) = std::env::var("JIG_NS_VERSION") {
            cfg.version = val;
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(val) = std::env::var("JIG_NS_DOMAIN") {
            self.domain = Some(val);
        }
        if let Ok(val) = std::env::var("JIG_NS_VERSION") {
            self.version = val;
        }
    }

    /// Generate DNS TXT records for capability advertisement
    pub fn to_dns_txt_records(&self) -> Vec<String> {
        let mut records = Vec::new();

        records.push(format!("jig-ns=version:{}", self.version));

        if !self.useful_work_types.is_empty() {
            records.push(format!("jig-ns=work:{}", self.useful_work_types.join(",")));
        }

        if self.tribunal_enabled {
            records.push("jig-ns=tribunal:enabled".into());
        }

        if self.transparency_enabled {
            records.push("jig-ns=transparency:enabled".into());
        }

        // Phase C: Add affordances if present
        if !self.affordances.is_empty() {
            records.push(format!("jig-ns=affordances:{}", self.affordances.join(",")));
        }

        records
    }

    /// Generate plain text capability document for /.well-known/jig-ns/capabilities
    pub fn to_capabilities_text(&self) -> String {
        let mut lines = Vec::new();

        lines.push("# Jig Nameserver Capabilities".to_string());
        lines.push(format!("version: {}", self.version));

        if let Some(ref domain) = self.domain {
            lines.push(format!("domain: {domain}"));
        }

        lines.push(String::new());
        lines.push("# Useful Work Types".into());
        for work_type in &self.useful_work_types {
            lines.push(format!("work: {work_type}"));
        }

        lines.push(String::new());
        lines.push("# Features".into());
        lines.push(format!(
            "tribunal: {}",
            if self.tribunal_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ));
        lines.push(format!(
            "transparency: {}",
            if self.transparency_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ));

        // Phase C: Add affordances if present
        if !self.affordances.is_empty() {
            lines.push(String::new());
            lines.push("# Affordances".into());
            for affordance in &self.affordances {
                lines.push(format!("affordance: {affordance}"));
            }
        }

        lines.join("\n")
    }
}

// Phase F: Analytics Configuration

/// Analytics configuration for nameserver metrics and insights
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AnalyticsConfig {
    /// Enable analytics collection and queries
    pub enabled: bool,

    /// Default time range for analytics queries
    pub default_time_range: String, // "last_hour", "last_day", "last_week", "last_month"
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_time_range: "last_day".to_string(),
        }
    }
}

impl AnalyticsConfig {
    fn from_env() -> Self {
        Self::default()
    }

    fn merge_env(&mut self) {
        if let Ok(val) = std::env::var("JIG_NS_ANALYTICS_ENABLED") {
            self.enabled = val == "true" || val == "1";
        }
        if let Ok(val) = std::env::var("JIG_NS_ANALYTICS_DEFAULT_RANGE") {
            self.default_time_range = val;
        }
    }
}

fn default_bind() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    7070
}

fn default_proxy_header() -> String {
    "x-forwarded-for".to_string()
}

fn default_database_path() -> PathBuf {
    std::env::var("JIG_NS_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("nameserver.db"))
}

fn default_penalty_decay() -> i64 {
    std::env::var("JIG_NS_PENALTY_DECAY")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(300)
}

fn default_penalty_step() -> u16 {
    std::env::var("JIG_NS_PENALTY_STEP_BITS")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(2)
}

fn default_anonymous_enabled() -> bool {
    std::env::var("JIG_NS_ANON_ENABLED")
        .ok()
        .and_then(|s| s.parse::<bool>().ok())
        .unwrap_or(true)
}

fn default_anon_min_pow() -> u16 {
    std::env::var("JIG_NS_ANON_MIN_POW")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(12)
}

const TEMPLATE: &str = r#"
# Jig Nameserver configuration

[network]
bind = "0.0.0.0"
port = 7070
trust_proxy = false
proxy_ip_header = "x-forwarded-for"

[storage]
# Names where the nameserver keeps <stem>_v002.db (aliases) and <stem>_v002.key
# (its signing key). The file itself is never created.
database_path = "~/.jig/nameserver.db"

# TLS, on by default. With neither path set, the nameserver makes a self-signed
# certificate on first start (in nameserver/tls/ next to the database), and its
# DID vouches for it at /.well-known/jig-ns. Set both paths to serve a
# certificate a CA issued. `enabled = false` serves plaintext: an unsafe
# option, listed in /.well-known/jig-ns under unsafe_options_active.
[tls]
enabled = true
# cert_path = "/etc/jig/nameserver.crt"
# key_path = "/etc/jig/nameserver.key"


# v0.0.2 register / rotate / renew. Refused requests get HTTP 429 with code
# RATE_LIMITED and a Retry-After header.
[alias_rate_limits]
enabled = true
per_ip_per_min = 30
per_did_per_min = 10
# GET /v1/challenge per client IP per minute, and the most challenges pending
# at once (past it, new ones get 503 BUSY).
challenge_per_ip_per_min = 60
max_pending_challenges = 100000

[penalties]
decay_secs = 300
step_bits = 2
max_points = 64

[anonymous]
enabled = true
min_difficulty = 16

[admin]
token = ""

[automation]
enabled = true
power_law_alpha = 1.4
pile_on_factor = 0.5
max_multiplier = 8.0
quorum = 3
evidence_window_secs = 600
human_review_window_secs = 3600

[reputation]
default_ruleset = "high-sec"

[[reputation.local_rulesets]]
key = "high-sec"
version = "0.1.0"
description = "Baseline high-sec social contract"
authority = "did:jig:central"
weight = 1.0

[reputation.local_rulesets.pow_policy]
min_bits = 12
max_bits = 28
multiplier = 1.0

[reputation.local_rulesets.tribunal_policy]
quorum = 5
auto_escalate_score = 0.25
evidence_window_secs = 3600

[[reputation.translation_contracts]]
from = "partner-high-sec"
to = "high-sec"
weight = 0.8

[reputation.translation_contracts.transform]
type = "linear"
slope = 0.9
intercept = 0.0

[useful_work]
assignment_ttl_secs = 600
max_assignments_per_worker = 5
result_retention_secs = 86400
max_queue_depth = 1024

[capabilities]
version = "v1"
# domain = "ns.example.com"  # Optional: your nameserver domain
useful_work_types = ["validate_block", "verify_observation", "audit_ruleset"]
tribunal_enabled = true
transparency_enabled = true

# Phase F: Analytics configuration
[analytics]
enabled = true
default_time_range = "last_day"  # Options: last_hour, last_day, last_week, last_month

# v0.0.2 alias API — GET /v1/challenge, POST /v1/register,
# GET /v1/resolve/:alias, GET /v1/handles, POST /v1/rotate, POST /v1/renew.
# Same key names as a jig-server config (`JigServerConfig`).
[v0_0_2.nameserver]
#
# Required: the suffixes this nameserver serves, the part after `@` in
# `alice@names.example.org`. There is no default; the nameserver refuses to
# start without at least one. One DID holds at most one name per suffix.
#
# [[v0_0_2.nameserver.alias_suffixes]]
# suffix = "names.example.org"
# registration = "open"        # or "closed": existing names still resolve,
#                              # renew and rotate; new ones are refused
# min_alias_len = 3
# # A single-label suffix such as `jig` needs `single_label_authority = true`:
# # clients trust it only through their own config, so its names verify only
# # for clients whose config names this nameserver's DID.
# # Refused at registration, compared after dropping `-`, `_`, `.` and
# # folding 0→o 1→i/l 3→e 4a 5s 7t. Defaults shown.
# reserved = ["admin", "root", "support", "help", "security", "abuse", "official",
#             "jig", "foundation", "team", "staff", "mod", "moderator", "system",
#             "postmaster", "noreply"]
# reserved_contains = ["official", "support", "jig"]   # anywhere in the alias
# reserved_affixes = ["admin", "staff"]                # at either end
#
# # These DIDs may register exactly these aliases, even when the suffix is
# # closed and regardless of length and reserved names. Removing an entry does
# # not affect a name already registered.
# [[v0_0_2.nameserver.alias_suffixes.registration_allow]]
# did = "did:jig:z..."
# aliases = ["alice"]
#
# # Proof-of-work on register, renew and rotate (JEP-0008). On by default
# # at the values shown, which jig clients solve; min_effort = 0 turns it
# # off. An allowlisted registration pays min_effort; an ordinary one pays
# # min_effort x short_name_factor^(short_name_len - length), up to max_effort.
# [v0_0_2.nameserver.alias_suffixes.pow]
# alg = 1
# min_effort = 1048576       # 2^20
# max_effort = 16777216      # 2^24, about 3 s on one server core
# max_solve_secs = 10
# short_name_len = 5
# short_name_factor = 4
# renew_effort = 1
# penalty_decay_secs = 600   # a penalty point's life; a repeat doubles it
#
# # The cap on registrations by DIDs registration_allow does not name. On by
# # default at the values shown; jig clients wait out 503 REGISTRATION_BUSY
# # and retry. enabled = false admits every stranger.
# [v0_0_2.nameserver.alias_suffixes.pool]
# enabled = true
# strangers_per_hour = 60
# burst = 10
# controller = "doubling"    # double the effort after a window with the queue
# controller_window_secs = 300  # full, halve it after a window with none queued
# queue_len = 20             # held for a token, highest effort first
# queue_wait_secs = 10       # then 503 REGISTRATION_BUSY with Retry-After

[v0_0_2.server]
# Ed25519 key that signs alias attestations. Left at the jig-server default
# (or empty) it is derived as a sibling of [storage].database_path, so a
# nameserver never signs with the chat server's DID.
# server_did_keyfile = "/var/lib/jig-nameserver/nameserver.key"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_sane() {
        let cfg = NameServerConfig::from_env();
        assert_eq!(cfg.network.port, default_port());
        assert!(cfg.reputation.local_rulesets.is_empty());
        assert!(cfg.reputation.translation_contracts.is_empty());
        assert!(cfg.useful_work.assignment_ttl_secs > 0);
        assert!(cfg.useful_work.max_queue_depth > 0);
    }

    #[test]
    fn reputation_template_parses() {
        let cfg: NameServerConfig = toml::from_str(TEMPLATE).expect("template parses");
        assert_eq!(cfg.reputation.default_ruleset.as_deref(), Some("high-sec"));
        assert_eq!(cfg.reputation.local_rulesets.len(), 1);
        assert_eq!(cfg.reputation.translation_contracts.len(), 1);
        let rule = &cfg.reputation.local_rulesets[0];
        assert_eq!(rule.key, "high-sec");
        assert_eq!(rule.pow_policy.min_bits, Some(12));
        match &cfg.reputation.translation_contracts[0].transform {
            TranslationKind::Linear { slope, .. } => assert!((*slope - 0.9).abs() < f64::EPSILON),
            _ => panic!("expected linear transform"),
        }
        assert_eq!(cfg.useful_work.max_queue_depth, 1024);
        assert_eq!(cfg.useful_work.assignment_ttl_secs, 600);
    }

    #[test]
    fn profile_merge_applies() {
        let doc = r#"
[nameserver]
profile = "prod"

[nameserver.network]
bind = "127.0.0.1"
port = 7070

[nameserver.profiles.default.alias_rate_limits]
per_ip_per_min = 10

[nameserver.profiles.prod.network]
bind = "0.0.0.0"
port = 8080
[nameserver.profiles.prod.reputation]
default_ruleset = "prod"
"#;
        let value: TomlValue = toml::from_str(doc).unwrap();
        let table = value
            .as_table()
            .unwrap()
            .get("nameserver")
            .unwrap()
            .as_table()
            .unwrap()
            .clone();
        let cfg = NameServerConfig::from_table(table, None).unwrap();
        assert_eq!(cfg.network.bind, "0.0.0.0");
        assert_eq!(cfg.network.port, 8080);
        assert_eq!(cfg.alias_rate_limits.per_ip_per_min, 10);
        assert_eq!(cfg.reputation.default_ruleset.as_deref(), Some("prod"));
    }

    #[test]
    fn profile_override_takes_precedence() {
        let doc = r#"
[nameserver]
profile = "prod"

[nameserver.network]
bind = "127.0.0.1"
port = 7070

[nameserver.profiles.qa.network]
bind = "10.0.0.1"
port = 9090
"#;
        let value: TomlValue = toml::from_str(doc).unwrap();
        let table = value
            .as_table()
            .unwrap()
            .get("nameserver")
            .unwrap()
            .as_table()
            .unwrap()
            .clone();
        let cfg = NameServerConfig::from_table(table, Some("qa".to_string())).unwrap();
        assert_eq!(cfg.network.bind, "10.0.0.1");
        assert_eq!(cfg.network.port, 9090);
    }

    #[test]
    fn capabilities_generates_dns_txt_records() {
        let cfg = CapabilitiesConfig::default();
        let records = cfg.to_dns_txt_records();

        assert!(records.iter().any(|r| r.starts_with("jig-ns=version:")));
        assert!(records.iter().any(|r| r.contains("work:")));
        assert!(records.iter().any(|r| r.contains("tribunal:enabled")));
        assert!(records.iter().any(|r| r.contains("transparency:enabled")));
    }

    #[test]
    fn capabilities_generates_text_format() {
        let cfg = CapabilitiesConfig {
            domain: Some("ns.example.com".into()),
            ..Default::default()
        };

        let text = cfg.to_capabilities_text();

        assert!(text.contains("version: v1"));
        assert!(text.contains("domain: ns.example.com"));
        assert!(text.contains("work: validate_block"));
        assert!(text.contains("tribunal: enabled"));
        assert!(text.contains("transparency: enabled"));
    }

    #[test]
    fn capabilities_from_toml() {
        let doc = r#"
version = "v2"
domain = "test.example.com"
useful_work_types = ["custom"]
tribunal_enabled = false
transparency_enabled = true
"#;
        let cfg: CapabilitiesConfig = toml::from_str(doc).unwrap();

        assert_eq!(cfg.version, "v2");
        assert_eq!(cfg.domain.as_deref(), Some("test.example.com"));
        assert_eq!(cfg.useful_work_types, vec!["custom"]);
        assert!(!cfg.tribunal_enabled);
        assert!(cfg.transparency_enabled);
    }

    #[test]
    fn capabilities_in_full_config() {
        let cfg: NameServerConfig = toml::from_str(TEMPLATE).unwrap();
        assert_eq!(cfg.capabilities.version, "v1");
        assert!(cfg.capabilities.tribunal_enabled);
        assert!(cfg.capabilities.transparency_enabled);
    }

    // --- [v0_0_2] alias-API section ----------------------------------------

    fn from_doc(doc: &str) -> Result<NameServerConfig> {
        let value: TomlValue = toml::from_str(doc).expect("valid TOML");
        NameServerConfig::from_table(value.as_table().unwrap().clone(), None)
    }

    /// Each removed section and key fails to load, naming itself and the fix.
    #[test]
    fn removed_sections_and_keys_are_named_errors() {
        for (path, _) in REMOVED_KEYS {
            let doc = match path.split_once('.') {
                None => format!("[{path}]\nenabled = true\n"),
                Some((section, key)) => format!("[{section}]\n{key} = \"x\"\n"),
            };
            let err = from_doc(&doc).expect_err(path).to_string();
            assert!(err.contains(path), "{path}: {err}");
            assert!(err.contains("Delete it"), "{path}: {err}");
        }
    }

    /// Every config struct denies unknown fields: a typo fails to load and
    /// serde's error names the key.
    #[test]
    fn an_unknown_key_in_any_section_is_an_error_naming_it() {
        for (section, key) in [
            ("network", "bnid"),
            ("storage", "databse_path"),
            ("alias_rate_limits", "per_ip"),
            ("penalties", "decay"),
            ("anonymous", "enable"),
            ("admin", "tokn"),
            ("automation", "alpha"),
            ("reputation", "default"),
            ("useful_work", "queue"),
            ("capabilities", "versoin"),
            ("analytics", "enable"),
        ] {
            let err = from_doc(&format!("[{section}]\n{key} = 1\n"))
                .expect_err(section)
                .to_string();
            assert!(err.contains(key), "[{section}] {key}: {err}");
        }
        let err = from_doc("lisen = 1\n").expect_err("root").to_string();
        assert!(err.contains("lisen"), "{err}");
    }

    #[test]
    fn the_template_and_examples_parse_strictly() {
        from_doc(TEMPLATE).expect("template");
        for example in [
            include_str!("../examples/config/profile_federated.toml"),
            include_str!("../examples/config/profile_potato.toml"),
        ] {
            from_doc(example).expect("example parses");
        }
    }

    /// `--config` wins over `JIG_NS_CONFIG`; with neither there is no default
    /// path, and the error names both and the old fallbacks it no longer reads.
    #[test]
    fn the_config_path_is_explicit_or_from_jig_ns_config() {
        let flag = Path::new("/etc/jig/flag.toml");
        let env = || Some(std::ffi::OsString::from("/etc/jig/env.toml"));
        assert_eq!(config_path(Some(flag), env()).unwrap(), flag);
        assert_eq!(
            config_path(None, env()).unwrap(),
            Path::new("/etc/jig/env.toml")
        );
        for missing in [None, Some(std::ffi::OsString::new())] {
            let err = config_path(None, missing).unwrap_err().to_string();
            assert!(
                err.contains("--config") && err.contains("JIG_NS_CONFIG"),
                "{err}"
            );
            assert!(err.contains("~/.jig/config.toml"), "{err}");
        }
    }

    #[test]
    fn removed_env_vars_are_reported_by_name_and_prefix() {
        let env = [
            "JIG_NS_SECRET",
            "JIG_NS_POW_DIFFICULTY",
            "JIG_NS_HOT_BACKEND",
            "JIG_NS_FEDERATION_ENABLED",
            "JIG_NS_BIND",
            "JIG_NS_POWER",
            "HOME",
        ]
        .map(String::from);
        let found: Vec<String> = removed_env_vars_in(env.into_iter())
            .into_iter()
            .map(|(var, _)| var)
            .collect();
        assert_eq!(
            found,
            [
                "JIG_NS_FEDERATION_ENABLED",
                "JIG_NS_HOT_BACKEND",
                "JIG_NS_POW_DIFFICULTY",
                "JIG_NS_SECRET"
            ],
            "live variables and near-miss names are not reported"
        );
    }

    #[test]
    fn v0_0_2_has_no_default_suffix() {
        let cfg = NameServerConfig::from_env();
        assert!(cfg.v0_0_2.nameserver.alias_suffixes.is_empty());
        let err = cfg.validate().expect_err("no suffix, no start");
        assert!(
            err.to_string().contains("alias_suffixes is required"),
            "{err}"
        );
    }

    #[test]
    fn the_template_names_no_suffix_and_so_does_not_start_unedited() {
        let cfg: NameServerConfig = toml::from_str(TEMPLATE).expect("template parses");
        let err = cfg.validate().expect_err("the operator must name a suffix");
        assert!(
            err.to_string().contains("alias_suffixes is required"),
            "{err}"
        );
    }

    #[test]
    fn v0_0_2_alias_suffixes_are_operator_settable() {
        let doc = r#"
[[v0_0_2.nameserver.alias_suffixes]]
suffix = "names.example.org"

[[v0_0_2.nameserver.alias_suffixes]]
suffix = "jig"
single_label_authority = true
registration = "closed"

[v0_0_2.server]
server_did_keyfile = "/var/lib/jig-ns/ns.key"
"#;
        let cfg: NameServerConfig = toml::from_str(doc).expect("parses");
        let suffixes: Vec<&str> = cfg
            .v0_0_2
            .nameserver
            .alias_suffixes
            .iter()
            .map(|s| s.suffix.as_str())
            .collect();
        assert_eq!(suffixes, ["names.example.org", "jig"]);
        assert_eq!(
            cfg.v0_0_2.server.server_did_keyfile,
            "/var/lib/jig-ns/ns.key"
        );
        cfg.validate().expect("valid");
    }

    /// The deploy's nameserver config loads through `JIG_NS_CONFIG`'s path.
    #[test]
    fn the_deploy_example_config_loads() {
        let dir = std::env::temp_dir().join(format!("jig-ns-deploy-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("jig-nameserver.toml");
        std::fs::write(
            &path,
            include_str!("../../../deploy/jig-nameserver.example.toml"),
        )
        .unwrap();
        let cfg = NameServerConfig::load_from_path(&path).expect("loads and validates");
        assert_eq!(
            cfg.v0_0_2.nameserver.alias_suffixes[0].suffix,
            "names.example.org"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_a_malformed_suffix_and_the_old_key() {
        let doc = r#"
[[v0_0_2.nameserver.alias_suffixes]]
suffix = "dj@dj.example"
"#;
        let cfg: NameServerConfig = toml::from_str(doc).expect("parses");
        let err = cfg.validate().expect_err("'@' in a suffix must be caught");
        assert!(err.to_string().contains("'@'"), "{err}");

        let doc = r#"
[v0_0_2.nameserver]
alias_suffix = "dj.jig"
"#;
        let cfg: NameServerConfig = toml::from_str(doc).expect("parses");
        let err = cfg.validate().expect_err("old key");
        assert!(err.to_string().contains("alias_suffixes"), "{err}");
    }
}
