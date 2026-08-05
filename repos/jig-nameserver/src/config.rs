//! Configuration for the Jig Nameserver.

use crate::error::{NameServerError, Result};
use crate::types::ReputationScore;
use jig_config;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

const DEFAULT_CONFIG_RELATIVE: &str = "config/jig-nameserver/jig-config.toml";

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
#[serde(default)]
pub struct NameServerConfig {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub pow: PowConfig,
    pub rate_limits: RateLimitConfig,
    pub penalties: PenaltyConfig,
    pub anonymous: AnonymousPolicy,
    pub federation: FederationConfig,
    pub admin: AdminConfig,
    pub automation: AutomationPolicy,
    pub transparency: TransparencyConfig,
    pub reputation: ReputationConfig,
    pub useful_work: UsefulWorkConfig,
    pub capabilities: CapabilitiesConfig,
    pub runtime: RuntimeConfig, // Phase E: Embedded WASM execution
    pub anomaly_detection: AnomalyDetectionConfig, // Phase D: Anomaly detection and cross-validation
    pub analytics: AnalyticsConfig,                // Phase F: Analytics and insights
    pub hot: HotConfig, // Phase F Tier 2/3: Hot state backend (rate limiting, caching)
    /// v0.0.2 alias-API wiring (`[v0_0_2]`), consumed by
    /// [`crate::server::build_app`] to boot `crate::v0_0_2::AppState`.
    ///
    /// Reuses jig-server's `JigServerConfig` verbatim so `[v0_0_2.nameserver]
    /// alias_suffix` and `[v0_0_2.server] server_did_keyfile` mean exactly what
    /// they mean in a jig-server config. Only the keys the nameserver actually
    /// consumes are honoured (`server.server_did_keyfile`,
    /// `identity.naively_allow_unknown_handles_fallback`, `nameserver.alias_suffix`);
    /// `server.allowed_block_kinds` is overridden with the ns-only allowlist by
    /// `v0_0_2::AppState::new`.
    #[serde(default)]
    pub v0_0_2: jig_config::v0_0_2_server::JigServerConfig,
}

impl NameServerConfig {
    /// Load configuration from disk if available, otherwise fall back to env
    /// defaults. The result is [`validate`](Self::validate)d, so a missing
    /// `[pow].server_secret` surfaces as an `Err` the caller can log — it used
    /// to panic inside `Default` during deserialization, which reached stderr
    /// via the panic hook only and looked like a silent death under systemd.
    pub fn load() -> Result<Self> {
        let cfg = Self::load_unvalidated()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Operator-fixable-misconfiguration check. Separate from parsing so tests
    /// (and callers who want to patch a field before booting) can build an
    /// unvalidated config, and so failures are errors rather than panics.
    pub fn validate(&self) -> Result<()> {
        if self.pow.server_secret.trim().is_empty() {
            return Err(NameServerError::Other(anyhow::anyhow!(
                "JIG_NS_SECRET env var is required. \
                 Set it to a strong random secret (e.g. `openssl rand -hex 32`), \
                 or set [pow].server_secret in the nameserver config file. \
                 See .env.example for all required variables."
            )));
        }
        self.v0_0_2
            .nameserver
            .validate()
            .map_err(|e| NameServerError::Other(anyhow::anyhow!("[v0_0_2] {e}")))?;
        Ok(())
    }

    fn load_unvalidated() -> Result<Self> {
        let env_profile = std::env::var("JIG_NS_PROFILE").ok();

        if let Ok(explicit) = std::env::var("JIG_NS_CONFIG") {
            return Self::load_from_path_with_profile(explicit, env_profile.clone());
        }

        if let Ok(global_path) = std::env::var("JIG_CONFIG")
            && let Some(cfg) =
                Self::load_from_global_path(&PathBuf::from(global_path), env_profile.clone())?
        {
            return Ok(cfg);
        }

        if let Some(cfg) =
            Self::load_from_global_path(&jig_config::default_config_path(), env_profile.clone())?
        {
            return Ok(cfg);
        }

        if Path::new(DEFAULT_CONFIG_RELATIVE).exists() {
            return Self::load_from_path_with_profile(DEFAULT_CONFIG_RELATIVE, env_profile);
        }

        let mut cfg = Self::from_env();
        cfg.normalize();
        Ok(cfg)
    }

    /// Load configuration from the given path. Validated like [`load`](Self::load).
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
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

    fn load_from_global_path(
        path: &Path,
        profile_override: Option<String>,
    ) -> Result<Option<Self>> {
        let data = match fs::read_to_string(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(NameServerError::Other(anyhow::anyhow!(format!(
                    "read global config {}: {}",
                    path.display(),
                    e
                ))));
            }
        };
        let value: TomlValue = toml::from_str(&data).map_err(|e| {
            NameServerError::Other(anyhow::anyhow!(format!("parse {}: {}", path.display(), e)))
        })?;
        let root = match value.as_table() {
            Some(table) => table,
            None => return Ok(None),
        };
        let nameserver_value = match root.get("nameserver") {
            Some(value) => value,
            None => return Ok(None),
        };
        let mut override_profile = profile_override;
        if override_profile.is_none() {
            override_profile = root
                .get("deployment")
                .and_then(|v| v.as_table())
                .and_then(|tbl| tbl.get("mode"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
        let table = nameserver_value.as_table().cloned().ok_or_else(|| {
            NameServerError::Other(anyhow::anyhow!(
                "nameserver section in {} must be a table",
                path.display()
            ))
        })?;
        let mut cfg = Self::from_table(table, override_profile)?;
        cfg.apply_env_overrides();
        cfg.normalize();
        Ok(Some(cfg))
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
            pow: PowConfig::from_env(),
            rate_limits: RateLimitConfig::from_env(),
            penalties: PenaltyConfig::from_env(),
            anonymous: AnonymousPolicy::from_env(),
            federation: FederationConfig::from_env(),
            admin: AdminConfig::from_env(),
            automation: AutomationPolicy::from_env(),
            transparency: TransparencyConfig::from_env(),
            reputation: ReputationConfig::from_env(),
            useful_work: UsefulWorkConfig::from_env(),
            capabilities: CapabilitiesConfig::from_env(),
            runtime: RuntimeConfig::from_env(),
            anomaly_detection: AnomalyDetectionConfig::from_env(),
            analytics: AnalyticsConfig::from_env(),
            hot: HotConfig::from_env(),
            v0_0_2: jig_config::v0_0_2_server::JigServerConfig::default(),
        }
    }

    fn apply_env_overrides(&mut self) {
        // Allow env vars to override settings after TOML load for quick tweaks.
        self.network.merge_env();
        self.storage.merge_env();
        self.pow.merge_env();
        self.rate_limits.merge_env();
        self.analytics.merge_env();
        self.hot.merge_env();
        self.penalties.merge_env();
        self.anonymous.merge_env();
        self.federation.merge_env();
        self.admin.merge_env();
        self.automation.merge_env();
        self.transparency.merge_env();
        self.reputation.merge_env();
        self.useful_work.merge_env();
        self.capabilities.merge_env();
        self.runtime.merge_env();
    }

    fn normalize(&mut self) {
        self.federation
            .allow_domains
            .iter_mut()
            .for_each(|d| *d = d.trim().to_lowercase());
        self.federation
            .deny_domains
            .iter_mut()
            .for_each(|d| *d = d.trim().to_lowercase());
        self.reputation.normalize();
    }

    pub fn compute_pow_difficulty(
        &self,
        base_bits: u16,
        penalty_points: u32,
        zone: ReputationZone,
        reputation: Option<&ReputationScore>,
        witness_weight: Option<f64>,
    ) -> u16 {
        let mut effective = base_bits;
        let constrained_points = penalty_points.min(self.penalties.max_points);
        let penalty_bits = self
            .penalties
            .step_bits
            .saturating_mul(constrained_points as u16);
        effective = effective.saturating_add(penalty_bits);

        let mut multiplier = 1.0;
        if let Some(score) = reputation {
            multiplier *= self.reputation_multiplier(score);
        }
        let witness = witness_weight
            .unwrap_or_else(|| self.automation.score_hint_from_penalty(constrained_points));
        multiplier *= self.automation.multiplier(witness);
        effective = ((effective as f64) * multiplier).round() as u16;

        let minimum_zone = match zone {
            ReputationZone::Anonymous if self.anonymous.enabled => self.anonymous.min_difficulty,
            ReputationZone::High => self.pow.min_difficulty.saturating_add(2),
            _ => self.pow.min_difficulty,
        };
        if effective < minimum_zone {
            effective = minimum_zone;
        }
        if effective < self.pow.min_difficulty {
            effective = self.pow.min_difficulty;
        }
        if effective > self.pow.max_difficulty {
            effective = self.pow.max_difficulty;
        }
        effective
    }

    fn reputation_multiplier(&self, score: &ReputationScore) -> f64 {
        let mut multiplier = 1.0;
        if let Some(rule) = self
            .reputation
            .local_rulesets
            .iter()
            .find(|r| r.key == score.ruleset)
            && let Some(rule_mult) = rule.pow_policy.multiplier
        {
            multiplier *= rule_mult;
        }
        let bounded_score = score.score.clamp(-1.0, 1.0);
        let trust_factor = (1.0 - bounded_score * 0.25).clamp(0.25, 4.0);
        multiplier *= trust_factor;
        let weight = score.weight.clamp(0.0, 1.0);
        if weight < 1.0 {
            multiplier = 1.0 + (multiplier - 1.0) * weight;
        }
        multiplier.clamp(0.1, 8.0)
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
#[serde(default)]
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
#[serde(default)]
pub struct StorageConfig {
    pub database_path: PathBuf,

    /// Storage backend type (truth database)
    /// - Tier 1 (Potato): "sqlite" (default)
    /// - Tier 2 (Prosumer): "postgres"
    /// - Tier 3 (Hyperscale): "cockroachdb", "tidb"
    #[serde(default = "default_storage_backend")]
    pub backend: String,

    /// Backend-specific configuration (key-value pairs passed to backend)
    /// Example for Postgres: {"connection_string": "postgres://localhost/nameserver", "pool_size": "10"}
    #[serde(default)]
    pub backend_config: std::collections::HashMap<String, String>,
}

fn default_storage_backend() -> String {
    "sqlite".to_string()
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: default_database_path(),
            backend: default_storage_backend(),
            backend_config: std::collections::HashMap::new(),
        }
    }
}

impl StorageConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(path) = std::env::var("JIG_NS_DB_PATH") {
            cfg.database_path = PathBuf::from(path);
        }
        if let Ok(backend) = std::env::var("JIG_NS_STORAGE_BACKEND") {
            cfg.backend = backend;
        }
        // Backend-specific config can be set via JIG_NS_STORAGE_BACKEND_<KEY>
        // e.g., JIG_NS_STORAGE_BACKEND_CONNECTION_STRING=postgres://...
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(path) = std::env::var("JIG_NS_DB_PATH") {
            self.database_path = PathBuf::from(path);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PowConfig {
    pub server_secret: String,
    pub base_difficulty: u16,
    pub min_difficulty: u16,
    pub max_difficulty: u16,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            server_secret: default_server_secret(),
            base_difficulty: default_base_pow(),
            min_difficulty: default_min_pow(),
            max_difficulty: default_max_pow(),
        }
    }
}

impl PowConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(secret) = std::env::var("JIG_NS_SECRET") {
            cfg.server_secret = secret;
        }
        if let Ok(bits) = std::env::var("JIG_NS_POW_DIFFICULTY")
            && let Ok(parsed) = bits.parse::<u16>()
        {
            cfg.base_difficulty = parsed;
        }
        if let Ok(bits) = std::env::var("JIG_NS_POW_MIN")
            && let Ok(parsed) = bits.parse::<u16>()
        {
            cfg.min_difficulty = parsed;
        }
        if let Ok(bits) = std::env::var("JIG_NS_POW_MAX")
            && let Ok(parsed) = bits.parse::<u16>()
        {
            cfg.max_difficulty = parsed;
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(secret) = std::env::var("JIG_NS_SECRET") {
            self.server_secret = secret;
        }
        if let Ok(bits) = std::env::var("JIG_NS_POW_DIFFICULTY")
            && let Ok(parsed) = bits.parse::<u16>()
        {
            self.base_difficulty = parsed;
        }
        if let Ok(bits) = std::env::var("JIG_NS_POW_MIN")
            && let Ok(parsed) = bits.parse::<u16>()
        {
            self.min_difficulty = parsed;
        }
        if let Ok(bits) = std::env::var("JIG_NS_POW_MAX")
            && let Ok(parsed) = bits.parse::<u16>()
        {
            self.max_difficulty = parsed;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub per_key_per_min: u32,
    pub per_ip_per_min: u32,
    pub global_per_min: Option<u32>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_key_per_min: default_per_key_limit(),
            per_ip_per_min: default_per_ip_limit(),
            global_per_min: None,
        }
    }
}

impl RateLimitConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(limit) = std::env::var("JIG_NS_RATE_PER_MIN")
            && let Ok(parsed) = limit.parse::<u32>()
        {
            cfg.per_key_per_min = parsed;
        }
        if let Ok(limit) = std::env::var("JIG_NS_RATE_PER_IP_PER_MIN")
            && let Ok(parsed) = limit.parse::<u32>()
        {
            cfg.per_ip_per_min = parsed;
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(limit) = std::env::var("JIG_NS_RATE_PER_MIN")
            && let Ok(parsed) = limit.parse::<u32>()
        {
            self.per_key_per_min = parsed;
        }
        if let Ok(limit) = std::env::var("JIG_NS_RATE_PER_IP_PER_MIN")
            && let Ok(parsed) = limit.parse::<u32>()
        {
            self.per_ip_per_min = parsed;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FederationConfig {
    pub enabled: bool,
    pub allow_domains: Vec<String>,
    pub deny_domains: Vec<String>,
    pub seed_peers: Vec<String>, // Initial peer endpoints
    pub max_peers: usize,
    pub cache_ttl_secs: i64,
    pub gossip_interval_secs: i64,
    pub handshake_timeout_secs: i64,
    pub gossip_batch_size: usize, // Max items per gossip message
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            seed_peers: Vec::new(),
            max_peers: 50,
            cache_ttl_secs: default_federation_cache_ttl(),
            gossip_interval_secs: 300,
            handshake_timeout_secs: 30,
            gossip_batch_size: 100,
        }
    }
}

impl FederationConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(val) = std::env::var("JIG_NS_FEDERATION_ENABLED") {
            cfg.enabled = val == "true" || val == "1";
        }
        if let Ok(domains) = std::env::var("JIG_NS_ALLOW_DOMAINS") {
            cfg.allow_domains = split_domains(&domains);
        }
        if let Ok(domains) = std::env::var("JIG_NS_DENY_DOMAINS") {
            cfg.deny_domains = split_domains(&domains);
        }
        if let Ok(peers) = std::env::var("JIG_NS_SEED_PEERS") {
            cfg.seed_peers = split_domains(&peers);
        }
        if let Ok(max) = std::env::var("JIG_NS_MAX_PEERS")
            && let Ok(parsed) = max.parse::<usize>()
        {
            cfg.max_peers = parsed;
        }
        if let Ok(secs) = std::env::var("JIG_NS_CACHE_TTL")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            cfg.cache_ttl_secs = parsed;
        }
        if let Ok(secs) = std::env::var("JIG_NS_GOSSIP_INTERVAL")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            cfg.gossip_interval_secs = parsed;
        }
        if let Ok(secs) = std::env::var("JIG_NS_HANDSHAKE_TIMEOUT")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            cfg.handshake_timeout_secs = parsed;
        }
        if let Ok(size) = std::env::var("JIG_NS_GOSSIP_BATCH_SIZE")
            && let Ok(parsed) = size.parse::<usize>()
        {
            cfg.gossip_batch_size = parsed;
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(val) = std::env::var("JIG_NS_FEDERATION_ENABLED") {
            self.enabled = val == "true" || val == "1";
        }
        if let Ok(domains) = std::env::var("JIG_NS_ALLOW_DOMAINS") {
            let parsed = split_domains(&domains);
            if !parsed.is_empty() {
                self.allow_domains = parsed;
            }
        }
        if let Ok(domains) = std::env::var("JIG_NS_DENY_DOMAINS") {
            let parsed = split_domains(&domains);
            if !parsed.is_empty() {
                self.deny_domains = parsed;
            }
        }
        if let Ok(peers) = std::env::var("JIG_NS_SEED_PEERS") {
            let parsed = split_domains(&peers);
            if !parsed.is_empty() {
                self.seed_peers = parsed;
            }
        }
        if let Ok(max) = std::env::var("JIG_NS_MAX_PEERS")
            && let Ok(parsed) = max.parse::<usize>()
        {
            self.max_peers = parsed;
        }
        if let Ok(secs) = std::env::var("JIG_NS_CACHE_TTL")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            self.cache_ttl_secs = parsed;
        }
        if let Ok(secs) = std::env::var("JIG_NS_GOSSIP_INTERVAL")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            self.gossip_interval_secs = parsed;
        }
        if let Ok(secs) = std::env::var("JIG_NS_HANDSHAKE_TIMEOUT")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            self.handshake_timeout_secs = parsed;
        }
        if let Ok(size) = std::env::var("JIG_NS_GOSSIP_BATCH_SIZE")
            && let Ok(parsed) = size.parse::<usize>()
        {
            self.gossip_batch_size = parsed;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
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
#[serde(default)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransparencyConfig {
    pub log_path: PathBuf,
    pub publish_interval_secs: i64,
}

impl Default for TransparencyConfig {
    fn default() -> Self {
        Self {
            log_path: default_transparency_path(),
            publish_interval_secs: 3600,
        }
    }
}

impl TransparencyConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(path) = std::env::var("JIG_NS_TRANSPARENCY_PATH") {
            cfg.log_path = PathBuf::from(path);
        }
        if let Ok(secs) = std::env::var("JIG_NS_TRANSPARENCY_INTERVAL")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            cfg.publish_interval_secs = parsed;
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(path) = std::env::var("JIG_NS_TRANSPARENCY_PATH") {
            self.log_path = PathBuf::from(path);
        }
        if let Ok(secs) = std::env::var("JIG_NS_TRANSPARENCY_INTERVAL")
            && let Ok(parsed) = secs.parse::<i64>()
        {
            self.publish_interval_secs = parsed;
        }
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
#[derive(Default)]
pub struct RuleTribunalPolicy {
    pub quorum: Option<u32>,
    pub auto_escalate_score: Option<f64>,
    pub evidence_window_secs: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct TranslationTableEntry {
    pub min: f64,
    pub max: f64,
    pub mapped: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
pub struct CapabilitiesConfig {
    pub version: String,
    pub domain: Option<String>,
    pub useful_work_types: Vec<String>,
    pub tribunal_enabled: bool,
    pub transparency_enabled: bool,
    pub federation_enabled: bool,
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
            federation_enabled: false,
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

        if self.federation_enabled {
            records.push("jig-ns=federation:enabled".into());
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
        lines.push(format!(
            "federation: {}",
            if self.federation_enabled {
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

// Phase E: Runtime Embedding Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Enable embedded WASM execution
    pub enabled: bool,

    /// Maximum fuel budget (instructions)
    pub fuel_max: u64,

    /// Maximum linear memory in MB
    pub memory_max_mb: u32,

    /// Wall-clock execution timeout in milliseconds
    pub execution_timeout_ms: u64,

    /// Allowed capabilities for nameserver-executed blocks
    /// Limited to: storage.read:receipts:*, storage.write:attestations:*, net.fetch:federation:*
    pub allowed_capabilities: Vec<String>,

    /// Enable deterministic execution (strongly recommended)
    pub deterministic: bool,

    /// Enable WASI preview2
    pub wasi_preview2: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,            // Opt-in for Phase E
            fuel_max: 5_000_000,       // 5M instructions
            memory_max_mb: 32,         // 32MB
            execution_timeout_ms: 250, // 250ms
            allowed_capabilities: vec![
                "storage.read:receipts:*".into(),
                "storage.write:attestations:*".into(),
                "net.fetch:federation:*".into(),
            ],
            deterministic: true,
            wasi_preview2: true,
        }
    }
}

impl RuntimeConfig {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(val) = std::env::var("JIG_NS_RUNTIME_ENABLED") {
            cfg.enabled = val == "true" || val == "1";
        }
        if let Ok(val) = std::env::var("JIG_RUNTIME_FUEL_MAX")
            && let Ok(fuel) = val.parse()
        {
            cfg.fuel_max = fuel;
        }
        if let Ok(val) = std::env::var("JIG_RUNTIME_MEMORY_MAX_MB")
            && let Ok(mem) = val.parse()
        {
            cfg.memory_max_mb = mem;
        }
        if let Ok(val) = std::env::var("JIG_RUNTIME_TIMEOUT_MS")
            && let Ok(timeout) = val.parse()
        {
            cfg.execution_timeout_ms = timeout;
        }
        cfg
    }

    fn merge_env(&mut self) {
        if let Ok(val) = std::env::var("JIG_NS_RUNTIME_ENABLED") {
            self.enabled = val == "true" || val == "1";
        }
        if let Ok(val) = std::env::var("JIG_RUNTIME_FUEL_MAX")
            && let Ok(fuel) = val.parse()
        {
            self.fuel_max = fuel;
        }
        if let Ok(val) = std::env::var("JIG_RUNTIME_MEMORY_MAX_MB")
            && let Ok(mem) = val.parse()
        {
            self.memory_max_mb = mem;
        }
        if let Ok(val) = std::env::var("JIG_RUNTIME_TIMEOUT_MS")
            && let Ok(timeout) = val.parse()
        {
            self.execution_timeout_ms = timeout;
        }
    }
}

// Phase D: Anomaly Detection Configuration
// TODO: Migrate to jig-config/src/nameserver.rs once cross-validation config is upstreamed

/// Anomaly detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnomalyDetectionConfig {
    /// Enable anomaly detection
    pub enabled: bool,

    /// Maximum fuel threshold for network operations
    pub max_network_fuel: u64,

    /// Fuel usage anomaly detection settings
    pub fuel_anomaly: FuelAnomalyConfig,

    /// Hard failure detection settings
    pub hard_failure: HardFailureConfig,

    /// Auto-escalation settings
    pub auto_escalation: AutoEscalationConfig,

    /// Cross-nameserver validation settings (Phase D)
    pub cross_validation: CrossValidationConfig,
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_network_fuel: 500_000,
            fuel_anomaly: FuelAnomalyConfig::default(),
            hard_failure: HardFailureConfig::default(),
            auto_escalation: AutoEscalationConfig::default(),
            cross_validation: CrossValidationConfig::default(),
        }
    }
}

/// Fuel anomaly detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FuelAnomalyConfig {
    pub enabled: bool,
    /// Excessive threshold multiplier (vs historical avg, e.g. 3.0 = 300%)
    pub excessive_threshold: f64,
    /// Suspicious threshold multiplier (vs historical avg, e.g. 0.3 = 30%)
    pub suspicious_threshold: f64,
    /// Minimum sample size for baseline
    pub min_sample_size: usize,
}

impl Default for FuelAnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            excessive_threshold: 3.0,
            suspicious_threshold: 0.3,
            min_sample_size: 10,
        }
    }
}

/// Hard failure detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HardFailureConfig {
    pub enabled: bool,
    /// Consecutive failures to trigger alert
    pub consecutive_threshold: u32,
    /// Time window for failure counting (seconds)
    pub time_window_secs: u32,
}

impl Default for HardFailureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            consecutive_threshold: 5,
            time_window_secs: 300, // 5 minutes
        }
    }
}

/// Auto-escalation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoEscalationConfig {
    pub enabled: bool,
    /// Severity levels that trigger auto-escalation
    pub severities: Vec<String>,
    /// PoW penalty bits for each severity (low, medium, high, critical)
    pub pow_penalties: std::collections::HashMap<String, u32>,
}

impl Default for AutoEscalationConfig {
    fn default() -> Self {
        let mut pow_penalties = std::collections::HashMap::new();
        pow_penalties.insert("low".into(), 0);
        pow_penalties.insert("medium".into(), 2);
        pow_penalties.insert("high".into(), 4);
        pow_penalties.insert("critical".into(), 8);

        Self {
            enabled: true,
            severities: vec!["high".into(), "critical".into()],
            pow_penalties,
        }
    }
}

/// Cross-nameserver validation configuration (Phase D)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CrossValidationConfig {
    /// Enable cross-validation for suspicious receipts
    pub enabled: bool,

    /// HTTP timeout for peer requests (seconds)
    pub validation_timeout_secs: u32,

    /// Maximum peers to query for validation
    pub max_validation_peers: usize,

    /// Fuel tolerance percentage (e.g., 5.0 = ±5%)
    pub fuel_tolerance_pct: f64,

    /// Consensus threshold (e.g., 0.5 = >50% agreement required)
    pub consensus_threshold: f64,

    /// Minimum peers required for validation
    pub min_peers: usize,
}

impl Default for CrossValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            validation_timeout_secs: 5,
            max_validation_peers: 3,
            fuel_tolerance_pct: 5.0,
            consensus_threshold: 0.5,
            min_peers: 2,
        }
    }
}

// Phase F: Analytics Configuration

/// Analytics configuration for nameserver metrics and insights
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalyticsConfig {
    /// Enable analytics collection and queries
    pub enabled: bool,

    /// Default time range for analytics queries
    pub default_time_range: String, // "last_hour", "last_day", "last_week", "last_month"

    /// Analytics backend type
    /// - Tier 1 (Potato): "sqlite" (default)
    /// - Tier 2 (Prosumer): "duckdb", "parquet"
    /// - Tier 3 (Hyperscale): "clickhouse" (future)
    pub backend: String,

    /// Backend-specific configuration (key-value pairs passed to backend factory)
    /// Example for DuckDB: {"database_path": "analytics.db", "parquet_export_path": "/data/parquet"}
    #[serde(default)]
    pub backend_config: std::collections::HashMap<String, String>,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_time_range: "last_day".to_string(),
            backend: "sqlite".to_string(), // Tier 1 default
            backend_config: std::collections::HashMap::new(),
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
        if let Ok(val) = std::env::var("JIG_NS_ANALYTICS_BACKEND") {
            self.backend = val;
        }
        // Backend-specific config can be set via JIG_NS_ANALYTICS_BACKEND_<KEY>
        // e.g., JIG_NS_ANALYTICS_BACKEND_DATABASE_PATH=/path/to/db
    }
}

// Phase F Tier 2/3: Hot State Backend Configuration

/// Hot state backend configuration for ephemeral data (rate limiting, caching, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HotConfig {
    /// Hot backend type
    /// - Tier 1 (Potato): "memory" (default - in-memory HashMap)
    /// - Tier 2 (Prosumer): "redis", "valkey", "dragonfly" (Redis-protocol compatible)
    /// - Tier 3 (Hyperscale): "scylladb" (distributed persistent cache)
    pub backend: String,

    /// Backend-specific configuration (key-value pairs passed to backend factory)
    /// Example for Redis: {"connection_string": "redis://localhost:6379", "pool_size": "5"}
    /// Example for ScyllaDB: {"nodes": "node1:9042,node2:9042", "keyspace": "jig_hot"}
    #[serde(default)]
    pub backend_config: std::collections::HashMap<String, String>,

    /// Fallback to in-memory if backend unavailable (Tier 2/3 only)
    #[serde(default)]
    pub fallback_to_memory: bool,
}

fn default_hot_backend() -> String {
    "memory".to_string()
}

impl Default for HotConfig {
    fn default() -> Self {
        Self {
            backend: default_hot_backend(),
            backend_config: std::collections::HashMap::new(),
            fallback_to_memory: true, // Safe default for Tier 2/3
        }
    }
}

impl HotConfig {
    fn from_env() -> Self {
        Self::default()
    }

    fn merge_env(&mut self) {
        if let Ok(val) = std::env::var("JIG_NS_HOT_BACKEND") {
            self.backend = val;
        }
        if let Ok(val) = std::env::var("JIG_NS_HOT_FALLBACK") {
            self.fallback_to_memory = val == "true" || val == "1";
        }
        // Backend-specific config can be set via JIG_NS_HOT_BACKEND_<KEY>
        // e.g., JIG_NS_HOT_BACKEND_CONNECTION_STRING=redis://localhost
    }
}

// from_env() implementations for anomaly detection configs
impl AnomalyDetectionConfig {
    fn from_env() -> Self {
        Self::default()
    }
}

impl FuelAnomalyConfig {
    #[allow(dead_code)]
    fn from_env() -> Self {
        Self::default()
    }
}

impl HardFailureConfig {
    #[allow(dead_code)]
    fn from_env() -> Self {
        Self::default()
    }
}

impl AutoEscalationConfig {
    #[allow(dead_code)]
    fn from_env() -> Self {
        Self::default()
    }
}

impl CrossValidationConfig {
    #[allow(dead_code)]
    fn from_env() -> Self {
        Self::default()
    }
}

fn split_domains(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
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

/// Empty when `JIG_NS_SECRET` is unset — deliberately NOT auto-generated and
/// deliberately not a panic. A `Default` impl runs during deserialization of
/// any config lacking `[pow].server_secret`, so panicking here killed the
/// process before `tracing` was ever consulted. The empty value is caught by
/// [`NameServerConfig::validate`]. Auto-generating would be worse: the secret
/// is security-relevant, and a fresh one per restart invalidates every
/// outstanding PoW challenge.
fn default_server_secret() -> String {
    std::env::var("JIG_NS_SECRET").unwrap_or_default()
}

fn default_base_pow() -> u16 {
    std::env::var("JIG_NS_POW_DIFFICULTY")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(18)
}

fn default_min_pow() -> u16 {
    std::env::var("JIG_NS_POW_MIN")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8)
}

fn default_max_pow() -> u16 {
    std::env::var("JIG_NS_POW_MAX")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(28)
}

fn default_per_key_limit() -> u32 {
    std::env::var("JIG_NS_RATE_PER_MIN")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(60)
}

fn default_per_ip_limit() -> u32 {
    std::env::var("JIG_NS_RATE_PER_IP_PER_MIN")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(120)
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

fn default_federation_cache_ttl() -> i64 {
    std::env::var("JIG_NS_CACHE_TTL")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(300)
}

fn default_transparency_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".jig")
            .join("nameserver")
            .join("transparency.log")
    } else {
        PathBuf::from("transparency.log")
    }
}

const TEMPLATE: &str = r#"
# Jig Nameserver configuration

[network]
bind = "0.0.0.0"
port = 7070
trust_proxy = false
proxy_ip_header = "x-forwarded-for"

[storage]
database_path = "~/.jig/nameserver.db"

# Truth backend selection (Tier 1: sqlite, Tier 2: postgres, Tier 3: cockroachdb/tidb)
backend = "sqlite"  # Default: Tier 1

# Backend-specific configuration (example for Postgres)
# [storage.backend_config]
# connection_string = "postgres://localhost/nameserver"
# pool_size = "10"
# max_connections = "20"

[pow]
server_secret = "replace-me"
base_difficulty = 18
min_difficulty = 8
max_difficulty = 28

[rate_limits]
per_key_per_min = 60
per_ip_per_min = 120

[penalties]
decay_secs = 300
step_bits = 2
max_points = 64

[anonymous]
enabled = true
min_difficulty = 16

[federation]
allow_domains = []
deny_domains = []
cache_ttl_secs = 300
gossip_interval_secs = 300

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

[transparency]
log_path = "~/.jig/nameserver/transparency.log"
publish_interval_secs = 3600

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
federation_enabled = false

[runtime]
enabled = false  # Phase E: Enable embedded WASM execution (opt-in)
fuel_max = 5_000_000
memory_max_mb = 32
execution_timeout_ms = 250
allowed_capabilities = [
  "storage.read:receipts:*",
  "storage.write:attestations:*",
  "net.fetch:federation:*"
]
deterministic = true
wasi_preview2 = true

[anomaly_detection]  # Phase D: Anomaly detection and cross-validation
enabled = true
max_network_fuel = 500_000

[anomaly_detection.fuel_anomaly]
enabled = true
excessive_threshold = 3.0  # Flag if fuel > 3x historical average
suspicious_threshold = 0.3  # Flag if fuel < 30% historical average
min_sample_size = 10

[anomaly_detection.hard_failure]
enabled = true
consecutive_threshold = 5  # Trigger alert after 5 consecutive failures
time_window_secs = 300  # 5 minutes

[anomaly_detection.auto_escalation]
enabled = true
severities = ["high", "critical"]

[anomaly_detection.auto_escalation.pow_penalties]
low = 0
medium = 2
high = 4
critical = 8

[anomaly_detection.cross_validation]
enabled = true
validation_timeout_secs = 5  # HTTP timeout for peer requests
max_validation_peers = 3  # Max peers to query
fuel_tolerance_pct = 5.0  # ±5% fuel variance allowed
consensus_threshold = 0.5  # >50% peers must agree
min_peers = 2  # Minimum 2 peers required

# Phase F: Analytics configuration
[analytics]
enabled = true
default_time_range = "last_day"  # Options: last_hour, last_day, last_week, last_month

# Analytics backend selection (Tier 1: sqlite, Tier 2: duckdb/parquet, Tier 3: clickhouse)
backend = "sqlite"  # Default: Tier 1

# Backend-specific configuration (example for DuckDB)
# [analytics.backend_config]
# database_path = "analytics.db"
# parquet_export_path = "/data/parquet"
# parquet_compression = "zstd"

# Phase F Tier 2/3: Hot state backend configuration
[hot]
backend = "memory"  # Default: Tier 1 in-memory
fallback_to_memory = true  # Fallback if Redis/ScyllaDB unavailable

# Backend-specific configuration (examples)
# For Redis/Valkey/DragonflyDB (Tier 2):
# [hot.backend_config]
# connection_string = "redis://localhost:6379"
# pool_size = "5"

# For ScyllaDB (Tier 3):
# [hot.backend_config]
# nodes = "node1:9042,node2:9042,node3:9042"
# keyspace = "jig_hot"

# v0.0.2 alias API — GET /v1/challenge, POST /v1/register,
# GET /v1/resolve/:alias, GET /v1/handles, POST /v1/rotate, POST /v1/renew.
# Same key names as a jig-server config (`JigServerConfig`).
[v0_0_2.nameserver]
# The suffix this nameserver is authoritative for: `<local>@<alias_suffix>`.
alias_suffix = "gigue.jig"

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
        // Set required env var for test environment. Edition 2024 makes
        // set_var unsafe; this test is single-threaded and runs once, so
        // the requirements (no concurrent env access from other threads)
        // are satisfied trivially.
        unsafe {
            std::env::set_var("JIG_NS_SECRET", "test-secret-for-unit-tests");
        }
        let cfg = NameServerConfig::from_env();
        assert!(!cfg.pow.server_secret.is_empty());
        assert!(cfg.pow.base_difficulty >= cfg.pow.min_difficulty);
        assert_eq!(cfg.network.port, default_port());
        assert!(cfg.reputation.local_rulesets.is_empty());
        assert!(cfg.reputation.translation_contracts.is_empty());
        assert!(cfg.useful_work.assignment_ttl_secs > 0);
        assert!(cfg.useful_work.max_queue_depth > 0);
    }

    #[test]
    fn compute_pow_respects_bounds() {
        unsafe {
            std::env::set_var("JIG_NS_SECRET", "test-secret-for-unit-tests");
        }
        let mut cfg = NameServerConfig::from_env();
        cfg.pow.base_difficulty = 18;
        cfg.pow.min_difficulty = 8;
        cfg.pow.max_difficulty = 28;
        cfg.penalties.step_bits = 3;
        cfg.automation.enabled = true;
        cfg.automation.max_multiplier = 4.0;
        let diff = cfg.compute_pow_difficulty(18, 10, ReputationZone::Low, None, None);
        assert!(diff >= cfg.pow.min_difficulty);
        assert!(diff <= cfg.pow.max_difficulty);
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

[nameserver.profiles.default.rate_limits]
per_key_per_min = 10

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
        assert_eq!(cfg.rate_limits.per_key_per_min, 10);
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
        let mut cfg = CapabilitiesConfig::default();
        cfg.domain = Some("ns.example.com".into());

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
federation_enabled = true
"#;
        let cfg: CapabilitiesConfig = toml::from_str(doc).unwrap();

        assert_eq!(cfg.version, "v2");
        assert_eq!(cfg.domain.as_deref(), Some("test.example.com"));
        assert_eq!(cfg.useful_work_types, vec!["custom"]);
        assert!(!cfg.tribunal_enabled);
        assert!(cfg.transparency_enabled);
        assert!(cfg.federation_enabled);
    }

    #[test]
    fn capabilities_in_full_config() {
        let cfg: NameServerConfig = toml::from_str(TEMPLATE).unwrap();
        assert_eq!(cfg.capabilities.version, "v1");
        assert!(cfg.capabilities.tribunal_enabled);
        assert!(cfg.capabilities.transparency_enabled);
        assert!(!cfg.capabilities.federation_enabled);
    }

    // --- startup validation -------------------------------------------------
    //
    // These two tests mutate JIG_NS_SECRET. Safe under `cargo nextest`, which
    // runs every test in its own process; they would race under `cargo test`'s
    // shared-process threads.

    #[test]
    fn missing_secret_yields_empty_default_instead_of_panicking() {
        unsafe {
            std::env::remove_var("JIG_NS_SECRET");
        }
        // A `Default` impl must never panic — the panic used to fire during
        // *deserialization* of any config lacking `[pow].server_secret`.
        let cfg = NameServerConfig::from_env();
        assert!(cfg.pow.server_secret.is_empty());

        let err = cfg
            .validate()
            .expect_err("empty server_secret must fail validation");
        let msg = err.to_string();
        assert!(
            msg.contains("JIG_NS_SECRET"),
            "operator-facing message must name the env var, got: {msg}"
        );
        assert!(
            msg.contains("openssl rand -hex 32"),
            "operator-facing message must keep the remediation hint, got: {msg}"
        );
    }

    #[test]
    fn configured_secret_passes_validation() {
        unsafe {
            std::env::set_var("JIG_NS_SECRET", "test-secret-for-unit-tests");
        }
        let cfg = NameServerConfig::from_env();
        cfg.validate().expect("a configured secret validates");
    }

    // --- [v0_0_2] alias-API section ----------------------------------------

    #[test]
    fn v0_0_2_alias_suffix_defaults_to_gigue_jig() {
        unsafe {
            std::env::set_var("JIG_NS_SECRET", "test-secret-for-unit-tests");
        }
        let cfg = NameServerConfig::from_env();
        assert_eq!(cfg.v0_0_2.nameserver.alias_suffix, "gigue.jig");
    }

    #[test]
    fn v0_0_2_alias_suffix_is_operator_settable() {
        let doc = r#"
[v0_0_2.nameserver]
alias_suffix = "dj.jig"

[v0_0_2.server]
server_did_keyfile = "/var/lib/jig-ns/ns.key"

[pow]
server_secret = "s"
"#;
        let cfg: NameServerConfig = toml::from_str(doc).expect("parses");
        assert_eq!(cfg.v0_0_2.nameserver.alias_suffix, "dj.jig");
        assert_eq!(
            cfg.v0_0_2.server.server_did_keyfile,
            "/var/lib/jig-ns/ns.key"
        );
        cfg.validate().expect("valid");
    }

    #[test]
    fn validate_rejects_a_malformed_alias_suffix() {
        let doc = r#"
[v0_0_2.nameserver]
alias_suffix = "dj@dj.jig"

[pow]
server_secret = "s"
"#;
        let cfg: NameServerConfig = toml::from_str(doc).expect("parses");
        let err = cfg.validate().expect_err("'@' in a suffix must be caught");
        assert!(err.to_string().contains("alias_suffix"));
    }
}
