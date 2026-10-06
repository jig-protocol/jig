//! Execution constraints and runtime configuration for symmetric block execution.
//!
//! These settings ensure identical runtime behavior across server, CLI, and GUI
//! per the block execution model in `jig-spec` (`block-execution.md`). All
//! runtimes must honor these constraints to maintain deterministic execution
//! and reproducible receipts.
//!
//! ## Design Principles
//!
//! 1. **Symmetric execution**: Same limits on server/CLI/GUI → same receipts
//! 2. **Determinism by default**: Strict validation unless explicitly relaxed
//! 3. **Profile-driven**: Potato has tighter limits than Hyperscale
//! 4. **Explicit escape hatches**: Relaxing constraints requires config opt-in
//!
//! ## Module Structure
//!
//! - `ExecutionConstraints`: Fuel/memory/timeout limits per profile
//! - `DeterminismConfig`: Float policy, PRNG, import restrictions
//! - `CapabilityConfig`: Default grants, scope patterns, rate limits
//! - `RuntimeConfig`: Aggregator bundling all runtime settings

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::profiles::Profile;

/// Execution constraints enforced by the Wasm runtime.
///
/// These limits are snapshotted into receipts (`limits` field) so auditors
/// can verify blocks executed under expected policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionConstraints {
    /// Maximum fuel budget per block execution.
    ///
    /// Fuel meters computational cost (instructions executed).
    /// Exhaustion results in graceful termination with diagnostic receipt.
    ///
    /// **Profile defaults:**
    /// - Potato: 1,000,000
    /// - Standard: 5,000,000
    /// - Hyperscale: 50,000,000
    pub fuel_max: u64,

    /// Maximum linear memory size in megabytes.
    ///
    /// Blocks requesting more memory are rejected at validation.
    /// Enforces deterministic memory behavior and prevents DOS.
    ///
    /// **Profile defaults:**
    /// - Potato: 32 MB
    /// - Standard: 64 MB
    /// - Hyperscale: 256 MB
    pub memory_max_mb: u32,

    /// Maximum execution time in milliseconds (wall-clock).
    ///
    /// Host-layer timeout. Differentiate CPU-bound vs blocked I/O:
    /// capability calls may extend deadline for long-running network ops.
    ///
    /// **Profile defaults:**
    /// - Potato: 250 ms
    /// - Standard: 500 ms
    /// - Hyperscale: 2000 ms
    pub execution_timeout_ms: u32,

    /// Require deterministic execution (strict validation).
    ///
    /// When true (default), runtime rejects:
    /// - Float instructions (unless explicitly allowed)
    /// - Non-allowlisted imports (clock, random, sockets)
    /// - Unbounded memory/table growth
    ///
    /// Set to false only for testing/debugging non-production blocks.
    #[serde(default = "default_deterministic")]
    pub deterministic: bool,

    /// Import allowlist for deterministic execution.
    ///
    /// Only imports matching these patterns are permitted.
    /// Empty list = deny all imports (pure computation only).
    ///
    /// **Common patterns:**
    /// - `"jig_host::*"` - All Jig host APIs
    /// - `"jig_host::net::fetch"` - Specific capability
    /// - `"env::*"` - Environment queries (read-only)
    ///
    /// Forbidden imports (always denied):
    /// - `wasi_snapshot_preview1::random_get`
    /// - `wasi_snapshot_preview1::clock_time_get`
    /// - `wasi_snapshot_preview1::sock_*`
    #[serde(default)]
    pub import_allowlist: Vec<String>,
}

fn default_deterministic() -> bool {
    true
}

impl Default for ExecutionConstraints {
    fn default() -> Self {
        Self::default_for_profile(Profile::default())
    }
}

impl ExecutionConstraints {
    /// Get default execution constraints for a given profile.
    ///
    /// Profiles cascade: Standard inherits Potato with increased limits,
    /// Hyperscale inherits Standard with further increases.
    pub fn default_for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Potato => Self::potato(),
            Profile::Standard => Self::standard(),
            Profile::Hyperscale => Self::hyperscale(),
            Profile::Custom => Self::custom(),
        }
    }

    /// Potato profile: tight limits for quick, safe experimentation.
    ///
    /// - 1M fuel (enough for simple transforms, ~100K instructions)
    /// - 32 MB memory (2 pages, minimal Wasm module size)
    /// - 250ms timeout (interactive latency target)
    /// - Strict determinism (no floats, no ambient authority)
    pub fn potato() -> Self {
        Self {
            fuel_max: 1_000_000,
            memory_max_mb: 32,
            execution_timeout_ms: 250,
            deterministic: true,
            import_allowlist: vec![
                "jig_host::*".to_string(),
                "env::get".to_string(), // Read-only env queries
            ],
        }
    }

    /// Standard profile: increased limits for production workloads.
    ///
    /// - 5M fuel (5x Potato, handles moderate transforms)
    /// - 64 MB memory (2x Potato, room for intermediate state)
    /// - 500ms timeout (2x Potato, allows slower I/O)
    /// - Strict determinism (same validation as Potato)
    pub fn standard() -> Self {
        Self {
            fuel_max: 5_000_000,
            memory_max_mb: 64,
            execution_timeout_ms: 500,
            deterministic: true,
            import_allowlist: vec!["jig_host::*".to_string(), "env::get".to_string()],
        }
    }

    /// Hyperscale profile: relaxed limits for high-throughput federation.
    ///
    /// - 50M fuel (10x Standard, handles complex workflows)
    /// - 256 MB memory (4x Standard, large data structures)
    /// - 2000ms timeout (4x Standard, multi-hop federation)
    /// - Strict determinism (consistent with lower tiers)
    pub fn hyperscale() -> Self {
        Self {
            fuel_max: 50_000_000,
            memory_max_mb: 256,
            execution_timeout_ms: 2000,
            deterministic: true,
            import_allowlist: vec!["jig_host::*".to_string(), "env::get".to_string()],
        }
    }

    /// Custom profile: conservative defaults, user must configure.
    ///
    /// Starts with Standard-like limits but requires explicit config
    /// for any deviations (including relaxed determinism).
    pub fn custom() -> Self {
        Self {
            fuel_max: 5_000_000,
            memory_max_mb: 64,
            execution_timeout_ms: 500,
            deterministic: true,
            import_allowlist: vec![], // Deny all imports by default
        }
    }

    /// Validate constraints are within acceptable bounds.
    ///
    /// Returns Err if constraints would allow unsafe or impractical execution.
    pub fn validate(&self) -> Result<(), String> {
        if self.fuel_max == 0 {
            return Err("fuel_max must be > 0".to_string());
        }

        if self.memory_max_mb == 0 {
            return Err("memory_max_mb must be > 0".to_string());
        }

        if self.memory_max_mb > 1024 {
            return Err("memory_max_mb exceeds reasonable limit (1024 MB)".to_string());
        }

        if self.execution_timeout_ms == 0 {
            return Err("execution_timeout_ms must be > 0".to_string());
        }

        if self.execution_timeout_ms > 60_000 {
            return Err("execution_timeout_ms exceeds reasonable limit (60s)".to_string());
        }

        Ok(())
    }

    /// Merge another ExecutionConstraints into this one.
    ///
    /// Non-zero/non-empty fields from `other` override this config.
    /// Used for profile inheritance and user overrides.
    pub fn merge(&mut self, other: &ExecutionConstraints) {
        if other.fuel_max != 0 {
            self.fuel_max = other.fuel_max;
        }
        if other.memory_max_mb != 0 {
            self.memory_max_mb = other.memory_max_mb;
        }
        if other.execution_timeout_ms != 0 {
            self.execution_timeout_ms = other.execution_timeout_ms;
        }
        // deterministic always overrides (explicit bool)
        self.deterministic = other.deterministic;

        if !other.import_allowlist.is_empty() {
            self.import_allowlist = other.import_allowlist.clone();
        }
    }
}

/// Determinism configuration for Wasm validation and execution.
///
/// Controls how strictly the runtime enforces deterministic behavior.
/// All profiles default to strict enforcement; relaxation requires explicit config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterminismConfig {
    /// Float instruction policy.
    ///
    /// - `Deny` (default): Reject modules with float instructions
    /// - `Deterministic`: Allow floats with Wasmtime deterministic mode
    /// - `Allow`: Permit non-deterministic floats (testing only)
    #[serde(default)]
    pub float_policy: FloatPolicy,

    /// PRNG seed source for deterministic randomness.
    ///
    /// Blocks needing randomness get a deterministic PRNG seeded from:
    /// - `Manifest` (default): Seed derived from block manifest fields
    /// - `Host`: Seed provided by host (still deterministic, same seed → same output)
    /// - `Mixed`: Combination of manifest + host entropy
    ///
    /// **Never** `Random`: that would break determinism.
    #[serde(default)]
    pub prng_seed_source: PrngSeedSource,

    /// Forbidden imports that are always denied regardless of allowlist.
    ///
    /// These imports break determinism and are blocked even if allowlisted:
    /// - `wasi_snapshot_preview1::random_get`
    /// - `wasi_snapshot_preview1::clock_time_get`
    /// - `wasi_snapshot_preview1::sock_*`
    ///
    /// Hosts should deny these at validation time with clear error messages.
    #[serde(default = "default_forbidden_imports")]
    pub forbidden_imports: Vec<String>,
}

fn default_forbidden_imports() -> Vec<String> {
    vec![
        "wasi_snapshot_preview1::random_get".to_string(),
        "wasi_snapshot_preview1::clock_time_get".to_string(),
        "wasi_snapshot_preview1::clock_res_get".to_string(),
        "wasi_snapshot_preview1::sock_accept".to_string(),
        "wasi_snapshot_preview1::sock_recv".to_string(),
        "wasi_snapshot_preview1::sock_send".to_string(),
    ]
}

impl Default for DeterminismConfig {
    fn default() -> Self {
        Self {
            float_policy: FloatPolicy::Deny,
            prng_seed_source: PrngSeedSource::Manifest,
            forbidden_imports: default_forbidden_imports(),
        }
    }
}

/// Float instruction policy for deterministic execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum FloatPolicy {
    /// Deny all float instructions (strictest, default).
    #[default]
    Deny,

    /// Allow floats with Wasmtime deterministic mode.
    ///
    /// Requires Wasmtime configuration flags:
    /// - `Config::wasm_deterministic_instructions(true)`
    ///
    /// Still deterministic but allows float ops for numeric workloads.
    Deterministic,

    /// Allow non-deterministic floats (testing/debugging only).
    ///
    /// **WARNING**: Breaks receipt reproducibility. Use only for:
    /// - Local testing with `jig-cli`
    /// - Debugging numeric algorithms
    /// - Never in production or federated contexts
    Allow,
}

/// PRNG seed source for deterministic randomness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PrngSeedSource {
    /// Seed derived from block manifest (block_id, author, timestamp).
    ///
    /// Same manifest → same seed → same random sequence.
    /// Guarantees deterministic replays.
    #[default]
    Manifest,

    /// Seed provided by host at execution time.
    ///
    /// Host passes seed via capability token. Still deterministic:
    /// same seed → same output. Useful for testing with controlled entropy.
    Host,

    /// Combined manifest + host entropy.
    ///
    /// XOR manifest-derived seed with host-provided seed.
    /// Adds flexibility while maintaining determinism.
    Mixed,
}

/// Capability configuration for runtime enforcement.
///
/// Defines which capabilities blocks can request and how hosts validate grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityConfig {
    /// Default capability grants (ambient authority).
    ///
    /// Empty by default (zero ambient authority).
    /// Add capabilities here to grant all blocks without manifest request:
    /// - `env::get` - Read-only environment queries
    /// - `log::*` - Logging to host (no sensitive data)
    ///
    /// **Use sparingly**: Most capabilities should require explicit manifest request.
    #[serde(default)]
    pub default_grants: Vec<String>,

    /// Scope pattern syntax for capability matching.
    ///
    /// - `Glob` (default): Unix-style globs (`jig_host::*`, `net::fetch:https://*.example.com/*`)
    /// - `Regex`: Full regex (more powerful but harder to audit)
    ///
    /// Recommendation: Use Glob unless you need complex patterns.
    #[serde(default)]
    pub scope_pattern_syntax: ScopePatternSyntax,

    /// Global rate limit for capability calls (requests/second).
    ///
    /// Applies across all capabilities to prevent DOS.
    /// Per-capability limits can be set via capability-specific config.
    ///
    /// **Profile defaults:**
    /// - Potato: 100 req/s
    /// - Standard: 1000 req/s
    /// - Hyperscale: 10000 req/s
    #[serde(default)]
    pub rate_limit_global: Option<u32>,

    /// Per-capability rate limits (capability_name → limit).
    ///
    /// Example:
    /// ```toml
    /// [runtime.capabilities.rate_limits]
    /// "net.fetch" = 100
    /// "crypto.sign" = 1000
    /// ```
    #[serde(default)]
    pub rate_limits: HashMap<String, u32>,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            default_grants: vec![],
            scope_pattern_syntax: ScopePatternSyntax::Glob,
            rate_limit_global: None,
            rate_limits: HashMap::new(),
        }
    }
}

impl CapabilityConfig {
    /// Get default capability config for a profile.
    pub fn default_for_profile(profile: Profile) -> Self {
        let rate_limit_global = match profile {
            Profile::Potato => Some(100),
            Profile::Standard => Some(1000),
            Profile::Hyperscale => Some(10_000),
            Profile::Custom => None,
        };

        Self {
            default_grants: vec![],
            scope_pattern_syntax: ScopePatternSyntax::Glob,
            rate_limit_global,
            rate_limits: HashMap::new(),
        }
    }
}

/// Scope pattern syntax for capability matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum ScopePatternSyntax {
    /// Unix-style glob patterns (default).
    ///
    /// - `*` matches any sequence within a segment
    /// - `**` matches across segments (if supported)
    /// - `?` matches single character
    ///
    /// Examples:
    /// - `https://*.example.com/*` - Any subdomain of example.com
    /// - `jig_host::net::*` - All network capabilities
    #[default]
    Glob,

    /// Full regex patterns.
    ///
    /// More powerful but harder to audit. Use only when glob patterns insufficient.
    Regex,
}

/// Aggregated runtime configuration bundling all execution settings.
///
/// This is the top-level runtime config consumed by jig-server, jig-cli, and jig-runtime.
/// Combines execution constraints, determinism rules, and capability grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Execution constraints (fuel, memory, timeout).
    #[serde(default)]
    pub constraints: ExecutionConstraints,

    /// Determinism configuration (float policy, PRNG, forbidden imports).
    #[serde(default)]
    pub determinism: DeterminismConfig,

    /// Capability configuration (grants, scopes, rate limits).
    #[serde(default)]
    pub capabilities: CapabilityConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::default_for_profile(Profile::default())
    }
}

impl RuntimeConfig {
    /// Get default runtime config for a profile.
    ///
    /// Combines profile-specific constraints, determinism defaults, and capability limits.
    pub fn default_for_profile(profile: Profile) -> Self {
        Self {
            constraints: ExecutionConstraints::default_for_profile(profile),
            determinism: DeterminismConfig::default(),
            capabilities: CapabilityConfig::default_for_profile(profile),
        }
    }

    /// Validate the entire runtime configuration.
    ///
    /// Checks constraints, determinism settings, and capability config for consistency.
    pub fn validate(&self) -> Result<(), String> {
        // Validate constraints
        self.constraints.validate()?;

        // Validate float policy compatibility
        if matches!(self.determinism.float_policy, FloatPolicy::Allow)
            && self.constraints.deterministic
        {
            return Err(
                "float_policy='allow' conflicts with deterministic=true in constraints".to_string(),
            );
        }

        // Validate rate limits are non-zero
        for (cap, limit) in &self.capabilities.rate_limits {
            if *limit == 0 {
                return Err(format!("rate limit for '{cap}' must be > 0"));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_potato() {
        let default = ExecutionConstraints::default();
        let potato = ExecutionConstraints::potato();
        assert_eq!(default, potato);
    }

    #[test]
    fn test_profile_constraints_escalate() {
        let potato = ExecutionConstraints::potato();
        let standard = ExecutionConstraints::standard();
        let hyperscale = ExecutionConstraints::hyperscale();

        // Fuel escalates
        assert!(potato.fuel_max < standard.fuel_max);
        assert!(standard.fuel_max < hyperscale.fuel_max);

        // Memory escalates
        assert!(potato.memory_max_mb < standard.memory_max_mb);
        assert!(standard.memory_max_mb < hyperscale.memory_max_mb);

        // Timeout escalates
        assert!(potato.execution_timeout_ms < standard.execution_timeout_ms);
        assert!(standard.execution_timeout_ms < hyperscale.execution_timeout_ms);

        // All maintain determinism
        assert!(potato.deterministic);
        assert!(standard.deterministic);
        assert!(hyperscale.deterministic);
    }

    #[test]
    fn test_default_for_profile() {
        assert_eq!(
            ExecutionConstraints::default_for_profile(Profile::Potato),
            ExecutionConstraints::potato()
        );
        assert_eq!(
            ExecutionConstraints::default_for_profile(Profile::Standard),
            ExecutionConstraints::standard()
        );
        assert_eq!(
            ExecutionConstraints::default_for_profile(Profile::Hyperscale),
            ExecutionConstraints::hyperscale()
        );
    }

    #[test]
    fn test_validation() {
        let valid = ExecutionConstraints::potato();
        assert!(valid.validate().is_ok());

        // Zero fuel
        let mut invalid = valid.clone();
        invalid.fuel_max = 0;
        assert!(invalid.validate().is_err());

        // Zero memory
        let mut invalid = valid.clone();
        invalid.memory_max_mb = 0;
        assert!(invalid.validate().is_err());

        // Excessive memory
        let mut invalid = valid.clone();
        invalid.memory_max_mb = 2048;
        assert!(invalid.validate().is_err());

        // Zero timeout
        let mut invalid = valid.clone();
        invalid.execution_timeout_ms = 0;
        assert!(invalid.validate().is_err());

        // Excessive timeout
        let mut invalid = valid.clone();
        invalid.execution_timeout_ms = 120_000;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_merge() {
        let mut base = ExecutionConstraints::potato();
        let override_constraints = ExecutionConstraints {
            fuel_max: 10_000_000,
            memory_max_mb: 128,
            execution_timeout_ms: 0, // Should not override (zero sentinel)
            deterministic: false,    // Should override (explicit bool)
            import_allowlist: vec!["custom::*".to_string()],
        };

        base.merge(&override_constraints);

        assert_eq!(base.fuel_max, 10_000_000);
        assert_eq!(base.memory_max_mb, 128);
        assert_eq!(base.execution_timeout_ms, 250); // Original preserved
        assert!(!base.deterministic);
        assert_eq!(base.import_allowlist, vec!["custom::*".to_string()]);
    }

    #[test]
    fn test_custom_profile_deny_all_imports() {
        let custom = ExecutionConstraints::custom();
        assert!(custom.import_allowlist.is_empty());
    }

    #[test]
    fn test_serde_roundtrip() {
        let constraints = ExecutionConstraints::standard();
        let json = serde_json::to_string(&constraints).unwrap();
        let deserialized: ExecutionConstraints = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, constraints);
    }

    // DeterminismConfig tests
    #[test]
    fn test_determinism_config_defaults() {
        let config = DeterminismConfig::default();
        assert_eq!(config.float_policy, FloatPolicy::Deny);
        assert_eq!(config.prng_seed_source, PrngSeedSource::Manifest);
        assert!(!config.forbidden_imports.is_empty());
    }

    #[test]
    fn test_float_policy_serialization() {
        assert_eq!(
            serde_json::to_string(&FloatPolicy::Deny).unwrap(),
            "\"deny\""
        );
        assert_eq!(
            serde_json::to_string(&FloatPolicy::Deterministic).unwrap(),
            "\"deterministic\""
        );
        assert_eq!(
            serde_json::to_string(&FloatPolicy::Allow).unwrap(),
            "\"allow\""
        );
    }

    #[test]
    fn test_prng_seed_source_serialization() {
        assert_eq!(
            serde_json::to_string(&PrngSeedSource::Manifest).unwrap(),
            "\"manifest\""
        );
        assert_eq!(
            serde_json::to_string(&PrngSeedSource::Host).unwrap(),
            "\"host\""
        );
        assert_eq!(
            serde_json::to_string(&PrngSeedSource::Mixed).unwrap(),
            "\"mixed\""
        );
    }

    #[test]
    fn test_forbidden_imports_include_wasi() {
        let config = DeterminismConfig::default();
        assert!(
            config
                .forbidden_imports
                .contains(&"wasi_snapshot_preview1::random_get".to_string())
        );
        assert!(
            config
                .forbidden_imports
                .contains(&"wasi_snapshot_preview1::clock_time_get".to_string())
        );
        assert!(
            config
                .forbidden_imports
                .contains(&"wasi_snapshot_preview1::sock_accept".to_string())
        );
    }

    // CapabilityConfig tests
    #[test]
    fn test_capability_config_defaults() {
        let config = CapabilityConfig::default();
        assert!(config.default_grants.is_empty());
        assert_eq!(config.scope_pattern_syntax, ScopePatternSyntax::Glob);
        assert_eq!(config.rate_limit_global, None);
        assert!(config.rate_limits.is_empty());
    }

    #[test]
    fn test_capability_config_profile_scaling() {
        let potato = CapabilityConfig::default_for_profile(Profile::Potato);
        let standard = CapabilityConfig::default_for_profile(Profile::Standard);
        let hyperscale = CapabilityConfig::default_for_profile(Profile::Hyperscale);

        assert_eq!(potato.rate_limit_global, Some(100));
        assert_eq!(standard.rate_limit_global, Some(1000));
        assert_eq!(hyperscale.rate_limit_global, Some(10_000));

        // All use glob by default
        assert_eq!(potato.scope_pattern_syntax, ScopePatternSyntax::Glob);
        assert_eq!(standard.scope_pattern_syntax, ScopePatternSyntax::Glob);
        assert_eq!(hyperscale.scope_pattern_syntax, ScopePatternSyntax::Glob);
    }

    #[test]
    fn test_capability_config_zero_ambient_authority() {
        let profiles = [
            Profile::Potato,
            Profile::Standard,
            Profile::Hyperscale,
            Profile::Custom,
        ];

        for profile in profiles {
            let config = CapabilityConfig::default_for_profile(profile);
            assert!(
                config.default_grants.is_empty(),
                "Profile {profile:?} should have zero ambient authority"
            );
        }
    }

    // RuntimeConfig tests
    #[test]
    fn test_runtime_config_aggregates_all_settings() {
        let config = RuntimeConfig::default_for_profile(Profile::Standard);

        // Has constraints
        assert_eq!(config.constraints.fuel_max, 5_000_000);
        assert_eq!(config.constraints.memory_max_mb, 64);

        // Has determinism config
        assert_eq!(config.determinism.float_policy, FloatPolicy::Deny);
        assert_eq!(
            config.determinism.prng_seed_source,
            PrngSeedSource::Manifest
        );

        // Has capability config
        assert_eq!(config.capabilities.rate_limit_global, Some(1000));
    }

    #[test]
    fn test_runtime_config_validation_detects_conflicts() {
        let mut config = RuntimeConfig::default_for_profile(Profile::Potato);

        // Valid config
        assert!(config.validate().is_ok());

        // Float policy conflict: Allow + deterministic=true
        config.determinism.float_policy = FloatPolicy::Allow;
        config.constraints.deterministic = true;
        assert!(config.validate().is_err());

        // Fix conflict
        config.determinism.float_policy = FloatPolicy::Deny;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_runtime_config_validation_rejects_zero_rate_limits() {
        let mut config = RuntimeConfig::default_for_profile(Profile::Potato);
        config
            .capabilities
            .rate_limits
            .insert("net.fetch".to_string(), 0);

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("rate limit"));
    }

    #[test]
    fn test_runtime_config_validation_accepts_nonzero_rate_limits() {
        let mut config = RuntimeConfig::default_for_profile(Profile::Potato);
        config
            .capabilities
            .rate_limits
            .insert("net.fetch".to_string(), 100);
        config
            .capabilities
            .rate_limits
            .insert("crypto.sign".to_string(), 1000);

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_runtime_config_serde_roundtrip() {
        let config = RuntimeConfig::default_for_profile(Profile::Hyperscale);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RuntimeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, config);
    }
}
