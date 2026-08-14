use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::{Result, RuntimeError};

/// Complete runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct RuntimeConfig {
    /// Resource limits for execution
    pub limits: ResourceLimits,

    /// Capability allowlist and quotas
    pub capabilities: CapabilityConfig,

    /// Fuel metering configuration
    pub fuel: FuelConfig,

    /// Engine-specific settings
    pub engine: EngineConfig,

    /// Pricing configuration (optional)
    pub pricing: PricingConfig,
}

impl RuntimeConfig {
    /// Load configuration from a TOML file
    pub fn from_toml_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml_str(&content)
    }

    /// Parse configuration from TOML string
    pub fn from_toml_str(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(RuntimeError::from)
    }

    /// Parse configuration from JSON string
    pub fn from_json_str(content: &str) -> Result<Self> {
        serde_json::from_str(content).map_err(RuntimeError::from)
    }

    /// Apply environment variable overrides
    ///
    /// Supported environment variables:
    /// - `JIG_RUNTIME_FUEL_MAX`: Override fuel_max
    /// - `JIG_RUNTIME_MEMORY_MAX_MB`: Override memory_max_mb
    /// - `JIG_RUNTIME_TIMEOUT_MS`: Override execution_timeout_ms
    pub fn with_env_overrides(mut self) -> Self {
        if let Ok(val) = std::env::var("JIG_RUNTIME_FUEL_MAX")
            && let Ok(fuel) = val.parse()
        {
            self.limits.fuel_max = fuel;
        }
        if let Ok(val) = std::env::var("JIG_RUNTIME_MEMORY_MAX_MB")
            && let Ok(mem) = val.parse()
        {
            self.limits.memory_max_mb = mem;
        }
        if let Ok(val) = std::env::var("JIG_RUNTIME_TIMEOUT_MS")
            && let Ok(timeout) = val.parse()
        {
            self.limits.execution_timeout_ms = timeout;
        }
        self
    }

    /// Validate configuration for consistency
    pub fn validate(&self) -> Result<()> {
        if self.limits.fuel_max == 0 {
            return Err(RuntimeError::InvalidConfig(
                "fuel_max must be greater than 0".into(),
            ));
        }
        if self.limits.memory_max_mb == 0 {
            return Err(RuntimeError::InvalidConfig(
                "memory_max_mb must be greater than 0".into(),
            ));
        }
        // Rejected rather than clamped. Callers used to `.max(1)` it, so an
        // operator asking for 0 silently got serialized execution — a
        // configuration they did not request and were never told about.
        if self.limits.max_concurrent_instances == 0 {
            return Err(RuntimeError::InvalidConfig(
                "max_concurrent_instances must be greater than 0 (it is the number \
                 of executions allowed at once; 0 would permit none)"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Resource limits for WASM execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceLimits {
    /// Maximum fuel budget (instructions)
    pub fuel_max: u64,

    /// Maximum linear memory in MB
    pub memory_max_mb: u32,

    /// Wall-clock execution timeout in milliseconds
    pub execution_timeout_ms: u64,

    /// Maximum instances a SINGLE execution may create. One, always, for the
    /// byte-payload convention: a block gets one instance per invocation.
    ///
    /// Not to be confused with [`ResourceLimits::max_concurrent_instances`],
    /// which bounds how many executions can be in flight at once. Conflating the
    /// two capped the whole process at one concurrent execution — see that field.
    pub max_instances: u32,

    /// How many executions may be in flight simultaneously, process-wide per
    /// engine.
    ///
    /// This sizes wasmtime's pooling allocator (`total_core_instances` /
    /// `total_memories`). Exceeding it does not queue — instantiation fails with
    /// "maximum concurrent limit of N for core instances reached", so a server
    /// under concurrent load drops messages rather than slowing down. Callers on
    /// a hot path should bound their own concurrency to this number; jig-pipeline's
    /// `BlockExecutor` does exactly that.
    ///
    /// Costs address space, not resident memory: the pool reserves
    /// `max_concurrent_instances * memory_max_mb` of virtual address space, which
    /// pages in only as guests touch it. The default of 16 is 512 MB of
    /// reservation at the default 32 MB limit — fine on 64-bit, including the
    /// $5-VPS and Raspberry Pi targets, while leaving real headroom over the
    /// single-execution cap this replaced.
    pub max_concurrent_instances: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            fuel_max: 5_000_000,          // 5M instructions
            memory_max_mb: 32,            // 32MB
            execution_timeout_ms: 250,    // 250ms
            max_instances: 1,             // one instance per execution
            max_concurrent_instances: 16, // 16 executions in flight
        }
    }
}

/// Capability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CapabilityConfig {
    /// Explicitly allowed capabilities (canonical names)
    pub allowed: Vec<String>,

    /// Per-capability quotas (optional)
    pub quotas: HashMap<String, CapabilityQuota>,

    /// Optional map of scopes supported by this host; used to validate usage keys.
    #[serde(default)]
    pub scope_policies: HashMap<String, Vec<String>>,

    /// Deny all capabilities by default
    pub deny_by_default: bool,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            allowed: vec![],
            quotas: HashMap::new(),
            scope_policies: HashMap::new(),
            deny_by_default: true,
        }
    }
}

/// Quota limits for a specific capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityQuota {
    /// Maximum calls per execution
    pub max_calls: Option<u32>,

    /// Maximum bytes transferred (in/out)
    pub max_bytes: Option<u64>,

    /// Capability-specific fuel allocation
    pub fuel_allocation: Option<u64>,
}

/// Fuel metering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FuelConfig {
    /// Enable instruction-level fuel metering
    pub enabled: bool,

    /// Path to cost schedule file (TOML)
    pub cost_schedule_path: Option<String>,

    /// Default fuel costs for hostcalls (if no schedule provided)
    pub default_hostcall_costs: HashMap<String, u64>,
}

impl Default for FuelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cost_schedule_path: None,
            default_hostcall_costs: HashMap::new(),
        }
    }
}

/// Pricing configuration for cost calculations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PricingConfig {
    /// Enable pricing calculations in receipts
    pub enabled: bool,

    /// Cost per fuel unit
    pub cost_per_fuel_unit: f64,

    /// Currency or unit (e.g., "USD", "tokens", "credits")
    pub currency: Option<String>,

    /// Cost schedule version to use.
    ///
    /// Bump this whenever the fuel a given operation costs changes, not just
    /// when `cost_per_fuel_unit` changes: receipts carry this string, and it is
    /// the only signal a consumer has that two receipts were metered under
    /// different rules and are therefore not cost-comparable.
    ///
    /// 0.1.0 -> 0.2.0: wasmtime 47 bills bulk memory operations (`memory.copy`,
    /// `memory.fill`) per byte where 24.x charged a flat rate. Per-operator
    /// costs for ordinary compute are unchanged. A block doing large memcpys is
    /// materially more expensive under 0.2.0 — the WASI reference fixture went
    /// from 1713 to 18098 fuel, all of it the 16 KiB memcpy in `_start`. This
    /// is the metering half of the fix for RUSTSEC-2026-0223.
    pub schedule_version: String,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            enabled: false,               // Disabled by default
            cost_per_fuel_unit: 0.000001, // 1 micro-unit per fuel
            currency: None,
            schedule_version: "0.2.0".to_string(),
        }
    }
}

/// Wasmtime engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    /// Enable deterministic execution
    pub deterministic: bool,

    /// Canonicalize NaN values
    pub canonicalize_nans: bool,

    /// Enable WASI preview2
    pub wasi_preview2: bool,

    /// Enable component model
    pub component_model: bool,

    /// Enable module caching (ensure determinism is preserved)
    pub enable_cache: bool,

    /// Cache directory path
    pub cache_dir: Option<String>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            deterministic: true,
            canonicalize_nans: true,
            wasi_preview2: true,
            component_model: false, // Opt-in for now
            enable_cache: false,    // Disabled by default for safety
            cache_dir: None,
        }
    }
}

#[cfg(test)]
mod tests {
    /// Zero concurrency is rejected, not clamped.
    ///
    /// Callers `.max(1)` this value, so before validation an operator writing
    /// `max_concurrent_executions = 0` silently got serialized execution — a
    /// configuration they never asked for and were never told about. Rejecting
    /// makes the mistake visible at startup.
    #[test]
    fn zero_concurrency_is_rejected_rather_than_silently_clamped() {
        let mut config = RuntimeConfig::default();
        config.limits.max_concurrent_instances = 0;

        let err = config
            .validate()
            .expect_err("zero concurrent instances must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("max_concurrent_instances"),
            "the error must name the offending key, got: {msg}"
        );

        // And a sane value still validates, so the check is not simply refusing
        // everything.
        config.limits.max_concurrent_instances = 1;
        config.validate().expect("one concurrent instance is valid");
    }

    use super::*;

    #[test]
    fn test_default_config() {
        let config = RuntimeConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.limits.fuel_max, 5_000_000);
        assert!(config.capabilities.deny_by_default);
        assert!(config.fuel.enabled);
        assert!(config.engine.deterministic);
    }

    #[test]
    fn test_toml_parse() {
        let toml = r#"
            [limits]
            fuel_max = 1000000
            memory_max_mb = 16

            [capabilities]
            allowed = ["http", "kv"]
            deny_by_default = true

            [fuel]
            enabled = true

            [engine]
            deterministic = true
        "#;

        let config = RuntimeConfig::from_toml_str(toml).unwrap();
        assert_eq!(config.limits.fuel_max, 1_000_000);
        assert_eq!(config.limits.memory_max_mb, 16);
        assert_eq!(config.capabilities.allowed.len(), 2);
    }

    #[test]
    fn test_validation() {
        let mut config = RuntimeConfig::default();
        assert!(config.validate().is_ok());

        config.limits.fuel_max = 0;
        assert!(config.validate().is_err());
    }
}
