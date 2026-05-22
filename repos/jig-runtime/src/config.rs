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

    /// Maximum number of instances (for future multi-instance support)
    pub max_instances: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            fuel_max: 5_000_000,       // 5M instructions
            memory_max_mb: 32,         // 32MB
            execution_timeout_ms: 250, // 250ms
            max_instances: 1,          // Single instance for now
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

    /// Cost schedule version to use
    pub schedule_version: String,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            enabled: false,               // Disabled by default
            cost_per_fuel_unit: 0.000001, // 1 micro-unit per fuel
            currency: None,
            schedule_version: "0.1.0".to_string(),
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
