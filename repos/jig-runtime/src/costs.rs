//! Fuel cost schedules and pricing
//!
//! This module defines versioned cost schedules that map WASM instructions
//! and hostcalls to fuel units, enabling reproducible pricing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "tracing")]
use tracing::{debug, info};

use crate::error::{Result, RuntimeError};

/// Versioned fuel cost schedule
///
/// Defines the cost in fuel units for WASM instructions and hostcalls.
/// Schedules are versioned to ensure pricing stability and reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSchedule {
    /// Schedule version (semver)
    pub version: String,

    /// Description of this schedule
    #[serde(default)]
    pub description: String,

    /// Base instruction costs
    pub instruction_costs: InstructionCosts,

    /// Per-capability hostcall costs
    #[serde(default)]
    pub capability_costs: HashMap<String, CapabilityCosts>,
}

/// WASM instruction base costs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionCosts {
    /// Fuel per WASM instruction (baseline)
    #[serde(default = "default_instruction_fuel")]
    pub wasm_instruction_base: u64,

    /// Additional cost for memory operations
    #[serde(default)]
    pub memory_load: u64,

    /// Additional cost for memory stores
    #[serde(default)]
    pub memory_store: u64,

    /// Additional cost for function calls
    #[serde(default)]
    pub call: u64,

    /// Additional cost for branches
    #[serde(default)]
    pub branch: u64,
}

fn default_instruction_fuel() -> u64 {
    1
}

impl Default for InstructionCosts {
    fn default() -> Self {
        Self {
            wasm_instruction_base: 1,
            memory_load: 1,
            memory_store: 2,
            call: 10,
            branch: 1,
        }
    }
}

/// Costs for a specific capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCosts {
    /// Base cost per call to this capability
    pub call_base: u64,

    /// Cost per byte of input
    #[serde(default)]
    pub per_byte_in: u64,

    /// Cost per byte of output
    #[serde(default)]
    pub per_byte_out: u64,

    /// Fixed costs for specific operations
    #[serde(default)]
    pub operations: HashMap<String, u64>,
}

impl CostSchedule {
    /// Load a cost schedule from TOML string
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        #[cfg(feature = "tracing")]
        debug!("Parsing cost schedule from TOML");

        toml::from_str(toml_str)
            .map_err(|e| RuntimeError::InvalidConfig(format!("Invalid cost schedule TOML: {e}")))
    }

    /// Load a cost schedule from TOML file
    pub fn from_toml_file(path: &std::path::Path) -> Result<Self> {
        #[cfg(feature = "tracing")]
        info!(?path, "Loading cost schedule from file");

        let contents = std::fs::read_to_string(path).map_err(|e| {
            RuntimeError::InvalidConfig(format!("Failed to read cost schedule file: {e}"))
        })?;

        Self::from_toml(&contents)
    }

    /// Serialize to TOML string
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| RuntimeError::InvalidConfig(format!("Failed to serialize schedule: {e}")))
    }

    /// Get the default v0.1 cost schedule
    pub fn default_v0_1() -> Self {
        Self {
            version: "0.1.0".to_string(),
            description: "Initial baseline cost schedule for jig-runtime".to_string(),
            instruction_costs: InstructionCosts::default(),
            capability_costs: Self::default_capability_costs(),
        }
    }

    fn default_capability_costs() -> HashMap<String, CapabilityCosts> {
        let mut costs = HashMap::new();

        // HTTP capability
        costs.insert(
            "http".to_string(),
            CapabilityCosts {
                call_base: 1000, // High base cost for network I/O
                per_byte_in: 1,  // Cost per byte downloaded
                per_byte_out: 1, // Cost per byte uploaded
                operations: HashMap::from([
                    ("get".to_string(), 500),
                    ("post".to_string(), 750),
                    ("put".to_string(), 750),
                    ("delete".to_string(), 500),
                ]),
            },
        );

        // KV capability
        costs.insert(
            "kv".to_string(),
            CapabilityCosts {
                call_base: 100,
                per_byte_in: 1,
                per_byte_out: 1,
                operations: HashMap::from([
                    ("get".to_string(), 50),
                    ("set".to_string(), 100),
                    ("delete".to_string(), 50),
                    ("list".to_string(), 200),
                ]),
            },
        );

        // Clock capability
        costs.insert(
            "clock".to_string(),
            CapabilityCosts {
                call_base: 10,
                per_byte_in: 0,
                per_byte_out: 0,
                operations: HashMap::from([("now".to_string(), 10)]),
            },
        );

        // Random capability
        costs.insert(
            "rand".to_string(),
            CapabilityCosts {
                call_base: 50,
                per_byte_in: 0,
                per_byte_out: 1,
                operations: HashMap::from([
                    ("random_bytes".to_string(), 50),
                    ("random_u64".to_string(), 25),
                ]),
            },
        );

        // Crypto capability
        costs.insert(
            "crypto".to_string(),
            CapabilityCosts {
                call_base: 100,
                per_byte_in: 1,
                per_byte_out: 1,
                operations: HashMap::from([
                    ("hash_blake3".to_string(), 200),
                    ("hash_sha256".to_string(), 250),
                    ("verify_ed25519".to_string(), 500),
                ]),
            },
        );

        costs
    }

    /// Validate the cost schedule
    pub fn validate(&self) -> Result<()> {
        #[cfg(feature = "tracing")]
        debug!(version = %self.version, "Validating cost schedule");

        // Validate version format (basic semver check)
        if !self.version.contains('.') {
            return Err(RuntimeError::InvalidConfig(
                "Cost schedule version must be semver format".to_string(),
            ));
        }

        // Ensure base instruction cost is non-zero
        if self.instruction_costs.wasm_instruction_base == 0 {
            return Err(RuntimeError::InvalidConfig(
                "Base instruction cost must be > 0".to_string(),
            ));
        }

        #[cfg(feature = "tracing")]
        info!(
            version = %self.version,
            capabilities = self.capability_costs.len(),
            "Cost schedule validated"
        );

        Ok(())
    }

    /// Calculate fuel cost for a capability call
    pub fn calculate_capability_fuel(
        &self,
        capability: &str,
        operation: Option<&str>,
        bytes_in: u64,
        bytes_out: u64,
    ) -> u64 {
        let cap_costs = match self.capability_costs.get(capability) {
            Some(costs) => costs,
            None => {
                #[cfg(feature = "tracing")]
                debug!(capability, "No cost schedule for capability, using base");
                // Default to conservative estimate
                return 1000 + bytes_in + bytes_out;
            }
        };

        let mut total = cap_costs.call_base;
        total = total.saturating_add(bytes_in.saturating_mul(cap_costs.per_byte_in));
        total = total.saturating_add(bytes_out.saturating_mul(cap_costs.per_byte_out));

        if let Some(op) = operation
            && let Some(&op_cost) = cap_costs.operations.get(op)
        {
            total = total.saturating_add(op_cost);
        }

        total
    }
}

impl Default for CostSchedule {
    fn default() -> Self {
        Self::default_v0_1()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_schedule() {
        let schedule = CostSchedule::default_v0_1();
        assert_eq!(schedule.version, "0.1.0");
        assert!(schedule.validate().is_ok());
    }

    #[test]
    fn test_schedule_serialization() {
        let schedule = CostSchedule::default_v0_1();
        let toml = schedule.to_toml().expect("Failed to serialize");
        assert!(toml.contains("version"));
        assert!(toml.contains("0.1.0"));

        let parsed = CostSchedule::from_toml(&toml).expect("Failed to deserialize");
        assert_eq!(parsed.version, schedule.version);
    }

    #[test]
    fn test_capability_fuel_calculation() {
        let schedule = CostSchedule::default_v0_1();

        // HTTP GET with 1000 bytes response
        let fuel = schedule.calculate_capability_fuel("http", Some("get"), 0, 1000);
        assert!(fuel > 1000); // Base + operation + bytes

        // KV get
        let fuel = schedule.calculate_capability_fuel("kv", Some("get"), 0, 100);
        assert!(fuel > 100);

        // Unknown capability defaults
        let fuel = schedule.calculate_capability_fuel("unknown", None, 100, 100);
        assert!(fuel >= 1000);
    }

    #[test]
    fn test_invalid_version() {
        let mut schedule = CostSchedule::default_v0_1();
        schedule.version = "1.0".to_string();
        assert!(schedule.validate().is_ok()); // Has a dot

        schedule.version = "nodot".to_string();
        assert!(schedule.validate().is_err()); // No dot = invalid
    }

    #[test]
    fn test_zero_instruction_cost_invalid() {
        let mut schedule = CostSchedule::default_v0_1();
        schedule.instruction_costs.wasm_instruction_base = 0;
        assert!(schedule.validate().is_err());
    }
}
