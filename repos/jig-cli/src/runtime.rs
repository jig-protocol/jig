//! Thin adapter to jig-runtime - NO host capability logic here
//!
//! This module provides a simple interface for jig-cli to execute WASM blocks
//! locally using the unified jig-runtime.

#![cfg(feature = "local-runtime")]

use anyhow::Result;
use jig_runtime::{BlockPackage, ExecutionContext, Limits, Receipt, Runtime, RuntimeConfig};
use std::time::Duration;

/// Execution specification for a block
pub struct ExecutionSpec {
    /// WASM bytecode
    pub wasm_bytes: Vec<u8>,
    /// Block identifier (optional)
    pub block_id: Option<String>,
    /// Seed for deterministic execution (optional)
    pub seed: Option<u64>,
    /// Execution limits (optional overrides)
    pub limits: Option<ExecutionLimits>,
    /// Capability allowlist
    pub capability_allowlist: Vec<String>,
}

/// Execution limits that can be specified via CLI
#[derive(Debug, Clone, Default)]
pub struct ExecutionLimits {
    /// Maximum fuel budget
    pub fuel: Option<u64>,
    /// Maximum memory in MB
    pub memory_mb: Option<u32>,
    /// Execution timeout in milliseconds
    pub timeout_ms: Option<u64>,
}

/// Runtime adapter for local WASM execution
pub struct LocalRuntime {
    runtime: Runtime,
}

impl LocalRuntime {
    /// Create a new runtime with default configuration
    pub fn new() -> Result<Self> {
        let runtime = Runtime::new()?;
        Ok(Self { runtime })
    }

    /// Create a new runtime with custom configuration
    pub fn with_config(config: RuntimeConfig) -> Result<Self> {
        let runtime = Runtime::with_config(config)?;
        Ok(Self { runtime })
    }

    /// Execute a WASM block and return a receipt
    pub fn execute(&self, spec: ExecutionSpec) -> Result<Receipt> {
        // Build execution context
        let mut context = ExecutionContext::default();
        context.block = BlockPackage {
            wasm_bytes: spec.wasm_bytes.clone(),
            block_id: spec.block_id.clone(),
            ..Default::default()
        };
        context.capabilities = spec.capability_allowlist;

        // Apply limits if specified
        if let Some(limits) = spec.limits {
            let cli_limits = Limits {
                fuel_max: limits.fuel.unwrap_or(5_000_000),
                memory_max_mb: limits.memory_mb.unwrap_or(32),
                timeout: Duration::from_millis(limits.timeout_ms.unwrap_or(250)),
            };
            context = context.with_limits(cli_limits);
        }

        // Add RNG seed if specified (for determinism)
        if let Some(seed) = spec.seed {
            // Convert u64 seed to [u8; 32]
            let mut seed_bytes = [0u8; 32];
            seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
            context = context.with_rng_seed(seed_bytes);
        }

        // Execute
        let receipt = self.runtime.execute(&spec.wasm_bytes, context)?;

        Ok(receipt)
    }
}
