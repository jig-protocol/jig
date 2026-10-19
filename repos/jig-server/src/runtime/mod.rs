//! Operator execution settings.
//!
//! `ExecutionConfig` carries the `[execution]` limits from `ServerConfig` to
//! the ingest path, which maps them onto `jig_runtime::RuntimeConfig` in
//! `v0_0_2::runtime_config_from`. Blocks run through jig-pipeline's
//! `BlockExecutor`; this module no longer executes anything itself.

/// Execution tuning knobs loaded from configuration.
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    pub fuel_max: u64,
    pub memory_max_mb: u32,
    pub timeout_ms: u64,
    pub host_id: String,
    pub pricing_enabled: bool,
    pub cost_per_fuel: Option<f64>,
    /// Concurrent executions permitted; see `ServerConfig`'s `[execution]`.
    pub max_concurrent_executions: u32,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            fuel_max: 5_000_000,
            memory_max_mb: 64,
            timeout_ms: 250,
            max_concurrent_executions: 16,
            host_id: "did:jig:server:local".into(),
            pricing_enabled: false,
            cost_per_fuel: None,
        }
    }
}
