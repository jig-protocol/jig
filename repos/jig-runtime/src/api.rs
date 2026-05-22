use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

#[cfg(feature = "tracing")]
use tracing::{debug, info, instrument, warn};

use cid::Cid;
use serde_json::Value;

use crate::config::{ResourceLimits, RuntimeConfig};
use crate::engine::WasmEngine;
use crate::error::{Result, RuntimeError};
use crate::fuel::CapabilityMeterHandle;
use crate::receipt::{CapabilityCall, ExecutionOutcome, ModuleHash, Receipt, ReceiptPricing};
use jig_core::CapabilityUsageKey;
use jig_core::receipt::{HashAlgorithms, Limits as CoreLimits, Outcome as CoreOutcome, ReasonCode};
use jig_core::wasm_validation::HostImportAllowlist;
use serde_json;

/// Main runtime entry point for WASM execution
///
/// This is the primary interface for executing WebAssembly modules
/// with deterministic, capability-secured, fuel-metered execution.
pub struct Runtime {
    config: RuntimeConfig,
    engine: WasmEngine,
}

impl Runtime {
    /// Create a new runtime with default configuration
    #[cfg_attr(feature = "tracing", instrument(name = "runtime_new"))]
    pub fn new() -> Result<Self> {
        #[cfg(feature = "tracing")]
        info!("Creating new runtime with default configuration");
        Self::with_config(RuntimeConfig::default())
    }

    /// Create a runtime with custom configuration
    #[cfg_attr(
        feature = "tracing",
        instrument(name = "runtime_with_config", skip(config))
    )]
    pub fn with_config(config: RuntimeConfig) -> Result<Self> {
        #[cfg(feature = "tracing")]
        debug!(
            fuel_enabled = config.fuel.enabled,
            deterministic = config.engine.deterministic,
            "Validating runtime configuration"
        );

        config.validate()?;

        #[cfg(feature = "tracing")]
        info!("Creating Wasmtime engine");
        let engine = WasmEngine::new(&config)?;

        #[cfg(feature = "tracing")]
        info!("Runtime created successfully");

        Ok(Self { config, engine })
    }

    /// Execute a WebAssembly module and return a receipt
    #[cfg_attr(
        feature = "tracing",
        instrument(
            name = "runtime_execute",
            skip(self, wasm_bytes, context),
            fields(
                wasm_size = wasm_bytes.len(),
                block_id = ?context.block.block_id
            )
        )
    )]
    pub fn execute(&self, wasm_bytes: &[u8], context: ExecutionContext) -> Result<Receipt> {
        use std::time::Instant;

        #[cfg(feature = "tracing")]
        info!("Starting WASM execution");

        let start_time = Instant::now();

        // Validate module first
        #[cfg(feature = "tracing")]
        debug!("Validating WASM module");
        self.validate_module(wasm_bytes)?;

        // Hash the module for provenance
        let module_hash = blake3::hash(wasm_bytes);
        let module_hash_hex = module_hash.to_hex().to_string();

        #[cfg(feature = "tracing")]
        debug!(module_hash = %module_hash_hex, "Generated module hash");

        // Compile the module
        #[cfg(feature = "tracing")]
        debug!("Compiling WASM module");
        let module = self.engine.compile_module(wasm_bytes)?;

        // Check if module requires WASI imports
        let requires_wasi = Self::module_requires_wasi(&module);
        #[cfg(feature = "tracing")]
        debug!(requires_wasi, "Checked WASI requirements");

        // Determine fuel and memory limits
        let fuel_limit = context
            .limits
            .as_ref()
            .map(|l| l.fuel_max)
            .unwrap_or(self.config.limits.fuel_max);

        let memory_limit_mb = context
            .limits
            .as_ref()
            .map(|l| l.memory_max_mb)
            .unwrap_or(self.config.limits.memory_max_mb);

        let timeout_ms = context
            .limits
            .as_ref()
            .map(|l| l.timeout.as_millis() as u64)
            .unwrap_or(self.config.limits.execution_timeout_ms);
        let timeout_duration = Duration::from_millis(timeout_ms);

        let capability_meter = context.capability_meter.clone();

        #[cfg(feature = "tracing")]
        debug!(
            fuel_limit,
            memory_limit_mb, timeout_ms, "Creating store with limits"
        );

        // Execute with or without WASI based on module requirements
        #[cfg(feature = "wasi-preview2")]
        if requires_wasi {
            return self.execute_with_wasi(
                module,
                context,
                wasm_bytes,
                fuel_limit,
                memory_limit_mb,
                capability_meter,
                timeout_ms,
                module_hash_hex,
                start_time,
            );
        }

        // Non-WASI execution path
        let mut store =
            self.engine
                .create_store_with_limits(fuel_limit, memory_limit_mb, timeout_duration)?;

        let epoch_guard = self.engine.schedule_epoch_interrupt(timeout_duration);

        // Track initial fuel (if fuel metering is enabled)
        let initial_fuel = if self.config.fuel.enabled {
            store.get_fuel().unwrap_or(0)
        } else {
            0
        };

        // Instantiate the module
        #[cfg(feature = "tracing")]
        debug!("Instantiating module");
        let instance = wasmtime::Instance::new(&mut store, &module, &[])
            .map_err(|e| RuntimeError::InstantiationError(e.to_string()))?;

        // Look for a "run" or "_start" export (common WASI entry points)
        let func = instance
            .get_func(&mut store, "run")
            .or_else(|| instance.get_func(&mut store, "_start"))
            .or_else(|| instance.get_func(&mut store, "main"))
            .ok_or_else(|| {
                RuntimeError::ExecutionError(
                    "No 'run', '_start', or 'main' function found".to_string(),
                )
            })?;

        // Execute the function
        #[cfg(feature = "tracing")]
        info!("Executing WASM function");

        // Check function signature and allocate appropriate results
        let func_ty = func.ty(&store);
        let result_count = func_ty.results().len();
        let mut results: Vec<wasmtime::Val> = match result_count {
            0 => vec![],
            1 => vec![wasmtime::Val::I32(0)], // Default to i32, will be replaced
            _ => {
                return Err(RuntimeError::ExecutionError(
                    "Functions with multiple return values are not supported".to_string(),
                ));
            }
        };

        let execution_result = func.call(&mut store, &[], &mut results);

        // Calculate execution time
        let duration_ns = start_time.elapsed().as_nanos() as u64;

        // Get remaining fuel to calculate consumption
        let remaining_fuel = store.get_fuel().unwrap_or(0);
        let fuel_used = initial_fuel.saturating_sub(remaining_fuel);

        #[cfg(feature = "tracing")]
        debug!(fuel_used, remaining_fuel, "Execution completed");

        let host_id = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
        let mut builder = Receipt::builder()
            .host(host_id)
            .render_hash(module_hash_hex.clone())
            .execution_duration_ns(duration_ns)
            .module_hash(ModuleHash::new(module_hash_hex.clone(), "blake3-256"));

        if let Some(ref block_id) = context.block.block_id {
            match block_id.parse::<Cid>() {
                Ok(cid) => {
                    builder = builder.block_id(cid);
                }
                Err(_) => {
                    #[cfg(feature = "tracing")]
                    warn!(
                        block_id,
                        "Invalid block id provided; deriving from wasm bytes"
                    );
                    builder = builder
                        .block_id_from_wasm(wasm_bytes)
                        .metadata("runtime.block_id_hint", Value::String(block_id.clone()));
                }
            }
        } else {
            builder = builder.block_id_from_wasm(wasm_bytes);
        }

        let memory_limit_mb = context
            .limits
            .as_ref()
            .map(|l| l.memory_max_mb)
            .unwrap_or(self.config.limits.memory_max_mb);
        let limits = CoreLimits {
            fuel_max: fuel_limit,
            memory_max_mb: memory_limit_mb,
            execution_timeout_ms: timeout_ms.min(u32::MAX as u64) as u32,
        };
        builder = builder.limits(limits);
        builder = builder.hash_algorithms(HashAlgorithms::default());

        let mut outcome = Outcome::Success;
        let mut legacy_outcome = ExecutionOutcome::Success;
        let mut error_info: Option<(String, Option<String>)> = None;

        match execution_result {
            Ok(_) => {
                #[cfg(feature = "tracing")]
                info!(fuel_used, remaining_fuel, "Execution succeeded");

                if self.config.fuel.enabled && fuel_used > (fuel_limit * 9 / 10) {
                    #[cfg(feature = "tracing")]
                    warn!(
                        fuel_used,
                        fuel_limit,
                        usage_pct = (fuel_used * 100 / fuel_limit),
                        "Execution used >90% of fuel budget"
                    );
                }
            }
            Err(trap) => {
                #[cfg(feature = "tracing")]
                warn!(error = %trap, fuel_used, "Execution trapped");
                let trap_msg = trap.to_string();
                if trap_msg.contains("all fuel consumed")
                    || trap_msg.contains("fuel exhausted")
                    || trap_msg.contains("out of fuel")
                {
                    outcome = Outcome::HardFailure {
                        reason: ReasonCode::FuelExhausted,
                    };
                    legacy_outcome = ExecutionOutcome::LimitsExceeded;
                    error_info = Some((
                        "ERR_FUEL_EXHAUSTED".to_string(),
                        Some(format!(
                            "Fuel exhausted: used {fuel_used} of {fuel_limit} limit"
                        )),
                    ));

                    #[cfg(feature = "tracing")]
                    info!(fuel_used, fuel_limit, "Fuel budget exhausted");
                } else {
                    outcome = Outcome::HardFailure {
                        reason: ReasonCode::RuntimeTrap,
                    };
                    legacy_outcome = ExecutionOutcome::ExecutionFailed;
                    error_info = Some(("ERR_TRAP".to_string(), Some(trap_msg)));
                }
            }
        }

        builder = builder.outcome(CoreOutcome::from(&outcome));
        builder = builder.legacy_outcome(legacy_outcome);

        if let Some((code, message)) = error_info {
            builder = builder.error(code, message);
        }

        if self.config.pricing.enabled {
            #[cfg(feature = "tracing")]
            debug!(
                cost_per_fuel = self.config.pricing.cost_per_fuel_unit,
                "Calculating pricing"
            );

            let pricing = ReceiptPricing {
                cost_per_fuel_unit: self.config.pricing.cost_per_fuel_unit,
                total_cost: fuel_used as f64 * self.config.pricing.cost_per_fuel_unit,
                currency: self.config.pricing.currency.clone(),
                schedule_version: self.config.pricing.schedule_version.clone(),
            };
            builder = builder.pricing(pricing);
        }
        let snapshot = capability_meter.snapshot();
        let status_bins = snapshot.status_bins_btree();
        let mut fuel_by_capability = snapshot.fuel_by_capability.clone();
        if fuel_by_capability.is_empty() {
            fuel_by_capability.insert(
                CapabilityUsageKey::without_scope("engine.wasm").to_canonical_string(),
                fuel_used,
            );
        }
        let fuel_total: u64 = fuel_by_capability.values().copied().sum();
        let counters = jig_core::receipt::Counters {
            fuel_total,
            fuel_by_capability: fuel_by_capability.clone(),
            status_by_capability: status_bins.clone(),
            bytes_tx: snapshot.bytes_tx,
            bytes_rx: snapshot.bytes_rx,
            syscalls: 0,
        };
        builder = builder.fuel_used(fuel_total).counters(counters);

        let mut capability_keys: BTreeSet<String> = fuel_by_capability.keys().cloned().collect();

        for record in snapshot.call_records.iter() {
            let canonical = record.key.to_canonical_string();
            capability_keys.insert(canonical.clone());
            builder = builder.capability_call(CapabilityCall {
                capability: canonical,
                operation: record.operation.clone(),
                fuel_used: record.fuel_used,
                bytes_transferred: if record.bytes_transferred > 0 {
                    Some(record.bytes_transferred)
                } else {
                    None
                },
                status: record.status.clone(),
            });
        }

        if !status_bins.is_empty()
            && let Ok(value) = serde_json::to_value(&status_bins)
        {
            builder = builder.metadata("runtime.status_bins", value);
        }

        for capability in capability_keys {
            builder = builder.capability(capability);
        }

        if let Some(guard) = epoch_guard.as_ref() {
            guard.cancel();
        }
        builder.build()
    }

    /// Validate a WebAssembly module without executing it
    #[cfg_attr(
        feature = "tracing",
        instrument(
            name = "validate_module",
            skip(self, wasm_bytes),
            fields(wasm_size = wasm_bytes.len())
        )
    )]
    pub fn validate_module(&self, wasm_bytes: &[u8]) -> Result<()> {
        #[cfg(feature = "tracing")]
        debug!("Validating WASM module structure");

        // Quick pre-scan: check if bytecode contains WASI imports
        // This is a simple heuristic - look for the string "wasi_snapshot_preview1" in the bytes
        let uses_wasi = wasm_bytes
            .windows("wasi_snapshot_preview1".len())
            .any(|window| window == b"wasi_snapshot_preview1");

        // Use appropriate policy based on WASI detection
        use jig_core::wasm_validation::{DeterminismPolicy, verify_determinism};
        let policy = if uses_wasi {
            #[cfg(feature = "tracing")]
            debug!("Module appears to use WASI imports, applying WASI-safe policy");
            DeterminismPolicy::strict()
                .with_allowlist(HostImportAllowlist::wasi_preview1_deterministic())
        } else {
            #[cfg(feature = "tracing")]
            debug!("Module uses no WASI, applying default strict policy");
            DeterminismPolicy::strict()
        };

        let report = verify_determinism(wasm_bytes, &policy)?;
        if !report.is_compliant() {
            let violation = report
                .violations
                .first()
                .map(|v| format!("{v:?}"))
                .unwrap_or_else(|| "unknown violation".to_string());
            return Err(RuntimeError::ValidationError(format!(
                "non-deterministic wasm module: {violation}"
            )));
        }

        let result = self.engine.validate_module(wasm_bytes);

        #[cfg(feature = "tracing")]
        match &result {
            Ok(_) => info!("Module validation successful"),
            Err(e) => warn!(error = %e, "Module validation failed"),
        }

        result
    }

    /// Get the current configuration
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Check if fuel metering is enabled
    pub fn is_fuel_enabled(&self) -> bool {
        self.config.fuel.enabled
    }

    /// Get default fuel limit from configuration
    pub fn default_fuel_limit(&self) -> u64 {
        self.config.limits.fuel_max
    }

    /// Check if a module requires WASI imports
    fn module_requires_wasi(module: &wasmtime::Module) -> bool {
        module.imports().any(|import| {
            import.module() == "wasi_snapshot_preview1" || import.module().starts_with("wasi")
        })
    }

    /// Execute a WASM module with WASI support
    #[cfg(feature = "wasi-preview2")]
    #[allow(clippy::too_many_arguments)]
    fn execute_with_wasi(
        &self,
        module: wasmtime::Module,
        context: ExecutionContext,
        wasm_bytes: &[u8],
        fuel_limit: u64,
        memory_limit_mb: u32,
        capability_meter: CapabilityMeterHandle,
        timeout_ms: u64,
        module_hash_hex: String,
        start_time: std::time::Instant,
    ) -> Result<Receipt> {
        use crate::engine::StoreContext;

        #[cfg(feature = "tracing")]
        info!("Creating WASI-enabled store");

        let timeout_duration = Duration::from_millis(timeout_ms);

        // Create store with WASI context
        let mut store = self.engine.create_store_with_wasi(
            fuel_limit,
            memory_limit_mb,
            &self.config,
            timeout_duration,
        )?;

        let epoch_guard = self.engine.schedule_epoch_interrupt(timeout_duration);

        // Track initial fuel (if fuel metering is enabled)
        let initial_fuel = if self.config.fuel.enabled {
            store.get_fuel().unwrap_or(0)
        } else {
            0
        };

        // Create linker and add WASI preview1 imports
        let mut linker = wasmtime::Linker::<StoreContext>::new(self.engine.engine());
        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |ctx| &mut ctx.wasi)
            .map_err(|e| RuntimeError::InternalError(format!("Failed to add WASI: {e}")))?;

        // Instantiate the module with WASI imports
        #[cfg(feature = "tracing")]
        debug!("Instantiating module with WASI");
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| RuntimeError::InstantiationError(e.to_string()))?;

        // Look for entry point
        let func = instance
            .get_func(&mut store, "run")
            .or_else(|| instance.get_func(&mut store, "_start"))
            .or_else(|| instance.get_func(&mut store, "main"))
            .ok_or_else(|| {
                RuntimeError::ExecutionError(
                    "No 'run', '_start', or 'main' function found".to_string(),
                )
            })?;

        // Execute the function
        #[cfg(feature = "tracing")]
        info!("Executing WASM function with WASI");

        let func_ty = func.ty(&store);
        let result_count = func_ty.results().len();
        let mut results: Vec<wasmtime::Val> = match result_count {
            0 => vec![],
            1 => vec![wasmtime::Val::I32(0)],
            _ => {
                return Err(RuntimeError::ExecutionError(
                    "Functions with multiple return values are not supported".to_string(),
                ));
            }
        };

        let execution_result = func.call(&mut store, &[], &mut results);

        // Calculate execution time
        let duration_ns = start_time.elapsed().as_nanos() as u64;

        // Get remaining fuel
        let remaining_fuel = store.get_fuel().unwrap_or(0);
        let fuel_used = initial_fuel.saturating_sub(remaining_fuel);

        #[cfg(feature = "tracing")]
        debug!(fuel_used, remaining_fuel, "WASI execution completed");

        let host_id = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
        let mut builder = Receipt::builder()
            .host(host_id)
            .render_hash(module_hash_hex.clone())
            .execution_duration_ns(duration_ns)
            .module_hash(ModuleHash::new(module_hash_hex.clone(), "blake3-256"));

        if let Some(ref block_id) = context.block.block_id {
            match block_id.parse::<Cid>() {
                Ok(cid) => {
                    builder = builder.block_id(cid);
                }
                Err(_) => {
                    #[cfg(feature = "tracing")]
                    warn!(
                        block_id,
                        "Invalid block id provided; deriving from wasm bytes"
                    );
                    builder = builder
                        .block_id_from_wasm(wasm_bytes)
                        .metadata("runtime.block_id_hint", Value::String(block_id.clone()));
                }
            }
        } else {
            builder = builder.block_id_from_wasm(wasm_bytes);
        }

        let limits = CoreLimits {
            fuel_max: fuel_limit,
            memory_max_mb: memory_limit_mb,
            execution_timeout_ms: timeout_ms.min(u32::MAX as u64) as u32,
        };
        builder = builder.limits(limits);
        builder = builder.hash_algorithms(HashAlgorithms::default());

        let mut outcome = Outcome::Success;
        let mut legacy_outcome = ExecutionOutcome::Success;
        let mut error_info: Option<(String, Option<String>)> = None;

        match execution_result {
            Ok(_) => {
                #[cfg(feature = "tracing")]
                info!(fuel_used, remaining_fuel, "WASI execution succeeded");

                if self.config.fuel.enabled && fuel_used > (fuel_limit * 9 / 10) {
                    #[cfg(feature = "tracing")]
                    warn!(
                        fuel_used,
                        fuel_limit,
                        usage_pct = (fuel_used * 100 / fuel_limit),
                        "Execution used >90% of fuel budget"
                    );
                }
            }
            Err(trap) => {
                #[cfg(feature = "tracing")]
                warn!(error = %trap, fuel_used, "WASI execution trapped");

                let trap_msg = trap.to_string();
                if trap_msg.contains("all fuel consumed")
                    || trap_msg.contains("fuel exhausted")
                    || trap_msg.contains("out of fuel")
                {
                    outcome = Outcome::HardFailure {
                        reason: ReasonCode::FuelExhausted,
                    };
                    legacy_outcome = ExecutionOutcome::LimitsExceeded;
                    error_info = Some((
                        "ERR_FUEL_EXHAUSTED".to_string(),
                        Some(format!(
                            "Fuel exhausted: used {fuel_used} of {fuel_limit} limit"
                        )),
                    ));

                    #[cfg(feature = "tracing")]
                    info!(fuel_used, fuel_limit, "Fuel budget exhausted");
                } else {
                    outcome = Outcome::HardFailure {
                        reason: ReasonCode::RuntimeTrap,
                    };
                    legacy_outcome = ExecutionOutcome::ExecutionFailed;
                    error_info = Some(("ERR_TRAP".to_string(), Some(trap_msg)));
                }
            }
        }

        builder = builder.outcome(CoreOutcome::from(&outcome));
        builder = builder.legacy_outcome(legacy_outcome);

        if let Some((code, message)) = error_info {
            builder = builder.error(code, message);
        }

        if self.config.pricing.enabled {
            #[cfg(feature = "tracing")]
            debug!(
                cost_per_fuel = self.config.pricing.cost_per_fuel_unit,
                "Calculating pricing"
            );

            let pricing = ReceiptPricing {
                cost_per_fuel_unit: self.config.pricing.cost_per_fuel_unit,
                total_cost: fuel_used as f64 * self.config.pricing.cost_per_fuel_unit,
                currency: self.config.pricing.currency.clone(),
                schedule_version: self.config.pricing.schedule_version.clone(),
            };
            builder = builder.pricing(pricing);
        }

        let snapshot = capability_meter.snapshot();
        let mut fuel_by_capability = snapshot.fuel_by_capability.clone();
        if fuel_by_capability.is_empty() {
            fuel_by_capability.insert(
                CapabilityUsageKey::without_scope("engine.wasm").to_canonical_string(),
                fuel_used,
            );
        }
        let fuel_total: u64 = fuel_by_capability.values().copied().sum();
        builder = builder
            .fuel_used(fuel_total)
            .counters(jig_core::receipt::Counters {
                fuel_total,
                fuel_by_capability,
                status_by_capability: snapshot.status_bins_btree(),
                bytes_tx: snapshot.bytes_tx,
                bytes_rx: snapshot.bytes_rx,
                syscalls: 0,
            });

        for record in snapshot.call_records.iter() {
            builder = builder.capability_call(CapabilityCall {
                capability: record.key.to_canonical_string(),
                operation: record.operation.clone(),
                fuel_used: record.fuel_used,
                bytes_transferred: if record.bytes_transferred > 0 {
                    Some(record.bytes_transferred)
                } else {
                    None
                },
                status: record.status.clone(),
            });
        }

        if !snapshot.status_bins.is_empty()
            && let Ok(value) = serde_json::to_value(&snapshot.status_bins)
        {
            builder = builder.metadata("runtime.status_bins", value);
        }

        if let Some(guard) = epoch_guard.as_ref() {
            guard.cancel();
        }

        builder.build()
    }
}

/// Execution context for a single WASM module run
///
/// Contains all parameters, limits, and capabilities for one execution.
#[derive(Debug, Clone, Default)]
pub struct ExecutionContext {
    /// Block package (module + metadata)
    pub block: BlockPackage,

    /// Resource limits (overrides config defaults if provided)
    pub limits: Option<Limits>,

    /// Allowed capabilities for this execution
    pub capabilities: Vec<String>,

    /// Environment variables exposed to the module
    pub env: HashMap<String, String>,

    /// Command-line arguments
    pub args: Vec<String>,

    /// Deterministic seed for RNG capability
    pub rng_seed: Option<[u8; 32]>,

    pub(crate) capability_meter: CapabilityMeterHandle,
}

impl ExecutionContext {
    /// Builder: set block package
    pub fn with_block(mut self, block: BlockPackage) -> Self {
        self.block = block;
        self
    }

    /// Builder: set limits
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Builder: add capability
    pub fn with_capability(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.push(cap.into());
        self
    }

    /// Builder: add multiple capabilities
    pub fn with_capabilities(mut self, caps: impl IntoIterator<Item = String>) -> Self {
        self.capabilities.extend(caps);
        self
    }

    /// Builder: add environment variable
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Builder: set RNG seed for determinism
    pub fn with_rng_seed(mut self, seed: [u8; 32]) -> Self {
        self.rng_seed = Some(seed);
        self
    }

    /// Builder: provide a custom capability meter handle (primarily for tests/bridges).
    pub fn with_capability_meter(mut self, meter: CapabilityMeterHandle) -> Self {
        self.capability_meter = meter;
        self
    }

    /// Cloneable handle that host bridges can use to record capability usage.
    pub fn capability_meter_handle(&self) -> CapabilityMeterHandle {
        self.capability_meter.clone()
    }
}

/// Block package containing WASM module and metadata
#[derive(Debug, Clone, Default)]
pub struct BlockPackage {
    /// Block identifier (CID or hash)
    pub block_id: Option<String>,

    /// WASM module bytes
    pub wasm_bytes: Vec<u8>,

    /// Block author DID
    pub author: Option<String>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl BlockPackage {
    /// Create a new block package from WASM bytes
    pub fn from_wasm(wasm_bytes: Vec<u8>) -> Self {
        Self {
            wasm_bytes,
            ..Default::default()
        }
    }

    /// Builder: set block ID
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.block_id = Some(id.into());
        self
    }

    /// Builder: set author
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }
}

/// Resource limits for a specific execution
///
/// Can override the config defaults for fine-grained control.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum fuel budget
    pub fuel_max: u64,

    /// Maximum memory in MB
    pub memory_max_mb: u32,

    /// Execution timeout
    pub timeout: Duration,
}

impl From<ResourceLimits> for Limits {
    fn from(rl: ResourceLimits) -> Self {
        Self {
            fuel_max: rl.fuel_max,
            memory_max_mb: rl.memory_max_mb,
            timeout: Duration::from_millis(rl.execution_timeout_ms),
        }
    }
}

impl Limits {
    /// Create limits with specified values
    pub fn new(fuel_max: u64, memory_max_mb: u32, timeout: Duration) -> Self {
        Self {
            fuel_max,
            memory_max_mb,
            timeout,
        }
    }
}

/// Execution outcome
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Execution completed successfully
    Success,

    /// Execution failed with a soft error (retryable)
    SoftFailure { reason: ReasonCode },

    /// Execution failed with a hard error (not retryable)
    HardFailure { reason: ReasonCode },
}

impl Outcome {
    /// Convert to receipt status string
    pub fn as_status_str(&self) -> &'static str {
        match self {
            Outcome::Success => "ok",
            Outcome::SoftFailure { .. } => "soft_fail",
            Outcome::HardFailure { .. } => "hard_fail",
        }
    }

    /// Get failure reason if any
    pub fn reason(&self) -> Option<&ReasonCode> {
        match self {
            Outcome::Success => None,
            Outcome::SoftFailure { reason } | Outcome::HardFailure { reason } => Some(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_creation() {
        let runtime = Runtime::new();
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_execution_context_builder() {
        let ctx = ExecutionContext::default()
            .with_capability("http".to_string())
            .with_capability("kv".to_string())
            .with_env("KEY", "VALUE");

        assert_eq!(ctx.capabilities.len(), 2);
        assert_eq!(ctx.env.get("KEY"), Some(&"VALUE".to_string()));
    }

    #[test]
    fn test_outcome_status() {
        assert_eq!(Outcome::Success.as_status_str(), "ok");
        assert_eq!(
            Outcome::SoftFailure {
                reason: ReasonCode::RuntimeTimeout
            }
            .as_status_str(),
            "soft_fail"
        );
        assert!(Outcome::Success.reason().is_none());
    }
}
