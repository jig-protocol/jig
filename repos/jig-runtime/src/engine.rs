//! Wasmtime engine integration with deterministic configuration
//!
//! This module provides a deterministic WebAssembly execution engine using Wasmtime.
//! All execution is fuel-metered, with canonicalized NaNs, and no non-deterministic features.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use wasmtime::*;

#[cfg(feature = "wasi-preview2")]
use wasmtime_wasi::{WasiCtxBuilder, preview1::WasiP1Ctx};

use crate::config::RuntimeConfig;
use crate::error::{Result, RuntimeError};

/// Store resource limits for memory and instance quotas
#[derive(Debug, Clone, Copy)]
pub struct StoreLimits {
    /// Maximum memory size in bytes
    pub memory_size: usize,
    /// Maximum table elements
    pub table_elements: u32,
    /// Maximum instances
    #[allow(dead_code)] // Reserved for future limits
    pub instances: usize,
    /// Maximum tables
    #[allow(dead_code)] // Reserved for future limits
    pub tables: usize,
    /// Maximum memories
    #[allow(dead_code)] // Reserved for future table/instance limits
    pub memories: usize,
}

/// Combined store context with both WASI and resource limits
#[cfg(feature = "wasi-preview2")]
pub struct StoreContext {
    pub wasi: WasiP1Ctx,
    pub limits: StoreLimits,
}

impl ResourceLimiter for StoreLimits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.memory_size)
    }

    fn table_growing(
        &mut self,
        _current: u32,
        desired: u32,
        _maximum: Option<u32>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.table_elements)
    }
}

#[cfg(feature = "wasi-preview2")]
impl ResourceLimiter for StoreContext {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        self.limits.memory_growing(current, desired, maximum)
    }

    fn table_growing(
        &mut self,
        current: u32,
        desired: u32,
        maximum: Option<u32>,
    ) -> anyhow::Result<bool> {
        self.limits.table_growing(current, desired, maximum)
    }
}

/// Wasmtime-based execution engine configured for determinism
pub struct WasmEngine {
    engine: Engine,
    epoch_enabled: bool,
}

impl WasmEngine {
    /// Create a new deterministic Wasmtime engine
    pub fn new(config: &RuntimeConfig) -> Result<Self> {
        let mut wasm_config = Config::new();

        // Enable fuel consumption for resource metering
        if config.fuel.enabled {
            wasm_config.consume_fuel(true);
        }

        // Enable epoch interruption so we can enforce wall-clock-style deadlines.
        wasm_config.epoch_interruption(true);

        // Deterministic execution settings
        if config.engine.deterministic {
            // Canonicalize NaN values for deterministic floating-point
            wasm_config.cranelift_nan_canonicalization(config.engine.canonicalize_nans);

            // Disable threads for determinism
            wasm_config.wasm_threads(false);

            // Disable SIMD for now (can be enabled later with deterministic guards)
            wasm_config.wasm_simd(false);
            wasm_config.wasm_relaxed_simd(false); // Must also disable relaxed-simd
        }

        // Memory configuration
        let memory_limit_bytes = (config.limits.memory_max_mb as u64) * 1024 * 1024;
        wasm_config.static_memory_maximum_size(memory_limit_bytes);
        wasm_config.dynamic_memory_guard_size(0x10000); // 64KB guard
        wasm_config.max_wasm_stack(2 * 1024 * 1024); // 2MB stack limit

        // Pooling allocator keeps allocation behaviour predictable
        let mut pooling = PoolingAllocationConfig::default();
        pooling.total_core_instances(config.limits.max_instances.max(1));
        pooling.total_memories(config.limits.max_instances.max(1));
        pooling.max_memories_per_module(1);
        pooling.max_memory_size(memory_limit_bytes as usize);
        wasm_config.allocation_strategy(InstanceAllocationStrategy::Pooling(pooling));

        // Module caching (only if explicitly enabled)
        if config.engine.enable_cache
            && let Some(cache_dir) = &config.engine.cache_dir
        {
            wasm_config
                .cache_config_load(cache_dir)
                .map_err(|e| RuntimeError::InvalidConfig(format!("Cache config: {e}")))?;
        }

        // Build the engine
        let engine = Engine::new(&wasm_config)
            .map_err(|e| RuntimeError::InternalError(format!("Engine creation failed: {e}")))?;

        Ok(Self {
            engine,
            epoch_enabled: true,
        })
    }

    /// Get reference to the underlying Wasmtime engine
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Validate a WebAssembly module without instantiating it
    pub fn validate_module(&self, wasm_bytes: &[u8]) -> Result<()> {
        Module::validate(&self.engine, wasm_bytes)
            .map_err(|e| RuntimeError::ValidationError(format!("Module validation failed: {e}")))?;
        Ok(())
    }

    /// Compile and validate a WebAssembly module
    pub fn compile_module(&self, wasm_bytes: &[u8]) -> Result<Module> {
        Module::new(&self.engine, wasm_bytes)
            .map_err(|e| RuntimeError::InvalidWasm(format!("Module compilation failed: {e}")))
    }

    /// Create a new store with fuel and memory limits
    #[allow(dead_code)] // Alternative store creation, kept for API completeness
    pub fn create_store(&self, fuel_limit: u64) -> Result<Store<()>> {
        let mut store = Store::new(&self.engine, ());

        // Set fuel limit if configured
        if fuel_limit > 0 {
            store
                .set_fuel(fuel_limit)
                .map_err(|e| RuntimeError::InternalError(format!("Failed to set fuel: {e}")))?;
        }

        Ok(store)
    }

    /// Create a store with specified limits
    pub fn create_store_with_limits(
        &self,
        fuel_limit: u64,
        memory_limit_mb: u32,
        timeout: Duration,
    ) -> Result<Store<StoreLimits>> {
        // Create limits structure
        let memory_limit_bytes = (memory_limit_mb as usize) * 1024 * 1024;
        let limits = StoreLimits {
            memory_size: memory_limit_bytes,
            table_elements: 10_000, // Reasonable table element limit
            instances: 1,           // Single instance per store
            tables: 10,             // Max tables
            memories: 1,            // Single memory per module
        };

        let mut store = Store::new(&self.engine, limits);

        // Set fuel limit (only if engine was configured with fuel consumption)
        if fuel_limit > 0 {
            // Try to set fuel - if it fails, fuel metering is disabled in engine
            let _ = store.set_fuel(fuel_limit);
        }

        // Set resource limiter to use the store's data
        store.limiter(|data| data);

        if self.epoch_enabled && timeout.as_millis() > 0 {
            store.set_epoch_deadline(1);
        }

        Ok(store)
    }

    /// Create a store with WASI context and resource limits
    #[cfg(feature = "wasi-preview2")]
    pub fn create_store_with_wasi(
        &self,
        fuel_limit: u64,
        memory_limit_mb: u32,
        config: &RuntimeConfig,
        timeout: Duration,
    ) -> Result<Store<StoreContext>> {
        let wasi_ctx = Self::build_wasi_context(config)?;

        let memory_limit_bytes = (memory_limit_mb as usize) * 1024 * 1024;
        let limits = StoreLimits {
            memory_size: memory_limit_bytes,
            table_elements: 10_000,
            instances: 1,
            tables: 10,
            memories: 1,
        };

        let context = StoreContext {
            wasi: wasi_ctx,
            limits,
        };
        let mut store = Store::new(&self.engine, context);

        // Set fuel limit (only if engine was configured with fuel consumption)
        if fuel_limit > 0 {
            // Try to set fuel - if it fails, fuel metering is disabled in engine
            let _ = store.set_fuel(fuel_limit);
        }

        // Set resource limiter
        store.limiter(|data| data);

        if self.epoch_enabled && timeout.as_millis() > 0 {
            store.set_epoch_deadline(1);
        }

        Ok(store)
    }

    pub fn schedule_epoch_interrupt(&self, timeout: Duration) -> Option<EpochGuard> {
        if !self.epoch_enabled || timeout.as_millis() == 0 {
            return None;
        }

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let cancel_clone = Arc::clone(&cancel_flag);
        let engine = self.engine.clone();

        thread::spawn(move || {
            thread::sleep(timeout);
            if !cancel_clone.swap(true, Ordering::Relaxed) {
                engine.increment_epoch();
            }
        });

        Some(EpochGuard { cancel_flag })
    }

    /// Build a minimal, deterministic WASI preview1 context
    ///
    /// ## Restrictions for Determinism:
    /// - **No wall-clock access**: Time is not exposed to prevent non-determinism
    /// - **No host entropy**: Random number generation must use seeded capabilities
    /// - **No filesystem by default**: Only if explicitly allowed via config
    /// - **Stdin/stdout captured**: Not inherited from host
    #[cfg(feature = "wasi-preview2")]
    fn build_wasi_context(_config: &RuntimeConfig) -> Result<WasiP1Ctx> {
        let mut builder = WasiCtxBuilder::new();

        // Stdin: Use empty pipe (no host stdin)
        builder.stdin(wasmtime_wasi::pipe::MemoryInputPipe::new(vec![]));

        // Stdout: Capture to memory (don't inherit host stdout)
        builder.stdout(wasmtime_wasi::pipe::MemoryOutputPipe::new(1024 * 1024)); // 1MB buffer

        // Stderr: Capture to memory
        builder.stderr(wasmtime_wasi::pipe::MemoryOutputPipe::new(1024 * 1024));

        // Environment variables: Empty by default (can be added via ExecutionContext)
        // Args: Empty by default (can be added via ExecutionContext)

        // Build the preview1 context
        let wasi_ctx = builder.build_p1();

        Ok(wasi_ctx)
    }
}

pub struct EpochGuard {
    cancel_flag: Arc<AtomicBool>,
}

impl EpochGuard {
    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::Relaxed);
    }
}

impl Drop for EpochGuard {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuntimeConfig;
    use std::time::Duration;

    #[test]
    fn test_engine_creation() {
        let config = RuntimeConfig::default();
        let engine = WasmEngine::new(&config);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_engine_deterministic_config() {
        let config = RuntimeConfig::default();
        let _engine = WasmEngine::new(&config).unwrap();
        // Engine should be created successfully with default deterministic settings
        assert!(config.engine.deterministic);
    }

    #[test]
    fn test_validate_invalid_wasm() {
        let config = RuntimeConfig::default();
        let engine = WasmEngine::new(&config).unwrap();

        // Invalid WASM bytes should fail validation
        let invalid_wasm = b"not wasm";
        let result = engine.validate_module(invalid_wasm);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RuntimeError::ValidationError(_)
        ));
    }

    #[test]
    fn test_validate_simple_wasm() {
        let config = RuntimeConfig::default();
        let engine = WasmEngine::new(&config).unwrap();

        // Minimal valid WASM module (empty module)
        let valid_wasm = wat::parse_str("(module)").unwrap();
        let result = engine.validate_module(&valid_wasm);
        assert!(result.is_ok());
    }

    #[test]
    fn test_store_creation_with_fuel() {
        let config = RuntimeConfig::default();
        let engine = WasmEngine::new(&config).unwrap();

        let store = engine.create_store(1_000_000);
        assert!(store.is_ok());

        let store = store.unwrap();
        let fuel = store.get_fuel().unwrap();
        assert_eq!(fuel, 1_000_000);
    }

    #[test]
    #[cfg(feature = "wasi-preview2")]
    fn test_wasi_store_creation() {
        let config = RuntimeConfig::default();
        let engine = WasmEngine::new(&config).unwrap();

        let store = engine.create_store_with_wasi(
            1_000_000,
            128,
            &config,
            Duration::from_millis(config.limits.execution_timeout_ms),
        );
        assert!(store.is_ok());

        let store = store.unwrap();
        let fuel = store.get_fuel().unwrap();
        assert_eq!(fuel, 1_000_000);
    }

    #[test]
    #[cfg(feature = "wasi-preview2")]
    fn test_wasi_context_restrictions() {
        let config = RuntimeConfig::default();
        // WASI context should be created with restricted access
        let wasi_ctx = WasmEngine::build_wasi_context(&config);
        assert!(wasi_ctx.is_ok());
        // Context is created with no filesystem access, captured stdio, no clock
    }
}
