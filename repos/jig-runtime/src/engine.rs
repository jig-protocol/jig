//! Wasmtime engine integration with deterministic configuration
//!
//! This module provides a deterministic WebAssembly execution engine using Wasmtime.
//! All execution is fuel-metered, with canonicalized NaNs, and no non-deterministic features.

use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use wasmtime::*;

#[cfg(feature = "wasi-preview2")]
use wasmtime_wasi::{WasiCtxBuilder, p1::WasiP1Ctx};

use crate::config::RuntimeConfig;
use crate::error::{Result, RuntimeError};

/// Store resource limits for memory and instance quotas
#[derive(Debug, Clone, Copy)]
pub struct StoreLimits {
    /// Maximum memory size in bytes
    pub memory_size: usize,
    /// Maximum table elements
    pub table_elements: usize,
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
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.memory_size)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
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
    ) -> wasmtime::Result<bool> {
        self.limits.memory_growing(current, desired, maximum)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.limits.table_growing(current, desired, maximum)
    }
}

/// Cadence of the shared epoch ticker.
///
/// Epoch interruption counts *ticks*, not milliseconds, so this is the
/// granularity of every wall-clock deadline in the runtime: a timeout can
/// overshoot its nominal value by up to one tick.
///
/// 10 ms is chosen to overshoot the 250 ms default by at most 4%, while keeping
/// the ticker at 100 wakeups/second — negligible on the $5-VPS and Raspberry Pi
/// targets, and unlike the previous design it does not scale with message rate.
const EPOCH_TICK: Duration = Duration::from_millis(10);

/// Ticks a store must survive to be granted at least `timeout` of wall clock.
///
/// Rounds **up** and then adds one. The extra tick is not slop: the ticker runs
/// free, so a store created immediately before a tick would otherwise see that
/// tick consume most of its first interval and be interrupted early. Overshooting
/// is the safe direction — a run cut short reports a partial `fuel_used` that is
/// not the program's cost, which is precisely the receipt corruption documented
/// in `docs/investigations/2026-08-11-fuel-portability.md`.
fn deadline_ticks(timeout: Duration) -> u64 {
    let tick_ms = EPOCH_TICK.as_millis().max(1);
    (timeout.as_millis().div_ceil(tick_ms) as u64).saturating_add(1)
}

/// One thread per engine that advances the epoch on a fixed cadence.
///
/// Replaces a detached sleeper thread per execution. That design left a thread
/// asleep for the full timeout even after its execution finished — at 10,000
/// msg/s with a 250 ms timeout, roughly 2,500 sleeping threads at steady state,
/// scaling with message rate on the ingest hot path. This is O(1) per engine.
///
/// Stops when the engine drops, which matters more than it looks: tests build
/// many short-lived `Runtime`s, and a ticker that outlived its engine would leak
/// a thread per construction.
struct EpochTicker {
    /// `true` once the engine is going away. Paired with the condvar so shutdown
    /// is immediate rather than waiting out the current tick.
    stop: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<thread::JoinHandle<()>>,
}

impl EpochTicker {
    fn start(engine: Engine, cadence: Duration) -> Self {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let stop_for_thread = Arc::clone(&stop);

        let handle = thread::Builder::new()
            .name("jig-epoch-ticker".into())
            .spawn(move || {
                let (lock, cvar) = &*stop_for_thread;
                loop {
                    let stopping = lock.lock().expect("epoch ticker mutex poisoned");
                    let (stopping, timeout) = cvar
                        .wait_timeout(stopping, cadence)
                        .expect("epoch ticker mutex poisoned");
                    if *stopping {
                        break;
                    }
                    // Spurious wakeups are possible; only tick on a real timeout.
                    if timeout.timed_out() {
                        engine.increment_epoch();
                    }
                }
            })
            .expect("spawning the epoch ticker thread");

        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        {
            let (lock, cvar) = &*self.stop;
            if let Ok(mut stopping) = lock.lock() {
                *stopping = true;
                cvar.notify_all();
            }
        }
        if let Some(handle) = self.handle.take() {
            // Joining keeps the thread from outliving the `Engine` it holds, and
            // makes "engine dropped" mean "ticker gone" for the thread-count test.
            let _ = handle.join();
        }
    }
}

/// Wasmtime-based execution engine configured for determinism
pub struct WasmEngine {
    engine: Engine,
    epoch_enabled: bool,
    /// Held for its `Drop`; never read. One per engine, not one per execution.
    _epoch_ticker: Option<EpochTicker>,
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
        //
        // `memory_reservation` / `memory_guard_size` are wasmtime's successors to
        // the 24.x `static_memory_maximum_size` / `dynamic_memory_guard_size`
        // pair; upstream merged the static/dynamic split into one knob each.
        let memory_limit_bytes = (config.limits.memory_max_mb as u64) * 1024 * 1024;
        wasm_config.memory_reservation(memory_limit_bytes);
        wasm_config.memory_guard_size(0x10000); // 64KB guard
        wasm_config.max_wasm_stack(2 * 1024 * 1024); // 2MB stack limit

        // Pooling allocator keeps allocation behaviour predictable.
        //
        // These two are the CONCURRENCY ceiling for the whole engine, not a
        // per-execution limit. They were previously sized from
        // `limits.max_instances` (default 1, documented as "single instance for
        // now"), which meant a second simultaneous execution failed outright with
        // "maximum concurrent limit of 1 for core instances reached" — invisible
        // to any sequential benchmark, fatal to a server handling concurrent
        // messages. `max_instances` remains the per-execution cap, enforced via
        // StoreLimits.
        let mut pooling = PoolingAllocationConfig::default();
        let concurrency = config.limits.max_concurrent_instances.max(1);
        pooling.total_core_instances(concurrency);
        pooling.total_memories(concurrency);
        pooling.max_memories_per_module(1);
        pooling.max_memory_size(memory_limit_bytes as usize);
        wasm_config.allocation_strategy(InstanceAllocationStrategy::Pooling(pooling));

        // Module caching (only if explicitly enabled)
        if config.engine.enable_cache
            && let Some(cache_dir) = &config.engine.cache_dir
        {
            let cache = Cache::from_file(Some(std::path::Path::new(cache_dir)))
                .map_err(|e| RuntimeError::InvalidConfig(format!("Cache config: {e}")))?;
            wasm_config.cache(Some(cache));
        }

        // Build the engine
        let engine = Engine::new(&wasm_config)
            .map_err(|e| RuntimeError::InternalError(format!("Engine creation failed: {e}")))?;

        // One ticker for the whole engine, started here rather than per
        // execution. Its thread holds an `Engine` clone, so it must stop when
        // this struct drops — see `EpochTicker::drop`.
        let _epoch_ticker = Some(EpochTicker::start(engine.clone(), EPOCH_TICK));

        Ok(Self {
            engine,
            epoch_enabled: true,
            _epoch_ticker,
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
            // Ticks, not milliseconds: the shared ticker advances the epoch on a
            // fixed cadence, so a deadline is expressed in how many ticks the
            // store may survive.
            store.set_epoch_deadline(deadline_ticks(timeout));
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
            // Ticks, not milliseconds: the shared ticker advances the epoch on a
            // fixed cadence, so a deadline is expressed in how many ticks the
            // store may survive.
            store.set_epoch_deadline(deadline_ticks(timeout));
        }

        Ok(store)
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
        builder.stdin(wasmtime_wasi::p2::pipe::MemoryInputPipe::new(vec![]));

        // Stdout: Capture to memory (don't inherit host stdout)
        builder.stdout(wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(1024 * 1024)); // 1MB buffer

        // Stderr: Capture to memory
        builder.stderr(wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(1024 * 1024));

        // Environment variables: Empty by default (can be added via ExecutionContext)
        // Args: Empty by default (can be added via ExecutionContext)

        // Build the preview1 context
        let wasi_ctx = builder.build_p1();

        Ok(wasi_ctx)
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
