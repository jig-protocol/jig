//! Executes `jig:block` components (JEP-0006, first-slice step 4).
//!
//! This is the one execution path the design commits server, client and CLI to (decision A4).
//! It sits beside the byte-payload ABI (`payload.rs`) until that is deleted.
//!
//! What it does, per decisions A2 and A3:
//!
//! - It refuses a component that fails jig-core's `jig-det-1` profile before compiling it.
//! - It runs on its own engine, built from the same deterministic configuration as
//!   `crate::engine`'s (fuel, NaN canonicalization, WebAssembly 2.0 minus SIMD, stack limit,
//!   pooling allocator). On top it adds only the component model, and turns component-model
//!   async support off.
//! - It classifies every run as one of three outcomes:
//!   - [`RunOutcome::Ok`] for the export's `ok`;
//!   - [`RunOutcome::Error`] for the export's `err`, or a trap that any conforming engine raises
//!     at the same point;
//!   - [`RunOutcome::Incomplete`] for fuel or stack exhaustion or a host fault. These depend on
//!     the engine, so they assert nothing about the block and are never compared.
//!
//! Only the `renderer` world is wired up here. The `bot` world comes with lane C's host
//! interfaces.
//!
//! Every run is bounded three ways, all per store:
//!
//! - **Fuel**, the bound that decides receipts. wasmtime 49.0.3 charges bulk memory operations
//!   per byte, so fuel tracks CPU closely, but only as closely as its cost table does.
//! - **A wall-clock deadline**, from `crate::engine`'s epoch ticker, as a backstop for work
//!   fuel prices too low: a cost-table gap, host-side canonical-ABI copies, a slow or loaded
//!   machine. This engine runs its own ticker. Missing the deadline is
//!   [`IncompleteReason::DeadlineExceeded`].
//! - **A memory cap** of the renderer's `max_memory_pages`, enforced by a resource limiter on top
//!   of the validator's check of declared maxima.

use jig_core::component_validation::{BlockWorld, ComponentProfile, validate_component};
use jig_core::grant::Grant;
use std::time::Duration;

use wasmtime::component::Component;
use wasmtime::{Engine, Store, StoreLimits, StoreLimitsBuilder, Trap};

use crate::config::RuntimeConfig;
use crate::engine::{EPOCH_TICK, EpochTicker, deadline_ticks, deterministic_config};
use crate::error::{Result, RuntimeError};
use crate::grant_linker::GrantLinkers;
use crate::identity::EngineIdentity;

wasmtime::component::bindgen!({
    world: "renderer",
    path: "../jig-spec/wit/jig-block",
    additional_derives: [PartialEq, Eq],
});

pub use jig::block::types::{BlockError, Hlc, Invocation, Payload};

/// Why a run asserts nothing about the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncompleteReason {
    /// The fuel limit ran out. Fuel is not portable across engines or versions.
    FuelExhausted,
    /// The native stack ran out. Stack use differs by architecture and engine.
    StackExhausted,
    /// The wall-clock deadline passed. Speed differs by machine and load.
    DeadlineExceeded,
    /// The host failed outside the guest's control.
    HostFault(String),
}

/// A comparable failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorOutcome {
    /// The export returned `err`.
    Guest(BlockError),
    /// The guest trapped in a way every conforming engine reproduces (`unreachable`, an
    /// out-of-bounds access, an integer divide by zero, and so on). The string is the trap code.
    Trap(String),
}

/// The outcome of one run (decision A3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Ok(Payload),
    Error(ErrorOutcome),
    Incomplete(IncompleteReason),
}

impl RunOutcome {
    /// Whether two executors must agree on this outcome.
    pub fn is_comparable(&self) -> bool {
        !matches!(self, RunOutcome::Incomplete(_))
    }
}

/// The bounds on one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderLimits {
    /// Fuel for the run.
    pub fuel: u64,
    /// Wall-clock time for the run, to within one epoch tick (10 ms) over.
    pub timeout: Duration,
}

/// One run: its outcome and the fuel it used. Fuel is local telemetry, never compared.
#[derive(Debug, Clone)]
pub struct RenderRun {
    pub outcome: RunOutcome,
    pub fuel_used: u64,
}

/// A validated, compiled renderer, ready to run many times.
pub struct CompiledRenderer {
    pre: RendererPre<HostState>,
    max_memory_pages: u32,
    component_hash: String,
}

impl CompiledRenderer {
    /// `blake3:<hex>` of the component bytes.
    pub fn component_hash(&self) -> &str {
        &self.component_hash
    }
}

impl std::fmt::Debug for CompiledRenderer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRenderer")
            .field("component_hash", &self.component_hash)
            .finish_non_exhaustive()
    }
}

struct HostState {
    limits: StoreLimits,
}

/// Compiles and runs `jig:block` components under the `jig-det-1` profile.
pub struct ComponentRuntime {
    engine: Engine,
    /// One linker per grant shape; see [`crate::grant_linker`].
    linkers: GrantLinkers<HostState>,
    /// Advances `engine`'s epoch for render deadlines; stops when the runtime drops.
    _epoch_ticker: EpochTicker,
}

impl ComponentRuntime {
    pub fn new() -> Result<Self> {
        let mut config = deterministic_config(&RuntimeConfig::default())?;
        config.wasm_component_model(true);
        // A narrowing, not a feature: the allowlist already leaves the component-model async
        // features off, and this also drops wasmtime's task machinery for them.
        config.concurrency_support(false);
        let engine = Engine::new(&config)
            .map_err(|e| RuntimeError::InternalError(format!("component engine: {e}")))?;

        let linkers = GrantLinkers::new(&engine);
        let _epoch_ticker = EpochTicker::start(engine.clone(), EPOCH_TICK)?;
        Ok(Self {
            engine,
            linkers,
            _epoch_ticker,
        })
    }

    /// The identity a receipt names for runs on this engine.
    pub fn engine_identity(&self) -> EngineIdentity {
        EngineIdentity::of(&self.engine)
    }

    /// Validate `bytes` against `jig-det-1` for the `renderer` world and `grant`, then compile it.
    ///
    /// Only `grant`'s imports may be imported, and the linker defines only those. No host
    /// interface has a provider yet, so a renderer whose grant names an import is refused at link
    /// time.
    pub fn compile_renderer(
        &self,
        bytes: &[u8],
        grant: &Grant,
        max_memory_pages: u32,
    ) -> Result<CompiledRenderer> {
        let import_names = grant.import_names();
        let granted: Vec<&str> = import_names.iter().map(String::as_str).collect();
        let report = validate_component(
            bytes,
            &ComponentProfile {
                world: BlockWorld::Renderer,
                granted: &granted,
                max_memory_pages,
            },
        )
        .map_err(|e| RuntimeError::ValidationError(e.to_string()))?;
        if let Some(v) = report.violations.first() {
            return Err(RuntimeError::ValidationError(format!(
                "component fails jig-det-1: {v}"
            )));
        }
        let component = Component::new(&self.engine, bytes)
            .map_err(|e| RuntimeError::InvalidWasm(e.to_string()))?;
        let component_hash = format!("blake3:{}", blake3::hash(bytes).to_hex());
        let pre = self
            .linkers
            .instantiate_pre(&component_hash, &component, grant)?;
        let pre =
            RendererPre::new(pre).map_err(|e| RuntimeError::InstantiationError(e.to_string()))?;
        Ok(CompiledRenderer {
            pre,
            max_memory_pages,
            component_hash,
        })
    }

    /// Run `render` once, in a fresh instance.
    pub fn render(
        &self,
        renderer: &CompiledRenderer,
        invocation: &Invocation,
        limits: &RenderLimits,
    ) -> RenderRun {
        let fuel = limits.fuel;
        let mut store = match self.store(renderer.max_memory_pages, limits) {
            Ok(store) => store,
            Err(e) => return host_fault(e.to_string(), 0),
        };

        let call = renderer
            .pre
            .instantiate(&mut store)
            .and_then(|r| r.jig_block_render().call_render(&mut store, invocation));
        let fuel_used = fuel.saturating_sub(store.get_fuel().unwrap_or(0));
        let outcome = match call {
            Ok(Ok(payload)) => RunOutcome::Ok(payload),
            Ok(Err(e)) => RunOutcome::Error(ErrorOutcome::Guest(e)),
            Err(e) => classify(e),
        };
        RenderRun { outcome, fuel_used }
    }

    /// A fresh store carrying all three bounds (see the module docs).
    fn store(&self, max_memory_pages: u32, limits: &RenderLimits) -> Result<Store<HostState>> {
        let memory_bytes = max_memory_pages as usize * 64 * 1024;
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits: StoreLimitsBuilder::new().memory_size(memory_bytes).build(),
            },
        );
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(limits.fuel)
            .map_err(|e| RuntimeError::InternalError(format!("setting fuel: {e}")))?;
        store.set_epoch_deadline(deadline_ticks(limits.timeout));
        Ok(store)
    }
}

fn host_fault(detail: String, fuel_used: u64) -> RenderRun {
    RenderRun {
        outcome: RunOutcome::Incomplete(IncompleteReason::HostFault(detail)),
        fuel_used,
    }
}

/// Sort a wasmtime error into a comparable trap or an incomplete run.
fn classify(err: wasmtime::Error) -> RunOutcome {
    match err.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => RunOutcome::Incomplete(IncompleteReason::FuelExhausted),
        Some(Trap::StackOverflow) => RunOutcome::Incomplete(IncompleteReason::StackExhausted),
        Some(Trap::Interrupt) => RunOutcome::Incomplete(IncompleteReason::DeadlineExceeded),
        Some(Trap::AllocationTooLarge) => {
            RunOutcome::Incomplete(IncompleteReason::HostFault(err.to_string()))
        }
        Some(trap) => RunOutcome::Error(ErrorOutcome::Trap(trap.to_string())),
        None => RunOutcome::Incomplete(IncompleteReason::HostFault(format!("{err:#}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A component whose one core module runs `body` from its start function.
    fn component_with_core_start(body: &str) -> Vec<u8> {
        wat::parse_str(format!(
            r#"(component
                (core module $m (func $f {body}) (start $f))
                (core instance (instantiate $m)))"#
        ))
        .expect("test component WAT parses")
    }

    // The engine itself refuses SIMD; the validator is not the only gate. `Component::new` is
    // called directly so that `compile_renderer`'s validation does not get there first.
    #[test]
    fn the_component_engine_refuses_simd() {
        let runtime = ComponentRuntime::new().expect("runtime builds");
        let simd = component_with_core_start("(drop (v128.const i64x2 0 0))");
        let err = Component::new(&runtime.engine, simd).expect_err("SIMD must be refused");
        assert!(format!("{err:#}").contains("SIMD"), "{err:#}");
    }

    #[test]
    fn the_component_engine_runs_out_of_fuel() {
        let runtime = ComponentRuntime::new().expect("runtime builds");
        let spin = component_with_core_start("(loop $l (br $l))");
        let component = Component::new(&runtime.engine, spin).expect("compiles");
        let mut store = runtime
            .store(
                1,
                &RenderLimits {
                    fuel: 10_000,
                    timeout: Duration::from_secs(60),
                },
            )
            .expect("store");
        let err = runtime
            .linkers
            .for_grant(&Grant::empty())
            .expect("linker")
            .instantiate(&mut store, &component)
            .map(|_| ())
            .expect_err("an endless loop must stop");
        assert_eq!(
            classify(err),
            RunOutcome::Incomplete(IncompleteReason::FuelExhausted)
        );
    }

    // The store's memory cap holds even where the validator's check of declared maxima is not
    // in the way: the module may grow to 16 pages, the store allows 1.
    #[test]
    fn the_store_caps_memory_growth() {
        let runtime = ComponentRuntime::new().expect("runtime builds");
        let grow = wat::parse_str(
            r#"(component
                (core module $m
                    (memory 1 16)
                    (func $f
                        (if (i32.eq (memory.grow (i32.const 4)) (i32.const -1))
                            (then unreachable)))
                    (start $f))
                (core instance (instantiate $m)))"#,
        )
        .expect("test component WAT parses");
        let component = Component::new(&runtime.engine, grow).expect("compiles");
        let limits = RenderLimits {
            fuel: 1_000_000,
            timeout: Duration::from_secs(60),
        };
        let mut capped = runtime.store(1, &limits).expect("store");
        let err = runtime
            .linkers
            .for_grant(&Grant::empty())
            .expect("linker")
            .instantiate(&mut capped, &component)
            .map(|_| ())
            .expect_err("growth past the cap must fail");
        assert!(
            matches!(classify(err), RunOutcome::Error(ErrorOutcome::Trap(_))),
            "the start function traps when memory.grow returns -1"
        );
        let mut roomy = runtime.store(16, &limits).expect("store");
        runtime
            .linkers
            .for_grant(&Grant::empty())
            .expect("linker")
            .instantiate(&mut roomy, &component)
            .expect("growth within the cap succeeds");
    }
}
