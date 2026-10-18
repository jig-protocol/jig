//! Executes `jig:block` components (JEP-0006, first-slice step 4).
//!
//! This is the one execution path the design commits server, client and CLI to (decision A4).
//! It sits beside the byte-payload ABI (`payload.rs`) until that is deleted.
//!
//! What it does, per decisions A2 and A3:
//!
//! - It refuses a component that fails jig-core's `jig-det-1` profile before compiling it.
//! - It runs on its own engine. The engine's feature set is the profile's: WebAssembly 2.0 minus
//!   SIMD, plus the component model, with component-model async off and NaN canonicalization and
//!   fuel on. It does not share [`crate::engine`]'s engine, whose feature set has no component
//!   model.
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
//! Termination is by fuel alone. A renderer imports nothing that can block, so fuel bounds every
//! run. A wall-clock guard would be liveness only; it can join when the engine's epoch ticker is
//! shared.

use jig_core::component_validation::{BlockWorld, ComponentProfile, validate_component};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder, Trap, WasmFeatures};

use crate::error::{Result, RuntimeError};
use crate::identity::EngineIdentity;

wasmtime::component::bindgen!({
    world: "renderer",
    path: "../jig-spec/wit/jig-block",
    additional_derives: [PartialEq, Eq],
});

pub use jig::block::types::{BlockError, Hlc, Invocation, Payload};

/// The version of `jig:block/types` the host links as an empty instance.
const TYPES_INTERFACE: &str = "jig:block/types@0.1.0";

/// Why a run asserts nothing about the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncompleteReason {
    /// The fuel limit ran out. Fuel is not portable across engines or versions.
    FuelExhausted,
    /// The native stack ran out. Stack use differs by architecture and engine.
    StackExhausted,
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
    linker: Linker<HostState>,
}

impl ComponentRuntime {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.cranelift_nan_canonicalization(true);
        config.concurrency_support(false);
        // Exactly the profile's features. wasmtime 49 enables most WebAssembly 3.0 proposals and
        // component-model async by default.
        config.wasm_features(WasmFeatures::all(), false);
        config.wasm_features(
            WasmFeatures::WASM2
                .difference(WasmFeatures::SIMD)
                .union(WasmFeatures::COMPONENT_MODEL),
            true,
        );
        let engine = Engine::new(&config)
            .map_err(|e| RuntimeError::InternalError(format!("component engine: {e}")))?;

        let mut linker = Linker::new(&engine);
        // `jig:block/types` carries only types; every host links it as an empty instance.
        linker
            .instance(TYPES_INTERFACE)
            .map_err(|e| RuntimeError::InternalError(format!("linking {TYPES_INTERFACE}: {e}")))?;
        Ok(Self { engine, linker })
    }

    /// The identity a receipt names for runs on this engine.
    pub fn engine_identity(&self) -> EngineIdentity {
        EngineIdentity::of(&self.engine)
    }

    /// Validate `bytes` against `jig-det-1` for the `renderer` world, then compile it.
    pub fn compile_renderer(
        &self,
        bytes: &[u8],
        max_memory_pages: u32,
    ) -> Result<CompiledRenderer> {
        let report = validate_component(
            bytes,
            &ComponentProfile {
                world: BlockWorld::Renderer,
                granted: &[],
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
        let pre = self
            .linker
            .instantiate_pre(&component)
            .and_then(RendererPre::new)
            .map_err(|e| RuntimeError::InstantiationError(e.to_string()))?;
        Ok(CompiledRenderer {
            pre,
            max_memory_pages,
            component_hash: format!("blake3:{}", blake3::hash(bytes).to_hex()),
        })
    }

    /// Run `render` once, in a fresh instance.
    pub fn render(
        &self,
        renderer: &CompiledRenderer,
        invocation: &Invocation,
        fuel: u64,
    ) -> RenderRun {
        let memory_bytes = renderer.max_memory_pages as usize * 64 * 1024;
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits: StoreLimitsBuilder::new().memory_size(memory_bytes).build(),
            },
        );
        store.limiter(|s| &mut s.limits);
        if let Err(e) = store.set_fuel(fuel) {
            return host_fault(format!("setting fuel: {e}"), 0);
        }

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
        // Interrupts come from a wall clock; allocation failures from the host.
        Some(Trap::Interrupt) | Some(Trap::AllocationTooLarge) => {
            RunOutcome::Incomplete(IncompleteReason::HostFault(err.to_string()))
        }
        Some(trap) => RunOutcome::Error(ErrorOutcome::Trap(trap.to_string())),
        None => RunOutcome::Incomplete(IncompleteReason::HostFault(format!("{err:#}"))),
    }
}
