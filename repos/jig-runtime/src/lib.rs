//! # Jig Runtime
//!
//! Unified WASM runtime for Jig Protocol implementing the Executable Internet specification.
//!
//! ## Features
//!
//! - **Deterministic execution**: Fuel-metered, canonicalized floating point, no threads
//! - **WASI support**: Preview1 with automatic detection and deterministic sandboxing
//! - **Capability security**: Closed-by-default with explicit allowlists
//! - **Instrumented fuel**: Per-capability tracking for pricing-compatible receipts
//! - **Receipt v0.2**: Deterministic execution receipts with counters, timings, and outcomes
//! - **Structured tracing**: Execution phases logged with span taxonomy (optional)
//!
//! ## Quick Start
//!
//! ```no_run
//! use jig_runtime::{Runtime, ExecutionContext};
//!
//! # fn main() -> anyhow::Result<()> {
//! let runtime = Runtime::new()?;
//! let ctx = ExecutionContext::default();
//! let wasm_bytes = std::fs::read("block.wasm")?;
//! let receipt = runtime.execute(&wasm_bytes, ctx)?;
//! println!("Fuel used: {}", receipt.fuel_used());
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature Flags
//!
//! - `deterministic` (default): Enable deterministic execution guarantees
//! - `wasi-preview2` (default): Enable WASI preview1 with minimal surfaces (name kept for compatibility)
//! - `component-model`: Enable WebAssembly Component Model support
//! - `tracing`: Enable structured logging with tracing
//! - `receipt-signing`: Enable receipt signing with ed25519

// Public API modules
pub mod api;
pub mod config;
pub mod error;
pub mod payload;
pub mod telemetry;

// Internal implementation modules
mod capabilities;
mod costs;
mod engine;
mod fuel;
pub(crate) mod receipt;

// Re-export primary types
pub use api::{BlockPackage, ExecutionContext, Limits, Outcome, Runtime};
pub use config::{PricingConfig, RuntimeConfig};
pub use costs::{CapabilityCosts, CostSchedule, InstructionCosts};
pub use error::{Result, RuntimeError};

/// Version of this crate, for recording which engine produced a measurement.
///
/// jig-runtime pins its wasmtime dependency, so this is a single-source proxy for
/// the whole engine stack — preferable to a hardcoded wasmtime version string,
/// which would be a second source of truth able to drift from Cargo.toml.
///
/// Needed because fuel is only comparable against a number from the same engine
/// at the same version: wasmtime has changed its own cost schedule (bulk-memory
/// operations now bill per byte). Anything recording `fuel_used` should record
/// this beside it.
pub const RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");
pub use fuel::{CapabilityMeterHandle, CapabilityMeterSnapshot};
pub use payload::{CompiledBlock, PayloadOutput, RC_OUTPUT_TOO_SMALL};
pub use receipt::{
    CapabilityCall, ExecutionOutcome, ModuleHash, Receipt, ReceiptBuilder, ReceiptError,
    ReceiptPricing,
};

// Legacy types (deprecated, kept for backward compatibility)
#[allow(dead_code)]
#[deprecated(since = "0.1.0", note = "Use Runtime API instead")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Success,
    Failure,
    Aborted,
}
