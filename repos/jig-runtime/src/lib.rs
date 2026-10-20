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
//! - `wasi-preview2` (default): Enable WASI preview1 with minimal surfaces (name kept for compatibility)
//! - `component-model`: Enable WebAssembly Component Model support
//! - `tracing`: Enable structured logging with tracing

// Public API modules
pub mod api;
pub mod component;
pub mod config;
pub mod error;
pub mod grant_linker;
pub mod payload;

// Internal implementation modules
mod engine;
mod identity;
pub(crate) mod receipt;
mod trap;

// Re-export primary types
pub use api::{BlockPackage, ExecutionContext, Limits, Outcome, Runtime};
pub use config::{PricingConfig, RuntimeConfig};
pub use engine::MAX_WASM_STACK;
pub use error::{Result, RuntimeError};

pub use identity::{EngineIdentity, FUEL_SCHEDULE_VERSION, WASMTIME_VERSION};
pub use payload::{CompiledBlock, PayloadOutput, RC_OUTPUT_TOO_SMALL};
pub use receipt::{
    CapabilityCall, ExecutionOutcome, ModuleHash, Receipt, ReceiptBuilder, ReceiptError,
    ReceiptPricing,
};
