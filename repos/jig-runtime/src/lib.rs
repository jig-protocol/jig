//! # Jig Runtime
//!
//! Executes `jig:block` components (JEP-0006) under the determinism profile `jig-det-1`.
//!
//! ## Features
//!
//! - **Deterministic execution**: fuel metering, canonicalized NaNs, WebAssembly 2.0 without
//!   SIMD, plus the component model. No threads, no WASI.
//! - **Capability security**: a component links only the host interfaces its grant names.
//! - **Comparable outcomes**: every run is `ok`, `error` or `incomplete`, with a hash over the
//!   canonical encoding of what it returned (see [`component`]).
//! - **Native and Pulley backends**: outcomes must not depend on the choice.
//!
//! ## Quick Start
//!
//! ```no_run
//! use jig_core::grant::Grant;
//! use jig_runtime::component::{ComponentRuntime, Invocation, RenderLimits};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let invocation: Invocation = unimplemented!();
//! let runtime = ComponentRuntime::new()?;
//! let bytes = std::fs::read("renderer.component.wasm")?;
//! let renderer = runtime.compile_renderer(&bytes, &Grant::empty(), 256)?;
//! let run = runtime.render(
//!     &renderer,
//!     &invocation,
//!     &RenderLimits { fuel: 50_000_000, timeout: std::time::Duration::from_millis(250) },
//! );
//! println!("{:?} (fuel used: {})", run.outcome, run.fuel_used);
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature Flags
//!
//! - `component-model`: Enable WebAssembly Component Model support

// Public API modules
pub mod component;
pub mod config;
pub mod error;
pub mod grant_linker;

// Internal implementation modules
mod engine;
mod identity;

// Re-export primary types
pub use config::{PricingConfig, RuntimeConfig};
pub use engine::MAX_WASM_STACK;
pub use error::{Result, RuntimeError};

pub use identity::{EngineIdentity, FUEL_SCHEDULE_VERSION, WASMTIME_VERSION};
