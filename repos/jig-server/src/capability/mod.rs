//! Capability-based security system for block execution.
//!
//! Implements object-capability security: no ambient authority,
//! all access controlled by explicit capability tokens.

pub mod fuel_tracker;
pub mod registry;
pub mod token;

pub use fuel_tracker::{FuelSnapshot, FuelTracker};
pub use registry::CapabilityRegistry;
pub use token::CapabilityToken;
