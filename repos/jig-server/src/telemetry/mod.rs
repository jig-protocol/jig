//! Telemetry modules (feature = "telemetry_v0_2").

pub mod timings;

pub use timings::{Percentiles, TimingsRecorder, TimingsSnapshot};
