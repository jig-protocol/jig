//! Which engine produced a measurement.
//!
//! Fuel is only comparable against a number from the same engine, built the
//! same way, metering under the same schedule. Wasmtime has changed its own
//! cost schedule between versions (bulk-memory operations now bill per byte),
//! so a receipt that records `fuel_used` must record this beside it. See
//! `docs/investigations/2026-08-11-fuel-portability.md`.

use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// The wasmtime version this crate was built against, as resolved in
/// `Cargo.lock` (see `build.rs`).
pub const WASMTIME_VERSION: &str = env!("JIG_WASMTIME_VERSION");

/// Version of the fuel schedule receipts are metered under.
///
/// jig does not load a cost schedule of its own: wasm fuel is wasmtime's
/// built-in per-operator metering. This names that schedule as jig has
/// observed it, and is a constant so that no configuration can make a receipt
/// claim a schedule the engine is not running.
///
/// Bump it whenever the fuel a given operation costs changes. The
/// golden-receipt tests pin fuel numbers, so a wasmtime upgrade that moves them
/// fails there first.
///
/// 0.1.0 -> 0.2.0: wasmtime 47 bills bulk memory operations (`memory.copy`,
/// `memory.fill`) per byte where 24.x charged a flat rate. Per-operator costs
/// for ordinary compute are unchanged. A block doing large memcpys is
/// materially more expensive under 0.2.0: the WASI reference fixture went from
/// 1713 to 18098 fuel, all of it the 16 KiB memcpy in `_start`. This is the
/// metering half of the fix for RUSTSEC-2026-0223.
pub const FUEL_SCHEDULE_VERSION: &str = "0.2.0";

/// Identity of the engine a [`crate::Runtime`] executes with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineIdentity {
    /// wasmtime crate version, e.g. `49.0.3`.
    pub wasmtime: String,
    /// `blake3:<hex>` over wasmtime's precompile-compatibility hash, which
    /// covers the wasmtime version, compilation target, Cranelift flags (NaN
    /// canonicalization among them), enabled wasm features and tunables (fuel,
    /// epoch interruption, memory layout). Two engines with the same
    /// fingerprint compile and meter a module identically.
    pub config_fingerprint: String,
    /// [`FUEL_SCHEDULE_VERSION`].
    pub fuel_schedule: String,
}

impl EngineIdentity {
    pub(crate) fn of(engine: &wasmtime::Engine) -> Self {
        let mut hasher = Blake3Hasher(blake3::Hasher::new());
        engine.precompile_compatibility_hash().hash(&mut hasher);
        Self {
            wasmtime: WASMTIME_VERSION.to_string(),
            config_fingerprint: format!("blake3:{}", hasher.0.finalize().to_hex()),
            fuel_schedule: FUEL_SCHEDULE_VERSION.to_string(),
        }
    }
}

/// Feeds a `Hash` impl into blake3.
///
/// `std`'s `DefaultHasher` is not guaranteed stable across Rust releases, so it
/// would make the fingerprint move with the toolchain. `finish` is unused.
struct Blake3Hasher(blake3::Hasher);

impl Hasher for Blake3Hasher {
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finish(&self) -> u64 {
        0
    }
}
