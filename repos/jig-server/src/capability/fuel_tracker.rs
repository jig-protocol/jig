//! Per-capability fuel tracking using Wasmtime Store fuel deltas.
//!
//! This module enables fine-grained metering of Wasm execution costs,
//! attributing fuel consumption to specific capabilities for billing,
//! analytics, and receipt generation.

use std::collections::BTreeMap;
use wasmtime::Store;

/// Snapshot of fuel consumption by capability and syscall count.
#[derive(Debug, Clone, Default)]
pub struct FuelSnapshot {
    pub fuel_by_capability: BTreeMap<String, u64>,
    pub syscalls: u64,
}

/// Tracks fuel consumption per capability using Wasmtime Store fuel readings.
///
/// Usage pattern:
/// ```ignore
/// let tracker = FuelTracker::default();
/// {
///     let _guard = tracker.begin(&mut store, "net:http:fetch");
///     // ... host function executes, consuming fuel ...
/// } // Guard drops here, delta computed and accumulated
/// let snapshot = tracker.snapshot();
/// ```
#[derive(Debug, Default)]
pub struct FuelTracker {
    /// Per-capability fuel accumulation.
    fuel_by_capability: BTreeMap<String, u64>,
    /// Total syscall (host function invocation) count.
    syscalls: u64,
}

impl FuelTracker {
    /// Create a new fuel tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin tracking fuel for a capability.
    ///
    /// Returns a guard that captures the fuel delta when dropped.
    ///
    /// TODO: Integrate with actual Wasmtime Store fuel tracking once runtime wiring is complete.
    pub fn begin<'a, T: 'static>(
        &'a mut self,
        _store: &'a mut Store<T>,
        capability: &str,
    ) -> FuelGuard<'a, T> {
        self.syscalls += 1;

        FuelGuard {
            tracker: self,
            capability: capability.to_string(),
            fuel_before: 0, // Placeholder until Wasmtime integration
            _phantom: std::marker::PhantomData,
        }
    }

    /// Record direct fuel consumption without a guard (for runtime-internal use).
    ///
    /// This is useful for attributing fuel to runtime initialization or other
    /// overhead that isn't tied to a specific host function invocation.
    pub fn consume_direct(&mut self, capability: &str, fuel: u64) {
        *self
            .fuel_by_capability
            .entry(capability.to_string())
            .or_insert(0) += fuel;
    }

    /// Take an immutable snapshot of current fuel consumption.
    pub fn snapshot(&self) -> FuelSnapshot {
        FuelSnapshot {
            fuel_by_capability: self.fuel_by_capability.clone(),
            syscalls: self.syscalls,
        }
    }
}

/// RAII guard that captures fuel delta on drop.
///
/// TODO: Full Wasmtime Store integration for automatic fuel delta tracking.
/// For now, this serves as the API surface for future runtime integration.
#[allow(dead_code)]
pub struct FuelGuard<'a, T: 'static> {
    tracker: &'a mut FuelTracker,
    capability: String,
    fuel_before: u64,
    _phantom: std::marker::PhantomData<&'a mut Store<T>>,
}

impl<'a, T: 'static> Drop for FuelGuard<'a, T> {
    fn drop(&mut self) {
        // TODO: Capture actual fuel delta from Wasmtime Store
        // For now, this is a no-op placeholder.
        // Real implementation will:
        // 1. Read store.fuel_consumed() or equivalent
        // 2. Compute delta = fuel_after - fuel_before
        // 3. Accumulate delta to tracker.fuel_by_capability[capability]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuel_snapshot_default_is_empty() {
        let snapshot = FuelSnapshot::default();
        assert_eq!(snapshot.fuel_by_capability.len(), 0);
        assert_eq!(snapshot.syscalls, 0);
    }

    #[test]
    fn fuel_tracker_new_is_empty() {
        let tracker = FuelTracker::new();
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.fuel_by_capability.len(), 0);
        assert_eq!(snapshot.syscalls, 0);
    }

    #[test]
    fn consume_direct_accumulates() {
        let mut tracker = FuelTracker::new();
        tracker.consume_direct("test", 100);
        tracker.consume_direct("test", 200);
        tracker.consume_direct("other", 50);

        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.fuel_by_capability.get("test"), Some(&300));
        assert_eq!(snapshot.fuel_by_capability.get("other"), Some(&50));
        // Direct consumption doesn't increment syscalls
        assert_eq!(snapshot.syscalls, 0);
    }
}
