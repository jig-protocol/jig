//! Tests for per-capability fuel tracking.

use jig_server::capability::FuelTracker;

#[test]
fn fuel_tracker_tracks_per_capability_via_direct_consumption() {
    let mut tracker = FuelTracker::new();

    // Simulate capability fuel consumption
    tracker.consume_direct("net:http:fetch", 1_000);
    tracker.consume_direct("storage:write", 2_500);
    tracker.consume_direct("net:http:fetch", 500);

    let snapshot = tracker.snapshot();

    assert_eq!(
        snapshot.fuel_by_capability.get("net:http:fetch"),
        Some(&1_500)
    );
    assert_eq!(
        snapshot.fuel_by_capability.get("storage:write"),
        Some(&2_500)
    );
    // Direct consumption doesn't increment syscalls
    assert_eq!(snapshot.syscalls, 0);
}

#[test]
fn fuel_tracker_accumulates_per_capability() {
    let mut tracker = FuelTracker::new();

    // Multiple consumptions for same capability
    tracker.consume_direct("core:compute", 100);
    tracker.consume_direct("core:compute", 200);
    tracker.consume_direct("log:emit", 50);

    let snapshot = tracker.snapshot();

    assert_eq!(snapshot.fuel_by_capability.get("core:compute"), Some(&300));
    assert_eq!(snapshot.fuel_by_capability.get("log:emit"), Some(&50));
}

#[test]
fn fuel_tracker_handles_zero_consumption() {
    let mut tracker = FuelTracker::new();

    tracker.consume_direct("noop:capability", 0);

    let snapshot = tracker.snapshot();

    // Zero fuel should still be recorded
    assert_eq!(snapshot.fuel_by_capability.get("noop:capability"), Some(&0));
}

#[test]
fn fuel_tracker_consume_direct_doesnt_increment_syscalls() {
    let mut tracker = FuelTracker::new();

    // Runtime-internal fuel consumption (e.g., initialization overhead)
    tracker.consume_direct("runtime:init", 500);

    let snapshot = tracker.snapshot();

    assert_eq!(snapshot.fuel_by_capability.get("runtime:init"), Some(&500));
    // Direct consumption doesn't increment syscall counter
    assert_eq!(snapshot.syscalls, 0);
}

#[test]
fn fuel_tracker_snapshot_is_immutable() {
    let mut tracker = FuelTracker::new();

    tracker.consume_direct("test:cap", 1_000);

    let snapshot1 = tracker.snapshot();
    assert_eq!(snapshot1.fuel_by_capability.get("test:cap"), Some(&1_000));

    // Add more fuel usage
    tracker.consume_direct("test:cap", 500);

    // Previous snapshot unchanged
    assert_eq!(snapshot1.fuel_by_capability.get("test:cap"), Some(&1_000));

    // New snapshot reflects updates
    let snapshot2 = tracker.snapshot();
    assert_eq!(snapshot2.fuel_by_capability.get("test:cap"), Some(&1_500));
}
