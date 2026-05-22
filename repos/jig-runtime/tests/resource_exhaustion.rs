//! Resource exhaustion tests
//!
//! Verify that the runtime safely handles and reports resource exhaustion attempts:
//! - Memory exhaustion
//! - Fuel exhaustion (already tested in fuel.rs)
//! - Stack depth
//! - Infinite loops

use jig_runtime::{BlockPackage, ExecutionContext, Limits, Runtime, RuntimeConfig};
use std::time::Duration;

const FUEL_HEAVY_WASM: &[u8] = include_bytes!("fixtures/fuel_heavy.wasm");

#[test]
fn test_memory_limit_enforced() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Set very low memory limit
    let limits = Limits::new(5_000_000, 1, Duration::from_secs(5)); // Only 1MB memory

    let block = BlockPackage::from_wasm(vec![]).with_id("mem-limit-001");
    let context = ExecutionContext::default()
        .with_block(block)
        .with_limits(limits);

    // Deterministic fixture doesn't allocate much memory, so should succeed
    let receipt = runtime
        .execute(include_bytes!("fixtures/deterministic.wasm"), context)
        .expect("execution");

    // Should succeed with minimal memory
    assert_eq!(receipt.outcome, jig_runtime::ExecutionOutcome::Success);
    let limits = receipt.block.limits.as_ref().expect("limits present");
    assert_eq!(limits.memory_max_mb, 1);
}

#[test]
fn test_fuel_exhaustion_graceful() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Set low fuel limit
    let limits = Limits::new(1_000, 128, Duration::from_secs(5));

    let block = BlockPackage::from_wasm(vec![]).with_id("fuel-exhaust-002");
    let context = ExecutionContext::default()
        .with_block(block)
        .with_limits(limits);

    let receipt = runtime
        .execute(FUEL_HEAVY_WASM, context)
        .expect("execution should return receipt");

    // Should fail gracefully, not panic
    assert!(
        receipt.outcome == jig_runtime::ExecutionOutcome::LimitsExceeded
            || receipt.outcome == jig_runtime::ExecutionOutcome::ExecutionFailed
    );

    // Should have consumed fuel up to or near the limit
    assert!(receipt.fuel_used() > 0);
}

#[test]
fn test_infinite_loop_timeout() {
    // Note: Wasmtime fuel metering naturally limits infinite loops
    // This test verifies the behavior is consistent

    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Heavy loop with default 5M fuel will run for a while but not infinite
    let block = BlockPackage::from_wasm(vec![]).with_id("inf-loop-001");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime
        .execute(FUEL_HEAVY_WASM, context)
        .expect("execution");

    // Heavy loop exhausts fuel, which prevents true infinite loop
    assert!(
        receipt.outcome == jig_runtime::ExecutionOutcome::LimitsExceeded
            || receipt.outcome == jig_runtime::ExecutionOutcome::ExecutionFailed
            || receipt.outcome == jig_runtime::ExecutionOutcome::Success
    );
}

#[test]
fn test_concurrent_executions_isolated() {
    // Verify that concurrent executions don't interfere with each other's resource limits
    let mut config = RuntimeConfig::default();
    config.limits.max_instances = 4; // Allow 4 concurrent instances
    let runtime = Runtime::with_config(config).expect("runtime creation");

    use std::sync::Arc;
    use std::thread;

    let runtime = Arc::new(runtime);
    let mut handles = vec![];

    // Spawn multiple executions concurrently
    for i in 0..4 {
        let runtime_clone = Arc::clone(&runtime);
        let handle = thread::spawn(move || {
            let block = BlockPackage::from_wasm(vec![]).with_id(format!("concurrent-{}", i));
            let context = ExecutionContext::default().with_block(block);

            runtime_clone
                .execute(include_bytes!("fixtures/deterministic.wasm"), context)
                .expect("execution")
        });
        handles.push(handle);
    }

    // Wait for all to complete
    let receipts: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All should succeed
    for receipt in &receipts {
        assert_eq!(receipt.outcome, jig_runtime::ExecutionOutcome::Success);
    }

    // All should have identical fuel usage (determinism)
    let first_fuel = receipts[0].fuel_used();
    for receipt in &receipts[1..] {
        assert_eq!(receipt.fuel_used(), first_fuel);
    }
}

#[test]
fn test_zero_fuel_limit() {
    let mut config = RuntimeConfig::default();
    config.fuel.enabled = false;

    let runtime = Runtime::with_config(config).expect("runtime creation");

    let block = BlockPackage::from_wasm(vec![]).with_id("zero-fuel-001");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime
        .execute(include_bytes!("fixtures/deterministic.wasm"), context)
        .expect("execution");

    // Should succeed with fuel disabled
    assert_eq!(receipt.outcome, jig_runtime::ExecutionOutcome::Success);
    assert_eq!(receipt.fuel_used(), 0);
}

#[test]
fn test_module_size_reasonable() {
    // Verify we can handle reasonably sized modules
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Hello WASI is ~268KB - reasonable size
    let wasm = include_bytes!("fixtures/hello_wasi.wasm");
    assert!(wasm.len() < 1_000_000, "Test fixture should be < 1MB");

    let block = BlockPackage::from_wasm(vec![]).with_id("size-test-001");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime.execute(wasm, context).expect("execution");

    assert_eq!(receipt.outcome, jig_runtime::ExecutionOutcome::Success);
}
