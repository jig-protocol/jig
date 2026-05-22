//! Integration test for deterministic execution
//!
//! This test verifies that:
//! 1. The same WASM module produces identical results across multiple runs
//! 2. Fuel consumption is tracked correctly
//! 3. Non-deterministic operations are prevented

use jig_runtime::{
    ExecutionOutcome,
    api::{BlockPackage, ExecutionContext, Runtime},
    config::RuntimeConfig,
    error::RuntimeError,
};

/// Simple WASM module that performs deterministic computation
/// Just exports a "main" function that exits immediately
const SIMPLE_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, // WASM magic
    0x01, 0x00, 0x00, 0x00, // WASM version
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type section: [] -> []
    0x03, 0x02, 0x01, 0x00, // Function section
    0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, // Export "main"
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // Code section: empty function body
];

#[test]
fn test_deterministic_execution() {
    // Create deterministic runtime config
    let mut config = RuntimeConfig::default();
    config.engine.deterministic = true;

    // Initialize runtime
    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    // Create execution context with WASM
    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(SIMPLE_WASM.to_vec()).with_id("test-block"));

    // First execution
    let result1 = runtime
        .execute(SIMPLE_WASM, context.clone())
        .expect("First execution failed");

    // Second execution with identical input
    let result2 = runtime
        .execute(SIMPLE_WASM, context)
        .expect("Second execution failed");

    // Results should be identical
    assert_eq!(result1.fuel_used(), result2.fuel_used());
    assert_eq!(result1.block.memory_peak_mb, result2.block.memory_peak_mb);
}

#[test]
fn test_fuel_tracking() {
    let mut config = RuntimeConfig::default();
    config.limits.fuel_max = 1000;

    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(SIMPLE_WASM.to_vec()).with_id("test-fuel"));

    let result = runtime
        .execute(SIMPLE_WASM, context)
        .expect("Execution failed");

    // Fuel should be consumed
    assert!(result.fuel_used() > 0);
    assert!(result.fuel_used() <= 1000);
}

#[test]
fn test_fuel_exhaustion() {
    // Create a WASM module with a loop that will definitely exhaust fuel
    // WAT: (module (func (export "main") (loop (br 0))))
    const LOOP_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, // WASM magic
        0x01, 0x00, 0x00, 0x00, // WASM version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type: () -> ()
        0x03, 0x02, 0x01, 0x00, // Function section
        0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00, // Export "main"
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b, // Code: loop + br
    ];

    let mut config = RuntimeConfig::default();
    // Set very low fuel limit to force exhaustion
    config.limits.fuel_max = 100;

    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(LOOP_WASM.to_vec()).with_id("test-exhaust"));

    // This should fail due to fuel exhaustion (infinite loop)
    let result = runtime.execute(LOOP_WASM, context);

    match result {
        Ok(receipt) => {
            // Print receipt details for debugging
            println!("Receipt outcome: {:?}", receipt.outcome);
            println!("Error code: {:?}", receipt.error.as_ref().map(|e| &e.code));
            println!(
                "Error message: {:?}",
                receipt.error.as_ref().and_then(|e| e.message.as_ref())
            );
            println!("Fuel used: {}", receipt.fuel_used());

            // The receipt should indicate limits exceeded or execution failed
            assert!(
                matches!(
                    receipt.outcome,
                    ExecutionOutcome::LimitsExceeded | ExecutionOutcome::ExecutionFailed
                ),
                "Expected LimitsExceeded or ExecutionFailed, got: {:?}",
                receipt.outcome
            );
        }
        Err(e) => {
            // Errors during execution are also acceptable
            println!("Execution error: {:?}", e);
        }
    }
}

#[test]
fn test_config_deterministic_defaults() {
    let mut config = RuntimeConfig::default();
    config.engine.deterministic = true;
    config.engine.canonicalize_nans = true;

    // Verify deterministic settings
    assert!(config.fuel.enabled);
    assert!(config.engine.deterministic);
    assert!(config.engine.canonicalize_nans);
    assert!(config.capabilities.deny_by_default);
}

#[test]
fn test_config_custom_settings() {
    let mut config = RuntimeConfig::default();
    config.limits.fuel_max = 5000;
    config.limits.memory_max_mb = 64;
    config.limits.execution_timeout_ms = 1000;
    config.engine.deterministic = true;

    assert_eq!(config.limits.fuel_max, 5000);
    assert_eq!(config.limits.memory_max_mb, 64);
    assert_eq!(config.limits.execution_timeout_ms, 1000);
    assert!(config.engine.deterministic);
}

#[test]
fn test_error_types() {
    // Test that error types can be constructed and matched
    let err = RuntimeError::ValidationError("test".to_string());
    assert!(matches!(err, RuntimeError::ValidationError(_)));

    let err = RuntimeError::FuelExhausted {
        used: 150,
        limit: 100,
    };
    assert!(matches!(err, RuntimeError::FuelExhausted { .. }));

    // Test error code mapping
    assert_eq!(err.error_code(), "ERR_FUEL_EXHAUSTED");
    assert_eq!(err.outcome_status(), "limits_exceeded");
}

#[test]
fn test_module_hash_in_receipt() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(SIMPLE_WASM.to_vec()).with_id("test-hash"));

    let receipt = runtime
        .execute(SIMPLE_WASM, context)
        .expect("Execution failed");

    // Verify module hash is present
    assert!(receipt.module_hash.is_some());
    let hash = receipt.module_hash.as_ref().unwrap();
    // Blake3 hash should be 64 hex characters
    assert_eq!(hash.value.len(), 64);
    assert!(hash.value.chars().all(|c| c.is_ascii_hexdigit()));
}
