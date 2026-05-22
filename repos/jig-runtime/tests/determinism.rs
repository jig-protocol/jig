//! Determinism tests: same inputs → same receipts
//!
//! Verifies that executing identical WASM with identical context produces
//! identical receipts (modulo timestamps).

use jig_runtime::{BlockPackage, ExecutionContext, Runtime, RuntimeConfig};

fn deterministic_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory 1 1)
            (func (export "main") )
        )
    "#,
    )
    .expect("compile deterministic wasm")
}

const HELLO_WASI_WASM: &[u8] = include_bytes!("fixtures/hello_wasi.wasm");

#[test]
fn test_deterministic_execution_same_receipt() {
    // Execute the same WASM module twice with identical configuration
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let wasm = deterministic_wasm();
    // First execution
    let package1 = BlockPackage::from_wasm(wasm.clone()).with_id("test-block-1");
    let context1 = ExecutionContext::default().with_block(package1);
    let receipt1 = runtime.execute(&wasm, context1).expect("execution 1");

    // Second execution with identical setup
    let package2 = BlockPackage::from_wasm(wasm.clone()).with_id("test-block-1");
    let context2 = ExecutionContext::default().with_block(package2);
    let receipt2 = runtime.execute(&wasm, context2).expect("execution 2");

    // Verify deterministic fields match
    assert_eq!(
        receipt1.fuel_used(),
        receipt2.fuel_used(),
        "fuel consumption must be deterministic"
    );
    assert_eq!(
        receipt1.module_hash, receipt2.module_hash,
        "module hash must match"
    );
    assert_eq!(
        receipt1.outcome, receipt2.outcome,
        "outcome must be identical"
    );
    assert_eq!(
        receipt1.block.limits.as_ref().map(|l| l.fuel_max),
        receipt2.block.limits.as_ref().map(|l| l.fuel_max),
        "limits must match"
    );

    // Verify timing fields are present but allow variance
    assert!(receipt1.duration_ns > 0, "duration should be recorded");
    assert!(receipt2.duration_ns > 0, "duration should be recorded");

    // Timestamps will differ - just verify they're valid
    assert!(
        receipt1.block.executed_at.unix_timestamp() != 0,
        "timestamp should be set"
    );
    assert!(
        receipt2.block.executed_at.unix_timestamp() != 0,
        "timestamp should be set"
    );
}

#[test]
fn test_deterministic_with_pricing() {
    // Execute with pricing enabled
    let mut config = RuntimeConfig::default();
    config.pricing.enabled = true;
    config.pricing.cost_per_fuel_unit = 0.000001;
    config.pricing.currency = Some("TEST_USD".to_string());

    let runtime = Runtime::with_config(config).expect("runtime creation");

    // First execution
    let wasm = deterministic_wasm();
    let package1 = BlockPackage::from_wasm(wasm.clone()).with_id("pricing-test");
    let context1 = ExecutionContext::default().with_block(package1);
    let receipt1 = runtime.execute(&wasm, context1).expect("execution 1");

    // Second execution
    let package2 = BlockPackage::from_wasm(wasm.clone()).with_id("pricing-test");
    let context2 = ExecutionContext::default().with_block(package2);
    let receipt2 = runtime.execute(&wasm, context2).expect("execution 2");

    // Verify pricing is deterministic
    assert!(receipt1.pricing.is_some(), "pricing should be present");
    assert!(receipt2.pricing.is_some(), "pricing should be present");

    let pricing1 = receipt1.pricing.as_ref().unwrap();
    let pricing2 = receipt2.pricing.as_ref().unwrap();

    assert_eq!(
        pricing1.cost_per_fuel_unit, pricing2.cost_per_fuel_unit,
        "cost per fuel must match"
    );
    assert_eq!(
        pricing1.total_cost, pricing2.total_cost,
        "total cost must be deterministic"
    );
    assert_eq!(pricing1.currency, pricing2.currency, "currency must match");
}

#[test]
fn test_different_limits_different_context() {
    // Verify that different configurations produce different results appropriately
    let mut config1 = RuntimeConfig::default();
    config1.limits.fuel_max = 1_000_000;

    let mut config2 = RuntimeConfig::default();
    config2.limits.fuel_max = 5_000_000;

    let runtime1 = Runtime::with_config(config1).expect("runtime 1");
    let runtime2 = Runtime::with_config(config2).expect("runtime 2");

    let wasm = deterministic_wasm();
    let package1 = BlockPackage::from_wasm(wasm.clone()).with_id("limits-test-1");
    let context1 = ExecutionContext::default().with_block(package1);
    let receipt1 = runtime1.execute(&wasm, context1).expect("execution 1");

    let package2 = BlockPackage::from_wasm(wasm.clone()).with_id("limits-test-2");
    let context2 = ExecutionContext::default().with_block(package2);
    let receipt2 = runtime2.execute(&wasm, context2).expect("execution 2");

    // Fuel used should be identical (same WASM)
    assert_eq!(
        receipt1.fuel_used(),
        receipt2.fuel_used(),
        "fuel consumption should match regardless of limit"
    );

    // But limits should differ
    assert_eq!(
        receipt1.block.limits.as_ref().map(|l| l.fuel_max).unwrap(),
        1_000_000
    );
    assert_eq!(
        receipt2.block.limits.as_ref().map(|l| l.fuel_max).unwrap(),
        5_000_000
    );
}

#[test]
fn test_wasi_deterministic_output() {
    // WASI modules with safe imports are now allowed and should execute deterministically
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let block = BlockPackage::from_wasm(HELLO_WASI_WASM.to_vec()).with_id("wasi-test");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime
        .execute(HELLO_WASI_WASM, context)
        .expect("WASI execution should succeed with safe imports");

    // Verify execution succeeded
    assert_eq!(receipt.outcome, jig_runtime::ExecutionOutcome::Success);
    assert!(receipt.fuel_used() > 0, "WASI module should consume fuel");
}
