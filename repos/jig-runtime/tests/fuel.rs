//! Fuel metering and exhaustion tests
//!
//! Verify that fuel metering works correctly and modules trap when fuel is exhausted.

use jig_runtime::{BlockPackage, ExecutionContext, Limits, Runtime, RuntimeConfig};
use std::time::Duration;

fn deterministic_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory 1 16)
            (func (export "run") (result i32)
                (local $sum i32)
                (local $i i32)
                (local.set $sum (i32.const 0))
                (local.set $i (i32.const 1))
                (block $break
                    (loop $continue
                        (local.set $sum
                            (i32.add
                                (local.get $sum)
                                (i32.mul (local.get $i) (local.get $i))
                            )
                        )
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br_if $continue (i32.le_s (local.get $i) (i32.const 100)))
                    )
                )
                (local.get $sum)
            )
        )
        "#,
    )
    .expect("wat compile")
}

fn fuel_heavy_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory 1 16)
            (func (export "run") (result i32)
                (local $sum i32)
                (local $i i32)
                (local.set $sum (i32.const 0))
                (local.set $i (i32.const 0))
                (block $break
                    (loop $continue
                        (local.set $sum
                            (i32.add
                                (local.get $sum)
                                (i32.rem_s
                                    (i32.add
                                        (i32.mul (local.get $i) (i32.const 7))
                                        (i32.const 13)
                                    )
                                    (i32.const 997)
                                )
                            )
                        )
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br_if $continue (i32.lt_s (local.get $i) (i32.const 1000000)))
                    )
                )
                (local.get $sum)
            )
        )
        "#,
    )
    .expect("wat compile")
}

#[test]
fn test_fuel_consumption_nonzero() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let block = BlockPackage::from_wasm(vec![]).with_id("fuel-test-001");
    let context = ExecutionContext::default().with_block(block);

    let wasm = deterministic_wasm();
    let receipt = runtime.execute(&wasm, context).expect("execution");

    // Fuel should be consumed
    assert!(receipt.fuel_used() > 0, "Fuel must be consumed");
    assert_eq!(receipt.outcome, jig_runtime::ExecutionOutcome::Success);
}

#[test]
fn test_fuel_exhaustion() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    // Set a very low fuel limit that will definitely be exceeded by fuel_heavy
    let limits = Limits::new(10_000, 128, Duration::from_millis(5000));

    let block = BlockPackage::from_wasm(vec![]).with_id("fuel-exhaust-001");
    let context = ExecutionContext::default()
        .with_block(block)
        .with_limits(limits);

    let wasm = fuel_heavy_wasm();
    let receipt = runtime
        .execute(&wasm, context)
        .expect("execution should return receipt even on fuel exhaustion");

    // Should fail - either LimitsExceeded or ExecutionFailed with fuel-related error
    // The exact classification depends on how Wasmtime reports the trap
    assert!(
        receipt.outcome == jig_runtime::ExecutionOutcome::LimitsExceeded
            || receipt.outcome == jig_runtime::ExecutionOutcome::ExecutionFailed,
        "Expected fuel exhaustion, got {:?}",
        receipt.outcome
    );

    // Fuel usage should be at or near the limit
    assert!(
        receipt.fuel_used() >= 9_000,
        "Should have consumed most of fuel limit"
    );
    assert!(
        receipt.fuel_used() <= 10_000,
        "Should not exceed fuel limit"
    );
}

#[test]
fn test_fuel_limit_respected() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let limits = Limits::new(100_000, 128, Duration::from_millis(5000));

    let block = BlockPackage::from_wasm(vec![]).with_id("fuel-limit-001");
    let context = ExecutionContext::default()
        .with_block(block)
        .with_limits(limits);

    let wasm = deterministic_wasm();
    let receipt = runtime.execute(&wasm, context).expect("execution");

    // Should succeed with fuel under limit
    assert_eq!(receipt.outcome, jig_runtime::ExecutionOutcome::Success);
    assert!(receipt.fuel_used() < 100_000, "Should use less than limit");
    let limits = receipt.block.limits.as_ref().expect("limits");
    assert_eq!(limits.fuel_max, 100_000);
}

#[test]
fn test_different_fuel_limits_same_usage() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let wasm = deterministic_wasm();

    // Execute with high limit
    let limits1 = Limits::new(10_000_000, 128, Duration::from_secs(60));
    let block1 = BlockPackage::from_wasm(vec![]).with_id("fuel-compare-1");
    let context1 = ExecutionContext::default()
        .with_block(block1)
        .with_limits(limits1);
    let receipt1 = runtime.execute(&wasm, context1).expect("execution 1");

    // Execute with lower (but sufficient) limit
    let limits2 = Limits::new(100_000, 128, Duration::from_secs(60));
    let block2 = BlockPackage::from_wasm(vec![]).with_id("fuel-compare-2");
    let context2 = ExecutionContext::default()
        .with_block(block2)
        .with_limits(limits2);
    let receipt2 = runtime.execute(&wasm, context2).expect("execution 2");

    // Fuel usage should be identical regardless of limit
    assert_eq!(receipt1.fuel_used(), receipt2.fuel_used());
    assert_eq!(receipt1.outcome, jig_runtime::ExecutionOutcome::Success);
    assert_eq!(receipt2.outcome, jig_runtime::ExecutionOutcome::Success);
}

#[test]
fn test_fuel_metering_disabled() {
    let mut config = RuntimeConfig::default();
    config.fuel.enabled = false;

    let runtime = Runtime::with_config(config).expect("runtime creation");

    let block = BlockPackage::from_wasm(vec![]).with_id("no-fuel-001");
    let context = ExecutionContext::default().with_block(block);

    let wasm = deterministic_wasm();
    let receipt = runtime.execute(&wasm, context).expect("execution");

    // Fuel should be 0 when metering is disabled
    assert_eq!(receipt.fuel_used(), 0);
    assert_eq!(receipt.outcome, jig_runtime::ExecutionOutcome::Success);
}

#[test]
fn test_heavy_loop_exceeds_default_limit() {
    let config = RuntimeConfig::default(); // 5M default fuel
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let block = BlockPackage::from_wasm(vec![]).with_id("heavy-loop-001");
    let context = ExecutionContext::default().with_block(block);

    let wasm = fuel_heavy_wasm();
    let receipt = runtime.execute(&wasm, context).expect("execution");

    // The 1M iteration loop exceeds the default 5M fuel limit
    // So it should fail (either LimitsExceeded or ExecutionFailed)
    assert!(
        receipt.outcome == jig_runtime::ExecutionOutcome::LimitsExceeded
            || receipt.outcome == jig_runtime::ExecutionOutcome::ExecutionFailed,
        "Heavy loop should exceed default fuel limit"
    );

    // Should have consumed significant fuel before failing
    assert!(
        receipt.fuel_used() > 1_000_000,
        "Should consume substantial fuel before failing"
    );
}
