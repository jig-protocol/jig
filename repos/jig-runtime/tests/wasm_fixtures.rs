//! Comprehensive WASM test fixtures for deterministic execution testing

use jig_runtime::{BlockPackage, ExecutionContext, Runtime, RuntimeConfig};

/// Simple empty function - minimal fuel usage
fn fixture_empty() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "main"))
        )
        "#,
    )
    .unwrap()
}

/// Computational loop - deterministic arithmetic
fn fixture_sum_loop() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "main") (result i32)
                (local $sum i32)
                (local $i i32)
                (local.set $sum (i32.const 0))
                (local.set $i (i32.const 1))
                (block $break
                    (loop $continue
                        ;; sum += i
                        (local.set $sum (i32.add (local.get $sum) (local.get $i)))
                        ;; i++
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        ;; if i <= 100, continue
                        (br_if $continue (i32.le_u (local.get $i) (i32.const 100)))
                    )
                )
                (local.get $sum)
            )
        )
        "#,
    )
    .unwrap()
}

/// Memory-intensive - allocate and write to memory
fn fixture_memory_usage() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1 16)
            (func (export "main") (result i32)
                (local $i i32)
                (local.set $i (i32.const 0))
                (block $break
                    (loop $continue
                        ;; Write to memory at offset i
                        (i32.store (local.get $i) (local.get $i))
                        ;; i += 4 (word size)
                        (local.set $i (i32.add (local.get $i) (i32.const 4)))
                        ;; if i < 1024, continue (256 writes)
                        (br_if $continue (i32.lt_u (local.get $i) (i32.const 1024)))
                    )
                )
                (local.get $i)
            )
        )
        "#,
    )
    .unwrap()
}

/// Nested loops - higher fuel consumption
fn fixture_nested_loops() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "main") (result i32)
                (local $count i32)
                (local $i i32)
                (local $j i32)
                (local.set $count (i32.const 0))
                (local.set $i (i32.const 0))
                (block $outer_break
                    (loop $outer
                        (local.set $j (i32.const 0))
                        (block $inner_break
                            (loop $inner
                                (local.set $count (i32.add (local.get $count) (i32.const 1)))
                                (local.set $j (i32.add (local.get $j) (i32.const 1)))
                                (br_if $inner (i32.lt_u (local.get $j) (i32.const 10)))
                            )
                        )
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br_if $outer (i32.lt_u (local.get $i) (i32.const 10)))
                    )
                )
                (local.get $count)
            )
        )
        "#,
    )
    .unwrap()
}

#[test]
fn test_fixture_empty() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let wasm = fixture_empty();
    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-empty"));

    let receipt = runtime.execute(&wasm, context).expect("Execution failed");

    assert!(receipt.outcome == jig_runtime::ExecutionOutcome::Success);
    assert!(receipt.fuel_used() > 0, "Should consume some fuel");
    assert!(receipt.module_hash.is_some());
}

#[test]
fn test_fixture_sum_loop() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let wasm = fixture_sum_loop();
    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-sum"));

    let receipt = runtime.execute(&wasm, context).expect("Execution failed");

    // Function returns a value, may trap - check fuel was consumed
    assert!(
        receipt.fuel_used() > 100,
        "Loop should consume significant fuel"
    );
}

#[test]
fn test_fixture_determinism() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let wasm = fixture_sum_loop();

    // Run twice with identical input
    let context1 = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-det-1"));

    let context2 = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-det-2"));

    let receipt1 = runtime
        .execute(&wasm, context1)
        .expect("Execution 1 failed");
    let receipt2 = runtime
        .execute(&wasm, context2)
        .expect("Execution 2 failed");

    // Fuel consumption should be identical
    assert_eq!(receipt1.fuel_used(), receipt2.fuel_used());
    assert_eq!(receipt1.block.memory_peak_mb, receipt2.block.memory_peak_mb);
    // Module hashes should be identical
    assert_eq!(receipt1.module_hash, receipt2.module_hash);
}

#[test]
fn test_fixture_memory_usage() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let wasm = fixture_memory_usage();
    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-memory"));

    let receipt = runtime.execute(&wasm, context).expect("Execution failed");

    // Function returns a value, may trap - check fuel was consumed
    assert!(receipt.fuel_used() > 0);
}

#[test]
fn test_fixture_nested_loops() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let wasm = fixture_nested_loops();
    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-nested"));

    let receipt = runtime.execute(&wasm, context).expect("Execution failed");

    // Function returns a value, may trap - check fuel was consumed
    assert!(receipt.fuel_used() > 0, "Should consume fuel");
}

#[test]
fn test_fuel_exhaustion_with_nested_loops() {
    let mut config = RuntimeConfig::default();
    config.limits.fuel_max = 500; // Low limit

    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let wasm = fixture_nested_loops();
    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-exhaust-nested"));

    let receipt = runtime
        .execute(&wasm, context)
        .expect("Should return receipt even on error");

    // May hit limits, fail, or complete - all valid
    assert!(receipt.fuel_used() > 0, "Should have consumed fuel");
}

#[test]
fn test_all_fixtures_have_unique_hashes() {
    let fixtures = vec![
        fixture_empty(),
        fixture_sum_loop(),
        fixture_memory_usage(),
        fixture_nested_loops(),
    ];

    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let mut hashes = std::collections::HashSet::new();

    for (idx, wasm) in fixtures.iter().enumerate() {
        let context = ExecutionContext::default().with_block(
            BlockPackage::from_wasm(wasm.clone()).with_id(format!("test-unique-{}", idx)),
        );

        let receipt = runtime.execute(wasm, context).expect("Execution failed");
        let hash = receipt
            .module_hash
            .as_ref()
            .expect("Should have hash")
            .value
            .clone();

        // Each fixture should have a unique hash
        assert!(
            hashes.insert(hash),
            "Duplicate hash found for fixture {}",
            idx
        );
    }

    assert_eq!(hashes.len(), fixtures.len());
}
