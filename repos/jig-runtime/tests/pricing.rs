//! Test pricing calculations in receipts

use jig_runtime::{BlockPackage, ExecutionContext, Runtime, RuntimeConfig};

#[test]
fn test_pricing_disabled_by_default() {
    let config = RuntimeConfig::default();
    assert!(!config.pricing.enabled);

    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "main"))
        )
        "#,
    )
    .unwrap();

    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-pricing-default"));

    let receipt = runtime.execute(&wasm, context).expect("Execution failed");

    assert!(
        receipt.pricing.is_none(),
        "Pricing should be None by default"
    );
}

#[test]
fn test_pricing_enabled() {
    let mut config = RuntimeConfig::default();
    config.pricing.enabled = true;
    config.pricing.cost_per_fuel_unit = 0.00001; // 10 micro-units per fuel
    config.pricing.currency = Some("USD".to_string());

    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "main"))
        )
        "#,
    )
    .unwrap();

    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-pricing-enabled"));

    let receipt = runtime.execute(&wasm, context).expect("Execution failed");

    assert!(receipt.pricing.is_some(), "Pricing should be present");

    let pricing = receipt.pricing.as_ref().unwrap();
    assert_eq!(pricing.cost_per_fuel_unit, 0.00001);
    assert_eq!(pricing.currency, Some("USD".to_string()));
    // Pins the DEFAULT schedule version. Bumped to 0.2.0 when wasmtime 47
    // started billing bulk memory ops per byte; update deliberately, never to
    // make a failure go away.
    assert_eq!(pricing.schedule_version, "0.2.0");

    // Total cost should be fuel_used * cost_per_fuel_unit
    let expected_cost = receipt.fuel_used() as f64 * 0.00001;
    assert_eq!(pricing.total_cost, expected_cost);
}

#[test]
fn test_pricing_calculation_accuracy() {
    let mut config = RuntimeConfig::default();
    config.pricing.enabled = true;
    config.pricing.cost_per_fuel_unit = 0.000001; // 1 micro-unit
    config.pricing.currency = Some("credits".to_string());
    config.pricing.schedule_version = "test-v1".to_string();

    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    // WASM with some computation
    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "main") (result i32)
                (local $sum i32)
                (local $i i32)
                (local.set $sum (i32.const 0))
                (local.set $i (i32.const 1))
                (block $break
                    (loop $continue
                        (local.set $sum (i32.add (local.get $sum) (local.get $i)))
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br_if $continue (i32.le_u (local.get $i) (i32.const 50)))
                    )
                )
                (local.get $sum)
            )
        )
        "#,
    )
    .unwrap();

    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-pricing-calc"));

    let receipt = runtime.execute(&wasm, context).expect("Execution failed");

    let pricing = receipt.pricing.as_ref().expect("Pricing should be present");

    // Verify calculation
    let expected_total = receipt.fuel_used() as f64 * pricing.cost_per_fuel_unit;
    assert_eq!(pricing.total_cost, expected_total);

    // Verify custom values
    assert_eq!(pricing.currency, Some("credits".to_string()));
    assert_eq!(pricing.schedule_version, "test-v1");

    // Should have consumed significant fuel
    assert!(
        receipt.fuel_used() > 100,
        "Should have used substantial fuel"
    );
    assert!(pricing.total_cost > 0.0, "Total cost should be positive");
}

#[test]
fn test_receipt_serialization_with_pricing() {
    let mut config = RuntimeConfig::default();
    config.pricing.enabled = true;
    config.pricing.cost_per_fuel_unit = 0.000005;
    config.pricing.currency = Some("tokens".to_string());

    let runtime = Runtime::with_config(config).expect("Failed to create runtime");

    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "main"))
        )
        "#,
    )
    .unwrap();

    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("test-serialization"));

    let receipt = runtime.execute(&wasm, context).expect("Execution failed");

    // Serialize to JSON
    let json = receipt.to_json().expect("Failed to serialize");

    assert!(json.contains("\"pricing\""));
    assert!(json.contains("\"cost_per_fuel_unit\""));
    assert!(json.contains("\"total_cost\""));
    assert!(json.contains("\"tokens\""));

    // Deserialize and verify
    let deserialized: jig_runtime::Receipt =
        serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(
        deserialized.pricing.as_ref().unwrap().cost_per_fuel_unit,
        0.000005
    );
    assert_eq!(
        deserialized.pricing.as_ref().unwrap().total_cost,
        receipt.pricing.as_ref().unwrap().total_cost
    );
}
