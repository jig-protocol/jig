//! Workspace integration test: Verify jig-runtime can be consumed by other workspace members

use jig_runtime::{
    BlockPackage, CostSchedule, ExecutionContext, ExecutionOutcome, Receipt, Runtime, RuntimeConfig,
};

#[test]
fn test_runtime_api_imports() {
    // Verify all core types are importable
    let _config = RuntimeConfig::default();
    let _context = ExecutionContext::default();
    let _package = BlockPackage::default();

    // Verify runtime creation
    let runtime = Runtime::new();
    assert!(runtime.is_ok(), "Runtime should create successfully");
}

#[test]
fn test_config_types_accessible() {
    let config = RuntimeConfig::default();

    // Verify config fields are accessible
    assert!(config.fuel.enabled);
    assert_eq!(config.limits.fuel_max, 5_000_000);
    assert!(!config.pricing.enabled);
}

#[test]
fn test_cost_schedule_loading() {
    let schedule = CostSchedule::default_v0_1();

    assert_eq!(schedule.version, "0.1.0");
    assert!(schedule.validate().is_ok());

    // Verify capability costs are defined
    assert!(schedule.capability_costs.contains_key("http"));
    assert!(schedule.capability_costs.contains_key("kv"));
}

#[test]
fn test_execution_context_builder() {
    let context = ExecutionContext::default()
        .with_capability("http".to_string())
        .with_capability("kv".to_string())
        .with_env("KEY", "VALUE");

    assert_eq!(context.capabilities.len(), 2);
    assert_eq!(context.env.get("KEY"), Some(&"VALUE".to_string()));
}

#[test]
fn test_receipt_types_accessible() {
    // Receipt is assembled by the runtime; verify the outcome enum is accessible
    assert!(matches!(ExecutionOutcome::Success, ExecutionOutcome::Success));
    assert!(matches!(
        ExecutionOutcome::ExecutionFailed,
        ExecutionOutcome::ExecutionFailed
    ));
}

#[test]
fn test_pricing_config() {
    let mut config = RuntimeConfig::default();
    config.pricing.enabled = true;
    config.pricing.cost_per_fuel_unit = 0.00001;
    config.pricing.currency = Some("USD".to_string());

    assert!(config.pricing.enabled);
    assert_eq!(config.pricing.cost_per_fuel_unit, 0.00001);
}

#[test]
fn test_basic_execution() {
    // Simple valid WASM module with empty main function
    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "main"))
        )
        "#,
    )
    .unwrap();

    let runtime = Runtime::new().expect("Failed to create runtime");

    let mut context = ExecutionContext::default();
    context.block = BlockPackage {
        wasm_bytes: wasm.clone(),
        block_id: Some("integration-test".to_string()),
        ..Default::default()
    };

    let receipt = runtime
        .execute(&wasm, context)
        .expect("Execution should succeed");

    assert!(matches!(receipt.outcome, ExecutionOutcome::Success));
    assert!(receipt.fuel_used() > 0);
    assert!(receipt.module_hash.is_some());
}
