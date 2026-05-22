//! Generate golden receipt fixtures
//!
//! Run with: cargo test --test golden -- --ignored --nocapture

use jig_runtime::{BlockPackage, ExecutionContext, Runtime, RuntimeConfig};
use std::fs;

const DETERMINISTIC_WASM: &[u8] = include_bytes!("fixtures/deterministic.wasm");
const HELLO_WASI_WASM: &[u8] = include_bytes!("fixtures/hello_wasi.wasm");

/// Utility to regenerate golden file for deterministic WASM fixture
/// Not a test - run with: cargo test --test golden generate_golden_deterministic -- --ignored --nocapture
#[test]
#[ignore = "utility to regenerate golden files, not a test"]
fn generate_golden_deterministic() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let block = BlockPackage::from_wasm(vec![]).with_id("golden-deterministic-v1");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime
        .execute(DETERMINISTIC_WASM, context)
        .expect("execution");

    // Normalize receipt for golden comparison (remove non-deterministic fields)
    let limits = receipt.block.limits.as_ref().expect("limits");
    let counters = receipt.block.counters.as_ref().expect("counters");
    let golden = serde_json::json!({
        "module_hash": receipt.module_hash.as_ref().map(|m| m.value.clone()),
        "fuel_used": receipt.fuel_used(),
        "outcome": format!("{:?}", receipt.outcome),
        "limits": {
            "fuel_max": limits.fuel_max,
            "memory_max_mb": limits.memory_max_mb,
        },
        "counters": {
            "fuel_total": counters.fuel_total,
            "fuel_by_capability": counters.fuel_by_capability,
            "bytes_tx": counters.bytes_tx,
            "bytes_rx": counters.bytes_rx,
        },
        "fixture": "deterministic.wasm",
        "description": "Pure computation: sum of squares 1..=100"
    });

    let json = serde_json::to_string_pretty(&golden).unwrap();
    fs::write("tests/golden/deterministic.json", json).expect("Failed to write golden file");

    println!("Generated: tests/golden/deterministic.json");
    println!("Fuel used: {}", receipt.fuel_used());
}

/// Utility to regenerate golden file for WASI WASM fixture
/// Not a test - run with: cargo test --test golden generate_golden_wasi -- --ignored --nocapture
#[test]
#[ignore = "utility to regenerate golden files, not a test"]
fn generate_golden_wasi() {
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let block = BlockPackage::from_wasm(vec![]).with_id("golden-wasi-v1");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime
        .execute(HELLO_WASI_WASM, context)
        .expect("execution");

    let limits = receipt.block.limits.as_ref().expect("limits");
    let counters = receipt.block.counters.as_ref().expect("counters");
    let golden = serde_json::json!({
        "module_hash": receipt.module_hash.as_ref().map(|m| m.value.clone()),
        "fuel_used": receipt.fuel_used(),
        "outcome": format!("{:?}", receipt.outcome),
        "limits": {
            "fuel_max": limits.fuel_max,
            "memory_max_mb": limits.memory_max_mb,
        },
        "counters": {
            "fuel_total": counters.fuel_total,
            "fuel_by_capability": counters.fuel_by_capability,
            "bytes_tx": counters.bytes_tx,
            "bytes_rx": counters.bytes_rx,
        },
        "fixture": "hello_wasi.wasm",
        "description": "WASI hello world with stdout"
    });

    let json = serde_json::to_string_pretty(&golden).unwrap();
    fs::write("tests/golden/hello_wasi.json", json).expect("Failed to write golden file");

    println!("Generated: tests/golden/hello_wasi.json");
    println!("Fuel used: {}", receipt.fuel_used());
}

#[test]
fn test_deterministic_matches_golden() {
    // Load golden receipt
    let golden_json =
        fs::read_to_string("tests/golden/deterministic.json").expect("Failed to read golden file");
    let golden: serde_json::Value =
        serde_json::from_str(&golden_json).expect("Failed to parse golden JSON");

    // Execute and generate new receipt
    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let block = BlockPackage::from_wasm(vec![]).with_id("golden-deterministic-v1");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime
        .execute(DETERMINISTIC_WASM, context)
        .expect("execution");

    // Verify deterministic fields match golden
    assert_eq!(
        receipt
            .module_hash
            .as_ref()
            .map(|h| h.value.as_str())
            .unwrap(),
        golden["module_hash"].as_str().unwrap(),
        "Module hash must match golden"
    );

    assert_eq!(
        receipt.fuel_used(),
        golden["fuel_used"].as_u64().unwrap(),
        "Fuel usage must match golden (determinism regression)"
    );

    assert_eq!(
        format!("{:?}", receipt.outcome),
        golden["outcome"].as_str().unwrap(),
        "Outcome must match golden"
    );

    let counters = receipt.block.counters.as_ref().expect("counters");
    let golden_counters = golden["counters"].as_object().unwrap();
    assert_eq!(
        counters.fuel_total,
        golden_counters["fuel_total"].as_u64().unwrap(),
        "fuel_total must match golden"
    );
    assert_eq!(
        counters.bytes_tx,
        golden_counters["bytes_tx"].as_u64().unwrap(),
        "bytes_tx must match golden"
    );
    assert_eq!(
        counters.bytes_rx,
        golden_counters["bytes_rx"].as_u64().unwrap(),
        "bytes_rx must match golden"
    );
}

#[test]
fn test_wasi_matches_golden() {
    let golden_json =
        fs::read_to_string("tests/golden/hello_wasi.json").expect("Failed to read golden file");
    let golden: serde_json::Value =
        serde_json::from_str(&golden_json).expect("Failed to parse golden JSON");

    let config = RuntimeConfig::default();
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let block = BlockPackage::from_wasm(vec![]).with_id("golden-wasi-v1");
    let context = ExecutionContext::default().with_block(block);

    let receipt = runtime
        .execute(HELLO_WASI_WASM, context)
        .expect("execution");

    // Verify WASI execution is deterministic
    assert_eq!(
        receipt
            .module_hash
            .as_ref()
            .map(|h| h.value.as_str())
            .unwrap(),
        golden["module_hash"].as_str().unwrap(),
        "Module hash must match golden"
    );

    assert_eq!(
        receipt.fuel_used(),
        golden["fuel_used"].as_u64().unwrap(),
        "WASI fuel usage must match golden (determinism regression)"
    );

    assert_eq!(
        format!("{:?}", receipt.outcome),
        golden["outcome"].as_str().unwrap(),
        "Outcome must match golden"
    );

    let counters = receipt.block.counters.as_ref().expect("counters");
    let golden_counters = golden["counters"].as_object().unwrap();
    assert_eq!(
        counters.fuel_total,
        golden_counters["fuel_total"].as_u64().unwrap(),
        "fuel_total must match golden"
    );
    assert_eq!(
        counters.bytes_tx,
        golden_counters["bytes_tx"].as_u64().unwrap(),
        "bytes_tx must match golden"
    );
    assert_eq!(
        counters.bytes_rx,
        golden_counters["bytes_rx"].as_u64().unwrap(),
        "bytes_rx must match golden"
    );
}
