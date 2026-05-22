//! Receipt v0.2 integration tests for the runtime wrapper.

use std::collections::BTreeMap;

use jig_core::receipt::{Counters, Limits, Outcome, OutcomeStatus, ReasonCode, Timings};
use jig_runtime::{CapabilityCall, ExecutionOutcome, ModuleHash, Receipt, ReceiptPricing};

#[test]
fn test_receipt_v0_2_structure() {
    let counters = Counters {
        status_by_capability: BTreeMap::new(),
        fuel_total: 4_500,
        fuel_by_capability: BTreeMap::from([
            ("http".to_string(), 500),
            ("kv".to_string(), 100),
            ("wasm".to_string(), 3_900),
        ]),
        bytes_tx: 2_048,
        bytes_rx: 256,
        syscalls: 0,
    };

    let timings = Timings {
        queue_wait: 1,
        init: 3,
        exec: 42,
        total: 45,
    };

    let limits = Limits {
        fuel_max: 5_000,
        memory_max_mb: 32,
        execution_timeout_ms: 250,
    };

    let outcome = Outcome {
        status: OutcomeStatus::Ok,
        affordances: vec!["email.delivered".to_string()],
        reason: None,
    };

    let receipt = Receipt::builder()
        .block_id_from_wasm(b"sample-wasm-module")
        .host("did:host:abc")
        .render_hash("sha256:render-hash")
        .fuel_used(4_500)
        .execution_duration_ns(2_500_000)
        .module_hash(ModuleHash::new("blake3:module-hash", "blake3-256"))
        .counters(counters)
        .timings(timings)
        .limits(limits)
        .outcome(outcome)
        .capability_call(CapabilityCall {
            capability: "net.fetch:https://api.example.com/foo/*".to_string(),
            operation: "GET".to_string(),
            fuel_used: 500,
            bytes_transferred: Some(2_048),
            status: Some("http.2xx".to_string()),
        })
        .capability_call(CapabilityCall {
            capability: "kv.read:mem://default/*".to_string(),
            operation: "set".to_string(),
            fuel_used: 100,
            bytes_transferred: Some(256),
            status: None,
        })
        .pricing(ReceiptPricing {
            cost_per_fuel_unit: 0.000_001,
            total_cost: 0.0045,
            currency: Some("tokens".to_string()),
            schedule_version: "test-1".to_string(),
        })
        .build()
        .expect("receipt build");

    assert_eq!(receipt.fuel_used(), 4_500);
    assert_eq!(receipt.duration_ns, 2_500_000);
    assert_eq!(
        receipt
            .block
            .counters
            .as_ref()
            .unwrap()
            .fuel_by_capability
            .get("http"),
        Some(&500)
    );
    assert_eq!(receipt.capability_calls.len(), 2);

    let json = receipt.to_json().expect("serialize receipt");
    let roundtrip = Receipt::from_json(&json).expect("deserialize receipt");

    assert_eq!(roundtrip.fuel_used(), 4_500);
    assert_eq!(roundtrip.capability_calls.len(), 2);

    let canonical = receipt.to_canonical_bytes().expect("canonical bytes");
    assert!(!canonical.is_empty());
}

#[test]
fn test_receipt_error_case() {
    let hard_fail = Outcome {
        status: OutcomeStatus::HardFail,
        affordances: vec![],
        reason: Some(ReasonCode::FuelExhausted),
    };

    let receipt = Receipt::builder()
        .block_id_from_wasm(b"failing-wasm")
        .host("host-xyz")
        .render_hash("sha256:render")
        .fuel_used(1_000)
        .execution_duration_ns(1_000_000)
        .module_hash(ModuleHash::new("blake3:fuel-out", "blake3-256"))
        .limits(Limits {
            fuel_max: 1_000,
            memory_max_mb: 8,
            execution_timeout_ms: 120,
        })
        .outcome(hard_fail)
        .legacy_outcome(ExecutionOutcome::LimitsExceeded)
        .error(
            "ERR_FUEL_EXHAUSTED",
            Some("Fuel exhausted: used 1000 of 1000 limit".into()),
        )
        .build()
        .expect("receipt build");

    assert_eq!(receipt.fuel_used(), 1_000);
    assert_eq!(
        receipt.error.as_ref().expect("error").code,
        "ERR_FUEL_EXHAUSTED"
    );
    assert_eq!(
        receipt.block.outcome.as_ref().unwrap().status,
        OutcomeStatus::HardFail
    );
}

#[test]
fn test_canonical_bytes_determinism() {
    use time::OffsetDateTime;

    // Fixed timestamp to ensure deterministic canonical bytes
    let fixed_timestamp = OffsetDateTime::from_unix_timestamp(1700000000).unwrap();

    let builder = || {
        Receipt::builder()
            .block_id_from_wasm(b"identical-wasm")
            .host("host-1")
            .render_hash("sha256:render")
            .fuel_used(2_000)
            .execution_duration_ns(500_000)
            .executed_at(fixed_timestamp) // Set fixed timestamp for determinism
            .module_hash(ModuleHash::new("blake3:identical", "blake3-256"))
            .limits(Limits {
                fuel_max: 5_000,
                memory_max_mb: 32,
                execution_timeout_ms: 250,
            })
            .outcome(Outcome {
                status: OutcomeStatus::Ok,
                affordances: vec![],
                reason: None,
            })
            .build()
            .expect("receipt")
    };

    let receipt_a = builder();
    let receipt_b = builder();

    let bytes_a = receipt_a.to_canonical_bytes().expect("canonical a");
    let bytes_b = receipt_b.to_canonical_bytes().expect("canonical b");

    assert_eq!(bytes_a, bytes_b);
}
