use jig_core::CapabilityScopePattern;
use jig_runtime::{BlockPackage, ExecutionContext, Runtime};

fn simple_module() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "main"))
        )
    "#,
    )
    .expect("wat compile")
}

#[test]
fn capability_meter_stats_attached_to_receipt() {
    let runtime = Runtime::new().expect("runtime");

    let wasm = simple_module();
    let context = ExecutionContext::default()
        .with_block(BlockPackage::from_wasm(wasm.clone()).with_id("cap-meter-test"))
        .with_capability("net.fetch|https://api.example.com/*".to_string());

    // Simulate host capability usage prior to execution (e.g., bridged host call)
    let meter = context.capability_meter_handle();
    let scope = CapabilityScopePattern::parse("https://api.example.com/*").unwrap();
    meter
        .record_invocation_with_scope(
            "net.fetch",
            &scope,
            "GET",
            150,
            1_024,
            2_048,
            Some("http.2xx"),
        )
        .expect("record");
    meter
        .record_invocation_with_scope("net.fetch", &scope, "GET", 50, 512, 1024, Some("http.5xx"))
        .expect("record");

    let receipt = runtime
        .execute(&wasm, context)
        .expect("execution should succeed");

    let counters = receipt.block.counters.as_ref().expect("counters");
    assert_eq!(counters.fuel_total, receipt.fuel_used());
    assert_eq!(
        counters
            .fuel_by_capability
            .get("net.fetch|https://api.example.com/*")
            .copied(),
        Some(200)
    );
    assert_eq!(counters.bytes_tx, 1_024 + 512);
    assert_eq!(counters.bytes_rx, 2_048 + 1_024);

    let status = counters
        .status_by_capability
        .get("net.fetch|https://api.example.com/*")
        .expect("status bins");
    assert_eq!(status.get("http.5xx"), Some(&1));
    assert_eq!(status.get("http.2xx"), Some(&1));

    assert_eq!(receipt.capability_calls.len(), 2);
    let status_bins = receipt
        .block
        .metadata
        .get("runtime.status_bins")
        .expect("status bins metadata")
        .as_object()
        .expect("status bins object");
    assert!(status_bins.contains_key("net.fetch|https://api.example.com/*"));
}
