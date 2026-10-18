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

/// Host-attributed fuel must sit beside the measured wasm fuel, not replace it.
///
/// The `engine.wasm` bucket used to be added only when the meter was empty, so
/// the first host charge silently dropped the guest's own instruction count:
/// `fuel_used` then reported host fuel alone, and the one portable measurement
/// in the receipt was gone.
#[test]
fn host_charges_do_not_drop_the_measured_wasm_fuel() {
    let runtime = Runtime::new().expect("runtime");

    // Enough work that wasm fuel is unambiguously non-zero.
    let wasm = wat::parse_str(
        r#"
        (module
            (func (export "main")
                (local i32)
                (local.set 0 (i32.const 1000))
                (loop
                    (local.set 0 (i32.sub (local.get 0) (i32.const 1)))
                    (br_if 0 (local.get 0))))
        )
    "#,
    )
    .expect("wat compile");

    let baseline = runtime
        .execute(
            &wasm,
            ExecutionContext::default().with_block(BlockPackage::from_wasm(wasm.clone())),
        )
        .expect("baseline execution");
    let wasm_fuel = baseline
        .block
        .counters
        .as_ref()
        .expect("counters")
        .fuel_by_capability["engine.wasm"];
    assert!(wasm_fuel > 0, "the loop must cost fuel");

    let context = ExecutionContext::default().with_block(BlockPackage::from_wasm(wasm.clone()));
    let scope = CapabilityScopePattern::parse("https://api.example.com/*").unwrap();
    context
        .capability_meter_handle()
        .record_invocation_with_scope("net.fetch", &scope, "GET", 150, 0, 0, None)
        .expect("record");

    let receipt = runtime.execute(&wasm, context).expect("execution");
    let counters = receipt.block.counters.as_ref().expect("counters");

    assert_eq!(
        counters.fuel_by_capability.get("engine.wasm").copied(),
        Some(wasm_fuel),
        "the measured wasm fuel must survive a host charge"
    );
    assert_eq!(counters.fuel_total, wasm_fuel + 150);
    assert_eq!(receipt.fuel_used(), counters.fuel_total);
}
