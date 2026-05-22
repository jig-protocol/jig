#![no_main]

use libfuzzer_sys::fuzz_target;
use jig_runtime::{BlockPackage, ExecutionContext, Runtime, RuntimeConfig};

fuzz_target!(|data: &[u8]| {
    // Skip if data is too small
    if data.len() < 8 {
        return;
    }

    // Create runtime with default config
    let config = RuntimeConfig::default();
    let Ok(runtime) = Runtime::with_config(config) else {
        return;
    };

    // Try to execute the fuzzer-provided bytecode as WASM
    let block = BlockPackage::from_wasm(vec![]).with_id("fuzz-001");
    let context = ExecutionContext::default().with_block(block);

    // We don't care about success/failure, just that it doesn't panic
    let _ = runtime.execute(data, context);
});
