#![no_main]

use jig_core::grant::Grant;
use jig_runtime::component::ComponentRuntime;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip if data is too small
    if data.len() < 8 {
        return;
    }

    let Ok(runtime) = ComponentRuntime::new() else {
        return;
    };

    // Validate and compile the fuzzer-provided bytes as a renderer component.
    // We don't care about success/failure, just that it doesn't panic.
    let _ = runtime.compile_renderer(data, &Grant::empty(), 16);
});
