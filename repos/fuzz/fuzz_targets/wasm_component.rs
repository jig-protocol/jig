//! A block's Wasm component, as jig-runtime validates and compiles a renderer
//! before running it. Moved from the old jig-runtime/fuzz crate.
#![no_main]

use std::sync::LazyLock;

use jig_core::grant::Grant;
use jig_runtime::component::ComponentRuntime;
use libfuzzer_sys::fuzz_target;

static RUNTIME: LazyLock<ComponentRuntime> =
    LazyLock::new(|| ComponentRuntime::new().expect("component runtime"));

fuzz_target!(|data: &[u8]| {
    let _ = RUNTIME.compile_renderer(data, &Grant::empty(), 16);
});
