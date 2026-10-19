//! Executes the `text-block` renderer component (JEP-0006, first-slice step 5).
//!
//! The component is the same block as the byte-payload module in `text_block_payload.rs`,
//! rebuilt for the `jig:block/renderer@0.1.0` world. This suite pins three things:
//!
//! - the committed artifact passes jig-core's component validator (`jig-det-1`);
//! - its output matches text-block's native `execute_pure`, the shared oracle;
//! - its `render_hash` equals the byte-payload module's, so servers on mixed versions keep
//!   agreeing while the server moves from one to the other.
//!
//! It drives wasmtime's component API directly. The component path inside jig-runtime is step
//! 4; once it lands, this suite moves onto it.
//!
//! As with the module, CI runs the suite twice: once against the committed artifact, and once
//! with `JIG_TEXT_BLOCK_COMPONENT` pointing at a fresh build. Wasm output is not reproducible
//! across hosts, so the two are held together by behaviour, not bytes.

use jig_core::component_validation::{BlockWorld, ComponentProfile, validate_component};
use jig_runtime::Runtime;
use text_block::{Input, Output, canonical, execute_pure};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

wasmtime::component::bindgen!({
    world: "renderer",
    path: "../jig-spec/wit/jig-block",
});

use jig::block::types::{BlockError, Hlc, Invocation, Payload};

/// The manifest memory limit the profile checks against: the 16 MiB `build-artifact.sh` sets.
const MAX_MEMORY_PAGES: u32 = 256;

/// The committed component, or the file `JIG_TEXT_BLOCK_COMPONENT` names. A relative path is
/// resolved against the workspace root, as in `text_block_payload.rs`.
fn component_bytes() -> std::borrow::Cow<'static, [u8]> {
    let Some(raw) = std::env::var_os("JIG_TEXT_BLOCK_COMPONENT") else {
        return std::borrow::Cow::Borrowed(canonical::CANONICAL_COMPONENT);
    };
    let path = std::path::PathBuf::from(&raw);
    let resolved = if path.is_relative() {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("package dir has a parent")
            .join(&path)
    } else {
        path
    };
    let bytes = std::fs::read(&resolved).unwrap_or_else(|e| {
        panic!("JIG_TEXT_BLOCK_COMPONENT={raw:?} (resolved to {resolved:?}) could not be read: {e}")
    });
    std::borrow::Cow::Owned(bytes)
}

/// An engine set up the way the profile requires: synchronous only, fuel on, NaNs
/// canonicalized.
fn engine() -> Engine {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.cranelift_nan_canonicalization(true);
    config.concurrency_support(false);
    Engine::new(&config).expect("engine builds")
}

fn invocation(body: &[u8]) -> Invocation {
    Invocation {
        block_cid: "bafytestblock".to_string(),
        sender_did: "did:jig:zabc".to_string(),
        channel_cid: "bafytestchannel".to_string(),
        ingest_seq: 7,
        ingest_hlc: Hlc {
            wall_ms: 1_747_680_000_000,
            logical: 3,
        },
        input: Payload {
            media_type: "text/plain".to_string(),
            body: body.to_vec(),
        },
    }
}

/// The `Input` the component builds from `invocation(body)`, for the native oracle.
fn native_input(body: &str) -> Input {
    Input {
        sender_did: "did:jig:zabc".to_string(),
        channel_id: "bafytestchannel".to_string(),
        body_raw: body.to_string(),
        hlc_wall_ms: 1_747_680_000_000,
        hlc_logical: 3,
        hlc_origin: String::new(),
        client_version: String::new(),
    }
}

/// Instantiate the component and call `render`.
fn render(engine: &Engine, component: &Component, body: &[u8]) -> Result<Payload, BlockError> {
    let mut linker = Linker::<()>::new(engine);
    // `jig:block/types` carries only types; the host supplies an empty instance for it.
    linker
        .instance("jig:block/types@0.1.0")
        .expect("types instance defines");
    let mut store = Store::new(engine, ());
    store.set_fuel(50_000_000).expect("fuel is enabled");
    let renderer = Renderer::instantiate(&mut store, component, &linker).expect("instantiates");
    renderer
        .jig_block_render()
        .call_render(&mut store, &invocation(body))
        .expect("render returns without trapping")
}

fn render_output(engine: &Engine, component: &Component, body: &str) -> Output {
    let payload = render(engine, component, body.as_bytes()).expect("render succeeds");
    assert_eq!(payload.media_type, canonical::COMPONENT_OUTPUT_MEDIA_TYPE);
    postcard::from_bytes(&payload.body).expect("body decodes as Output")
}

const CORPUS: &[&str] = &[
    "",
    "hello",
    "hi @alice, see https://example.com/x?y=1",
    "<script>alert(1)</script> & \"quotes\"",
    "ﬁ ligature and ① circled digits normalise under NFKC",
    "emoji 🧩 and combining e\u{301}",
];

#[test]
fn the_component_passes_the_profile() {
    let bytes = component_bytes();
    let report = validate_component(
        &bytes,
        &ComponentProfile {
            world: BlockWorld::Renderer,
            granted: &[],
            max_memory_pages: MAX_MEMORY_PAGES,
        },
    )
    .expect("component parses");
    assert!(report.is_compliant(), "{:?}", report.violations);
    assert_eq!(report.exports, ["jig:block/render@0.1.0"]);
}

#[test]
fn component_and_native_agree() {
    let engine = engine();
    let component = Component::new(&engine, &*component_bytes()).expect("component compiles");
    for body in CORPUS {
        assert_eq!(
            render_output(&engine, &component, body),
            execute_pure(&native_input(body)),
            "body {body:?}"
        );
    }
}

#[test]
fn render_hash_matches_the_byte_payload_module() {
    let engine = engine();
    let component = Component::new(&engine, &*component_bytes()).expect("component compiles");
    let runtime = Runtime::new().expect("runtime construction");
    for body in CORPUS {
        let input = postcard::to_allocvec(&native_input(body)).expect("input encodes");
        let module = runtime
            .execute_payload(canonical::CANONICAL_WASM, canonical::ENTRY_POINT, &input)
            .expect("byte-payload module executes");
        let from_module: Output = postcard::from_bytes(&module.bytes).expect("output decodes");
        let from_component = render_output(&engine, &component, body);
        assert_eq!(
            from_component.render_hash, from_module.render_hash,
            "body {body:?}"
        );
    }
}

#[test]
fn a_body_that_is_not_utf8_is_invalid_input() {
    let engine = engine();
    let component = Component::new(&engine, &*component_bytes()).expect("component compiles");
    match render(&engine, &component, &[0xff, 0xfe]) {
        Err(BlockError::InvalidInput(_)) => {}
        other => panic!("expected invalid-input, got {other:?}"),
    }
}
