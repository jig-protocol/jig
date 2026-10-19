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
//! It runs through jig-runtime's component path (`jig_runtime::component`), the same one the
//! server and client use.
//!
//! As with the module, CI runs the suite twice: once against the committed artifact, and once
//! with `JIG_TEXT_BLOCK_COMPONENT` pointing at a fresh build. Wasm output is not reproducible
//! across hosts, so the two are held together by behaviour, not bytes.

use jig_core::component_validation::{BlockWorld, ComponentProfile, validate_component};
use jig_core::grant::Grant;
use jig_runtime::Runtime;
use jig_runtime::component::{
    BlockError, CompiledRenderer, ComponentRuntime, ErrorOutcome, Hlc, Invocation, Payload,
    RenderLimits, RunOutcome,
};
use text_block::{Input, Output, canonical, execute_pure};

const LIMITS: RenderLimits = RenderLimits {
    fuel: 50_000_000,
    timeout: std::time::Duration::from_secs(60),
};

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

fn compiled() -> (ComponentRuntime, CompiledRenderer) {
    let runtime = ComponentRuntime::new().expect("component runtime builds");
    let renderer = runtime
        .compile_renderer(&component_bytes(), &Grant::empty(), MAX_MEMORY_PAGES)
        .expect("text-block component validates and compiles");
    (runtime, renderer)
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

fn render(runtime: &ComponentRuntime, renderer: &CompiledRenderer, body: &[u8]) -> RunOutcome {
    runtime.render(renderer, &invocation(body), &LIMITS).outcome
}

fn render_output(runtime: &ComponentRuntime, renderer: &CompiledRenderer, body: &str) -> Output {
    let RunOutcome::Ok(payload) = render(runtime, renderer, body.as_bytes()) else {
        panic!("render of {body:?} did not succeed");
    };
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
    let (runtime, renderer) = compiled();
    for body in CORPUS {
        assert_eq!(
            render_output(&runtime, &renderer, body),
            execute_pure(&native_input(body)),
            "body {body:?}"
        );
    }
}

#[test]
fn render_hash_matches_the_byte_payload_module() {
    let (runtime, renderer) = compiled();
    let module_runtime = Runtime::new().expect("runtime construction");
    for body in CORPUS {
        let input = postcard::to_allocvec(&native_input(body)).expect("input encodes");
        let module = module_runtime
            .execute_payload(canonical::CANONICAL_WASM, canonical::ENTRY_POINT, &input)
            .expect("byte-payload module executes");
        let from_module: Output = postcard::from_bytes(&module.bytes).expect("output decodes");
        let from_component = render_output(&runtime, &renderer, body);
        assert_eq!(
            from_component.render_hash, from_module.render_hash,
            "body {body:?}"
        );
    }
}

#[test]
fn a_body_that_is_not_utf8_is_invalid_input() {
    let (runtime, renderer) = compiled();
    match render(&runtime, &renderer, &[0xff, 0xfe]) {
        RunOutcome::Error(ErrorOutcome::Guest(BlockError::InvalidInput(_))) => {}
        other => panic!("expected invalid-input, got {other:?}"),
    }
}
