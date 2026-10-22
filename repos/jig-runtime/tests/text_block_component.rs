//! Executes the `text-block` renderer component (JEP-0006, first-slice step 5).
//!
//! The component is the `text-render` block for the `jig:block/renderer@0.1.0` world. This
//! suite pins three things:
//!
//! - the committed artifact passes jig-core's component validator (`jig-det-1`);
//! - its output matches text-block's native `execute_pure`, the shared oracle;
//! - its `render_hash` for a fixed corpus is what the byte-payload module (ABI 1) produced
//!   before it was deleted, so servers on mixed versions keep agreeing.
//!
//! It runs through jig-runtime's component path (`jig_runtime::component`), the same one the
//! server and client use.
//!
//! CI runs the suite twice: once against the committed artifact, and once
//! with `JIG_TEXT_BLOCK_COMPONENT` pointing at a fresh build. Wasm output is not reproducible
//! across hosts, so the two are held together by behaviour, not bytes.

use jig_core::component_validation::{BlockWorld, ComponentProfile, validate_component};
use jig_core::grant::Grant;
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
/// resolved against the workspace root (`repos/`), which is where CI runs from.
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

/// `render_hash` for each body in [`CORPUS`], as the byte-payload module (ABI 1) produced it
/// before it was deleted. A server or client on any version must keep producing these, or
/// servers on mixed versions stop agreeing.
const RENDER_HASHES: &[&str] = &[
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f",
    "e2e526e9f22bd44ee96c841e6d16837198f116c70bb3a68f449251f508a61d75",
    "fc9abd2ab1d9b73e164db57ed088c28c5e9f4ea598a13de45eded347e7ef03d2",
    "e0429a89d7d07b06101b6ec461847bdcba8c5ccff91b3f3d9b541ae19c0313b3",
    "0b2f21fbcf847c67fbc32b5d027a4a0eec7fceeda9ee57bb38a8a2a853eb52db",
];

#[test]
fn render_hash_has_not_moved() {
    let (runtime, renderer) = compiled();
    assert_eq!(CORPUS.len(), RENDER_HASHES.len());
    for (body, expected) in CORPUS.iter().zip(RENDER_HASHES) {
        assert_eq!(
            render_output(&runtime, &renderer, body).render_hash,
            *expected,
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
