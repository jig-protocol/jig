//! How jig-runtime's component path classifies runs (JEP-0006, decision A3).
//!
//! Each test builds a small `jig:block/renderer@0.1.0` component from WAT, with a hand-written
//! core module behind the canonical ABI, so that one run lands in each outcome class:
//!
//! - an `err` from the guest, and a deterministic trap: comparable `Error` outcomes;
//! - fuel exhaustion and stack exhaustion: `Incomplete`, never compared.
//!
//! It also checks that a component failing `jig-det-1` is refused before it compiles.

use jig_runtime::component::{
    BlockError, ComponentRuntime, ErrorOutcome, Hlc, IncompleteReason, Invocation, Payload,
    RunOutcome,
};

const MAX_MEMORY_PAGES: u32 = 16;

/// A renderer whose core `render` function has the given body.
///
/// `render` receives the invocation's 13 flattened parameters and returns a pointer to the
/// lowered `result<payload, block-error>`. `realloc` is a bump allocator, enough for the host
/// to lower the invocation's strings and lists.
fn renderer(render_body: &str, extra_funcs: &str) -> Vec<u8> {
    let wat = format!(
        r#"(component
            (type $hlc (record (field "wall-ms" u64) (field "logical" u32)))
            (type $payload (record (field "media-type" string) (field "body" (list u8))))
            (type $invocation (record
                (field "block-cid" string)
                (field "sender-did" string)
                (field "channel-cid" string)
                (field "ingest-seq" u64)
                (field "ingest-hlc" $hlc)
                (field "input" $payload)))
            (type $block-error (variant (case "invalid-input" string) (case "failed" string)))
            (type $render (func (param "inv" $invocation)
                (result (result $payload (error $block-error)))))

            (core module $m
                (memory (export "memory") 1 1)
                (global $bump (mut i32) (i32.const 4096))
                (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                    (local $p i32)
                    (local.set $p (global.get $bump))
                    (global.set $bump (i32.add (global.get $bump) (local.get 3)))
                    (local.get $p))
                {extra_funcs}
                (func (export "render")
                    (param i32 i32 i32 i32 i32 i32 i64 i64 i32 i32 i32 i32 i32)
                    (result i32)
                    {render_body}))
            (core instance $i (instantiate $m))
            (alias core export $i "memory" (core memory $mem))
            (func $render-lifted (type $render)
                (canon lift (core func $i "render")
                    (memory $mem) (realloc (core func $i "realloc"))))
            (instance $exports
                (export "hlc" (type $hlc))
                (export "payload" (type $payload))
                (export "invocation" (type $invocation))
                (export "block-error" (type $block-error))
                (export "render" (func $render-lifted)))
            (export "jig:block/render@0.1.0" (instance $exports)))"#
    );
    wat::parse_str(wat).expect("test component WAT parses")
}

fn invocation() -> Invocation {
    Invocation {
        block_cid: "bafyblock".into(),
        sender_did: "did:jig:zabc".into(),
        channel_cid: "bafychannel".into(),
        ingest_seq: 1,
        ingest_hlc: Hlc {
            wall_ms: 1,
            logical: 0,
        },
        input: Payload {
            media_type: "text/plain".into(),
            body: b"hi".to_vec(),
        },
    }
}

fn run(component: &[u8], fuel: u64) -> RunOutcome {
    let runtime = ComponentRuntime::new().expect("runtime builds");
    let renderer = runtime
        .compile_renderer(component, MAX_MEMORY_PAGES)
        .expect("test component validates and compiles");
    runtime.render(&renderer, &invocation(), fuel).outcome
}

#[test]
fn a_guest_err_is_a_comparable_error() {
    // Lower `err(failed("x"))` at 256: result discriminant 1, variant discriminant 1 at offset
    // 4, then the string's pointer and length.
    let body = r#"
        (i32.store8 (i32.const 256) (i32.const 1))
        (i32.store8 (i32.const 260) (i32.const 1))
        (i32.store (i32.const 264) (i32.const 512))
        (i32.store (i32.const 268) (i32.const 1))
        (i32.store8 (i32.const 512) (i32.const 120))
        (i32.const 256)"#;
    let outcome = run(&renderer(body, ""), 1_000_000);
    assert_eq!(
        outcome,
        RunOutcome::Error(ErrorOutcome::Guest(BlockError::Failed("x".into())))
    );
    assert!(outcome.is_comparable());
}

#[test]
fn unreachable_is_a_comparable_trap() {
    let outcome = run(&renderer("unreachable", ""), 1_000_000);
    assert!(
        matches!(outcome, RunOutcome::Error(ErrorOutcome::Trap(_))),
        "{outcome:?}"
    );
    assert!(outcome.is_comparable());
}

#[test]
fn fuel_exhaustion_is_incomplete() {
    let body = "(loop $l (br $l)) (i32.const 0)";
    let outcome = run(&renderer(body, ""), 10_000);
    assert_eq!(
        outcome,
        RunOutcome::Incomplete(IncompleteReason::FuelExhausted)
    );
    assert!(!outcome.is_comparable());
}

#[test]
fn stack_exhaustion_is_incomplete() {
    let recurse = "(func $deep (call $deep))";
    let body = "(call $deep) (i32.const 0)";
    let outcome = run(&renderer(body, recurse), u64::MAX / 2);
    assert_eq!(
        outcome,
        RunOutcome::Incomplete(IncompleteReason::StackExhausted)
    );
    assert!(!outcome.is_comparable());
}

#[test]
fn a_component_failing_the_profile_is_refused_before_it_compiles() {
    let body = "f32.const 1 drop (i32.const 0)";
    let runtime = ComponentRuntime::new().expect("runtime builds");
    let err = runtime
        .compile_renderer(&renderer(body, ""), MAX_MEMORY_PAGES)
        .expect_err("a float instruction must be refused");
    assert!(err.to_string().contains("jig-det-1"), "{err}");
}

#[test]
fn the_engine_identity_names_the_exact_wasmtime_version() {
    let runtime = ComponentRuntime::new().expect("runtime builds");
    let identity = runtime.engine_identity();
    assert_eq!(identity.wasmtime, jig_runtime::WASMTIME_VERSION);
}
