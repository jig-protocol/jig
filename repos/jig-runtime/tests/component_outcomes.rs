//! How jig-runtime's component path classifies runs (JEP-0006, decision A3).
//!
//! Each test builds a small `jig:block/renderer@0.1.0` component from WAT, with a hand-written
//! core module behind the canonical ABI, so that one run lands in each outcome class:
//!
//! - an `err` from the guest, and a deterministic trap: comparable `Error` outcomes;
//! - fuel exhaustion, stack exhaustion and a missed deadline: `Incomplete`, never compared.
//!
//! It also checks that a component failing `jig-det-1` is refused before it compiles.

use std::time::{Duration, Instant};

use jig_core::grant::{Grant, Scope};
use jig_runtime::RuntimeError;
use jig_runtime::component::{
    BlockError, ComponentRuntime, ErrorOutcome, Hlc, IncompleteReason, Invocation, Payload,
    RenderLimits, RunOutcome, TrapCode,
};

const MAX_MEMORY_PAGES: u32 = 16;

/// A renderer whose core `render` function has the given body.
///
/// `render` receives the invocation's 13 flattened parameters and returns a pointer to the
/// lowered `result<payload, block-error>`. `realloc` is a bump allocator, enough for the host
/// to lower the invocation's strings and lists.
fn renderer(render_body: &str, extra_funcs: &str) -> Vec<u8> {
    renderer_importing("", render_body, extra_funcs)
}

fn renderer_importing(imports: &str, render_body: &str, extra_funcs: &str) -> Vec<u8> {
    let wat = format!(
        r#"(component
            {imports}
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
    run_with(
        component,
        RenderLimits {
            fuel,
            timeout: Duration::from_secs(60),
        },
    )
}

fn run_with(component: &[u8], limits: RenderLimits) -> RunOutcome {
    let runtime = ComponentRuntime::new().expect("runtime builds");
    let renderer = runtime
        .compile_renderer(component, &Grant::empty(), MAX_MEMORY_PAGES)
        .expect("test component validates and compiles");
    runtime.render(&renderer, &invocation(), &limits).outcome
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
        outcome == RunOutcome::Error(ErrorOutcome::Trap(TrapCode::Unreachable)),
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

// With fuel out of the way, the deadline alone stops a run. The loop fills the whole 64 KiB page
// each pass, so the test also checks that the deadline interrupts long bulk operations.
#[test]
fn a_bulk_memory_loop_misses_its_deadline() {
    let body = r#"
        (loop $l
            (memory.fill (i32.const 0) (i32.const 0) (i32.const 65536))
            (br $l))
        (i32.const 0)"#;
    let started = Instant::now();
    let outcome = run_with(
        &renderer(body, ""),
        RenderLimits {
            fuel: u64::MAX / 2,
            timeout: Duration::from_millis(50),
        },
    );
    assert_eq!(
        outcome,
        RunOutcome::Incomplete(IncompleteReason::DeadlineExceeded)
    );
    assert!(!outcome.is_comparable());
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_component_failing_the_profile_is_refused_before_it_compiles() {
    let body = "f32.const 1 drop (i32.const 0)";
    let runtime = ComponentRuntime::new().expect("runtime builds");
    let err = runtime
        .compile_renderer(&renderer(body, ""), &Grant::empty(), MAX_MEMORY_PAGES)
        .expect_err("a float instruction must be refused");
    assert!(err.to_string().contains("jig-det-1"), "{err}");
}

#[test]
fn the_engine_identity_names_the_exact_wasmtime_version() {
    let runtime = ComponentRuntime::new().expect("runtime builds");
    let identity = runtime.engine_identity();
    assert_eq!(identity.wasmtime, jig_runtime::WASMTIME_VERSION);
}

#[test]
fn a_renderer_may_import_only_what_its_grant_names() {
    let runtime = ComponentRuntime::new().unwrap();
    let component = renderer_importing(
        r#"(import "jig:host/compose@0.1.0" (instance))"#,
        "(unreachable)",
        "",
    );

    let Err(err) = runtime.compile_renderer(&component, &Grant::empty(), MAX_MEMORY_PAGES) else {
        panic!("an ungranted import is refused");
    };
    assert!(
        matches!(&err, RuntimeError::ValidationError(m) if m.contains("not granted")),
        "{err:?}"
    );

    let grant = Grant::from_scopes([Scope::Compose {
        children: Default::default(),
        max_depth: 1,
        max_calls: 1,
    }])
    .unwrap();
    runtime
        .compile_renderer(&component, &grant, MAX_MEMORY_PAGES)
        .expect("a granted import passes");
}
