//! The epoch deadline must cost O(1) threads per engine, not O(1) per execution.
//!
//! Before this, `schedule_epoch_interrupt` spawned a detached thread per
//! execution that slept out the full timeout even after the execution finished.
//! A render completing in ~85 µs left a thread asleep for the remaining ~250 ms,
//! so at the protocol's 10,000 msg/s target roughly 2,500 threads accumulated at
//! steady state — scaling with message rate on the ingest hot path, and hostile
//! to the $5-VPS and Raspberry Pi deployment targets.
//!
//! These tests pin what that fix has to preserve on the component path: the
//! thread count stops growing, a dropped runtime takes its ticker with it, and a
//! deadline never fires early. `component_outcomes.rs` checks that a deadline
//! does fire, and that a missed one is `incomplete`.

use std::time::{Duration, Instant};

use jig_core::grant::Grant;
use jig_runtime::component::{
    CompiledRenderer, ComponentRuntime, Hlc, IncompleteReason, Invocation, Payload, RenderLimits,
    RunOutcome,
};
use text_block::canonical;

/// The text-block component's declared memory maximum: 16 MiB.
const TEXT_BLOCK_MEMORY_PAGES: u32 = 256;

const LIMITS: RenderLimits = RenderLimits {
    fuel: 50_000_000,
    timeout: Duration::from_secs(60),
};

/// Live threads in this process.
///
/// Linux exposes this directly; elsewhere there is no portable equivalent, so
/// the count-based tests below are skipped rather than asserted against a number
/// that does not mean what it says.
#[cfg(target_os = "linux")]
fn thread_count() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
}

#[cfg(not(target_os = "linux"))]
fn thread_count() -> Option<usize> {
    None
}

fn invocation(body: &[u8]) -> Invocation {
    Invocation {
        block_cid: "bafyblock".into(),
        sender_did: "did:jig:zabc".into(),
        channel_cid: "bafychannel".into(),
        ingest_seq: 1,
        ingest_hlc: Hlc {
            wall_ms: 1_747_680_000_000,
            logical: 0,
        },
        input: Payload {
            media_type: "text/plain".into(),
            body: body.to_vec(),
        },
    }
}

fn text_block(runtime: &ComponentRuntime) -> CompiledRenderer {
    runtime
        .compile_renderer(
            canonical::CANONICAL_COMPONENT,
            &Grant::empty(),
            TEXT_BLOCK_MEMORY_PAGES,
        )
        .expect("the text-block component compiles")
}

/// Render once, requiring it to actually succeed.
///
/// Discarding the outcome would let both thread-count tests pass while the
/// render failed before ever reaching the execution path — measuring the thread
/// count around a no-op and reporting it as evidence.
fn run_once(runtime: &ComponentRuntime, renderer: &CompiledRenderer) {
    let run = runtime.render(renderer, &invocation(b"hello"), &LIMITS);
    assert!(
        matches!(run.outcome, RunOutcome::Ok(_)),
        "the render must succeed, not merely return: {:?}",
        run.outcome
    );
}

/// The headline property from #36: executions must not accumulate threads.
///
/// Sampling is deliberately generous — a few threads of slack absorbs the
/// runtime's own pooling and any test-harness churn. The old behaviour would
/// have added one thread per execution and blown past it by two orders of
/// magnitude, so the assertion does not need to be tight to be decisive.
#[test]
fn executions_do_not_accumulate_threads() {
    let Some(_) = thread_count() else {
        eprintln!("skipping: no portable thread count on this platform");
        return;
    };

    let runtime = ComponentRuntime::new().expect("runtime creation");
    let renderer = text_block(&runtime);

    // Warm up first: the first runs may spin up one-time machinery, which would
    // otherwise be counted as growth.
    for _ in 0..5 {
        run_once(&runtime, &renderer);
    }
    let before = thread_count().expect("thread count");

    let executions = 200;
    for _ in 0..executions {
        run_once(&runtime, &renderer);
    }
    let after = thread_count().expect("thread count");

    assert!(
        after <= before + 8,
        "thread count grew from {before} to {after} across {executions} executions — \
         the per-execution timer is back (the old design would reach ~{})",
        before + executions
    );
}

/// A ticker that outlived its engine would leak a thread per runtime, which
/// tests construct freely. Build and drop several, then confirm the count
/// returned to where it was after the runtime's one-time threads existed.
///
/// The first engine starts wasmtime's process-global rayon pool — one worker
/// per CPU, and it lives until process exit. Sampling before that pool exists
/// counts those workers as leaked tickers, so the budget is measured after the
/// pool is up; otherwise the assertion is about the host's CPU count.
#[test]
fn dropping_a_runtime_reclaims_its_ticker_thread() {
    let Some(_) = thread_count() else {
        eprintln!("skipping: no portable thread count on this platform");
        return;
    };

    {
        let runtime = ComponentRuntime::new().expect("runtime creation");
        run_once(&runtime, &text_block(&runtime));
    }
    let before = thread_count().expect("thread count");

    for _ in 0..20 {
        let runtime = ComponentRuntime::new().expect("runtime creation");
        run_once(&runtime, &text_block(&runtime));
    }

    // Join can return while `/proc` still lists the thread. A leaked ticker
    // stays; a reaped one leaves within a few milliseconds.
    let after = settled_thread_count(before);
    assert!(
        after <= before,
        "thread count grew from {before} to {after} after building and dropping \
         20 runtimes — ticker threads are outliving their engines"
    );
}

/// Re-read the thread count until it falls back to `target`, or 5 s passes.
///
/// The window is generous on purpose. A reaped thread leaves `/proc` within
/// milliseconds on an idle machine but can take longer on a loaded CI runner,
/// and the loop returns as soon as the count falls, so a passing run pays
/// nothing for it. A leaked ticker never leaves, so the window does not
/// weaken the check.
fn settled_thread_count(target: usize) -> usize {
    let mut last = thread_count().expect("thread count");
    let start = Instant::now();
    while last > target && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(1));
        last = thread_count().expect("thread count");
    }
    last
}

/// A renderer whose core `render` loops forever, so only the deadline can end it.
fn looping_renderer() -> Vec<u8> {
    wat::parse_str(
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
                (func (export "render")
                    (param i32 i32 i32 i32 i32 i32 i64 i64 i32 i32 i32 i32 i32)
                    (result i32)
                    (loop $l (br $l))
                    (i32.const 0)))
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
            (export "jig:block/render@0.1.0" (instance $exports)))"#,
    )
    .expect("test component WAT parses")
}

/// The ticker's cadence is the granularity of every timeout, so a deadline
/// overshoots but must never fire *early*. A run cut short records a partial
/// `fuel_used`, and is `incomplete` when the guest might have finished in time.
///
/// Run on a worker and bounded, so a ticker that never fires fails in 10 s
/// rather than hanging the test until CI's job timeout. On timeout the worker is
/// abandoned, not joined: it is still spinning inside the guest by definition.
#[test]
fn a_deadline_never_fires_before_its_timeout() {
    let timeout = Duration::from_millis(100);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = ComponentRuntime::new().expect("runtime creation");
        let renderer = runtime
            .compile_renderer(&looping_renderer(), &Grant::empty(), 1)
            .expect("the looping renderer compiles");
        let started = Instant::now();
        let run = runtime.render(
            &renderer,
            &invocation(b""),
            &RenderLimits {
                fuel: u64::MAX / 2,
                timeout,
            },
        );
        let _ = tx.send((run.outcome, started.elapsed()));
    });
    let (outcome, elapsed) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("render did not return within 10s — the epoch deadline never fired");

    assert_eq!(
        outcome,
        RunOutcome::Incomplete(IncompleteReason::DeadlineExceeded)
    );
    assert!(
        elapsed >= timeout,
        "interrupted after {elapsed:?}, before its {timeout:?} budget"
    );
}
