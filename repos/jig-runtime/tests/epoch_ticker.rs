//! The epoch deadline must cost O(1) threads per engine, not O(1) per execution.
//!
//! Before this, `schedule_epoch_interrupt` spawned a detached thread per
//! execution that slept out the full timeout even after the execution finished.
//! A render completing in ~85 µs left a thread asleep for the remaining ~250 ms,
//! so at the protocol's 10,000 msg/s target roughly 2,500 threads accumulated at
//! steady state — scaling with message rate on the ingest hot path, and hostile
//! to the $5-VPS and Raspberry Pi deployment targets.
//!
//! These tests pin the two properties that fix has to preserve: the thread count
//! stops growing, and the deadline still actually fires.

use jig_runtime::{ExecutionContext, Runtime, RuntimeConfig};
use std::time::{Duration, Instant};

/// A module that runs essentially instantly.
const DETERMINISTIC_WASM: &[u8] = include_bytes!("fixtures/deterministic.wasm");

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

/// Execute the fixture, requiring it to actually succeed.
///
/// Discarding the result would let both thread-count tests pass while the
/// fixture failed before ever reaching the execution path — measuring the thread
/// count around a no-op and reporting it as evidence.
fn run_once(runtime: &Runtime) {
    let receipt = runtime
        .execute(DETERMINISTIC_WASM, ExecutionContext::default())
        .expect("the deterministic fixture must execute");
    assert_eq!(
        receipt.outcome,
        jig_runtime::ExecutionOutcome::Success,
        "the deterministic fixture must succeed, not merely return a receipt"
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

    let runtime = Runtime::new().expect("runtime creation");

    // Warm up first: the very first execution compiles and may spin up
    // one-time machinery, which would otherwise be counted as growth.
    for _ in 0..5 {
        run_once(&runtime);
    }
    let before = thread_count().expect("thread count");

    let executions = 200;
    for _ in 0..executions {
        run_once(&runtime);
    }
    let after = thread_count().expect("thread count");

    assert!(
        after <= before + 8,
        "thread count grew from {before} to {after} across {executions} executions — \
         the per-execution timer is back (the old design would reach ~{})",
        before + executions
    );
}

/// A ticker that outlived its engine would leak a thread per `Runtime`, which
/// tests construct freely. Build and drop several, then confirm the count
/// returned to roughly where it started.
#[test]
fn dropping_a_runtime_reclaims_its_ticker_thread() {
    let Some(before) = thread_count() else {
        eprintln!("skipping: no portable thread count on this platform");
        return;
    };

    for _ in 0..20 {
        let runtime = Runtime::new().expect("runtime creation");
        run_once(&runtime);
        drop(runtime);
    }

    let after = thread_count().expect("thread count");
    assert!(
        after <= before + 4,
        "thread count grew from {before} to {after} after building and dropping \
         20 runtimes — ticker threads are outliving their engines"
    );
}

/// Execute on a worker thread, failing the test if nothing comes back in time.
///
/// These two tests run a guest that loops forever, so a ticker that stopped
/// advancing would leave `execute` blocked and the assertions unreachable — the
/// test would hang until CI's job timeout rather than failing. Bounding it turns
/// a broken ticker into a prompt, legible failure.
///
/// The worker is abandoned rather than joined on timeout: it is still spinning
/// inside the guest by definition, and the process reaps it on exit.
fn run_bounded(
    runtime: Runtime,
    wasm: Vec<u8>,
) -> (jig_runtime::Result<jig_runtime::Receipt>, Duration) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let started = Instant::now();
        let result = runtime.execute(&wasm, ExecutionContext::default());
        let _ = tx.send((result, started.elapsed()));
    });

    rx.recv_timeout(Duration::from_secs(10))
        .expect("execution did not return within 10s — the epoch deadline never fired")
}

/// The deadline must still interrupt a guest that overruns it.
///
/// Uses a module that runs effectively forever with a short timeout, so only the
/// deadline can end it. Bounded via `run_bounded`, so a deadline that never fires
/// surfaces as a 10s failure rather than a hang.
#[test]
fn a_deadline_still_interrupts_a_long_running_guest() {
    // An infinite loop, so only the deadline can end it. Fuel is set high enough
    // that the wall clock is what runs out first — otherwise this would prove
    // fuel exhaustion works, not the epoch.
    let wat = r#"(module (func (export "run") (loop $l br $l)))"#;
    let wasm = wat::parse_str(wat).expect("wat parses");

    let mut config = RuntimeConfig::default();
    config.limits.execution_timeout_ms = 50;
    config.limits.fuel_max = u64::MAX;
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let (result, elapsed) = run_bounded(runtime, wasm);

    // Either an Err or a receipt with a failed outcome is acceptable; what
    // matters is that it STOPPED.
    if let Ok(receipt) = result {
        assert_ne!(
            receipt.outcome,
            jig_runtime::ExecutionOutcome::Success,
            "an infinite loop must not report success"
        );
    }

    assert!(
        elapsed < Duration::from_secs(10),
        "took {elapsed:?} — the deadline did not fire promptly"
    );
}

/// The ticker's cadence is the granularity of every timeout, so a deadline
/// overshoots but must never fire *early*. Firing early truncates a run and
/// records a partial `fuel_used` as though it were the program's cost — the
/// receipt corruption described in the fuel-portability investigation.
#[test]
fn a_deadline_never_fires_before_its_timeout() {
    let wat = r#"(module (func (export "run") (loop $l br $l)))"#;
    let wasm = wat::parse_str(wat).expect("wat parses");

    let timeout_ms = 100;
    let mut config = RuntimeConfig::default();
    config.limits.execution_timeout_ms = timeout_ms;
    config.limits.fuel_max = u64::MAX;
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let (_, elapsed) = run_bounded(runtime, wasm);

    assert!(
        elapsed >= Duration::from_millis(timeout_ms),
        "interrupted after {elapsed:?}, before its {timeout_ms}ms budget — an \
         early interrupt reports a partial fuel_used as the program's cost"
    );
}
