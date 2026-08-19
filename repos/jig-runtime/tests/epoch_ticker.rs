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

/// A deadline-interrupted run must be its OWN outcome, not a generic trap.
///
/// Before this, trap classification string-matched only for fuel exhaustion and
/// sent everything else — including a wall-clock interruption — to
/// `ReasonCode::RuntimeTrap`. So a receipt could not distinguish "the program
/// faulted" from "the host was slow", and the truncated `fuel_used` was recorded
/// as though it were the program's cost. Both are wrong in ways that corrupt a
/// receipt rather than merely losing detail.
#[test]
fn a_deadline_interruption_is_distinguishable_from_a_guest_fault() {
    let wat = r#"(module (func (export "run") (loop $l br $l)))"#;
    let wasm = wat::parse_str(wat).expect("wat parses");

    let mut config = RuntimeConfig::default();
    config.limits.execution_timeout_ms = 50;
    // Fuel deliberately effectively unlimited: otherwise this would prove fuel
    // exhaustion is classified, which was never the broken case.
    config.limits.fuel_max = u64::MAX;
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let (result, _elapsed) = run_bounded(runtime, wasm);
    let receipt = result.expect("a deadline produces a receipt, not an Err");

    let outcome = receipt
        .block
        .outcome
        .as_ref()
        .expect("receipt carries an outcome");

    assert_eq!(
        outcome.status,
        jig_core::receipt::OutcomeStatus::HardFail,
        "an interrupted run must not report success"
    );
    assert_eq!(
        outcome.reason,
        Some(jig_core::receipt::ReasonCode::RuntimeTimeout),
        "a wall-clock interruption must be RuntimeTimeout, not RuntimeTrap — \
         otherwise 'the host was slow' reads as 'the program faulted'"
    );

    // And the receipt must SAY the fuel is partial, so nobody bills it or
    // compares it against another server's number.
    let error = receipt.error.as_ref().expect("an error is recorded");
    assert_eq!(error.code, "ERR_DEADLINE_EXCEEDED");
    let msg = error.message.clone().unwrap_or_default();
    assert!(
        msg.contains("PARTIAL"),
        "the message must flag fuel_used as partial, got: {msg}"
    );
}

/// A deadline-interrupted run must not be priced.
///
/// The receipt already says `fuel_used` is a PARTIAL count of a truncated run,
/// but pricing was computed from that same number, so a timed-out execution
/// produced a bill. That bill is host-dependent by construction: the slower or
/// busier the host, the further the guest gets before the interrupt, and the
/// more it is charged for identical work. Charging for the host's own slowness
/// is the one thing the fuel-portability investigation says fuel must never be
/// used for — see docs/investigations/2026-08-11-fuel-portability.md.
///
/// Absent pricing, rather than a zero cost, is the honest encoding: the receipt
/// schema already uses `pricing: None` to mean "not priced", while `0.0` would
/// read as "free" and invite someone to sum it.
///
/// Measured while writing this, and deliberately NOT asserted: today the
/// interrupt path reports `fuel_used = 0` no matter how long the guest ran
/// (verified from a 1e8 budget up to `u64::MAX`, all zero at ~60ms of looping),
/// while a guest fault on the same runtime reports millions. Wasmtime appears
/// not to write consumed fuel back to the store when an epoch interrupt unwinds.
/// So the bill this test forbids currently computes to 0.00 by accident — which
/// is precisely why the fix belongs here rather than being waved off: the day
/// that accounting is corrected, the partial count becomes a real, host-
/// dependent charge. Asserting the zero would only pin the accounting bug in
/// place.
#[test]
fn a_deadline_interrupted_run_is_not_priced() {
    let wat = r#"(module (func (export "run") (loop $l br $l)))"#;
    let wasm = wat::parse_str(wat).expect("wat parses");

    let mut config = RuntimeConfig::default();
    config.limits.execution_timeout_ms = 50;
    config.limits.fuel_max = u64::MAX;
    config.pricing.enabled = true;
    config.pricing.cost_per_fuel_unit = 0.001;
    config.pricing.currency = Some("credits".to_string());
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let (result, _elapsed) = run_bounded(runtime, wasm);
    let receipt = result.expect("a deadline produces a receipt, not an Err");

    assert_eq!(
        receipt
            .block
            .outcome
            .as_ref()
            .and_then(|o| o.reason.as_ref()),
        Some(&jig_core::receipt::ReasonCode::RuntimeTimeout),
        "precondition: this must be the deadline path, not some other trap"
    );
    assert!(
        receipt.pricing.is_none(),
        "a truncated run must carry no pricing; got {:?} — billing partial fuel \
         charges the caller for how slow the host was",
        receipt.pricing
    );
}

/// The converse, so the fix above cannot quietly disable billing everywhere.
///
/// Fuel exhaustion is a truncated run too, but its fuel number is *not*
/// host-dependent: the guest burned exactly the budget it was given, and every
/// host would report the same figure for the same input. It stays billable.
#[test]
fn an_exhausted_fuel_budget_is_still_priced() {
    let wat = r#"(module (func (export "run") (loop $l br $l)))"#;
    let wasm = wat::parse_str(wat).expect("wat parses");

    let mut config = RuntimeConfig::default();
    // Generous wall clock, tiny fuel budget: fuel must be what runs out.
    config.limits.execution_timeout_ms = 10_000;
    config.limits.fuel_max = 10_000;
    config.pricing.enabled = true;
    config.pricing.cost_per_fuel_unit = 0.001;
    let runtime = Runtime::with_config(config).expect("runtime creation");

    let (result, _elapsed) = run_bounded(runtime, wasm);
    let receipt = result.expect("fuel exhaustion produces a receipt, not an Err");

    assert_eq!(
        receipt
            .block
            .outcome
            .as_ref()
            .and_then(|o| o.reason.as_ref()),
        Some(&jig_core::receipt::ReasonCode::FuelExhausted),
        "precondition: this must be the fuel path, not the deadline"
    );
    let pricing = receipt
        .pricing
        .as_ref()
        .expect("an exhausted budget is deterministic and must still be priced");
    assert!(
        pricing.total_cost > 0.0,
        "a run that burned its whole budget must cost something"
    );
}
