//! Is `fuel_used` a property of the program, or of the machine that ran it?
//!
//! It has to be the former. Receipts carry `fuel_used`, pricing derives from it,
//! and cross-server receipt agreement depends on two servers deriving the same
//! number from the same block. If fuel varies with host speed or load, none of
//! that holds — and it cannot be fixed by a conversion table, because there is
//! no stable quantity to convert between.
//!
//! Wasmtime documents fuel as deterministic: "the same program always uses the
//! same fuel for the same input." The one documented cross-architecture
//! exception is relaxed-SIMD lowering, and jig-runtime already disables SIMD and
//! relaxed SIMD outright.
//!
//! So a divergence points at our own configuration, and these tests localise it:
//! `epoch_interruption` is enabled alongside fuel, with a default 250 ms
//! WALL-CLOCK deadline. Wasmtime's determinism guide names epoch interruption as
//! the *non-deterministic* alternative to fuel. When the deadline fires
//! mid-execution the run is truncated, and the fuel counter faithfully reports a
//! partial execution — so `fuel_used` becomes a function of how fast and how
//! loaded the host was.
//!
//! Observed in CI: 1713 against a golden of 18098 for the same module and the
//! same wasmtime, on a runner executing ~1232 tests in parallel.

use jig_runtime::{ExecutionContext, ExecutionOutcome, Runtime, RuntimeConfig};

const HELLO_WASI_WASM: &[u8] = include_bytes!("fixtures/hello_wasi.wasm");
const DETERMINISTIC_WASM: &[u8] = include_bytes!("fixtures/deterministic.wasm");

struct Run {
    fuel_used: u64,
    outcome: ExecutionOutcome,
    /// `Runtime::execute` can return `Err` outright under contention — observed
    /// locally when the jig-runtime suite runs in parallel. Captured rather than
    /// unwrapped so a diagnostic run reports the failure instead of dying on it.
    error: Option<String>,
}

/// Execute `wasm` with an explicit wall-clock timeout, changing nothing else.
fn run_with_timeout_ms(wasm: &[u8], timeout_ms: u64) -> Run {
    let mut config = RuntimeConfig::default();
    config.limits.execution_timeout_ms = timeout_ms;

    let runtime = Runtime::with_config(config).expect("runtime creation");
    match runtime.execute(wasm, ExecutionContext::default()) {
        Ok(receipt) => Run {
            fuel_used: receipt.fuel_used(),
            outcome: receipt.outcome,
            error: None,
        },
        Err(e) => Run {
            fuel_used: 0,
            outcome: ExecutionOutcome::ExecutionFailed,
            error: Some(e.to_string()),
        },
    }
}

/// The property receipts need: a completed run costs the same fuel regardless of
/// how much wall-clock headroom it was given.
///
/// A failure here is the whole problem in miniature — it means `fuel_used`
/// describes the host, not the program.
#[test]
fn fuel_for_a_completed_run_is_independent_of_the_wall_clock_budget() {
    // Generous budgets only: every one of these should complete comfortably, so
    // any variation is attributable to the deadline mechanism rather than to a
    // genuinely truncated run.
    let budgets = [1_000, 5_000, 30_000];

    for wasm in [HELLO_WASI_WASM, DETERMINISTIC_WASM] {
        let runs: Vec<Run> = budgets
            .iter()
            .map(|ms| run_with_timeout_ms(wasm, *ms))
            .collect();

        // Only COMPLETED runs are comparable. A run that errored or was cut
        // short measured something other than the program, so it is dropped
        // rather than asserted against — that is the difference between this
        // test and a timing-sensitive one.
        let measured: Vec<(u64, u64)> = budgets
            .iter()
            .zip(&runs)
            .filter(|(_, r)| r.error.is_none() && matches!(r.outcome, ExecutionOutcome::Success))
            .map(|(ms, r)| (*ms, r.fuel_used))
            .collect();

        // Guard against passing vacuously: if load ate almost everything there is
        // nothing to compare, and silence would look like success.
        assert!(
            measured.len() >= 2,
            "need at least two completed runs to compare; got {} of {} \
             (outcomes: {:?})",
            measured.len(),
            budgets.len(),
            runs.iter()
                .map(|r| (r.outcome, r.error.clone()))
                .collect::<Vec<_>>()
        );

        let (_, first) = measured[0];
        for (budget, fuel) in &measured {
            assert_eq!(
                *fuel, first,
                "fuel changed with the wall-clock budget ({budget}ms gave {fuel}, \
                 baseline gave {first}) — fuel_used is describing the host, not \
                 the program, so no two servers can be expected to agree on it"
            );
        }
    }
}

/// The mechanism, demonstrated deliberately: starve the wall clock and the same
/// module reports LESS fuel, because it was cut off partway.
///
/// This is what a loaded CI runner does to a 250 ms default by accident. The
/// test documents the causal chain rather than asserting a specific number,
/// since exactly where a 1 ms deadline lands is itself timing-dependent.
///
/// `#[ignore]` deliberately: whether a 1 ms budget truncates depends on machine
/// speed and load, so in a parallel suite this flakes — for the very reason it
/// exists to document. The fuel-portability matrix runs it with
/// `--include-ignored`, where a flake IS the datum.
#[test]
#[ignore = "timing-sensitive diagnostic; run via the fuel-portability matrix"]
fn a_starved_wall_clock_budget_truncates_the_run_and_undercounts_fuel() {
    let complete = run_with_timeout_ms(HELLO_WASI_WASM, 30_000);
    assert!(
        complete.error.is_none() && matches!(complete.outcome, ExecutionOutcome::Success),
        "baseline run should complete, got {:?} error={:?}",
        complete.outcome,
        complete.error
    );

    // 1ms is far below what instantiation plus two writes needs.
    let starved = run_with_timeout_ms(HELLO_WASI_WASM, 1);

    if matches!(starved.outcome, ExecutionOutcome::Success) {
        // The machine beat the deadline. Not a failure of the point being made,
        // and not something to assert against — but then fuel must still agree.
        assert_eq!(
            starved.fuel_used, complete.fuel_used,
            "a run that completed under a 1ms budget must still cost the same fuel"
        );
        return;
    }

    assert!(
        starved.fuel_used < complete.fuel_used,
        "a truncated run should report less fuel than a complete one \
         (truncated {}, complete {})",
        starved.fuel_used,
        complete.fuel_used
    );
}

/// Fuel must not depend on how many other things the host is doing.
///
/// Runs the same module while the machine is busy. Under a wall-clock deadline
/// this is exactly the shape that fails in CI, where hundreds of tests share the
/// cores.
///
/// `#[ignore]` for the same reason as above: it manufactures contention, so it
/// cannot also be a stable member of a contended suite. Run it deliberately.
#[test]
#[ignore = "manufactures host load; run via the fuel-portability matrix"]
fn fuel_is_stable_under_host_load() {
    let quiet = run_with_timeout_ms(HELLO_WASI_WASM, 30_000);

    let threads: Vec<_> = (0..std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4))
        .map(|_| {
            std::thread::spawn(|| {
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(400);
                let mut spins: u64 = 0;
                while std::time::Instant::now() < deadline {
                    spins = spins.wrapping_add(1);
                }
                spins
            })
        })
        .collect();

    let under_load = run_with_timeout_ms(HELLO_WASI_WASM, 30_000);

    for t in threads {
        let _ = t.join();
    }

    assert_eq!(
        under_load.fuel_used, quiet.fuel_used,
        "fuel changed under host load (loaded {}, quiet {}) — receipts would \
         disagree between a busy server and an idle one",
        under_load.fuel_used, quiet.fuel_used
    );
}

/// Report the numbers for this host so a CI matrix across targets produces a
/// comparable table. Always passes; the value is in the captured output.
#[test]
fn report_this_host_fuel_profile() {
    println!("FUEL-PROFILE arch={}", std::env::consts::ARCH);
    println!("FUEL-PROFILE os={}", std::env::consts::OS);
    println!(
        "FUEL-PROFILE cores={}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );

    // A generous budget is the reference: this is what fuel SHOULD be everywhere.
    for (name, wasm) in [
        ("hello_wasi", HELLO_WASI_WASM),
        ("deterministic", DETERMINISTIC_WASM),
    ] {
        let r = run_with_timeout_ms(wasm, 30_000);
        println!(
            "FUEL-PROFILE reference {name} fuel_used={} outcome={:?} error={:?}",
            r.fuel_used, r.outcome, r.error
        );
    }

    // The sweep across wall-clock budgets, including the 250ms production
    // default. Any row differing from the reference is the deadline truncating
    // execution — the effect being investigated, made visible per platform.
    for ms in [1, 5, 25, 250, 1_000] {
        let r = run_with_timeout_ms(HELLO_WASI_WASM, ms);
        println!(
            "FUEL-PROFILE sweep hello_wasi timeout_ms={ms} fuel_used={} outcome={:?} error={:?}",
            r.fuel_used, r.outcome, r.error
        );
    }
}
