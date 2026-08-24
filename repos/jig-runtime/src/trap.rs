//! What a wasmtime trap means for a receipt.
//!
//! Three things end a guest and they must not be conflated: the program burned
//! its fuel budget, the HOST cut the program short, or the program genuinely
//! faulted. A receipt that blurs them cannot answer the only questions anyone
//! asks of it — was this the program's fault, and may this be billed?
//!
//! The policy lives here rather than at the call sites because there are two of
//! them (`Runtime::execute` and the WASI path) and they must agree. When the
//! policy was inline, a fix landed in one copy and not the other, which is
//! exactly the failure this module exists to prevent.

use crate::api::Outcome;
use crate::receipt::ExecutionOutcome;
use jig_core::receipt::ReasonCode;

/// How a guest stopped, as far as a receipt is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrapKind {
    /// The program burned its own fuel budget. `fuel_used` equals the limit and
    /// is the same on every host, because the budget is what determined it.
    FuelExhausted,
    /// The wall-clock deadline fired and the host interrupted a program that was
    /// still running. `fuel_used` is a PARTIAL count of a truncated execution:
    /// how far the guest got depends on how fast the host was, so a slower or
    /// busier machine reports a different number for identical input.
    DeadlineExceeded,
    /// A genuine guest fault. `fuel_used` is the program's own consumption up to
    /// the fault.
    Fault,
}

/// Classify a trap from wasmtime's typed `Trap`, and nothing else.
///
/// Measured against wasmtime 47.0.3, which is why there is no message fallback:
///
/// | what happened | `downcast_ref::<Trap>()` | `err.to_string()` |
/// |---|---|---|
/// | fuel budget burned | `Some(OutOfFuel)`  | a bare wasm backtrace |
/// | epoch deadline fired | `Some(Interrupt)` | a bare wasm backtrace |
/// | host function returned `Err` | `None`     | a bare wasm backtrace |
///
/// Two things follow. First, **the display text is worthless here** — all three
/// render as the same backtrace, with the host's own message reachable only
/// through the source chain (`{:#}`), never through `to_string()`. An earlier
/// classifier matched on `"all fuel consumed"` / `"fuel exhausted"` / `"out of
/// fuel"` and so recognised no real fuel exhaustion at all, reporting every one
/// as a guest fault.
///
/// Second, the typed variant covers every case we can produce, so a text
/// fallback could only ever add false positives. The removed one matched a bare
/// `"interrupt"`, which would have claimed anything merely *containing* that
/// word — an EINTR surfacing from a WASI syscall, say — was a deadline, and a
/// deadline verdict suppresses billing. That is a data-integrity bug waiting on
/// a wording change rather than a bug today, since `to_string()` does not carry
/// host text in this version. It is deleted rather than narrowed because it has
/// no demonstrated upside to trade against that risk.
///
/// A host error is a `Fault`: the guest did stop, and we know nothing more.
/// `Fault` is also the right home for every other `Trap` variant — an
/// out-of-bounds access or an `unreachable` is the program's own doing.
///
/// The end-to-end guard for this is
/// `epoch_ticker::a_deadline_interruption_is_distinguishable_from_a_guest_fault`,
/// which drives a real epoch interrupt. If wasmtime ever stops attaching the
/// typed trap, that test fails rather than this silently degrading.
pub(crate) fn classify_trap(err: &wasmtime::Error) -> TrapKind {
    match err.downcast_ref::<wasmtime::Trap>() {
        Some(wasmtime::Trap::OutOfFuel) => TrapKind::FuelExhausted,
        Some(wasmtime::Trap::Interrupt) => TrapKind::DeadlineExceeded,
        _ => TrapKind::Fault,
    }
}

/// The receipt-facing consequences of a trap.
pub(crate) struct TrapVerdict {
    pub outcome: Outcome,
    pub legacy_outcome: ExecutionOutcome,
    pub error_code: &'static str,
    pub error_message: String,
    /// Whether `fuel_used` may be priced.
    ///
    /// False only for a deadline interruption, where the number measures the
    /// host's speed rather than the program's work. Billing it would charge a
    /// caller more for identical input on a busier server — the one use of fuel
    /// ruled out by `docs/investigations/2026-08-11-fuel-portability.md`.
    pub fuel_is_billable: bool,
}

/// Map a trap to the outcome, error and billability a receipt should record.
pub(crate) fn trap_verdict(err: &wasmtime::Error, fuel_used: u64, fuel_limit: u64) -> TrapVerdict {
    match classify_trap(err) {
        TrapKind::FuelExhausted => {
            #[cfg(feature = "tracing")]
            tracing::info!(fuel_used, fuel_limit, "Fuel budget exhausted");

            TrapVerdict {
                outcome: Outcome::HardFailure {
                    reason: ReasonCode::FuelExhausted,
                },
                legacy_outcome: ExecutionOutcome::LimitsExceeded,
                error_code: "ERR_FUEL_EXHAUSTED",
                error_message: format!("Fuel exhausted: used {fuel_used} of {fuel_limit} limit"),
                fuel_is_billable: true,
            }
        }
        TrapKind::DeadlineExceeded => TrapVerdict {
            outcome: Outcome::HardFailure {
                reason: ReasonCode::RuntimeTimeout,
            },
            legacy_outcome: ExecutionOutcome::LimitsExceeded,
            error_code: "ERR_DEADLINE_EXCEEDED",
            error_message: format!(
                "execution exceeded the wall-clock deadline; fuel_used={fuel_used} is a \
                 PARTIAL count of a truncated run, not the program's cost"
            ),
            fuel_is_billable: false,
        },
        TrapKind::Fault => TrapVerdict {
            outcome: Outcome::HardFailure {
                reason: ReasonCode::RuntimeTrap,
            },
            legacy_outcome: ExecutionOutcome::ExecutionFailed,
            error_code: "ERR_TRAP",
            error_message: err.to_string(),
            fuel_is_billable: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two classifications that carry consequences must come from the typed
    /// trap, since that is the only signal wasmtime 47 actually provides.
    #[test]
    fn the_typed_trap_drives_both_limit_classifications() {
        assert_eq!(
            classify_trap(&wasmtime::Error::from(wasmtime::Trap::OutOfFuel)),
            TrapKind::FuelExhausted
        );
        assert_eq!(
            classify_trap(&wasmtime::Error::from(wasmtime::Trap::Interrupt)),
            TrapKind::DeadlineExceeded
        );
    }

    /// Regression: a host-originating error must never be read as a deadline.
    ///
    /// A WASI syscall surfacing EINTR is the realistic source of the word
    /// "interrupted" in an error that is not a deadline at all. Classifying it
    /// as one would both mislabel the failure and, because a deadline verdict is
    /// unbillable, silently waive the charge for a run that really did fault.
    #[test]
    fn a_host_error_mentioning_interruption_is_not_a_deadline() {
        for msg in [
            "Interrupted system call (os error 4)",
            "request interrupted",
            "epoch deadline reached",
            "all fuel consumed",
        ] {
            let verdict = trap_verdict(&wasmtime::Error::msg(msg), 7, 100);
            assert_eq!(
                classify_trap(&wasmtime::Error::msg(msg)),
                TrapKind::Fault,
                "untyped error {msg:?} must be a Fault — text is not a signal"
            );
            assert!(
                verdict.fuel_is_billable,
                "untyped error {msg:?} must stay billable"
            );
        }
    }

    /// Every other `Trap` variant is the program's own doing, not a limit.
    #[test]
    fn other_trap_variants_are_faults() {
        for trap in [
            wasmtime::Trap::UnreachableCodeReached,
            wasmtime::Trap::MemoryOutOfBounds,
            wasmtime::Trap::IntegerDivisionByZero,
        ] {
            assert_eq!(
                classify_trap(&wasmtime::Error::from(trap)),
                TrapKind::Fault,
                "{trap:?} must be a Fault"
            );
        }
    }

    /// The billability split is the whole point of this module: only the
    /// deadline's fuel is host-dependent, so only the deadline is unbillable.
    #[test]
    fn only_a_deadline_is_unbillable() {
        let deadline = trap_verdict(&wasmtime::Error::from(wasmtime::Trap::Interrupt), 42, 100);
        assert!(!deadline.fuel_is_billable);
        assert_eq!(deadline.error_code, "ERR_DEADLINE_EXCEEDED");
        assert!(
            deadline.error_message.contains("PARTIAL"),
            "the message must flag the count as partial: {}",
            deadline.error_message
        );

        let fuel = trap_verdict(&wasmtime::Error::from(wasmtime::Trap::OutOfFuel), 100, 100);
        assert!(fuel.fuel_is_billable);
        assert_eq!(fuel.error_code, "ERR_FUEL_EXHAUSTED");

        let fault = trap_verdict(&wasmtime::Error::msg("unreachable"), 7, 100);
        assert!(fault.fuel_is_billable);
        assert_eq!(fault.error_code, "ERR_TRAP");
    }

    /// A fault must preserve the engine's own message; it is the only diagnostic
    /// a caller gets for a genuine crash.
    #[test]
    fn a_fault_preserves_the_engine_message() {
        let verdict = trap_verdict(&wasmtime::Error::msg("wasm backtrace: 0x20"), 7, 100);
        assert!(verdict.error_message.contains("wasm backtrace"));
    }
}
