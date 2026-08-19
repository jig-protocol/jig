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

/// Classify a trap, preferring wasmtime's typed `Trap` over its message.
///
/// The typed variant is the only reliable signal, and this is not theoretical:
/// under wasmtime 47 a fuel-exhaustion trap renders as nothing but a wasm
/// backtrace — the strings below appear in it nowhere. The message-matching
/// classifier this replaced therefore sent every real fuel exhaustion to
/// `Fault`, so a receipt reported "your program crashed" for what was actually
/// "your program ran out of the budget you gave it".
///
/// The string checks are kept only as a fallback for paths that surface a
/// message without a typed trap, and for engine versions that word things
/// differently. They are insurance, not the mechanism.
pub(crate) fn classify_trap(err: &wasmtime::Error) -> TrapKind {
    if let Some(trap) = err.downcast_ref::<wasmtime::Trap>() {
        match trap {
            wasmtime::Trap::OutOfFuel => return TrapKind::FuelExhausted,
            wasmtime::Trap::Interrupt => return TrapKind::DeadlineExceeded,
            _ => {}
        }
    }

    let msg = err.to_string();
    if msg.contains("all fuel consumed")
        || msg.contains("fuel exhausted")
        || msg.contains("out of fuel")
    {
        TrapKind::FuelExhausted
    } else if msg.contains("epoch deadline") || msg.contains("interrupt") {
        TrapKind::DeadlineExceeded
    } else {
        TrapKind::Fault
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

    /// A trap carrying no recognisable signal must not be guessed at. Defaulting
    /// to `FuelExhausted` or `DeadlineExceeded` would invent a limits breach out
    /// of an unknown failure; `Fault` says only "the guest stopped".
    #[test]
    fn an_unrecognised_trap_is_a_fault() {
        let err = wasmtime::Error::msg("something entirely unexpected");
        assert_eq!(classify_trap(&err), TrapKind::Fault);
    }

    #[test]
    fn the_message_fallback_still_recognises_both_limits() {
        for msg in ["all fuel consumed", "fuel exhausted", "out of fuel"] {
            assert_eq!(
                classify_trap(&wasmtime::Error::msg(msg)),
                TrapKind::FuelExhausted,
                "message fallback failed for {msg:?}"
            );
        }
        for msg in ["epoch deadline reached", "interrupt"] {
            assert_eq!(
                classify_trap(&wasmtime::Error::msg(msg)),
                TrapKind::DeadlineExceeded,
                "message fallback failed for {msg:?}"
            );
        }
    }

    /// The billability split is the whole point of this module: only the
    /// deadline's fuel is host-dependent, so only the deadline is unbillable.
    #[test]
    fn only_a_deadline_is_unbillable() {
        let deadline = trap_verdict(&wasmtime::Error::msg("epoch deadline reached"), 42, 100);
        assert!(!deadline.fuel_is_billable);
        assert_eq!(deadline.error_code, "ERR_DEADLINE_EXCEEDED");
        assert!(
            deadline.error_message.contains("PARTIAL"),
            "the message must flag the count as partial: {}",
            deadline.error_message
        );

        let fuel = trap_verdict(&wasmtime::Error::msg("all fuel consumed"), 100, 100);
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
