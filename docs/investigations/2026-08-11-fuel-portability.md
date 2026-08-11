# Is `fuel_used` a protocol quantity? — investigation for #33

**Status:** findings below are settled except where marked *pending matrix*.
**Blocks:** receipt work (PR-B of the Wasm execution series).
**Trigger:** CI reported `fuel_used=1713` for a module whose golden says `18098`
— same module bytes, same wasmtime 47.0.3, same rustc 1.97.1.

## The question

If fuel differs by host, does it differ across *every* build target — Linux
versions, other Unixes, Windows, mobile, ARM? Is this a known problem with a
documented translation between fuel "currencies"? Or do receipts need to carry
multi-currency fuel?

And explicitly **not** on the table: "pick one host and mandate it everywhere."
That is artificial lock-in and caps adoption, which defeats the point of an open
block ecosystem.

## Finding 1 — fuel is deterministic, but it is not a *standard*

Wasmtime documents fuel as deterministic: most instructions cost 1 unit, `nop` /
`drop` / `block` / `loop` cost 0, and "wasm always consumes a fixed amount of fuel
per-operation." Same program, same input, same fuel. The single documented
cross-architecture exception is **relaxed-SIMD lowering**, and jig-runtime already
disables both SIMD and relaxed SIMD (`engine.rs:115-116`), so that exception does
not apply to us.

But "deterministic" is not "portable", and this is the important part:

**There is no cross-runtime metering standard, and therefore no translation
table.** Every engine invents its own:

| Engine | Mechanism |
|---|---|
| Wasmtime | Cranelift injects charges during operator translation, against a **hardcoded** cost schedule |
| wasmi | Charges per executed instruction via a `ConsumeFuel` IR instruction |
| Wasmer | Injects a mutable global plus check instructions around each operator |
| WAMR / WASM3 | A step counter at best; frequently no metering |
| WasmEdge | Non-standard, opt-in execution-limit options |

Each has its own hardcoded schedule. Nobody publishes a conversion. So the
premise behind "multi-currency with a known exchange rate" does not hold — there
are currencies, but no exchange rates, and no authority that could define one.

**Worse: fuel is not stable across wasmtime's own versions.** Wasmtime changed
bulk-data-transfer instructions to consume fuel *proportional to transfer size* —
which this repo already absorbed as `pricing.schedule_version` 0.2.0 during the
24 → 47 bump. So a fuel number is only comparable against another number produced
by the same engine at the same version with the same schedule.

**Conclusion: `fuel_used` cannot be a protocol-level quantity that federated
servers agree on.** Making it one would require pinning a single runtime *and*
version protocol-wide — the exact lock-in we are trying to avoid, and a hard
ceiling on who can implement a conforming server.

## Finding 2 — the observed 10x is almost certainly ours, not the architecture

*Pending matrix confirmation.*

jig-runtime enables `epoch_interruption(true)` **alongside** fuel, with a default
`execution_timeout_ms` of **250 ms** (`config.rs:108`).
`schedule_epoch_interrupt` spawns a thread that sleeps for the timeout then calls
`increment_epoch()`, and the store is armed with `set_epoch_deadline(1)` — so the
first increment traps the guest.

Wasmtime's determinism guide names **epoch-based interruption as the
non-deterministic alternative to fuel**. Mixing the two means a wall-clock timer
can cut a run short, and the fuel counter then honestly reports a *partial*
execution. `fuel_used` becomes a function of how fast and how loaded the host was.

The numbers fit: 1713 is a fraction of 18098, and CI ran ~1232 tests in parallel
on a shared runner where a 250 ms budget is easily blown. Not reproducible on an
idle 12-core laptop — even a 1 ms budget completes at 18098 there, which is why
this needs the matrix rather than local measurement.

If confirmed, **no multi-currency mechanism is needed for this defect.** The fix
is to stop letting a wall-clock timer decide how much of a program runs.

## Finding 3 — a truncated run is indistinguishable from a guest fault

`execute_with_wasi` classifies traps by string-matching the message for
`all fuel consumed` / `fuel exhausted` / `out of fuel` → `FuelExhausted`.
Everything else, **including an epoch/deadline trap**, falls to a generic `else`
→ `ReasonCode::RuntimeTrap` / `ERR_TRAP` (`api.rs:598-627`).

So today you cannot tell from a receipt whether the program failed or the host was
merely slow — and the partial `fuel_used` is recorded as though it were the
program's cost. That is a defect independent of Finding 2's cause, and it is the
one that would quietly corrupt receipt data.

## Finding 4 — the load sensitivity reproduces locally, and `execute` can fail outright

Not pending anything: this was observed on an idle 12-core laptop.

Running the jig-runtime suite in parallel under nextest three times produced three
different results — one run failed the starved-budget diagnostic, one failed
`report_this_host_fuel_profile` (**a test with no assertions at all**), and one
passed cleanly. The middle case is the informative one: that test could only fail
by panicking inside its harness, which means

> under contention, `Runtime::execute` on the WASI path returns `Err`, not a
> receipt describing a failed run.

So contention does not merely change the fuel number — it can make execution fail
entirely. A single idle machine reproduces this; no cross-architecture explanation
is required, which is strong corroboration for Finding 2 ahead of the matrix.

It also means an ingest path calling `execute` under load gets an error rather
than a receipt, so "the server was busy" and "the block is invalid" arrive at the
caller looking the same. Worth fixing alongside Finding 3.

**Consequence for these tests:** the two timing-sensitive diagnostics are
`#[ignore]`d, since a test that manufactures or depends on contention cannot also
be a stable member of a contended suite. The matrix runs them with
`--include-ignored`, where a flake is the datum rather than a nuisance. The
remaining invariant test drops unmeasurable runs but requires at least two
completed ones, so it cannot pass vacuously when load eats the sample.

## The principle this exposes

`render_hash` is computed **inside the guest** — `blake3(canonical_text)`, by the
Wasm module itself. Any conforming runtime on any architecture produces the same
value, because the computation is part of the program.

`fuel_used` is **measured outside the guest**, by the host engine, against that
engine's private schedule.

> Anything a receipt needs independent parties to agree on must be computed
> **inside** the sandbox, not measured **outside** it.

Guest-computed values are portable by construction. Host-measured values are
observations about a particular execution on a particular engine, and no amount of
schema work makes them otherwise.

## Recommendation

1. **Cross-server agreement rests on `render_hash`, never on fuel.** It already
   does structurally; make it explicit so nobody later "strengthens" parity by
   comparing fuel.
2. **Fuel becomes engine-attributed local telemetry.** Record it *with* the
   engine identity that produced it — name, version, cost-schedule version —
   exactly parallel to the module identity added in PR #32. Same pattern: a
   measurement is meaningless without knowing what produced it. This is the
   honest version of "multi-currency": provenance labelling, not conversion.
3. **Termination for receipt-producing execution must be deterministic.** The
   fuel limit is deterministic (the same program exhausts it at the same point);
   the wall clock is not. Keep the epoch deadline only as a liveness safety net.
4. **An epoch trap must be its own outcome, and its fuel must never be treated as
   the program's cost.** A receipt from a truncated run should be marked
   non-canonical rather than silently carrying a partial number.
5. **Do not regenerate the WASI golden** to make CI green. It would assert the
   other platform's number and hide all of the above.

## What the matrix settles

`.github/workflows/fuel-portability.yml` runs the same module across
x86_64-linux, aarch64-linux, aarch64-macOS, and x86_64-Windows on otherwise idle
runners with a generous budget, plus a deliberately CPU-loaded run.

- **Reference rows identical across platforms** → Finding 2 confirmed; the cause
  is our config, and recommendations 3 and 4 are the fix.
- **Reference rows differ per platform** → fuel diverges at the engine level too.
  Findings 1 and 3 and recommendations 1, 2, 5 stand regardless; only the
  additional question of whether even same-version-same-engine fuel is portable
  changes, and recommendation 2 becomes load-bearing rather than tidy.
- **`fuel_is_stable_under_host_load` fails while references agree** → direct
  confirmation that contention alone moves fuel.

## Sources

- [Deterministic Execution — Wasmtime](https://docs.wasmtime.dev/examples-deterministic-wasm-execution.html)
- [Interrupting Execution — Wasmtime](https://docs.wasmtime.dev/examples-interrupting-wasm.html)
- [`wasmtime::Config`](https://docs.wasmtime.dev/api/wasmtime/struct.Config.html)
- [`wasmtime::Store`](https://docs.rs/wasmtime/latest/wasmtime/struct.Store.html)
- [Gas Metering for Wasm Programs — Alexander Gryaznov](https://agryaznov.com/posts/wasm-gas-metering/)
- [Slacked fuel metering — wasmtime#4109](https://github.com/bytecodealliance/wasmtime/issues/4109)
