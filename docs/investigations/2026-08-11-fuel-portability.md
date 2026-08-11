# Is `fuel_used` a protocol quantity? — investigation for #33

**Status:** settled. The cross-platform matrix has run; results in Finding 2.
My leading hypothesis (a wall-clock deadline) was **wrong** and is retracted there.
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

## Finding 2 — the matrix results, and the retraction of my leading hypothesis

I predicted the 10x came from our own wall-clock deadline: jig-runtime enables
`epoch_interruption(true)` **alongside** fuel with a 250 ms default
(`config.rs:108`), and wasmtime's guide names epoch interruption as the
non-deterministic alternative to fuel. **The matrix disproves that as the cause.**

Same committed module, generous 30 s budget, `outcome=Success` on every row:

| Host | `hello_wasi` (imports WASI) | `deterministic` (no imports) |
|---|---|---|
| aarch64 macOS | **18098** | **2512** |
| x86_64 Windows | **9906** | **2512** |
| aarch64 Linux | **1713** | **2512** |
| x86_64 Linux | **1713** | **2512** |

And the wall-clock sweep is **flat on every platform** from 5 ms through 1000 ms —
1713 stays 1713, 9906 stays 9906, 18098 stays 18098. A deadline-truncation story
would have produced budget-dependent numbers. It did not.

Two things fall out, and they matter more than the original hypothesis:

**1. Fuel for a no-import module is portable.** `deterministic` is 2512 on all
four hosts, across two architectures and three operating systems. So fuel is not
inherently host-dependent.

**2. The divergence tracks the host OS, not the architecture.** Both Linux hosts
agree exactly (1713 on aarch64 and x86_64) while the two aarch64 hosts disagree by
10x (1713 Linux vs 18098 macOS). Architecture is not the variable; the platform's
WASI implementation is.

The mechanism is **not established**. The module bytes are identical and the WASI
context is hermetic (empty env and args, memory pipes for stdio), so the guest
ought to execute the same instructions. Something in the host WASI surface must be
returning different results during Rust's `_start` initialisation, causing the
guest to run different amounts of code. Worth knowing, but not needed for the
decision below.

The deadline is still a real hazard — the 1 ms rows on both Linux hosts failed
with `ExecutionFailed` at 63 and 0 fuel — just not the cause of this spread. See
Finding 3.

### Why this is good news

jig's byte-payload convention **instantiates with an empty import list**, so a
module importing WASI cannot be loaded at all. Canonical blocks are pure
no-import modules built for `wasm32-unknown-unknown`.

That means the divergence lives entirely in a class of module jig already refuses
to execute, and for the blocks jig actually runs, fuel is portable across every
host measured. The no-imports policy was added in PR #32 as a *security*
property; it turns out to be the *determinism* property too.

This does not rescue fuel as a protocol quantity — Finding 1's version and
cross-runtime arguments are untouched by any of this — but it does mean fuel is a
usable local metric rather than noise.

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
entirely, on a single idle machine, with no cross-architecture explanation needed.

At the time I read this as corroborating the wall-clock hypothesis. It is not:
the matrix showed fuel to be flat across budgets on every host, so contention
*failing* a run and contention *changing its fuel* are separate effects. This
finding stands on its own — an execution path that returns `Err` under load is a
problem for ingest regardless of what it does to fuel — but it is not evidence
about the cause of #33's divergence, and I over-read it as such.

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

## What the matrix settled

`.github/workflows/fuel-portability.yml` ran the same module on four hosts, idle
and loaded. Results are in Finding 2. Summarising against the branches I wrote
before seeing them:

- **Reference rows identical across platforms** — happened for the no-import
  module (2512 everywhere), NOT for the WASI module.
- **Reference rows differ per platform** — happened for the WASI module, and by
  OS rather than architecture. But since jig refuses to load modules with imports,
  this does not affect the blocks jig executes.
- **`fuel_is_stable_under_host_load` fails** — it did **not** fail on any host, so
  contention alone does not move fuel at realistic budgets.

Net effect on the recommendations: **1, 2, 4 and 5 stand unchanged.** Number 3
(deterministic termination) drops from "the fix" to "a real but separate hazard" —
worth doing, since a 1 ms budget produced `ExecutionFailed` at 63 fuel on Linux,
but it is not what caused #33's divergence.

The remaining open question is narrow and does not block receipts: *why* does an
identical module with a hermetic WASI context execute a different number of
instructions per host OS? Answering it would let us decide whether WASI blocks
could ever be admitted, which is not a v0.0.x question.

## Sources

- [Deterministic Execution — Wasmtime](https://docs.wasmtime.dev/examples-deterministic-wasm-execution.html)
- [Interrupting Execution — Wasmtime](https://docs.wasmtime.dev/examples-interrupting-wasm.html)
- [`wasmtime::Config`](https://docs.wasmtime.dev/api/wasmtime/struct.Config.html)
- [`wasmtime::Store`](https://docs.rs/wasmtime/latest/wasmtime/struct.Store.html)
- [Gas Metering for Wasm Programs — Alexander Gryaznov](https://agryaznov.com/posts/wasm-gas-metering/)
- [Slacked fuel metering — wasmtime#4109](https://github.com/bytecodealliance/wasmtime/issues/4109)
