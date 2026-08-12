# Is `fuel_used` a protocol quantity? — investigation for #33

**Status:** settled. The cross-platform matrix has run; results in Finding 2.
My leading hypothesis (a wall-clock deadline) was **wrong** and is retracted there.
**Blocks:** receipt work (PR-B of the Wasm execution series) — **now unblocked**, on
the terms in Recommendation below.
**Also covers:** what the no-imports rule actually costs, and how metered blocks
differ from free ones — see "What this means for metered blocks".
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
and loaded. Results are in Finding 2, and a second independent run reproduced every
number exactly — so these are per-host constants, not sampling noise.

The workflow now runs **Linux only on pull requests** (both architectures, which
preserves the axis that mattered) and the full four platforms on
`workflow_dispatch`. macOS and Windows minutes bill above baseline, and re-running
them on every review round buys nothing once the table above is recorded. Dispatch
manually when the table itself needs redoing — a PR run cannot surface an
OS-dependent difference, because Linux is the only OS in it.

Summarising against the branches I wrote before seeing the results:

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

## What this means for metered blocks and the effectful tier

Follow-on questions after the matrix: what is actually locked behind "no imports",
do we still need multiple fuel currencies, must blocks ship their own imports to be
fuel-safe, and does a billed block differ from a free one. Answered against the
code, because the tree already contains more of this than it appears to.

### The no-imports rule is narrower than it sounds

It belongs to `jig_runtime::payload::execute_payload`, **not** to the runtime.
`Runtime::execute` validates against a `HostImportAllowlist`
(`jig-core/src/wasm_validation.rs:102`), and the `Default` impl is
`default_jig_allowlist()` — which already permits
`jig_host::{log, emit_message, read_resource}` plus
`wasi_snapshot_preview1::proc_exit`. There is also
`wasi_preview1_deterministic()`, a broad stdio/environ/args subset that explicitly
excludes `random_get`, `clock_*` and `sock_*`.

`jig-core/src/capability_registry.rs` goes further and already names the effectful
capabilities — `net:http:fetch`, `storage:read`, `storage:write`,
`ai:llm:inference`, `log:emit`, `message:emit` — each with `required_imports`, a
`fuel_cost_estimate`, and `attestation_requirements`.

**But no `jig_host` function is implemented.** jig-runtime does build a
`wasmtime::Linker` (`api.rs:494`), and it populates it with exactly one thing —
WASI preview1, via `wasmtime_wasi::p1::add_to_linker_sync`. Nothing anywhere
provides `jig_host::*`, so a module importing it cannot instantiate however
thoroughly the allowlist and registry describe it.

The effectful tier today is therefore declarative scaffolding: a vocabulary
(capability names, required imports, cost estimates, attestation requirements)
with no implementation behind it. Useful — it means the shape is already agreed —
but nothing about it is exercised or tested.

### What is genuinely locked out

Only effects the block performs **itself, mid-execution**. Side data is not locked;
it is **inverted into explicit input**. jig already does this — `Input.hlc_wall_ms`
is the clock, handed in as data — and the same works for randomness, config, or
prior state.

That inversion is why receipts are verifiable by re-execution: the input is
recorded, so anyone can re-derive the output. Pure computation over a payload
covers most render/transform work (markdown, LaTeX, diff, CRDT merge, syntax
highlighting, validation). What it cannot express is "fetch this URL", "query this
row", "call this model".

### Multiple currencies: no. A validity predicate.

Since fuel is portable for no-import modules and jig only executes those, fuel
within one engine+version is already comparable across hosts. What remains
incomparable is across wasmtime *versions* and across *runtimes* (Finding 1).

That is not an exchange-rate problem, it is a **compatibility predicate**: a fuel
number may be compared with another only when engine, version, and cost schedule
match. One tag, not a conversion matrix.

`fuel_by_capability` is already the right structure — a labelled breakdown, not a
single currency, with in-module work bucketed under the pseudo-capability
`engine.wasm`.

> **Defect:** `fuel_total` is the **sum** of `fuel_by_capability`
> (`jig-runtime/src/api.rs:332`). That adds the portable quantity (`engine.wasm`)
> to non-portable host-attributed buckets, producing one number that reads as
> comparable and is not. For billing, keep the buckets separate.

Note also three distinct fuel-ish quantities that must not be conflated: measured
wasm fuel (the `engine.wasm` bucket), the `CapabilityCosts` charging schedule in
jig-runtime (`call_base` / `per_byte_in` / `per_byte_out` / per-operation), and the
advisory `fuel_cost_estimate` per capability in jig-core's registry. Only the first
is a measurement.

### Blocks already ship their own imports, and that is the fuel-safety rule

`wasm32-unknown-unknown` statically links the allocator, `memcpy`, and everything
else, so all the work is in-module and counted as wasm operators.

Work behind an import is host-native and consumes **zero wasm fuel**. So:

> An import is a fuel-accounting hole unless its capability has a `CapabilityCosts`
> entry. Otherwise a block can offload compute to the host and under-pay.

Enforce it when the tier lands: no allowlisted import without a cost entry. This is
also the mechanism behind Finding 2's WASI spread — the host-side work was never
counted at all; only the guest-side portion, which varied by host OS.

### Metered and free blocks differ materially

| | Free (e.g. IRC text server) | Metered (e.g. inference server) |
|---|---|---|
| Fuel is | a safety ceiling | an invoice |
| Question it answers | "did it exceed the budget?" | "what is owed?" |
| Needs | a bound | precision, non-gameability, agreement |
| Portability | irrelevant — a local ceiling | required between biller and billed |
| Expensive work | in-module | behind an import (GPU) |
| Verified by | re-execution | **attestation** |

For inference the wasm fuel is nearly blind to the real cost: GPU seconds are not
wasm operators. It has to be metered in tokens or GPU-ms by whoever ran the model,
and that number cannot be re-derived from the receipt the way `render_hash` can.

> **The dividing line:** pure blocks are verifiable by **re-execution**; effectful
> blocks are only auditable by **attestation**.

This is already latent in the design rather than a new proposal —
`CapabilityDefinition.attestation_requirements` exists, and `ai:llm:inference`
already declares `["ai_usage_policy:v1"]`. The work is to make it load-bearing:
an effect meter is a *signed claim by its executor*, carried in the same receipt
envelope as the reproducible parts but never confused with them.

### Practical upshot

Today's no-imports tier needs nothing further. When the effectful tier is built,
two things must be right from the start: **every allowlisted import has a cost
entry**, and **effect meters are never summed into a field that reads as
reproducible**.

### A lead on the open mechanism

`wasi_preview1_deterministic()` permits `environ_get`/`environ_sizes_get`,
`args_get`/`args_sizes_get`, and `fd_prestat_get`/`fd_prestat_dir_name`. Their
host-side answers plausibly differ per platform (preopens in particular), and Rust's
`_start` walks them during init — so the *number of guest instructions spent
processing the reply* can differ even though each call is individually
"deterministic from context". That is a candidate explanation for why an identical
module with a hermetic context executes differently per host OS, and where I would
look first.

## Sources

- [Deterministic Execution — Wasmtime](https://docs.wasmtime.dev/examples-deterministic-wasm-execution.html)
- [Interrupting Execution — Wasmtime](https://docs.wasmtime.dev/examples-interrupting-wasm.html)
- [`wasmtime::Config`](https://docs.wasmtime.dev/api/wasmtime/struct.Config.html)
- [`wasmtime::Store`](https://docs.rs/wasmtime/latest/wasmtime/struct.Store.html)
- [Gas Metering for Wasm Programs — Alexander Gryaznov](https://agryaznov.com/posts/wasm-gas-metering/)
- [Slacked fuel metering — wasmtime#4109](https://github.com/bytecodealliance/wasmtime/issues/4109)
