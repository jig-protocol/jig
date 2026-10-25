# jig-runtime

Executes `jig:block` components ([JEP-0006](../jig-spec/jep/jep-0006-block-abi.md)) under the
determinism profile `jig-det-1`, with fuel, stack, memory and deadline limits.

## Architecture

**jig-runtime** sits between:
- **jig-core**: the profile validator (`component_validation`), the canonical encoding and
  outcome hashes (`block_abi`), and grants;
- **jig-pipeline, jig-client and jig-cli**: which compile components once and render with them.

### Design principles

1. **Deterministic execution**
   - Fuel metering, canonicalized NaNs, WebAssembly 2.0 without SIMD, plus the component model
     without async, threads or error context.
   - No WASI: every input arrives in the `invocation` record.
   - The same engine configuration on native Cranelift and on Pulley.

2. **Comparable outcomes**
   - Every run is `ok`, `error` (a guest `block-error` or a WebAssembly core trap) or
     `incomplete` (fuel, stack, deadline, host fault).
   - `ok` and `error` carry a hash over the canonical encoding of what was returned; two
     conforming executors agree on it on any architecture. `incomplete` is never compared.

3. **Capability security**
   - A component links only the host interfaces its grant names (`grant_linker`); nothing else
     is defined in its linker.

4. **One engine, one ticker**
   - The epoch ticker that enforces deadlines is one thread per engine, not per run, and stops
     when the runtime drops.

## Usage

```rust
use jig_core::grant::Grant;
use jig_runtime::component::{ComponentRuntime, RenderLimits};

let runtime = ComponentRuntime::new()?;
let renderer = runtime.compile_renderer(&component_bytes, &Grant::empty(), max_memory_pages)?;

let run = runtime.render(&renderer, &invocation, &RenderLimits { fuel, timeout });
println!("{:?}, hash {:?}", run.outcome, run.outcome.hash());
```

`ComponentRuntime::with_config(&RuntimeConfig, Backend)` applies an operator's pooling ceilings
and memory reservation; per-run fuel and deadline come from `RenderLimits`.

## Configuration

`RuntimeConfig` holds the engine-wide settings: memory and concurrency ceilings, fuel metering,
NaN canonicalization and the module cache. It can be loaded from TOML:

```toml
[limits]
memory_max_mb = 32
max_concurrent_instances = 64
```

## Testing

```bash
cargo test -p jig-runtime
```

- `block_abi_vectors`: the JEP-0006 conformance vectors, on native and Pulley.
- `component_outcomes`: one run in each outcome class, the profile refusal and the grant
  linker.
- `text_block_component`: the committed text-block component (or the build named by
  `JIG_TEXT_BLOCK_COMPONENT`) passes the profile, agrees with its native renderer, and keeps its
  pinned `render_hash` values.
- `epoch_ticker`: deadlines cost one thread per engine and never fire early.
- `engine_identity`: the identity a receipt names, and its configuration fingerprint.
