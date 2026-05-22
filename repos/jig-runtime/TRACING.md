# Structured Tracing in jig-runtime

This document describes the structured logging and tracing implementation in jig-runtime using the `tracing` crate.

## Overview

jig-runtime uses structured tracing to provide detailed insights into execution phases, performance, and errors. Tracing is **opt-in** via the `tracing` feature flag and has zero runtime overhead when disabled.

## Enabling Tracing

Add the `tracing` feature to your `Cargo.toml`:

```toml
jig-runtime = { version = "0.1", features = ["tracing"] }
```

Initialize a tracing subscriber in your application:

```rust
use tracing_subscriber;

fn main() {
    // Simple stdout subscriber
    tracing_subscriber::fmt::init();

    // Your code here
}
```

## Span Taxonomy

jig-runtime uses a consistent span naming convention to identify execution phases:

### Runtime Lifecycle

| Span Name | Level | Description | Fields |
|-----------|-------|-------------|--------|
| `runtime_new` | INFO | Creating a new runtime with default config | - |
| `runtime_with_config` | INFO | Creating runtime with custom config | `fuel_enabled`, `deterministic` |

### Execution Phases

| Span Name | Level | Description | Fields |
|-----------|-------|-------------|--------|
| `runtime_execute` | INFO | Executing a WASM module | `wasm_size`, `block_id` |
| `validate_module` | DEBUG | Validating WASM module structure | `wasm_size` |

### Events Within Spans

| Event | Level | Description |
|-------|-------|-------------|
| Creating Wasmtime engine | INFO | Engine initialization started |
| Runtime created successfully | INFO | Runtime ready for execution |
| Starting WASM execution | INFO | Begin execution phase |
| Validating WASM module | DEBUG | Module validation in progress |
| Module validation successful | INFO | Validation passed |
| Module validation failed | WARN | Validation failed with error |

## Log Levels

jig-runtime uses the following log levels:

- **DEBUG**: Detailed diagnostic information (validation steps, internal state)
- **INFO**: High-level lifecycle events (runtime creation, execution start/end)
- **WARN**: Recoverable errors or unexpected conditions
- **ERROR**: Critical failures (not currently used in M1)

## Example Output

With `RUST_LOG=jig_runtime=debug`:

```
2025-11-03T05:00:00.000Z  INFO runtime_new: Creating new runtime with default configuration
2025-11-03T05:00:00.001Z DEBUG runtime_with_config: Validating runtime configuration fuel_enabled=true deterministic=true
2025-11-03T05:00:00.002Z  INFO runtime_with_config: Creating Wasmtime engine
2025-11-03T05:00:00.005Z  INFO runtime_with_config: Runtime created successfully
2025-11-03T05:00:00.010Z  INFO runtime_execute: Starting WASM execution wasm_size=1024 block_id="cid:bafy..."
2025-11-03T05:00:00.011Z DEBUG validate_module: Validating WASM module structure wasm_size=1024
2025-11-03T05:00:00.012Z  INFO validate_module: Module validation successful
```

## Performance Impact

When the `tracing` feature is **disabled** (default):
- All tracing code is compiled out via `#[cfg(feature = "tracing")]`
- **Zero** runtime overhead
- No allocations for span creation
- No string formatting

When the `tracing` feature is **enabled**:
- Minimal overhead from span creation (nanoseconds)
- Structured fields avoid string formatting until needed
- Spans can be filtered by level via `RUST_LOG`

## Future Additions (M2+)

Planned tracing enhancements:

- **Fuel metering spans**: Track fuel consumption per capability
- **Capability invocation**: Log each capability call with quotas
- **Receipt generation**: Trace receipt creation and serialization
- **Performance metrics**: Execution timing and memory usage
- **Error context**: Enhanced error reporting with span context

## Integration with External Systems

Tracing output can be exported to:

- **OpenTelemetry**: For distributed tracing
- **JSON logs**: For structured log aggregation
- **Jaeger/Zipkin**: For visualization
- **Custom subscribers**: For application-specific handling

See the `tracing-subscriber` documentation for export options.

## Best Practices

1. **Use appropriate log levels**: DEBUG for diagnostics, INFO for lifecycle, WARN for errors
2. **Include contextual fields**: Span fields provide structured context (e.g., `wasm_size`, `block_id`)
3. **Avoid sensitive data**: Never log secrets, keys, or PII
4. **Filter in production**: Use `RUST_LOG` to control verbosity
5. **Test with tracing enabled**: Ensure your code compiles with and without the feature

## See Also

- [tracing documentation](https://docs.rs/tracing)
- [tracing-subscriber documentation](https://docs.rs/tracing-subscriber)
- `src/api.rs` - Instrumented runtime methods
