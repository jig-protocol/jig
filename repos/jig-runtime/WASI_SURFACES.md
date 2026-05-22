# WASI Surfaces: Exposed vs Restricted

This document describes which WASI APIs are available to WebAssembly modules in jig-runtime and what restrictions are in place to ensure deterministic execution.

## Overview

jig-runtime uses **WASI preview1** (wasi_snapshot_preview1) with a **minimal, deterministic configuration**. Most host APIs are disabled by default to prevent non-deterministic behavior and maintain security through the capability model.

**Implementation Status**: ✅ Complete with automatic detection
- Modules with WASI imports automatically use WASI-enabled execution path
- Non-WASI modules continue to work with zero overhead
- Both paths fully tested and deterministic

## Enabled Surfaces (Minimal I/O)

### Standard I/O (Captured)
- ✅ **stdin**: Available but mapped to an empty memory pipe (no host stdin)
- ✅ **stdout**: Available, captured to a 1MB memory buffer (via `MemoryOutputPipe`)
- ✅ **stderr**: Available, captured to a 1MB memory buffer (via `MemoryOutputPipe`)

**Implementation**: `WasiCtxBuilder` with memory-backed pipes

**Rationale**: Stdio is captured rather than inherited to:
- Prevent leaking host information
- Enable deterministic testing (same output every time)
- Allow future inspection of output in receipts (not yet exposed)

### Environment & Arguments
- 🚧 **Environment variables**: Reserved in `ExecutionContext.env` (not yet wired to WASI)
- 🚧 **Command-line arguments**: Reserved in `ExecutionContext.args` (not yet wired to WASI)

**Status**: API present but not passed to WASI context yet. Empty by default.

**Rationale**: Controlled injection allows reproducibility while preventing ambient authority.

## Restricted Surfaces (Determinism & Security)

### Time & Clock (🚫 DISABLED)
- ❌ **Wall-clock time**: Not available (no `clock_time_get` for realtime)
- ❌ **Monotonic clock**: Not available in standard form

**Rationale**: 
- Wall-clock access breaks determinism (different results at different times)
- Use the `clock` capability for controlled, monotonic time if needed
- Capability-based clock can be seeded for deterministic testing

### Randomness (🚫 DISABLED)
- ❌ **Host entropy**: No access to `random_get`

**Rationale**:
- Host randomness breaks determinism
- Use the `rand` capability with a deterministic seed from `ExecutionContext.rng_seed`
- Receipt includes seed for reproducibility

### Filesystem (🚫 DISABLED by default)
- ❌ **File reads/writes**: No preopened directories by default
- ❌ **Path operations**: Not available

**Rationale**:
- Filesystem access breaks sandboxing and determinism
- Use the `storage` capability for content-addressed reads if needed
- Capability layer enforces allowlists and quotas

### Network (🚫 DISABLED)
- ❌ **Socket creation**: Not available via WASI
- ❌ **DNS resolution**: Not available via WASI

**Rationale**:
- Network access via WASI would bypass capability controls
- Use the `http` capability for controlled HTTP requests
- Capability layer enforces domain allowlists and bandwidth quotas

### Process & Threading (🚫 DISABLED)
- ❌ **Process spawning**: Not available
- ❌ **Threading**: WASM threads disabled at engine level

**Rationale**:
- Threading introduces non-determinism
- Process spawning breaks sandboxing
- Single-threaded execution is deterministic and easier to meter

## Migration from Standard WASI

If your module expects standard WASI with ambient authority:

1. **Replace filesystem access** → Use `storage.read` capability
2. **Replace network calls** → Use `http.fetch` capability  
3. **Replace `random_get`** → Use `rand` capability with seed
4. **Replace wall-clock** → Use `clock` capability for monotonic time
5. **Capture stdout** → Output is automatically captured to receipts

## Enabling WASI

WASI preview1 is enabled by default via the `wasi-preview2` feature flag (name kept for compatibility):

```toml
jig-runtime = { version = "0.1", features = ["wasi-preview2"] }
```

Modules are automatically detected - no configuration needed. To compile WASI modules:

```bash
# For WASI preview1 (recommended)
rustc --target wasm32-wasip1 your_module.rs

# Or with cargo
cargo build --target wasm32-wasip1
```

**Testing**: See `tests/fixtures/hello_wasi.wasm` and `tests/security.rs` for examples.

## Future Extensions

Planned additions with deterministic guarantees:

- **Environment variable injection**: Wire `ExecutionContext.env` to WASI builder
- **Command-line arguments**: Wire `ExecutionContext.args` to WASI builder
- **Stdout/stderr capture in receipts**: Expose captured output
- **Monotonic clock capability**: Seeded time source
- **Controlled filesystem**: Preopened directories with quotas
- **Async I/O**: Non-blocking operations within fuel budget

All extensions will maintain determinism and be gated by capabilities.

## Implementation Details

**Location**: `src/engine.rs::build_wasi_context()`

**Current Configuration**:
```rust
WasiCtxBuilder::new()
    .stdin(MemoryInputPipe::new(vec![])) // Empty
    .stdout(MemoryOutputPipe::new(1MB))  // Captured
    .stderr(MemoryOutputPipe::new(1MB))  // Captured
    .build_p1()                          // Preview1
```

**Tested**: 7 security tests verify WASI sandboxing works correctly.

## See Also

- `architecture/EXECUTION_ENVIRONMENT.md` - Runtime requirements
- `architecture/BLOCK_RUNTIME_SPEC.md` - Block manifest and capabilities
- `src/capabilities.rs` - Capability implementation
