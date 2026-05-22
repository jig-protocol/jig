# Test WASM Fixtures

This directory contains minimal WASM test fixtures for jig-runtime testing.

## Fixtures

### `deterministic.wasm`
- **Purpose**: Test deterministic execution without WASI
- **Source**: `deterministic.rs` (no_std, no WASI imports)
- **Behavior**: Pure computation (sum of squares 1..=100)
- **Expected**: Identical fuel usage and result across runs

### `fuel_heavy.wasm`
- **Purpose**: Test fuel metering and exhaustion
- **Source**: `fuel_heavy.rs` (no_std, no WASI imports)
- **Behavior**: 1M iteration loop with modular arithmetic
- **Expected**: Can exhaust fuel with low limits

### `hello_wasi.wasm`
- **Purpose**: Test WASI integration and stdout capture
- **Source**: `hello_wasi.rs` (WASI preview1)
- **Behavior**: Prints to stdout using WASI
- **Expected**: Requires WASI imports, deterministic output

## Building

Run `./build.sh` to rebuild all fixtures. Requires:
- Rust toolchain (nightly or stable)
- `wasm32-unknown-unknown` target (for no_std modules)
- `wasm32-wasip1` target (for WASI modules)

The build script will install missing targets automatically.

## Usage in Tests

```rust
const DETERMINISTIC_WASM: &[u8] = include_bytes!("fixtures/deterministic.wasm");
const FUEL_HEAVY_WASM: &[u8] = include_bytes!("fixtures/fuel_heavy.wasm");
const HELLO_WASI_WASM: &[u8] = include_bytes!("fixtures/hello_wasi.wasm");
```

## Version Control

All `.wasm` files are committed to ensure deterministic testing across environments.
