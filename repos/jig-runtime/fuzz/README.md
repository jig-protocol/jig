# Fuzzing jig-runtime

This directory contains fuzz targets for testing jig-runtime with random inputs.

## Fuzz Targets

### `fuzz_wasm_bytes`
- **Purpose**: Feed arbitrary byte sequences as WASM modules
- **Goal**: Ensure no panics on invalid/malformed WASM
- **Coverage**: Validation, compilation, instantiation

## Running Fuzz Tests

**Note**: Fuzzing requires a nightly Rust toolchain.

```bash
# Install cargo-fuzz if not already installed
cargo install cargo-fuzz

# Run a specific fuzz target
cargo +nightly fuzz run fuzz_wasm_bytes

# Run with a timeout (e.g., 60 seconds)
cargo +nightly fuzz run fuzz_wasm_bytes -- -max_total_time=60

# Run with multiple cores
cargo +nightly fuzz run fuzz_wasm_bytes -- -workers=4
```

## CI/CD Integration

For CI, run fuzz tests with a short timeout to catch obvious issues:

```bash
cargo +nightly fuzz run fuzz_wasm_bytes -- -max_total_time=30 -rss_limit_mb=2048
```

## Corpus

Fuzz targets will build a corpus of interesting inputs in `fuzz/corpus/<target>/`. These are tracked by Git to maintain coverage across runs.

## Interpreting Results

- **No crashes**: Good! The runtime handles all inputs gracefully.
- **Crashes**: Indicates a panic or unhandled edge case that needs fixing.
- **Slow inputs**: May indicate performance issues or potential DoS vectors.

## Adding New Fuzz Targets

To add a new fuzz target:

```bash
cargo fuzz add <target_name>
```

Then edit `fuzz/fuzz_targets/<target_name>.rs` to implement your fuzz logic.

## Coverage

After running fuzz tests, generate coverage reports:

```bash
cargo +nightly fuzz coverage fuzz_wasm_bytes
```

This helps identify untested code paths.
