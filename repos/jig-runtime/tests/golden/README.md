# Golden Receipt Fixtures

This directory contains golden receipt fixtures for regression testing.

## Purpose

Golden receipts capture the expected deterministic behavior of WASM execution:
- **Module hash**: BLAKE3 hash of the WASM bytecode
- **Fuel usage**: Exact fuel consumption for deterministic execution
- **Outcome**: Expected execution result (Success, Failed, etc.)
- **Limits**: Resource limits applied

## Files

### `deterministic.json`
- **Fixture**: `deterministic.wasm`
- **Description**: Pure computation (sum of squares 1..=100)
- **Expected behavior**: Deterministic fuel usage, no WASI imports

### `hello_wasi.json`
- **Fixture**: `hello_wasi.wasm`
- **Description**: WASI hello world with stdout
- **Expected behavior**: Deterministic WASI execution with captured output

## Regenerating Golden Files

To regenerate golden files (e.g., after intentional runtime changes):

```bash
cargo test --test golden -- --ignored --nocapture
```

This will update the JSON files with new fuel costs and hashes.

## Validation Tests

Regular tests validate current execution against golden receipts:

```bash
cargo test --test golden
```

If fuel usage changes unexpectedly, these tests will fail, indicating a potential regression or performance change.

## Version Control

All golden receipt files are committed to ensure consistent testing across:
- Different machines
- CI/CD pipelines
- Team members
- Runtime versions

## When to Update

Update golden receipts when:
1. Wasmtime version is upgraded (fuel costs may change)
2. Runtime optimizations are made
3. WASM fixtures are modified
4. Intentional behavior changes occur

**Never** update golden receipts to make failing tests pass without understanding why they changed.
