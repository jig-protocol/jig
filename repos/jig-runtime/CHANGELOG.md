# Changelog

All notable changes to jig-runtime will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **WASI Preview1 Support** - Automatic detection and deterministic sandboxing
  - Captured stdin/stdout/stderr (memory-backed pipes)
  - No filesystem, time, or entropy access by default
  - Non-WASI modules continue to work with zero overhead
  - Both execution paths fully tested
- **Comprehensive Test Suite** - 93 tests covering:
  - Determinism (identical receipts across runs)
  - Fuel metering (consumption, limits, exhaustion)
  - Capability security (WASI sandboxing, isolation)
  - Resource exhaustion (memory, fuel, concurrent execution)
  - Malicious WASM (invalid bytecode, traps, bad imports)
  - Golden receipts (regression detection)
- **Fuzzing Infrastructure** - cargo-fuzz setup for continuous testing
  - `fuzz_wasm_bytes` target for arbitrary bytecode
  - README with usage instructions
- **Test Fixtures** - Version-controlled WASM modules
  - `deterministic.wasm` - Pure computation (464 bytes)
  - `fuel_heavy.wasm` - Heavy loop for exhaustion tests (453 bytes)
  - `hello_wasi.wasm` - WASI stdout test (268KB)
  - Build script for reproducibility

### Changed
- **Store Architecture** - Dual store types for optimal performance
  - `Store<StoreLimits>` for non-WASI modules
  - `Store<StoreContext>` for WASI modules
  - Automatic selection based on module imports
- **Error Handling** - Graceful handling of all error cases
  - No panics on malformed WASM
  - Proper error classification (Validation, Instantiation, Execution)
  - Traps produce receipts with detailed error messages

### Fixed
- **Fuel Metering** - Handle disabled fuel gracefully
- **Code Quality** - Zero compilation warnings, minimal clippy warnings

## [0.1.0] - 2024-11-03

Initial release with deterministic execution, fuel metering, and receipt v0.2.

### Added
- Deterministic WASM execution with fuel metering
- Receipt v0.2 with optional pricing fields
- Capability security model (closed-by-default)
- Resource limits (fuel, memory, timeout)
- Configuration via TOML or code
- BLAKE3 module hashing
- Optional tracing support

[Unreleased]: https://github.com/jig-protocol/repos/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jig-protocol/repos/releases/tag/v0.1.0
