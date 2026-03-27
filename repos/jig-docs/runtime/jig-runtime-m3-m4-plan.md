# jig-runtime M3 & M4 Planning

**Date:** 2025-11-03  
**Status:** 📋 PLANNING

---

## Milestone 3: Consumer Integration Parity

**Goal:** Integrate jig-runtime with all consumers (jig-server, jig-cli, jig-gui) and achieve receipt parity across all execution paths.

**Exit Criteria:** 
- jig-server/cli/gui all use the unified jig-runtime API
- Parity tests passing with identical receipts (allowing documented time tolerances)
- Shared config format across consumers
- E2E tests validating receipt consistency

### P0 Tasks (Critical Path)

#### M3.1: Publish jig-runtime crate
**Status:** ☐  
**Dependencies:** M2 complete ✅  
**Scope:**
- Ensure jig-runtime builds cleanly in workspace
- Add jig-runtime to workspace Cargo.toml as path dependency
- Verify public API exports are complete
- Test consumers can import and use basic types

**Deliverables:**
```toml
# workspace Cargo.toml
[workspace]
members = [
    "repos/jig-runtime",
    "repos/jig-cli",
    "repos/jig-server",
    # ...
]

# consumer Cargo.toml
[dependencies]
jig-runtime = { path = "../jig-runtime" }
```

---

#### M3.2: Migrate jig-cli to new Runtime API
**Status:** ☐  
**Dependencies:** M3.1  
**Scope:**
- Remove jig-runtime-select dependency
- Import and use `jig_runtime::{Runtime, ExecutionContext, RuntimeConfig}`
- Add CLI flags:
  - `--fuel-limit <u64>`: Override fuel limit
  - `--memory-limit <mb>`: Override memory limit
  - `--timeout <ms>`: Override timeout
  - `--pricing`: Enable pricing in receipts
  - `--config <path>`: Load runtime config from TOML
  - `--receipt-output <path>`: Write receipt JSON to file
  - `--capability <name>`: Allow specific capability (repeatable)
- Produce JSON receipts to stdout or file
- Handle errors gracefully with exit codes

**CLI Interface Example:**
```bash
# Basic execution
jig run block.wasm

# With limits
jig run block.wasm --fuel-limit 10000000 --memory-limit 64

# With pricing and receipt output
jig run block.wasm --pricing --receipt-output receipt.json

# With capabilities
jig run block.wasm --capability http --capability kv

# With config file
jig run block.wasm --config runtime.toml
```

**Deliverables:**
- Updated `jig-cli/src/commands/run.rs` (or equivalent)
- CLI help text and examples
- Error handling and user-friendly messages
- Receipt output formatting (pretty JSON)

---

#### M3.3: Migrate jig-server to use Runtime
**Status:** ☐  
**Dependencies:** M3.1  
**Scope:**
- Remove jig-runtime-select dependency
- Import jig-runtime Runtime API
- Expose REST endpoints:
  - `POST /v1/execute`: Execute WASM with JSON config, return receipt
  - `GET /v1/config`: Get default runtime config
  - `POST /v1/validate`: Validate WASM without executing
- Expose gRPC endpoints (if implemented):
  - `Execute(ExecuteRequest) → ExecuteResponse`
  - `ValidateModule(ValidateRequest) → ValidateResponse`
- Optional streaming logs via WebSocket or Server-Sent Events (feature-gated)
- Async execution with tokio/axum or similar

**REST API Example:**
```bash
# Execute WASM
curl -X POST http://localhost:8080/v1/execute \
  -H "Content-Type: application/json" \
  -d '{
    "wasm": "<base64>",
    "config": {
      "limits": {"fuel_max": 5000000},
      "pricing": {"enabled": true}
    }
  }'

# Response: Receipt JSON
```

**Deliverables:**
- REST API implementation with axum/actix
- Request/response schemas
- Error handling and HTTP status codes
- Optional streaming logs support
- Server config for runtime defaults

---

#### M3.4: Migrate jig-gui to call runtime via unified API
**Status:** ☐  
**Dependencies:** M3.1  
**Scope:**
- Import jig-runtime Runtime (if Rust backend)
- OR: Call jig-server REST API (if frontend-only)
- Receipt viewer component:
  - Display all receipt fields (fuel, memory, duration, pricing)
  - Visualize fuel consumption breakdown
  - Show capability calls
  - Export receipt as JSON
- Execution monitoring:
  - Real-time execution status
  - Progress indicators
  - Error display
- Config editor for RuntimeConfig

**Deliverables:**
- Receipt viewer UI component
- Runtime config editor
- Execution trigger and status display
- Integration with existing jig-gui architecture

---

### P1 Tasks (High Priority)

#### M3.5: Shared config file format
**Status:** ☐  
**Dependencies:** M3.2, M3.3  
**Scope:**
- Define canonical TOML config format
- Support config file discovery:
  - `./jig-runtime.toml`
  - `~/.config/jig/runtime.toml`
  - `/etc/jig/runtime.toml`
- Environment variable overrides (already in RuntimeConfig)
- CLI flag overrides take precedence
- Validate config on load with helpful error messages

**Example Config:**
```toml
# jig-runtime.toml

[limits]
fuel_max = 10_000_000
memory_max_mb = 64
execution_timeout_ms = 500
max_instances = 1

[capabilities]
deny_by_default = true
allowed = ["http", "kv"]

[capabilities.quotas.http]
max_calls = 100
max_bytes = 1048576  # 1MB

[fuel]
enabled = true
cost_schedule_path = "cost-schedules/v0.1.0.toml"

[pricing]
enabled = false
cost_per_fuel_unit = 0.000001
currency = "USD"
schedule_version = "0.1.0"

[engine]
deterministic = true
canonicalize_nans = true
wasi_preview2 = true
component_model = false
```

**Deliverables:**
- Config discovery logic in all consumers
- Config validation and error reporting
- Documentation for config format
- Example configs for common scenarios

---

#### M3.6: E2E parity tests (Golden Receipts)
**Status:** ☐  
**Dependencies:** M3.2, M3.3, M3.4  
**Scope:**
- Create test harness that runs identical WASM through all consumers
- Verify receipts are identical (except timing fields)
- Allow documented tolerances:
  - `duration_ns`: ±10% acceptable
  - `executed_at`: different timestamps OK
  - All other fields must match exactly
- Create golden receipt fixtures:
  - Empty execution
  - Computational loop
  - Memory-intensive
  - Fuel exhaustion
  - Error cases
- Tests run in CI on multiple platforms (macOS, Linux)

**Test Structure:**
```rust
#[test]
fn test_cli_server_parity() {
    let wasm = include_bytes!("fixtures/sum_loop.wasm");
    
    // Execute via CLI
    let cli_receipt = execute_via_cli(wasm);
    
    // Execute via server API
    let server_receipt = execute_via_server_api(wasm);
    
    // Compare (with tolerances)
    assert_receipts_match(&cli_receipt, &server_receipt);
}
```

**Deliverables:**
- E2E test suite in `tests/e2e/`
- Golden receipt fixtures
- Receipt comparison utilities with tolerance
- CI integration for parity tests

---

#### M3.7: Example "hello-capabilities" block
**Status:** ☐  
**Dependencies:** Capability system (M3/M4)  
**Scope:**
- Create tutorial WASM module demonstrating:
  - HTTP request
  - KV storage
  - Random number generation
  - Hashing
- WAT source with comments
- Documentation walkthrough
- Receipt example showing capability usage

**Example:**
```wat
(module
  ;; Import jig:cap/http@0.1
  (import "jig:cap/http" "get" (func $http_get ...))
  
  ;; Import jig:cap/kv@0.1
  (import "jig:cap/kv" "set" (func $kv_set ...))
  
  (func (export "main")
    ;; Make HTTP request
    call $http_get
    
    ;; Store result in KV
    call $kv_set
  )
)
```

**Deliverables:**
- hello-capabilities.wat
- Compiled hello-capabilities.wasm
- Tutorial documentation
- Receipt showing capability fuel breakdown

---

#### M3.8: Integration docs and diagrams
**Status:** ☐  
**Dependencies:** M3.2, M3.3, M3.4  
**Scope:**
- Architecture diagram: Runtime → Consumers flow
- Sequence diagrams for execution paths
- API reference documentation
- Migration guide from runtime-select
- Best practices for consumer integration

**Deliverables:**
- `docs/INTEGRATION.md`
- `docs/MIGRATION.md` (runtime-select → jig-runtime)
- Architecture diagrams (Mermaid/PlantUML)
- API reference (auto-generated from Rust docs)

---

### P2 Tasks (Nice to Have)

#### M3.9: SDK snippets for block authors
**Status:** ☐  
**Scope:**
- Code snippets for common WASM patterns
- Rust guest library examples (wit-bindgen)
- AssemblyScript examples
- TinyGo examples
- Memory management best practices

#### M3.10: Backpressure and queueing guidance
**Status:** ☐  
**Scope:**
- Document jig-server scaling strategies
- Queue depth recommendations
- Rate limiting patterns
- Circuit breaker integration

---

## Milestone 4: Test Hardening + Deprecations

**Goal:** Harden the runtime with comprehensive testing, archive vestigial repositories, and complete documentation.

**Exit Criteria:**
- All vestigial repos archived with migration guides
- Fuzz/soak/security tests passing
- CI matrix covering macOS and Linux
- Performance baselines documented
- Documentation complete and up-to-date

### P0 Tasks (Critical Path)

#### M4.1: Archive jig-docker repo
**Status:** ☐  
**Scope:**
- Add prominent README stating deprecation
- Link to jig-runtime migration guide
- Archive GitHub repository
- Update workspace to remove jig-docker

**README.md:**
```markdown
# jig-docker [ARCHIVED]

⚠️ **This repository is archived and no longer maintained.**

The Jig Protocol now uses WASM-only execution via `jig-runtime`.
Docker-based execution is out-of-scope for the core runtime.

For migration instructions, see:
- [jig-runtime](../jig-runtime)
- [Migration Guide](../docs/MIGRATION.md)
```

---

#### M4.2: Archive jig-podman repo
**Status:** ☐  
**Scope:** Same as M4.1 for podman

---

#### M4.3: Archive jig-runtime-select repo
**Status:** ☐  
**Dependencies:** M3.2, M3.3 (consumers migrated)  
**Scope:**
- Add deprecation README with migration guide
- Document how runtime-select consumers should migrate
- Archive GitHub repository
- Remove from workspace

**Migration Guide Topics:**
- How to replace `RuntimeSelect` with `jig_runtime::Runtime`
- Config migration from runtime-select format
- API differences and breaking changes
- Example before/after code

---

#### M4.4: Remove jig-runtime-select from jig-cli
**Status:** ☐  
**Dependencies:** M3.2  
**Scope:**
- Remove Cargo.toml dependency
- Remove any feature flags related to runtime-select
- Remove src/runtime.rs (or equivalent abstraction layer)
- Update imports to use jig-runtime directly

---

#### M4.5: Remove jig-runtime-select from workspace
**Status:** ☐  
**Dependencies:** M4.3, M4.4  
**Scope:**
- Remove from workspace Cargo.toml members list
- Update CI to exclude archived repos
- Clean up any cross-references in docs

---

#### M4.6: Update docs to state WASM-only
**Status:** ☐  
**Scope:**
- Update top-level README
- Update architecture documentation
- Update deployment guides
- Add prominent notice about WASM-only runtime
- Remove all docker/podman references from active docs

**Key Messages:**
- "Jig Protocol uses WASM as the single core runtime"
- "Docker/Podman support has been removed in favor of WASM"
- "All blocks must be compiled to WASM"

---

### P1 Tasks (High Priority)

#### M4.7: Fuzz hostcall inputs
**Status:** ☐  
**Dependencies:** Capability system implementation  
**Scope:**
- Set up cargo-fuzz for jig-runtime
- Fuzz targets for:
  - Module validation
  - Capability calls (HTTP, KV, etc.)
  - Config parsing
  - Receipt serialization
- Run fuzzing in CI for X minutes per commit
- Document fuzzing setup and results

**Example Fuzz Target:**
```rust
#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: &[u8]) -> i32 {
    let _ = jig_runtime::Runtime::new()
        .and_then(|rt| rt.validate_module(data));
    0
}
```

---

#### M4.8: Snapshot/golden receipt suite
**Status:** ☐  
**Scope:**
- Create comprehensive golden receipt fixtures
- Store receipts in `tests/golden/`
- Add test that validates new receipts match golden (with tolerances)
- Update guardrails for receipt changes
- Document when golden receipts should be updated

**Golden Receipt Categories:**
- Basic execution (success)
- Fuel exhaustion
- Memory exhaustion
- Validation errors
- Various capability usage patterns
- Pricing enabled/disabled

---

#### M4.9: Performance baselines
**Status:** ☐  
**Scope:**
- Create benchmark suite with criterion
- Benchmarks for:
  - Cold start: engine creation + first execution
  - Warm execution: repeated execution
  - Module validation time
  - Receipt serialization
  - Fuel metering overhead
- Document p50, p95, p99 latencies
- Set performance regression thresholds in CI

**Benchmark Categories:**
```
Execution:
  - cold_start_empty       <100μs
  - warm_execution_empty   <50μs
  - cold_start_compute     <500μs
  - warm_execution_compute <200μs

Validation:
  - validate_small_module  <50μs
  - validate_large_module  <500μs

Serialization:
  - receipt_to_json        <100μs
  - receipt_from_json      <50μs
```

---

#### M4.10: CI matrix (macOS, Linux)
**Status:** ☐  
**Scope:**
- Set up GitHub Actions matrix:
  - OS: macOS-latest, ubuntu-latest
  - Rust: stable, nightly
- Run on PR and main branch
- Jobs:
  - Build
  - Test (unit + integration)
  - Clippy (with -D warnings)
  - Fmt check
  - cargo-deny (license checks)
  - Benchmarks (report only)
  - Fuzz (time-limited)
- Badge in README showing CI status

**GitHub Actions:**
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        rust: [stable]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: ${{ matrix.rust }}
      - run: cargo test --all-features
      - run: cargo clippy -- -D warnings
      - run: cargo fmt -- --check
      - run: cargo deny check
```

---

#### M4.11: Crate-level docs and README
**Status:** ☐  
**Scope:**
- Comprehensive README.md with:
  - Quick start example
  - Features overview
  - Installation instructions
  - Configuration guide
  - Links to docs
- Update lib.rs module docs
- Ensure all public APIs have rustdoc
- Add examples/ directory with runnable examples
- Publish to crates.io (when ready)

---

#### M4.12: Search-and-replace docker/podman/runtime-select refs
**Status:** ☐  
**Scope:**
- Grep entire workspace for:
  - "jig-docker"
  - "jig-podman"
  - "runtime-select"
  - "docker"
  - "podman"
- Update or remove references in:
  - Documentation
  - Comments
  - Error messages
  - Configuration examples
- Ensure only valid references remain

---

### P2 Tasks (Nice to Have)

#### M4.13: Code coverage targets
**Status:** ☐  
**Scope:**
- Set up tarpaulin or cargo-llvm-cov
- Target: >80% coverage for core modules
- Report coverage in CI
- Badge in README

#### M4.14: Static analysis and SAST
**Status:** ☐  
**Scope:**
- Run clippy with strict lints
- Run cargo-audit for security advisories
- Optional: SonarQube or similar SAST tool
- Document findings and remediation

#### M4.15: Security review checklist
**Status:** ☐  
**Scope:**
- Manual security review of:
  - Input validation
  - Resource limits enforcement
  - Capability isolation
  - Error handling (no info leakage)
  - Dependency vulnerabilities
- Document security assumptions
- Threat model documentation

#### M4.16: Soak tests
**Status:** ☐  
**Scope:**
- Long-running tests (hours) with:
  - Varying workloads
  - Memory pressure
  - Fuel exhaustion scenarios
- Monitor for:
  - Memory leaks
  - Performance degradation
  - Resource exhaustion

#### M4.17: Versioning strategy and CHANGELOG
**Status:** ☐  
**Scope:**
- Define semver policy for jig-runtime
- Create CHANGELOG.md following Keep a Changelog format
- Document breaking changes policy
- Tag M1, M2, M3, M4 releases
- Prepare for 1.0 release

#### M4.18: Receipt validator CLI
**Status:** ☐  
**Scope:**
- Add `jig receipt validate <file>` command
- Validate receipt structure
- Check field constraints
- Verify signatures (if present)
- Output validation report

---

## Dependency Graph

```
M3.1 (Publish)
  ├─> M3.2 (jig-cli)
  │     └─> M3.5 (Shared config)
  │           └─> M3.6 (E2E tests)
  ├─> M3.3 (jig-server)
  │     └─> M3.5 (Shared config)
  │           └─> M3.6 (E2E tests)
  └─> M3.4 (jig-gui)
        └─> M3.6 (E2E tests)

M3.2, M3.3 complete
  └─> M4.3 (Archive runtime-select)
        └─> M4.4 (Remove from cli)
              └─> M4.5 (Remove from workspace)

M3.6 complete
  └─> M4.8 (Golden receipts)

All M3 complete
  └─> M4.1, M4.2 (Archive docker/podman)
  └─> M4.6 (Update docs)
  └─> M4.7-M4.18 (Hardening)
```

---

## Timeline Estimate

### M3: Consumer Integration (~2-3 weeks)
- Week 1: M3.1-M3.4 (CLI, Server, GUI migrations)
- Week 2: M3.5-M3.6 (Shared config, E2E tests)
- Week 3: M3.7-M3.8 (Examples, documentation)

### M4: Test Hardening + Deprecations (~1-2 weeks)
- Week 1: M4.1-M4.6 (Deprecations, docs)
- Week 2: M4.7-M4.12 (Testing, CI, performance)
- Ongoing: M4.13-M4.18 (P2 items as time allows)

**Total Estimated Time: 3-5 weeks for M3+M4**

---

## Open Questions for M3/M4

1. **jig-server API design**: REST only, or REST + gRPC?
2. **jig-gui architecture**: Rust backend with egui/iced, or web frontend calling server?
3. **Streaming logs**: Required for M3, or defer to later?
4. **Capability implementation**: Block M3, or use stubs for parity testing?
5. **Receipt signing**: Required for M3/M4, or defer?
6. **Crates.io publish**: When to publish jig-runtime publicly?
7. **Backwards compatibility**: Any v0.1 receipt support needed?
8. **Windows support**: Test on Windows in CI, or macOS/Linux only?

---

## Success Metrics

### M3 Success:
- ✅ All consumers use jig-runtime API
- ✅ E2E parity tests passing on CI
- ✅ Receipts identical across consumers (with documented tolerances)
- ✅ Shared config format adopted
- ✅ Documentation complete for integration

### M4 Success:
- ✅ Vestigial repos archived
- ✅ CI green on macOS and Linux
- ✅ Performance benchmarks documented
- ✅ Fuzz tests running in CI
- ✅ Golden receipt suite in place
- ✅ All docs updated to reflect WASM-only runtime
- ✅ Ready for production use

---

**Next Action:** Review M3/M4 plan, prioritize tasks, and begin M3.1 (Publish jig-runtime) 🚀
