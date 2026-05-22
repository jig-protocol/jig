# jig-runtime

Unified WebAssembly runtime for Jig Protocol implementing deterministic, capability-secured execution with fuel metering and optional pricing.

## Architecture

**jig-runtime** is the execution layer that sits between:
- **jig-core** (protocol primitives: manifests, bundles, CIDs)
- **Servers/CLI** (business logic: storage, billing, API endpoints)

### Design Principles

1. **Deterministic Execution**
   - Fuel-metered instruction counting
   - Canonicalized floating point (NaN normalization)
   - No threading, no non-deterministic syscalls
   - Reproducible results across hosts

2. **WASI Support**
   - WASI preview1 with automatic import detection
   - Deterministic sandboxing (captured stdio, no filesystem/time/entropy by default)
   - Non-WASI modules continue to work with zero overhead
   - Both execution paths fully tested and secure

3. **Capability Security**
   - Closed-by-default (deny all capabilities unless explicitly allowed)
   - Per-capability fuel tracking for granular metering
   - Capability calls recorded in receipts for auditing

4. **Receipt v0.2**
   - Execution metadata: fuel_used, duration, memory_peak
   - Per-capability fuel breakdown (enables pricing)
   - Outcome status: Success, LimitsExceeded, ExecutionFailed, ValidationFailed
   - **Optional pricing fields**: cost_per_fuel_unit, total_cost, currency, schedule_version

### Why Pricing Lives Here (Not in jig-core)

**Critical Architectural Decision:**

- `jig-core::BlockReceipt` = Protocol-level receipts (wire format, federation, attestation)
  - Contains: fuel_used, outcome, counters, timings
  - Does NOT contain: pricing fields (stays policy-neutral)

- `jig-runtime::Receipt` = Execution-level receipts (runtime output)
  - Contains: all core fields PLUS optional pricing
  - Pricing can be disabled via RuntimeConfig

- **Servers** apply pricing policy:
  - Configure RuntimeConfig with pricing rates
  - Store full jig_runtime::Receipt (with pricing) in database
  - Convert to jig_core::BlockReceipt for protocol operations
  - Pricing stored in metadata for flexibility

**Benefits:**
- Protocol stays neutral (different pricing models don't break compatibility)
- Servers control pricing policy without core protocol changes
- Federation works across pricing domains
- Pricing evolves independently of protocol versioning

## Usage

```rust
use jig_runtime::{Runtime, RuntimeConfig, ExecutionContext, BlockPackage};

// Configure runtime with optional pricing
let mut config = RuntimeConfig::default();
config.pricing.enabled = true;
config.pricing.cost_per_fuel_unit = 0.000001;

let runtime = Runtime::with_config(config)?;

// Execute WASM
let wasm_bytes = std::fs::read("block.wasm")?;
let package = BlockPackage::from_wasm(wasm_bytes).with_id("block-123");
let context = ExecutionContext::default().with_block(package);

let receipt = runtime.execute(&wasm_bytes, context)?;

println!("Fuel used: {}", receipt.fuel_used);
if let Some(pricing) = receipt.pricing {
    println!("Cost: {} {}", pricing.total_cost, pricing.currency.unwrap_or("units".into()));
}
```

## Configuration

See `RuntimeConfig` for:
- Resource limits (fuel_max, memory_max_mb, timeout)
- Capability allowlists and quotas
- Pricing settings (enabled, cost_per_fuel_unit, currency)
- Engine settings (deterministic mode, WASI preview2)

Config can be loaded from TOML:
```toml
[limits]
fuel_max = 5_000_000
memory_max_mb = 32

[pricing]
enabled = true
cost_per_fuel_unit = 0.000001
currency = "USD"
```

## Integration Points

**For CLI tools (jig-cli):**
- Use `Runtime::execute()` directly
- Output full `jig_runtime::Receipt` (with pricing) as JSON
- No need to convert to BlockReceipt unless federating

**For servers (jig-server):**
- Store full `jig_runtime::Receipt` with pricing metadata
- Convert to `jig_core::BlockReceipt` for wire protocol
- Billing/analytics query stored receipts directly

**For federation:**
- Convert to `jig_core::BlockReceipt` (pricing in metadata)
- Attestation/signature on BlockReceipt only
- Cross-domain pricing preserved but not enforced

## Features

- ✅ **Deterministic execution** - Fuel metering, canonicalized NaN, no threading
- ✅ **WASI support** - Preview1 with deterministic sandboxing
- ✅ **Capability security** - Closed-by-default, per-capability quotas
- ✅ **Resource limits** - Fuel, memory, timeout enforcement
- ✅ **Receipt v0.2** - Detailed execution metadata with optional pricing
- ✅ **Error handling** - Graceful handling of malformed/malicious WASM
- ✅ **Concurrent execution** - Isolated store contexts per execution

## Testing

**93 tests** covering:
- Determinism (identical receipts across runs)
- Fuel metering (consumption, limits, exhaustion)
- Capability security (WASI sandboxing, isolation)
- Resource exhaustion (memory, fuel, concurrent execution)
- Malicious WASM (invalid bytecode, traps, bad imports)
- Golden receipts (regression detection)

Run tests:
```bash
cargo test
```

Fuzz testing:
```bash
cargo +nightly fuzz run fuzz_wasm_bytes -- -max_total_time=60
```

## Development

**Requirements**:
- Rust 1.75+ (edition 2024)
- `wasm32-wasip1` target for test fixtures
- Nightly Rust for fuzzing (optional)

**Build**:
```bash
cargo build --all-features
```

**Lint**:
```bash
cargo clippy --all-features
```

**Test fixtures**:
```bash
cd tests/fixtures && ./build.sh
```

