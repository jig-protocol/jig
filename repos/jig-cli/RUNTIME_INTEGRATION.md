# jig-cli Runtime Integration Guide (M3.2)

## Architecture: CLI as Direct Runtime Consumer

Unlike jig-server (which converts receipts for protocol operations), **jig-cli should consume jig-runtime directly** without forced conversions.

## Design Principles

### 1. Output Full Runtime Receipts
```rust
// ✅ CORRECT: Output jig_runtime::Receipt directly
let receipt = runtime.execute(&wasm_bytes, context)?;
println!("{}", receipt.to_json()?);
```

```rust
// ❌ WRONG: Don't convert to BlockReceipt for CLI output
let block_receipt = convert_to_core_receipt(&receipt)?;  // Unnecessary!
println!("{}", serde_json::to_string_pretty(&block_receipt)?);
```

**Why?** CLI users want full execution details (pricing, capability calls, fuel breakdown). Converting to BlockReceipt loses this information.

### 2. BlockReceipt Only for Federation
```rust
// Use case: Submitting receipts to a server
jig-cli submit --receipt execution.json --server https://jig.example.com
```

In this case, convert to BlockReceipt ONLY when sending to server:
```rust
let runtime_receipt = Receipt::from_json(&receipt_json)?;
let block_receipt = convert_for_federation(&runtime_receipt)?;
client.post("/receipts").json(&block_receipt).send()?;
```

### 3. Receipt Storage
CLI should save full jig_runtime::Receipt JSON files:
```bash
jig-cli run block.wasm --receipt-output execution-receipt.json
```

Contents:
```json
{
  "version": "0.2",
  "block_id": "bafk...",
  "fuel_used": 4500,
  "pricing": {
    "cost_per_fuel_unit": 0.000001,
    "total_cost": 0.0045,
    "currency": "USD",
    "schedule_version": "0.1.0"
  },
  "capability_calls": [...],
  "fuel_by_capability": {...}
}
```

## Implementation Checklist

### Core Execution
- [ ] Import `jig_runtime::{Runtime, RuntimeConfig, ExecutionContext}`
- [ ] Load RuntimeConfig from CLI flags / TOML config
- [ ] Execute: `runtime.execute(&wasm_bytes, context)?`
- [ ] Output: `receipt.to_json()` (NOT converted BlockReceipt)

### CLI Flags (Suggested)
```bash
# Resource limits
--fuel-max <UNITS>
--memory-max-mb <MB>
--timeout-ms <MS>

# Pricing
--pricing-enabled
--cost-per-fuel <FLOAT>
--pricing-currency <STRING>

# Config
--runtime-config <PATH>     # Load RuntimeConfig from TOML

# Output
--receipt-output <PATH>     # Save full jig_runtime::Receipt JSON
--json                      # Output receipt as JSON to stdout
--quiet                     # Suppress output, only return exit code
```

### Config File (runtime-config.toml)
```toml
[limits]
fuel_max = 5_000_000
memory_max_mb = 32
execution_timeout_ms = 250

[pricing]
enabled = true
cost_per_fuel_unit = 0.000001
currency = "USD"

[capabilities]
allowed = ["http", "kv"]
deny_by_default = true
```

### Capabilities
```bash
# CLI approach
jig-cli run block.wasm --capability http --capability kv

# Config approach (preferred)
jig-cli run block.wasm --manifest block-manifest.toml
```

Read from manifest.capabilities and pass to ExecutionContext:
```rust
for cap in manifest.capabilities {
    context = context.with_capability(cap.name);
}
```

## Example Implementation

```rust
use jig_runtime::{Runtime, RuntimeConfig, ExecutionContext, BlockPackage};

pub fn execute_block(
    wasm_path: &str,
    config: RuntimeConfig,
    capabilities: Vec<String>,
) -> Result<()> {
    // Create runtime
    let runtime = Runtime::with_config(config)?;
    
    // Load WASM
    let wasm_bytes = std::fs::read(wasm_path)?;
    let package = BlockPackage::from_wasm(wasm_bytes)
        .with_id(format!("file:{}", wasm_path));
    
    // Build context
    let mut context = ExecutionContext::default()
        .with_block(package);
    
    for cap in capabilities {
        context = context.with_capability(cap);
    }
    
    // Execute
    let receipt = runtime.execute(&wasm_bytes, context)?;
    
    // Output full receipt (NOT converted)
    println!("{}", receipt.to_json()?);
    
    // Check outcome
    if !receipt.is_success() {
        eprintln!("Execution failed: {:?}", receipt.error_message);
        std::process::exit(1);
    }
    
    Ok(())
}
```

## Anti-Patterns to Avoid

### ❌ Don't Create Unnecessary Abstractions
```rust
// BAD: Creating a wrapper that hides runtime details
pub struct CliRuntime {
    inner: Runtime,
}

impl CliRuntime {
    pub fn run(&self, wasm: &[u8]) -> CliReceipt { ... }  // Custom receipt type
}
```

Just use `jig_runtime::Runtime` directly.

### ❌ Don't Convert Receipts for Display
```rust
// BAD: Losing information
let core_receipt = to_block_receipt(&runtime_receipt);
println!("{}", serde_json::to_string(&core_receipt)?);  // Missing pricing!
```

### ❌ Don't Hardcode Pricing
```rust
// BAD: Inflexible
let config = RuntimeConfig {
    pricing: PricingConfig {
        enabled: true,
        cost_per_fuel_unit: 0.000001,  // Hardcoded!
        ..Default::default()
    },
    ..Default::default()
};
```

Use CLI flags or config file instead.

## Summary

**jig-cli = Direct Runtime Consumer**
- Input: WASM + RuntimeConfig + ExecutionContext
- Execute: `Runtime::execute()`
- Output: Full `jig_runtime::Receipt` JSON (with pricing, capability calls, etc.)
- Storage: Save receipts as-is (no conversion)
- Federation: Convert to BlockReceipt ONLY when submitting to servers

This keeps CLI simple, preserves all execution data, and avoids unnecessary abstraction layers.

See `jig-runtime/README.md` for full architecture rationale.
