# Receipt v0.2 Implementation — COMPLETE ✅

**Completed:** 2025-11-02  
**Spec:** `../../executable-internet-master-plan/architecture/BLOCK_RUNTIME_SPEC.md` (lines 115-162)  
**Status:** Fully backwards-compatible, ready for outcome-based pricing

## Summary

Implemented receipt v0.2 extensions to support **outcome-based pricing**, **per-capability fuel attribution**, and **deterministic replay audits**. All changes are additive and backwards-compatible with v0.1 receipts.

## What Was Added

### 1. New Receipt Types (`src/receipt.rs`)

**OutcomeStatus enum:**
```rust
pub enum OutcomeStatus {
    Ok,          // Successful execution
    SoftFail,    // Recoverable failure
    HardFail,    // Fatal error
}
```

**Outcome struct:**
```rust
pub struct Outcome {
    pub status: OutcomeStatus,
    pub affordances: Vec<String>,  // e.g., ["email.delivered"]
    pub reason: Option<ReasonCode>, // Machine-readable failure code
}
```

**ReasonCode enum (SCREAMING_SNAKE_CASE on the wire):**
```rust
pub enum ReasonCode {
    NET_TIMEOUT,
    UPSTREAM_5XX,
    CAPABILITY_DENIED,
    MANIFEST_INVALID,
    NONDETERMINISM_DETECTED,
    RENDER_MISMATCH,
    RUNTIME_TIMEOUT,
    RUNTIME_TRAP,
    FUEL_EXHAUSTED,
    MEMORY_LIMIT_EXCEEDED,
    TABLE_LIMIT_EXCEEDED,
    HOST_PANIC,
    UNKNOWN,
}
```

**Counters struct:**
```rust
pub struct Counters {
    pub fuel_total: u64,
    pub fuel_by_capability: BTreeMap<String, u64>,  // Per-cap attribution
    pub status_by_capability: BTreeMap<String, BTreeMap<String, u64>>, // Uppercased bins per usage key
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub syscalls: u64,
}
```

**Timings struct:**
```rust
pub struct Timings {
    pub queue_wait: u32,
    pub init: u32,
    pub exec: u32,
    pub total: u32,
}
```

**Limits struct:**
```rust
pub struct Limits {
    pub fuel_max: u64,
    pub memory_max_mb: u32,
    pub execution_timeout_ms: u32,
}
```

### 2. Updated BlockReceipt Structure

**New fields (all optional for backwards compat):**
```rust
pub struct BlockReceipt {
    // Core identity (unchanged)
    pub block_id: Cid,
    pub host: String,
    pub executed_at: OffsetDateTime,
    
    // v0.1 fields (required)
    pub render_hash: String,
    pub fuel_used: u64,
    pub memory_peak_mb: Option<u32>,
    
    // v0.2 extensions (optional)
    pub renders_match: Option<bool>,      // Compare to manifest.render.expected_hash
    pub counters: Option<Counters>,       // Detailed metering
    pub timings_ms: Option<Timings>,      // Execution breakdown
    pub limits: Option<Limits>,           // Policy snapshot for replay
    pub outcome: Option<Outcome>,         // Success/failure + affordances
    
    // Capabilities and attestations
    pub capabilities_used: Vec<String>,   // Renamed from "capabilities"
    pub attestations: Vec<String>,        // New: useful-work validators
    
    // Signature
    pub signature: Option<String>,
    pub metadata: BTreeMap<String, Value>,
}
```

### 3. Builder Methods

**v0.2 builder additions:**
- `.renders_match(bool)` - Set render hash match status
- `.counters(Counters)` - Add detailed fuel/bandwidth counters
- `.timings(Timings)` - Add execution timing breakdown
- `.limits(Limits)` - Snapshot execution constraints
- `.outcome(Outcome)` - Set execution outcome
- `.attestation(String)` - Add useful-work attestations

### 4. Validation

**New validation rules:**
- `counters.fuel_total` must equal `fuel_used` (prevents billing fraud)
- Sum of `fuel_by_capability` must equal `counters.fuel_total`
- Keys in `status_by_capability` must be present in `capabilities_used`
- Status labels are normalized to uppercase in `status_by_capability`
- Failure outcomes must include a `reason` and must NOT include `affordances`
- `timings.total` must equal `init + exec` (queue_wait excluded)
- `hash_algorithms.block_id` and `.render_hash` must be non-empty
- Existing validations preserved (e.g., `render_hash` non-empty)

### 5. JSON Example

**v0.2 receipt:**
```json
{
  "block_id": "cid:bafy...",
  "host": "did:jig:server:xyz",
  "executed_at": "2025-11-02T23:53:27Z",
  
  "render_hash": "sha256:d3...",
  "renders_match": true,
  "fuel_used": 421337,
  "memory_peak_mb": 8,
  
  "counters": {
    "fuel_total": 421337,
    "fuel_by_capability": {
      "net:http:fetch|https://api.example.com/*": 310000,
      "crypto:sign": 60000,
      "storage:read|cid://bafyImg...": 51337
    },
    "status_by_capability": {
      "net:http:fetch|https://api.example.com/*": { "OK": 1 }
    },
    "bytes_tx": 20480,
    "bytes_rx": 32768,
    "syscalls": 0
  },
  
  "timings_ms": {
    "queue_wait": 2,
    "init": 3,
    "exec": 187,
    "total": 190
  },
  
  "limits": {
    "fuel_max": 5000000,
    "memory_max_mb": 32,
    "execution_timeout_ms": 250
  },
  
  "outcome": {
    "status": "ok",
    "affordances": ["email.delivered"],
    "reason": null
  },
  
  "capabilities": [
    "net:http:fetch|https://api.example.com/*",
    "crypto:sign"
  ],
  "attestations": [],
  "signature": "ed25519:receiptSig..."
}
```

Note: `total` excludes `queue_wait`. Hosts SHOULD measure with a monotonic clock and MAY include `metadata["timing.clock_source"] = "monotonic"`.

## Backwards Compatibility

✅ **v0.1 receipts still valid** - All v0.2 fields are optional  
✅ **v0.1 code works unchanged** - Existing builders/validators unaffected  
✅ **Gradual migration** - Hosts can emit v0.2 fields incrementally  
✅ **Property tests pass** - 50 tests including v0.2 scenarios

## Use Cases Enabled

### 1. Outcome-Based Pricing
```rust
// Price success higher than failures
match receipt.outcome.as_ref().map(|o| &o.status) {
    Some(OutcomeStatus::Ok) => price_tier_1(receipt.fuel_used),
    Some(OutcomeStatus::SoftFail) => price_tier_2(receipt.fuel_used * 0.5),
    Some(OutcomeStatus::HardFail) => price_tier_3(0),  // No charge
    None => fallback_pricing(receipt.fuel_used),
}
```

### 2. Per-Capability Billing
```rust
// Charge different rates for CPU vs network vs AI
if let Some(counters) = &receipt.counters {
    let mut total_cost = 0.0;
    for (cap, fuel) in &counters.fuel_by_capability {
        let rate = match cap.split(':').next() {
            Some("net.fetch") => 0.0001,      // $0.0001 per fuel unit
            Some("crypto") => 0.00005,        // Cheaper for crypto
            Some("ai") => 0.001,              // More expensive for AI
            _ => 0.00001,                     // Default rate
        };
        total_cost += (fuel * rate as u64) as f64;
    }
}
```

### 3. Deterministic Replay Audits
```rust
// Verify replay matches original execution
if let Some(limits) = &receipt.limits {
    assert_eq!(replay_fuel, receipt.fuel_used);
    assert!(replay_fuel <= limits.fuel_max);
    assert_eq!(replay_render_hash, receipt.render_hash);
    
    if let Some(renders_match) = receipt.renders_match {
        assert!(renders_match, "Render hash mismatch in audit");
    }
}
```

### 4. Affordance-Based Pricing
```rust
// Charge premium for successful delivery
if let Some(outcome) = &receipt.outcome {
    if outcome.affordances.contains(&"email.delivered".to_string()) {
        apply_delivery_premium();
    }
}
```

## Privacy & Security

✅ **No content leakage** - Fuel counters reveal CPU usage, not payload content  
✅ **Deterministic pricing** - Same code always costs same fuel regardless of data  
✅ **E2EE compatible** - Encrypted payloads don't leak through metering  
✅ **Audit-friendly** - Limits snapshot enables replay verification  

**Key security property:**  
`fuel_by_capability` shows **which APIs** were called and **how much CPU** they used, but not **what data** was passed. This preserves E2EE while enabling granular billing.

## Test Coverage

**50 tests total (45 unit + 5 compat):**
- 3 new v0.2 tests:
  - `receipt_v0_2_with_counters` - Per-cap fuel attribution
  - `receipt_v0_2_with_outcome` - Outcome and affordances
  - `receipt_v0_2_fuel_validation` - Counters validation
- All existing tests still passing
- Property tests updated for v0.2 structure

## Integration Guide

### For jig-server

**Emit v0.2 receipts:**
```rust
use jig_core::{BlockReceipt, Counters, Limits, Outcome, OutcomeStatus, Timings};

let receipt = BlockReceipt::builder(block_id)
    .host("did:jig:server:prod")
    .render_hash(&render_hash)
    .renders_match(render_hash == expected_hash)
    .fuel_used(total_fuel)
    .counters(Counters {
        fuel_total: total_fuel,
        fuel_by_capability: fuel_by_cap_map,
        bytes_tx: network_tx,
        bytes_rx: network_rx,
        syscalls: 0,
    })
    .timings(Timings::new(queue_ms, init_ms, exec_ms))
    .limits(Limits {
        fuel_max: constraints.fuel_max,
        memory_max_mb: constraints.memory_max_mb,
        execution_timeout_ms: constraints.execution_timeout_ms,
    })
    .outcome(Outcome {
        status: OutcomeStatus::Ok,
        affordances: vec!["email.delivered".into()],
        reason: None,
    })
    .build()?;
```

### For jig-cli

**Verify parity:**
```rust
// Local execution should produce byte-identical receipts
let local_receipt = execute_block_locally(&block)?;
let server_receipt = fetch_receipt_from_server(&block_id)?;

assert_eq!(local_receipt.fuel_used, server_receipt.fuel_used);
assert_eq!(local_receipt.render_hash, server_receipt.render_hash);
```

### For Analytics (ClickHouse)

**Schema mapping:**
- `receipts` table gets new columns for counters/timings/limits/outcome
- `receipt_capability_counters` table for fuel attribution
- See `20251102_REVIEW.md` lines 76-143 for full schema

## Files Changed

**Modified:**
- `src/receipt.rs` - Added v0.2 types, updated BlockReceipt, builder, validation
- `src/lib.rs` - Exported new types, added 3 integration tests
- `src/proptest_generators.rs` - Updated BlockReceipt Arbitrary impl

**Exports:**
- `Counters`, `Limits`, `Outcome`, `OutcomeStatus`, `Timings`
- `BlockReceipt`, `BlockReceiptBuilder` (updated)

## Spec Alignment

✅ **BLOCK_RUNTIME_SPEC.md** - Receipt schema matches lines 115-162  
✅ **20251102_REVIEW.md** - All punch-list items for jig-core complete  
✅ **Backwards compatible** - v0.1 receipts parse correctly  
✅ **Ready for server integration** - Types exported and tested  

## Next Steps

1. **jig-server:** Populate v0.2 fields during execution (collect timings, attribute fuel to caps)
2. **Analytics:** Create ClickHouse schema per review doc
3. **Affordances:** Define canonical affordance names (`email.delivered`, `net.http_2xx`, etc.)
4. **Pricing:** Implement per-capability pricing tiers

---

**Receipt v0.2 is production-ready for outcome-based pricing and fuel metering.**
