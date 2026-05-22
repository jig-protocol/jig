# Receipts

**Audience:** This chapter is for **protocol implementers** running hosts that emit receipts, **developers** building blocks that need to understand billing, and **server operators** setting pricing policies. **End users** might want to skim the outcome-based pricing section to understand how billing works.

---

**Version:** 0.2
**Status:** Stable

Receipts are like itemized bills for block execution. When a host runs your block, it emits a signed receipt proving:

- **What ran**: Block CID, host DID, timestamp
- **What happened**: Success, soft fail, or hard fail
- **What it cost**: Fuel consumed, broken down by capability
- **What it achieved**: Affordances (e.g., "email delivered", "HTTP 2xx")

Receipts enable three critical features:

1. **Outcome-based pricing**: Charge different rates for success vs. failure. If a block fails due to network timeout (not your fault), you get a partial refund.
2. **Fraud detection**: Anyone can replay a block and verify the receipt matches. If a server says your block used 5M fuel but your replay only uses 500k, they're overcharging.
3. **Federation trust**: Receipts travel with blocks across servers as cryptographic proof of work done.

## Receipt Schema (v0.2)

Here's a complete receipt with all fields explained:

```json
{
  "version": "0.2.0",
  "block_id": "cid:bafyBlock123...",
  "host": "did:jig:server:prod",
  "executed_at": "2025-11-09T12:34:56.789Z",

  "outcome": {
    "status": "ok",
    "affordances": ["email.delivered"],
    "reason": null
  },

  "counters": {
    "fuel_total": 421337,
    "fuel_by_capability": {
      "net.fetch": 310000,
      "crypto.sign": 60000,
      "core.compute": 51337
    },
    "status_by_capability": {
      "net.fetch": { "OK": 1 }
    },
    "bytes_tx": 20480,
    "bytes_rx": 32768,
    "syscalls": 0
  },

  "timings": {
    "queue_wait_ms": 2,
    "init_ms": 3,
    "exec_ms": 187,
    "total_ms": 190
  },

  "limits": {
    "max_fuel": 5000000,
    "max_memory_bytes": 33554432,
    "max_execution_time_ms": 250
  },

  "render": {
    "output_hash": "blake3:d3abc...",
    "output_size_bytes": 512,
    "matches_expected": true
  },

  "capabilities_used": [
    "net.fetch",
    "crypto.sign"
  ],

  "signature": {
    "key": "ed25519:v1:hostKey...",
    "signature": "ed25519:v1:sigBytes..."
  },

  "metadata": {
    "timing.clock_source": "monotonic",
    "host.region": "us-west-2"
  }
}
```

Let's break down each section:

## Core Fields

**`version`**: Receipt schema version (currently `0.2.0`). Future breaking changes will bump to `0.3.0`.

**`block_id`**: Content identifier (CID) of the block that was executed. This ties the receipt to a specific, immutable block.

**`host`**: DID of the server/host that executed the block. This is who's attesting to the execution.

**`executed_at`**: Timestamp in RFC 3339 format (UTC). Useful for chronological ordering and replay audits.

**For implementers:** All receipts MUST be signed by the host's keypair. Invalid signatures → reject the receipt.

## Outcome

The `outcome` object tells you whether execution succeeded and what was achieved:

```json
"outcome": {
  "status": "ok",
  "affordances": ["email.delivered"],
  "reason": null
}
```

### Status

**`ok`**: Execution completed successfully. Block did what it promised.

**`soft_fail`**: Recoverable failure. Examples:
- Network timeout (upstream API down)
- Upstream 5xx error (their problem, not yours)
- Render mismatch (output hash doesn't match expected)

**`hard_fail`**: Fatal error. Examples:
- Fuel exhausted (block ran out of CPU budget)
- Memory limit exceeded
- Capability denied (block requested something not granted)
- Manifest invalid (signature failed)

**Why three statuses?**

- **`ok`**: You pay full price (100% fuel cost).
- **`soft_fail`**: You pay partial or nothing (network retry isn't your fault).
- **`hard_fail`**: You pay nothing (server's fault for accepting invalid manifest, or your fault for exceeding limits—policy determines refund).

**For server operators:** Configure refund policies:

- **Soft fail**: 50% refund (user attempted, server couldn't deliver)
- **Hard fail**: 100% refund if manifest was invalid (server's fault), 0% refund if fuel exhausted (user's fault)

### Affordances

Affordances are success signals that prove what the block achieved. They enable outcome-based pricing without leaking payload content.

**Canonical affordances:**

- **`email.delivered`**: Email delivered to recipient's mail server (SMTP 250 OK).
- **`bridge.forwarded`**: Message forwarded to external protocol (Slack, Discord, IRC).
- **`net.http_2xx`**: HTTP request returned 2xx status (success).
- **`queue.enqueued`**: Message persisted to durable queue (Kafka, SQS, RabbitMQ).
- **`storage.persisted`**: Data written to durable storage (S3, IPFS, database).

**Why affordances matter:**

**Privacy-preserving**: Reveals THAT an action succeeded, not WHAT data was involved. "Email delivered" doesn't tell you the recipient or content—just that delivery succeeded.

**Outcome-based pricing**: Hosts can charge a premium for successful delivery:

```
Base cost: 421,337 fuel × $0.000001/fuel = $0.42
Affordance bonus: "email.delivered" × 1.5× = $0.21
Total: $0.63
```

**Federation trust**: Receipts with `email.delivered` can be relayed to federated servers as proof that email was sent (without exposing the email content).

**Custom affordances:**

If you need application-specific affordances, use this format:

```
custom:<namespace>:<action>
```

Examples:

- `custom:stripe.com:payment_captured`
- `custom:example.com:invoice_generated`

**For developers:** Namespace SHOULD be a domain you control (DNS-style). Use past-tense verbs (snake_case) for actions. Don't expose PII in affordance names.

### Reason Codes

When execution fails (`soft_fail` or `hard_fail`), the `reason` field contains a machine-readable code:

| Code | Description | Typical Status |
|------|-------------|----------------|
| `FUEL_EXHAUSTED` | Ran out of CPU budget | `hard_fail` |
| `MEMORY_LIMIT_EXCEEDED` | Memory limit exceeded | `hard_fail` |
| `RUNTIME_TIMEOUT` | Execution timeout | `hard_fail` |
| `RUNTIME_TRAP` | WebAssembly panic/trap | `hard_fail` |
| `CAPABILITY_DENIED` | Capability not granted | `hard_fail` |
| `MANIFEST_INVALID` | Manifest validation failed | `hard_fail` |
| `NONDETERMINISM_DETECTED` | Replay gave different result | `hard_fail` |
| `RENDER_MISMATCH` | Output hash ≠ expected | `soft_fail` |
| `NET_TIMEOUT` | Network operation timeout | `soft_fail` |
| `UPSTREAM_5XX` | Upstream service error | `soft_fail` |
| `HOST_PANIC` | Host runtime panic | `hard_fail` |
| `UNKNOWN` | Unclassified error | `hard_fail` |

**Normative requirements:**

- Failures (`soft_fail`, `hard_fail`) MUST include `reason`.
- Failures MUST NOT include `affordances` (if it failed, it didn't afford anything).
- Success (`ok`) SHOULD include `affordances` when applicable.

**For implementers:** Use SCREAMING_SNAKE_CASE for reason codes to match established conventions.

## Counters

The `counters` object breaks down resource usage:

```json
"counters": {
  "fuel_total": 421337,
  "fuel_by_capability": {
    "net.fetch": 310000,
    "crypto.sign": 60000,
    "core.compute": 51337
  },
  "status_by_capability": {
    "net.fetch": { "OK": 1 }
  },
  "bytes_tx": 20480,
  "bytes_rx": 32768,
  "syscalls": 0
}
```

**`fuel_total`**: Total CPU instructions consumed. MUST equal the sum of `fuel_by_capability` values.

**`fuel_by_capability`**: Fuel consumed per capability. This enables granular pricing:

```
net.fetch:     310,000 fuel × $0.000001/fuel = $0.31
crypto.sign:    60,000 fuel × $0.000002/fuel = $0.12  (crypto costs more)
core.compute:   51,337 fuel × $0.000001/fuel = $0.05
Total: $0.48
```

**Why per-capability billing:** Because different operations have different real costs. Network calls are expensive (latency, bandwidth). Crypto operations need specialized hardware. Pure CPU is cheap.

**`status_by_capability`**: Bins status codes by capability. Example:

```json
"status_by_capability": {
  "net.fetch": {
    "OK": 3,      // 3 successful requests
    "TIMEOUT": 1  // 1 timeout
  }
}
```

Status labels MUST be UPPERCASE (e.g., `OK`, `FAIL`, `TIMEOUT`).

**`bytes_tx` / `bytes_rx`**: Network bytes transmitted/received. Useful for metered bandwidth pricing.

**`syscalls`**: System calls made (0 unless WASI syscalls are explicitly enabled—rare in deterministic mode).

**Validation rules:**

- `fuel_total` MUST equal sum of `fuel_by_capability` values.
- Keys in `status_by_capability` MUST exist in `capabilities_used`.

**For implementers:** Track fuel at the capability level (not just total). This prevents billing fraud—hosts can't claim "500k fuel for compute" when it was actually "400k compute + 100k network."

## Timings

Execution time breakdown (milliseconds):

```json
"timings": {
  "queue_wait_ms": 2,
  "init_ms": 3,
  "exec_ms": 187,
  "total_ms": 190
}
```

**`queue_wait_ms`**: Time waiting in the execution queue (not counted in `total_ms`). High queue wait suggests the host is overloaded.

**`init_ms`**: WebAssembly module initialization time (loading, linking, compiling).

**`exec_ms`**: Actual execution time (running the block's code).

**`total_ms`**: `init_ms + exec_ms` (MUST equal sum). This is the billable time.

**Why separate init and exec:** Because init time is amortized—if the host caches compiled modules, init drops to near-zero on subsequent runs. Exec time is per-invocation.

**Validation rule:** `total_ms == init_ms + exec_ms`.

**For implementers:** Use **monotonic clocks** (not wall-clock time) to prevent time drift or NTP adjustments from affecting measurements.

## Limits

Execution constraints snapshot:

```json
"limits": {
  "max_fuel": 5000000,
  "max_memory_bytes": 33554432,
  "max_execution_time_ms": 250
}
```

**Why include limits in the receipt?**

For **replay verification**. When you replay a block to verify the receipt, you use the exact same limits:

```
replay_receipt = execute(block, limits=receipt.limits)
assert replay_receipt.fuel_used == receipt.fuel_used
assert replay_receipt.render.output_hash == receipt.render.output_hash
```

If the replayed receipt differs, the original receipt was forged or the host misbehaved.

**For developers:** When debugging billing disputes, replay locally with the same limits. If your replay uses 100k fuel but the server's receipt claims 1M fuel, you have evidence of fraud.

## Render Output

The `render` object describes the block's output:

```json
"render": {
  "output_hash": "blake3:d3abc...",
  "output_size_bytes": 512,
  "matches_expected": true
}
```

**`output_hash`**: Hash of the render output (stdout, return value). Uses BLAKE3 for speed.

**`output_size_bytes`**: Size of the output in bytes. Useful for storage accounting.

**`matches_expected`**: Boolean indicating whether `output_hash` matches the `manifest.render.expected_hash`. If `false`, this might be a `soft_fail` with `RENDER_MISMATCH` reason (output was produced, but it's not what the manifest promised).

**For implementers:** Always hash the output, even if the manifest doesn't provide an expected hash. This enables post-hoc verification.

## Capabilities Used

```json
"capabilities_used": [
  "net.fetch",
  "crypto.sign"
]
```

List of capabilities actually used during execution (subset of what was requested in the manifest).

**Why track this:** A block might declare 10 capabilities but only use 2. The receipt shows which were actually invoked, enabling accurate billing.

**For developers:** If your block requests `net.fetch` but the receipt shows `capabilities_used: []`, you forgot to call `fetch()` or it was optimized out.

## Signature

```json
"signature": {
  "key": "ed25519:v1:hostKey...",
  "signature": "ed25519:v1:sigBytes..."
}
```

**What gets signed:** Canonical JSON of the entire receipt (minus the `signature` field itself).

**Why sign receipts:** So you can verify the receipt came from the host it claims. If a malicious actor tries to forge a receipt (claiming you owe $100 when you actually owe $1), they can't fake the host's signature.

**For implementers:** Use constant-time signature verification (see [Crypto Primitives § Constant-Time Operations](crypto.md#constant-time-operations)) to prevent timing attacks.

## Metadata

```json
"metadata": {
  "timing.clock_source": "monotonic",
  "host.region": "us-west-2"
}
```

Optional map for host-specific metadata. Common uses:

- **Clock source**: `monotonic` (preferred) vs `realtime` (discouraged)
- **Host region**: Geographic location (e.g., `us-west-2`, `eu-central-1`)
- **Runtime version**: `wasmtime:v15.0.0`

**For server operators:** Don't put PII in metadata. This field may be logged or published to transparency logs.

## Backwards Compatibility

### Version History

**v0.1** (deprecated): Core fields only (`block_id`, `host`, `executed_at`, `render_hash`, `fuel_used`).

**v0.2** (current): Added `outcome`, `counters`, `timings`, `limits`, `version` field.

### Migration Path

All v0.2 fields are backward-compatible with v0.1:

- Parsers MUST accept v0.1 receipts (missing v0.2 fields default to `null`).
- Hosts MAY emit v0.2 fields incrementally (don't have to add all at once).
- No explicit version detection required—presence of v0.2 fields indicates v0.2.

**For implementers:** When parsing receipts, check if `outcome` exists. If yes, it's v0.2. If no, it's v0.1.

### Future Versions

Breaking changes (e.g., renaming fields, changing semantics) will trigger **v0.3** with an explicit `receipt_version` field.

## Use Cases

### Outcome-Based Pricing

Charge different rates based on execution outcome:

```python
def calculate_cost(receipt):
    base_cost = receipt['counters']['fuel_total'] * FUEL_RATE

    if receipt['outcome']['status'] == 'ok':
        return base_cost  # Full price
    elif receipt['outcome']['status'] == 'soft_fail':
        return base_cost * 0.5  # 50% refund (network retry)
    elif receipt['outcome']['status'] == 'hard_fail':
        if receipt['outcome']['reason'] == 'MANIFEST_INVALID':
            return 0  # Our fault, full refund
        else:
            return base_cost * 0.25  # User's fault (fuel exhausted), partial refund
```

**Why this matters:** Aligns incentives. If the server's network is flaky and requests timeout, users shouldn't pay full price. If the user submits a block that runs out of fuel, they pay for wasted CPU.

### Per-Capability Billing

Price different capabilities at different rates:

```python
PRICING = {
    'net.fetch': 0.000002,   # $2/M fuel (network is expensive)
    'crypto.sign': 0.000003, # $3/M fuel (crypto is specialized)
    'core.compute': 0.000001 # $1/M fuel (CPU is cheap)
}

def calculate_cost(receipt):
    total = 0
    for capability, fuel in receipt['counters']['fuel_by_capability'].items():
        capability_type = capability.split(':')[0]  # Extract "net", "crypto", etc.
        rate = PRICING.get(capability_type, PRICING['core.compute'])
        total += fuel * rate
    return total
```

**Real-world pricing example:**

```
Block uses:
  - net.fetch: 310,000 fuel × $0.000002 = $0.62
  - crypto.sign: 60,000 fuel × $0.000003 = $0.18
  - core.compute: 51,337 fuel × $0.000001 = $0.05
Total: $0.85
```

**For server operators:** Set rates based on your actual costs. If you're running on AWS, network costs real money. If you're on bare metal with 10Gbps, network is nearly free.

### Deterministic Replay

Verify receipts by re-executing the block:

```python
def verify_receipt(block, receipt):
    # Replay with same limits
    replay = execute_block(block, limits=receipt['limits'])

    # Check fuel consumption
    if replay['counters']['fuel_total'] != receipt['counters']['fuel_total']:
        raise FraudDetected(f"Fuel mismatch: {replay} vs {receipt}")

    # Check output hash
    if replay['render']['output_hash'] != receipt['render']['output_hash']:
        raise FraudDetected(f"Render mismatch: {replay} vs {receipt}")

    # Receipt verified!
    return True
```

**Why this matters:** Prevents billing fraud. If a malicious server claims your block used 10M fuel, you can replay it locally and prove it only used 500k.

**For end users:** If you suspect overcharging, run `jig replay <receipt_id>` (CLI tool) to verify locally.

### Affordance-Based Pricing

Charge premiums for successful delivery:

```python
def calculate_cost(receipt):
    base_cost = receipt['counters']['fuel_total'] * FUEL_RATE

    if 'email.delivered' in receipt['outcome'].get('affordances', []):
        base_cost *= 1.5  # 50% premium for email delivery

    if 'storage.persisted' in receipt['outcome'].get('affordances', []):
        base_cost *= 1.2  # 20% premium for durable storage

    return base_cost
```

**Why premiums:** Because delivery has real costs beyond CPU. Email delivery requires SMTP server resources, reputation management, bounce handling. Durable storage requires disk, backups, replication.

## Privacy & Security

### E2EE Compatibility

Receipts are designed to work with end-to-end encryption:

**What receipts reveal:**

- Fuel consumed (how much CPU was used)
- Capabilities used (e.g., `net.fetch` called)
- Affordances achieved (e.g., `email.delivered`)

**What receipts DON'T reveal:**

- Email recipient (just "email was delivered")
- HTTP request payload (just "HTTP 2xx returned")
- Message content (encrypted, not metered)

**For developers:** Fuel consumption is deterministic—same code + same inputs = same fuel, regardless of encrypted data. This prevents content leakage through metering.

### Fraud Prevention

**Validation checks:**

- `counters.fuel_total == sum(fuel_by_capability)` prevents fuel inflation.
- `timings.total_ms == init_ms + exec_ms` prevents timing manipulation.
- `signature` verification ensures receipt came from claimed host.

**Replay audits:**

Anyone can re-execute a block with `limits` from the receipt and verify fuel/output match.

**Transparency logs:**

Receipts SHOULD be published to transparency logs (e.g., Rekor) so anyone can audit billing over time.

**For server operators:** If you detect fraud (user replayed and got vastly different results), investigate immediately. Either your metering is broken or the receipt was forged.

### PII Protection

**Don't include in receipts:**

- Email addresses
- User names (beyond DIDs)
- Message content
- IP addresses (unless required for abuse prevention, then hash them)

**For server operators:** Receipts may be published to transparency logs or shared with federated servers. Treat them as public.

## Example Receipts

### Success Receipt (Email Delivery)

```json
{
  "version": "0.2.0",
  "block_id": "cid:bafyEmailBlock...",
  "host": "did:jig:server:prod",
  "executed_at": "2025-11-09T12:34:56.789Z",

  "outcome": {
    "status": "ok",
    "affordances": ["email.delivered"],
    "reason": null
  },

  "counters": {
    "fuel_total": 421337,
    "fuel_by_capability": {
      "net.fetch": 310000,
      "crypto.sign": 60000,
      "core.compute": 51337
    },
    "bytes_tx": 20480,
    "bytes_rx": 32768
  },

  "timings": {
    "queue_wait_ms": 2,
    "init_ms": 3,
    "exec_ms": 187,
    "total_ms": 190
  },

  "limits": {
    "max_fuel": 5000000,
    "max_memory_bytes": 33554432,
    "max_execution_time_ms": 250
  },

  "render": {
    "output_hash": "blake3:d3abc...",
    "output_size_bytes": 512,
    "matches_expected": true
  },

  "capabilities_used": ["net.fetch", "crypto.sign"],

  "signature": {
    "key": "ed25519:v1:hostKey...",
    "signature": "ed25519:v1:sigBytes..."
  }
}
```

### Failure Receipt (Fuel Exhausted)

```json
{
  "version": "0.2.0",
  "block_id": "cid:bafyInfiniteLoop...",
  "host": "did:jig:server:prod",
  "executed_at": "2025-11-09T12:35:00.123Z",

  "outcome": {
    "status": "hard_fail",
    "affordances": [],
    "reason": "FUEL_EXHAUSTED"
  },

  "counters": {
    "fuel_total": 1000000,
    "fuel_by_capability": {
      "core.compute": 1000000
    }
  },

  "timings": {
    "queue_wait_ms": 1,
    "init_ms": 2,
    "exec_ms": 45,
    "total_ms": 47
  },

  "limits": {
    "max_fuel": 1000000,
    "max_memory_bytes": 16777216,
    "max_execution_time_ms": 100
  },

  "render": {
    "output_hash": "",
    "output_size_bytes": 0,
    "matches_expected": false
  },

  "capabilities_used": [],

  "signature": {
    "key": "ed25519:v1:hostKey...",
    "signature": "ed25519:v1:sigBytes..."
  }
}
```

**What happened:** Block ran out of fuel after consuming exactly 1M fuel (the limit). No output was produced. User pays 0% or partial cost (policy-dependent).

## Normative Requirements Summary

**MUST:**

- Include `version`, `block_id`, `host`, `executed_at`, `outcome`, `signature` in every receipt.
- Sign receipts with the host's Ed25519 keypair.
- Ensure `counters.fuel_total == sum(fuel_by_capability)`.
- Ensure `timings.total_ms == init_ms + exec_ms`.
- Include `reason` for all failures (`soft_fail`, `hard_fail`).
- Exclude `affordances` from failure receipts.
- Use SCREAMING_SNAKE_CASE for reason codes.
- Use UPPERCASE labels for `status_by_capability` bins.

**SHOULD:**

- Use monotonic clocks for timings (not wall-clock).
- Publish receipts to transparency logs (e.g., Rekor).
- Track fuel at the capability level (not just total).
- Verify receipts via replay when fraud is suspected.

**MAY:**

- Include optional `metadata` for host-specific details.
- Implement reputation-based affordance trust (trust `verified` users more than `null_sec`).
- Cache compiled WebAssembly modules to reduce `init_ms` on repeated executions.
- Add custom affordances using `custom:<namespace>:<action>` format.

---

**Next:** Now that you understand receipts, check out [Transports](transports.md) to see how blocks and receipts are transmitted over IRC, WebSocket, and SSH, or jump to [Federation](federation.md) to see how receipts enable trustless inter-server collaboration.
