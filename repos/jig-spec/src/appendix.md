# Appendix

**Audience:** This appendix is a reference for **protocol implementers** and **developers** who need canonical definitions, test vectors, or historical context. **Server operators** might consult the affordances registry when configuring pricing policies.

---

## Change Log

### 2025-11-09

- Added Block Execution Model chapter
- Added Receipts v0.2 specification
- Added Canonical Affordances reference
- Added Analytics Schema reference

### 2024-09-04

- Initial specification scaffold

## Canonical Affordances Reference

This section provides detailed specifications for canonical affordances used in receipt outcomes.

### email.delivered

**Description:** Email successfully delivered to recipient's mail server with SMTP 2xx response.

**When to Use:**
- SMTP delivery succeeded (250 OK or similar)
- Recipient mail server accepted message
- DKIM and SPF validation passed (recommended)

**Evidence Required:**
- SMTP transaction log showing 2xx response
- Recipient domain MX resolution succeeded
- Message-ID generated

**NOT Applicable When:**
- Email queued but not yet delivered (use `email.queued`)
- Delivery to local outbox (use `email.sent`)
- Bounce received after initial acceptance

**Example Receipt:**
```json
{
  "outcome": {
    "status": "ok",
    "affordances": ["email.delivered"]
  },
  "metadata": {
    "smtp.response_code": "250",
    "smtp.recipient_domain": "example.com",
    "message_id": "<abc123@jig.example.com>"
  }
}
```

---

### bridge.forwarded

**Description:** Message successfully forwarded to external protocol (Slack, Discord, IRC, etc.).

**When to Use:**
- Message posted to external system API and acknowledged
- External system returned success response
- Message visible to target users

**Evidence Required:**
- External API response indicating success
- Message ID or timestamp from external system
- No immediate delivery errors

**NOT Applicable When:**
- Message queued but not yet sent
- External system returned 5xx error (use `soft_fail`)
- Bridge authentication failed (use `hard_fail`)

**Example Receipt:**
```json
{
  "outcome": {
    "status": "ok",
    "affordances": ["bridge.forwarded"]
  },
  "metadata": {
    "bridge.target": "slack",
    "bridge.channel_id": "C1234567890",
    "bridge.message_ts": "1699564800.123456"
  }
}
```

---

### net.http_2xx

**Description:** HTTP request completed with 2xx success status code.

**When to Use:**
- Outbound HTTP request returned 200-299 status
- Response body successfully parsed (if expected)
- No transport-level errors

**Evidence Required:**
- HTTP status code in 2xx range
- Response headers received
- Connection successfully closed

**NOT Applicable When:**
- HTTP 3xx redirect (use `net.http_3xx`)
- HTTP 4xx client error (use `soft_fail` with `UPSTREAM_4XX`)
- HTTP 5xx server error (use `soft_fail` with `UPSTREAM_5XX`)
- Connection timeout (use `soft_fail` with `NET_TIMEOUT`)

**Example Receipt:**
```json
{
  "outcome": {
    "status": "ok",
    "affordances": ["net.http_2xx"]
  },
  "counters": {
    "status_by_capability": {
      "net:http:fetch|https://api.example.com/*": {
        "OK": 1,
        "CREATED": 1
      }
    }
  }
}
```

---

### queue.enqueued

**Description:** Message or task successfully added to durable queue.

**When to Use:**
- Queue system acknowledged message receipt
- Message persisted to durable storage
- Queue returned message ID or receipt handle

**Evidence Required:**
- Queue system response confirming enqueue
- Message ID or receipt handle
- Queue depth or position (optional)

**NOT Applicable When:**
- Queue full / over quota (use `soft_fail`)
- Queue authentication failed (use `hard_fail`)
- Message not yet persisted (in-memory buffer)

**Example Receipt:**
```json
{
  "outcome": {
    "status": "ok",
    "affordances": ["queue.enqueued"]
  },
  "metadata": {
    "queue.name": "email-outbound",
    "queue.message_id": "msg_abc123",
    "queue.estimated_delay_ms": 500
  }
}
```

---

### storage.persisted

**Description:** Data successfully written to durable storage with confirmation.

**When to Use:**
- Write operation succeeded with fsync/commit confirmation
- Storage system returned success status
- Data verifiable via immediate read-back (optional)

**Evidence Required:**
- Storage API response indicating success
- Data size and content hash
- Storage location or key

**NOT Applicable When:**
- Data written to cache but not persisted
- Write succeeded but fsync pending
- Storage quota exceeded (use `hard_fail`)

**Example Receipt:**
```json
{
  "outcome": {
    "status": "ok",
    "affordances": ["storage.persisted"]
  },
  "counters": {
    "bytes_tx": 4096
  },
  "metadata": {
    "storage.key": "blocks/bafyBlock123",
    "storage.content_hash": "blake3:abc123...",
    "storage.backend": "s3"
  }
}
```

---

## Analytics Schema Reference

This section defines reference schemas for storing and querying execution receipts. Implementations MAY use different backends (ClickHouse, DuckDB, Parquet) per deployment profile.

### Receipts Table

**Purpose:** One row per block execution, capturing all receipt fields.

**ClickHouse DDL:**
```sql
CREATE TABLE receipts (
  -- Core Identity
  block_id         String,
  host_did         String,
  executed_at      DateTime64(3, 'UTC'),

  -- Render Output
  render_hash      String,
  renders_match    UInt8,

  -- Resource Usage
  fuel_used        UInt64,
  memory_peak_mb   UInt32,

  -- Counters
  counters_fuel_total       UInt64,
  counters_bytes_tx         UInt64,
  counters_bytes_rx         UInt64,
  counters_syscalls         UInt64,

  -- Timings (milliseconds)
  timings_queue_wait_ms     UInt32,
  timings_init_ms           UInt32,
  timings_exec_ms           UInt32,
  timings_total_ms          UInt32,

  -- Limits
  limit_fuel_max            UInt64,
  limit_memory_max_mb       UInt32,
  limit_exec_timeout_ms     UInt32,

  -- Outcome
  outcome_status    LowCardinality(String),
  outcome_reason    LowCardinality(Nullable(String)),
  outcome_affordances Array(String),

  -- Capabilities
  capabilities_used Array(LowCardinality(String)),
  attestations      Array(String),

  -- Signature
  signature         Nullable(String),

  -- Metadata
  metadata          String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(executed_at)
ORDER BY (executed_at, block_id);
```

### Capability Counters Table

**Purpose:** Per-capability fuel attribution.

**ClickHouse DDL:**
```sql
CREATE TABLE receipt_capability_counters (
  block_id       String,
  executed_at    DateTime64(3, 'UTC'),
  capability     LowCardinality(String),
  fuel_used      UInt64,
  status_counts  Map(String, UInt64)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(executed_at)
ORDER BY (executed_at, block_id, capability);
```

### Common Queries

**Total fuel by capability (last 7 days):**
```sql
SELECT
  capability,
  SUM(fuel_used) AS total_fuel,
  COUNT(*) AS executions
FROM receipt_capability_counters
WHERE executed_at >= now() - INTERVAL 7 DAY
GROUP BY capability
ORDER BY total_fuel DESC
LIMIT 10;
```

**Outcome distribution:**
```sql
SELECT
  outcome_status,
  COUNT(*) AS count,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS pct
FROM receipts
WHERE executed_at >= now() - INTERVAL 24 HOUR
GROUP BY outcome_status;
```

**Affordance success rate:**
```sql
SELECT
  arrayJoin(outcome_affordances) AS affordance,
  COUNT(*) AS success_count,
  AVG(fuel_used) AS avg_fuel
FROM receipts
WHERE outcome_status = 'ok'
  AND executed_at >= now() - INTERVAL 30 DAY
GROUP BY affordance
ORDER BY success_count DESC;
```

---

## Test Vectors

This section provides canonical test vectors for validating implementations. All examples use deterministic values suitable for unit testing.

### Block Manifest Test Vectors

#### Minimal Valid Manifest

**TOML Source:**
```toml
schema = "https://jig.dev/schema/block-manifest/v0.1"
block_id = "cid:bafytest123minimal"
version = "1.0.0"

[[authors]]
did = "did:jig:alice"
roles = ["author"]

[constraints]
fuel_max = 1000000
memory_max_mb = 16
execution_timeout_ms = 100
deterministic = true
```

**Canonical JSON:**
```json
{
  "schema": "https://jig.dev/schema/block-manifest/v0.1",
  "block_id": "cid:bafytest123minimal",
  "version": "1.0.0",
  "authors": [
    {
      "did": "did:jig:alice",
      "roles": ["author"]
    }
  ],
  "constraints": {
    "fuel_max": 1000000,
    "memory_max_mb": 16,
    "execution_timeout_ms": 100,
    "deterministic": true
  }
}
```

**Validation:**
- ✅ Required fields present
- ✅ Semver version valid
- ✅ CID format correct
- ✅ Constraints within bounds

---

#### Manifest with Capabilities

**TOML Source:**
```toml
schema = "https://jig.dev/schema/block-manifest/v0.1"
block_id = "cid:bafytest456withcaps"
version = "1.0.0"

[[authors]]
did = "did:jig:bob"
public_key = "ed25519:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
roles = ["author", "maintainer"]

[[capabilities]]
name = "net.fetch"
scope = ["https://api.example.com/*"]
fuel = 500000

[[capabilities]]
name = "crypto.sign"

[constraints]
fuel_max = 5000000
memory_max_mb = 32
execution_timeout_ms = 250
deterministic = true

[render]
entry = "_start"
expected_hash = "sha256:d3abc123"
output_type = "application/json"
```

**Canonical JSON:**
```json
{
  "schema": "https://jig.dev/schema/block-manifest/v0.1",
  "block_id": "cid:bafytest456withcaps",
  "version": "1.0.0",
  "authors": [
    {
      "did": "did:jig:bob",
      "public_key": "ed25519:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "roles": ["author", "maintainer"]
    }
  ],
  "capabilities": [
    {
      "name": "net.fetch",
      "scope": ["https://api.example.com/*"],
      "fuel": 500000
    },
    {
      "name": "crypto.sign"
    }
  ],
  "constraints": {
    "fuel_max": 5000000,
    "memory_max_mb": 32,
    "execution_timeout_ms": 250,
    "deterministic": true
  },
  "render": {
    "entry": "_start",
    "expected_hash": "sha256:d3abc123",
    "output_type": "application/json"
  }
}
```

**Validation:**
- ✅ Multiple capabilities declared
- ✅ Scoped capability uses glob pattern
- ✅ Render output specified
- ✅ Public key format correct (Ed25519)

---

### Receipt Test Vectors

#### v0.1 Minimal Receipt

**Canonical JSON:**
```json
{
  "block_id": "cid:bafytest123minimal",
  "host": "did:jig:server:prod",
  "executed_at": "2025-11-09T12:00:00.000Z",
  "render_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "fuel_used": 123456,
  "capabilities_used": ["core:compute"]
}
```

**Validation:**
- ✅ v0.1 required fields present
- ✅ No v0.2 fields (backwards compat test)
- ✅ RFC 3339 timestamp
- ✅ SHA-256 render hash (empty string hash for determinism)

---

#### v0.2 Success Receipt

**Canonical JSON:**
```json
{
  "block_id": "cid:bafytest456withcaps",
  "host": "did:jig:server:prod",
  "executed_at": "2025-11-09T12:34:56.789Z",
  "render_hash": "sha256:d3abc123456789",
  "renders_match": true,
  "fuel_used": 421337,
  "memory_peak_mb": 8,
  "counters": {
    "fuel_total": 421337,
    "fuel_by_capability": {
      "net:http:fetch|https://api.example.com/*": 310000,
      "crypto:sign": 60000,
      "core:compute": 51337
    },
    "status_by_capability": {
      "net:http:fetch|https://api.example.com/*": {
        "OK": 1
      }
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
    "affordances": ["net.http_2xx"]
  },
  "capabilities_used": [
    "net:http:fetch|https://api.example.com/*",
    "crypto:sign",
    "core:compute"
  ],
  "attestations": [],
  "signature": "ed25519:0123456789abcdef",
  "metadata": {
    "timing.clock_source": "monotonic"
  }
}
```

**Validation:**
- ✅ All v0.2 fields present
- ✅ `counters.fuel_total == fuel_used` (421337)
- ✅ Sum of `fuel_by_capability` == `fuel_total`
- ✅ `timings_ms.total == init + exec` (190 == 3 + 187)
- ✅ Success status has affordances, no reason
- ✅ Capabilities in `status_by_capability` exist in `capabilities_used`

---

#### v0.2 Failure Receipt

**Canonical JSON:**
```json
{
  "block_id": "cid:bafyfailurefuel",
  "host": "did:jig:cli:local",
  "executed_at": "2025-11-09T13:00:00.000Z",
  "render_hash": "",
  "fuel_used": 1000000,
  "counters": {
    "fuel_total": 1000000,
    "fuel_by_capability": {
      "core:compute": 1000000
    },
    "bytes_tx": 0,
    "bytes_rx": 0,
    "syscalls": 0
  },
  "timings_ms": {
    "queue_wait": 1,
    "init": 2,
    "exec": 98,
    "total": 100
  },
  "limits": {
    "fuel_max": 1000000,
    "memory_max_mb": 16,
    "execution_timeout_ms": 100
  },
  "outcome": {
    "status": "hard_fail",
    "reason": "FUEL_EXHAUSTED"
  },
  "capabilities_used": ["core:compute"],
  "attestations": [],
  "signature": "ed25519:fedcba9876543210"
}
```

**Validation:**
- ✅ Failure status has `reason` field
- ✅ Failure status has NO `affordances` field
- ✅ Empty `render_hash` (execution didn't complete)
- ✅ `fuel_used == limits.fuel_max` (hit limit)
- ✅ All counters validation rules still hold

---

### Affordance Test Cases

#### Valid Affordances

```json
[
  "email.delivered",
  "bridge.forwarded",
  "net.http_2xx",
  "queue.enqueued",
  "storage.persisted",
  "custom:example.com:invoice_generated",
  "custom:stripe:payment_captured"
]
```

**Validation:**
- ✅ Canonical affordances use dot notation
- ✅ Custom affordances use `custom:namespace:action` format
- ✅ All lowercase with underscores for multi-word

#### Invalid Affordances

```json
[
  "Email.Delivered",          // ❌ Must be lowercase
  "custom:payment_captured",  // ❌ Missing namespace
  "custom::missing_ns",       // ❌ Empty namespace
  "NET.HTTP_5XX",            // ❌ Not a success signal
  "email delivered",         // ❌ No spaces allowed
  "email-delivered"          // ❌ Hyphens not allowed
]
```

---

### Canonicalization Rules

#### JSON Canonical Form

For signature verification, JSON MUST be canonicalized:

1. **Key Ordering**: Lexicographic (alphabetical) order
2. **Whitespace**: No spaces, no newlines
3. **Numbers**: No leading zeros, no trailing decimals
4. **Unicode**: UTF-8 encoding, escaped control characters
5. **Arrays**: Preserve order

**Example:**
```json
{"block_id":"cid:bafy123","executed_at":"2025-11-09T12:00:00.000Z","fuel_used":1000,"host":"did:jig:server:prod"}
```

#### CBOR Canonical Form

For CBOR (RFC 8949 Section 4.2):

1. **Shortest length encoding** for all types
2. **Sorted keys** in maps (bytewise lexicographic)
3. **Definite length** for strings and collections
4. **No duplicate keys** in maps

---

### Hash Algorithm Test Vectors

#### BLAKE3

**Input:** `"Hello, Jig Protocol!"`
**Output:** `blake3:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`

#### SHA-256

**Input:** `"Hello, Jig Protocol!"`
**Output:** `sha256:d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592`

**Note:** These are example values for testing hash formatting. Implementations MUST compute actual hashes using standard libraries.

## JEP Process

_(To be added)_
