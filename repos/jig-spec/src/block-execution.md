# Block Execution Model

**Audience:** This chapter is primarily for **developers** building executable blocks and **protocol implementers** running hosts that execute blocks. **End users** don't need to understand block internals—your client handles execution automatically. **Server operators** might care about resource limits, capability policies, and security sandboxing.

---

Executable blocks are where Jig gets interesting. Instead of just sending text messages, you can send **code** that runs on the server (or recipient's client) in a secure, metered sandbox. Think of it like embedding a Lambda function in a message—but deterministic, portable, and cryptographically verifiable.

## Why Executable Blocks?

Here's the problem with traditional messaging: you can send data, but you can't send **behavior**. If you want the server to fetch data from an API, format it, and deliver the result, you either hardcode that logic in the server (inflexible) or make the client do it (doesn't work for bots or automation).

Executable blocks solve this:

1. **Portable computation**: Write code once, run it anywhere (any Jig server, desktop client, CLI tool).
2. **Outcome-based pricing**: Hosts charge based on what the block *does* (CPU used, network calls made), not just message size.
3. **Deterministic verification**: Anyone can re-execute a block with the same inputs and verify the receipt matches (prevents billing fraud).
4. **Capability-based security**: Blocks start with zero permissions. Want network access? Declare it in the manifest. The host decides whether to grant it.

**Real-world example:** Alice sends a block that fetches weather data from an API and formats it as JSON. The server executes it, charges Alice based on CPU used (fuel) and the network request, and emits a signed receipt proving the API call succeeded. Bob can verify the receipt by replaying the block—if the receipt says it used 500k fuel but Bob's replay only uses 100k, something's fishy.

**Trade-off:** More complexity. You need a WebAssembly compiler, a sandboxed runtime, fuel metering, and signature verification. But the payoff is programmable messages—entire categories of bots, automation, and integrations become possible without server-side changes.

## Block Structure

A **Jig Block** is a content-addressed archive containing:

```
/manifest.json              # Metadata: capabilities, constraints, authors
/code.wasm                  # WebAssembly module (the executable)
/resources/<cid>            # Optional data files (images, configs, etc.)
/proofs/manifest.sig        # Ed25519 signature over manifest
/proofs/attestations/...    # Optional third-party signatures
```

**Content addressing:** Every file is hashed with BLAKE3, and the block's ID (CID) is the Merkle root of the entire tree. This makes blocks immutable—change one byte and you get a different CID.

**Why content addressing:**

- **Deduplication**: If 100 people send the same block, it only gets stored once.
- **Integrity**: You can verify the block wasn't tampered with by recomputing the CID.
- **Caching**: Hosts can cache blocks by CID and skip re-execution if they've seen it before.

**For developers:** Use a tool like `ipfs add` or similar to compute CIDs. The Jig SDK handles this for you.

## Manifest Schema

The manifest is the block's "contract"—it declares what the block needs (capabilities, resources, constraints) and what it promises to deliver (output type, expected hash).

### Minimal Example

```json
{
  "schema": "https://jig.dev/schema/block-manifest/v0.1",
  "block_id": "cid:bafyBlock123...",
  "version": "0.1.0",
  "authors": [
    {
      "did": "did:jig:alice",
      "public_key": "ed25519:v1:PkQx7TfHJ...",
      "roles": ["author"]
    }
  ],
  "constraints": {
    "max_fuel": 5000000,
    "max_memory_pages": 16,
    "max_execution_time_ms": 250
  }
}
```

This is a "hello world" block with no capabilities (can't access network, filesystem, crypto—just pure computation).

### Required Fields

**`schema`**: Manifest version (e.g., `https://jig.dev/schema/block-manifest/v0.1`). Hosts MUST reject unknown schema versions (fail closed).

**`block_id`**: Content identifier (CID) of the entire block. Hosts MUST recompute the CID and verify it matches—prevents manifest tampering.

**`version`**: Semantic version of the block (e.g., `1.2.3`). Useful for lineage tracking—if you publish block v1.0.0 and later v1.1.0, hosts can see they're related.

**`authors`**: Array of DIDs with roles (`author`, `maintainer`, `contributor`). Each author's signature goes in `/proofs/manifest.sig`. Multi-signature support means you can co-author blocks with bots or require 2-of-3 tribunal approval for high-risk blocks.

**For implementers:** Verify at least one author signature before executing. Invalid signatures → reject the block.

### Capabilities

The `capabilities` array declares which host APIs the block needs:

```json
"capabilities": [
  {
    "name": "net.fetch",
    "scope": ["https://api.weather.gov/*"],
    "fuel_budget": 1000000
  },
  {
    "name": "crypto.sign",
    "scope": []
  }
]
```

**Canonical capability types:**

The following capabilities are standardized across all Jig implementations:

#### 1. `net.fetch`

**Description:** Make HTTP/HTTPS requests to external APIs.

**Scope parameters:**
- `allow`: URL patterns (e.g., `["https://*.example.com/*", "https://api.github.com/repos/*"]`)
- `bandwidth_kb`: Maximum bandwidth quota in KB (prevents data exfiltration)

**Example:**
```json
{
  "name": "net.fetch",
  "scope": ["https://api.weather.gov/*"],
  "bandwidth_kb": 100
}
```

**Use cases:** Weather blocks, API integrations, webhook notifications.

**Security:** Hosts MUST validate every request URL against the allow patterns. Bandwidth limits prevent blocks from downloading gigabytes.

---

#### 2. `storage.read`

**Description:** Read from content-addressed storage.

**Scope parameters:**
- `mounts`: List of CIDs that can be read (e.g., `["cid:bafyImg123", "cid:bafyData456"]`)

**Example:**
```json
{
  "name": "storage.read",
  "scope": ["cid:bafyImg123", "cid:bafyConfig456"]
}
```

**Use cases:** Reading bundled assets (images, configs), accessing shared datasets.

**Security:** Read-only mounts prevent blocks from modifying storage. CID scoping prevents reading arbitrary files.

---

#### 3. `storage.write`

**Description:** Write to persistent storage.

**Scope parameters:**
- `quota_bytes`: Maximum write quota in bytes (prevents storage exhaustion)
- `allowed_prefixes`: Namespace prefixes for write paths (e.g., `["blocks/<author_did>/"]`)

**Example:**
```json
{
  "name": "storage.write",
  "quota_bytes": 1048576,
  "scope": ["blocks/did:jig:alice/"]
}
```

**Use cases:** Caching computation results, persisting user preferences.

**Security:** Quota limits prevent blocks from filling disk. Namespace scoping prevents overwriting other users' data.

---

#### 4. `message.emit`

**Description:** Send messages or emit events to channels.

**Scope parameters:**
- `channels`: List of channel identifiers (e.g., `["#general", "dm:did:jig:bob"]`)
- `rate_limit`: Maximum messages per minute

**Example:**
```json
{
  "name": "message.emit",
  "scope": ["#alerts", "dm:did:jig:alice"],
  "rate_limit": 10
}
```

**Use cases:** Notification blocks, alert systems, automated responses.

**Security:** Rate limiting prevents spam. Channel scoping prevents blocks from broadcasting to arbitrary channels.

---

#### 5. `crypto.sign`

**Description:** Sign data with the user's private key.

**Scope parameters:**
- `operations`: Which crypto operations are allowed (`["sign"]`, `["encrypt"]`, `["decrypt"]`)
- `key_refs`: Which keys can be used (e.g., `["user_primary"]`, `["ephemeral"]`)

**Example:**
```json
{
  "name": "crypto.sign",
  "operations": ["sign"],
  "key_refs": ["user_primary"]
}
```

**Use cases:** Signing attestations, creating verifiable credentials, authenticating API requests.

**Security:** User MUST explicitly consent before blocks can sign with their key (prevents unauthorized signatures).

---

#### 6. `crypto.verify`

**Description:** Verify cryptographic signatures.

**Scope parameters:** None (verification is safe—no secrets involved).

**Example:**
```json
{
  "name": "crypto.verify"
}
```

**Use cases:** Validating message signatures, checking block authenticity.

**Security:** No security concerns (read-only operation on public data).

---

#### 7. `timer`

**Description:** Schedule delayed or periodic execution.

**Scope parameters:**
- `min_interval_ms`: Minimum time between executions (prevents tight loops)
- `max_interval_ms`: Maximum scheduling horizon (prevents far-future spam)

**Example:**
```json
{
  "name": "timer",
  "min_interval_ms": 60000,
  "max_interval_ms": 86400000
}
```

**Use cases:** Cron-like scheduled tasks, periodic polling, reminder notifications.

**Security:** Interval limits prevent blocks from scheduling infinite timers or waking too frequently.

---

#### 8. `external_process` (opt-in, default denied)

**Description:** Spawn external processes (advanced, high-risk capability).

**Scope parameters:**
- `allowed_bins`: Whitelist of executable paths (e.g., `["/usr/bin/convert", "/usr/bin/ffmpeg"]`)

**Example:**
```json
{
  "name": "external_process",
  "scope": ["/usr/bin/imagemagick/convert"]
}
```

**Use cases:** Image processing, video transcoding, PDF generation.

**Security:** **EXTREMELY DANGEROUS.** Only grant to highly-trusted blocks (verified authors, enterprise-signed). Hosts SHOULD deny by default.

---

**For developers:** Request only the capabilities you actually need. Asking for `external_process` when you just need `net.fetch` makes users and hosts suspicious.

**For server operators:** Configure per-tier capability policies in `jig-config.toml`. Consider denying `external_process` entirely (or requiring enterprise attestations).

**Zero ambient authority:** Blocks start with **no capabilities**. If the manifest doesn't declare `net.fetch`, the block can't make network requests—period. Even if the WebAssembly code tries to call `fetch()`, the runtime denies it.

**Scoped capabilities:** Instead of granting blanket network access, you scope it to specific domains:

```json
{
  "name": "net.fetch",
  "scope": ["https://api.github.com/*", "https://api.example.com/v1/users/*"]
}
```

The host validates every network request against the scope. If the block tries to fetch `https://evil.com`, the request fails.

**Why this matters:** Prevents malicious blocks from exfiltrating data or attacking third-party services. Even if an attacker tricks you into running their block, it can't do anything the manifest didn't declare.

**For server operators:** Configure capability policies based on reputation:

- **`null_sec` users**: Deny all capabilities (pure computation only).
- **`low_sec` users**: Allow scoped `net.fetch` to approved domains.
- **`verified` users**: Allow broader capabilities (storage, crypto, etc.).

**Trade-off:** More restrictive than traditional server-side code (where everything runs with full permissions). But that's the point—untrusted code from random internet strangers should have *no* permissions by default.

### Constraints

Execution constraints limit resource usage:

```json
"constraints": {
  "max_fuel": 5000000,
  "max_memory_pages": 16,
  "max_execution_time_ms": 250
}
```

**`max_fuel`**: Maximum CPU instructions. Hosts meter every WebAssembly instruction and halt execution when fuel runs out. Think AWS Lambda's "compute seconds" but for WebAssembly.

**`max_memory_pages`**: Maximum memory in WebAssembly pages (1 page = 64KB). `max_memory_pages: 16` means 1MB max.

**`max_execution_time_ms`**: Wall-clock timeout. If the block doesn't finish in 250ms, the host kills it.

**Why fuel metering:** To prevent runaway loops. Without fuel limits, a block could do `while (true) {}` and hang the server. With fuel, it exhausts its budget and gets terminated.

**For developers:** Profile your block locally to estimate fuel usage. The Jig SDK provides a `jig-fuel` tool that reports fuel consumption. If your block uses 500k fuel in testing, request `max_fuel: 1000000` (2x headroom) in the manifest.

**For implementers:** Use a WebAssembly runtime with fuel metering (e.g., Wasmtime, wasmer). If the manifest says `max_fuel: 1000000` but your host policy only allows 500k for `null_sec` users, reject the block during validation (don't start execution and fail midway).

### Render Output

The `render` field declares expected output:

```json
"render": {
  "entry": "_start",
  "expected_hash": "sha256:d3abc...",
  "output_type": "application/json"
}
```

**`entry`**: WebAssembly export to call (default `_start`). If you have multiple entry points (e.g., `render_html`, `render_json`), specify which one.

**`expected_hash`**: Hash of expected deterministic output. Hosts can verify the actual output matches and include this in the receipt (prevents output tampering).

**`output_type`**: MIME type of render output (e.g., `application/json`, `text/html`, `image/png`).

**Why expected hash:** For reproducible builds. If the block's source code is public, anyone can recompile it and verify the output hash matches. This proves the WebAssembly module wasn't backdoored during compilation.

**For developers:** Use deterministic build tools (e.g., `cargo build --release` with fixed toolchain version) to ensure output hashes are stable.

## Execution Lifecycle

Block execution proceeds in three phases: **Validation** → **Execution** → **Receipt**.

### Phase 1: Validation

Before running any code, the host validates the block:

1. **Schema check**: Is `manifest.schema` a version we recognize? If not, reject.
2. **CID verification**: Recompute block CID from `manifest + code + resources` and verify it matches `manifest.block_id`. If mismatched, reject (block was tampered with).
3. **Signature verification**: Check `/proofs/manifest.sig` against author public keys. Invalid signature → reject.
4. **Capability policy check**: Does the block request capabilities the host allows? If a `null_sec` user requests `net.fetch`, reject.
5. **WebAssembly validation**: Parse `code.wasm` and check:
   - Imports limited to approved host functions (no sneaky syscalls)
   - No floats (if `deterministic: true`)
   - Memory limits within bounds

If any validation step fails, execution **MUST NOT** proceed. The host emits a `hard_fail` receipt with the reason (e.g., `INVALID_SIGNATURE`, `CAPABILITY_DENIED`).

**Why fail early:** Running invalid code wastes resources and opens security holes. Better to reject at validation than crash mid-execution.

### Phase 2: Execution

Validation passed—time to run the code:

1. **Instantiate WebAssembly module** in an isolated runtime (e.g., Wasmtime with seccomp sandbox).
2. **Configure fuel metering** based on `constraints.max_fuel`.
3. **Provide capability handles** (not raw host functions). Example: Instead of exposing `libc::fetch(url)`, expose a safe `jig_net_fetch(url)` that validates scope.
4. **Mount resources** as read-only content-addressed files (block can't modify them).
5. **Invoke entry function** (e.g., `_start()`).
6. **Capture output** (stdout, return value) and measure fuel consumption.

Execution may terminate early if:

- **Fuel exhausted**: Block ran out of CPU budget → `soft_fail` receipt (user pays partial cost).
- **Memory limit exceeded**: Block tried to allocate more memory than allowed → `hard_fail`.
- **Timeout reached**: Execution took longer than `max_execution_time_ms` → `soft_fail`.
- **Capability denied**: Block tried to use a capability it didn't declare → `hard_fail`.

**For implementers:** Use defense-in-depth:

- **Process isolation** (seccomp on Linux, pledge on OpenBSD, AppContainer on Windows)
- **Filesystem isolation** (mount only declared resources, not the entire filesystem)
- **Network isolation** (firewall rules per capability scope)

Even if the WebAssembly runtime has a vulnerability, these layers prevent escape.

### Phase 3: Receipt

After execution (success or failure), the host emits a **receipt**—a signed attestation of what happened:

```json
{
  "version": "0.2.0",
  "block_id": "cid:bafyBlock123...",
  "host": "did:jig:server:prod",
  "executed_at": "2025-11-09T12:34:56Z",
  "outcome": {
    "status": "ok",
    "affordances": ["net.http_2xx"]
  },
  "counters": {
    "fuel_total": 873422,
    "fuel_by_capability": {
      "net.fetch": 800000,
      "core.compute": 73422
    }
  },
  "timings": {
    "init_ms": 5,
    "exec_ms": 45,
    "total_ms": 50
  },
  "limits": {
    "max_fuel": 5000000,
    "max_memory_bytes": 1048576
  },
  "signature": {
    "key": "ed25519:v1:hostKey...",
    "signature": "ed25519:v1:sigBytes..."
  }
}
```

**What receipts enable:**

1. **Outcome-based pricing**: Charge different rates for `ok` (full price), `soft_fail` (partial refund), `hard_fail` (no charge).
2. **Per-capability billing**: Network calls cost more than pure CPU. Receipt breaks down fuel by capability.
3. **Deterministic replay**: Anyone can re-execute the block and verify the receipt matches (fraud detection).
4. **Audit trails**: Federation peers exchange receipts to prove work was done.

See [Receipts](receipts.md) for the full v0.2 schema.

**For end users:** Receipts are like itemized bills. If a server charges you $0.10 for a block but the receipt shows it only used $0.01 worth of fuel, you can dispute it (or downgrade that server's reputation).

## Determinism Requirements

Jig blocks are **deterministic by default**: same inputs → same outputs, every time.

**Why determinism matters:**

- **Verifiable execution**: Anyone can replay a block and get the same result (prevents fraud).
- **Reproducible billing**: Fuel consumption is deterministic (no "this block cost 500k fuel on Monday but 1M fuel on Tuesday").
- **Cacheable results**: If the block and inputs haven't changed, the output hasn't either (hosts can cache aggressively).

### Forbidden Operations

When `constraints.deterministic = true` (the default), hosts MUST reject WebAssembly modules containing:

**Floating-point instructions**: `f32`, `f64` ops are non-deterministic (different CPUs, rounding modes, NaN handling). If you need math, use fixed-point integers.

**Non-deterministic syscalls:**

- `wasi_snapshot_preview1::random_get` (randomness is non-deterministic)
- `wasi_snapshot_preview1::clock_time_get` (wall-clock time varies)
- `wasi_snapshot_preview1::sock_*` (network sockets have non-deterministic latency)

**Threading**: Shared memory, atomic wait/notify, etc. (race conditions are non-deterministic).

**Exception:** Blocks MAY use time, randomness, or network data if provided via **capability handles**:

- **Time**: Passed as an explicit argument (e.g., `render(timestamp: u64)`), not an ambient syscall.
- **Randomness**: Derived from `BLAKE3(manifest.block_id || host_seed)` (deterministic for replay).
- **Network**: Responses cached and replayed for deterministic re-execution.

**For developers:** Compile with `--target wasm32-wasi` and avoid `std::time::SystemTime::now()`. Use the Jig SDK's `jig::time()` instead, which gets time from the host as an argument.

### Canonical Serialization

Render output MUST use canonical serialization:

**JSON**: Keys sorted lexicographically, no whitespace, deterministic number formatting.

**CBOR**: Deterministic CBOR (RFC 8949 § 4.2).

**Why:** So everyone agrees on the output hash. If Alice's block outputs `{"a":1,"b":2}` and Bob's replay outputs `{"b":2,"a":1}` (different key order), the hashes won't match.

**For implementers:** Use a canonicalization library (e.g., `jcs` for JSON Canonicalization Scheme, `minicbor` with deterministic encoding for CBOR).

## Security Considerations

### Capability-Based Security

**Zero ambient authority**: Blocks start with no capabilities. The manifest explicitly declares what's needed.

**Explicit grants only**: The host reviews capability requests and grants them based on policy (reputation, quotas, etc.).

**Least privilege**: Grant minimum scope. If a block only needs to fetch from `https://api.example.com/v1/users/*`, don't grant `https://*`.

**For server operators:** Review capability requests before granting. If a "hello world" block requests network access, that's suspicious.

### Sandboxing

Hosts SHOULD use defense-in-depth:

**Process isolation**: Run each block in a separate process with seccomp (Linux), pledge (OpenBSD), or AppContainer (Windows). If the block exploits a Wasm runtime bug, it's still contained.

**Filesystem isolation**: Mount only `/resources/<cid>` (read-only). Block can't read `/etc/passwd` or write to `/tmp`.

**Network isolation**: Firewall rules per capability scope. If the block's scope is `https://api.example.com/*`, block all other outbound connections.

**For implementers:** Use tools like systemd's `DynamicUser=true`, firejail, or Docker's `--security-opt` to layer isolation.

### Supply Chain Security

**Signed manifests**: Every manifest MUST be signed by at least one author. Hosts verify signatures before execution.

**Transparency logs**: Blocks SHOULD be published to transparency logs (e.g., Sigstore/Rekor) so anyone can audit what's been executed.

**Multi-signature support**: High-risk blocks can require 2-of-3 tribunal signatures (e.g., a bot + 2 humans).

**Reproducible builds**: If the block's source code is public, anyone can recompile and verify the `code.wasm` hash matches.

**For developers:** Publish block source code alongside manifests. Use reproducible build tools (e.g., Nix, Bazel).

## Compatibility

### WebAssembly Target

**Current**: Wasmtime with WASI preview1.

**Future**: Component Model (when stable).

Hosts MUST support:

- WebAssembly MVP spec
- Fuel metering
- Memory limits
- Imports restricted to declared capabilities

**For implementers:** Use Wasmtime (Rust), wasmer (multi-language), or a similar runtime. Avoid browsers' WebAssembly APIs—they lack fuel metering.

### Language Support

Blocks MAY be authored in any language compiling to WebAssembly:

**Rust** (primary, best support): `cargo build --target wasm32-wasi`

**AssemblyScript** (TypeScript-like): Great for web developers.

**C/C++** (with wasi-sdk): For low-level code.

**Go** (with TinyGo): Standard `go` compiler produces large binaries; use TinyGo.

**For developers:** Use the Jig SDK for your language (provides capability bindings and manifest builders).

## Example: Weather Fetcher Block

Let's walk through a real block that fetches weather data from an API.

### Manifest

```json
{
  "schema": "https://jig.dev/schema/block-manifest/v0.2",
  "block_id": "cid:bafyWeather123...",
  "version": "1.0.0",
  "authors": [
    {
      "did": "did:jig:alice",
      "public_key": "ed25519:v1:PkQx...",
      "roles": ["author"]
    }
  ],
  "capabilities": [
    {
      "name": "net.fetch",
      "scope": ["https://api.weather.gov/*"]
    }
  ],
  "constraints": {
    "max_fuel": 2000000,
    "max_memory_pages": 16,
    "max_execution_time_ms": 500
  },
  "render": {
    "entry": "_start",
    "output_type": "application/json"
  }
}
```

### Rust Code

```rust
use jig_sdk::capabilities::net;
use serde_json::json;

#[no_mangle]
pub extern "C" fn _start() {
    // Fetch weather data from API
    let response = net::fetch("https://api.weather.gov/gridpoints/TOP/31,80/forecast")
        .expect("Failed to fetch weather");

    // Parse JSON response
    let data: serde_json::Value = serde_json::from_str(&response.body)
        .expect("Failed to parse JSON");

    // Extract temperature from first period
    let temp = data["properties"]["periods"][0]["temperature"]
        .as_i64()
        .expect("Missing temperature");

    // Format output
    let output = json!({
        "temperature": temp,
        "unit": "F",
        "location": "San Francisco"
    });

    // Print to stdout (captured as render output)
    println!("{}", serde_json::to_string(&output).unwrap());
}
```

### Execution Flow

1. **Validation**: Host verifies `did:jig:alice` signed the manifest, checks `net.fetch` against policy (approved for `low_sec` users), validates WebAssembly module.

2. **Execution**: Host instantiates the Wasm module, grants scoped `net.fetch` capability, calls `_start()`. Block fetches weather data, parses JSON, prints output. Total fuel used: 873k (800k for network, 73k for compute).

3. **Receipt**: Host emits:

```json
{
  "version": "0.2.0",
  "block_id": "cid:bafyWeather123...",
  "host": "did:jig:server:prod",
  "executed_at": "2025-11-09T12:34:56Z",
  "outcome": {
    "status": "ok",
    "affordances": ["net.http_2xx"]
  },
  "counters": {
    "fuel_total": 873422,
    "fuel_by_capability": {
      "net.fetch": 800000,
      "core.compute": 73422
    },
    "bytes_rx": 2048,
    "bytes_tx": 128
  },
  "timings": {
    "init_ms": 5,
    "exec_ms": 120,
    "total_ms": 125
  },
  "limits": {
    "max_fuel": 2000000,
    "max_memory_bytes": 1048576
  },
  "render": {
    "output_hash": "blake3:9fa8...",
    "output_size_bytes": 87
  },
  "signature": {
    "key": "ed25519:v1:serverKey...",
    "signature": "ed25519:v1:sigBytes..."
  }
}
```

**Outcome-based pricing:**

- **Base cost**: 873,422 fuel × $0.000001/fuel = $0.87
- **Network surcharge**: 1 HTTP request × $0.01/request = $0.01
- **Total**: $0.88

If the block had failed (network timeout), it would be a `soft_fail` with 50% refund (user pays $0.44 for the attempt).

**Verification**: Alice can replay the block locally, fetch the same weather data (cached from the original request), and verify her replay also uses 873k fuel. If the server's receipt claimed 5M fuel, Alice knows they're overcharging.

## Normative Requirements Summary

**MUST:**

- Verify `manifest.block_id` matches computed CID before execution.
- Verify at least one author signature on the manifest.
- Reject blocks requesting capabilities beyond host policy (fail closed).
- Meter fuel consumption and halt execution when `max_fuel` is exceeded.
- Enforce memory limits (`max_memory_pages`) and timeouts (`max_execution_time_ms`).
- Emit signed receipts after execution (success or failure).
- Reject modules with floats, non-deterministic syscalls, or threading (when `deterministic: true`).
- Use canonical serialization (JSON or CBOR) for render output.

**SHOULD:**

- Use process isolation (seccomp, pledge, AppContainer) for sandboxing.
- Mount only declared resources (read-only) in the block's filesystem view.
- Apply network firewall rules based on capability scope.
- Publish blocks to transparency logs (e.g., Sigstore/Rekor).
- Support reproducible builds (deterministic compilation).

**MAY:**

- Cache block executions by `(block_id, inputs)` for performance.
- Implement reputation-based capability policies (stricter for `null_sec`, looser for `verified`).
- Support multiple WebAssembly entry points (e.g., `render_html`, `render_json`).
- Add third-party attestations to `/proofs/attestations/` for supply chain auditing.

---

**Next:** With blocks defined, let's look at [Receipts](receipts.md) to see the full v0.2 receipt schema with fuel metering, outcome-based pricing, and affordances. Or jump to [Transports](transports.md) to see how blocks are transmitted over IRC, WebSocket, and SSH.
