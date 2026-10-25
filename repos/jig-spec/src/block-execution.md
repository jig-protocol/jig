# Block Execution Model

**Audience:** This chapter is primarily for **developers** building executable blocks and **protocol implementers** running hosts that execute blocks. **End users** don't need to understand block internals—your client handles execution automatically. **Server operators** might care about resource limits, capability policies, and security sandboxing.

> **Partly implemented.** Blocks are components of the `jig:block` package
> ([JEP-0006](../jep/jep-0006-block-abi.md)), checked against the determinism profile
> `jig-det-1` and executed under fuel, stack, memory and deadline limits. The reference server
> executes the `text-render` block's `renderer` component on ingest and signs a v0.3 receipt;
> the reference client re-executes it to check that receipt. Third-party programs run only if
> the server's operator policy allows them ([JEP-0011](../jep/jep-0011-block-programs.md) §5.1).
> Host imports and capabilities (JEP-0007), resource mounts and outcome-based billing are not
> implemented. The capability sections below describe that later design.

---

Executable blocks are where Jig gets interesting. Instead of just sending text messages, you can send **code** that runs on the server (or recipient's client) in a secure, metered sandbox. Think of it like embedding a Lambda function in a message—but deterministic, portable, and cryptographically verifiable.

## Why Executable Blocks?

Here's the problem with traditional messaging: you can send data, but you can't send **behavior**. If you want the server to fetch data from an API, format it, and deliver the result, you either hardcode that logic in the server (inflexible) or make the client do it (doesn't work for bots or automation).

Executable blocks solve this:

1. **Portable computation**: Write code once, run it anywhere (any Jig server, desktop client, CLI tool).
2. **Outcome-based pricing**: Hosts charge based on what the block *does* (CPU used, network calls made), not just message size.
3. **Deterministic verification**: Anyone can re-execute a block with the same invocation and check that the outcome matches the receipt.
4. **Capability-based security**: Blocks start with zero permissions. Want network access? Declare it in the manifest. The host decides whether to grant it.

**Real-world example:** Alice sends a chat message. Her server renders it with the `text-render` block and signs a receipt naming the component, the invocation and the outcome hash. Bob's client runs the same component on the same invocation and gets the same outcome hash, or shows him that the server's render differs.

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
[JEP-0006](../jep/jep-0006-block-abi.md) is normative for all three.

### Phase 1: Validation

Before running any code, the host checks:

1. **The program.** Its manifest is signed by its author, and the host's operator policy allows
   it ([JEP-0011](../jep/jep-0011-block-programs.md) §5.1). A server's default policy allows
   only the renderer components it ships.
2. **The component, against `jig-det-1`:**
   - it validates with exactly the WebAssembly 2.0 features minus SIMD, plus the component
     model without async, threads or error context;
   - no core module, at any depth, contains a scalar float instruction;
   - every memory and table declares a maximum within the manifest's limits;
   - it imports only what its world allows (no `wasi:*`) and exports exactly its world's
     interface.

A host MUST refuse a component that fails any check, before compiling it.

### Phase 2: Execution

1. **Build the invocation.** Every input is data in one `invocation` record: the triggering
   block's CID, its sender, the channel's CID, and the `ingest-seq` and `ingest-hlc` from the
   block's signed `ingest` record. A block has no clock, no randomness and no environment.
2. **Call the world's export:** `render(invocation)` for a `renderer`,
   `handle(invocation, state)` for a `bot`.
3. **Enforce limits:** fuel (deterministic), and a wall-clock deadline as a liveness guard;
   plus the stack limit and memory maxima.
4. **Classify the outcome:**
   - `ok`: the export returned a value;
   - `error`: the guest returned a `block-error`, or a WebAssembly core trap occurred;
   - `incomplete`: fuel or stack ran out, the deadline passed, or the host failed.

`ok` and `error` carry a hash over the canonical encoding of what was returned, and are
comparable across executors. `incomplete` asserts nothing about the block.

A `bot` never performs an effect during a call: it returns effects, which the host checks against
the install's grants before applying them.

**For implementers:** the sandbox is one layer (threat SC-03). Run hosts with OS isolation as
well; see [Security Considerations](#security-considerations).

### Phase 3: Receipt

The host signs a v0.3 receipt ([Receipts](receipts.md)): `exec` with the component, program,
world, invocation hash, outcome, limits and engine; or `accepted` if it stored the block without
executing it. A server never executes encrypted content: for that it signs `sealed`.

Anyone with the component and the block can re-execute it and compare outcomes. Fuel is
recorded for diagnosis and never compared.

## Determinism Requirements

Two conforming executors that both reach `ok` or `error` for the same run MUST reach the same
outcome and hash, on any architecture, operating system, engine or engine version. That is what
lets a client check a server, and one server check another.

**Why determinism matters:**

- **Verifiable execution**: Anyone can re-execute a block and get the same outcome.
- **Federation**: Servers that render the same message agree on its outcome hash.
- **Cacheable results**: If the component and invocation haven't changed, neither has the outcome.

### The profile: `jig-det-1`

The rules are [JEP-0006's](../jep/jep-0006-block-abi.md#determinism-profile-jig-det-1): the
feature set, no floats, declared memory maxima, no `wasi:*` imports, and exact exports. Hosts
MUST configure their engine to the same feature set, and MUST enforce the profile as an
allowlist, not as a list of forbidden instructions: a list misses every proposal its author did
not know about.

What the profile excludes, and why:

- **Floats** (`f32`, `f64`, and SIMD's float lanes): NaN payloads and rounding differ across
  engines. Use fixed-point integers.
- **WASI**: host answers to clocks, randomness and filesystem calls differ by OS.
- **Threads and shared memory**: scheduling is not deterministic.

**Time, sender and context** arrive in the invocation. A block never reads a clock.

**For developers:** Build with `jig block build`, which compiles for `wasm32-unknown-unknown`
(no WASI) and checks the result against `jig-det-1`.

### Canonical Encoding

Outcome and invocation hashes are taken over the canonical encoding of a WIT value: deterministic
CBOR (RFC 8949 §4.2.1) under JEP-0006's type mapping. The host computes them from the lifted
value, so they never depend on how a guest language serialises its output.

## Security Considerations

### Capability-Based Security

**Zero ambient authority**: Blocks start with no capabilities. A `renderer` imports nothing but
types, and at most child renderers its manifest pins. A `bot` imports only the host interfaces
its install grants (JEP-0007).

**Explicit grants only**: The host checks a bot's returned effects against its grants before
applying them.

**Least privilege**: Grant minimum scope.

### Sandboxing

Hosts SHOULD use defense-in-depth:

**Process isolation**: seccomp (Linux), pledge (OpenBSD) or AppContainer (Windows) around the
runtime. If a component exploits a Wasm runtime bug, it is still contained.

**Resource limits**: fuel, stack, memory and a deadline on every run.

**For implementers:** Use tools like systemd's `DynamicUser=true` to layer isolation.

### Supply Chain Security

**Signed manifests**: A program manifest is signed by its author ([JEP-0011](../jep/jep-0011-block-programs.md)).

**Operator policy**: A server executes only what its operator policy allows, and publishes that
policy signed, so clients see exactly what it will run.

**Reproducible builds are not assumed**: Wasm output differs across build hosts. Equivalence is
checked by behaviour (the conformance vectors), not by bytes.

## Compatibility

### WebAssembly Target

Blocks are components of the `jig:block` package, at version `0.1.0` during v0.3 development.
The WIT is [`wit/jig-block/block.wit`](../wit/jig-block/block.wit). Hosts MUST support:

- the component model under `jig-det-1`;
- fuel metering, stack limits and memory maxima;
- the `renderer` world, and the `bot` world once JEP-0007 is implemented.

The reference host is wasmtime, on native Cranelift and on Pulley. The conformance vectors run
on both, on x86_64 and aarch64.

### Language Support

Blocks MAY be authored in any language that compiles to a component without floats or WASI
imports:

**Rust** (the only language with a template in v0.3): `jig block new <name>`, then `jig block build`.

**For developers:** `wit-bindgen` generates the bindings for the `jig:block` worlds.

## Example: the `text-render` block

The reference server's built-in renderer. Its source is `repos/text-block`.

### The export

```rust
impl Guest for TextBlock {
    fn render(inv: Invocation) -> Result<Payload, BlockError> {
        let body_raw = String::from_utf8(inv.input.body)
            .map_err(|_| BlockError::InvalidInput("message body is not UTF-8".into()))?;
        let input = Input {
            sender_did: inv.sender_did,
            channel_id: inv.channel_cid,
            body_raw,
            hlc_wall_ms: inv.ingest_hlc.wall_ms,
            hlc_logical: inv.ingest_hlc.logical,
            hlc_origin: String::new(),
            client_version: String::new(),
        };
        let body = postcard::to_allocvec(&execute_pure(&input))
            .map_err(|_| BlockError::Failed("output did not encode".into()))?;
        Ok(Payload {
            media_type: COMPONENT_OUTPUT_MEDIA_TYPE.into(),
            body,
        })
    }
}
```

The body arrives as bytes. A body that is not UTF-8 is a guest `invalid-input` error: a
comparable outcome, so every executor agrees on it.

### Execution flow

1. **Validation**: The server's default operator policy lists this component's hash, and the
   component passes `jig-det-1`.
2. **Execution**: After the message lands, the server builds the invocation from its `ingest`
   record and calls `render`. The outcome is `ok`, with a hash over the returned
   `result<payload, block-error>`.
3. **Receipt**: The server signs `exec`, naming the component, its own program CID for it, the
   invocation hash and the outcome.
4. **Verification**: A client with the same component rebuilds the invocation from the block and
   its `ingest` record, runs `render`, and compares the outcome hash. A second server does the
   same under its own policy and program CID, and agrees.

## Normative Requirements Summary

**MUST:**

- Refuse a program its operator policy does not allow.
- Refuse a component that fails `jig-det-1`, before compiling it.
- Configure the engine to `jig-det-1`'s feature set.
- Pass every input in the invocation; provide no clock, randomness or WASI.
- Meter fuel and halt at the limit; enforce stack and memory limits.
- Never execute encrypted content on a server.
- Sign a v0.3 receipt for every block a server stores ([Receipts](receipts.md)).
- Treat `incomplete` as not comparable.

**SHOULD:**

- Use process isolation (seccomp, pledge, AppContainer) around the runtime.
- Use a wall-clock deadline as a liveness guard.

**MAY:**

- Cache outcomes by component and invocation hash.

---

**Next:** See [Receipts](receipts.md) for the v0.3 receipt and how a client checks it. Or jump
to [Transports](transports.md) to see how blocks are transmitted over IRC, WebSocket, and SSH.
