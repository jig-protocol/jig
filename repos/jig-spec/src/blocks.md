# Blocks

**Audience:** This chapter is for **protocol implementers** and **developers building executable blocks**. **Server operators** might care about storage requirements and validation policies. **End users** don't need to understand block internals—just know that blocks are like apps: self-contained, signed, and executable.

---

Blocks are the fundamental unit of computation in Jig. Think of them as tiny, self-contained apps that can run anywhere: on your server, in your client, or forwarded across federation. Unlike traditional messages (just text), blocks carry code, data, and proofs in a single package.

**Real-world analogy:** A block is like a shipping container. You know what's inside (the manifest lists it), it's sealed (cryptographically signed), and it can be transported anywhere (content-addressed so you can verify it wasn't tampered with).

## Why Blocks?

Here's the problem with traditional messaging: Alice sends Bob a message saying "Check if it's raining in Tokyo." Bob's client can't do anything with that—it's just text. Bob has to manually open a browser, search for Tokyo weather, and reply.

**With blocks:**

1. Alice sends a block containing code that fetches Tokyo weather.
2. Bob's client (or Bob's server) executes the block automatically.
3. The output ("It's sunny, 72°F") appears in the conversation.
4. The execution is metered (fuel tracking) so Bob knows it didn't waste resources.
5. A receipt proves what happened (for billing, auditing, or debugging).

**Trade-offs:**

- **More complex:** You need a runtime (Wasm VM) to execute blocks. Plain-text messages are simpler.
- **More powerful:** Blocks enable automation, integrations, and programmable workflows that aren't possible with static text.
- **Safer:** Capability-based security means blocks can't do anything you don't explicitly allow (no file access, no network access unless granted).

**For end users:** You can send blocks like "Summarize this PDF" or "Schedule a meeting with Alice next Tuesday" and the block figures out the details.

**For developers:** You write blocks in Rust, TypeScript, or any language that compiles to Wasm. Blocks are portable—write once, run anywhere (server, client, CLI).

**For server operators:** Blocks have resource limits (fuel, memory, time) so rogue blocks can't DoS your server. Failed executions produce receipts so you can debug what went wrong.

## Block Anatomy

Blocks are packaged as **CAR-like archives** (Content-Addressed aRchives). Each block contains:

```
/manifest.json              # What the block does, who wrote it, what it needs
/code.wasm                  # The executable (WebAssembly module)
/data/...                   # Optional: images, files, datasets (chunked, content-addressed)
/proofs/manifest.sig        # Author's signature (Ed25519)
/proofs/transparency.log    # Inclusion proof for key transparency
/proofs/attestations/...    # Optional: third-party signatures, ZK proofs
```

**Why this structure:**

- **`manifest.json`**: Tells the runtime what capabilities the block needs, who wrote it, and what outputs to expect.
- **`code.wasm`**: The actual program, compiled to WebAssembly for safety and portability.
- **`/data/`**: Supporting files (e.g., a weather icon for the forecast block). Content-addressed so they can be deduplicated across blocks.
- **`/proofs/`**: Cryptographic proofs so you can verify the block hasn't been tampered with and was actually signed by the claimed author.

**For developers:** You don't manually create these files. Use the Jig SDK (`jig-sdk`) which bundles your code, generates the manifest, and signs everything automatically.

### Content Addressing

Every file in a block is hashed with BLAKE3. The **block CID** (Content IDentifier) is the Merkle root of all these hashes:

```
Block CID = BLAKE3_merkle_root(
  hash(manifest.json),
  hash(code.wasm),
  hash(data/*),
  hash(proofs/*)
)
```

**Why content addressing:**

- **Deduplication**: If two blocks use the same weather icon, it's stored once and referenced by CID.
- **Tamper-proof**: Change one byte → CID changes → everyone knows it's been modified.
- **Federation-friendly**: Servers can verify blocks without trusting the sender (just re-compute the CID and check it matches).

**For implementers:** The manifest includes a `block_id` field with the expected CID. Hosts MUST verify the CID matches before executing. If it doesn't match, reject the block (fail closed).

**Example:**

```json
{
  "block_id": "cid:bafyBlock123...",
  "manifest": { /* ... */ }
}
```

If you compute the Merkle root and get `cid:bafyDifferent456...`, the block is invalid (either corrupted in transit or maliciously modified).

## Manifest Schema

The manifest is a JSON file describing the block. Here's what's in it:

### Basic Identity

```json
{
  "schema": "https://jig.dev/schema/block-manifest/v0.1",
  "block_id": "cid:bafyBlock123...",
  "version": "0.1.0",
  "authors": [
    {
      "did": "did:jig:alice",
      "public_key": "ed25519:9f...",
      "roles": ["author", "maintainer"]
    }
  ],
  "parents": ["cid:bafyParent..."]
}
```

**Fields:**

- **`schema`**: Which manifest version this is (for forwards/backwards compatibility).
- **`block_id`**: The expected CID (so you can verify integrity).
- **`version`**: Semantic versioning for the block itself (e.g., weather block v1.2.3).
- **`authors`**: Who wrote it (DIDs + public keys for verification).
- **`parents`**: Lineage. If this block is a reply or edit of another block, list the parent CIDs here (enables threading).

### Capabilities

```json
{
  "capabilities": [
    {
      "name": "net.fetch",
      "scope": ["https://api.weather.gov/*"],
      "fuel": 1000000,
      "attestations": ["did:jig:validator:trusted"]
    }
  ]
}
```

**What this means:** "This block wants to make HTTP requests to `api.weather.gov`. It'll use up to 1M fuel units. A trusted validator (`did:jig:validator:trusted`) has attested that this is safe."

**For server operators:** You decide whether to grant these capabilities. If a block requests `net.fetch` for `https://evil.com/*`, you can deny it (or only allow it for low-reputation users with extra scrutiny).

**For developers:** List only the capabilities you actually need. Asking for too many capabilities makes users and servers suspicious (why does a weather block need `storage.write`?).

### Constraints

```json
{
  "constraints": {
    "fuel_max": 5000000,
    "memory_max_mb": 32,
    "execution_timeout_ms": 250,
    "deterministic": true
  }
}
```

**What this means:**

- **`fuel_max`**: Maximum CPU budget. If execution exceeds this, it's killed (prevents infinite loops).
- **`memory_max_mb`**: Maximum RAM. Prevents blocks from allocating gigabytes and crashing the host.
- **`execution_timeout_ms`**: Wall-clock limit. Even if fuel remains, execution stops after 250ms (prevents blocks from sleeping forever).
- **`deterministic`**: If true, re-running the block with the same inputs MUST produce identical outputs (required for receipt verification).

**For implementers:** Enforce these limits strictly. If a block exceeds fuel, emit a receipt with `outcome.status = "hard_fail"` and `reason = "FUEL_EXHAUSTED"`.

### Resources

```json
{
  "resources": [
    {
      "name": "icon.png",
      "cid": "bafyImg...",
      "mime": "image/png"
    }
  ]
}
```

**What this means:** The block includes an image (`icon.png`) stored at CID `bafyImg...`. The runtime mounts this as a read-only file so the block can read it (but not modify it).

**For developers:** Use this for bundling assets (images, JSON configs, datasets). Don't hardcode paths—use the resource name (`icon.png`) and the runtime will mount it for you.

### Render Expectations

```json
{
  "render": {
    "entry": "render::main",
    "expected_hash": "sha256:d3...",
    "output_type": "application/jig-markup"
  }
}
```

**What this means:** After execution, call the `render::main` function. Its output should hash to `sha256:d3...` (deterministic rendering). The output format is `application/jig-markup` (Jig's rich text format).

**Why this matters:** Receipts include `render_hash` and compare it to `expected_hash`. If they mismatch, something went wrong (non-determinism, corrupted data, malicious code).

### Provenance

```json
{
  "provenance": {
    "created_at": "2025-11-09T16:30:00Z",
    "useful_work_refs": ["cid:bafyScore..."],
    "reputation_tier": "low-sec"
  }
}
```

**What this means:**

- **`created_at`**: When the block was created (UTC timestamp).
- **`useful_work_refs`**: References to useful work assignments this block completed (for reputation scoring).
- **`reputation_tier`**: The author's reputation when the block was created (`null-sec`, `low-sec`, `high-sec`, `verified`).

**For server operators:** You might trust `high-sec` blocks more than `null-sec` blocks. Use this field to adjust rate limits or scrutiny.

### Attestations

```json
{
  "attestations": [
    {
      "issuer": "did:jig:newsroom1",
      "claim": "fact_checked:v1",
      "signature": "ed25519:..."
    }
  ]
}
```

**What this means:** A third party (`did:jig:newsroom1`) has signed a claim (`fact_checked:v1`) about this block. Think of it like a blue checkmark—someone you trust vouches for this block.

**For end users:** If you only want to run blocks that have been fact-checked or audited, filter by attestations.

### Privacy

```json
{
  "privacy": {
    "encryption": "none",
    "recipients": ["did:jig:alice", "did:jig:bob"],
    "metadata_visibility": "public"
  }
}
```

**What this means:** `encryption` names the block's [encryption suite](encryption.md#registry). It MUST be a registered suite this implementation implements; anything else is refused. v0.1 implements only `none`. MLS (`mls`) is reserved for v0.2. Metadata (who sent it, when, how much fuel it used) is visible to the server under every suite.

## Execution Lifecycle

When a host receives a block, it goes through three phases:

### Phase 1: Validation

**What happens:**

1. **Schema check**: Is `manifest.json` valid? Does it have all required fields?
2. **CID verification**: Re-compute the Merkle root. Does it match `block_id`?
3. **Signature verification**: Check `proofs/manifest.sig`. Was this actually signed by the claimed author?
4. **Transparency check**: Verify inclusion proof in key transparency log (prevents key substitution attacks).
5. **Capability check**: Does the host allow the requested capabilities? If the block wants `net.fetch` for `https://evil.com/*`, reject it.
6. **Wasm validation**: Is `code.wasm` a valid WebAssembly module? Does it only import approved host functions?

**If any check fails:** Reject the block. Don't execute it. Log the failure for debugging.

**For server operators:** Configure your validation policy in `jig-config.toml`. You can allowlist/denylist specific capability scopes, authors, or reputation tiers.

### Phase 2: Execution

**What happens:**

1. **Instantiate Wasm module**: Load `code.wasm` into the runtime (Wasmtime with fuel metering enabled).
2. **Provide capabilities**: Grant the requested capabilities as opaque handles (the block can't forge them).
3. **Mount resources**: Make `data/*` files available as read-only mounts.
4. **Run `_start()` or specified entry point**: The block's main function executes.
5. **Capture outputs**: Collect stdout/stderr and the render output.
6. **Track fuel usage**: Count how many instructions were executed, broken down by capability.

**If execution fails:**

- **Out of fuel**: Emit a receipt with `outcome.status = "hard_fail"` and `reason = "FUEL_EXHAUSTED"`.
- **Timeout**: Emit `reason = "RUNTIME_TIMEOUT"`.
- **Capability denied**: Emit `reason = "CAPABILITY_DENIED"`.
- **Crash (Wasm trap)**: Emit `reason = "RUNTIME_TRAP"`.

**For implementers:** Use Wasmtime's fuel API to meter execution. Every Wasm instruction costs fuel (exact costs are configurable, but roughly: arithmetic = 1 fuel, memory access = 2 fuel, capability call = thousands of fuel).

### Phase 3: Receipt Generation

**What happens:**

1. **Hash the render output**: `render_hash = BLAKE3(output)`.
2. **Compare to expected**: Does `render_hash` match `manifest.render.expected_hash`? If not, flag it (`renders_match = false`).
3. **Collect counters**: Fuel used per capability, HTTP status codes, bytes transmitted/received.
4. **Determine outcome**: Success (`ok`), soft fail (retry possible, e.g., network timeout), or hard fail (fatal error).
5. **Sign the receipt**: Host signs the entire receipt with its keypair (proves this host executed it).
6. **Emit receipt**: Return the receipt to the sender (so they can verify billing and debug failures).

**Receipt example:**

```json
{
  "block_id": "cid:bafyBlock123...",
  "host": "did:jig:server:xyz",
  "executed_at": "2025-11-09T12:34:56Z",
  "render_hash": "blake3:d3...",
  "renders_match": true,
  "fuel_used": 421337,
  "outcome": {
    "status": "ok",
    "affordances": ["net.http_2xx"]
  },
  "signature": "ed25519:receiptSig..."
}
```

**For developers:** If your block's render output is non-deterministic (changes every time), set `manifest.render.expected_hash` to `null`. But this prevents receipt verification, so it's discouraged.

**For end users:** Receipts are your proof-of-work. If a server claims your block used 5M fuel but you replay it and it only uses 500k, the server is cheating (or buggy). Report them to the tribunal.

## Signing & Transparency

Blocks MUST be signed by their authors. This prevents forgeries and enables accountability.

### Author Signatures

**Process:**

1. Generate canonical JSON of the manifest (sorted keys, no whitespace).
2. Hash it with BLAKE3: `manifest_hash = BLAKE3(canonical_json)`.
3. Sign the hash with Ed25519: `signature = Ed25519_sign(author_private_key, manifest_hash)`.
4. Store signature in `/proofs/manifest.sig`.

**Verification:**

1. Re-compute `manifest_hash` from canonical JSON.
2. Verify `signature` using `author_public_key` (from manifest).
3. If verification fails, reject the block.

**For implementers:** Use `libsodium` or `ed25519-dalek` for signing. Don't implement Ed25519 yourself—it's tricky to get right (timing attacks, etc.).

### Key Transparency

**Problem:** How do you know the public key in the manifest is actually Alice's? An attacker could substitute their own key.

**Solution:** Key transparency logs (like Certificate Transparency for HTTPS). Every public key is logged in an append-only log. Before trusting a key, verify it appears in the log.

**Process:**

1. Alice publishes her public key to the transparency log (Rekor, Trillian, or Jig's own log).
2. The log returns an inclusion proof: "This key appears at index 12345."
3. Alice includes the inclusion proof in `/proofs/transparency.log`.
4. Hosts verify the proof before accepting Alice's key.

**For server operators:** Run your own transparency log or trust a federated log (gossip-based). Configure the trusted log URLs in `jig-config.toml`.

**For developers:** Use Sigstore's Rekor (open-source, compatible with Jig) or wait for Jig's native transparency log implementation (tracked in the roadmap).

### Attestations

Third parties can attest to blocks:

- **Fact-checkers**: "This block's claims are accurate."
- **Security auditors**: "This block passed our malware scan."
- **Enterprise re-signers**: "Our company approves this block for internal use."

Attestations are stored in `/proofs/attestations/` and include:

- **Issuer DID**: Who's making the claim.
- **Claim type**: What they're claiming (e.g., `fact_checked:v1`, `malware_scan_passed:v2`).
- **Signature**: Ed25519 signature over the block CID + claim.

**For end users:** Filter blocks by attestations. Only run blocks that have been audited by entities you trust.

## WebAssembly Requirements

Blocks are compiled to WebAssembly (Wasm) for portability and sandboxing.

### Target Environment

**Wasm version:** WASI 0.2 (WebAssembly System Interface preview 2).

**Runtime:** Wasmtime (or compatible: Wasmer, wasmtime.js for browsers).

**Imports:** Blocks MAY only import approved host functions. The following are **forbidden**:

- `wasi:clocks/wall-clock` (non-deterministic—time changes every execution)
- `wasi:random` (non-deterministic)
- `wasi:filesystem/*` (no direct file access—use capabilities instead)
- `wasi:sockets/*` (no direct network access—use `net.fetch` capability)

**Exports:** Blocks MUST export at least `_start()` (entry point) and optionally `render::main()` if they produce output.

**For developers:** Use the Jig SDK to generate compliant Wasm modules. It automatically stubs out forbidden imports and wires up capabilities.

### Determinism

Blocks marked `deterministic: true` in the manifest MUST produce identical outputs when run with identical inputs.

**What this means:**

- No random numbers (unless passed as input via capability token).
- No wall-clock timestamps (unless passed as input).
- No environment variables (they differ across hosts).
- No floating-point operations (unless compiled with deterministic rounding modes).

**Why this matters:** Receipts are verifiable. If Alice runs a block and gets output A, Bob should get output A too (with the same inputs). If Bob gets output B, either the block is non-deterministic (bug) or someone's cheating.

**For implementers:** Wasmtime supports deterministic mode (disable WASI clock/random, pin floating-point behavior). Enable it for `deterministic: true` blocks.

### Resource Limits

**Fuel:** Every Wasm instruction costs fuel. Hosts MUST enforce `fuel_max` from the manifest.

**Memory:** Wasm modules have linear memory (array of bytes). Hosts MUST enforce `memory_max_mb`.

**Stack depth:** Prevent infinite recursion. Wasmtime's default stack limit is 512KB (configurable).

**For server operators:** Adjust these limits based on your hardware. A Raspberry Pi might cap memory at 16MB. A beefy server might allow 128MB.

## Normative Requirements Summary

**MUST:**

- Package blocks as CAR-like archives with manifest, code, data, and proofs.
- Use content addressing (BLAKE3 Merkle roots) for block CIDs.
- Verify CIDs match before execution (fail closed on mismatch).
- Sign manifests with Ed25519 and store signatures in `/proofs/manifest.sig`.
- Validate Wasm modules before instantiation (only approved imports).
- Enforce fuel, memory, and timeout limits from manifest constraints.
- Generate receipts after execution with render hash, fuel usage, and outcome.
- Use WASI 0.2 (or newer) as the Wasm target environment.
- Disable non-deterministic Wasm imports (clocks, random) for `deterministic: true` blocks.

**SHOULD:**

- Publish public keys to transparency logs and verify inclusion proofs.
- Use Sigstore (Rekor + Fulcio) for keyless signing when appropriate.
- Deduplicate resources (`/data/*`) across blocks using content addressing.
- Support multi-signature attestations for supply chain audits.
- Provide SDK tooling to automate manifest generation and signing.

**MAY:**

- Include zero-knowledge proofs in `/proofs/attestations/` for privacy-preserving claims.
- Use the Wasm component model for multi-module blocks (experimental).
- Support streaming execution for large media blocks (progressive rendering).

---

**Related chapters:**

- **[Block Execution](block-execution.md)**: How blocks are executed, capability security, fuel metering.
- **[Receipts](receipts.md)**: Detailed receipt schema, outcome-based pricing, affordances.
- **[Crypto Primitives](crypto.md)**: Ed25519 signing, BLAKE3 hashing, key rotation.
- **[Zero-Trust Model](zero-trust.md)**: Why blocks need signatures, fail-closed semantics, adversarial assumptions.

**Next:** Now that you know what blocks are and how they're structured, dive into [Block Execution](block-execution.md) to see how the runtime actually runs them (capability grants, fuel metering, sandboxing). Or check [Receipts](receipts.md) to understand how execution outcomes are metered and billed.
