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

**What this means:** `encryption` names the block's [encryption suite](encryption.md#registry). It MUST be a registered suite this implementation implements; anything else is refused. The reference implementation implements `none` and `mls`. Metadata (who sent it, when, how much fuel it used) is visible to the server under every suite.

## Execution Lifecycle

An executable block is a component of the `jig:block` package
([JEP-0006](../jep/jep-0006-block-abi.md)), named by a signed program manifest
([JEP-0011](../jep/jep-0011-block-programs.md)). [Block Execution](block-execution.md) describes
the three phases in full. In short:

1. **Validation**: the manifest's signature, the host's operator policy, and the determinism
   profile `jig-det-1`. Any failure refuses the block before its code is compiled.
2. **Execution**: the host calls the world's export with an `invocation` record that carries
   every input (no clock, no randomness, no WASI), under fuel, stack, memory and deadline
   limits. The outcome is `ok`, `error` or `incomplete`.
3. **Receipt**: the host signs a v0.3 receipt naming the component, the invocation hash and the
   outcome hash ([Receipts](receipts.md)).

**For end users:** a receipt is a claim. Your client checks it by running the same component on
the same invocation and comparing outcomes, never fuel.

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

Blocks are WebAssembly components, for portability and sandboxing.

### Target Environment

**Package:** `jig:block@0.1.0`, with the `renderer` and `bot` worlds
([`wit/jig-block/block.wit`](../wit/jig-block/block.wit)).

**Runtime:** wasmtime, or any engine that implements the component model under `jig-det-1`.

**Imports:** a `renderer` imports only `jig:block/types` (types, no functions) and at most
`jig:host/compose`. A `bot` imports only the `jig:host/*` interfaces its install grants. No
`wasi:*` import is allowed.

**Exports:** exactly the world's interface: `render` for a `renderer`, `handler` for a `bot`.

**For developers:** `jig block new` and `jig block build` produce a compliant component.

### Determinism

Every block is deterministic: the determinism profile `jig-det-1` admits no floats, no threads
and no WASI, and every input arrives in the invocation. Two conforming executors that reach `ok`
or `error` for the same run reach the same outcome hash.

**Why this matters:** receipts are checked by re-execution. If Bob's client gets a different
outcome from the same component and invocation, the server's claim is wrong.

### Resource Limits

**Fuel:** deterministic metering. Hosts MUST enforce the manifest's fuel limit, capped by
their own.

**Memory:** every memory declares a maximum, and hosts MUST enforce the manifest's limit.

**Stack:** hosts MUST cap the stack (the reference host uses 512 KiB).

A run that hits any limit is `incomplete`: it asserts nothing about the block and is never
compared.

**For server operators:** set the ceilings in the `[execution]` section of the server
configuration. Fuel and memory get the lower of the manifest's limit and yours; the deadline is
always yours.

## Normative Requirements Summary

**MUST:**

- Package blocks as CAR-like archives with manifest, code, data, and proofs.
- Use content addressing (BLAKE3 Merkle roots) for block CIDs.
- Verify CIDs match before execution (fail closed on mismatch).
- Sign manifests with Ed25519 and store signatures in `/proofs/manifest.sig`.
- Validate components against `jig-det-1` before compiling them.
- Enforce fuel, memory, and timeout limits from manifest constraints.
- Sign a v0.3 receipt after execution, with the component, invocation hash and outcome.
- Target the `jig:block` component worlds; allow no `wasi:*` import.

**SHOULD:**

- Publish public keys to transparency logs and verify inclusion proofs.
- Use Sigstore (Rekor + Fulcio) for keyless signing when appropriate.
- Deduplicate resources (`/data/*`) across blocks using content addressing.
- Support multi-signature attestations for supply chain audits.
- Provide SDK tooling to automate manifest generation and signing.

**MAY:**

- Include zero-knowledge proofs in `/proofs/attestations/` for privacy-preserving claims.
- Support streaming execution for large media blocks (progressive rendering).

---

**Related chapters:**

- **[Block Execution](block-execution.md)**: How blocks are executed, capability security, fuel metering.
- **[Receipts](receipts.md)**: The v0.3 receipt, and how a client checks it.
- **[Crypto Primitives](crypto.md)**: Ed25519 signing, BLAKE3 hashing, key rotation.
- **[Zero-Trust Model](zero-trust.md)**: Why blocks need signatures, fail-closed semantics, adversarial assumptions.

**Next:** Now that you know what blocks are and how they're structured, dive into [Block Execution](block-execution.md) to see how the runtime actually runs them (capability grants, fuel metering, sandboxing). Or check [Receipts](receipts.md) to see how a host's execution claims are signed and checked.
