# Receipts

**Audience:** This chapter is for **protocol implementers** running hosts that sign receipts or
clients that check them. **Server operators** might care about what a receipt reveals.
**End users** only need to know that a receipt is a server's signed claim about a block, and that
their client can check it by running the block itself.

---

**Version:** 0.3
**Status:** Draft. The format is [JEP-0006](../jep/jep-0006-block-abi.md#receipts), which is
normative; this chapter explains it. The reference server and client implement it.

A receipt is a signed statement by the host that handled a block. It says which block, who
signed, in what role, when, and, if the host executed the block, exactly what ran and what came
out:

- **What ran:** the component (by hash), the program that named it, the world, and the hash of
  the invocation it was given.
- **What came out:** the outcome class and its hash.
- **Under what limits:** fuel, stack, memory and deadline.

A receipt is a claim, not proof (threat OP-07). It is checked by **re-executing** the block, not
by trusting the signer: a client that holds the same component and the same invocation runs it
and compares outcomes. Fuel is never compared, because fuel is not portable across engines or
versions.

## Encoding and signature

A receipt is a CBOR map with text keys, encoded under the core deterministic rules of RFC 8949
§4.2.1. The executor signs it as a COSE_Sign1 object (RFC 9052):

- the payload is attached;
- the protected header names algorithm EdDSA (`-8`, Ed25519);
- `kid` is the executor's DID.

A verifier MUST refuse a receipt whose signature does not verify against the key of the DID in
its `executor` field, or whose payload is not in deterministic form.

## Kinds

| `kind` | Issued for | Carries |
| --- | --- | --- |
| `exec` | a block the executor ran | the run and its outcome (below) |
| `sealed` | encrypted content the server stored but cannot read | nothing derived from the content |
| `accepted` | a block stored without executing | nothing beyond the common fields |

A server never executes encrypted content, so it never issues `exec` for it; a verifier MUST
refuse a server `exec` receipt for a block in an encrypted channel. Members of an encrypted
group execute its blocks on their own devices. A member's receipt travels only inside the
group's encrypted messages.

## Fields

Every receipt:

| Key | Value |
| --- | --- |
| `domain` | `"jig-block-receipt-v1"` |
| `kind` | `exec`, `sealed` or `accepted` |
| `block_cid` | the block's CID, binary |
| `executor` | the signer's DID |
| `role` | `server` or `member` |
| `produced_at` | milliseconds since the Unix epoch |

An `exec` receipt adds:

| Key | Value |
| --- | --- |
| `component` | BLAKE3 over the component's bytes |
| `program` | the CID of the program manifest that named it (JEP-0011 §2) |
| `world` | the world with its version, e.g. `jig:block/renderer@0.1.0` |
| `invocation_hash` | BLAKE3 over the canonical encoding of the invocation |
| `operator_policy_cid` | the operator policy the run was allowed under (JEP-0011 §5.1). Present exactly when `role` is `server`. |
| `outcome` | `class` (`ok`, `error` or `incomplete`); `hash` for `ok` and `error`; `trap` for an error from a trap; `reason` for `incomplete` |
| `limits` | `fuel`, `max_wasm_stack`, `memory_max_pages`, `timeout_ms` |
| `engine` | `name`, `version`, `profile`, `config_fingerprint`, `fuel_used` |

`engine` is telemetry: it helps diagnose a divergence, and verifiers MUST NOT compare it.
`cost` is reserved for pricing, which is deferred; v0.3 executors MUST NOT emit it and
verifiers MUST ignore it.

[JEP-0006](../jep/jep-0006-block-abi.md#runs-and-outcomes) defines the outcome classes, the trap
codes and how each hash is computed. In short:

- **`ok`** and **`error`** are comparable. Two conforming executors that reach either for the
  same run MUST reach the same class and hash on any architecture, engine or engine version.
- **`incomplete`** (fuel, stack, deadline, host fault, or refusal by policy) asserts nothing
  about the block. It is never compared and is never evidence against an executor.

## When a server issues one

A server builds a block's invocation from the block's signed `ingest` record (its sequence
number, clock and channel), so it executes the block only after the block has landed. A landed
block cannot be refused, so:

1. Before landing, the server MAY run the block to decide whether to accept it, and MUST refuse
   a block whose run is `incomplete`.
2. After landing, it executes and signs `exec`. If that fails, it signs `accepted` instead; the
   block stays. If it cannot sign either, the block has no receipt yet.
3. It keeps one receipt per block. A server that restarts before signing one signs it then.
   Until then, readers show the block as pending.

## Checking a receipt

A client that holds a block in plaintext and has the component the receipt names can check an
`exec` receipt by running the block itself. The steps are
[JEP-0006's](../jep/jep-0006-block-abi.md#receipts); the reference client
(`jig-client`, `verify` feature) follows them:

1. Check the signature, that the `executor` is the server that delivered the receipt, and that
   the receipt's `block_cid` is this block. A receipt for another block says nothing about it.
2. If the outcome is `incomplete`, stop: there is nothing to compare.
3. Check that the block's `ingest` record names this block and is signed by the same server.
   Otherwise a forged record would make an honest receipt look divergent.
4. If the client does not have the named component, the block is **unverified**, not divergent.
5. Rebuild the invocation. A different `invocation_hash` is a divergence.
6. Run it with fuel at most the receipt's `limits.fuel`. A local `incomplete` is not comparable.
7. Compare class and hash. Equal is **agreement**; anything else is a **divergence**.

The comparison keys on component, world, invocation and outcome, never on the program CID: two
servers wrap the same component in different program manifests (JEP-0011 §5.1). A client MUST
show a divergence to its user. What follows from one is not yet specified.

The reference CLI marks a text message `[server render differs]` on a divergence and
`[unverified]` when it could not check, and adds nothing on agreement.

## Older formats

Stores and peers from before v0.3 hold JSON receipts. A host MUST keep reading them and MUST
NOT write them. Each is `{"canonical_hex": …, "sig_hex": …}`: the hex of a JSON payload, and an
Ed25519 signature over those bytes by the key of the payload's `server_did`. The payload's `v`
names its shape:

| `v` | Was issued for | Also carries |
| --- | --- | --- |
| `0.3-render` | a rendered `text-render` block | `render.hash`, `render.module`, `render.length_bytes` |
| `0.3-sealed` | encrypted content | no content-derived value |
| `0.2-synthetic` | a block stored without executing | nothing beyond the common fields |

Every payload carries `block_cid` and `server_did`. A reader MUST check the signature before
using any of it.

`jig-runtime` also still builds the v0.2 runtime receipt for its WASI preview 1 path. No server
path signs or serves it, and it is removed with that path.

## What a receipt reveals

A receipt names the block, the signer, the time and the facts of a run. It reveals that this
server handled this block, and when (threat PV-02). A `sealed` receipt MUST NOT carry anything
derived from the content: no hash of it, no length.

## Normative requirements

The requirements are JEP-0006's. Collected here:

**MUST:**

- Encode a receipt as deterministic CBOR and sign it as COSE_Sign1 with EdDSA, `kid` the
  executor's DID.
- Refuse a receipt whose signature does not verify or whose payload is not deterministic CBOR.
- Never issue a server `exec` receipt for encrypted content, and refuse one.
- Never put a content-derived value in a `sealed` receipt.
- Never compare `incomplete` outcomes, or `fuel_used`.
- Refuse an `incomplete` run before landing a block; after landing, never undo the block.
- Check the `ingest` record against the receipt's signer before re-executing.
- Show a divergence on a comparable outcome to the user.

**MAY:**

- Re-execute a block to check a receipt, when the client has its component.

---

**Related chapters:** [Block Execution](block-execution.md) for how a block runs,
[Blocks](blocks.md) for what a block is, and the [threat register](threat-register.md) for
OP-07 (receipts are claims) and PV-02 (receipt linkage).
