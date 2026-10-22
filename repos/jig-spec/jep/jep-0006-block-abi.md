+++
jep = 0006
title = "Block ABI on the WebAssembly Component Model"
status = "Draft"
type = "Standards Track"
category = "Core"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-18"
requires = ["0002"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

This JEP replaces jig's two ad hoc block calling conventions with one ABI defined in WIT on
the WebAssembly Component Model. It defines:

- the `jig:block` package and its worlds;
- a determinism profile hosts enforce;
- what it means for two executors to agree on a run;
- a single receipt format.

Hosts and clients run the same components under the same profile, so anyone holding a block
and its inputs can re-execute it and check a receipt, on any architecture.

**Draft status.** The maintainer decided the design questions on 2026-10-18 (decisions A1–A8
in the [design doc](../../../docs/superpowers/specs/2026-10-18-v0.3-block-abi-design.md), which
holds the options and rationale). The first slice of the reference implementation and its test
vectors now exist (see Reference Implementation and Test Vectors). The JEP stays Draft until the
maintainer moves it on.

# Motivation

- **Two ABIs.** The byte-payload convention (`jig_alloc`/`execute`) runs only the server's
  compiled-in text renderer. `Runtime::execute` runs argument-less WASI preview 1 entry points.
  Neither can express capabilities, and neither has a typed interface a third party can target.
- **Four receipt formats,** none fully specified.
- **Phase 2's exit criterion** (`ROADMAP.md`) needs a block a third party ships in minutes that
  runs identically on client and server.

Non-goals:
- host imports, capabilities, state and nesting (a companion design by lane C);
- the UI ABI (phase 3, a separate `jig:ui` package);
- effects that cannot be re-executed (network fetch, inference), which need attestation;
- the world `jig-server` itself exports when compiled to a component (phase 4).

# Specification

## Package and worlds

The package is `jig:block`, versioned with semver. During v0.3 development it is `0.1.0`, and
every minor version is incompatible.

- **`renderer`** exports `render: func(inv: invocation) -> result<payload, block-error>`. It
  imports `jig:block/types` (types, no functions), which every host links as an empty instance,
  and at most `jig:host/compose`, for child renderers its manifest pins by CID.
- **`bot`** exports
  `handle: func(inv: invocation, state: list<u8>) -> result<handled, block-error>`, where
  `handled` carries the returned effects and an optional new state. It imports only
  `jig:host/*` interfaces, specified in JEP-0007.
  - A `bot` MUST NOT perform an effect during a call. It returns effects for the host to check
    against granted capabilities and apply.
- **No floats.** The ABI contains no `f32` or `f64`.
- **Inputs are data.** Every input a block depends on, including time and sender, is a field of
  `invocation`.

The normative WIT is [`wit/jig-block/block.wit`](../wit/jig-block/block.wit).

## Determinism profile `jig-det-1`

A host MUST refuse, before execution, a component that fails any of the following:

1. Validation with exactly the WebAssembly 2.0 features minus SIMD, plus the component model
   without its async, threading or error-context extensions. No nested component may contain a
   core module.
2. For every core module, at any depth: no scalar float instruction, and declared maxima for every memory and
   table, within the manifest's limits.
3. Imports: `jig:block/types` (types only) is always allowed. Beyond it, a `renderer` may import
   at most `jig:host/compose`, and a `bot` only `jig:host/*` interfaces that its manifest
   capabilities grant, at a version the host links. No `wasi:*` import.
4. Exports: exactly the interface of the world its manifest declares.

A host MUST configure its engine to the same feature set. It MUST terminate execution by a
deterministic fuel limit, and MAY also use a wall-clock deadline as a liveness guard.

## Runs and outcomes

A run is identified by:
- the component's hash, BLAKE3 over its bytes;
- the world and its version;
- `invocation_hash`, BLAKE3 over the canonical encoding of the invocation value;
- for `bot`, the hash of the state passed in and the content-addressed answers to its fetch
  imports;
- for a composed block, the child CIDs its manifest pins.

`invocation.ingest-seq` and `invocation.ingest-hlc` are copied from the triggering block's
`ingest` record, which the channel's sequencing server signs (lane L7). Every per-channel key, including
`invocation.channel-cid`, is the CID of the channel's `channel-create` block (lane F). An executor MUST verify that
record before execution. The author-set `hlc_ts` is never an input.

Its outcome is one of:

- **`ok`**, with `hash` = BLAKE3 over the canonical encoding of the returned value;
- **`error`**, with `hash` over the returned `block-error`, or over a deterministic trap code;
- **`incomplete`**, with a `reason`: fuel exhaustion, stack exhaustion, wall-clock deadline,
  host fault, or refusal by host policy.

**What is hashed.** `ok` and a guest `err` hash the export's whole return value: for a renderer,
the `result<payload, block-error>`, encoded as `["ok", …]` or `["err", …]`. A trap hashes the
variant value `trap(<code>)`, encoded `["trap", "<code>"]`, which cannot equal either. Every
outcome hash is BLAKE3 in key-derivation mode with the context `jig:block outcome v1`, over the
canonical encoding.

**Trap codes.** Only the WebAssembly core specification's traps are comparable, under these
names:

| Code | Raised by |
| --- | --- |
| `unreachable` | `unreachable` |
| `memory-out-of-bounds` | a load, store or bulk memory operation outside linear memory |
| `table-out-of-bounds` | `call_indirect` or a table operation past the end of a table |
| `uninitialized-element` | `call_indirect` through an empty table slot |
| `indirect-call-type-mismatch` | `call_indirect` to a function of another type |
| `integer-overflow` | signed division of the minimum value by -1 |
| `integer-divide-by-zero` | integer division or remainder by zero |
| `invalid-conversion-to-integer` | a float-to-integer conversion out of range. Unreachable under `jig-det-1` (no floats), so it has no vector. |

Any other trap, including an engine-specific one, is `incomplete` with reason `host-fault`.
So is a malformed return value, such as a string or list past the end of memory, a bad
discriminant or a misaligned return pointer. Engines report those differently, and treating
them as `incomplete` costs nothing: such a block is never compared, and `incomplete` is never
evidence against an executor. A later revision may replace this with a single comparable
`invalid-return` code, once a second engine's lifting order has been checked against the
vectors.

A feature added to `jig-det-1` later (threads, GC, exceptions) brings its own traps. Each one
stays `incomplete(host-fault)` until this table names it.

Two conforming executors that both reach `ok` or `error` for the same run MUST reach the same
outcome and hash, on any architecture, operating system, engine or engine version. An
`incomplete` outcome asserts nothing about the block, and MUST NOT be compared or treated as
evidence of misbehaviour.

**Canonical encoding.** The canonical encoding of a WIT value is deterministic CBOR under the
core deterministic rules of RFC 8949 §4.2.1, with each value mapped as follows:

| WIT type | CBOR |
| --- | --- |
| `bool` | `true` / `false` |
| `u8`…`u64`, `s8`…`s64` | integer (major type 0 or 1), shortest form |
| `char` | text string holding that one character |
| `string` | text string |
| `list<u8>` | byte string |
| any other `list<T>`, `tuple<…>` | array |
| `record` | map from field name (text) to value, keys in canonical order |
| `variant` case, `result` | array `[case]` or `[case, payload]`; `result` uses the cases `ok` and `err` |
| `enum` case | text string |
| `option<T>` | `none` is `null`; `some(x)` is the one-element array `[x]` |

`option` wraps `some` in an array so that `option<option<T>>` stays unambiguous: `none` is
`null`, `some(none)` is `[null]`. `f32`, `f64`, `flags`, resources, futures and streams have no
mapping: `jig:block` uses none of them, and an encoder MUST refuse a value that needs one.

## Who executes

- **Encrypted content.** A server MUST NOT execute it. Members execute it on their own devices.
  A sender SHOULD include its outcome hash inside the encrypted application message, so other
  members can compare.
- **Third-party components.** A server MUST NOT execute one unless its operator policy allows
  it. JEP-0011 §5.1 defines that policy (`operator-policy`): programs are allowed by program
  CID or by signing author, and renderers with no requests and no children also by component
  hash. The default policy allows only the renderer components the server ships.

## Receipts

A receipt is a CBOR map with text keys, encoded under the core deterministic rules of RFC 8949
§4.2.1. It is signed by its executor as a COSE_Sign1 object (RFC 9052) with an attached payload,
algorithm EdDSA (`-8`, Ed25519) and `kid` set to the executor's DID. Its fields:

- `domain`: `"jig-block-receipt-v1"`.
- `kind`: `exec`, `sealed` or `accepted`.
- `block_cid` (binary CID), `executor` (DID), `role` (`server` or `member`) and `produced_at`
  (milliseconds since the Unix epoch).
- For `exec` only:
  - `component` (its hash, as in Runs and outcomes), `program` (the program's CID,
    JEP-0011 §2), `world` and `invocation_hash`;
  - `operator_policy_cid`: the CID of the operator policy (JEP-0011 §5.1) the run was allowed
    under. Present exactly when `role` is `server`;
  - `outcome`: `class` (`ok`, `error` or `incomplete`), with `hash` for `ok` and `error`, `trap`
    for an `error` from a trap, and `reason` for `incomplete`;
  - `limits` the run was held to: `fuel`, `max_wasm_stack`, `memory_max_pages` and
    `timeout_ms`;
  - `engine`: `name`, the exact `version`, `profile`, `config_fingerprint` and `fuel_used`.

Rules:
- `engine` is telemetry. Verifiers MUST NOT compare `fuel_used` across executors.
- A server MUST NOT issue an `exec` receipt for encrypted content, and a verifier MUST refuse
  one.
- `cost` is reserved for pricing (billing is deferred to the distributed-OS phase). v0.3
  executors MUST NOT emit it; verifiers MUST ignore it.
- A `sealed` receipt MUST NOT carry any content-derived value.
- A member-signed receipt for encrypted content MUST travel only inside the group's encrypted
  messages.

**Executing on ingest.** A server that executes a block when it ingests it builds the invocation
from the block's signed `ingest` record (see Runs and outcomes), so it executes after the block
lands. A landed block cannot be refused afterwards. Therefore:

- Before landing, a server MAY run the block to decide whether to accept it. It MUST refuse a
  block whose run is `incomplete`, since its receipt could not carry a comparable outcome.
- After landing, a failure to execute or sign MUST NOT undo the block. The server issues an
  `accepted` receipt in place of `exec`. If it cannot sign that either, the block stays without
  a receipt, and the server issues one later, at the latest when it restarts.
- A server keeps at most one receipt per block. A server that restarts before issuing it issues
  it then. Until a receipt exists, readers SHOULD show the block as pending, not as unverified.

**Checking a receipt (client).** A client that holds a block in plaintext MAY re-execute it and
compare. A client that does:

1. MUST check the `exec` receipt's signature, that its `executor` is the server that
   delivered it, and that its `block_cid` is the block being checked. A receipt for another
   block is not evidence about this one.
2. MUST NOT execute or compare when the receipt's outcome is `incomplete`.
3. MUST check that the block's `ingest` record names the block and is signed by the same server
   as the receipt, before using it to build the invocation. A forged record would otherwise turn
   an honest receipt into a false divergence.
4. Compares only when it holds the component the receipt names. Otherwise the block is
   unverified, not divergent.
5. Rebuilds the invocation. A different `invocation_hash` is a divergence.
6. Executes with fuel at most the receipt's `limits.fuel`, capped by its own limit. A local
   `incomplete` is not comparable.
7. Compares the outcome class and hash. Any difference is a divergence.

Comparison keys on the component, world, invocation and outcome, never on the program CID,
which differs between servers for the same component (JEP-0011 §5.1). A client MUST surface a
divergence to its user. This JEP does not define what follows from one.

## Versioning and discovery

- A manifest names its world with the full version (`jig:block/renderer@0.1.0`).
- A host advertises in its handshake capabilities (JEP-0002) the `jig:block` versions and
  profiles it executes.
- The package becomes `1.0.0` at the v0.3 exit. After that, additions are minor versions
  gated with `@since`.

# Security Considerations (Zero-Trust)

- **The sandbox is one layer (SC-03).** Fuel, memory and stack limits, no ambient imports, and
  operator policy over which third-party code a server runs are the others.
- **Verification is re-execution.** A receipt is a signed claim (OP-07). A divergent comparable
  outcome is evidence against an executor and MUST be surfaced to the user.
- **No content-derived value leaves an encrypted group (PV-02).**
- **Effects are checked against capabilities** before they are applied (AB-04). Imports are
  checked at upload and at link time.
- **Non-portable traps** (fuel, stack) are `incomplete`, so an executor cannot manufacture a
  "divergence" by running on a host with a smaller stack.

# Backwards Compatibility

- The `text-render` kind moves to a `renderer` component. Its `render_hash` keeps its current
  definition, so servers running mixed versions keep agreeing.
- The byte-payload ABI is removed: servers and clients run `text-block` only as a component.
  The WASI preview 1 ABI and its v0.2 receipt follow once no caller remains. New receipts are
  v0.3 only; stored receipts in the old formats stay readable.

# Reference Implementation (if applicable)

The first slice, in `repos/`:

- `jig-core`: the canonical encoding and outcome hashes (`block_abi`), the component validator
  for `jig-det-1` (`component_validation`) and v0.3 receipts (`block_receipt`).
- `jig-runtime`: the component executor (`component`), on native Cranelift and on Pulley.
- `text-block`: the `text-render` block as a `renderer` component.
- `jig-pipeline`: the server executes it on ingest and signs `exec`, `sealed` and `accepted`
  receipts.
- `jig-client` (`verify` feature): the client re-executes and compares, as above.
- CI runs the vectors on x86_64 and aarch64 Linux, native and Pulley.

# Test Vectors

[`vectors/block-abi/`](../vectors/block-abi/README.md) holds the renderer vectors. Each one
gives a component, an invocation, the invocation hash and the expected outcome: the class, the
trap code or incomplete reason, and the outcome hash for a comparable outcome. They cover:

- `ok` with an empty payload, an echo of the invocation's strings and list, every integer field
  at its maximum, and a body that is not UTF-8;
- both `block-error` cases;
- each trap code reachable under `jig-det-1`;
- malformed return values, which are `incomplete(host-fault)`;
- fuel and stack exhaustion;
- `text-block` on six inputs, one of them not UTF-8.

jig-runtime runs them on native Cranelift and on Pulley; CI runs them on x86_64 and aarch64
Linux.

[`vectors/operator-policy/`](../vectors/operator-policy/README.md) holds the JEP-0011 §5.1
vectors that decide which components a server executes here. Each one gives a signed policy
payload, a program's manifest facts and its pinned children, and whether the policy allows it.

# LLM Influence (if applicable)

Drafted with Claude Code from a research pass over the repository and the wasmtime 49.0.3
sources. The maintainer reviews every decision.

# Rejected Alternatives

- **A deterministic WASI 0.2 subset.** No standard profile exists; host WASI answers varied by
  OS in jig's own measurements; pure `wasm32-wasip2` builds import 14 interfaces.
- **Receipts as signed JSON (`canonical_hex`).** Replaced by deterministic CBOR and COSE_Sign1
  (decision A5): one canonical encoding for receipts and outcome hashes, and a standard signature
  envelope.
- **Comparing fuel.** Fuel is not portable across engines or versions (fuel-portability
  investigation).
- **Host functions that perform effects mid-call** for v0.3. Their results can be attested but
  not re-executed. Deferred to an attested tier.

# Copyright

This document is licensed under CC-BY-4.0.
