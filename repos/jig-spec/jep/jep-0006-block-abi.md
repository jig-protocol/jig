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

**Draft status.** Every requirement below is proposed and awaits the maintainer's decisions on
the open questions in the
[design doc](../../../docs/superpowers/specs/2026-10-18-v0.3-block-abi-design.md), which holds
the options and rationale. Nothing here is implemented.

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

- **`renderer`** exports `render: func(inv: invocation) -> result<payload, block-error>`. Its
  only possible import is `jig:host/compose`, for child renderers its manifest pins by CID.
- **`bot`** exports
  `handle: func(inv: invocation, state: list<u8>) -> result<handled, block-error>`, where
  `handled` carries the returned effects and an optional new state. It imports only
  `jig:host/*` interfaces, specified in JEP-0007.
  - A `bot` MUST NOT perform an effect during a call. It returns effects for the host to check
    against granted capabilities and apply.
- **No floats.** The ABI contains no `f32` or `f64`.
- **Inputs are data.** Every input a block depends on, including time and sender, is a field of
  `invocation`.

The normative WIT will live in `repos/jig-spec/wit/` once approved. The design doc holds the
current sketch.

## Determinism profile `jig-det-1`

A host MUST refuse, before execution, a component that fails any of the following:

1. Validation with exactly the WebAssembly 2.0 features minus SIMD, plus the component model
   without its async, threading or error-context extensions.
2. For every core module: no scalar float instruction, and declared maxima for every memory and
   table, within the manifest's limits.
3. Imports: for `renderer`, at most `jig:host/compose`. For `bot`, only `jig:host/*` interfaces that its manifest
   capabilities grant, at a version the host links. No `wasi:*` import.
4. Exports: exactly the interface of the world its manifest declares.

A host MUST configure its engine to the same feature set. It MUST terminate execution by a
deterministic fuel limit, and MAY also use a wall-clock deadline as a liveness guard.

## Runs and outcomes

A run is identified by:
- the component's CID;
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

Two conforming executors that both reach `ok` or `error` for the same run MUST reach the same
outcome and hash, on any architecture, operating system, engine or engine version. An
`incomplete` outcome asserts nothing about the block, and MUST NOT be compared or treated as
evidence of misbehaviour.

**Canonical encoding.** The canonical encoding of a WIT value is deterministic CBOR (RFC 8949
§4.2) under a fixed type mapping, which this JEP will define before it leaves Draft.

## Who executes

- **Encrypted content.** A server MUST NOT execute it. Members execute it on their own devices.
  A sender SHOULD include its outcome hash inside the encrypted application message, so other
  members can compare.
- **Third-party components.** A server MUST NOT execute one unless operator policy selects it
  (by component CID or by signing author). The default policy selects none.

## Receipts

A receipt is a JSON object, signed by its executor over the exact bytes (`canonical_hex` and
`sig_hex`). Its fields:

- `v`: `"0.3"`.
- `kind`: `exec`, `sealed` or `accepted`.
- `block_cid`, `executor` (DID), `role` (`server` or `member`) and `produced_at`.
- For `exec` only:
  - `component`, `world` and `invocation_hash`;
  - `outcome`;
  - `engine`: `name`, the exact `version`, `profile`, `pricing_schedule` and `fuel_used`.

Rules:
- `engine` is telemetry. Verifiers MUST NOT compare `fuel_used` across executors.
- `cost` is reserved for pricing (billing is deferred to the distributed-OS phase). v0.3
  executors MUST NOT emit it; verifiers MUST ignore it.
- A `sealed` receipt MUST NOT carry any content-derived value.
- A member-signed receipt for encrypted content MUST travel only inside the group's encrypted
  messages.

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
- The byte-payload ABI, the WASI preview 1 ABI and the four existing receipt formats are
  removed once the component path is live. Stored receipts in the old formats stay readable.

# Reference Implementation (if applicable)

None yet. The first slice: `text-block` as a `renderer` component, executed by the server and
by `jig-client`, with a CI determinism matrix on x86_64 and aarch64, native and Pulley.

# Test Vectors

To be added with the reference implementation: component, invocation, and expected outcome and
hash.

# LLM Influence (if applicable)

Drafted with Claude Code from a research pass over the repository and the wasmtime 49.0.3
sources. The maintainer reviews every decision.

# Rejected Alternatives

- **A deterministic WASI 0.2 subset.** No standard profile exists; host WASI answers varied by
  OS in jig's own measurements; pure `wasm32-wasip2` builds import 14 interfaces.
- **Comparing fuel.** Fuel is not portable across engines or versions (fuel-portability
  investigation).
- **Host functions that perform effects mid-call** for v0.3. Their results can be attested but
  not re-executed. Deferred to an attested tier.

# Copyright

This document is licensed under CC-BY-4.0.
