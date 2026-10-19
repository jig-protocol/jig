# `jig:block` conformance vectors

These vectors pin what a conforming executor of `jig:block@0.1.0` must compute (JEP-0006).
Two executors that reach a comparable outcome (`ok` or `error`) for the same vector must reach
the one recorded here, on any architecture, engine or engine version.

## Files

- `vectors.json`: the vectors (format `jig:block vectors v1`).
- `guests/*.wat`: small hand-written `renderer` components, one per behaviour. Each `.wasm` next
  to it is the compiled form, which is what the vector runs.
- `text-block` vectors use the committed component at
  `repos/text-block/artifacts/text_block.component.wasm`, by relative path.

## A vector

| Field | Meaning |
| --- | --- |
| `name` | Unique name. |
| `component` | The component's path, relative to this directory. |
| `component-hash` | `blake3:<hex>` of the component's bytes. If the component changes, the vector has to be re-blessed. |
| `world` | `renderer`; `bot` vectors come with lane C. |
| `max-memory-pages` | The manifest's memory limit, in 64 KiB pages. |
| `fuel`, `timeout-ms` | Limits for the run. Neither is compared; they only need to be generous enough for the expected class. |
| `invocation` | The `invocation` record, with field names as in the WIT. `input.body-hex` is the body in lowercase hex. |
| `invocation-hash` | BLAKE3 (key derivation, context `jig:block invocation v1`) over the invocation's canonical CBOR. |
| `expected` | `{"outcome": "ok", "hash"}`, `{"outcome": "error", "hash"}` for a guest `err`, `{"outcome": "error", "trap", "hash"}` for a trap, or `{"outcome": "incomplete", "reason"}`. |

The `hash` of a comparable outcome is BLAKE3 (key derivation, context `jig:block outcome v1`)
over the canonical CBOR of the returned `result`, or of `trap(<code>)` for a trap. JEP-0006
defines both, and the trap codes.

There is one vector per trap code, except `invalid-conversion-to-integer`, which needs a float
instruction that `jig-det-1` refuses. Four `malformed-*` vectors pin the malformed return values
that are `incomplete(host-fault)`.

An `incomplete` vector asserts only its reason. Stack exhaustion in particular happens at a depth
that differs by engine and architecture.

## Running and adding vectors

```sh
cargo test -p jig-runtime --test block_abi_vectors
```

runs every vector on native Cranelift and on Pulley. To add a vector:

1. Write the guest `.wat`, if it needs one.
2. Add the vector to `vectors.json` with `expected` holding only the class (and trap code or
   reason).
3. Run the same command with `JIG_BLESS_BLOCK_ABI_VECTORS=1`.

Blessing compiles each `.wat`, records the component and invocation hashes, and fills in the
outcome hash from a native run. It refuses a vector whose run lands in a class other than the one
written down. `an_expected_hash_matches_hand_written_cbor` checks one hash against CBOR bytes
written by hand, so the set does not rest only on the encoder that blessed it.
