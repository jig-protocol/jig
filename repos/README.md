# The jig workspace

This directory is the Cargo workspace: every crate of the reference implementation, the
integration tests, and the specification. Build and test from here. The repository root
holds the docs, scripts, installer and CI; start with the root [`README.md`](../README.md)
and [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Crates

| Crate | Role |
| --- | --- |
| [`jig-core`](jig-core/) | Protocol primitives: DIDs, signing, COSE and deterministic CBOR, manifests and bundles, request auth, key links, the key store, the suite registry, receipts, naming objects, proof-of-work, contract messages, Wasm and component validation |
| [`jig-pipeline`](jig-pipeline/) | The write path shared by server and nameserver (`ingest`, the write gate, the MLS gate, effects, SQLite persistence, fanout), `ingest` records, the follower stream and the handshake |
| [`jig-server`](jig-server/) | The reference server, binary `jig-server` |
| [`jig-client`](jig-client/) | Client library: connections and handshake checks, pins, identity and keychain, proof-of-work, re-execution of receipts |
| [`jig-cli`](jig-cli/) | The `jig` binary |
| [`jig-config`](jig-config/) | The server's config types |
| [`jig-mls`](jig-mls/) | MLS (RFC 9420) on openmls: the server's validating delivery service and the client's group member |
| [`jig-nameserver`](jig-nameserver/) | Verified names: registration with proof-of-work, resolution and rotation, binary `jig-nameserver` |
| [`jig-runtime`](jig-runtime/) | Runs `jig:block` components on wasmtime under the `jig-det-1` determinism profile. No WASI |
| [`text-block`](text-block/) | The canonical text-render block, built as a `jig:block/renderer` component |
| [`bridges/core`](bridges/core/), [`bridges/email`](bridges/email/) | The bridge trait, and the in-process email bridge |
| [`integration-tests`](integration-tests/) | Starts real servers and nameservers on loopback and runs end-to-end scenarios |

[`jig-spec/`](jig-spec/) is the specification (an mdBook), with the JEPs, schemas, test
vectors and WIT. It is not a workspace member.

## Build and test

```bash
cargo build --workspace
cargo nextest run --workspace
```

The toolchain is pinned in the root `rust-toolchain.toml` (rustup installs it), with the
`wasm32-unknown-unknown` target; the workspace's minimum Rust version is 1.95. CI runs
`fmt`, `clippy` and `nextest` on every crate above; [`CONTRIBUTING.md`](../CONTRIBUTING.md)
has the details.

Two binaries are built for operators, `jig-server` and `jig-nameserver`, and one for
users, `jig`. A block is run locally with `jig block run`.

## License

Every crate in this workspace is licensed `MIT OR Apache-2.0`, at your option. The spec
(`jig-spec/`) is CC-BY-4.0. See the root [`README.md`](../README.md#license) and
`LICENSE-MIT` / `LICENSE-APACHE`.
